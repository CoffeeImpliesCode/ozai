//! The fold: probe results in, one report out.
//!
//! Upstream, captured 2026-09-30 at n0-computer/iroh commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8 (the `iroh` 1.3.0 crate as
//! published): `Report::update` from `iroh/src/net_report/report.rs:68-130`, and
//! the preferred-relay choice from `iroh/src/net_report.rs`.
//!
//! # Pure in the strong sense
//!
//! It reads no clock, no environment and no global, and takes no allocator. Time
//! arrives twice, both as arguments — `now`, and each probe's own `instant` —
//! and every figure in the result is derived from the two of them plus the
//! latencies. Two calls with equal arguments produce equal reports whatever
//! order the probes are in, which upstream's sequential `Report::update` does
//! not promise for `global_v4` and which the permutation test at the bottom
//! pins.
//!
//! Folding nothing produces the default report, and that is a defined answer
//! rather than a shrug: no UDP, no address, no classification, no preferred
//! relay. `Report.mappingVariesByDest` on it is null — "not measured" — and not
//! the `false` that would read as "measured, and symmetric". A caller that wants
//! to know whether the node is reachable directly has to have probed first.
//!
//! # The one deliberate divergence
//!
//! `beats` is it. Upstream keeps whichever address a probe happened to report
//! first and never replaces it (`global_v4 = Some(ipp)` only into an empty slot),
//! which makes the field a function of the order probes arrived in. The address
//! is read by peers to decide where to try, and a report folded from one set of
//! probes must not name a different peer when the same set is handed over in
//! another order, so the winner is decided on the probe's own contents. It can
//! only differ when probes to several relays disagree, which is exactly the case
//! where upstream's answer was arrival order.

const std = @import("std");
const addr = @import("../base/addr.zig");
const base_relay_url = @import("../base/relay_url.zig");
const claim = @import("report_claim.zig");
const report = @import("report.zig");

const SocketAddr = addr.SocketAddr;

/// The vocabulary the fold is written in, named once per source so that a
/// reader can tell the three files apart: these are values from `report.zig`,
/// these are values from `report_claim.zig`, and nothing here is private to
/// this file but the two rules below.
const Nanos = report.Nanos;
const ProbeResult = report.ProbeResult;
const QadProbe = report.QadProbe;
const RelayLatencies = report.RelayLatencies;
const max_report_age = report.max_report_age;

const History = claim.History;
const Report = claim.Report;
const Varying = claim.Varying;

const RelayUrl = base_relay_url.RelayUrl;

/// and takes no allocator. Time arrives twice, both as arguments — `now`, and
/// each probe's own `instant` — and every figure in the result is derived from
/// the two of them plus the latencies. Two calls with equal arguments produce
/// equal reports whatever order the probes are in, which upstream's sequential
/// `Report::update` does not promise for `global_v4` and which the permutation
/// test at the bottom pins.
///
/// Folding nothing produces the default report, and that is a defined answer
/// rather than a shrug: no UDP, no address, no classification, no preferred
/// relay. `mappingVariesByDest` on it is null — "not measured" — and not the
/// `false` that would read as "measured, and symmetric". A caller that wants to
/// know whether the node is reachable directly has to have probed first.
pub fn fold(probes: []const ProbeResult, history: History, now: Nanos) Report {
    var report: Report = .{};
    var varying_v4: Varying = .{};
    var varying_v6: Varying = .{};
    var best_v4: ?QadProbe = null;
    var best_v6: ?QadProbe = null;

    for (probes) |probe| {
        // A full list is not a fold failure: it costs a slower preferred relay,
        // not a wrong one, and the report has no field to record it in.
        _ = report.relay_latency.update(probe.relay(), probe.latency(), probe.kind());
        switch (probe) {
            .https => {},
            .qad_ipv4 => |qad| switch (qad.addr.ip) {
                .v4 => {
                    report.udp_v4 = true;
                    varying_v4.observe(qad.addr);
                    if (best_v4 == null or beats(qad, best_v4.?)) best_v4 = qad;
                },
                // A relay answering a v4 probe with a v6 address. Upstream logs
                // it and returns, and the return comes after the latency is
                // already recorded, so the measurement is kept and the address is
                // dropped. Kept here for the same reason, and the address is not
                // classified: a NAT characterised from an address of the wrong
                // family is the failure this module exists to prevent.
                .v6 => {},
            },
            .qad_ipv6 => |qad| switch (qad.addr.ip) {
                .v6 => {
                    report.udp_v6 = true;
                    varying_v6.observe(qad.addr);
                    if (best_v6 == null or beats(qad, best_v6.?)) best_v6 = qad;
                },
                .v4 => {},
            },
        }
    }

    report.mapping_varies_by_dest_ipv4 = varying_v4.classify();
    report.mapping_varies_by_dest_ipv6 = varying_v6.classify();
    if (best_v4) |probe| report.global_v4 = probe.addr;
    if (best_v6) |probe| report.global_v6 = probe.addr;

    if (history.last) |last| {
        // A round that measured nothing inherits the last answer rather than
        // dropping back to "unknown", which would make an unchanged NAT look
        // newly unclassified every time a probe failed.
        if (report.mapping_varies_by_dest_ipv4 == null) {
            report.mapping_varies_by_dest_ipv4 = last.mapping_varies_by_dest_ipv4;
        }
        if (report.mapping_varies_by_dest_ipv6 == null) {
            report.mapping_varies_by_dest_ipv6 = last.mapping_varies_by_dest_ipv6;
        }
    }

    choosePreferredRelay(&report, history, now);
    return report;
}
/// which is exactly the case where upstream's answer was arrival order.
fn beats(candidate: QadProbe, incumbent: QadProbe) bool {
    if (candidate.latency != incumbent.latency) return candidate.latency < incumbent.latency;
    if (candidate.instant != incumbent.instant) return candidate.instant > incumbent.instant;
    return candidate.relay.order(incumbent.relay) == .lt;
}
/// and is the only reason the fold takes a clock reading at all.
fn choosePreferredRelay(report: *Report, history: History, now: Nanos) void {
    var best_recent: RelayLatencies = .{};
    for (history.entries) |entry| {
        // Saturating: an entry stamped after `now` is not old, it is simply not
        // yet stale. The alternative is a panic in the middle of a fold.
        if (now -| entry.instant > max_report_age) continue;
        best_recent.merge(&entry.report.relay_latency);
    }
    best_recent.merge(&report.relay_latency);

    var best_any: Nanos = 0;
    var current_latency: Nanos = 0;
    var iterator = report.relay_latency.iter();
    while (iterator.next()) |entry| {
        if (history.last) |last| {
            if (last.preferred_relay) |current| {
                if (current.order(entry.relay) == .eq) current_latency = entry.latency;
            }
        }
        const best = best_recent.get(entry.relay) orelse continue;
        // The first candidate always wins; after that only a strict improvement
        // displaces it, so a tie keeps the relay that sorts first. Upstream's
        // `(r.preferred_relay.is_none() || best < best_any)`.
        if (report.preferred_relay == null or best < best_any) {
            best_any = best;
            report.preferred_relay = entry.relay;
        }
    }

    if (history.last) |last| {
        const current = last.preferred_relay orelse return;
        const moved = report.preferred_relay == null or
            report.preferred_relay.?.order(current) != .eq;
        // Two thirds, floored: `(latency / 3) * 2` upstream, and the comparison
        // is strict so a challenger that is exactly two thirds does not move us.
        if (moved and current_latency != 0 and best_any > @divFloor(current_latency, 3) * 2) {
            report.preferred_relay = current;
        }
    }
}

const t = std.testing;
/// Ten minutes in, on the timeline the tests hand to `fold`. Past
/// `max_report_age`, so a vector can place a report on either side of the
/// window, and far past every probe instant below.
const test_now: Nanos = 600 * std.time.ns_per_s;
/// A duration in the units the report counts in, so the vectors read as
/// milliseconds rather than as nine-digit integers.
fn millis(n: u64) Nanos {
    return n * std.time.ns_per_ms;
}
/// A relay URL for a test vector, rendered into `scratch` and parsed from it.
/// The host is `<n>.example.`, so the URLs sort by index. `parse` copies the
/// host, so one `scratch` serves the whole test — the value carries no borrow.
fn namedRelay(scratch: []u8, index: usize) !RelayUrl {
    return RelayUrl.parse(try std.fmt.bufPrint(scratch, "https://{d}.example./", .{index}));
}
const public_v4: SocketAddr = .{ .ip = .{ .v4 = .{ 198, 51, 100, 7 } }, .port = 41234 };
const other_v4: SocketAddr = .{ .ip = .{ .v4 = .{ 198, 51, 100, 9 } }, .port = 51234 };
const public_v6: SocketAddr = .{
    .ip = .{ .v6 = .{
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
        0,    0,    0,    0,    0, 0, 0, 0x07,
    } },
    .port = 41234,
};
test "two probes that report the same public address do not vary" {
    const a = try RelayUrl.parse("https://a.example./");
    const b = try RelayUrl.parse("https://b.example./");
    const report = fold(&.{
        .{ .qad_ipv4 = .{
            .relay = a,
            .instant = test_now - millis(50),
            .latency = millis(10),
            .addr = public_v4,
        } },
        .{ .qad_ipv4 = .{
            .relay = b,
            .instant = test_now - millis(40),
            .latency = millis(12),
            .addr = public_v4,
        } },
    }, .{}, test_now);

    try t.expectEqual(@as(?bool, false), report.mapping_varies_by_dest_ipv4);
    try t.expectEqual(@as(?bool, null), report.mapping_varies_by_dest_ipv6);
    // The combined answer takes the family that answered, and null means
    // unclassified, not stable.
    try t.expectEqual(@as(?bool, false), report.mappingVariesByDest());
    try t.expect(report.udp_v4);
    try t.expect(!report.udp_v6);
    try t.expectEqual(public_v4, report.global_v4.?);
}
test "two probes that report different public addresses vary by destination" {
    const a = try RelayUrl.parse("https://a.example./");
    const b = try RelayUrl.parse("https://b.example./");
    const report = fold(&.{
        .{ .qad_ipv4 = .{
            .relay = a,
            .instant = test_now - millis(50),
            .latency = millis(10),
            .addr = public_v4,
        } },
        .{ .qad_ipv4 = .{
            .relay = b,
            .instant = test_now - millis(40),
            .latency = millis(12),
            .addr = other_v4,
        } },
    }, .{}, test_now);

    try t.expectEqual(@as(?bool, true), report.mapping_varies_by_dest_ipv4);
    try t.expectEqual(@as(?bool, true), report.mappingVariesByDest());
    try t.expect(report.udp_v4);
}
test "one probe has nothing to compare against" {
    // The distinction that matters: null is "never classified". Reporting false
    // here would claim a symmetric NAT from a single observation, and a symmetric
    // NAT is the easy case — hole punching assumes the hard one.
    const a = try RelayUrl.parse("https://a.example./");
    const report = fold(&.{
        .{ .qad_ipv4 = .{
            .relay = a,
            .instant = test_now - millis(50),
            .latency = millis(10),
            .addr = public_v4,
        } },
    }, .{}, test_now);

    try t.expectEqual(@as(?bool, null), report.mapping_varies_by_dest_ipv4);
    try t.expectEqual(@as(?bool, null), report.mappingVariesByDest());
    // The address is still reported: one probe is enough to publish, and is not
    // enough to classify.
    try t.expectEqual(public_v4, report.global_v4.?);
    try t.expect(report.hasUdp());
}
test "the two families answer the combined question with or" {
    const a = try RelayUrl.parse("https://a.example./");
    const b = try RelayUrl.parse("https://b.example./");
    const both = fold(&.{
        .{ .qad_ipv4 = .{
            .relay = a,
            .instant = test_now - millis(50),
            .latency = millis(10),
            .addr = public_v4,
        } },
        .{ .qad_ipv4 = .{
            .relay = b,
            .instant = test_now - millis(40),
            .latency = millis(12),
            .addr = public_v4,
        } },
        .{ .qad_ipv6 = .{
            .relay = a,
            .instant = test_now - millis(50),
            .latency = millis(30),
            .addr = public_v6,
        } },
        .{ .qad_ipv6 = .{
            .relay = b,
            .instant = test_now - millis(40),
            .latency = millis(31),
            .addr = .{ .ip = .{ .v6 = public_v6.ip.v6 }, .port = 41235 },
        } },
    }, .{}, test_now);

    // v4 agrees, v6 does not: one varying family makes the mapping varying.
    try t.expectEqual(@as(?bool, false), both.mapping_varies_by_dest_ipv4);
    try t.expectEqual(@as(?bool, true), both.mapping_varies_by_dest_ipv6);
    try t.expectEqual(@as(?bool, true), both.mappingVariesByDest());
}
test "an address of the wrong family is a measurement and nothing more" {
    // Upstream logs this and returns after the latency has already been
    // recorded. The address is dropped, so the family is neither proved working
    // nor classified.
    const a = try RelayUrl.parse("https://a.example./");
    const report = fold(&.{
        .{ .qad_ipv4 = .{
            .relay = a,
            .instant = test_now - millis(50),
            .latency = millis(10),
            .addr = public_v6,
        } },
    }, .{}, test_now);

    try t.expect(!report.udp_v4);
    try t.expect(!report.hasUdp());
    try t.expectEqual(@as(?SocketAddr, null), report.global_v4);
    try t.expectEqual(@as(?bool, null), report.mapping_varies_by_dest_ipv4);
    // The latency stands: the relay did answer.
    try t.expectEqual(millis(10), report.relay_latency.get(a).?);
}
test "folding nothing produces a report that claims nothing" {
    const report = fold(&.{}, .{}, test_now);

    try t.expect(!report.udp_v4);
    try t.expect(!report.udp_v6);
    try t.expect(!report.hasUdp());
    try t.expectEqual(@as(?bool, null), report.mapping_varies_by_dest_ipv4);
    try t.expectEqual(@as(?bool, null), report.mapping_varies_by_dest_ipv6);
    try t.expectEqual(@as(?bool, null), report.mappingVariesByDest());
    try t.expectEqual(@as(?RelayUrl, null), report.preferred_relay);
    try t.expectEqual(@as(?SocketAddr, null), report.global_v4);
    try t.expectEqual(@as(?SocketAddr, null), report.global_v6);
    try t.expectEqual(@as(?bool, null), report.captive_portal);
    var iterator = report.relay_latency.iter();
    try t.expectEqual(@as(?RelayLatencies.Entry, null), iterator.next());
}
test "the public address is the one on the best observation" {
    const a = try RelayUrl.parse("https://a.example./");
    const b = try RelayUrl.parse("https://b.example./");

    // Fastest wins, and the port rides with the address.
    const fastest = fold(&.{
        .{ .qad_ipv4 = .{
            .relay = a,
            .instant = test_now - millis(50),
            .latency = millis(10),
            .addr = public_v4,
        } },
        .{ .qad_ipv4 = .{
            .relay = b,
            .instant = test_now - millis(40),
            .latency = millis(20),
            .addr = other_v4,
        } },
    }, .{}, test_now);
    try t.expectEqual(public_v4, fastest.global_v4.?);

    // Equal latency, so the fresher observation wins — and it is a property of
    // the probe, not of where it sat in the slice.
    const tied = fold(&.{
        .{ .qad_ipv4 = .{
            .relay = a,
            .instant = test_now - millis(50),
            .latency = millis(10),
            .addr = public_v4,
        } },
        .{ .qad_ipv4 = .{
            .relay = b,
            .instant = test_now - millis(10),
            .latency = millis(10),
            .addr = other_v4,
        } },
    }, .{}, test_now);
    try t.expectEqual(other_v4, tied.global_v4.?);
    // Whichever way that went, the two addresses disagree, so the mapping is
    // destination-dependent and the choice above is only which one to publish.
    try t.expectEqual(@as(?bool, true), tied.mapping_varies_by_dest_ipv4);
}
test "the preferred relay is the lowest recent latency" {
    const a = try RelayUrl.parse("https://a.example./");
    const b = try RelayUrl.parse("https://b.example./");
    const c = try RelayUrl.parse("https://c.example./");
    const report = fold(&.{
        .{ .https = .{ .relay = a, .instant = test_now, .latency = millis(50) } },
        .{ .https = .{ .relay = b, .instant = test_now, .latency = millis(20) } },
        .{ .https = .{ .relay = c, .instant = test_now, .latency = millis(30) } },
    }, .{}, test_now);

    try t.expectEqual(std.math.Order.eq, report.preferred_relay.?.order(b));
}
test "a report outside the age window stops steering the preferred relay" {
    // Same probes both times, and the history is the only thing that changes:
    // b looks better than it is while its report is still in the window.
    const a = try RelayUrl.parse("https://a.example./");
    const b = try RelayUrl.parse("https://b.example./");
    const probes = [_]ProbeResult{
        .{ .https = .{ .relay = a, .instant = test_now, .latency = millis(20) } },
        .{ .https = .{ .relay = b, .instant = test_now, .latency = millis(30) } },
    };
    var old_report: Report = .{};
    try t.expect(old_report.relay_latency.update(b, millis(5), .https));
    const fresh = fold(&probes, .{
        .entries = &.{.{ .instant = test_now - millis(1), .report = old_report }},
    }, test_now);
    try t.expectEqual(std.math.Order.eq, fresh.preferred_relay.?.order(b));

    // Same claim, one nanosecond too old. `now` is the only clock in the fold,
    // and moving it is the only thing that retires the measurement.
    const stale = fold(&probes, .{
        .entries = &.{.{ .instant = test_now - max_report_age - 1, .report = old_report }},
    }, test_now);
    try t.expectEqual(std.math.Order.eq, stale.preferred_relay.?.order(a));

    // An entry stamped in the future is not stale; it is not yet old.
    const ahead = fold(&probes, .{
        .entries = &.{.{ .instant = test_now + millis(1), .report = old_report }},
    }, test_now);
    try t.expectEqual(std.math.Order.eq, ahead.preferred_relay.?.order(b));
}
test "the preferred relay holds unless a challenger beats two thirds" {
    const a = try RelayUrl.parse("https://a.example./");
    const b = try RelayUrl.parse("https://b.example./");
    const last: Report = .{ .preferred_relay = a };

    // Hysteresis holds the current relay while the challenger's best recent
    // latency is more than two thirds of it. Against a's 30 ms that line is
    // 20 ms, and the comparison is strict, so 20 ms is enough to move and
    // 20 ms + 1 ns is not.
    const held = fold(&.{
        .{ .https = .{ .relay = a, .instant = test_now, .latency = millis(30) } },
        .{ .https = .{ .relay = b, .instant = test_now, .latency = millis(21) } },
    }, .{ .last = last }, test_now);
    try t.expectEqual(std.math.Order.eq, held.preferred_relay.?.order(a));

    const exact = fold(&.{
        .{ .https = .{ .relay = a, .instant = test_now, .latency = millis(30) } },
        .{ .https = .{ .relay = b, .instant = test_now, .latency = millis(20) } },
    }, .{ .last = last }, test_now);
    try t.expectEqual(std.math.Order.eq, exact.preferred_relay.?.order(b));

    const decisive = fold(&.{
        .{ .https = .{ .relay = a, .instant = test_now, .latency = millis(30) } },
        .{ .https = .{ .relay = b, .instant = test_now, .latency = millis(19) } },
    }, .{ .last = last }, test_now);
    try t.expectEqual(std.math.Order.eq, decisive.preferred_relay.?.order(b));

    // With no previous relay there is nothing to hold, so the same measurement
    // moves at once.
    const first = fold(&.{
        .{ .https = .{ .relay = a, .instant = test_now, .latency = millis(30) } },
        .{ .https = .{ .relay = b, .instant = test_now, .latency = millis(20) } },
    }, .{}, test_now);
    try t.expectEqual(std.math.Order.eq, first.preferred_relay.?.order(b));
}
test "a classification carries forward until it is measured again" {
    const a = try RelayUrl.parse("https://a.example./");
    const last: Report = .{ .mapping_varies_by_dest_ipv4 = true, .udp_v4 = true };

    // A round that only managed an HTTPS probe knows nothing new about the
    // mapping, and says what it last knew rather than claiming to have reset.
    const carried = fold(
        &.{.{ .https = .{ .relay = a, .instant = test_now, .latency = millis(10) } }},
        .{ .last = last },
        test_now,
    );
    try t.expectEqual(@as(?bool, true), carried.mapping_varies_by_dest_ipv4);
    try t.expectEqual(@as(?bool, null), carried.mapping_varies_by_dest_ipv6);
    // The carry-over is a classification, not a measurement: no UDP round trip
    // happened this round and the report does not claim one did.
    try t.expect(!carried.udp_v4);

    // A fresh answer replaces it.
    const b = try RelayUrl.parse("https://b.example./");
    const replaced = fold(&.{
        .{ .qad_ipv4 = .{
            .relay = a,
            .instant = test_now,
            .latency = millis(10),
            .addr = public_v4,
        } },
        .{ .qad_ipv4 = .{
            .relay = b,
            .instant = test_now,
            .latency = millis(11),
            .addr = public_v4,
        } },
    }, .{ .last = last }, test_now);
    try t.expectEqual(@as(?bool, false), replaced.mapping_varies_by_dest_ipv4);
}
/// The ordering the permutation test walks. Four probes have 24 orderings, and
/// the test covers all of them rather than a sample.
const permutation_count = 4 * 3 * 2 * 1;
/// Scratch space for one ordering, sized to the probe set below.
const permutation_arena = 4;
/// Fold `remaining` in every order, each one appended to `order`, and write each
/// resulting report to `out`. Recursion over what is left, so every ordering is
/// produced once and every probe reaches every position.
fn forEachOrder(
    order: []const ProbeResult,
    remaining: []const ProbeResult,
    out: []Report,
) usize {
    if (remaining.len == 0) {
        out[0] = fold(order, .{}, test_now);
        return 1;
    }
    var written: usize = 0;
    for (remaining, 0..) |probe, index| {
        var rest: [permutation_arena]ProbeResult = undefined;
        @memcpy(rest[0..index], remaining[0..index]);
        @memcpy(rest[index .. remaining.len - 1], remaining[index + 1 ..]);
        var next: [permutation_arena]ProbeResult = undefined;
        @memcpy(next[0..order.len], order);
        next[order.len] = probe;
        written += forEachOrder(
            next[0 .. order.len + 1],
            rest[0 .. remaining.len - 1],
            out[written..],
        );
    }
    return written;
}
test "the fold is the same report for every ordering of the same probes" {
    const a = try RelayUrl.parse("https://a.example./");
    const b = try RelayUrl.parse("https://b.example./");
    const c = try RelayUrl.parse("https://c.example./");
    const d = try RelayUrl.parse("https://d.example./");
    const probes = [_]ProbeResult{
        .{ .https = .{ .relay = a, .instant = test_now - millis(50), .latency = millis(50) } },
        .{ .qad_ipv4 = .{
            .relay = b,
            .instant = test_now - millis(40),
            .latency = millis(10),
            .addr = public_v4,
        } },
        .{ .qad_ipv4 = .{
            .relay = c,
            .instant = test_now - millis(30),
            .latency = millis(20),
            .addr = other_v4,
        } },
        .{ .qad_ipv6 = .{
            .relay = d,
            .instant = test_now - millis(20),
            .latency = millis(30),
            .addr = public_v6,
        } },
    };
    const baseline = fold(&probes, .{}, test_now);

    // The arena and the count are sized to this set. A fifth probe would be a
    // bounds panic rather than a failing assertion, so tie them here.
    try t.expectEqual(@as(usize, permutation_arena), probes.len);
    var results: [permutation_count]Report = undefined;
    const count = forEachOrder(&.{}, &probes, &results);
    try t.expectEqual(@as(usize, permutation_count), count);
    for (results[0..count]) |got| try t.expect(baseline.eql(got));

    // The property is only worth having if the fold produces something. Pin the
    // report these probes describe: two v4 observations that disagree, one v6
    // observation with nothing to compare against, and the fastest relay.
    try t.expect(baseline.udp_v4);
    try t.expect(baseline.udp_v6);
    try t.expectEqual(@as(?bool, true), baseline.mapping_varies_by_dest_ipv4);
    try t.expectEqual(@as(?bool, null), baseline.mapping_varies_by_dest_ipv6);
    try t.expectEqual(@as(?bool, true), baseline.mappingVariesByDest());
    try t.expectEqual(public_v4, baseline.global_v4.?);
    try t.expectEqual(public_v6, baseline.global_v6.?);
    try t.expectEqual(std.math.Order.eq, baseline.preferred_relay.?.order(b));
}

test "a report prints the claims it can make" {
    var buffer: [256]u8 = undefined;

    const empty = try std.fmt.bufPrint(&buffer, "{f}", .{fold(&.{}, .{}, test_now)});
    try t.expect(std.mem.indexOf(u8, empty, "varies_by_dest: null/null") != null);
    try t.expect(std.mem.indexOf(u8, empty, "captive_portal: null") != null);
    try t.expect(std.mem.indexOf(u8, empty, "preferred_relay: none") != null);

    const a = try RelayUrl.parse("https://a.example./");
    const measured = fold(
        &.{.{ .qad_ipv4 = .{
            .relay = a,
            .instant = test_now,
            .latency = millis(10),
            .addr = public_v4,
        } }},
        .{},
        test_now,
    );
    const text = try std.fmt.bufPrint(&buffer, "{f}", .{measured});
    try t.expect(std.mem.indexOf(u8, text, "udp_v4: true") != null);
    try t.expect(std.mem.indexOf(u8, text, "varies_by_dest: null/null") != null);
    try t.expect(std.mem.indexOf(u8, text, "preferred_relay: https://a.example./") != null);
    try t.expect(std.mem.indexOf(u8, text, "global_v4: 198.51.100.7:41234") != null);
}
