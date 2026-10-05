//! Net report: what this node's NAT looks like from the outside.
//!
//! Upstream runs probes, opens sockets and drives a QUIC address-discovery
//! exchange. None of that is here. What is here is the fold from probe results
//! to a report, and the classifier that fold runs, and both are a function of
//! their arguments: a probe carries the instant it was observed, the caller
//! passes the current one, and the result is a value. Nothing below
//! `ozai.base` may read a clock, and this is what that rule buys — a test
//! drives the fold instead of a network.
//!
//! Upstream, captured 2026-09-30 at n0-computer/iroh commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8 (the `iroh` 1.3.0 crate as
//! published): `Report` and `RelayLatencies` from `iroh/src/net_report/report.rs`,
//! `Probe` from `iroh/src/net_report/probes.rs`, the probe payloads and the fold
//! from `iroh/src/net_report/reportgen.rs`, and the preferred-relay choice from
//! `iroh/src/net_report.rs`. Every field and every rule below is one of those
//! files', and each is named in the comment that reproduces it.
//!
//! # What lives where
//!
//! This file is the facade. Three modules hold the bodies:
//!
//! - `report_measure.zig` — what a probe round hands the fold: `Probe`,
//!   `QadProbe`, `HttpsProbe`, `ProbeResult` and the `RelayLatencies` table.
//! - `report_fold.zig` — `Varying`, `Report`, `History` and `fold` itself.
//! - `user_data.zig` — `UserData` and the 245-byte DNS TXT limit.
//!
//! Every declaration the facade published before the split is re-exported here,
//! so a caller outside `src/net/` is unchanged.
//!
//! `UserData` is the exception upstream and is called out as such: it is not on
//! the report upstream, it is on `EndpointData`, and it lives in
//! `iroh-dns/src/endpoint_info.rs` at the same commit. It is here because the
//! 245 is a discovery-layer number and the milestone lists it, not because the
//! report carries one.

const std = @import("std");
const addr = @import("../base/addr.zig");

const measure = @import("report_measure.zig");
const fold_mod = @import("report_fold.zig");
const user_data = @import("user_data.zig");

const RelayUrl = addr.RelayUrl;
const SocketAddr = addr.SocketAddr;

// The measured values the fold consumes.
pub const Nanos = measure.Nanos;
pub const max_report_age = measure.max_report_age;
pub const Probe = measure.Probe;
pub const QadProbe = measure.QadProbe;
pub const HttpsProbe = measure.HttpsProbe;
pub const ProbeResult = measure.ProbeResult;
pub const RelayLatency = measure.RelayLatency;
pub const max_relays = measure.max_relays;
pub const RelayLatencies = measure.RelayLatencies;

// The fold.
pub const Varying = fold_mod.Varying;
pub const Report = fold_mod.Report;
pub const HistoryEntry = fold_mod.HistoryEntry;
pub const History = fold_mod.History;
pub const fold = fold_mod.fold;

// The endpoint metadata the milestone listed beside the report.
pub const max_user_data_length = user_data.max_user_data_length;
pub const UserDataError = user_data.UserDataError;
pub const UserData = user_data.UserData;

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

test "a relay keeps the fastest latency ever measured to it" {
    const a = try RelayUrl.parse("https://a.example./");
    const b = try RelayUrl.parse("https://b.example./");
    var latencies: RelayLatencies = .{};

    // Nothing measured yet.
    try t.expectEqual(@as(?Nanos, null), latencies.get(a));

    try t.expect(latencies.update(a, millis(40), .https));
    try t.expectEqual(millis(40), latencies.get(a).?);

    // Slower, and it is discarded: upstream's `if latency < old_latency`.
    try t.expect(latencies.update(a, millis(90), .https));
    try t.expectEqual(millis(40), latencies.get(a).?);

    // Faster, and it is kept.
    try t.expect(latencies.update(a, millis(8), .https));
    try t.expectEqual(millis(8), latencies.get(a).?);

    // The families are separate: an HTTPS probe and a v4 probe to one relay are
    // two measurements, and `get` is the fastest of the two.
    try t.expect(latencies.update(a, millis(20), .qad_ipv4));
    try t.expectEqual(millis(8), latencies.get(a).?);

    // A single element is a list, and the list stays sorted: https first, then
    // the address-discovery families, each ascending by relay.
    try t.expect(latencies.update(b, millis(30), .qad_ipv4));
    try t.expectEqual(millis(30), latencies.get(b).?);

    var iterator = latencies.iter();
    const first = iterator.next() orelse return error.TestUnexpectedResult;
    try t.expectEqual(Probe.https, first.probe);
    try t.expectEqual(std.math.Order.eq, first.relay.order(a));
    try t.expectEqual(millis(8), first.latency);
    const second = iterator.next() orelse return error.TestUnexpectedResult;
    try t.expectEqual(Probe.qad_ipv4, second.probe);
    try t.expectEqual(std.math.Order.eq, second.relay.order(a));
    try t.expectEqual(millis(20), second.latency);
    const third = iterator.next() orelse return error.TestUnexpectedResult;
    try t.expectEqual(Probe.qad_ipv4, third.probe);
    try t.expectEqual(std.math.Order.eq, third.relay.order(b));
    try t.expectEqual(millis(30), third.latency);
    try t.expectEqual(@as(?RelayLatencies.Entry, null), iterator.next());
}

test "merging takes the fastest of both sets" {
    const a = try RelayUrl.parse("https://a.example./");
    const b = try RelayUrl.parse("https://b.example./");
    var older: RelayLatencies = .{};
    try t.expect(older.update(a, millis(50), .https));
    try t.expect(older.update(b, millis(5), .https));

    var newer: RelayLatencies = .{};
    try t.expect(newer.update(a, millis(20), .https));
    try t.expect(newer.update(b, millis(60), .https));

    newer.merge(&older);
    try t.expectEqual(millis(20), newer.get(a).?);
    try t.expectEqual(millis(5), newer.get(b).?);
}

test "a family holds as many relays as upstream probes" {
    // Upstream bounds the probe fan-out at `MAX_RELAYS = 5`, so a sixth relay
    // is never probed. The bound here is structural rather than a plan
    // constant, and this is what pins it to five.
    try t.expectEqual(@as(usize, 5), max_relays);

    var latencies: RelayLatencies = .{};
    var scratch: [32]u8 = undefined;
    for (0..max_relays + 1) |index| {
        // The sixth relay is the one that does not fit, and the list says so
        // rather than dropping the measurement in silence.
        const recorded = latencies.update(try namedRelay(&scratch, index), millis(10), .https);
        try t.expectEqual(index < max_relays, recorded);
    }
    try t.expectEqual(millis(10), latencies.get(try namedRelay(&scratch, 0)).?);

    // A relay already in the list is still improved when the list is full: the
    // bound is on new relays, not on measurements.
    try t.expect(latencies.update(try namedRelay(&scratch, 0), millis(5), .https));
    try t.expectEqual(millis(5), latencies.get(try namedRelay(&scratch, 0)).?);
    try t.expectEqual(@as(?Nanos, null), latencies.get(try namedRelay(&scratch, max_relays)));
}

test "an update in the middle of the order shifts the entries after it" {
    const Want = struct { relay: RelayUrl, latency: Nanos };
    const a = try RelayUrl.parse("https://a.example./");
    const b = try RelayUrl.parse("https://b.example./");
    const c = try RelayUrl.parse("https://c.example./");
    const d = try RelayUrl.parse("https://d.example./");
    var latencies: RelayLatencies = .{};

    // Ascending with a hole at `b`, so `b` lands at index 1 and the entries
    // behind it have somewhere to go. Appending shifts nothing, and updating a
    // relay that is already in the list does not shift at all.
    try t.expect(latencies.update(a, millis(10), .https));
    try t.expect(latencies.update(c, millis(30), .https));
    try t.expect(latencies.update(d, millis(40), .https));
    try t.expectEqual(@as(usize, 3), latencies.https.len);

    try t.expect(latencies.update(b, millis(20), .https));
    try t.expectEqual(@as(usize, 4), latencies.https.len);

    // Still ascending: `RelayList.get` gives up at the first entry that sorts
    // high, so order is what makes a lookup mean anything.
    const list = &latencies.https;
    var index: usize = 1;
    while (index < list.len) : (index += 1) {
        const ordered = list.items[index - 1].relay.order(list.items[index].relay);
        try t.expectEqual(std.math.Order.lt, ordered);
    }

    // Every relay recorded before the insert survived it. A shift that runs the
    // wrong way overwrites the entry one place along and loses the last one, so
    // this is where a lost entry shows up as a relay that was never measured.
    try t.expectEqual(@as(?Nanos, millis(10)), list.get(a));
    try t.expectEqual(@as(?Nanos, millis(20)), list.get(b));
    try t.expectEqual(@as(?Nanos, millis(30)), list.get(c));
    try t.expectEqual(@as(?Nanos, millis(40)), list.get(d));

    // Three relays in, four out, and the fourth is the one that was just
    // measured rather than a second copy of a neighbour.
    const expected = [_]Want{
        .{ .relay = a, .latency = millis(10) },
        .{ .relay = b, .latency = millis(20) },
        .{ .relay = c, .latency = millis(30) },
        .{ .relay = d, .latency = millis(40) },
    };
    var iterator = latencies.iter();
    for (expected) |want| {
        const entry = iterator.next() orelse return error.TestUnexpectedResult;
        try t.expectEqual(Probe.https, entry.probe);
        try t.expectEqual(std.math.Order.eq, entry.relay.order(want.relay));
        try t.expectEqual(want.latency, entry.latency);
    }
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

test "user data holds 245 bytes and not one more" {
    try t.expectEqual(@as(usize, 245), max_user_data_length);
    // 255 is a DNS TXT character-string and `user-data=` is ten bytes of it.
    try t.expectEqual(@as(usize, 255 - 10), max_user_data_length);
    try t.expectEqual(max_user_data_length, UserData.max_length);

    const empty = try UserData.init("");
    try t.expectEqualStrings("", empty.slice());

    const full = try UserData.init("x" ** max_user_data_length);
    try t.expectEqualStrings("x" ** max_user_data_length, full.slice());

    try t.expectError(
        error.MaxLengthExceeded,
        UserData.init("x" ** (max_user_data_length + 1)),
    );
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

test "the same relay is the same relay whatever the unused host tail holds" {
    // `RelayUrl.parse` copies the host into a 253-byte array and records only
    // how much of it it wrote. Everything that reads a relay — `format`,
    // `socketAddr`, `order`, `RelayList` — goes through `hostSlice`, so the
    // bytes past `host_length` are bytes nothing consults. Two URLs parsed
    // from the same text name the same relay whatever those bytes happen to
    // hold, and a report that has been through a struct copy still equals
    // itself.
    var first = try RelayUrl.parse("https://relay.example./");
    var second = try RelayUrl.parse("https://relay.example./");
    @memset(first.host[first.host_length..], 0x11);
    @memset(second.host[second.host_length..], 0x22);

    // The premise first: the two are one relay to every reader of the value.
    try t.expectEqual(std.math.Order.eq, first.order(second));
    try t.expectEqualStrings(first.hostSlice(), second.hostSlice());

    const a: Report = .{ .preferred_relay = first };
    const b: Report = .{ .preferred_relay = second };
    try t.expect(a.eql(b));
    try t.expect(b.eql(a));

    // `null` is a value of its own and not an absence of one: a report with no
    // preferred relay is not the same report as one that has chosen this.
    try t.expect(!a.eql(.{}));
    try t.expect((Report{}).eql(.{}));
    try t.expect(!(Report{}).eql(a));

    // And a different relay is still a different relay, so the host is not
    // simply being ignored: scheme, port and host bytes each decide it.
    try t.expect(!a.eql(.{ .preferred_relay = try RelayUrl.parse("https://other.example./") }));
    try t.expect(!a.eql(.{ .preferred_relay = try RelayUrl.parse("http://relay.example./") }));
    try t.expect(!a.eql(.{
        .preferred_relay = try RelayUrl.parse("https://relay.example.:8443/"),
    }));

    // The same rule reaches the latency table, which compared its relays by
    // `order` already: one relay measured twice is one entry, and two reports
    // that measured the same relay compare equal.
    var measured: Report = .{ .preferred_relay = first };
    try t.expect(measured.relay_latency.update(first, millis(10), .https));
    try t.expect(measured.relay_latency.update(second, millis(10), .https));
    try t.expectEqual(@as(usize, 1), measured.relay_latency.https.len);
    var twin: Report = .{ .preferred_relay = second };
    try t.expect(twin.relay_latency.update(second, millis(10), .https));
    try t.expect(measured.eql(twin));
}
