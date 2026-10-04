//! When these answers end the round.
//!
//! Upstream's `have_enough_reports` at `iroh/src/net_report.rs:661-746`, arm
//! for arm, plus the two helpers it is written on. It is a rule about answers
//! and not about tasks: it reads a results slice and an `IfState`, and it has
//! no opinion about which task is open or when it was sent. `probe.zig` decides
//! what to run and `probe_step.zig` holds the runner; this is the one question
//! whose answer is the same whichever of the two is asked.
//!
//! The HTTPS arm is upstream's too and it is the loosest of the three: one
//! answer per planned relay is enough whatever else is missing, because an
//! HTTPS answer still times a relay and still feeds the preferred-relay choice.
//! A round that reaches it is a round that learned no NAT and homed on a relay,
//! which is a real and useful answer.
//!
//! # Why one observation classifies nothing
//!
//! Every QAD quota here is at least two answers of a family, because the
//! question a quota exists to answer is whether two probes to *different* relays
//! reported different public addresses — a property of the set, not of one
//! answer. `report_claim.Varying` classifies a single observation as "not
//! measured" rather than as symmetric, and a quota of one would contradict it
//! by claiming the round had enough.

const std = @import("std");
const addr = @import("../base/addr.zig");
const base_relay_url = @import("../base/relay_url.zig");
const probe = @import("probe.zig");
const report = @import("report.zig");

/// The plan's vocabulary, named once per source. `IfState` and the probe kinds
/// are the plan's because a quota is asked about a plan that ran, and
/// `ProbeResult` is the report's because a quota counts answers.
const IfState = probe.IfState;
const enough_endpoints = probe.enough_endpoints;
const qadResult = probe.qadResult;
const Nanos = report.Nanos;
const Probe = report.Probe;
const ProbeResult = report.ProbeResult;

const RelayUrl = base_relay_url.RelayUrl;
const SocketAddr = addr.SocketAddr;

/// How many relays have a latency recorded in `probe`. Upstream's
/// `have_enough_reports` counts entries of the three `BTreeMap`s in
/// `RelayLatencies`, so two answers to one relay count once: `update_relay`
/// keeps the faster of them and the map still holds a single entry.
///
/// A walk rather than a bit set, because a result may name a relay the plan
/// does not contain. Upstream seeds a report with whatever a live QUIC
/// connection last saw, and that relay need not be one this round plans:
/// `spawn_qad_probes` truncates to `MAX_RELAYS` and `QadConns::current_v4`
/// does not. The count therefore has to be over relay URLs and not over plan
/// positions.
///
/// A `usize`, not a `u8`: the only ceiling on a results slice is the one its
/// caller brought. `Results.push` caps this module's own results at
/// `max_results`, and a count narrowed below even that would be a bound proved
/// nowhere for a list this module did not fill.
pub fn measured(probe: Probe, results: []const ProbeResult) usize {
    var count: usize = 0;
    for (results, 0..) |result, index| {
        if (result.kind() != probe) continue;
        if (countedBefore(results[0..index], probe, result.relay())) continue;
        count += 1;
    }
    return count;
}
fn countedBefore(earlier: []const ProbeResult, probe: Probe, relay: RelayUrl) bool {
    for (earlier) |result| {
        if (result.kind() != probe) continue;
        if (result.relay().order(relay) == .eq) return true;
    }
    return false;
}
/// A shape of answers that satisfies a round.
pub const Quota = struct { ipv4: u8, ipv6: u8 };
/// The (v4, v6) shapes that end a round, per host capability. Upstream's
/// `have_enough_reports` match on `(have_v4, have_v6)`, read as a list because
/// the full arm admits two of them: two v4 answers with one v6, or two v6 with
/// one v4.
///
/// Two of one family and one of the other is the smallest count that can both
/// prove UDP works and compare two public addresses from different relays — a
/// single answer compares against nothing, which is why `claim.Varying`
/// classifies one observation as "not measured" rather than as symmetric.
fn quotas(state: IfState, full: bool) []const Quota {
    if (state.have_v4 and state.have_v6) {
        return if (full)
            &.{ .{ .ipv4 = 2, .ipv6 = 1 }, .{ .ipv4 = 1, .ipv6 = 2 } }
        else
            &.{.{ .ipv4 = 1, .ipv6 = 1 }};
    }
    if (state.have_v4) {
        return if (full) &.{.{ .ipv4 = 2, .ipv6 = 0 }} else &.{.{ .ipv4 = 1, .ipv6 = 0 }};
    }
    if (state.have_v6) {
        return if (full) &.{.{ .ipv4 = 0, .ipv6 = 2 }} else &.{.{ .ipv4 = 0, .ipv6 = 1 }};
    }
    // No address family at all: no QAD probe is ever spawned, so no QAD answer
    // can arrive and the HTTPS check is the only way a round can end.
    return &.{};
}
/// `net_report.rs:661-746`, arm for arm.
///
/// The HTTPS arm is upstream's too and it is the loosest of the three: one
/// answer per planned relay is enough whatever else is missing, because an
/// HTTPS answer still times a relay and still feeds the preferred-relay
/// choice. A round that reaches it is a round that learned no NAT and homed on
/// a relay, which is a real and useful answer.
pub fn haveEnough(
    results: []const ProbeResult,
    if_state: IfState,
    full: bool,
    enough_relays: usize,
) bool {
    // The counts are `usize` because a count is however many answers the
    // caller's list holds, and the quota is a `u8` because a shape is
    // something this module writes.
    const ipv4 = measured(.qad_ipv4, results);
    const ipv6 = measured(.qad_ipv6, results);
    const https = measured(.https, results);
    for (quotas(if_state, full)) |quota| {
        if (ipv4 >= @as(usize, quota.ipv4) and ipv6 >= @as(usize, quota.ipv6)) return true;
    }
    return https >= enough_relays;
}

const t = std.testing;
/// A minute in, on the timeline the tests hand to the runner. Five minutes is
/// `full_report_interval`, so a round stamped with it is incremental and one
/// left at zero is a full round for being stale.
const test_start: Nanos = 600 * std.time.ns_per_s;
fn millis(n: u64) Nanos {
    return n * std.time.ns_per_ms;
}
/// A relay URL rendered into `scratch`. The host is `<n>.example.`, so the
/// URLs sort by index and the fold's relay ordering is predictable.
fn namedRelay(scratch: []u8, index: usize) !RelayUrl {
    return RelayUrl.parse(try std.fmt.bufPrint(scratch, "https://{d}.example./", .{index}));
}
/// Three relays, in relay-map order.
fn relaySet(scratch: []u8) ![3]RelayUrl {
    return .{
        try namedRelay(scratch[0..64], 0),
        try namedRelay(scratch[64..128], 1),
        try namedRelay(scratch[128..192], 2),
    };
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
test "an incremental round ends at one answer per family, a full one at two" {
    var scratch: [192]u8 = undefined;
    const relays = try relaySet(&scratch);
    const dual: IfState = .{ .have_v4 = true, .have_v6 = true };
    const enough: usize = enough_endpoints;

    const v4_a = qadResult(.v4, relays[0], test_start, millis(9), public_v4);
    const v4_b = qadResult(.v4, relays[1], test_start, millis(9), other_v4);
    const v6_a = qadResult(.v6, relays[0], test_start, millis(9), public_v6);
    const v6_b = qadResult(.v6, relays[1], test_start, millis(9), public_v6);

    // Incremental: one of each family, in either order, and one alone is not
    // enough for a host that has both.
    try t.expect(!haveEnough(&.{v4_a}, dual, false, enough));
    try t.expect(!haveEnough(&.{v6_a}, dual, false, enough));
    try t.expect(haveEnough(&.{ v4_a, v6_a }, dual, false, enough));
    try t.expect(haveEnough(&.{ v6_a, v4_a }, dual, false, enough));
    // Full: the same two are not. The two admitted shapes are two of one
    // family *and* one of the other, and two of one with none of the other is
    // not a shape — the other family is what proves the other family works.
    try t.expect(!haveEnough(&.{ v4_a, v6_a }, dual, true, enough));
    try t.expect(!haveEnough(&.{ v4_a, v4_b }, dual, true, enough));
    try t.expect(haveEnough(&.{ v4_a, v4_b, v6_a }, dual, true, enough));
    try t.expect(haveEnough(&.{ v4_a, v6_a, v6_b }, dual, true, enough));
    // A host with one family needs two of it on a full round and one on an
    // incremental one.
    const v4_only: IfState = .{ .have_v4 = true, .have_v6 = false };
    try t.expect(haveEnough(&.{v4_a}, v4_only, false, enough));
    try t.expect(!haveEnough(&.{v4_a}, v4_only, true, enough));
    try t.expect(haveEnough(&.{ v4_a, v4_b }, v4_only, true, enough));
    // A host with neither never gets a QUIC answer, so only HTTPS can end it.
    const no_addr: IfState = .{};
    try t.expect(!haveEnough(&.{ v4_a, v4_b }, no_addr, true, enough));
    try t.expect(haveEnough(&.{
        .{ .https = .{ .relay = relays[0], .instant = test_start, .latency = millis(9) } },
        .{ .https = .{ .relay = relays[1], .instant = test_start, .latency = millis(9) } },
        .{ .https = .{ .relay = relays[2], .instant = test_start, .latency = millis(9) } },
    }, no_addr, true, enough));
    // One answer per relay is the HTTPS arm, and it is enough whatever else is
    // missing.
    try t.expect(haveEnough(&.{
        .{ .https = .{ .relay = relays[0], .instant = test_start, .latency = millis(9) } },
    }, dual, true, 1));
    try t.expect(!haveEnough(&.{
        .{ .https = .{ .relay = relays[0], .instant = test_start, .latency = millis(9) } },
    }, dual, true, 2));
}
test "two answers to one relay count once, as upstream's map does" {
    var scratch: [192]u8 = undefined;
    const relays = try relaySet(&scratch);
    const results = [_]ProbeResult{
        .{ .https = .{ .relay = relays[0], .instant = test_start, .latency = millis(40) } },
        .{ .https = .{ .relay = relays[0], .instant = test_start, .latency = millis(12) } },
        .{ .https = .{ .relay = relays[1], .instant = test_start, .latency = millis(30) } },
        qadResult(.v4, relays[0], test_start, millis(9), public_v4),
    };
    try t.expectEqual(@as(usize, 2), measured(.https, &results));
    try t.expectEqual(@as(usize, 1), measured(.qad_ipv4, &results));
    try t.expectEqual(@as(usize, 0), measured(.qad_ipv6, &results));
}
