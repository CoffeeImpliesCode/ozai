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
//! Tests live beside what they test: the thirteen that drive `fold` are in
//! `report_fold.zig`. The six here are the ones that reach across a boundary —
//! four on the `RelayLatencies` table, one on the 245-byte limit, and one that
//! spans `base/addr.zig`, `Report.eql` and that same table at once.
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

// The fold's duration helper, aliased rather than copied: the tests this file
// still holds read in milliseconds, and the fold's tests read them at source.
const millis = fold_mod.millis;

/// A relay URL for a test vector, rendered into `scratch` and parsed from it.
/// The host is `<n>.example.`, so the URLs sort by index. `parse` copies the
/// host, so one `scratch` serves the whole test — the value carries no borrow.
fn namedRelay(scratch: []u8, index: usize) !RelayUrl {
    return RelayUrl.parse(try std.fmt.bufPrint(scratch, "https://{d}.example./", .{index}));
}

// Stays here: this drives `RelayLatencies`, which `report_measure.zig` owns.
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

// Stays here: `merge` and `get` are `report_measure.zig`'s table, not the fold's.
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

// Stays here: `max_relays` is `report_measure.zig`'s bound, not the fold's.
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

// Stays here: the ordering under test is `RelayLatencies`' own list.
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

// Stays here: the 245 is `user_data.zig`'s, and the report does not read it.
test "user data holds 245 bytes and not one more" {
    try t.expectEqual(@as(usize, 245), max_user_data_length);
    // 255 is a DNS TXT character-string and `user-data=` is ten bytes of it.
    try t.expectEqual(@as(usize, 255 - 10), max_user_data_length);
    try t.expectEqual(max_user_data_length, UserData.max_length);

    const empty = try UserData.init("");
    try t.expectEqualStrings("", empty.slice());

    const full = try UserData.init(&@as([max_user_data_length:0]u8, @splat('x')));
    try t.expectEqualStrings(&@as([max_user_data_length:0]u8, @splat('x')), full.slice());

    try t.expectError(
        error.MaxLengthExceeded,
        UserData.init(&@as([(max_user_data_length + 1):0]u8, @splat('x'))),
    );
}

// Stays here: it spans `base/addr.zig`, `Report.eql` and the latency table.
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
