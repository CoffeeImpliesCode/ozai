//! What a net report is made of: one probe's result, and the latency tables.
//!
//! Upstream runs probes, opens sockets and drives a QUIC address-discovery
//! exchange. None of that is here. What is here is the vocabulary the fold is
//! written in and the per-relay bookkeeping it writes into: `ProbeResult` with
//! its three arms, the `BTreeMap<RelayUrl, Duration>` upstream keeps three of,
//! and `UserData`.
//!
//! Upstream, captured 2026-09-30 at n0-computer/iroh commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8 (the `iroh` 1.3.0 crate as
//! published): `RelayLatencies` from `iroh/src/net_report/report.rs`, `Probe`
//! from `iroh/src/net_report/probes.rs`, the probe payloads from
//! `iroh/src/net_report/reportgen.rs`, and the `BTreeMap` probe fan-out from
//! `reportgen.rs:497`. Every field and every rule below is one of those files',
//! and each is named in the comment that reproduces it.
//!
//! Nothing below `ozai.base` may read a clock, and this is what that rule buys:
//! a probe carries the instant it was observed and the caller passes the
//! current one, so a test drives the arithmetic instead of a network.
//!
//! # The two siblings this was split into
//!
//! What was one file is three, in the order the data flows through them, and
//! this one is the leaf — it imports no sibling, so both of the others can name
//! everything here without a cycle.
//!
//! * `report_claim.zig` is what a report *claims*: the classifier
//!   (`Varying`), the `Report` itself and the `History` the fold reads. That is
//!   `Report::update`'s state upstream, held here as a value.
//! * `report_fold.zig` is `fold`, and the two private rules it applies:
//!   `beats`, which decides which observation of an address wins, and
//!   `choosePreferredRelay`, which is upstream's two-thirds hysteresis
//!   (`iroh/src/net_report.rs`).
//!
//! `UserData` is the exception and is called out as such: it is not on the
//! report upstream, it is on `EndpointData`, and it lives in
//! `iroh-dns/src/endpoint_info.rs` at the same commit. It is here because the
//! 245 is a discovery-layer number and the milestone lists it, not because the
//! report carries one.

const std = @import("std");
const addr = @import("../base/addr.zig");
const base_relay_url = @import("../base/relay_url.zig");

const RelayUrl = base_relay_url.RelayUrl;
const SocketAddr = addr.SocketAddr;

/// Nanoseconds on a monotonic timeline the caller owns.
///
/// Upstream has two types, `Duration` and `Instant`, and the distinction is
/// real: a latency is a length and cannot be negative. One unsigned integer
/// keeps the arithmetic honest, because the only subtraction the fold performs
/// is an age against a `now` it was handed, and that one saturates.
pub const Nanos = u64;
/// Upstream's `MAX_AGE`: how long a previous report still counts towards the
/// preferred relay. Five minutes is also how long a public address is worth
/// believing, so the two ages agreeing is not a coincidence worth relying on.
pub const max_report_age: Nanos = 5 * 60 * std.time.ns_per_s;
/// The protocol that timed a probe. Upstream's `Probe`.
///
/// It is the key the latencies are partitioned by rather than a label: HTTPS
/// and the two address-discovery families are measured independently, merged
/// only at the preferred-relay choice, and only a QAD probe can classify a NAT.
pub const Probe = enum {
    /// An empty HTTPS GET to the relay. Works where QUIC is blocked, and is the
    /// only probe a browser build has. It times a relay and learns nothing else.
    https,
    /// QUIC address discovery over IPv4: yields a public IPv4 socket address.
    qad_ipv4,
    /// QUIC address discovery over IPv6: yields a public IPv6 socket address.
    qad_ipv6,
};
/// One QUIC address discovery result. Upstream's `QadProbeReport`, which is
/// `{relay, latency, addr}`.
pub const QadProbe = struct {
    /// The relay that answered, held by value: this probe owns its `RelayUrl`
    /// in full and borrows nothing from whoever built it, so it can be copied
    /// into a report, kept in an array or compared without a lifetime to
    /// track. Two of these name the same relay when `RelayUrl.order` says so
    /// and not when their fields match, because only the host's first
    /// `host_length` bytes are part of the value.
    relay: RelayUrl,
    /// When the observation was made, in `Nanos`: nanoseconds on the caller's
    /// own monotonic timeline, the one `Nanos` defines. It is an instant and
    /// nothing here reads a clock to produce it — the fold compares it
    /// against the `now` it is given and against its siblings.
    instant: Nanos,
    /// The measured round trip, in `Nanos` on that same caller-owned timeline.
    ///
    /// A length, not an instant: no code here subtracts one, and the only
    /// subtraction the fold performs is an age against the `now` it was
    /// handed. What compares two latencies is `beats`, which reads fastest
    /// first and then freshest; see `ProbeResult.latency`.
    latency: Nanos,
    /// The public address the relay saw us come from.
    ///
    /// Its family is expected to match the probe that produced it, and nothing
    /// here enforces that — a v4 probe carrying a v6 address is a real thing
    /// that really happens, and upstream logs it. `fold` handles it; see the
    /// switch there for what it does with the address.
    addr: SocketAddr,
};
/// One HTTPS latency result. Upstream's `HttpsProbeReport`.
///
/// No address, which is the whole difference: an HTTPS probe can time a relay
/// and can never classify a NAT, so a fold over HTTPS probes alone reports a
/// mapping as unknown rather than as stable.
pub const HttpsProbe = struct {
    /// The relay that answered, owned by value and borrowing nothing, exactly
    /// as `QadProbe.relay` is.
    relay: RelayUrl,
    /// When the observation was made: `Nanos`, nanoseconds on the caller's own
    /// monotonic timeline. No HTTPS measurement reaches `Report.global_v4` or
    /// `Report.global_v6`, because an HTTPS probe has no address to put in
    /// either, but `instant` is carried and aged the same way regardless.
    instant: Nanos,
    /// The measured round trip in `Nanos`, the same figure and the same units
    /// as `QadProbe.latency`, and kept for the same reason: the fastest
    /// showing for a relay across every probe family is what `get` returns
    /// and what `choosePreferredRelay` compares.
    latency: Nanos,
};
/// One probe's result. Upstream's `ProbeReport`.
pub const ProbeResult = union(enum) {
    qad_ipv4: QadProbe,
    qad_ipv6: QadProbe,
    https: HttpsProbe,

    /// The partition this result belongs in.
    pub fn kind(self: ProbeResult) Probe {
        return switch (self) {
            .https => .https,
            .qad_ipv4 => .qad_ipv4,
            .qad_ipv6 => .qad_ipv6,
        };
    }

    /// By value, not by pointer. `ProbeResult` is passed around by value and a
    /// borrowed relay would point into whichever copy the caller happened to
    /// hold; the relay is already owned by whichever arm is active, so handing
    /// one back costs a copy of a value the caller then owns outright rather
    /// than a lifetime it has to track.
    pub fn relay(self: ProbeResult) RelayUrl {
        return switch (self) {
            .https => |probe| probe.relay,
            .qad_ipv4 => |probe| probe.relay,
            .qad_ipv6 => |probe| probe.relay,
        };
    }

    /// The measured latency, in nanoseconds on the caller's own timeline.
    ///
    /// Every arm carries the same figure and there is no arm without one, so
    /// this is total: a `ProbeResult` cannot name a relay it did not time.
    /// `instant` is not read here — a caller comparing two observations wants
    /// the cost, and `fold` is what decides which cost wins; see `beats`.
    pub fn latency(self: ProbeResult) Nanos {
        return switch (self) {
            .https => |probe| probe.latency,
            .qad_ipv4 => |probe| probe.latency,
            .qad_ipv6 => |probe| probe.latency,
        };
    }
};
/// A relay and the fastest latency measured to it in one probe family.
///
/// Upstream's `BTreeMap<RelayUrl, Duration>` entry: a key and the value that
/// key accumulated, which is where a key and a value being separate types
/// stops being a fiction.
pub const RelayLatency = struct {
    /// The relay this entry is about, owned by value and borrowing nothing.
    /// It is the key the enclosing `RelayList` is sorted and deduplicated by
    /// through `RelayUrl.order`, never field by field.
    relay: RelayUrl,
    /// The fastest latency seen to `relay` in this family, in `Nanos`:
    /// nanoseconds on the caller's own monotonic timeline, as `QadProbe.latency`
    /// and `HttpsProbe.latency` are.
    ///
    /// A minimum, not a last reading — `RelayList.update` keeps the smaller of
    /// the two. It is therefore *not* the entry's sort key: the list is
    /// ascending by relay URL, so the latencies in it are in no order at all.
    /// The fastest latency in a list is `RelayLatencies.get`; the fastest
    /// relay is `choosePreferredRelay`.
    latency: Nanos,
};
/// How many relays one family of a report carries a latency for.
///
/// Upstream's probe fan-out is bounded at `MAX_RELAYS = 5` in `reportgen.rs`, so
/// a sixth relay is never probed and there is nothing to record. Here the bound
/// is structural: the report is a value with no allocator behind it, so the list
/// is an inline array. `RelayList.update` reports whether a latency was
/// recorded, and the fold does not treat a full list as an error — a lost
/// measurement costs a slower preferred relay, not a wrong one.
pub const max_relays = 5;
/// One family's latencies, ascending by relay URL and one entry per relay.
///
/// Sorted rather than hashed because the order is load-bearing twice over: the
/// fold breaks a latency tie on the first relay it sees, and a report is a value
/// a test compares, so an insertion order would make it incomparable.
///
/// Sorted by relay and **not** by latency: the key is what the list is ordered
/// and deduplicated by, and each entry carries a minimum over everything ever
/// seen for its relay, so reading the list left to right gives relays in
/// `RelayUrl.order` and latencies in no order whatsoever. Nothing in this
/// package walks a list expecting the first entry to be the fastest one —
/// `RelayLatencies.get` is the way to ask for a relay's figure, and
/// `choosePreferredRelay` is the way to ask for the fastest relay.
const RelayList = struct {
    /// The entries, first `len` of them ascending by relay URL. Entries past
    /// `len` are never written and are never read, so a default value is a
    /// list with an entirely unspecified array behind it — a valid value, not
    /// a broken one.
    items: [max_relays]RelayLatency = undefined,
    /// How many entries of `items` are live. Zero by default, and never above
    /// `max_relays`: `update` drops a sixth relay rather than growing past it.
    len: usize = 0,

    fn get(self: *const RelayList, relay: RelayUrl) ?Nanos {
        var index: usize = 0;
        while (index < self.len) : (index += 1) {
            switch (self.items[index].relay.order(relay)) {
                .eq => return self.items[index].latency,
                .gt => return null,
                .lt => {},
            }
        }
        return null;
    }

    /// Record `latency` for `relay`, keeping the fastest seen. False when the
    /// list is full and the relay is one it has never seen.
    ///
    /// Upstream's `update_relay` is `entry(url).or_insert(latency)` followed by
    /// `if latency < old { *old = latency }`, which is a minimum over everything
    /// ever observed rather than a last-write-wins update. A relay that answers
    /// in 8 ms once and in 40 ms afterwards is recorded as 8 ms, which is most
    /// of what makes the preferred relay sticky.
    fn update(self: *RelayList, relay: RelayUrl, latency: Nanos) bool {
        var index: usize = 0;
        while (index < self.len) : (index += 1) {
            switch (self.items[index].relay.order(relay)) {
                .eq => {
                    if (latency < self.items[index].latency) self.items[index].latency = latency;
                    return true;
                },
                .gt => break,
                .lt => {},
            }
        }
        if (self.len == max_relays) return false;
        // `@memmove`, not `@memcpy`: the destination starts one entry *after*
        // the source, so the ranges overlap and a forward copy reads back the
        // entry it has already overwritten, dropping the tail. `@memmove`
        // picks the direction from the pointers, which is what `copyBackwards`
        // spelled by hand and is now deprecated.
        @memmove(self.items[index + 1 .. self.len + 1], self.items[index..self.len]);
        self.items[index] = .{ .relay = relay, .latency = latency };
        self.len += 1;
        return true;
    }
};
/// The measured latency to each relay, per probe family. Upstream's
/// `RelayLatencies`, which is three `BTreeMap`s keyed by relay.
///
/// The three families are measured independently and merged only where a
/// choice is made, so one relay can appear in all three lists at three
/// different figures and `get` returns the smallest of them. Read a family
/// through `iter`, `get` or `update`; the lists are `RelayList`s and their
/// fields are written by those.
///
/// Every list defaults to empty, and an empty list is not a measurement of
/// nothing: it is the statement that this family was never probed, which is
/// what keeps `Report.udp_v4` and `Report.udp_v6` independent of it.
pub const RelayLatencies = struct {
    /// What the HTTPS probes measured: one entry per relay those probes
    /// timed, ascending by `RelayUrl.order` and **not** by latency. Empty by
    /// default; `update` and `merge` are what put anything in it.
    https: RelayList = .{},
    /// The same for the IPv4 QUIC address-discovery probes, which are the
    /// family `Report.global_v4` is chosen from. Ascending by relay URL, empty
    /// by default.
    ipv4: RelayList = .{},
    /// The same for the IPv6 address-discovery probes, and the family
    /// `Report.global_v6` is chosen from. Ascending by relay URL, empty by
    /// default.
    ipv6: RelayList = .{},

    fn list(self: *RelayLatencies, probe: Probe) *RelayList {
        return switch (probe) {
            .https => &self.https,
            .qad_ipv4 => &self.ipv4,
            .qad_ipv6 => &self.ipv6,
        };
    }

    fn listConst(self: *const RelayLatencies, probe: Probe) *const RelayList {
        return switch (probe) {
            .https => &self.https,
            .qad_ipv4 => &self.ipv4,
            .qad_ipv6 => &self.ipv6,
        };
    }

    /// Iteration order: HTTPS first, then the two address-discovery families.
    ///
    /// Data rather than a switch someone can reorder, because the fold breaks a
    /// tie on the first relay it sees and this is that order.
    const family_order = [3]Probe{ .https, .qad_ipv4, .qad_ipv6 };

    /// One measurement, with the family it came from.
    pub const Entry = struct {
        /// The family this measurement was made in, which is the family the
        /// probe *ran* with rather than any family the relay answered in.
        probe: Probe,
        /// The relay measured, a by-value copy that borrows nothing: an `Entry`
        /// outlives the `RelayLatencies` it came from.
        relay: RelayUrl,
        /// The figure, in `Nanos` — nanoseconds on the caller's own monotonic
        /// timeline. A minimum over every measurement of this relay in this
        /// family, not the most recent one; see `RelayLatency.latency`.
        latency: Nanos,
    };

    /// Walks every measurement in `family_order`, each family ascending by
    /// relay URL — the same order upstream's `iter` produces from three
    /// `BTreeMap`s.
    pub const Iter = struct {
        latencies: *const RelayLatencies,
        /// An index into `RelayLatencies.family_order`, not a `Probe`, because
        /// iteration has to be able to say "none of them" as well.
        family: usize = 0,
        index: usize = 0,

        // `Entry` is declared `pub` in this same container, so a caller
        // reaches it as `RelayLatencies.Entry` and nothing private is exposed.
        // ziglint-ignore: Z012
        pub fn next(self: *Iter) ?Entry {
            while (self.family < RelayLatencies.family_order.len) {
                const probe = RelayLatencies.family_order[self.family];
                const entries = self.latencies.listConst(probe);
                if (self.index < entries.len) {
                    const item = entries.items[self.index];
                    self.index += 1;
                    return .{ .probe = probe, .relay = item.relay, .latency = item.latency };
                }
                self.family += 1;
                self.index = 0;
            }
            return null;
        }
    };

    /// Every measurement, in `family_order` and each family ascending by relay.
    ///
    /// The returned iterator borrows `self` and is over a `*const`, so it
    /// stays valid exactly as long as the `RelayLatencies` does and cannot be
    /// used to mutate one. Entries come back by value, so an `Entry.relay` is
    /// a copy that borrows nothing.
    pub fn iter(self: *const RelayLatencies) Iter {
        return .{ .latencies = self };
    }

    /// Record `latency` for `relay` in one probe family, keeping the fastest
    /// seen. `true` when it was recorded, `false` when the family's list is
    /// full of relays it has never seen.
    ///
    /// `false` is not a failure and not an error: `max_relays` bounds what a
    /// round may probe, so a caller passing more is passing something the plan
    /// cannot have produced. The fold ignores it, because a lost measurement
    /// costs a slower preferred relay and not a wrong one.
    ///
    /// `latency` is nanoseconds and is not checked against a clock: the caller
    /// measured it, and this only keeps the minimum.
    pub fn update(self: *RelayLatencies, relay: RelayUrl, latency: Nanos, probe: Probe) bool {
        return self.list(probe).update(relay, latency);
    }

    /// Fold another set of latencies in. Upstream's `merge`, and like
    /// `RelayList.update` it keeps the fastest: a relay is as good as its best
    /// showing across every report that still counts.
    pub fn merge(self: *RelayLatencies, other: *const RelayLatencies) void {
        var iterator = other.iter();
        while (iterator.next()) |entry| {
            // A full list drops the measurement rather than the merge; see
            // `RelayLatencies.update`.
            _ = self.list(entry.probe).update(entry.relay, entry.latency);
        }
    }

    /// The fastest latency to `relay` across all three families, or null when
    /// this set never measured it. Upstream's `get`.
    pub fn get(self: *const RelayLatencies, relay: RelayUrl) ?Nanos {
        var best: ?Nanos = null;
        for (RelayLatencies.family_order) |probe| {
            const latency = self.listConst(probe).get(relay) orelse continue;
            if (best == null or latency < best.?) best = latency;
        }
        return best;
    }

    /// Whether two sets record the same measurements.
    ///
    /// Equal as *sets of measurements*, in `Iter` order: HTTPS first, then the
    /// two address-discovery families, each ascending by relay. Both sides
    /// therefore have to hold the same entries in the same slots, which is what
    /// the sorted insertion in `RelayList.update` guarantees. Relays are
    /// compared through `RelayUrl.order`, so two entries that name the same
    /// relay are one entry whatever the unused tail of either `RelayUrl`
    /// holds, and the entries past `len` in either inline array are never read.
    pub fn eql(self: RelayLatencies, other: RelayLatencies) bool {
        var left = self.iter();
        var right = other.iter();
        while (true) {
            const a = left.next();
            const b = right.next();
            if (a == null or b == null) return a == null and b == null;
            if (a.?.probe != b.?.probe) return false;
            if (a.?.relay.order(b.?.relay) != .eq) return false;
            if (a.?.latency != b.?.latency) return false;
        }
    }
};
/// The most user-defined bytes an endpoint can publish.
///
/// A DNS TXT record is a sequence of character-strings and each one is capped at
/// 255 bytes (RFC 1035 §3.3.14). The attribute is spelled `user-data=`, so ten
/// of those 255 are spent before any of the value exists:
///
/// ```text
///   255  one DNS TXT character-string
///  -  10  the "user-data=" attribute prefix
///  -----
///   245  what is left for the value
/// ```
///
/// The arithmetic is written out because the number is otherwise a magic
/// constant, and because the failure it prevents is not a local one: a publisher
/// that overruns does not get an error, a *resolver* gets a truncated attribute
/// and quietly reads another endpoint's metadata.
pub const max_user_data_length = 245;
/// Why an application's attached metadata could not be built. The single
/// variant is upstream's `MaxLengthExceededError`, whose message is "max length
/// exceeded", and there is no allocator in this type that could fail: the value
/// is inline, so the only way to refuse is a length.
pub const UserDataError = error{
    /// The value is longer than `max_user_data_length` bytes. Upstream's
    /// `MaxLengthExceededError`, whose message is "max length exceeded".
    MaxLengthExceeded,
};
/// Data an application attaches to its endpoint and reads back out of discovery
/// records. Upstream's `UserData`, from `iroh-dns/src/endpoint_info.rs`.
///
/// Nothing here parses it or looks at it, exactly as upstream: it is bytes the
/// application put there and expects to find again. The value is inline rather
/// than borrowed so that a `UserData` can sit in a discovery record without a
/// lifetime attached to it, which is the trap invariant 6 in
/// `docs/ARCHITECTURE.md` is about.
pub const UserData = struct {
    /// The limit, named on the type as well as at module scope because upstream
    /// exposes it as an associated constant and callers reach for it there.
    pub const max_length = max_user_data_length;

    bytes: [max_user_data_length]u8 = undefined,
    len: u8 = 0,

    /// The bytes, up to `max_length` of them, or `error.MaxLengthExceeded`.
    ///
    /// Inline rather than borrowed so a `UserData` can sit inside a discovery
    /// record with no lifetime attached to it, and no allocation is involved.
    /// Nothing here parses the value or looks at it; a caller that needs a
    /// `[]const u8` takes `slice`, whose borrow ends with the value's address.
    ///
    /// An empty input is a `UserData` with `len == 0`, which is a value and not
    /// an absent one: it reads back as empty rather than as unset.
    pub fn init(text: []const u8) UserDataError!UserData {
        // 245 fits a `u8`, so this cast admits nothing the length check did not.
        if (text.len > max_user_data_length) return error.MaxLengthExceeded;
        var result: UserData = .{ .len = @intCast(text.len) };
        @memcpy(result.bytes[0..text.len], text);
        return result;
    }

    /// Pointer receiver for the reason `RelayUrl.hostSlice` takes one: the value
    /// is 246 bytes and a by-value receiver can hand back a slice into a
    /// temporary that is dead the moment it returns.
    pub fn slice(self: *const UserData) []const u8 {
        return self.bytes[0..self.len];
    }
};

const t = std.testing;
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
