//! The measured values a probe round produces, and the per-family
//! latency tables that accumulate them.
//!
//! `report.zig` is this package's facade and holds the fold; this module
//! holds everything the fold is handed. Nothing here reads a clock: an
//! observation carries the instant it was made, and the tables only ever keep
//! a minimum over what they were told.

const std = @import("std");
const addr = @import("../base/addr.zig");

const RelayUrl = addr.RelayUrl;
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

    // `RelayList` itself stays private, so this widens nothing a caller can
    // name: the test in `report.zig` reaches this through `RelayLatencies.https`.
    // ziglint-ignore: Z012
    pub fn get(self: *const RelayList, relay: RelayUrl) ?Nanos {
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
