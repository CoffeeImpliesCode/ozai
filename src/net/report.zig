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
//! `UserData` is the exception and is called out as such: it is not on the
//! report upstream, it is on `EndpointData`, and it lives in
//! `iroh-dns/src/endpoint_info.rs` at the same commit. It is here because the
//! 245 is a discovery-layer number and the milestone lists it, not because the
//! report carries one.

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
    relay: RelayUrl,
    /// When the observation was made. The fold compares this against the `now`
    /// it is given and against its siblings; it never reads a clock itself.
    instant: Nanos,
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
    relay: RelayUrl,
    instant: Nanos,
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
    /// hold; `RelayUrl` is 258 bytes and the copy is the cheap option.
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
/// Upstream's `BTreeMap<RelayUrl, Duration>` entry.
pub const RelayLatency = struct {
    relay: RelayUrl,
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
const RelayList = struct {
    /// Entries past `len` are never written and are never read.
    items: [max_relays]RelayLatency = undefined,
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
pub const RelayLatencies = struct {
    https: RelayList = .{},
    ipv4: RelayList = .{},
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
        probe: Probe,
        relay: RelayUrl,
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

/// The classifier, in accumulator form.
///
/// The question is "did two probes to different relays report different public
/// addresses", which is a property of the *set* of observations, not of the
/// order they arrived in. Upstream answers it by comparing each new address
/// against the first one it stored; this answers the same question with a count
/// and a flag, which makes the independence a property of the type rather than
/// of how carefully the caller ordered its probes. See `Varying.classify` for
/// why one observation is not an answer.
pub const Varying = struct {
    count: usize = 0,
    first: SocketAddr = undefined,
    differs: bool = false,

    /// Fold one observation in.
    ///
    /// The first observation becomes the reference and every later one is
    /// compared with it, so the accumulator is order-independent by
    /// construction rather than by discipline: any observation that differs
    /// from the first sets `differs` and nothing unsets it. A caller may pass
    /// an address of a family the probe did not run in; `fold` is what decides
    /// which family an answer belongs to, and this is only an accumulator.
    pub fn observe(self: *Varying, socket: SocketAddr) void {
        if (self.count == 0) {
            self.first = socket;
        } else if (!std.meta.eql(socket, self.first)) {
            self.differs = true;
        }
        self.count += 1;
    }

    /// `null` while a single address is all that is known, `false` when two or
    /// more agree, `true` when two or more disagree.
    ///
    /// `null` for the single-observation case is upstream's behaviour and it is
    /// load-bearing: `None` means the NAT was never classified, and reporting
    /// `false` for one probe would claim a symmetric NAT that nobody measured.
    /// A later probe that agrees is what turns the answer into `false`.
    pub fn classify(self: Varying) ?bool {
        if (self.count < 2) return null;
        return self.differs;
    }
};

/// Whether two optional relay URLs name the same relay.
///
/// Through `RelayUrl.order`, so a relay is the scheme, then the port, then the
/// host's first `host_length` bytes — not the 253-byte array behind the host,
/// whose tail `parse` never writes and no reader ever consults. `null` is a
/// value here and not an absence of one: a report that has chosen no relay is
/// not the same report as one that has chosen this.
fn sameRelay(left: ?RelayUrl, right: ?RelayUrl) bool {
    if (left) |url| {
        const other = right orelse return false;
        return url.order(other) == .eq;
    }
    return right == null;
}

/// What this node's NAT looks like, as measured by probes. Upstream's `Report`,
/// field for field.
///
/// The type is shaped by how it travels. Upstream derives serde over it, and
/// `global_v4` and `global_v6` are `Option<SocketAddrV4>` and
/// `Option<SocketAddrV6>` so that a serialised report cannot carry an IPv4
/// address in the IPv6 slot. The serialisation is a later milestone; this is the
/// value, and it keeps the family in the name of the field that holds it and
/// checks the family of an address at the one place an address enters.
pub const Report = struct {
    /// A QAD round trip over IPv4 completed. Upstream's `udp_v4`, under the
    /// name it uses: evidence that UDP works, not "we hold a v4 address". An
    /// address whose family does not match the probe does not set it.
    udp_v4: bool = false,
    /// A QAD round trip over IPv6 completed.
    udp_v6: bool = false,
    /// Whether the public address differs between probes. Null until two probes
    /// of that family have answered, and see `Varying.classify`.
    mapping_varies_by_dest_ipv4: ?bool = null,
    /// The same question, asked over IPv6.
    mapping_varies_by_dest_ipv6: ?bool = null,
    /// The relay to home on: the lowest recent latency among the relays this
    /// report can still see, held over from the previous report unless a
    /// challenger beats it by two thirds. See `choosePreferredRelay`.
    preferred_relay: ?RelayUrl = null,
    /// The measured latency to each relay, per probe family.
    relay_latency: RelayLatencies = .{},
    /// The public address a v4 probe reported. Which of several, when they
    /// disagree, is answered in `observeGlobal`.
    global_v4: ?SocketAddr = null,
    /// The public address a v6 probe reported.
    global_v6: ?SocketAddr = null,
    /// Set by a captive-portal check and by nothing else. Null means "not
    /// checked", which is not the same as `false`: a portal that was never
    /// looked for has not been ruled out.
    captive_portal: ?bool = null,

    /// Do we have any indication that UDP works? Upstream's `has_udp`.
    pub fn hasUdp(self: Report) bool {
        return self.udp_v4 or self.udp_v6;
    }

    /// Whether the mapping is destination-dependent, across both families.
    /// Upstream's `mapping_varies_by_dest`: true if either family varies, the
    /// answered family's answer when only one has, null when neither has.
    ///
    /// This is the number hole punching actually reads. A destination-dependent
    /// mapping hands a different public address to every relay, so a port
    /// guessed from one of them is wrong for all the others.
    pub fn mappingVariesByDest(self: Report) ?bool {
        const v4 = self.mapping_varies_by_dest_ipv4;
        const v6 = self.mapping_varies_by_dest_ipv6;
        if (v4 != null and v6 != null) return v4.? or v6.?;
        if (v6 != null) return v6;
        if (v4 != null) return v4;
        return null;
    }

    /// Structural equality, field for field.
    ///
    /// Not `==`, and not `std.meta.eql` over the whole value either: two fields
    /// are inline arrays whose tail past their length is never written, and a
    /// comparison that reads those bytes is not an equivalence at all. Upstream
    /// gets equality from `BTreeMap`s, which have no such tail.
    ///
    /// `preferred_relay` is the second of the two. `RelayUrl` is a 253-byte
    /// fixed array with a length beside it, and `parse` writes only
    /// `host_length` bytes: two URLs parsed from the same text are the same
    /// relay whatever the rest of the array holds, and `format`, `socketAddr`,
    /// `order` and `RelayList` all read it through `hostSlice`. So the relay is
    /// compared by `RelayUrl.order` — scheme, then port, then the host's first
    /// `host_length` bytes — and a caller that filled the unused tail cannot
    /// make two reports that name the same relay stop comparing equal. The
    /// latency table already compares its relays the same way; see
    /// `RelayLatencies.eql`.
    pub fn eql(self: Report, other: Report) bool {
        if (self.udp_v4 != other.udp_v4) return false;
        if (self.udp_v6 != other.udp_v6) return false;
        if (self.mapping_varies_by_dest_ipv4 != other.mapping_varies_by_dest_ipv4) return false;
        if (self.mapping_varies_by_dest_ipv6 != other.mapping_varies_by_dest_ipv6) return false;
        if (self.captive_portal != other.captive_portal) return false;
        if (!std.meta.eql(self.global_v4, other.global_v4)) return false;
        if (!std.meta.eql(self.global_v6, other.global_v6)) return false;
        if (!sameRelay(self.preferred_relay, other.preferred_relay)) return false;
        return self.relay_latency.eql(other.relay_latency);
    }

    /// The claims a report makes, in one line. Upstream's `Display` is `Debug`,
    /// and a report here is four kilobytes of inline latency table: printing all
    /// of it is not what a reader wants.
    pub fn format(self: Report, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("udp_v4: {} udp_v6: {} varies_by_dest: {?}/{?} captive_portal: {?}", .{
            self.udp_v4,
            self.udp_v6,
            self.mapping_varies_by_dest_ipv4,
            self.mapping_varies_by_dest_ipv6,
            self.captive_portal,
        });
        try writer.writeAll(" preferred_relay: ");
        if (self.preferred_relay) |url| {
            try writer.print("{f}", .{url});
        } else {
            try writer.writeAll("none");
        }
        if (self.global_v4) |socket| try writer.print(" global_v4: {f}", .{socket});
        if (self.global_v6) |socket| try writer.print(" global_v6: {f}", .{socket});
    }
};

/// A previous report, with the instant it was generated.
pub const HistoryEntry = struct {
    instant: Nanos,
    report: Report,
};

/// What the fold carries in from earlier reports.
///
/// Upstream keeps `Reports { prev: BTreeMap<Instant, Report>, last: Option<Report> }`
/// as client state and mutates it from inside the fold. Here it is an argument,
/// which is what makes `fold` a function: the caller owns what is remembered and
/// for how long, and the fold only reads.
pub const History = struct {
    /// Earlier reports, each with the instant it was generated. Entries older
    /// than `max_report_age` are ignored, so a caller may pass everything it
    /// kept rather than pruning it itself.
    entries: []const HistoryEntry = &.{},
    /// The most recent earlier report, for the two things the age window does not
    /// cover: the relay to stay on, and a classification to carry forward. It is
    /// separate from `entries` because "the last report" is not "a recent
    /// report" — the last one is the last one even after it has aged out.
    last: ?Report = null,
};

/// Fold probe results into a report. This is the whole of the pure half.
///
/// Pure in the strong sense: it reads no clock, no environment and no global,
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

/// Whether `candidate` is the better of two observations of the same public
/// address: fastest first, then freshest, then lowest relay URL.
///
/// Upstream keeps whichever address a probe happened to report first and never
/// replaces it (`global_v4 = Some(ipp)` only into an empty slot), which makes
/// the field a function of the order probes arrived in. The address is read by
/// peers to decide where to try, and a report folded from one set of probes must
/// not name a different peer when the same set is handed over in another order,
/// so the winner is decided on the probe's own contents. A deliberate divergence
/// from upstream; it can only differ when probes to several relays disagree,
/// which is exactly the case where upstream's answer was arrival order.
fn beats(candidate: QadProbe, incumbent: QadProbe) bool {
    if (candidate.latency != incumbent.latency) return candidate.latency < incumbent.latency;
    if (candidate.instant != incumbent.instant) return candidate.instant > incumbent.instant;
    return candidate.relay.order(incumbent.relay) == .lt;
}

/// Pick the relay to home on, with upstream's two-thirds hysteresis.
///
/// Upstream merges the reports still inside `max_report_age` into `best_recent`,
/// takes the relay that this report can still see with the lowest latency in
/// that window, and then refuses to move off the current relay unless the
/// challenger beats it by more than two thirds. `now` is what prunes the window,
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
