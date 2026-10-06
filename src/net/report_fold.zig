//! The fold: probe results and an instant in, a report out.
//!
//! The classifier and the report value live here, and the tables they are
//! built from live in `report_measure.zig`. `report.zig` re-exports both.
//!
//! The tests that drive `fold` live here too, beside the fold rather than
//! behind a re-export, so a change to the classification fails in the file
//! that owns it. The facade keeps the tests that cross a boundary: the latency
//! table `report_measure.zig` owns, the 245-byte limit `user_data.zig` owns,
//! and one that spans `base/addr.zig`, `Report.eql` and the latency table at
//! once.

const std = @import("std");
const addr = @import("../base/addr.zig");
const measure = @import("report_measure.zig");

const RelayUrl = addr.RelayUrl;
const SocketAddr = addr.SocketAddr;
const Nanos = measure.Nanos;
const max_report_age = measure.max_report_age;
const ProbeResult = measure.ProbeResult;
const QadProbe = measure.QadProbe;
const RelayLatencies = measure.RelayLatencies;

const t = std.testing;

/// The classifier, in accumulator form.
///
/// The question is "did two probes to different relays report different public
/// addresses", which is a property of the *set* of observations, not of the
/// order they arrived in. Upstream answers it by comparing each new address
/// against the first one it stored; this answers the same question with a count
/// and a flag, which makes the independence a property of the type rather than
/// of how carefully the caller ordered its probes. See `Varying.classify` for
/// why one observation is not an answer.
///
/// A `Varying` is only meaningful as the output of `observe` and read through
/// `classify`. The fields are an accumulator, not an interface: a caller that
/// writes `count` or `differs` directly is asserting a history no address
/// backs, and a caller that reads `first` before the first `observe` reads
/// undefined bytes rather than an absence — `classify`'s null is how this
/// type says "nothing observed", and it is a method, not a field.
pub const Varying = struct {
    /// How many observations have been folded in. Zero on a default value, and
    /// the only precondition under which `first` means anything: it becomes
    /// valid at one. Nothing decrements it, so it is a total of `observe`
    /// calls rather than of addresses still held.
    count: usize = 0,
    /// The reference address: the first observation, which every later one is
    /// compared against and which none of them replaces.
    ///
    /// **Undefined until `count` is at least one.** A default-constructed
    /// `Varying` has no reference address, and reading this field before the
    /// first `observe` reads poison bytes — not a zero address and not a null.
    /// `classify` is how a caller asks the question that does not need it.
    first: SocketAddr = undefined,
    /// Whether any observation past the first has disagreed with `first`. False
    /// on a default value and also for one observation or for several that all
    /// agree, which is why it is never the answer on its own: read `classify`,
    /// which is `differs` once two or more observations are in.
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
    /// The v4 address selected by `fold`: lowest latency, then newest instant,
    /// then lowest relay URL. Null means no probe supplied an address of this
    /// family. An address is selected even when the probes disagree.
    global_v4: ?SocketAddr = null,
    /// The same selection over v6 probes; null has the same meaning.
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
    /// and a report here carries `relay_latency` inline — three families of
    /// `max_relays` entries, each holding a `RelayUrl` by value — so printing
    /// all of it is not what a reader wants.
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

/// Ten minutes in, on the timeline the tests hand to `fold`. Past
/// `max_report_age`, so a vector can place a report on either side of the
/// window, and far past every probe instant below.
pub const test_now: Nanos = 600 * std.time.ns_per_s;

/// A duration in the units the report counts in, so the vectors read as
/// milliseconds rather than as nine-digit integers.
pub fn millis(n: u64) Nanos {
    return n * std.time.ns_per_ms;
}

pub const public_v4: SocketAddr = .{ .ip = .{ .v4 = .{ 198, 51, 100, 7 } }, .port = 41234 };
pub const other_v4: SocketAddr = .{ .ip = .{ .v4 = .{ 198, 51, 100, 9 } }, .port = 51234 };
pub const public_v6: SocketAddr = .{
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
