//! The fold: probe results and an instant in, a report out.
//!
//! The classifier and the report value live here, and the tables they are
//! built from live in `report_measure.zig`. `report.zig` re-exports both.

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
