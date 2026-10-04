//! What a report claims, and what the fold remembers about earlier ones.
//!
//! Upstream, captured 2026-09-30 at n0-computer/iroh commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8 (the `iroh` 1.3.0 crate as
//! published): `Report` field for field from `iroh/src/net_report/report.rs`,
//! and the classification upstream accumulates inside `Report::update` —
//! `mapping_varies_by_dest_ipv4` and `mapping_varies_by_dest_ipv6`, which
//! upstream computes by comparing each new address against the first one it
//! stored and which are an accumulator with a method here.
//!
//! Upstream keeps `Reports { prev: BTreeMap<Instant, Report>, last: Option<Report> }`
//! as client state and mutates it from inside the fold. Here that is `History`,
//! and it is an *argument*, which is what makes `fold` a function: the caller
//! owns what is remembered and for how long, and the fold only reads.
//!
//! So this file is the state and nothing else: no fold, no choice, no rule
//! about which of two answers wins. `Varying` is an accumulator and not an
//! interface, and `Report` is a value whose every field says something a caller
//! can act on.

const std = @import("std");
const addr = @import("../base/addr.zig");
const base_relay_url = @import("../base/relay_url.zig");
const report = @import("report.zig");

const Nanos = report.Nanos;
const RelayLatencies = report.RelayLatencies;

const RelayUrl = base_relay_url.RelayUrl;
const SocketAddr = addr.SocketAddr;

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

const t = std.testing;
/// A duration in the units the report counts in, so the vectors below read as
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
