//! How a set of observations becomes a claim about this node's own network.
//!
//! `observed_address.zig` answers "where did the relay see us". This module
//! answers the question that answer feeds: **how many independent witnesses
//! does it take before we are willing to say our public address is that, and
//! what happens when a later witness says otherwise.**
//!
//! # Upstream
//!
//! Every rule below is either upstream's or a property of a value this tree
//! already owns, and each names the spelling it reuses rather than writing a
//! second:
//!
//! - `Report::update`'s address handling, `iroh/src/net_report/report.rs:68-130`
//!   as ported into `report_fold.fold` (`report_fold.zig:256-290`): the family
//!   check at `report.rs:81-84`, `Varying.observe` against the first address,
//!   and `Report.mapping_varies_by_dest`.
//! - `MAX_RELAYS = 5` at `reportgen.rs:497`, ported as `report_measure.max_relays`
//!   (`report_measure.zig:168`), which bounds this table.
//! - `RelayList.update`'s minimum rule, `report_measure.zig:216-238`:
//!   `if latency < old { *old = latency }`, and its sorted-by-relay layout,
//!   which is what makes an answer independent of arrival order.
//!
//! # What a claim asserts
//!
//! A `Claim` asserts five things and no others: an address for one family, the
//! fastest latency measured for exactly that address, how many **distinct
//! relays** reported exactly it, how many reported something else, and whether
//! the mapping varies by destination. Deliberately not asserted:
//!
//! - **That the address is reachable.** This module never opens a socket. A
//!   claim is evidence, and `Report.global_v4` — which peers act on — is
//!   `report_fold.fold`'s to publish, not this module's.
//! - **That the mapping is stable while fewer than two relays have answered.**
//!   That is `varies == null` and it reads "not measured", the same distinction
//!   `Varying.classify` draws (`report_fold.zig:78-81`). A single relay is the
//!   easy case, and hole punching assumes the hard one.
//!
//! # Decision: the threshold is two *distinct relays*, not two observations
//!
//! `Varying.classify` already returns null below two observations, false when
//! they agree and true when they do not, so the three-way answer exists and is
//! not reinvented here. What `Varying` cannot see is *who* answered: two
//! observations from one relay are two frames off one wire, and treating them
//! as two witnesses would classify a NAT on a single relay's word. So the
//! accumulator here feeds `Varying` **one observation per relay**, taken as
//! the lowest-latency sighting of that relay. That is the extension and it is
//! small — the rule `probe_turn.measured` already applies when it counts a
//! relay once (`probe_turn.zig:66-72`).
//!
//! The consequence is pinned by a test: two frames from one relay classify
//! nothing, and three relays of which two agree say `varies == false`.
//!
//! Which observation of a relay is the one that counts is a determinism
//! device, not evidence: latency is a round trip and says nothing about which
//! address is right. It is the lowest-latency reading because that is the same
//! minimum-then-order rule `report_measure.RelayList.update` already applies
//! when one relay is measured twice, so this module adds no second spelling
//! of it. A relay that contradicts itself therefore contributes its fastest
//! reading, once.
//!
//! # Decision: a contradiction escalates a claim and never retracts it
//!
//! A later observation that disagrees does **not** replace the claimed address
//! and does **not** clear the escalation. It moves `varies` from `false` to
//! `true` and leaves `addr` and `latency` exactly where they were. Three
//! reasons, and the first is the one that settles it:
//!
//! 1. **It is the direction `Varying` already runs.** `Varying.observe` only
//!    ever sets `differs` and nothing unsets it (`report_fold.zig:62-69`). A
//!    rule that let a later sighting un-contest a claim would be a second,
//!    weaker version of the same question with the opposite polarity.
//! 2. **The address is not what the contradiction is about.** A
//!    destination-dependent NAT still has *an* address, and
//!    `report_fold.fold` selects one "even when the probes disagree"
//!    (`report_fold.zig:126-128`). Replacing the address on every disagreement
//!    would make the published address a function of arrival order — the
//!    divergence `report_fold.beats` exists to prevent (`report_fold.zig:308-323`).
//! 3. **Escalation is monotone, so the result is order-independent.** Every
//!    answer this module gives is a function of the *set* of sightings, which
//!    the permutation test below holds directly.
//!
//! Fail-closed, which is the house rule: the escalation can only make the
//! claim less useful to a peer, never more. A peer that ignores `varies` and
//! uses `addr` alone is trusting the address we had before the contradiction,
//! which is the same address upstream would have published.
//!
//! # Which address a contested set names
//!
//! The address with the most distinct relays reporting it, then the lowest
//! latency, then `SocketAddr.order`. A deliberate difference from
//! `report_fold.beats`, which selects on latency alone: this module answers
//! *what is true* and that fold answers *what is fastest to try*, and a
//! one-relay address with a fast round trip is not better evidence than a
//! two-relay address with a slow one. Both are total and both are
//! order-independent; the table is kept sorted by `RelayUrl.order` so that a
//! full tie resolves to the same relay whatever order the sightings arrived in.
//!
//! # Pure
//!
//! No socket, no clock, no allocator, no global. `fold` is a function of a
//! slice of sightings, and two calls with equal arguments produce equal
//! claims — which is what lets a test drive it with values a test wrote by
//! hand, and what lets the accumulation be a fixed-size inline table.

const std = @import("std");
const addr = @import("../base/addr.zig");
const fold_mod = @import("report_fold.zig");
const measure = @import("report_measure.zig");
const observed = @import("observed_address.zig");
const qad = @import("qad.zig");

const Family = qad.Family;
const RelayUrl = addr.RelayUrl;
const SocketAddr = addr.SocketAddr;
const Nanos = measure.Nanos;
const Observation = observed.Observation;
const Varying = fold_mod.Varying;

/// How many distinct relays one family's table holds.
///
/// `measure.max_relays`, reused rather than restated: the probe fan-out is
/// bounded at `MAX_RELAYS = 5` upstream (`reportgen.rs:497`), so a sixth relay
/// is never probed and there is nothing to record. A sighting from a relay past
/// the bound is **dropped, not an error** — the same trade `report_fold.fold`
/// makes when it ignores `RelayList.update`'s return (`report_fold.zig:259`) —
/// because a lost witness costs a weaker claim, never a wrong one.
pub const max_observers: usize = measure.max_relays;

/// One relay's answer: what it saw, and which probe it was answering.
///
/// The probe's family is an argument and not a field of `Observation` because
/// the check needs both and `observed_address.zig` has only one of them by the
/// time it returns: `Observation.family` is the frame's declared family, which
/// is not the family the probe ran in.
pub const Sighting = struct {
    /// The relay that answered. Owned by value, like every other `RelayUrl` in
    /// `src/net/`, so a sighting borrows nothing and can be held in an array.
    relay: RelayUrl,
    /// What that relay saw, already canonicalised by `observed.canonical`.
    observation: Observation,
    /// The family the probe ran with: `report.Probe`'s `qad_ipv4` or
    /// `qad_ipv6`, spelled as the frame family the path was opened in.
    probed: Family,

    /// Whether this sighting may become an address claim.
    ///
    /// Exactly `report_fold.fold`'s rule (`report_fold.zig:262-283`): an
    /// address whose family is not the probe's is a measurement and nothing
    /// more. The latency is still a real round trip and still belongs to
    /// `report_measure.RelayLatencies`, which this module does not own — so the
    /// sighting is dropped whole here, and saying so is what keeps the rule in
    /// one place instead of two.
    pub fn isAddressBearing(self: Sighting) bool {
        return self.observation.ipFamily() == self.probed;
    }
};

/// What the sightings of one family assert about this node's public address.
pub const Claim = struct {
    /// The address: the most-corroborated one, then the fastest, then the
    /// lowest by `SocketAddr.order`. Never null inside a `Claim` — a claim
    /// about no address is not a claim, and `Claims.v4` / `Claims.v6` are where
    /// "nothing was observed" is said.
    addr: SocketAddr,
    /// The fastest latency measured to a relay that reported exactly `addr`.
    /// The fastest *supporting* latency: a contradicting relay's round trip is
    /// real but is not evidence about this address.
    latency: Nanos,
    /// How many distinct relays reported exactly `addr`. Two is the threshold;
    /// see the module doc.
    relays: u8,
    /// How many distinct relays reported some other address of this family.
    /// Never negative and never larger than the table's length.
    contradicting: u8,
    /// `Varying.classify` over one observation per distinct relay: null below
    /// two relays, false when they agree, true when they disagree.
    varies: ?bool,

    /// Two or more distinct relays, and they all said this. The only state in
    /// which a claim may be called corroborated.
    pub fn confirmed(self: Claim) bool {
        return self.varies == false;
    }

    /// Two or more distinct relays, and they disagreed. `addr` is still the
    /// best-supported address; it is simply no longer an assertion that the
    /// mapping is symmetric.
    pub fn contested(self: Claim) bool {
        return self.varies == true;
    }

    /// Fewer than two distinct relays answered. Not "stable", not "varying":
    /// unmeasured, and the distinction `report_fold.fold` inherits from
    /// `Varying.classify` when it carries a classification forward.
    pub fn unmeasured(self: Claim) bool {
        return self.varies == null;
    }
};

/// One family's observations, one relay per slot.
///
/// Sorted by `RelayUrl.order` and deduplicated by it, for the reason
/// `report_measure.RelayList` is sorted rather than hashed
/// (`report_measure.zig:176-182`): the order is load-bearing, and a table whose
/// order depended on arrival would make a full tie in `subject` depend on it
/// too.
const Table = struct {
    relays: [max_observers]RelayUrl = undefined,
    addrs: [max_observers]SocketAddr = undefined,
    latencies: [max_observers]Nanos = undefined,
    len: usize = 0,

    fn slotOf(self: *const Table, relay: RelayUrl) ?usize {
        var index: usize = 0;
        while (index < self.len) : (index += 1) {
            switch (self.relays[index].order(relay)) {
                .eq => return index,
                .gt => return null,
                .lt => {},
            }
        }
        return null;
    }

    /// Record one address-bearing sighting. Drops a sighting past
    /// `max_observers` and a sighting whose relay already contributed a faster
    /// one; see `Sighting.isAddressBearing` and the module doc.
    fn observe(self: *Table, sighting: Sighting) void {
        if (!sighting.isAddressBearing()) return;
        const addr_of = sighting.observation.addr;
        const latency = sighting.observation.latency;
        if (self.slotOf(sighting.relay)) |index| {
            if (!better(latency, addr_of, self.latencies[index], self.addrs[index])) return;
            self.addrs[index] = addr_of;
            self.latencies[index] = latency;
            return;
        }
        if (self.len == max_observers) return;
        var index = self.len;
        while (index > 0) : (index -= 1) {
            if (self.relays[index - 1].order(sighting.relay) != .gt) break;
            // Walked from the end downwards, so every entry still ahead of
            // `index` is read before anything overwrites it. Each copy is
            // between two adjacent elements, so the ranges never overlap and
            // a plain assignment is the whole of the shift.
            self.relays[index] = self.relays[index - 1];
            self.addrs[index] = self.addrs[index - 1];
            self.latencies[index] = self.latencies[index - 1];
        }
        self.relays[index] = sighting.relay;
        self.addrs[index] = addr_of;
        self.latencies[index] = latency;
        self.len += 1;
    }

    /// How many distinct relays reported exactly `socket`.
    fn support(self: *const Table, socket: SocketAddr) u8 {
        var count: u8 = 0;
        for (self.addrs[0..self.len]) |candidate| {
            if (std.meta.eql(candidate, socket)) count += 1;
        }
        return count;
    }

    /// Whether `slot` should replace `best` as the claimed address: more
    /// independent support, then a faster round trip, then the lower address.
    ///
    /// Latency is compared before the address, which is what stops a slower
    /// second sighting of the *same* address from holding the claim at the
    /// slower figure, and the address is what settles two addresses seen once
    /// each — the case where there is no latency to prefer.
    fn outranks(self: *const Table, slot: usize, best: usize) bool {
        const mine = self.support(self.addrs[slot]);
        const theirs = self.support(self.addrs[best]);
        if (mine != theirs) return mine > theirs;
        return better(
            self.latencies[slot],
            self.addrs[slot],
            self.latencies[best],
            self.addrs[best],
        );
    }

    /// The slot whose address the claim is about. The lowest index wins a full
    /// tie, and the slots are sorted by relay, so that index is the lowest relay
    /// URL rather than whichever sighting arrived first.
    fn subject(self: *const Table) usize {
        var best: usize = 0;
        var index: usize = 1;
        while (index < self.len) : (index += 1) {
            if (self.outranks(index, best)) best = index;
        }
        return best;
    }

    /// The claim this table supports, or null when it holds nothing.
    ///
    /// `Varying` is built here rather than kept live, so that a relay whose slot
    /// is later replaced by a faster sighting is compared against the address it
    /// now holds rather than the one it first reported: `Varying.first` is the
    /// first observation and nothing replaces it (`report_fold.zig:44-47`), so a
    /// live accumulator would compare later sightings against a superseded
    /// address.
    fn claim(self: *const Table) ?Claim {
        if (self.len == 0) return null;
        var varying: Varying = .{};
        for (self.addrs[0..self.len]) |socket| varying.observe(socket);

        const chosen = self.subject();
        const claimed = self.addrs[chosen];
        const supporting = self.support(claimed);
        return .{
            .addr = claimed,
            .latency = self.latencies[chosen],
            .relays = supporting,
            .contradicting = @intCast(self.len - supporting),
            .varies = varying.classify(),
        };
    }
};

/// Whether a sighting of `socket` at `latency` replaces one at `incumbent`.
/// The fastest wins, and `socket` breaks a latency tie so that two equal-cost
/// sightings of different addresses still resolve the same way every time.
fn better(latency: Nanos, socket: SocketAddr, incumbent: Nanos, other: SocketAddr) bool {
    if (latency != incumbent) return latency < incumbent;
    return socket.order(other) == .lt;
}

/// Both families' claims at once, so a caller holds one value.
pub const Claims = struct {
    /// The v4 claim, or null when no v4 probe produced an address-bearing
    /// sighting.
    v4: ?Claim = null,
    /// The same for v6. Independent of `v4`: the two are measured separately
    /// and a host routinely has one, the other, or both.
    v6: ?Claim = null,

    /// The claim for `family`.
    pub fn get(self: Claims, family: Family) ?Claim {
        return switch (family) {
            .v4 => self.v4,
            .v6 => self.v6,
        };
    }
};

/// What a set of sightings has established, accumulated one at a time.
///
/// State is explicit and the mutation is a method, so a caller may run two
/// accumulators over the same sightings — two rounds, two nodes — and get two
/// answers with neither being a capture.
pub const Fold = struct {
    v4: Table = .{},
    v6: Table = .{},

    /// Fold one sighting in. Dropping it is a defined outcome, not a failure:
    /// see `Sighting.isAddressBearing` and `max_observers`.
    pub fn observe(self: *Fold, sighting: Sighting) void {
        switch (sighting.observation.ipFamily()) {
            .v4 => self.v4.observe(sighting),
            .v6 => self.v6.observe(sighting),
        }
    }

    /// What the sightings seen so far establish, per family.
    pub fn claims(self: *const Fold) Claims {
        return .{ .v4 = self.v4.claim(), .v6 = self.v6.claim() };
    }
};

/// The claims a set of sightings supports.
///
/// The batch form of `Fold.observe` and `Fold.claims`, and the entry point a
/// caller with all the sightings already in hand uses. Folding no sightings
/// yields two null claims, which is the answer "nothing was observed" rather
/// than an absent one.
pub fn fold(sightings: []const Sighting) Claims {
    var accumulator: Fold = .{};
    for (sightings) |sighting| accumulator.observe(sighting);
    return accumulator.claims();
}

const t = std.testing;

/// `2001:db8::7`, from the documentation prefix, so a v6 sighting is a real v6
/// address rather than something the synthetic refusal would catch upstream.
const doc_v6: [16]u8 = .{
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
    0,    0,    0,    0,    0, 0, 0, 0x07,
};

/// `198.51.100.7` in the IPv4-mapped IPv6 form, so a test can name the spelling
/// a dual-stack relay produces.
const mapped_v6: [16]u8 = .{
    0, 0, 0,    0,    0,   0,  0,   0,
    0, 0, 0xff, 0xff, 198, 51, 100, 7,
};

fn millis(n: u64) Nanos {
    return n * std.time.ns_per_ms;
}

const public_v4: SocketAddr = .{ .ip = .{ .v4 = .{ 198, 51, 100, 7 } }, .port = 41234 };
const other_v4: SocketAddr = .{ .ip = .{ .v4 = .{ 198, 51, 100, 9 } }, .port = 51234 };
const public_v6: SocketAddr = .{ .ip = .{ .v6 = doc_v6 }, .port = 41234 };

/// A sighting from an address the test already trusts, so a test states its
/// claim scenario without restating `observed.canonical`'s refusals. `family` is
/// the *frame's* declared family and `probed` the probe's, which is exactly the
/// pair a mapped address needs to be interesting.
fn seen(
    relay: RelayUrl,
    socket: SocketAddr,
    latency: u64,
    family: Family,
    probed: Family,
) Sighting {
    return .{
        .relay = relay,
        .observation = .{
            .family = family,
            .addr = socket,
            .latency = millis(latency),
            .sequence = 1,
        },
        .probed = probed,
    };
}

fn v4Seen(relay: RelayUrl, socket: SocketAddr, latency: u64) Sighting {
    return seen(relay, socket, latency, .v4, .v4);
}

/// Relays whose URLs sort by index, so a full tie in the claim resolves to the
/// same relay rather than to whichever sighting the test wrote first.
fn namedRelay(scratch: []u8, index: usize) !RelayUrl {
    return RelayUrl.parse(try std.fmt.bufPrint(scratch, "https://{d}.example./", .{index}));
}

test "one relay's word is unmeasured, and two relays that agree confirm" {
    var scratch: [64]u8 = undefined;
    const a = try namedRelay(&scratch, 1);
    const b = try namedRelay(&scratch, 2);

    // A single relay reported the address, so the address is claimed and the
    // mapping is *not* classified. `unmeasured` is not "stable": reporting
    // false here would claim a symmetric NAT nobody measured, which is the
    // easy case hole punching assumes the hard one is.
    const one = fold(&.{v4Seen(a, public_v4, 10)});
    const only = one.v4.?;
    try t.expectEqual(public_v4, only.addr);
    try t.expectEqual(millis(10), only.latency);
    try t.expectEqual(@as(u8, 1), only.relays);
    try t.expectEqual(@as(u8, 0), only.contradicting);
    try t.expectEqual(@as(?bool, null), only.varies);
    try t.expect(only.unmeasured());
    try t.expect(!only.confirmed());
    try t.expect(!only.contested());
    // The family that never reported claims nothing at all, which is a
    // different thing from a family that reported and was not corroborated.
    try t.expectEqual(@as(?Claim, null), one.v6);
    try t.expectEqual(@as(?Claim, null), one.get(.v6));

    // Two distinct relays, both saying the same address: corroborated.
    const agreed = fold(&.{ v4Seen(a, public_v4, 10), v4Seen(b, public_v4, 12) }).v4.?;
    try t.expectEqual(@as(u8, 2), agreed.relays);
    try t.expectEqual(@as(u8, 0), agreed.contradicting);
    try t.expectEqual(@as(?bool, false), agreed.varies);
    try t.expect(agreed.confirmed());
    try t.expect(!agreed.contested());
    // The claim's latency is the fastest *supporting* one, the same order
    // `report_fold.beats` publishes from.
    try t.expectEqual(millis(10), agreed.latency);
}

test "two frames from one relay are one witness, not two" {
    var scratch: [64]u8 = undefined;
    const a = try namedRelay(&scratch, 1);

    // The same relay twice: one slot, one observation fed to `Varying`, so the
    // mapping stays unmeasured. Counting frames would classify a NAT on one
    // relay's word, which is the extension this module adds to `Varying`.
    const only = fold(&.{ v4Seen(a, public_v4, 10), v4Seen(a, public_v4, 12) }).v4.?;
    try t.expectEqual(@as(u8, 1), only.relays);
    try t.expectEqual(@as(?bool, null), only.varies);
    try t.expect(only.unmeasured());
    // The faster of the two frames is the one held, by the same
    // minimum-then-order rule `report_measure.RelayList.update` applies.
    try t.expectEqual(millis(10), only.latency);

    // One relay saying two different addresses is still one witness: the
    // faster frame wins the slot and the disagreement is not counted as a
    // second relay's dissent.
    const mixed = fold(&.{ v4Seen(a, public_v4, 10), v4Seen(a, other_v4, 12) }).v4.?;
    try t.expectEqual(@as(?bool, null), mixed.varies);
    try t.expectEqual(@as(u8, 1), mixed.relays);
}

test "a contradicting relay contests the claim and never retracts the address" {
    var scratch: [64]u8 = undefined;
    const a = try namedRelay(&scratch, 1);
    const b = try namedRelay(&scratch, 2);
    const c = try namedRelay(&scratch, 3);

    const agreed = fold(&.{ v4Seen(a, public_v4, 10), v4Seen(b, public_v4, 12) }).v4.?;
    try t.expect(agreed.confirmed());
    try t.expectEqual(public_v4, agreed.addr);

    // A third relay reports something else, with a *faster* round trip than
    // either. The address does not move: a destination-dependent NAT still has
    // an address, and `report_fold.fold` selects one "even when the probes
    // disagree". Only the escalation changes.
    const contested = fold(&.{
        v4Seen(a, public_v4, 10),
        v4Seen(b, public_v4, 12),
        v4Seen(c, other_v4, 3),
    }).v4.?;
    try t.expect(contested.contested());
    try t.expect(!contested.confirmed());
    try t.expectEqual(@as(?bool, true), contested.varies);
    try t.expectEqual(public_v4, contested.addr);
    try t.expectEqual(@as(u8, 2), contested.relays);
    try t.expectEqual(@as(u8, 1), contested.contradicting);
    // A contradicting relay's round trip is real but is not evidence about the
    // claimed address, so it never becomes the claim's latency.
    try t.expectEqual(millis(10), contested.latency);
}

test "a one-relay address cannot outrank a two-relay one however fast it is" {
    var scratch: [64]u8 = undefined;
    const a = try namedRelay(&scratch, 1);
    const b = try namedRelay(&scratch, 2);
    const c = try namedRelay(&scratch, 3);

    // `other_v4` is seen by one relay at 1 ms; `public_v4` by two at 40 ms each.
    // This module answers *what is true*, `report_fold.beats` answers *what is
    // fastest to try*, and independence outranks speed here.
    const claim = fold(&.{
        v4Seen(a, public_v4, 40),
        v4Seen(b, public_v4, 41),
        v4Seen(c, other_v4, 1),
    }).v4.?;
    try t.expectEqual(public_v4, claim.addr);
    try t.expectEqual(@as(u8, 2), claim.relays);
    try t.expectEqual(millis(40), claim.latency);
    try t.expect(claim.contested());
}

test "the claims do not depend on the order the sightings arrived in" {
    var scratch: [64]u8 = undefined;
    const a = try namedRelay(&scratch, 1);
    const b = try namedRelay(&scratch, 2);
    const c = try namedRelay(&scratch, 3);

    const set = [_]Sighting{
        v4Seen(a, public_v4, 40),
        v4Seen(b, public_v4, 41),
        v4Seen(c, other_v4, 1),
    };
    const reference = fold(&set).v4.?;

    // Every element held back and re-folded is the trivial half of the claim;
    // the rotations are the half that matters, and between them they put every
    // sighting in every position. A table whose order depended on arrival would
    // not survive this, and neither would a subject chosen by first-seen.
    var rotated = [_]Sighting{ set[1], set[2], set[0] };
    try t.expectEqual(reference.addr, fold(&rotated).v4.?.addr);
    try t.expectEqual(reference.latency, fold(&rotated).v4.?.latency);
    try t.expectEqual(reference.relays, fold(&rotated).v4.?.relays);
    try t.expectEqual(reference.contradicting, fold(&rotated).v4.?.contradicting);
    try t.expectEqual(reference.varies, fold(&rotated).v4.?.varies);
    rotated = .{ set[2], set[0], set[1] };
    try t.expectEqual(reference.addr, fold(&rotated).v4.?.addr);
    rotated = .{ set[2], set[1], set[0] };
    try t.expectEqual(reference.addr, fold(&rotated).v4.?.addr);
    try t.expectEqual(reference.latency, fold(&rotated).v4.?.latency);
}

test "two addresses seen once each resolve to the same claim in either order" {
    var scratch: [64]u8 = undefined;
    const a = try namedRelay(&scratch, 1);
    const b = try namedRelay(&scratch, 2);

    // Equal latency and equal support, so only the address can settle it.
    // `SocketAddr.order` puts every v4 before every v6 and then compares bytes.
    const forward = fold(&.{ v4Seen(a, public_v4, 10), v4Seen(b, other_v4, 10) }).v4.?;
    const backward = fold(&.{ v4Seen(a, other_v4, 10), v4Seen(b, public_v4, 10) }).v4.?;
    try t.expectEqual(forward.addr, backward.addr);
    try t.expectEqual(@as(?bool, true), forward.varies);
    try t.expectEqual(@as(u8, 1), forward.relays);
    try t.expectEqual(@as(u8, 1), forward.contradicting);
}

test "the two families are claimed separately and independently" {
    var scratch: [64]u8 = undefined;
    const a = try namedRelay(&scratch, 1);
    const b = try namedRelay(&scratch, 2);

    const claims = fold(&.{
        v4Seen(a, public_v4, 10),
        v4Seen(b, public_v4, 12),
        seen(a, public_v6, 30, .v6, .v6),
        seen(b, public_v6, 31, .v6, .v6),
    });
    try t.expectEqual(public_v4, claims.v4.?.addr);
    try t.expectEqual(millis(10), claims.v4.?.latency);
    try t.expectEqual(public_v6, claims.v6.?.addr);
    try t.expectEqual(millis(30), claims.v6.?.latency);
    // Each is corroborated on its own relays, and the same two relays count for
    // both families because they are two probes rather than one.
    try t.expect(claims.v4.?.confirmed());
    try t.expect(claims.v6.?.confirmed());
    try t.expectEqual(claims.v4.?.addr, claims.get(.v4).?.addr);
    try t.expectEqual(claims.v6.?.addr, claims.get(.v6).?.addr);
}

test "a mapped address is claimed as the v4 address it names, and never as v6" {
    var scratch: [64]u8 = undefined;
    const a = try namedRelay(&scratch, 1);
    const b = try namedRelay(&scratch, 2);

    // A dual-stack relay answering a v4 probe: the frame is typed v6 and carries
    // `::ffff:198.51.100.7`, which `observed.canonical` unmaps before this
    // module sees it. The claim therefore lands in v4 and corroborates v4, and
    // the sixteen mapped octets never become a second path anywhere.
    const mapped = seen(b, public_v4, 12, .v6, .v4);
    try t.expectEqual(Family.v6, mapped.observation.family);
    try t.expectEqual(Family.v4, mapped.observation.ipFamily());
    try t.expect(mapped.isAddressBearing());

    const claim = fold(&.{ v4Seen(a, public_v4, 10), mapped }).v4.?;
    try t.expectEqual(public_v4, claim.addr);
    try t.expectEqual(@as(u8, 2), claim.relays);
    try t.expect(claim.confirmed());
    try t.expectEqual(@as(?Claim, null), fold(&.{mapped}).v6);

    // The same address on a v6 *probe* is a family mismatch, dropped whole,
    // exactly as `report_fold.fold` drops it (`report_fold.zig:276-283`).
    const mismatched = seen(b, public_v4, 12, .v6, .v6);
    try t.expect(!mismatched.isAddressBearing());
    const dropped = fold(&.{mismatched});
    try t.expectEqual(@as(?Claim, null), dropped.v4);
    try t.expectEqual(@as(?Claim, null), dropped.v6);

    // And the mapped octets themselves, un-canonicalised, become a v6 address
    // in the v6 claim — a second path for one public address, which is the
    // whole thing `canonical` prevents by unmapping before this module runs.
    // Two claims of one witness each, rather than one claim corroborated by the
    // same address written two ways.
    const raw = seen(a, .{ .ip = .{ .v6 = mapped_v6 }, .port = 41234 }, 10, .v6, .v6);
    try t.expect(std.meta.eql(raw.observation.addr.ip, .{ .v6 = mapped_v6 }));
    const split = fold(&.{ raw, v4Seen(b, public_v4, 12) });
    try t.expectEqual(@as(u8, 1), split.v6.?.relays);
    try t.expectEqual(@as(u8, 1), split.v4.?.relays);
    try t.expect(split.v6.?.unmeasured());
    try t.expect(split.v4.?.unmeasured());
}

test "a sighting past the bound is dropped and nothing fails" {
    var scratch: [64]u8 = undefined;
    var relays: [max_observers + 1]RelayUrl = undefined;
    var sightings: [max_observers + 1]Sighting = undefined;
    for (&relays, 0..) |*relay, index| relay.* = try namedRelay(&scratch, index + 1);
    for (&sightings, 0..) |*item, index| item.* = v4Seen(relays[index], public_v4, 10 + index);

    // Every relay says the same address, so the bound alone decides whether
    // this is corroborated. Five relays is `max_observers` and enough; a sixth
    // is dropped rather than refused, because a lost witness costs a weaker
    // claim and never a wrong one.
    const within = fold(sightings[0..max_observers]).v4.?;
    try t.expectEqual(@as(u8, max_observers), within.relays);
    try t.expect(within.confirmed());

    // Six relays arriving in ascending order: the first five fill the table and
    // the sixth is dropped. The bound is on the table rather than on arrival,
    // and the surviving five all reported the same address, so the claim is
    // unchanged — a lost witness costs a weaker claim, never a wrong one.
    const beyond = fold(sightings[0 .. max_observers + 1]).v4.?;
    try t.expectEqual(@as(u8, max_observers), beyond.relays);
    try t.expect(beyond.confirmed());
    try t.expectEqual(public_v4, beyond.addr);
    try t.expectEqual(millis(10), beyond.latency);

    // A table holding three relays reports three, never five.
    const three = fold(sightings[0..3]).v4.?;
    try t.expectEqual(@as(u8, 3), three.relays);
    try t.expect(three.confirmed());
    try t.expectEqual(millis(10), three.latency);
}

test "folding no sightings claims nothing, in either direction" {
    const claims = fold(&.{});
    try t.expectEqual(@as(?Claim, null), claims.v4);
    try t.expectEqual(@as(?Claim, null), claims.v6);
    try t.expectEqual(@as(?Claim, null), claims.get(.v4));
    try t.expectEqual(@as(?Claim, null), claims.get(.v6));
}

test "two accumulators over the same relay are two independent answers" {
    var scratch: [64]u8 = undefined;
    const a = try namedRelay(&scratch, 1);
    const b = try namedRelay(&scratch, 2);

    // State is a parameter, not a capture: one relay's word is one unmeasured
    // claim in each accumulator and neither can see the other's second relay.
    var first: Fold = .{};
    var second: Fold = .{};
    first.observe(v4Seen(a, public_v4, 10));
    try t.expect(first.claims().v4.?.unmeasured());
    try t.expectEqual(@as(?Claim, null), second.claims().v4);

    second.observe(v4Seen(a, public_v4, 10));
    second.observe(v4Seen(b, public_v4, 12));
    try t.expect(second.claims().v4.?.confirmed());
    try t.expect(first.claims().v4.?.unmeasured());
    try t.expectEqual(@as(?Claim, null), first.claims().v6);
}
