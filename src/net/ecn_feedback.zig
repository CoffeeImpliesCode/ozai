//! ECN feedback for one path: what the codepoint on it was, what that means,
//! and what the path should carry next.
//!
//! `docs/DECISIONS/0002-async-substrate.md` records the gap this closes:
//! "a P2P stack that drops ECN cannot report congestion to the path it actually
//! used." The plumbing that carries a codepoint is in place — `batch.Send.ecn`
//! going out and `batch.Recv.ecn` coming back (`transport/batch_run.zig:135`,
//! `:237`) — and nothing above it asks what a codepoint means. This module is
//! the part that asks, over one path.
//!
//! # What it holds and what it decides
//!
//! One `Path` value per path, and three answers over it:
//!
//! - `Seen.codepoint` names the codepoint a report is about, which is the
//!   first question.
//! - `Path.standing` is what that codepoint means for the path's capacity.
//! - `Path.marker` is the codepoint the next datagram on this path carries,
//!   which is the last.
//!
//! **A report is three counts and not a codepoint**, because that is what the
//! peer's report is: RFC 9000 §13.4.2 has a peer report cumulative ECT(0) and
//! CE tallies per packet number space rather than a codepoint per packet, and
//! `ack_handler`'s `ecn_ect0`/`ecn_ce` are exactly those two
//! (`vendor/quic/src/quic/ack_handler.zig:823-830`). Naming the codepoint is
//! therefore derived, in `Seen.codepoint`, so a report that claims a codepoint
//! its own counts do not support cannot be written.
//!
//! # Reversible standing, and why not a monotone one
//!
//! **The standing is reversible, and the threshold is what makes that safe.**
//! A CE says the path's bottleneck queue was full when one packet crossed it.
//! It is a report about a moment, not a fact about the address: the same path
//! at the same pair of sockets is congested at one minute and clear at the
//! next, and the only evidence of the change is the CE stopping. A monotone
//! rule — once congested, congested until the path is forgotten — throws that
//! evidence away and never hands the capacity back, so a path that recovered
//! keeps being throttled for the life of the connection and is throttled by a
//! fact that stopped being true.
//!
//! That is the opposite of what this directory does with every other figure.
//! `Entry.latency` hands back a null rather than a stale number
//! (`path_table.zig:195`), and `path_revalidate`'s module doc is explicit that
//! a figure which stops being true does not become a permanent refusal. A CE is
//! an RTT sample that happened to arrive as a codepoint, and it may not be a
//! stronger kind of evidence than one.
//!
//! Reversal needs a run, or it flaps. `recovery_run` accounted non-CE codepoints
//! win the capacity back, so the last CE on a busy path does not set the
//! standing back to what it was before the first, and a path crossing the
//! threshold once is not oscillating across it on single packets.
//!
//! # A dropped mark is not an unmarked packet
//!
//! **A mark the network did not carry is doubt, and doubt is never read as
//! clearance.** The two are the same bytes on the wire: a packet that went out
//! ECT(0) and arrived Not-ECT, and a packet that went out Not-ECT, are the same
//! two bits either side of the network, and neither the reader nor the writer
//! can tell them from the packet. `batch_opt.socketOptions` spells out the
//! socket-level version of the same trap — without `IP_RECVTOS` the kernel
//! sends no traffic class and every read reports not-ECT, "a silently wrong
//! answer rather than a missing one" (`transport/batch_opt.zig:298-300`).
//!
//! So a report says which marked packets the peer has acknowledged and how many
//! of them it accounted for, and `acked > accounted` is the shortfall: some
//! marked packet reached the peer and did not arrive marked. There are only two
//! places that can happen — the socket refused our control message, which
//! `Report.ecnSurvived` already reports and `node_stats.ecn_lost` already counts,
//! and something on the path between us. Neither is congestion, and neither is
//! evidence of capacity. The path goes to `.unknown`, which stops marking, and
//! `.unknown` is reachable from silence only through a positive report: nothing
//! is answered as clear until a codepoint that was accounted for arrives.
//!
//! A local mark loss needs no state here and gets none: the packet was never
//! marked on the wire, so it is never in the caller's `acked`, so it cannot
//! shorten the report and cannot raise doubt it did not earn. The transport
//! side owns that count and this module never sees it.
//!
//! The converse is the half that is easy to get wrong. **Silence clears
//! nothing.** A report that accounts for no marked packet at all is not a
//! clear path — it is no report — and a congested path stays congested across
//! any number of them. That is what makes the short-fall rule safe in the
//! direction that matters: a stack whose ECN is being dropped reads no CE for
//! ever, and the only standing that stops it declaring every path clear is one
//! that a CE cannot leave and silence cannot leave either.
//!
//! **One observation clears a doubt; a run earns clearance.** They are two
//! claims about two different things and they do not take the same evidence.
//! Doubt is about this stack's own plumbing — a control message was refused, or
//! a path is clearing marks — and one accounted codepoint disproves it, so
//! `.unknown` returns to `.probing` on the first one. Clearance is about the
//! network's queue, which is what the run is for.
//!
//! # One vocabulary
//!
//! `frame_types.Ecn` is the codepoint type and it is reused whole — this module
//! names no codepoint, spells no two-bit value and reads no traffic-class byte.
//! `relay/frame_types.zig:381` is where the three live, and it is where a
//! fourth would go; `Ecn` is re-exported under its own name here so a caller
//! passing one does not import a relay module to do it.
//!
//! # Purity and the boundary
//!
//! No socket, no clock, no allocator, no global. A path's standing is a value
//! a caller holds wherever it already holds its paths; nothing here decides
//! which paths a peer has or bounds how many, because `path_table.zig` does and
//! a second opinion about which paths exist is a second opinion about which
//! peer a datagram belongs to.
//!
//! **This is the first import from `src/net/` into `src/relay/`, and it is
//! worth saying why that is not the inversion `holepunch_run.zig` refuses.**
//! That module's rule is "nothing under `src/net/` imports `src/transport/`",
//! and this file still breaks nothing: `relay/frame_types.zig` is a value
//! module holding an enum and a header table, and it reaches `std` plus
//! `base/key.zig` and nothing else — no socket, no `Io`, no clock, no
//! allocator. Transport is the inversion because it holds the descriptor and
//! the syscalls; a codepoint is a two-bit value that already travels in a
//! `batch.Send`, so importing it upward is reuse rather than a new dependency.
//! The alternative — declaring a second three-value enum here — is what the
//! tree forbids outright ("a rule written down twice is a rule one table
//! extension away from being wrong in two places", `batch_run.zig:24-28`).
//!
//! `acked`, `ect0` and `ce` are per-report deltas over packets newly
//! acknowledged, not cumulative totals, because `ecn.EcnValidator.validate`
//! takes them that way (`vendor/quic/src/quic/ecn.zig:132-140`) and a total
//! cannot be compared against a path's own send history without the in-flight
//! set, which is the core's to hold. Nothing under `src/net/` imports
//! `src/transport/`, so the caller bridges: `transport/socket.zig` is the only
//! place a report becomes bytes, and it is the only place that knows whether
//! `IP_RECVTOS` was set on the socket that carried the answer.
//!
//! # What this module does not decide
//!
//! Three things a reader will look for here and will not find, each with its
//! owner:
//!
//! - **The window.** `vendor/quic/src/quic/congestion.zig` reduces it on a CE
//!   (`connection.zig:2663-2665`). Restating a window here would be a second
//!   congestion controller that no socket ever consults.
//! - **Which path carries.** `path_select.zig` ranks on latency and picks; a CE
//!   is not a latency and this module does not rank.
//! - **Whether the path carries ECN at all.** That is `ecn.EcnValidator` and its
//!   `.disabled`/`.testing`/`.capable`/`.failed` states
//!   (`vendor/quic/src/quic/ecn.zig:50-71`). The standing here is per path and
//!   is not that machine: `.clear` means no congestion was reported on this
//!   path, not that the path was validated, and `.unknown` means a mark did not
//!   survive, not that validation failed.
//!
//! `.unknown` here is not `holepunch.PathStatus.unknown`, which is a path
//! nobody has tried. This one is a path whose marking did not survive, and the
//! two differ in what they do: `path_select` selects an `.unknown` path because
//! refusing to would mean nothing is ever sent on it, and `marker` answers null
//! for this one because marking a path whose marks do not survive produces no
//! evidence and destroys the ability to tell congestion from a dropped mark.

const std = @import("std");
const addr = @import("../base/addr.zig");
const frame_types = @import("../relay/frame_types.zig");

const TransportAddr = addr.TransportAddr;

/// The codepoint vocabulary, reused whole from `relay/frame_types.zig:381`.
///
/// Re-exported under this module's own name rather than referred to by import
/// at every use, so a caller that already holds a `batch.Send.ecn` — which is
/// this same type, via `batch_run.zig:29` — passes it without importing a
/// relay module and without a conversion that does not exist.
pub const Ecn = frame_types.Ecn;

/// How many accounted non-CE codepoints win back a congested path's marking.
///
/// Ten, which is the number `ecn.EcnValidator` already uses for the same
/// question — enough packets sent before a path's ECN behaviour is judged at
/// all (`vendor/quic/src/quic/ecn.zig:45`) — because a rule written down twice
/// is a rule one table extension away from being wrong in two places. It
/// counts reports rather than packets because the caller is what holds the
/// packet ledger, and a run of reports is what the peer can actually be held to.
pub const recovery_run: u8 = 10;

/// What one path's capacity is believed to be.
///
/// Four values, and the two that stop marking are the two that are not clear.
/// A path this module has no better reading for than "mark it" still gets
/// marked, because marking is the only thing that produces the evidence the
/// next reading is made of — `ecn.EcnValidator` marks through `.testing` and
/// `.unknown` for the same reason.
pub const Standing = enum {
    /// Marking is in use and nothing has said this path is congested, and no
    /// run has been earned yet. The value a path is born with.
    probing,
    /// A run of accounted non-CE codepoints. The path was marked all along, so
    /// this records that the marking has been understood rather than that the
    /// path has capacity it did not have.
    clear,
    /// A CE was reported and the run that would undo it has not been earned.
    congested,
    /// Marking was in use and did not survive the path: some marked packet the
    /// peer acknowledged arrived without its codepoint. See the module doc.
    unknown,
};

/// What one report from the peer says about one path.
///
/// Three deltas over the packets this report newly acknowledges, in the shape
/// RFC 9000 §13.4.2 and `ecn.EcnValidator.validate` already use
/// (`vendor/quic/src/quic/ecn.zig:132-140`). Deltas rather than totals because
/// a total cannot be compared against a path's own send history without the
/// in-flight set, which is the core's to hold.
///
/// **Zero is what each of them means when the peer accounted for none of those
/// packets, so all three default to zero.** That report is one this module is
/// named for — `observe` reads it as silence, and silence clears nothing — so
/// it has to be spellable: `.{}` is "no report" and `.{ .acked = 9 }` is the
/// shortfall. `ack_handler`'s three counters, which are the numbers these are,
/// default the same way (`vendor/quic/src/quic/ack_handler.zig:823-830`).
///
/// A default here cannot state a claim. Zero `acked` is never above
/// `accounted()`, so it cannot invent a shortfall, and zero `ect0` and `ce`
/// leave `codepoint` null, so they cannot advance `clean_run`. What a default
/// cannot recover is a real shortfall a caller left out, and `acked` is the
/// core's own number rather than this module's — see the module doc under "A
/// dropped mark" — so stating it is the caller's obligation whatever the
/// default says.
pub const Seen = struct {
    /// Marked packets this peer has newly acknowledged on this path.
    ///
    /// Marked means the codepoint went on the wire, so a packet whose control
    /// message the socket refused is not in here and cannot appear as a
    /// shortfall — see the module doc under "A dropped mark".
    acked: u64 = 0,
    /// Of those, how many arrived ECT(0): the mark survived the path.
    ect0: u64 = 0,
    /// Of those, how many arrived CE: the path was congested and said so.
    ///
    /// Congestion is reported for a packet the path already accepted, so this
    /// is never evidence that the path is idle.
    ce: u64 = 0,

    /// How many of `acked` the peer accounted for with a codepoint at all.
    ///
    /// Saturating, because two deltas each near the top of the range are
    /// summed here and a wrapped total would read as a shortfall on a path
    /// that reported everything.
    pub fn accounted(self: Seen) u64 {
        return self.ect0 +| self.ce;
    }

    /// The codepoint this report is about, or null for none.
    ///
    /// Derived from the counts rather than carried beside them, so no report
    /// can name a codepoint its own numbers do not support. CE wins over
    /// ECT(0) when both are present: a report with any CE in it is a
    /// congestion report, and that is the one fact a path's standing turns on.
    ///
    /// Null is not "not congested". It is a report that accounted for nothing
    /// marked, which is silence, and `observe` reads it as silence.
    pub fn codepoint(self: Seen) ?Ecn {
        if (self.ce > 0) return .ce;
        if (self.ect0 > 0) return .ect0;
        return null;
    }
};

/// One path's ECN standing: what its last reports said, and what it should carry.
///
/// A value, held by whoever already holds the path, and nothing more: no
/// address table, no allocator and no clock, so a `Path` is a few dozen bytes on
/// a stack and a copy is an independent standing rather than a second view of
/// one.
pub const Path = struct {
    /// Where this path goes. The identity, and the guard on every report: a
    /// report about another path is refused rather than folded in, because a
    /// measurement credited to the wrong path is a standing nobody observed.
    /// Compared with `TransportAddr.order`, which is what `path_table` and
    /// `holepunch_failure_memory` compare with.
    addr: TransportAddr,
    /// What the path's capacity is believed to be. Born `.probing`.
    standing: Standing = .probing,
    /// Accounted non-CE codepoints seen in a row, saturating at
    /// `recovery_run`. The distance to `.clear` from `.probing` or
    /// `.congested`, and zero everywhere else: a CE, a shortfall and a return
    /// from `.unknown` each restart it.
    clean_run: u8 = 0,

    /// A path at `addr` with no reports on it yet.
    ///
    /// Born `.probing` rather than clear, which is the one that does not
    /// deadlock: a path that refuses to mark is a path that never receives a
    /// marked packet, so it is never accounted for, so it never becomes clear.
    pub fn init(address: TransportAddr) Path {
        return .{ .addr = address };
    }

    /// Fold one report in and answer whether it was about this path.
    ///
    /// False for an address this `Path` does not name, and nothing moves: the
    /// refusal `path_table.sample` makes for the same reason, that a
    /// measurement of a path this value does not hold would have to be
    /// attributed to some other path. True otherwise, including for a report
    /// that says nothing, because silence is an observation and this module
    /// answers it.
    ///
    /// The order is the decision and it is the module doc's:
    ///
    /// 1. A shortfall is doubt whatever else the report says, and doubt is the
    ///    only thing here that stops marking without a CE behind it.
    /// 2. A CE is congestion, and it replaces doubt: positive news about the
    ///    path beats a plumbing failure we cannot see around.
    /// 3. An accounted codepoint leaves doubt on its own, in one report.
    /// 4. Anything else advances the run, and only a full run is `.clear`.
    ///
    /// A report that accounts for nothing falls out of all four and moves
    /// nothing, which is what keeps silence from being clearance.
    pub fn observe(self: *Path, address: TransportAddr, seen: Seen) bool {
        if (self.addr.order(address) != .eq) return false;
        if (seen.acked > seen.accounted()) {
            self.standing = .unknown;
            self.clean_run = 0;
            return true;
        }
        const mark = seen.codepoint() orelse return true;
        if (mark == .ce) {
            self.standing = .congested;
            self.clean_run = 0;
            return true;
        }
        if (self.standing == .unknown) {
            self.standing = .probing;
            self.clean_run = 0;
            return true;
        }
        // Saturating, so a path that stays clear for the life of a connection
        // counts to the threshold and stops rather than wrapping past it and
        // standing a whole run's credit short of `.clear`.
        if (self.clean_run < recovery_run) self.clean_run += 1;
        if (self.clean_run == recovery_run) {
            self.standing = .clear;
            self.clean_run = 0;
        }
        return true;
    }

    /// The codepoint the next datagram on this path carries, or null for none.
    ///
    /// ECT(0) unless the path is `.congested` or `.unknown`, and ECT(1) never:
    /// this stack does not use it, which is why `ack_handler` counts a peer's
    /// ECT(1) as the peer's doing (`vendor/quic/src/quic/ack_handler.zig:824`)
    /// and why an ECT(1) report is not congestion here either. Null is the
    /// same value `batch.Send.ecn` takes for none and needs no conversion.
    ///
    /// A pure read. It does not advance anything, so a path nobody reports on
    /// keeps the answer it was born with for ever — which is why the default
    /// marks.
    pub fn marker(self: *const Path) ?Ecn {
        return switch (self.standing) {
            .probing, .clear => .ect0,
            .congested, .unknown => null,
        };
    }
};

comptime {
    // A recovery run of zero would let one clean report undo a CE, which is the
    // flap the run exists to prevent, and it would do it silently rather than
    // as a claim a reader could check.
    std.debug.assert(recovery_run > 0);
}

// --- tests

const t = std.testing;

/// A direct address on `port` from one documentation range, so a test that
/// prints one is never mistaken for a routable host.
fn ip(port: u16) addr.SocketAddr {
    return .{ .ip = .{ .v4 = .{ 192, 0, 2, 1 } }, .port = port };
}

/// `ip(port)` as the address a path is keyed on.
fn at(port: u16) TransportAddr {
    return .{ .ip = ip(port) };
}

/// A report of `marked` newly acknowledged marked packets, all of which came
/// back carrying `codepoint`.
///
/// The `.ect1` arm is the whole of what this stack can say about ECT(1): a
/// report of it is a report of nothing, because no packet here was ever marked
/// with it and so none is in the caller's `acked`. It is spelled as silence
/// rather than refused, so a caller passing one learns what crossed the path
/// rather than being handed a packet nobody can account for.
fn report(marked: u64, codepoint: Ecn) Seen {
    return switch (codepoint) {
        .ect0 => .{ .acked = marked, .ect0 = marked, .ce = 0 },
        .ect1 => .{ .acked = 0, .ect0 = 0, .ce = 0 },
        .ce => .{ .acked = marked, .ect0 = 0, .ce = marked },
    };
}

test "a path nobody has heard from is marked, and marking is what gets it evidence" {
    var path = Path.init(at(1000));
    // No reports, and the answer is ECT(0) rather than null. The alternative
    // deadlocks in one step: a path that refuses to mark is never sent a
    // marked packet, so no report ever accounts for one, so it never reaches a
    // standing that would mark it.
    try t.expectEqual(@as(?Ecn, .ect0), path.marker());
    try t.expectEqual(Standing.probing, path.standing);

    // One report of marked packets that all came back marked is enough to move
    // the run, and ten of them clear it. Without that the loop above never
    // closes.
    var round: u8 = 0;
    while (round < recovery_run - 1) : (round += 1) {
        try t.expect(path.observe(at(1000), report(4, .ect0)));
        try t.expectEqual(Standing.probing, path.standing);
    }
    try t.expect(path.observe(at(1000), report(4, .ect0)));
    try t.expectEqual(Standing.clear, path.standing);
    try t.expectEqual(@as(?Ecn, .ect0), path.marker());
}

test "a CE takes the marking off and only a full run puts it back" {
    var path = Path.init(at(1000));
    _ = path.observe(at(1000), report(4, .ect0));
    try t.expect(path.observe(at(1000), report(4, .ce)));
    try t.expectEqual(Standing.congested, path.standing);
    try t.expectEqual(@as(?Ecn, null), path.marker());

    // Nine of the ten do not: the last CE sets the run back rather than being
    // undone by the next clean report, which is what stops a busy path
    // oscillating across the threshold on single packets.
    var round: u8 = 0;
    while (round < recovery_run - 1) : (round += 1) {
        try t.expect(path.observe(at(1000), report(4, .ect0)));
        try t.expectEqual(Standing.congested, path.standing);
        try t.expectEqual(@as(?Ecn, null), path.marker());
    }
    try t.expect(path.observe(at(1000), report(4, .ect0)));
    try t.expectEqual(Standing.clear, path.standing);
    try t.expectEqual(@as(?Ecn, .ect0), path.marker());

    // A second CE restarts the same run rather than adding to it, so a path
    // that is congested every few reports never accumulates a credit.
    try t.expect(path.observe(at(1000), report(4, .ce)));
    try t.expectEqual(Standing.congested, path.standing);
    _ = path.observe(at(1000), report(4, .ect0));
    try t.expectEqual(Standing.congested, path.standing);
    try t.expect(path.observe(at(1000), report(4, .ce)));
    // Still congested, and the run is back at zero rather than at the one the
    // single clean report before it earned.
    try t.expectEqual(@as(u8, 0), path.clean_run);
}

test "a run saturates at the threshold instead of wrapping past it" {
    var path = Path.init(at(1000));
    // Far more clean reports than the run needs, and the standing and the
    // counter are both what they would be after exactly the tenth. A counter
    // that wrapped would leave the path a whole run's credit short of `.clear`
    // for the rest of its life, and nothing would report it.
    var round: u8 = 0;
    while (round < 200) : (round += 1) {
        _ = path.observe(at(1000), report(4, .ect0));
    }
    try t.expectEqual(Standing.clear, path.standing);
    try t.expectEqual(@as(u8, 0), path.clean_run);
    try t.expect(recovery_run > 0);
}

test "a mark that did not survive is doubt, and doubt does not mark" {
    var path = Path.init(at(1000));
    var round: u8 = 0;
    while (round < recovery_run) : (round += 1) {
        _ = path.observe(at(1000), report(4, .ect0));
    }
    try t.expectEqual(Standing.clear, path.standing);

    // Twelve marked packets the peer acknowledged and none of them accounted
    // for: some marked packet reached the peer and did not arrive marked. That
    // is not congestion and it is not capacity, so the path stops marking
    // rather than reading the shortfall as a clear path.
    try t.expect(path.observe(at(1000), .{ .acked = 12, .ect0 = 0, .ce = 0 }));
    try t.expectEqual(Standing.unknown, path.standing);
    try t.expectEqual(@as(?Ecn, null), path.marker());
    try t.expectEqual(@as(u8, 0), path.clean_run);

    // Even a report that says the path is fine does not clear the doubt: one
    // accounted codepoint is what leaves it, and silence must never do better.
    try t.expect(path.observe(at(1000), .{}));
    try t.expectEqual(Standing.unknown, path.standing);
    try t.expectEqual(@as(?Ecn, null), path.marker());

    // A shortfall outranks a CE in the same report, because it means the
    // report's own numbers cannot be taken at face value at all: twenty
    // acknowledged, ten accounted for, and a CE among them.
    try t.expect(path.observe(at(1000), .{ .acked = 20, .ect0 = 1, .ce = 9 }));
    try t.expectEqual(Standing.unknown, path.standing);
    try t.expectEqual(@as(?Ecn, null), path.marker());
}

test "one accounted codepoint leaves doubt and a run still earns clearance" {
    var path = Path.init(at(1000));
    _ = path.observe(at(1000), .{ .acked = 5, .ect0 = 0, .ce = 0 });
    try t.expectEqual(Standing.unknown, path.standing);

    // Doubt is about this stack's plumbing, and one codepoint that survived
    // disproves it. The path is probing again — marked, and not yet clear,
    // because clearance is a claim about the network's queue and that takes a
    // run whatever ended the doubt.
    try t.expect(path.observe(at(1000), report(6, .ect0)));
    try t.expectEqual(Standing.probing, path.standing);
    try t.expectEqual(@as(u8, 0), path.clean_run);
    try t.expectEqual(@as(?Ecn, .ect0), path.marker());

    // And a CE in the same position takes over from doubt, because positive
    // news about the path outranks a plumbing failure we cannot see around.
    try t.expect(path.observe(at(1000), .{ .acked = 5, .ect0 = 0, .ce = 0 }));
    try t.expectEqual(Standing.unknown, path.standing);
    try t.expect(path.observe(at(1000), report(6, .ce)));
    try t.expectEqual(Standing.congested, path.standing);
    try t.expectEqual(@as(?Ecn, null), path.marker());
}

test "silence clears nothing, and a congested path is the case that matters" {
    var path = Path.init(at(1000));
    try t.expect(path.observe(at(1000), report(4, .ce)));
    try t.expectEqual(Standing.congested, path.standing);

    // Any number of reports that account for nothing at all. This is the half
    // that is easy to get wrong: a stack whose ECN is being dropped reads no
    // CE for ever, and the only standing that stops it declaring every path
    // clear is one that silence cannot leave.
    var round: u8 = 0;
    while (round < 50) : (round += 1) {
        try t.expect(path.observe(at(1000), .{}));
        try t.expectEqual(Standing.congested, path.standing);
        try t.expectEqual(@as(?Ecn, null), path.marker());
    }

    // A path nobody has reported on at all is not congestion and not clear
    // either: it is `.probing`, and it marks.
    const virgin = Path.init(at(2000));
    try t.expectEqual(Standing.probing, virgin.standing);
    try t.expectEqual(@as(?Ecn, .ect0), virgin.marker());
}

test "a report about another path is refused and moves nothing" {
    var path = Path.init(at(1000));
    try t.expect(path.observe(at(1000), report(4, .ce)));
    try t.expectEqual(Standing.congested, path.standing);

    // A CE measured on a path this value does not name. Folding it in would
    // throttle 1000 on 1001's congestion, and there is no second question to
    // ask afterwards, because the standing that resulted would be right about
    // neither path.
    try t.expect(!path.observe(at(1001), report(4, .ect0)));
    // And the address itself is untouched by a refused report, so a caller
    // that misfiled one cannot recover by re-reading this value's identity.
    try t.expect(path.addr.order(at(1000)) == .eq);
    try t.expect(path.addr.order(at(1001)) != .eq);
    try t.expectEqual(Standing.congested, path.standing);
    try t.expectEqual(@as(u8, 0), path.clean_run);
}

test "the codepoint a report names is the one its own counts support" {
    // Silence is null, and null is not "not congested".
    try t.expectEqual(@as(?Ecn, null), (Seen{}).codepoint());
    try t.expectEqual(@as(?Ecn, null), (Seen{ .acked = 9 }).codepoint());
    try t.expectEqual(@as(u64, 0), (Seen{}).accounted());

    // One accounted packet is a codepoint. A partial one — some acknowledged,
    // some accounted — names the codepoint of the ones that came back, because
    // that is the news the report carries.
    try t.expectEqual(@as(?Ecn, .ect0), (Seen{ .acked = 9, .ect0 = 1 }).codepoint());
    try t.expectEqual(@as(?Ecn, .ce), (Seen{ .acked = 9, .ce = 1 }).codepoint());
    try t.expectEqual(@as(u64, 9), (Seen{ .acked = 9, .ect0 = 4, .ce = 5 }).accounted());

    // CE outranks ECT(0) when a report holds both, because a report with any
    // CE in it is a congestion report and that is the one fact a standing
    // turns on.
    const both: Seen = .{ .acked = 9, .ect0 = 4, .ce = 5 };
    try t.expectEqual(@as(?Ecn, .ce), both.codepoint());
    var path = Path.init(at(1000));
    _ = path.observe(at(1000), .{ .acked = 9, .ect0 = 9, .ce = 0 });
    try t.expectEqual(Standing.probing, path.standing);
    _ = path.observe(at(1000), both);
    try t.expectEqual(Standing.congested, path.standing);

    // ECT(1) is a value the vocabulary has and this module never names and
    // never puts on the wire. `Seen` has no column for an ECT(1) report at
    // all, because this stack never marks with one — `ack_handler` counts a
    // peer's ECT(1) as the peer's doing
    // (`vendor/quic/src/quic/ack_handler.zig:824-826`) — so the only such
    // "report" this module can be handed is silence, and `codepoint` answers
    // null for it. `marker` likewise never answers `.ect1`.
    try t.expectEqual(@as(?Ecn, null), report(4, .ect1).codepoint());
    try t.expectEqual(@as(?Ecn, null), path.marker());
    var fresh = Path.init(at(1000));
    try t.expectEqual(@as(?Ecn, .ect0), fresh.marker());
}

test "the codepoint handed back is the one batch.Send.ecn takes" {
    // `batch.Send.ecn` is `?frame.Ecn` (`transport/batch_run.zig:51`) and
    // `tosBits` reads it through `Ecn.toBits`, so a path's answer is the same
    // value the send's ancillary data is built from, with no conversion and no
    // second vocabulary in between.
    // And the two answers are the two the wire has for "mark it" and "do not
    // mark it", read back through the type's own two-bit spelling: ECT(0) is
    // `0b10`, and absence is `0b00`, which is what `tosBits` writes for a null
    // codepoint (`batch_run.zig:327-328`) and what `Ecn.fromBits` reads back as
    // no codepoint at all (`frame_types.zig:391`). A `Path` that answered with
    // anything else would not survive the trip to the socket.
    var path = Path.init(at(1000));
    try t.expectEqual(@as(?Ecn, .ect0), path.marker());
    try t.expectEqual(@as(u8, 0b10), Ecn.toBits(path.marker().?));
    try t.expectEqual(@as(?Ecn, .ect0), Ecn.fromBits(0b10));

    _ = path.observe(at(1000), report(4, .ce));
    try t.expectEqual(@as(?Ecn, null), path.marker());
    // Absence is spelled `0b00` and reads back as absence: the wire has no
    // fourth codepoint for "do not mark", and `marker` needs none.
    try t.expectEqual(@as(?Ecn, null), Ecn.fromBits(0b00));

    // And back the other way, a path that was throttled and won its marking
    // back answers the same value a path that never lost it does.
    var round: u8 = 0;
    while (round < recovery_run) : (round += 1) {
        _ = path.observe(at(1000), report(4, .ect0));
    }
    try t.expectEqual(Standing.clear, path.standing);
    try t.expectEqual(@as(u8, 0b10), Ecn.toBits(path.marker().?));
}
