//! Which relay this node should home on, and what the answer obliges a caller
//! to do.
//!
//! `report_fold.choosePreferredRelay` already owns the first half of the
//! question: the lowest recent latency among the relays a folded report can
//! still see, merged over every report inside `report_measure.max_report_age`
//! and held over from the previous report unless a challenger beats it by two
//! thirds (`report_fold.zig:325`-`:371`). This module does not restate that rule
//! and holds no latency table of its own. It answers the narrower question the
//! fold has no way to ask.
//!
//! # What a preferred relay is for
//!
//! **It is not the nearest relay. It is the one this node can still reach.**
//! The fold's output is a ranking over *measurements*, and a measurement is a
//! statement about a round trip that happened. Two things sit between that and
//! "home on this relay", and both are refusals:
//!
//! 1. **The relay has to be one this node is configured to dial.** Upstream
//!    seeds a report from whatever a live QUIC connection last saw
//!    (`probe_turn.new` via `probe_plan`'s `carried_v4` / `carried_v6`), so a
//!    folded report can name a relay nobody put in the configuration. Upstream
//!    is happy to home on it, because upstream's node is handed its relay map
//!    and the same code built the report. This node's relay list is a
//!    `discovery/preset.Preset.relays` the operator chose, and a preference is
//!    an instruction to *dial*, so a relay outside that list is refused rather
//!    than substituted for.
//! 2. **Nothing may claim reachability it has not measured.** A preferred relay
//!    here means "the evidence in this report points here", never "this relay
//!    answers". The only reachability fact in this tree is `relay.Cause` in
//!    `relay/reconnect.zig`, and this module does not touch it. See below.
//!
//! # Why the fold is consumed and not re-derived
//!
//! Consuming `Report.preferred_relay` is the whole of the first decision, and
//! the reason is that a second latency order would be a second opinion about
//! which relay is faster with nothing to say which is right. The fold already
//! owns three things this tree would otherwise have to restate: the recency
//! window, the fastest-figure-ever-seen rule behind
//! `report_measure.RelayList.update`, and the two-thirds hysteresis that stops
//! a node from flapping between two relays of nearly equal latency. `path_select`
//! reached the same conclusion for the same question — which path carries — and
//! its module doc says why in one line; this is that line applied to relays.
//!
//! What the fold deliberately does not say is *why* it chose, and this module
//! does not reconstruct it either. `choosePreferredRelay` can name a relay that
//! this round's latency table does not show as fastest, because the merge
//! window and the hysteresis both reach outside this round, and the report it
//! returns does not carry the merged figure. Re-deriving "the fastest" here
//! would therefore not reproduce the fold's answer — it would replace it with a
//! different and simpler one. So the reason below describes what the *caller*
//! has to do, which is the part a caller can act on, and `report_fold`'s own
//! doc stays where the reason it chose lives.
//!
//! # Why nothing here knows about an unreachable relay
//!
//! `relay/reconnect.zig` already models the two facts that make a relay
//! unusable — a relay that vanished and a relay that announced a restart — each
//! with its own budget, its own backoff and its own `Cause`. Selection has
//! nothing to add to that and does not try. It has no timers, no attempts and
//! no give-up, and there is no variant of this file that would: the interaction
//! runs in one direction and it runs by *exclusion*.
//!
//! - When a caller is handed `reconnect.Action.give_up`, the relay is out. The
//!   caller passes null for `previous` — this node is homed on nothing — and it
//!   keeps that relay out of the pool it hands to `relay_selection.plan`. The
//!   next `prefer` call then answers over what is left, or answers that
//!   nothing was measured.
//! - While `reconnect` is still inside a budget for a relay, that relay is not
//!   dead to this module; it is merely being retried, and a preference that
//!   named it is not wrong, it is early.
//!
//! Neither of those is a fact this module can hold without a second copy of a
//! deadline. That is the whole of the interaction: **selection consumes the
//! verdict, and the verdict is somebody else's.** Re-deciding a relay's fate
//! here would mean two `give_up` instants that could disagree.

const std = @import("std");
const addr = @import("../base/addr.zig");
const report_mod = @import("report.zig");

const RelayUrl = addr.RelayUrl;

/// Nanoseconds on the caller's own timeline, re-exported so a caller holding a
/// `Selected.latency` and an instant has one import rather than two. This is
/// `relay/reconnect.zig`'s `Nanos` too, reached through `report_measure`.
pub const Nanos = report_mod.Nanos;

/// What a folded report is about. Re-exported because every input to `prefer`
/// is a report or a pool of relays, and a caller spelling `report.Report` here
/// means importing `report.zig` anyway.
pub const Report = report_mod.Report;

/// What the caller has to do about the answer.
///
/// **A reason about the caller, not about the fold.** `report_fold`'s own reason
/// for choosing is inside `choosePreferredRelay` and is not recomputed here; see
/// the module doc. What is knowable from a report and a previous relay is
/// exactly these three things, and they are three because a caller takes three
/// different actions.
pub const Reason = enum {
    /// This node was homed on nothing, so the relay is simply the one to home
    /// on. A first connection has no incumbent and no hysteresis to honour, so
    /// this is the common case for a fresh node.
    adopted,
    /// The relay is the one already homed on: nothing to do. Reported
    /// explicitly because "no change" is the answer a caller most often wants
    /// and a `?RelayUrl` on its own cannot say it.
    held,
    /// A different relay from the one homed on. The previous relay is carried
    /// in `Selected.previous` so a caller can log the move without holding the
    /// older report.
    moved,
};

/// The relay to home on, and the caller's part of the story.
pub const Selected = struct {
    /// The relay. A by-value copy that borrows nothing: it outlives the report
    /// it came from, exactly as `report_measure.RelayLatency.relay` does.
    relay: RelayUrl,
    /// The relay the caller was homed on, when it was homed on one. Null on
    /// `.adopted` and never anything else, so `reason` never has to be read to
    /// know whether there is a previous relay.
    previous: ?RelayUrl,
    /// What to do about it.
    reason: Reason,
    /// The fastest latency this report holds for `relay`, and null when it
    /// holds none.
    ///
    /// A report from `report_fold.fold` never answers null: the fold's
    /// candidate loop walks this round's own table, and the two-thirds hold
    /// that could substitute an unprobed relay is guarded on a nonzero current
    /// latency, so every relay the fold names is one it measured. Null is
    /// still a value, because `prefer` takes a `Report` from a caller and a
    /// caller may build one field-wise — `report.zig`'s tests do. A caller is
    /// given no number nobody measured, whichever report it brought.
    latency: ?Nanos,
};

/// The three answers, kept apart because a caller recovers from them
/// differently.
pub const Choice = union(enum) {
    /// A relay to home on.
    selected: Selected,
    /// The report names a relay this node is not configured to dial. Nothing is
    /// substituted for it: the pooled relay with the best figure is a *different
    /// answer*, and handing it back here would hide the fact that the report is
    /// about somebody else's relay — which is a configuration fault, not a
    /// measurement to be worked around. `relay_selection` falls back to the
    /// measured relays; this module does not, because falling back is choosing,
    /// and choosing is `relay_selection`'s list.
    outside_pool,
    /// The report names no relay at all. For a report from
    /// `report_fold.fold` that is exactly an empty `Report.relay_latency`,
    /// because the fold only chooses a preferred relay from relays the round
    /// measured — but the arm is written against `preferred_relay` being null
    /// rather than against the table, so a caller who built a report field-wise
    /// gets the same answer. It is not a fault and it is not a refusal to try:
    /// a node that has never dialled has no preference yet, and
    /// `relay_selection` still hands it the whole pool to try.
    unmeasured,
};

/// What `prefer` is asked, and over what.
pub const Input = struct {
    /// The folded report. Its `preferred_relay` is the only field read for the
    /// choice and its `relay_latency` is the only one read for the evidence.
    report: Report,
    /// The relays this node is configured to dial: a `discovery/preset`'s
    /// `relays`, parsed. Order does not matter and membership is everything;
    /// `relay_selection` is where an order is imposed.
    pool: []const RelayUrl,
    /// The relay this node is currently homed on, or null when it is homed on
    /// nothing — which is what a caller holds after `reconnect` gave up on it,
    /// and what a node with no connection yet holds.
    previous: ?RelayUrl = null,
};

/// The relay to home on, or why none is named.
pub fn prefer(input: Input) Choice {
    // `choosePreferredRelay` walks this round's `relay_latency` and takes the
    // first entry it sees when nothing beats it, so a report with entries in
    // the table always ends with a preferred relay. Null and "measured
    // nothing" are therefore one fact, which is what `.unmeasured` says.
    const wanted = input.report.preferred_relay orelse return .unmeasured;
    if (!inPool(input.pool, wanted)) return .outside_pool;
    return .{ .selected = .{
        .relay = wanted,
        .previous = input.previous,
        .reason = if (input.previous) |held| heldReason(held, wanted) else .adopted,
        .latency = input.report.relay_latency.get(wanted),
    } };
}

/// Whether `pool` holds `relay`.
///
/// Through `RelayUrl.order`, because that is how one relay compares to another
/// anywhere in this tree: `parse` writes only the host's first `host_length`
/// bytes, so the 253-byte array behind a URL has a tail no comparison may read
/// (`base/addr.zig`'s `RelayUrl.hostSlice`, and `report_fold.sameRelay`).
fn inPool(pool: []const RelayUrl, relay: RelayUrl) bool {
    for (pool) |candidate| {
        if (candidate.order(relay) == .eq) return true;
    }
    return false;
}

/// Whether `wanted` is the relay already homed on.
///
/// A comparison and not a tag test, for the reason above.
fn heldReason(held: RelayUrl, wanted: RelayUrl) Reason {
    return if (held.order(wanted) == .eq) .held else .moved;
}

// --- tests

const t = std.testing;

/// Ten minutes on the caller's timeline. Past `report_measure.max_report_age`,
/// so a history entry can be placed on either side of the window.
const test_now: Nanos = 600 * std.time.ns_per_s;

fn millis(n: u64) Nanos {
    return n * std.time.ns_per_ms;
}

/// The relay the fold names, with `latency` as this round's figure for it.
fn homeOn(wanted: RelayUrl, latency: Nanos) Report {
    var latencies: report_mod.RelayLatencies = .{};
    _ = latencies.update(wanted, latency, .https);
    return .{ .preferred_relay = wanted, .relay_latency = latencies };
}

/// Whether a `Choice` is the named arm.
///
/// Through `std.meta.activeTag` rather than `==`, because a union whose payload
/// holds a `RelayUrl` has no byte-wise equality this toolchain accepts: a
/// `RelayUrl` is a struct with a padding tail, and comparing it as bytes is not
/// an equivalence. The tag is also the whole of what these assertions ask —
/// every test below reads the payload through a `switch` where it matters.
fn isArm(choice: Choice, comptime tag: std.meta.Tag(Choice)) bool {
    return std.meta.activeTag(choice) == tag;
}

// The fold's answer is taken whole. This report's latency table says `quick`
// is the fastest thing in it and the fold still names `held`, because the fold
// merges a window and applies a two-thirds margin; a module that ranked the
// table itself would answer `quick` here.
test "the fold's relay is the relay, not the fastest this round measured" {
    const held = try RelayUrl.parse("https://held.example./");
    const quick = try RelayUrl.parse("https://quick.example./");

    // The hold that produces the disagreement: a previous report naming `held`.
    const previous: Report = .{ .preferred_relay = held };
    var last: report_mod.RelayLatencies = .{};
    _ = last.update(held, millis(30), .https);
    const report = report_mod.fold(&.{
        .{ .https = .{ .relay = held, .instant = test_now, .latency = millis(30) } },
        .{ .https = .{ .relay = quick, .instant = test_now, .latency = millis(21) } },
    }, .{ .last = previous, .entries = &.{
        .{ .instant = test_now, .report = .{ .relay_latency = last } },
    } }, test_now);

    // The fold held `held` against a challenger at 21 ms: two thirds of 30 ms is
    // 20 ms, and 21 ms does not beat that line. This is `report_fold`'s rule
    // and it is asserted here so the disagreement below is a known-good fold
    // rather than a strange one.
    try t.expectEqual(std.math.Order.eq, report.preferred_relay.?.order(held));
    // And this round's table says the other one is faster, which is the fact a
    // re-derivation would have ranked on.
    try t.expectEqual(millis(21), report.relay_latency.get(quick).?);
    try t.expectEqual(millis(30), report.relay_latency.get(held).?);

    const choice = prefer(.{
        .report = report,
        .pool = &.{ held, quick },
        .previous = held,
    });
    switch (choice) {
        .selected => |chosen| {
            // The fold's relay, and the caller's part: nothing to do.
            try t.expectEqual(std.math.Order.eq, chosen.relay.order(held));
            try t.expectEqual(Reason.held, chosen.reason);
            try t.expectEqual(std.math.Order.eq, chosen.previous.?.order(held));
            // The evidence, which is the figure this round holds and not the
            // merged one the fold ranked on.
            try t.expectEqual(millis(30), chosen.latency.?);
        },
        else => return error.TestUnexpectedResult,
    }
}

// A node homed on one relay and handed a report naming another is told to move,
// and is given the relay it is leaving so the log line needs nothing else.
test "a different relay is a move, and the one being left comes with it" {
    const home = try RelayUrl.parse("https://home.example./");
    const next = try RelayUrl.parse("https://next.example./");

    const choice = prefer(.{
        .report = homeOn(next, millis(12)),
        .pool = &.{ home, next },
        .previous = home,
    });
    switch (choice) {
        .selected => |chosen| {
            try t.expectEqual(std.math.Order.eq, chosen.relay.order(next));
            try t.expectEqual(Reason.moved, chosen.reason);
            try t.expectEqual(std.math.Order.eq, chosen.previous.?.order(home));
        },
        else => return error.TestUnexpectedResult,
    }

    // The same relay with nothing homed on is an adoption, not a move: the
    // difference is a fact about the caller, not about the relay.
    const fresh = prefer(.{
        .report = homeOn(next, millis(12)),
        .pool = &.{ home, next },
    });
    switch (fresh) {
        .selected => |chosen| {
            try t.expectEqual(Reason.adopted, chosen.reason);
            try t.expectEqual(@as(?RelayUrl, null), chosen.previous);
        },
        else => return error.TestUnexpectedResult,
    }
}

// The refusal is a refusal and not a substitution: a report about a relay this
// node does not dial names nothing, even when a pooled relay has a figure.
test "a relay this node does not dial is refused and nothing takes its place" {
    const foreign = try RelayUrl.parse("https://elsewhere.example./");
    const mine = try RelayUrl.parse("https://mine.example./");

    const choice = prefer(.{
        .report = homeOn(foreign, millis(4)),
        .pool = &.{mine},
        .previous = null,
    });
    try t.expect(isArm(choice, .outside_pool));

    // The refusal does not depend on there being nothing better: `mine` is in
    // the report's own latency table with a slower figure, and it is not
    // promoted. Ranking it is `relay_selection`'s job, and this answer is the
    // fact that the report is about somebody else's relay.
    var latencies: report_mod.RelayLatencies = .{};
    _ = latencies.update(mine, millis(90), .https);
    try t.expectEqual(millis(90), latencies.get(mine).?);
    const again = prefer(.{
        .report = .{ .preferred_relay = foreign, .relay_latency = latencies },
        .pool = &.{mine},
    });
    try t.expect(isArm(again, .outside_pool));
}

// The two null-shaped answers are told apart, because a caller recovers from
// them differently and one of them is not a fault at all.
test "a report that measured nothing and a report about a stranger are two answers" {
    const foreign = try RelayUrl.parse("https://elsewhere.example./");
    const mine = try RelayUrl.parse("https://mine.example./");
    const pool = [_]RelayUrl{mine};

    // Folded from nothing: no probe, no latency, no preferred relay.
    const empty = prefer(.{ .report = report_mod.fold(&.{}, .{}, test_now), .pool = &pool });
    try t.expect(isArm(empty, .unmeasured));
    // The fold really did produce the empty report, so `.unmeasured` is not
    // this module refusing an answer the report did carry.
    try t.expectEqual(@as(?RelayUrl, null), report_mod.fold(&.{}, .{}, test_now).preferred_relay);

    // Folded from a round to a relay outside the pool.
    const elsewhere = report_mod.fold(&.{
        .{ .https = .{ .relay = foreign, .instant = test_now, .latency = millis(5) } },
    }, .{}, test_now);
    const strayed = prefer(.{ .report = elsewhere, .pool = &pool });
    try t.expect(isArm(strayed, .outside_pool));
    // The two arms are distinct values, not one: a caller that logs which one
    // it got can tell "I have not measured" from "my report is about a relay
    // I do not dial".
    try t.expect(!isArm(empty, .outside_pool));
}

// A folded report's preferred relay always comes with the figure that chose
// it, and the reason is structural rather than lucky: `choosePreferredRelay`
// walks this round's own `relay_latency` and takes a candidate from there, and
// the two-thirds hold that could substitute the previous report's relay is
// guarded on `current_latency != 0` — so a relay this round did not measure is
// never substituted in. The answer therefore hands the caller a number for
// every relay the fold can name.
test "a folded report's preferred relay is one it measured" {
    const home = try RelayUrl.parse("https://home.example./");
    const challenger = try RelayUrl.parse("https://challenger.example./");

    // The hold: a previous report names `home`, this round times it at 30 ms and
    // the challenger at 21 ms. Two thirds of 30 ms is 20 ms, so the challenger
    // misses the line and the incumbent is held.
    const previous: Report = .{ .preferred_relay = home };
    const held = report_mod.fold(&.{
        .{ .https = .{ .relay = home, .instant = test_now, .latency = millis(30) } },
        .{ .https = .{ .relay = challenger, .instant = test_now, .latency = millis(21) } },
    }, .{ .last = previous }, test_now);
    try t.expectEqual(std.math.Order.eq, held.preferred_relay.?.order(home));

    switch (prefer(.{ .report = held, .pool = &.{ home, challenger } })) {
        .selected => |chosen| {
            try t.expectEqual(std.math.Order.eq, chosen.relay.order(home));
            // The figure is the one this round holds for the chosen relay, not
            // the merged one the fold ranked over.
            try t.expectEqual(millis(30), chosen.latency.?);
        },
        else => return error.TestUnexpectedResult,
    }
}

// Null is not unreachable. `prefer` takes a `Report` from a caller, and a
// caller may build one field-wise — `report.zig`'s own tests do exactly that at
// its hysteresis test — so a report naming a relay it holds no figure for is a
// report this module must answer about rather than assume away. It answers
// with the relay and no number, because inventing one is the failure the module
// exists to prevent.
test "a relay named without a figure is named, and no figure is invented" {
    const named = try RelayUrl.parse("https://named.example./");
    const report: Report = .{ .preferred_relay = named };
    try t.expectEqual(@as(?Nanos, null), report.relay_latency.get(named));

    switch (prefer(.{ .report = report, .pool = &.{named} })) {
        .selected => |chosen| {
            try t.expectEqual(std.math.Order.eq, chosen.relay.order(named));
            try t.expectEqual(@as(?Nanos, null), chosen.latency);
        },
        else => return error.TestUnexpectedResult,
    }
}

// Membership is relay sameness. Two `RelayUrl` values parsed from one text
// differ in the padding `parse` leaves unwritten, so a membership test that
// compared fields would reject one of them; and the same host under another
// scheme or port is another relay, which a test that compared hosts would
// wrongly accept. Both directions are here.
test "membership compares the relay and neither its padding nor its host alone" {
    const home = try RelayUrl.parse("https://a.example./");
    const other_port = try RelayUrl.parse("https://a.example.:8443/");
    const other_scheme = try RelayUrl.parse("http://a.example./");

    // The exact relay is in the pool.
    const found = prefer(.{ .report = homeOn(home, millis(1)), .pool = &.{home} });
    try t.expect(isArm(found, .selected));

    // Same host, different port: a different relay, so the pool does not hold
    // it and nothing is named. A host-only membership test would say the
    // opposite here.
    const by_port = prefer(.{ .report = homeOn(home, millis(1)), .pool = &.{other_port} });
    try t.expect(isArm(by_port, .outside_pool));

    // Same host and port, other scheme: still another relay. `order` compares
    // the scheme first, which is why the port arm above and this one are both
    // refusals rather than one of them being a match.
    const by_scheme = prefer(.{
        .report = homeOn(home, millis(1)),
        .pool = &.{other_scheme},
    });
    try t.expect(isArm(by_scheme, .outside_pool));

    // Both of them in the pool beside the real one changes nothing: membership
    // is per relay and the choice is the fold's.
    const beside = prefer(.{
        .report = homeOn(home, millis(1)),
        .pool = &.{ other_scheme, home, other_port },
    });
    try t.expect(isArm(beside, .selected));
}
