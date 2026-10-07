//! How long a wind-down may take, and what it gives up when it runs out.
//!
//! **Pure: the elapsed time is the caller's.** Every function here is a total
//! function of a number the caller read from the clock it already keeps
//! (`node_loop.run` reads one every pass, `node_loop.zig:164`). Nothing reads
//! one, so a test decides when the budget is spent and a shutdown is drivable
//! at any elapsed time without a clock at all.
//!
//! # What is given up first, and why that one
//!
//! **The graceful connection close, and nothing else.** It is the only step
//! whose performance a peer can observe — `closeConnections` stamps
//! `conn.close` on every connection the core holds and writes it out
//! (`node_close.zig:232-240`) — and it is therefore the only step whose loss a
//! peer can be hurt by. Everything else on the way down is local: a handler's
//! state, the accept tasks, the relay's clients and the descriptor are this
//! node's own, and a peer learns about all of them from a timeout rather than
//! from a packet.
//!
//! The reason it is given up rather than stretched is stated in the direction
//! the failure goes. A shutdown that stops *part way* through telling peers
//! leaves two populations: the ones told, who stop offering, and the ones not
//! told, who keep sending to a node that will not answer. The second population
//! is worse than a clean refusal to start, because the peer had no way to know
//! and this node has stopped answering — so the announcement is **all or
//! nothing, decided before the walk and never during it.** A caller asks
//! `maySkip` first; there is no per-connection answer to ask.
//!
//! # What is never given up
//!
//! **The descriptor release, at any elapsed time.** A node that keeps its
//! socket keeps *serving*: the accept loop would admit a connection this node
//! has already decided to stop servicing, which is the exact failure the first
//! decision exists to prevent, produced by this node itself rather than by the
//! network. It is also one `close(2)`, which is why bounding it would bound
//! nothing.
//!
//! **There is no second bound, and that is the decision.** Past
//! `announce_budget` everything that remains is local and bounded by counts
//! rather than by time: four shutdown phases and `max_close_steps` of them
//! (`node_close.zig:31`), `max_accepts` accept tasks (`node_accept.zig:35`),
//! `max_relay_clients` client slots (`node_relay_table.zig:34`). A bound on
//! those would authorise giving up a resource this node still holds when it is
//! gone, in exchange for bounding a walk over 64 entries.
//!
//! # Where the bound comes from
//!
//! A quarter of the silence a peer accepts before it gives a connection up. A
//! budget at or above that silence would spend the expensive part of the close
//! announcing to peers that have already stopped listening, and the three
//! quarters left over are the peer's own margin — this node does not get to
//! spend the silence a peer needs for its own retransmits.
//!
//! **A policy number rather than a derived one.** The announcement costs one
//! datagram per connection, so a node with a very large connection table can
//! overrun it, and the answer to that is `Budget.budget_ns` rather than a
//! longer constant: the bound says how long this node will spend, not how long
//! it may need.
//!
//! # What is not wired
//!
//! **`node_loop.windDown` consults no budget.** It closes under
//! `CancelProtection` with cancellation switched off
//! (`node_loop.zig:205-215`) and no time bound, so the bound below is this
//! node's policy stated and tested rather than a bound the loop enforces. The
//! loop's own ceiling is `poll_interval_ms` — a stop is acted on within one
//! tick of a clock it already reads — and nothing downstream reads this file
//! yet.
//!
//! One thing this module deliberately does not do: make the walk atomic.
//! `closeConnections` can stop part way on a send error, and a resumed close
//! re-stamps from the first connection (`node_close.zig:226-231`). That is a
//! transport failure with its own answer, and what is refused here is
//! *deciding* to stop part way.

const std = @import("std");
const order = @import("shutdown_order.zig");

/// Nanoseconds of elapsed time on the caller's own clock.
///
/// Unsigned, and not the core's `Instant`, which is signed because the core
/// compares instants (`bridge_config.zig:43`). A duration is not an instant and
/// is never negative, so a caller hands the difference of two readings from the
/// same clock and this file never has to reason about a clock that went
/// backwards.
pub const Nanos = u64;

/// One step of the wind-down. See `shutdown_order.zig` for the whole order; it
/// is aliased rather than re-imported by every caller of both files.
pub const Step = order.Step;

/// The silence a peer accepts before it gives this node's connection up.
///
/// Thirty seconds, and it is two things that are already thirty seconds:
/// `bridge_config.Config.idle_timeout_ms`, the core's own idle timeout for
/// every connection on this node (`bridge_config.zig:160`), and
/// `path_table.idle_timeout` (`path_table.zig:124`). A node that announces
/// later than this announces to nobody.
///
/// **Named here rather than imported**, because a budget that borrowed another
/// layer's default would change value when that default changed, and this
/// number is a policy: it says how long this node will spend telling a peer it
/// is going away.
pub const peer_idle_timeout: Nanos = 30 * std.time.ns_per_s;

/// How many parts a peer's silence is divided into for the bound below. Twelve
/// because thirty seconds divides by it exactly, so the bound is a quarter of
/// the silence and not a quarter of it less a rounding.
pub const announce_share: u8 = 12;

/// The bound, in nanoseconds.
///
/// Two and a half seconds: a quarter of the silence a peer accepts, and
/// `@divExact` says the division loses nothing at build time rather than in a
/// test. A caller that has measured a larger wind-down says so in
/// `Budget.budget_ns` rather than here.
pub const announce_budget: Nanos = @divExact(peer_idle_timeout, announce_share);

/// What a wind-down is doing at a given elapsed time.
pub const Mode = enum {
    /// Tell every peer, in full. The only thing that spends the budget.
    announce,
    /// Tell nobody and give everything else up: the rest of the order is local
    /// and bounded by counts.
    local,
};

/// What the wind-down is doing after `elapsed_ns`, on this node's budget.
///
/// At the bound the budget is spent: the announcement is all or nothing, and a
/// wind-down that reaches the bound has not announced.
pub fn mode(elapsed_ns: Nanos) Mode {
    return if (elapsed_ns < announce_budget) .announce else .local;
}

/// Whether `step` may be given up after `elapsed_ns` has passed.
///
/// **One step, and only once the bound is spent.** The connection close is the
/// only step a peer can observe, so it is the only one a budget may take;
/// everything else is this node's own and is given up on every path, which
/// `shutdown_order.skipped` refuses as a capability question rather than this
/// one. Before `announce_budget` this answers `false` for every step, because
/// the announcement is all or nothing and a caller that could ask again part
/// way through the walk would be asking per connection.
///
/// Note what this does not say: having a runtime and an instant does not buy
/// extra time. Those are what the close needs to *happen*
/// (`node_close.zig:213-216`), and having them is not a claim on more of the
/// budget.
pub fn maySkip(step: Step, elapsed_ns: Nanos) bool {
    if (!order.announced(step)) return false;
    return elapsed_ns >= announce_budget;
}

/// One wind-down's budget, held by the caller across it.
///
/// The bound is a field rather than the constant above because a caller that
/// knows what it is shutting down may choose: a node with four relay clients
/// and a small connection table wants this node's bound, and a caller that has
/// measured a larger one has a reason this file cannot see. What a caller may
/// not change is *which* step is given up — that is `maySkip`, and it holds for
/// any bound.
pub const Budget = struct {
    /// When the wind-down started, in the caller's nanoseconds.
    started_ns: Nanos,
    /// What the whole wind-down may have.
    budget_ns: Nanos = announce_budget,

    /// How long it has been running. Saturating, because a reading from before
    /// the start is a clock that moved backwards and the answer for that is no
    /// time has passed, not a very large number of seconds.
    pub fn elapsed(self: Budget, now_ns: Nanos) Nanos {
        return now_ns -| self.started_ns;
    }

    /// What it has of its budget left, saturating at zero.
    pub fn left(self: Budget, now_ns: Nanos) Nanos {
        return self.budget_ns -| self.elapsed(now_ns);
    }

    /// Whether the budget is spent at `now_ns`. At the bound it is: the
    /// announcement is all or nothing, so the last nanosecond of the budget is
    /// not enough to announce in.
    pub fn spent(self: Budget, now_ns: Nanos) bool {
        return self.elapsed(now_ns) >= self.budget_ns;
    }

    /// What the wind-down is doing at `now_ns`, on this budget.
    pub fn mode(self: Budget, now_ns: Nanos) Mode {
        return if (self.spent(now_ns)) .local else .announce;
    }

    /// Whether `step` may be given up at `now_ns`, on **this** budget.
    ///
    /// The bound compared against is `self.budget_ns` and not
    /// `announce_budget`: a caller that chose a longer bound bought more of
    /// the announcement with it, and one that chose a shorter one bought
    /// less. Reading the constant here instead would make `budget_ns` a field
    /// the wind-down read but never spent. Which *step* may be given up is
    /// `order.announced`, and no bound changes that.
    pub fn maySkip(self: Budget, step: Step, now_ns: Nanos) bool {
        if (!order.announced(step)) return false;
        return self.spent(now_ns);
    }
};

// --- tests

const t = std.testing;

/// The wind-down the code performs, at one elapsed time: every step the budget
/// still allows, with the releases each gives up, a latched release left alone
/// on the reach that would give it twice, and the connections given up by
/// whichever of the two steps that reach them actually ran.
fn windDown(ledger: *order.Ledger, budget: Budget, now_ns: Nanos) order.Error!void {
    // Whether the close announced the connections, which is what decides which
    // of the two steps that reach them reaches any work.
    //
    // **Keyed to what advanced, never to what the budget says.** This is set
    // after the step has run rather than from the clock, so it is false on
    // either way the close is not reached — by `order.skipped` with no
    // runtime, or by `budget.maySkip` with the budget spent — and that is the
    // same question in both. Reading the budget instead would answer it
    // correctly here and wrongly in `shutdown_order.zig`'s own `windDown`,
    // which has no budget to read.
    //
    // It is set *after* this step's own releases, because a close that had
    // already suppressed its own give-up would announce nothing and release
    // nothing.
    var close_announced = false;
    for (order.order) |step| {
        if (order.skipped(step, .{ .runtime = true, .instant = true })) continue;
        if (budget.maySkip(step, now_ns)) continue;
        try ledger.advance(step);
        for (order.releases(step)) |release| {
            // `connections` is reached twice and latched zero times
            // (`shutdown_order.latched`), and `Ledger.giveUp` refuses the
            // second. The machine gives that release up once — by
            // `closeConnections` on the path that announced them, and by
            // `Bridge.destroy` on the path that did not
            // (`node_build.zig:389`) — so which step ran is what decides, and
            // the second reach correctly finds nothing left to release.
            if (release == .connections and close_announced) continue;
            if (order.latched(release) and ledger.hasGiven(release)) continue;
            try ledger.giveUp(release);
        }
        if (step == .connections) close_announced = true;
    }
}

test "the bound is a share of the silence a peer accepts, and the share is whole" {
    // A close written after the peer's idle timeout is written to nobody, so
    // the bound has to sit inside that silence rather than against it.
    try t.expect(announce_budget < peer_idle_timeout);
    // And a budget that lost a nanosecond to the division would leave a peer
    // with a margin that is not the one the doc names, so the share is exact.
    try t.expectEqual(peer_idle_timeout, announce_budget * announce_share);
    try t.expect(announce_share > 1);
}

test "the boundary is the named bound, and it is spent at the bound" {
    try t.expectEqual(Mode.announce, mode(0));
    try t.expectEqual(Mode.announce, mode(announce_budget - 1));
    try t.expectEqual(Mode.local, mode(announce_budget));
    try t.expectEqual(Mode.local, mode(announce_budget * 1000));

    // A budget that started at 1_000 and is read at `announce_budget` has spent
    // exactly the difference, which is the arithmetic the boundary is made of.
    const budget: Budget = .{ .started_ns = 1_000 };
    const spent_at = announce_budget + 1_000;
    try t.expectEqual(@as(Nanos, 0), budget.elapsed(1_000));
    try t.expectEqual(announce_budget - 1_000, budget.elapsed(announce_budget));
    try t.expectEqual(budget.budget_ns, budget.left(1_000));
    try t.expectEqual(@as(Nanos, 1_000), budget.left(announce_budget));
    try t.expectEqual(@as(Nanos, 0), budget.left(spent_at));
    try t.expect(!budget.spent(spent_at - 1));
    try t.expect(budget.spent(spent_at));
    try t.expectEqual(Mode.announce, budget.mode(spent_at - 1));
    try t.expectEqual(Mode.local, budget.mode(spent_at));
    // A clock that moved backwards has spent no time and has the whole budget
    // left, which is the answer that does not turn a bad reading into a
    // wind-down that announces nothing.
    try t.expectEqual(@as(Nanos, 0), budget.elapsed(0));
    try t.expectEqual(budget.budget_ns, budget.left(0));
    try t.expectEqual(Mode.announce, budget.mode(0));
}

test "the connection close is the only step a budget ever gives up" {
    // Four points on the timeline, the last of which no wall clock reaches.
    const elapsed = [4]Nanos{ 0, announce_budget - 1, announce_budget, std.math.maxInt(Nanos) };
    inline for (@typeInfo(order.Step).@"enum".fields) |field| {
        const step: order.Step = @enumFromInt(field.value);
        for (elapsed) |at| {
            // The close is the only step a budget may give up, and it is given
            // up only once the bound is spent. At `0` and one nanosecond short
            // of the bound the announcement is still what happens, and one
            // given up there is the part-way wind-down this file exists to
            // refuse — so the answer is not "the close, at every elapsed
            // time" but "the close, past the bound, and nothing before it".
            const spent = at >= announce_budget;
            try t.expectEqual(step == .connections and spent, maySkip(step, at));
        }
        // Every step the budget refuses to give up is a step a caller may
        // still not skip for any other reason either.
        if (step != .connections) {
            try t.expect(!order.skippable(step));
            try t.expect(!order.skipped(step, .{}));
        }
    }
}

test "giving up the announcement gives up nothing else" {
    const budget: Budget = .{ .started_ns = 0 };
    var ledger: order.Ledger = .{};
    try windDown(&ledger, budget, announce_budget);
    // The announcement is gone and every other step still ran: a budget that
    // had run out has made this node local, not abandoned.
    try t.expect(!ledger.hasRun(.connections));
    try t.expect(ledger.hasRun(.descriptor));
    try t.expect(ledger.hasRun(.node));
    // Nothing leaks for it, because the connections are given up with the
    // bridge — the announcement was lost, the connections were not.
    try t.expectEqual(@as(order.Mask, 0), ledger.outstanding());
    try t.expect(ledger.hasGiven(.connections));
    // And nothing was given up twice on the way, which is the other half of
    // what "exactly once" means.
    inline for (@typeInfo(order.Release).@"enum".fields) |field| {
        try t.expect(ledger.hasGiven(@enumFromInt(field.value)));
    }
}

test "a wind-down that announces every peer gives every release up once" {
    // The unspent path, which the test above does not reach: here the close
    // runs, so it gives the connections up itself, and the bridge reaches the
    // same release a second time with nothing left to give. A helper that
    // consulted only the latches would refuse that second reach as a double
    // free, which is a refusal of the machine's own order rather than of
    // anything it did.
    const budget: Budget = .{ .started_ns = 0 };
    var ledger: order.Ledger = .{};
    try windDown(&ledger, budget, 0);
    try t.expect(ledger.hasRun(.connections));
    try t.expectEqual(@as(order.Mask, 0), ledger.outstanding());
    // And every release, including the one two steps reach, went exactly once:
    // the second reach of `.connections` found nothing and gave nothing, which
    // is what "once" means here rather than "twice, harmlessly".
    inline for (@typeInfo(order.Release).@"enum".fields) |field| {
        try t.expect(ledger.hasGiven(@enumFromInt(field.value)));
    }
    try t.expectError(error.ReleasedTwice, ledger.giveUp(.connections));
}

test "having a runtime buys no time" {
    const have: order.Have = .{ .runtime = true, .instant = true };
    // With a runtime and an instant the close can happen, so the capability
    // question says no — and the budget says yes anyway, because these are
    // different questions and only one of them is about time.
    try t.expect(!order.skipped(.connections, have));
    try t.expect(maySkip(.connections, announce_budget));
    try t.expect(!maySkip(.connections, announce_budget - 1));
}

test "a caller may choose a longer bound, and not a different step" {
    const patient: Budget = .{ .started_ns = 0, .budget_ns = announce_budget * 4 };
    // Four budgets past this node's own bound, and it is still announcing: the
    // field is a choice and not a hole in the decision.
    try t.expectEqual(Mode.announce, patient.mode(announce_budget * 4 - 1));
    try t.expect(!patient.maySkip(.connections, announce_budget * 4 - 1));
    try t.expect(patient.maySkip(.connections, announce_budget * 4));
    // Whatever the bound, the step given up is the announcement and only the
    // announcement.
    inline for (@typeInfo(order.Step).@"enum".fields) |field| {
        const step: order.Step = @enumFromInt(field.value);
        try t.expectEqual(step == .connections, patient.maySkip(step, announce_budget * 4));
    }
}
