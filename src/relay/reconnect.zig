//! What a client does with the relay it lost: how long it waits, how long it
//! keeps trying, and what it does with a relay that told it in advance.
//!
//! `relay/frame.zig` carries `Restarting` and says plainly that nothing in this
//! tree acts on either of its numbers: a node dials its relay once and never
//! reconnects (`node_relay_client.zig:150`), and the frame's two milliseconds are
//! decoded, sized and dropped (`node_relay_client.zig:243-255`). This file is
//! the consumer that was missing, and it is a consumer and not a change to the
//! frame: `Restarting` stays exactly as `frame_types.zig` defines it.
//!
//! # A restarting relay and a gone-away relay are different facts
//!
//! **A `Restarting` frame is a promise with a deadline on it; a vanished relay
//! is a fact with nothing to wait for.** Upstream says both halves are advisory
//! — "no advisory wait, no budget" for a zero, and nothing checks that one
//! number exceeds the other (`frame_types.Restarting`) — so this file decides
//! what to do with them, in three rules:
//!
//! - **`reconnect_in_ms` is a floor, never a ceiling.** The wait is the *longer*
//!   of what the relay asked for and the next step of this client's own backoff.
//!   A relay may smear reconnects out (`reconnect_in_ms` exists for that) and it
//!   may not make this client hammer a relay that said wait; and a relay that
//!   sends zero does not get a zero wait, because zero is what a relay with no
//!   opinion sends.
//! - **`try_for_ms` is the budget, measured from the instant the frame
//!   arrived.** That is the whole difference from a relay that went away: this
//!   client's give-up deadline is the relay's own promise, so a relay that says
//!   "back within ten seconds" is believed for ten seconds and not one
//!   nanosecond longer. **Zero means no budget** — upstream's own wording — and
//!   then the budget is this client's `gone_budget` from the same instant, so
//!   the deadline always exists and is always the same shape.
//! - **A relay that went away gets this client's own numbers**: the same floor
//!   rule against `first_delay`, and a budget it owns rather than one it was
//!   given. A loss while already waiting keeps the earlier of the two deadlines,
//!   because the budget is the time this client has spent on a relay it does not
//!   have, not a sum of windows — and because a relay that announced a restart
//!   and then vanished instead has missed its own deadline, which is the one
//!   fact the announced budget was waiting for.
//!
//! The two are told apart in the state as well as in the policy: `Source` says
//! whose budget is running, and `Cause` says which one expired, so a log line can
//! tell "the relay asked us to wait and then went quiet" from "the relay
//! vanished", which are different faults with the same symptom.
//!
//! # A displacement is not a disconnection
//!
//! **A `Status.same_endpoint_id_connected` gives up at once and never retries.**
//! The relay is answering, the connection is healthy, and another connection
//! holds this node's id: a redial would be admitted, displaced again and told so
//! again. Retrying here would spend a budget to arrive at the same answer, and
//! the answer is terminal in the only sense that matters — this client cannot be
//! the peer at that relay while the other connection is. It is its own `Cause`
//! because it is the one case where the relay is not what went wrong.
//!
//! # The backoff, and why it is not random here
//!
//! `backoff` doubles from `first_delay` up to `max_delay`, and the loop is
//! bounded by `attempt` rather than by a wall clock. Upstream jitters its
//! reconnect; this file does not, because `AGENTS.md` §2 asks for seeds over
//! entropy and a caller that wants jitter can add it to the wait the state names.
//! The doubling saturates, so an attempt count that would overflow a `u8`
//! multiplication cannot, and the cap means the arithmetic terminates whatever
//! number it is handed.
//!
//! Everything here is pure over values: a state, an event and an instant in, a
//! new state and at most one action out. No clock, no socket, no allocator, and
//! a terminal state that absorbs everything after it — so a caller that keeps
//! stepping a machine it gave up on is told nothing new and never dials twice.

const std = @import("std");
const client = @import("client.zig");
const frame = @import("frame.zig");

const std_testing = std.testing;

/// Nanoseconds on the caller's timeline. See `client.Nanos`.
pub const Nanos = client.Nanos;

/// The relay's own notice, with both numbers in the milliseconds the wire
/// carries them in. See `frame.Restarting`.
pub const Restarting = frame.Restarting;

const second = std.time.ns_per_s;

/// How long a client waits before it tries a relay again, on its own numbers.
///
/// **Every field is this client's to choose and none of them is read from the
/// relay.** They are the floor the relay's advisory wait is measured against and
/// the budget that applies when the relay said nothing at all; a deployment that
/// wants a different shape changes them here rather than reaching for a global.
pub const Config = struct {
    /// The wait before the first redial, and the floor under every wait after
    /// it.
    first_delay: Nanos = 1 * second,
    /// The longest one wait. The backoff stops doubling here.
    max_delay: Nanos = 60 * second,
    /// The whole time a relay that went away may be retried at, from the instant
    /// it went away. Also the budget for a `Restarting` frame whose `try_for_ms`
    /// is zero.
    gone_budget: Nanos = 300 * second,
    /// How long one redial has to produce traffic before it counts as failed.
    /// This is the wait between "we dialled" and "the relay is not answering".
    attempt_timeout: Nanos = 10 * second,
};

/// Whose deadline is running.
///
/// **It is in the state rather than in the policy because it changes what a log
/// line can say**, and it is what `Cause` is computed from when the deadline is
/// reached.
pub const Source = enum {
    /// The relay said it was restarting, so the budget is its `try_for_ms`.
    relay_announced,
    /// Nothing was said, so the budget is `Config.gone_budget`.
    ours,
};

/// Why this client stopped retrying, named so a log line says which fault it
/// was.
///
/// All three are terminal. A caller that gives up hands the endpoint back to
/// whatever owns its connections: the retry policy for a *peer* belongs with
/// discovery (`src/discovery/dial_source.zig` is the module that names a lookup
/// as its own missing half), and this is the policy for one relay.
pub const Cause = enum {
    /// A relay that announced a restart spent the budget it announced.
    relay_restarting,
    /// A relay that went away spent this client's budget.
    relay_gone,
    /// Another connection holds this node's id at that relay.
    displaced,
};

/// The deadline behind a wait, and whose it is.
const Budget = ?struct {
    give_up_at: Nanos,
    source: Source,
};

/// A redial is owed at `until`, under a budget that ends at `give_up_at`.
pub const Waiting = struct {
    until: Nanos,
    /// How many redials have already been made. The backoff reads it, so the
    /// first wait after a fresh loss is `first_delay`.
    attempt: u8,
    /// When the budget ends.
    give_up_at: Nanos,
    /// Whose budget that is.
    source: Source,
};

/// A redial is in flight and has to produce traffic by `until`.
pub const Dialing = struct {
    until: Nanos,
    attempt: u8,
    give_up_at: Nanos,
    source: Source,
};

/// Where a client is with the relay it dialled.
pub const State = union(enum) {
    /// The relay is connected. The instant it was last seen, which is where a
    /// later `.gone` measures its wait from.
    connected: Nanos,
    /// A redial is owed.
    waiting: Waiting,
    /// A redial is in flight.
    dialing: Dialing,
    /// Terminal. Nothing after this changes it.
    given_up: Cause,
};

/// What happened to the relay connection.
pub const Event = union(enum) {
    /// The relay is connected. A bare arm rather than a payload, because there
    /// is nothing to carry: the instant is an argument to `step`.
    connected,
    /// The stream ended, or a ping went unanswered: the relay is gone and
    /// nothing said so.
    gone,
    /// A `Restarting` frame arrived: the relay is going down and says when it
    /// will be back.
    restarting: Restarting,
    /// A `Status.same_endpoint_id_connected` arrived.
    displaced,
    /// Nothing happened and the clock moved.
    tick,
};

/// What the caller must do after a step: at most one thing, never two.
pub const Action = union(enum) {
    /// Do not dial for this long. It is a wait and not a deadline — the caller
    /// may redial earlier for a reason of its own and nothing here objects.
    wait: Nanos,
    /// Dial the relay again. The next state is `dialing`, and the instant it
    /// carries is when this attempt stops counting.
    redial,
    /// Stop. The cause is the log line, and the endpoint's own failure logic
    /// takes over from here.
    give_up: Cause,
};

/// One step: the next state, and the one thing to do about it.
pub const Step = struct {
    state: State,
    action: ?Action,
};

/// A machine that has never lost its relay.
pub fn start(now: Nanos) State {
    return .{ .connected = now };
}

/// One step of the reconnect policy.
///
/// `now` is on the caller's timeline and is compared rather than waited on, so a
/// test reaches an expiry in one call. `policy` is an argument rather than a
/// field in the state: a state is a value a caller may hold, log and compare,
/// and the policy a deployment runs is not part of where the machine has got to.
pub fn step(state: State, event: Event, now: Nanos, policy: Config) Step {
    // A machine that has given up stays given up. It absorbs every later event,
    // so a caller that keeps passing ticks at a machine it gave up on is never
    // handed a second `give_up` and never dials a relay it has quit.
    if (std.meta.activeTag(state) == .given_up) {
        return .{ .state = state, .action = null };
    }
    return switch (event) {
        // The one event with no recovery: a second connection holds this node's
        // id, so there is nothing to wait for and nothing a retry would change.
        .displaced => giveUp(.displaced),
        .connected => .{ .state = .{ .connected = now }, .action = null },
        .gone => begin(attemptOf(state), budgetOf(state), now, policy),
        .restarting => |notice| announced(notice, attemptOf(state), now, policy),
        .tick => advance(state, now, policy),
    };
}

/// The wait before redial number `attempt`.
fn backoff(policy: Config, attempt: u8) Nanos {
    var wait = @min(policy.first_delay, policy.max_delay);
    var counted: u8 = 0;
    // Bounded by `attempt`, which is a `u8`, and short-circuited at the cap: a
    // client that has retried 255 times answers the cap, and the loop can never
    // be the reason this function is slow.
    while (counted < attempt) : (counted += 1) {
        if (wait >= policy.max_delay) return policy.max_delay;
        wait = @min(policy.max_delay, wait *| 2);
    }
    return wait;
}

/// The wait and budget for a relay that is restarting.
fn announced(notice: Restarting, attempt: u8, now: Nanos, policy: Config) Step {
    // A relay advertising a wait longer than `u32.max` milliseconds cannot be
    // built: `Restarting` holds the truncated value the wire carries, which is
    // why the multiplication is into `Nanos` and cannot overflow either.
    const asked: Nanos = @as(Nanos, notice.reconnect_in_ms) * std.time.ns_per_ms;
    const asked_for: Nanos = @as(Nanos, notice.try_for_ms) * std.time.ns_per_ms;
    const wait = @max(asked, backoff(policy, attempt));
    return .{
        .state = .{
            .waiting = .{
                .until = now +| wait,
                .attempt = attempt,
                // Zero is "no budget" in upstream's own wording, and then this client's
                // budget runs from the same instant.
                .give_up_at = now +| if (asked_for == 0) policy.gone_budget else asked_for,
                .source = .relay_announced,
            },
        },
        .action = .{ .wait = wait },
    };
}

/// The wait and budget for a relay that went away, keeping the attempt count.
fn begin(attempt: u8, previous: Budget, now: Nanos, policy: Config) Step {
    const wait = backoff(policy, attempt);
    // The earlier of a fresh budget and the one already running: a second loss
    // does not buy time, and an announced budget that has not yet expired keeps
    // governing the wait for the reconnect the relay promised.
    const held = previous orelse return .{ .state = .{ .waiting = .{
        .until = now +| wait,
        .attempt = attempt,
        .give_up_at = now +| policy.gone_budget,
        .source = .ours,
    } }, .action = .{ .wait = wait } };
    return .{ .state = .{ .waiting = .{
        .until = now +| wait,
        .attempt = attempt,
        .give_up_at = @min(now +| policy.gone_budget, held.give_up_at),
        .source = held.source,
    } }, .action = .{ .wait = wait } };
}

/// The clock moved and nothing else happened.
fn advance(state: State, now: Nanos, policy: Config) Step {
    return switch (state) {
        .connected => .{ .state = state, .action = null },
        .waiting => |wait| waiting(wait, now, policy),
        .dialing => |dial| dialing(dial, now, policy),
        // Unreachable through `step`, which absorbs a given-up machine before it
        // gets here. Answered rather than `unreachable` so the arm states the
        // policy instead of asserting that a caller honoured it.
        .given_up => |cause| .{ .state = .{ .given_up = cause }, .action = null },
    };
}

fn waiting(wait: Waiting, now: Nanos, policy: Config) Step {
    if (now >= wait.give_up_at) return giveUp(causeOf(wait.source));
    if (now < wait.until) return .{ .state = .{ .waiting = wait }, .action = null };
    return .{ .state = .{ .dialing = .{
        .until = now +| policy.attempt_timeout,
        .attempt = wait.attempt + 1,
        .give_up_at = wait.give_up_at,
        .source = wait.source,
    } }, .action = .redial };
}

fn dialing(dial: Dialing, now: Nanos, policy: Config) Step {
    if (now >= dial.give_up_at) return giveUp(causeOf(dial.source));
    if (now < dial.until) return .{ .state = .{ .dialing = dial }, .action = null };
    // A redial that produced nothing by its deadline is a relay that went away,
    // and it counts: the attempt goes up, so the next wait is longer, and the
    // budget keeps running rather than restarting.
    return begin(dial.attempt, .{
        .give_up_at = dial.give_up_at,
        .source = dial.source,
    }, now, policy);
}

fn giveUp(cause: Cause) Step {
    return .{ .state = .{ .given_up = cause }, .action = .{ .give_up = cause } };
}

/// The fault a spent budget names. `Source` says whose budget was running and
/// `Cause` says which one expired, and each source has exactly one fault of its
/// own: the relay's own restart deadline, or this client's patience with a
/// relay that vanished.
fn causeOf(source: Source) Cause {
    return switch (source) {
        .relay_announced => .relay_restarting,
        .ours => .relay_gone,
    };
}

/// How many redials have been made, which is the backoff's input.
fn attemptOf(state: State) u8 {
    return switch (state) {
        .connected => 0,
        .waiting => |w| w.attempt,
        .dialing => |d| d.attempt,
        // Unreachable through `step` for the reason `advance` states, and the
        // cap is the answer that cannot understate a lost relay's patience.
        .given_up => std.math.maxInt(u8),
    };
}

/// The budget the current state is under, or null while connected.
fn budgetOf(state: State) Budget {
    return switch (state) {
        .connected => null,
        .waiting => |w| .{ .give_up_at = w.give_up_at, .source = w.source },
        .dialing => |d| .{ .give_up_at = d.give_up_at, .source = d.source },
        .given_up => null,
    };
}

// --- tests

/// The numbers the policy tests run on, named so the instants in them are
/// readable: a one second first wait doubling to eight, ten seconds of budget
/// for a relay that said nothing, and two seconds for one attempt.
const config: Config = .{
    .first_delay = 1 * second,
    .max_delay = 8 * second,
    .gone_budget = 10 * second,
    .attempt_timeout = 2 * second,
};

/// One hour on the caller's timeline, for the tests that need to be nowhere near
/// zero.
fn hour() Nanos {
    return 3600 * second;
}

// The deadline a restarting relay announced is honoured to the nanosecond, and
// the wait it asked for is a floor rather than a choice.
test "a restarting relay's budget is the deadline and its wait is a floor" {
    const opened = step(
        start(0),
        .{ .restarting = .{ .reconnect_in_ms = 3000, .try_for_ms = 5000 } },
        0,
        config,
    );

    // Three seconds because the relay asked for three and this client's own
    // first step is one: the longer of the two wins, so a relay cannot be
    // outwaited and cannot be beaten either.
    try std_testing.expectEqual(Action{ .wait = 3 * second }, opened.action.?);
    try std_testing.expectEqual(
        State{ .waiting = .{
            .until = 3 * second,
            .attempt = 0,
            .give_up_at = 5 * second,
            .source = .relay_announced,
        } },
        opened.state,
    );

    // Nothing happens before the wait is up, and the deadline is not consulted
    // early either.
    const held = opened.state;
    try std_testing.expectEqual(
        @as(?Action, null),
        step(held, .tick, 3 * second - 1, config).action,
    );

    // At the wait: redial, and this attempt has to produce traffic within
    // `attempt_timeout` or it counts as failed.
    const dialed = step(held, .tick, 3 * second, config);
    try std_testing.expectEqual(Action.redial, dialed.action.?);
    try std_testing.expectEqual(
        State{ .dialing = .{
            .until = 5 * second,
            .attempt = 1,
            .give_up_at = 5 * second,
            .source = .relay_announced,
        } },
        dialed.state,
    );

    // The relay's own budget ends five seconds after the frame arrived, and this
    // attempt's deadline is the same instant — two independent rules coinciding,
    // which is why the give-up is checked one nanosecond earlier as well.
    try std_testing.expectEqual(
        @as(?Action, null),
        step(dialed.state, .tick, 5 * second - 1, config).action,
    );
    const spent = step(dialed.state, .tick, 5 * second, config);
    try std_testing.expectEqual(Action{ .give_up = .relay_restarting }, spent.action.?);
    try std_testing.expectEqual(State{ .given_up = .relay_restarting }, spent.state);

    // A wait shorter than this client's own first step is not obeyed as one, and
    // a zero budget is not obeyed at all: both fall back to this client's
    // numbers, measured from the same instant.
    const quiet = step(
        start(0),
        .{ .restarting = .{ .reconnect_in_ms = 0, .try_for_ms = 0 } },
        0,
        config,
    );
    try std_testing.expectEqual(Action{ .wait = 1 * second }, quiet.action.?);
    try std_testing.expectEqual(
        State{ .waiting = .{
            .until = 1 * second,
            .attempt = 0,
            .give_up_at = 10 * second,
            .source = .relay_announced,
        } },
        quiet.state,
    );
}

// Two machines on one clock: the one whose relay announced a restart gives up
// when the relay said to, and the one whose relay vanished is still working.
test "a relay that is restarting and a relay that went away are not one policy" {
    const opened = step(
        start(0),
        .{ .restarting = .{ .reconnect_in_ms = 1000, .try_for_ms = 2000 } },
        0,
        config,
    ).state;
    const lost = step(start(0), .gone, 0, config).state;

    // Same event and the same clock, two different budgets: the announced one
    // ends at two seconds and the vanished one at ten. Both redial at one.
    const redialed = step(opened, .tick, 1 * second, config);
    try std_testing.expectEqual(Action.redial, redialed.action.?);
    const gone = step(lost, .tick, 1 * second, config);
    try std_testing.expectEqual(Action.redial, gone.action.?);

    // The announced relay spent exactly what it promised, and named which fault
    // it was.
    const spent = step(redialed.state, .tick, 2 * second, config);
    try std_testing.expectEqual(Action{ .give_up = .relay_restarting }, spent.action.?);

    // The vanished one has not reached the end of its second attempt, so a log
    // line at this instant tells the two apart without reading a field.
    const still = step(gone.state, .tick, 2 * second, config);
    try std_testing.expectEqual(@as(?Action, null), still.action);
    try std_testing.expect(std.meta.activeTag(still.state) != .given_up);

    // And it ends on its own budget, under a different name.
    const also_spent = step(still.state, .tick, 10 * second, config);
    try std_testing.expectEqual(Action{ .give_up = .relay_gone }, also_spent.action.?);
}

// A relay that vanishes is waited for with a doubling backoff and a cap. The
// budget is long enough that the loop is about the waits and not about the
// budget, which the test above holds to.
test "the backoff doubles from the first wait and stops at the cap" {
    const generous: Config = .{
        .first_delay = 1 * second,
        .max_delay = 8 * second,
        .gone_budget = hour(),
        .attempt_timeout = 2 * second,
    };
    const expected = [_]Nanos{ 1, 2, 4, 8, 8, 8 };
    var machine = start(0);
    var now: Nanos = 0;
    for (expected, 0..) |wait, round| {
        const lost = step(machine, .gone, now, generous);
        try std_testing.expectEqual(Action{ .wait = wait * second }, lost.action.?);

        // The wait expires, a redial goes out, and the attempt produces nothing:
        // each of those steps is what makes the next wait longer.
        now += wait * second;
        const dialed = step(lost.state, .tick, now, generous);
        try std_testing.expectEqual(Action.redial, dialed.action.?);
        try std_testing.expectEqual(@as(u8, @intCast(round + 1)), attemptOf(dialed.state));

        now += generous.attempt_timeout;
        machine = step(dialed.state, .tick, now, generous).state;
        try std_testing.expect(std.meta.activeTag(machine) == .waiting);
    }
}

// A displacement is terminal at once, and is acted on exactly once.
test "a displacement gives up at once and nothing acts on it twice" {
    const displaced = step(start(0), .displaced, 0, config);
    try std_testing.expectEqual(Action{ .give_up = .displaced }, displaced.action.?);
    try std_testing.expectEqual(State{ .given_up = .displaced }, displaced.state);

    // A machine that has given up absorbs every later event, including the two
    // that would otherwise restart it: a loss, a restarting frame, and a second
    // displacement.
    const late = [_]Event{ .tick, .gone, .connected, .displaced, Event{
        .restarting = .{ .reconnect_in_ms = 1, .try_for_ms = 1 },
    } };
    for (late) |event| {
        const later = step(displaced.state, event, hour(), config);
        try std_testing.expectEqual(@as(?Action, null), later.action);
        try std_testing.expectEqual(displaced.state, later.state);
    }
}

// Being connected is not waiting, and a loss measures from when it was seen.
test "a connected relay never waits and a loss runs from the loss" {
    const connected = step(start(5 * second), .connected, 5 * second, config);
    try std_testing.expectEqual(@as(?Action, null), connected.action);
    try std_testing.expectEqual(State{ .connected = 5 * second }, connected.state);
    try std_testing.expectEqual(
        @as(?Action, null),
        step(connected.state, .tick, hour(), config).action,
    );

    // The wait runs from the loss and not from when the connection was last
    // seen, and the budget runs from the same instant.
    const lost = step(connected.state, .gone, hour(), config);
    try std_testing.expectEqual(Action{ .wait = 1 * second }, lost.action.?);
    try std_testing.expectEqual(
        State{ .waiting = .{
            .until = hour() + 1 * second,
            .attempt = 0,
            .give_up_at = hour() + 10 * second,
            .source = .ours,
        } },
        lost.state,
    );
}
