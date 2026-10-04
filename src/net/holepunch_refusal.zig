//! What a round's answer means, and how that answer folds back into the
//! state.
//!
//! `classify` is the whole of holepunching's policy about refusal: a function
//! from the stack's error to retry-or-stop, one arm per variant and no
//! everything-else. `settle` is the one transition that consults it, and it is
//! where an accepted round records the instant it ran and the candidates the
//! stack found.
//!
//! The module is mutual with `holepunch_gate.zig` and deliberately so: the
//! state carries the error that ended punching, so it needs this module's
//! `NatTraversalError`, and `settle` writes that state, so this module needs
//! the gate's `PunchState`. `holepunch.zig` re-exports both as the layer's one
//! surface.

const std = @import("std");
const addr = @import("../base/addr.zig");
const gate = @import("holepunch_gate.zig");
const report = @import("report.zig");

const Nanos = report.Nanos;
const SocketAddr = addr.SocketAddr;

/// How long to wait before repeating a round the stack refused.
///
/// Upstream writes the 100 ms inline in `do_holepunching`, for the two errors
/// that mean "not yet" rather than "never".
pub const retry_interval: Nanos = 100 * std.time.ns_per_ms;

/// Why a round could not start. Upstream's `noq_proto::n0_nat_traversal::Error`,
/// one arm per variant.
///
/// `Multipath` carries a `PathError` upstream and does not here: every failure
/// inside it classifies the same way, so the payload would be a second thing to
/// keep correct for a decision that never changes.
pub const NatTraversalError = enum {
    /// The advertised set is full. Fatal, and see `max_qnt_addresses`.
    too_many_addresses,
    /// The round is not allowed from this end of the connection.
    wrong_connection_side,
    /// The peer never negotiated the extension, so a round cannot mean anything.
    extension_not_negotiated,
    /// Not enough addresses on one side or the other yet.
    not_enough_addresses,
    /// The multipath layer refused to open the paths the round asked for.
    multipath,
    /// The connection is closed or closing.
    closed,
};

comptime {
    // Upstream matches on this enum exhaustively, so a variant added there is a
    // compile error there. The switch in `classify` is exhaustive for the same
    // reason; this says so out loud and pins the count the arms above were
    // copied from, so a variant added without a classification fails the build
    // rather than inheriting a default arm nobody chose.
    if (@typeInfo(NatTraversalError).@"enum".fields.len != 6) {
        @compileError("a NatTraversalError variant has no classification");
    }
}

/// What to do about a refused round.
pub const Verdict = union(enum) {
    /// Ask again after this long. Only for the errors that mean the stack is not
    /// ready yet rather than that it never will be.
    retry: Nanos,
    /// Stop punching on this connection.
    fatal,
};

/// What a refused round means.
///
/// A function from the error to the decision, not an if-chain: each arm is a
/// policy call about whether this peer can still be reached directly, and there
/// is no "everything else" — the enum is closed, and closing it is the point.
pub fn classify(err: NatTraversalError) Verdict {
    return switch (err) {
        // Neither refuses the idea, only the moment: the multipath layer was
        // busy, or there were not enough addresses on one side to try with.
        .multipath, .not_enough_addresses => .{ .retry = retry_interval },
        // One end is full, one is the wrong end, one never spoke the extension,
        // one is gone. None of them becomes untrue while the connection is up.
        .closed, .too_many_addresses, .wrong_connection_side, .extension_not_negotiated => .fatal,
    };
}

/// What the stack said about a round.
pub const Outcome = union(enum) {
    /// `Ok`, and the remote candidates it found. These are what the next wakeup
    /// compares against, so they are the ones the caller must keep alive.
    accepted: []const SocketAddr,
    /// `Err`, classified by `classify`.
    refused: NatTraversalError,
};

/// Fold a round's answer back into the state. Pure, like `decide`.
///
/// Takes no candidate set, because there is nothing left of one to keep: the
/// accepted arm records when the round started and what the stack found, and
/// the caller already holds the set it started the round with — it is the same
/// `Candidates.local` it will hand to the next `decide` as
/// `previous_local`. Recording a slice of it here instead would be the one
/// thing in this layer that survives a copy of the state pointing at bytes that
/// are no longer the state being read.
pub fn settle(
    state: gate.PunchState,
    now: Nanos,
    outcome: Outcome,
) gate.Step {
    return switch (outcome) {
        .accepted => |remote| .{ .next = .{
            .punch = state.punch,
            .last = .{ .when = now, .remote = remote },
            .selected = state.selected,
            .stopped = state.stopped,
        } },
        .refused => |err| switch (classify(err)) {
            .retry => .{
                .next = state,
                .action = .{ .wakeAt = now +| retry_interval },
            },
            .fatal => .{
                .next = .{
                    .punch = state.punch,
                    .last = state.last,
                    .selected = state.selected,
                    .stopped = err,
                },
                .action = .stopPunching,
            },
        },
    };
}

const t = std.testing;

/// A direct address on port `port`, all from one documentation range so a test
/// that prints one is never mistaken for a routable host.
fn ip(port: u16) SocketAddr {
    return .{ .ip = .{ .v4 = .{ 192, 0, 2, 1 } }, .port = port };
}

/// The one instruction a step produced.
fn onlyAction(step: gate.Step) !gate.Action {
    return step.action orelse error.NoAction;
}

/// Whether two address lists name the same addresses in the same order.
/// `SocketAddr` is a struct, so `expectEqualSlices` cannot compare one.
fn expectSameAddrs(expected: []const SocketAddr, actual: []const SocketAddr) !void {
    if (expected.len != actual.len) return error.DifferentAddresses;
    for (expected, actual) |left, right| {
        if (left.order(right) != .eq) return error.DifferentAddresses;
    }
}

/// What a refused round classified to, as the two things a caller can ask.
fn expectVerdict(err: NatTraversalError, want: Verdict) !void {
    switch (want) {
        .retry => |after| switch (classify(err)) {
            .retry => |delay| try t.expectEqual(after, delay),
            .fatal => return error.NotRetried,
        },
        .fatal => switch (classify(err)) {
            .fatal => {},
            .retry => return error.NotFatal,
        },
    }
}

test "every retryable error asks again in 100 ms" {
    const state: gate.PunchState = .{ .punch = 3 };
    for ([_]NatTraversalError{ .multipath, .not_enough_addresses }) |err| {
        const step = settle(state, 50_000, .{ .refused = err });
        try t.expect(std.meta.eql(
            gate.Action{ .wakeAt = 50_000 + retry_interval },
            try onlyAction(step),
        ));

        try t.expect(step.next.stopped == null);
    }
}

test "every fatal error stops punching" {
    const state: gate.PunchState = .{ .punch = 3 };
    const fatal = [_]NatTraversalError{
        .closed,
        .too_many_addresses,
        .wrong_connection_side,
        .extension_not_negotiated,
    };
    for (fatal) |err| {
        const step = settle(state, 50_000, .{ .refused = err });
        try t.expect(std.meta.eql(gate.Action.stopPunching, try onlyAction(step)));
        try t.expectEqual(err, step.next.stopped.?);
        // A stopped state does not punch again, whatever the wakeup says.
        const again = gate.decide(step.next, 50_000 + gate.punch_interval, .{
            .local = &.{},
            .remote = &.{ip(1)},
            .previous_local = &.{},
        });
        try t.expect(again.action == null);
    }
}

test "every error variant is classified, and none is left over" {
    // The `comptime` guard above is the half the compiler checks: a variant
    // without a classification fails the build. This is the half it cannot —
    // that each of the six the guard names lands where upstream puts it.
    //
    // `too_many_addresses` is the reason that ceiling is a correctness bound:
    // it is fatal here, so `holepunch_gate.mayAdvertise` refuses the set before
    // the gate is asked rather than letting the stack answer fatally.
    const retryable = [_]NatTraversalError{ .multipath, .not_enough_addresses };
    const fatal = [_]NatTraversalError{
        .closed,
        .too_many_addresses,
        .wrong_connection_side,
        .extension_not_negotiated,
    };
    try t.expectEqual(
        @typeInfo(NatTraversalError).@"enum".fields.len,
        retryable.len + fatal.len,
    );
    for (retryable) |err| try expectVerdict(err, .{ .retry = retry_interval });
    for (fatal) |err| try expectVerdict(err, .fatal);
}

test "an accepted round records when it ran and what the stack found" {
    const discovered = [_]SocketAddr{ ip(2000), ip(2001) };
    const state: gate.PunchState = .{ .punch = 3, .selected = .{ .ip = ip(1000) } };
    const step = settle(state, 7_000, .{ .accepted = &discovered });
    // Upstream schedules nothing on `Ok`: the next trigger is an address
    // change, the scheduled wakeup it may already hold, or the periodic
    // connection check.
    try t.expect(step.action == null);
    const last = step.next.last orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(Nanos, 7_000), last.when);
    try expectSameAddrs(&discovered, last.remote);
    // The set the round *started* with is not recorded here: it is the caller's,
    // and the caller hands it back as `Candidates.previous_local`. A state that
    // kept a slice of it would be borrowing the storage its own owner holds,
    // and a copy of the state would read the original's bytes.
    try t.expectEqual(@as(?gate.ConnId, 3), step.next.punch);
}

test "a refused round does not move the interval" {
    // The state has no record of the failed round, so the same candidates read
    // as new on the next wakeup and the round happens again rather than sitting
    // out five seconds. This is what makes the 100 ms retry reachable at all.
    const local = [_]SocketAddr{ip(1000)};
    const state: gate.PunchState = .{ .punch = 3 };
    const step = settle(state, 1_000, .{ .refused = .not_enough_addresses });
    try t.expect(step.next.last == null);
    const again = gate.decide(step.next, 1_000 + retry_interval, .{
        .local = &local,
        .remote = &local,
        .previous_local = &.{},
    });
    try t.expect(std.meta.eql(
        gate.Action{ .initiateNatTraversalRound = 3 },
        try onlyAction(again),
    ));
}