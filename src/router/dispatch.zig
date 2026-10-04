//! One connection attempt: the machine that turns a state and an event into the
//! next state and the one thing to do about it.
//!
//! **Why this is its own file.** `dispatchStep` is a function of
//! `(table, state, event)` and nothing else, and the values it moves are the
//! protocol set's, not this machine's — `ConnState`, `ConnEvent` and
//! `DispatchStep` are declared in `router.zig` because a caller holding a task
//! needs them whether or not it steps anything. Keeping the machine out of the
//! type file is what makes the type file usable on its own: a caller that only
//! registers handlers and reads a `Claim` pulls in no state machine at all.
//!
//! **Nothing here performs anything.** Every handler call is *named* by a
//! `DispatchAction` (`on_accepting`, `accept`) and the caller makes it, which
//! is what lets a test drive a whole connection without a socket or a
//! scheduler.
//!
//! Captured 2026-09-30 from n0-computer/iroh commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8: upstream's four awaits in
//! `handle_connection` (`protocol.rs:637-671`) are the four live arms of
//! `ConnState`, in this order — the filter rules, the handshake produces an
//! ALPN, the handler takes the connection, the handler runs on it — and the
//! accept loop's `warn!`-and-return endings are this file's `Drop` arms.

const std = @import("std");
const router = @import("router.zig");

/// One step of a connection attempt.
///
/// `table` is a parameter, not state: which handler an ALPN resolves to is a
/// question about the table, and the table is the caller's, so nothing about
/// the answer is captured where a copy of it could go stale. Pure — the same
/// table, state and event always give the same step, which is what lets a test
/// drive a whole connection without a socket or a scheduler.
pub fn dispatchStep(
    table: *const router.Router,
    state: router.ConnState,
    event: router.ConnEvent,
) router.DispatchStep {
    return switch (state) {
        .incoming => incomingStep(event),
        .negotiating => negotiatingStep(table, event),
        .accepting => |handler| acceptingStep(handler, event),
        .handling => handledStep(event),
        // A terminal state absorbs everything. The first ending is the ending,
        // and a later event claiming otherwise is reported by the state the
        // caller already has, not by a second verdict written over the first.
        .retried, .refused, .ignored, .released, .dropped => .{
            .state = state,
            .action = .none,
        },
    };
}

fn incomingStep(event: router.ConnEvent) router.DispatchStep {
    const verdict = switch (event) {
        .filtered => |verdict| verdict,
        .outcome => return dropped(.{ .out_of_order = event }),
    };
    return switch (verdict) {
        .accept => .{ .state = .negotiating, .action = .negotiate_alpn },
        .retry => |retry| .{
            .state = .{ .retried = retry },
            .action = .{ .send_retry = retry },
        },
        .reject => .{ .state = .refused, .action = .refuse },
        .ignore => .{ .state = .ignored, .action = .ignore },
    };
}

fn negotiatingStep(
    table: *const router.Router,
    event: router.ConnEvent,
) router.DispatchStep {
    const outcome = switch (event) {
        .outcome => |outcome| outcome,
        .filtered => return dropped(.{ .out_of_order = event }),
    };
    return switch (outcome) {
        .alpn => |alpn| switch (table.dispatch(alpn)) {
            // No configured protocol claims it, so the connection goes away
            // and the peer is told nothing: upstream warns and returns
            // (`protocol.rs:653-656`). The *reason* is a refusal rather than a
            // bare ALPN, so a caller can say what it serves and that the peer
            // asked for something else. A clean refusal of a wrong protocol
            // normally happens earlier than this — in the handshake, on the
            // empty intersection with `Router.offers` — and this arm is the
            // residue of a table and a transport configured apart.
            .refused => |refusal| dropped(.{ .refused_protocol = refusal }),
            .protocol => |found| blk: {
                const handler = found.entry.handler;
                break :blk .{
                    .state = .{ .accepting = handler },
                    // Upstream's default `on_accepting` is the router's await,
                    // so a handler that has no `on_accepting` is not called at
                    // all.
                    .action = if (handler.on_accepting == null)
                        .await_handshake
                    else
                        .{ .on_accepting = handler },
                };
            },
        },
        .failed => |failure| switch (failure) {
            .handshake => |err| dropped(.{ .failed = .{ .handshake = err } }),
            // The other two belong to the two stages after this one.
            .accepting, .accept => dropped(.{ .out_of_order = event }),
        },
        .connection, .finished => dropped(.{ .out_of_order = event }),
    };
}

fn acceptingStep(
    handler: router.ProtocolHandler,
    event: router.ConnEvent,
) router.DispatchStep {
    const outcome = switch (event) {
        .outcome => |outcome| outcome,
        .filtered => return dropped(.{ .out_of_order = event }),
    };
    return switch (outcome) {
        .connection => .{
            .state = .{ .handling = handler },
            .action = .{ .accept = handler },
        },
        .failed => |failure| switch (failure) {
            .accepting => |err| dropped(.{ .failed = .{ .accepting = err } }),
            .handshake, .accept => dropped(.{ .out_of_order = event }),
        },
        .alpn, .finished => dropped(.{ .out_of_order = event }),
    };
}

fn handledStep(event: router.ConnEvent) router.DispatchStep {
    const outcome = switch (event) {
        .outcome => |outcome| outcome,
        .filtered => return dropped(.{ .out_of_order = event }),
    };
    return switch (outcome) {
        // Upstream drops the connection when the future returns; the handler
        // kept a clone if it wanted the connection to live
        // (`protocol.rs:262-265`).
        .finished => .{ .state = .released, .action = .release },
        .failed => |failure| switch (failure) {
            // The headline: a drop, and nothing sent to the peer. See
            // `Failure.accept`.
            .accept => |err| dropped(.{ .failed = .{ .accept = err } }),
            .handshake, .accepting => dropped(.{ .out_of_order = event }),
        },
        .alpn, .connection => dropped(.{ .out_of_order = event }),
    };
}

/// The terminal step for a connection that is gone. The state and the action
/// carry the same reason, because the caller has to act on one and the next
/// step has to remember the other.
fn dropped(reason: router.Drop) router.DispatchStep {
    return .{ .state = .{ .dropped = reason }, .action = .{ .drop = reason } };
}

const t = std.testing;

/// A handler that records what this machine named it for. Every test here owns
/// one, so the context pointer is the observable "which handler won".
const Recorder = struct {
    on_accepting_calls: usize = 0,
    accept_calls: usize = 0,
    accept_error: ?router.AcceptError = null,

    fn onAccepting(
        ctx: *anyopaque,
        accepting: router.Accepting,
    ) router.AcceptError!router.Connection {
        const self: *Recorder = @ptrCast(@alignCast(ctx));
        _ = accepting;
        self.on_accepting_calls += 1;
        return .{ .ptr = ctx };
    }

    fn accept(ctx: *anyopaque, connection: router.Connection) router.AcceptError!void {
        const self: *Recorder = @ptrCast(@alignCast(ctx));
        _ = connection;
        self.accept_calls += 1;
        if (self.accept_error) |err| return err;
    }

    fn handler(self: *Recorder) router.ProtocolHandler {
        return .{
            .ptr = self,
            .on_accepting = Recorder.onAccepting,
            .accept = Recorder.accept,
            // Nothing in this file shuts a handler down — that is
            // `shutdown.zig`'s machine — so the recorder takes the router's own
            // default and no test here can tell the difference.
            .shutdown = null,
        };
    }

    /// A handler that implements `accept` and nothing else, which is the shape
    /// upstream's default methods are for: the router runs both defaults and
    /// this one is never called for them.
    fn bare(self: *Recorder) router.ProtocolHandler {
        return .{
            .ptr = self,
            .on_accepting = null,
            .accept = Recorder.accept,
            .shutdown = null,
        };
    }
};

/// A table with one handler for `alpn`, and the recorder behind it.
fn oneHandler(
    alpn: []const u8,
    entries: []router.Entry,
    recorder: *Recorder,
) router.RegisterError!router.Router {
    var builder = router.Builder.init(entries);
    _ = try builder.accept(alpn, recorder.handler());
    return builder.build();
}

/// Which handler a dispatch found. `*anyopaque` does not compare with a typed
/// pointer, so a test names the handler it expects through this.
fn isContext(handler: router.ProtocolHandler, context: *Recorder) bool {
    return handler.ptr == @as(*anyopaque, context);
}

/// The claim a dispatch found, or null when nothing claimed it. A test names
/// the handler it expects through the claim rather than through a bare entry,
/// so the index is one assertion away.
fn claim(table: *const router.Router, alpn: []const u8) ?router.Claim {
    return switch (table.dispatch(alpn)) {
        .protocol => |found| found,
        .refused => null,
    };
}

test "the filter's four verdicts, and only a refusal reaches the peer" {
    var recorder: Recorder = .{};
    var entries: [1]router.Entry = undefined;
    const table = try oneHandler("/echo", &entries, &recorder);

    // Carry on: the handshake is owed and nothing is sent.
    const accept = dispatchStep(&table, .incoming, .{ .filtered = .accept });
    try t.expectEqual(router.ConnState.negotiating, accept.state);
    try t.expectEqual(router.DispatchAction.negotiate_alpn, accept.action);
    try t.expectEqual(router.PeerOutcome.nothing, accept.action.peerOutcome());

    // Retry: the token is sent and the attempt ends. The meaning rides along.
    const direct = dispatchStep(&table, .incoming, .{
        .filtered = .{ .retry = router.retryMeaning(.custom) },
    });
    try t.expectEqual(router.ConnState{ .retried = .source_validation }, direct.state);
    try t.expectEqual(
        router.DispatchAction{ .send_retry = .source_validation },
        direct.action,
    );
    try t.expectEqual(router.PeerOutcome.nothing, direct.action.peerOutcome());

    // The same verdict on a relayed path is a different value and a different
    // state, which is the whole point of carrying the meaning.
    const relayed = dispatchStep(&table, .incoming, .{
        .filtered = .{ .retry = router.retryMeaning(.relay) },
    });
    try t.expectEqual(router.ConnState{ .retried = .cost_imposition }, relayed.state);

    // Reject: the one thing the peer is told.
    const reject = dispatchStep(&table, .incoming, .{ .filtered = .reject });
    try t.expectEqual(router.ConnState.refused, reject.state);
    try t.expectEqual(router.DispatchAction.refuse, reject.action);
    try t.expectEqual(router.PeerOutcome.refused, reject.action.peerOutcome());

    // Ignore: no packet, and unlike every other ending here, no warning.
    const ignore = dispatchStep(&table, .incoming, .{ .filtered = .ignore });
    try t.expectEqual(router.ConnState.ignored, ignore.state);
    try t.expectEqual(router.DispatchAction.ignore, ignore.action);
    try t.expectEqual(router.PeerOutcome.nothing, ignore.action.peerOutcome());
}

test "an ALPN no configured protocol claims is refused cleanly and told to nobody" {
    var recorder: Recorder = .{};
    var entries: [1]router.Entry = undefined;
    const table = try oneHandler("/echo", &entries, &recorder);

    const step = dispatchStep(&table, .negotiating, .{
        .outcome = .{ .alpn = "/unknown" },
    });
    // Upstream warns and returns: the peer is told nothing, so this is a drop
    // and not a refusal even though the router does know the ALPN
    // (`protocol.rs:653-656`). What is clean about it is the *reason* — it
    // names the ALPN the peer asked for and how many protocols are configured,
    // so the caller's log line says what this endpoint serves rather than only
    // that something went away.
    const refusal: router.Refusal = .{ .alpn = "/unknown", .configured = 1 };
    try t.expectEqual(router.ConnState{ .dropped = .{ .refused_protocol = refusal } }, step.state);
    try t.expectEqual(
        router.DispatchAction{ .drop = .{ .refused_protocol = refusal } },
        step.action,
    );
    try t.expectEqual(router.PeerOutcome.nothing, step.action.peerOutcome());
    try t.expectEqual(@as(usize, 0), recorder.accept_calls);

    // The same refusal is what the table hands a caller that asked directly, so
    // the connection's ending and the table's answer are one type: a caller
    // that routes a task and finds this can name the reason without reading it
    // back out of a state.
    try t.expectEqual(refusal, table.dispatch("/unknown").refused);

    // And an endpoint configured with nothing refuses every ALPN, including
    // the one its own registration would have used: `configured` of zero is
    // what tells the two apart in a log line.
    var empty_entries: [1]router.Entry = undefined;
    var empty_builder = router.Builder.init(&empty_entries);
    const empty = empty_builder.build();
    try t.expectEqual(@as(usize, 0), empty.configured());
    try t.expectEqual(
        router.Refusal{ .alpn = "/echo", .configured = 0 },
        dispatchStep(&empty, .negotiating, .{ .outcome = .{ .alpn = "/echo" } })
            .state.dropped.refused_protocol,
    );
}

test "several configured protocols each dispatch to their own handler" {
    // The shape the single-ALPN runtime could not express: three protocols on
    // one table, each with its own handler, each reached only by its own ALPN.
    var gossip: Recorder = .{};
    var blobs: Recorder = .{};
    var relay: Recorder = .{};
    var entries: [3]router.Entry = undefined;
    var builder = router.Builder.init(&entries);
    _ = try builder.accept("/iroh-gossip/1", gossip.handler());
    _ = try builder.accept("/iroh-bytes/4", blobs.handler());
    _ = try builder.accept("/iroh-relay/1", relay.handler());
    const table = builder.build();
    try t.expectEqual(@as(usize, 3), table.protocolCount());

    // The pairs a caller asserts on: ALPN, the handler it must reach, and the
    // index its lane and its tasks are addressed by.
    const cases = [_]struct { alpn: []const u8, recorder: *Recorder, index: usize }{
        .{ .alpn = "/iroh-gossip/1", .recorder = &gossip, .index = 0 },
        .{ .alpn = "/iroh-bytes/4", .recorder = &blobs, .index = 1 },
        .{ .alpn = "/iroh-relay/1", .recorder = &relay, .index = 2 },
    };
    for (cases) |want| {
        const negotiated = dispatchStep(&table, .negotiating, .{
            .outcome = .{ .alpn = want.alpn },
        });
        const accepted = claim(&table, want.alpn).?;
        try t.expectEqual(want.index, accepted.index);
        // Each ALPN finds its own handler and nobody else's, which is the whole
        // of a multi-protocol dispatch table: the state carries the handler, so
        // a caller that reads it can see which protocol a connection landed on
        // without asking the table again.
        try t.expectEqual(
            router.ConnState{ .accepting = want.recorder.handler() },
            negotiated.state,
        );
        try t.expectEqual(
            router.DispatchAction{ .on_accepting = want.recorder.handler() },
            negotiated.action,
        );
        // And the table's answer is the same one the machine took, so a caller
        // routing an accept task to a lane and the machine dispatching the
        // connection cannot disagree about which protocol this is.
        try t.expect(isContext(negotiated.state.accepting, want.recorder));
        // Nothing has been called yet: dispatch names the handler, it does not
        // hand the connection over, which is what lets a caller run three
        // protocols' worth of state machine with no scheduler between them.
        try t.expectEqual(@as(usize, 0), want.recorder.on_accepting_calls);
        try t.expectEqual(@as(usize, 0), want.recorder.accept_calls);

        // The named call, made by the caller, reaching the handler the ALPN
        // chose and no other.
        const takeover = negotiated.action.on_accepting;
        const on_accepting = takeover.on_accepting orelse
            return error.TestUnexpectedResult;
        _ = try on_accepting(takeover.ptr, .{ .ptr = @as(*anyopaque, want.recorder) });
        try t.expectEqual(@as(usize, 1), want.recorder.on_accepting_calls);
    }

    // Three protocols, three handlers, each called once, and each called for
    // its own ALPN: a handler never sees a connection that negotiated a
    // protocol it was not registered for.
    try t.expectEqual(@as(usize, 1), gossip.on_accepting_calls);
    try t.expectEqual(@as(usize, 1), blobs.on_accepting_calls);
    try t.expectEqual(@as(usize, 1), relay.on_accepting_calls);
    try t.expectEqual(@as(usize, 0), gossip.accept_calls);
    try t.expectEqual(@as(usize, 0), blobs.accept_calls);
    try t.expectEqual(@as(usize, 0), relay.accept_calls);

    // A peer asking for a fourth protocol is refused by the same table, and it
    // never reaches a handler: the refusal is the answer, not a missing entry.
    try t.expectEqual(
        router.Refusal{ .alpn = "/iroh-docs/1", .configured = 3 },
        dispatchStep(&table, .negotiating, .{ .outcome = .{ .alpn = "/iroh-docs/1" } })
            .state.dropped.refused_protocol,
    );
    try t.expectEqual(@as(usize, 1), gossip.on_accepting_calls);
}

test "the two accepting routes converge on the same call" {
    var with_default: Recorder = .{};
    var with_own: Recorder = .{};
    var entries: [2]router.Entry = undefined;
    var builder = router.Builder.init(&entries);
    _ = try builder.accept("/bare", with_default.bare());
    _ = try builder.accept("/own", with_own.handler());
    const table = builder.build();

    // No `on_accepting`: the router awaits the handshake itself, which is
    // upstream's default body.
    const awaited = dispatchStep(&table, .negotiating, .{
        .outcome = .{ .alpn = "/bare" },
    });
    try t.expectEqual(router.ConnState{ .accepting = with_default.bare() }, awaited.state);
    try t.expectEqual(router.DispatchAction.await_handshake, awaited.action);
    try t.expectEqual(@as(usize, 0), with_default.on_accepting_calls);

    // With one: the handler is called, and the action names the call rather
    // than the router having made it. Calling it here is what makes the action
    // checkable without a scheduler.
    const called = dispatchStep(&table, .negotiating, .{
        .outcome = .{ .alpn = "/own" },
    });
    switch (called.action) {
        .on_accepting => |handler| {
            const on_accepting = handler.on_accepting orelse return error.TestUnexpectedResult;
            const connection = try on_accepting(handler.ptr, .{ .ptr = &with_own });
            // The handle comes back unchanged, which is the whole of what a
            // pre-handshake handle is allowed to be here.
            try t.expect(connection.ptr == @as(*anyopaque, &with_own));
            try t.expectEqual(@as(usize, 1), with_own.on_accepting_calls);

            // Both routes now owe the same call, on the same kind of state.
            const next = dispatchStep(&table, called.state, .{
                .outcome = .{ .connection = connection },
            });
            try t.expectEqual(router.ConnState{ .handling = handler }, next.state);
            try t.expectEqual(router.DispatchAction{ .accept = handler }, next.action);
        },
        else => return error.TestUnexpectedResult,
    }
    try t.expectEqual(@as(usize, 0), with_default.on_accepting_calls);
}

test "an accept failure drops the connection and sends no error code" {
    var recorder: Recorder = .{ .accept_error = error.NotAllowed };
    var entries: [1]router.Entry = undefined;
    const table = try oneHandler("/echo", &entries, &recorder);

    // All the way to a running accept.
    const offered_alpn = dispatchStep(&table, .negotiating, .{
        .outcome = .{ .alpn = "/echo" },
    });
    const handling = dispatchStep(&table, offered_alpn.state, .{
        .outcome = .{ .connection = .{ .ptr = &entries } },
    });
    try t.expectEqual(router.ConnState{ .handling = recorder.handler() }, handling.state);
    try t.expectEqual(router.DispatchAction{ .accept = recorder.handler() }, handling.action);

    // And now it fails.
    const failed = dispatchStep(&table, handling.state, .{
        .outcome = .{ .failed = .{ .accept = error.NotAllowed } },
    });
    const drop: router.Drop = .{ .failed = .{ .accept = error.NotAllowed } };
    try t.expectEqual(router.ConnState{ .dropped = drop }, failed.state);
    try t.expectEqual(router.DispatchAction{ .drop = drop }, failed.action);
    // Invariant 19. The connection is dropped, nothing is sent, and the only
    // trace of it is the warning the caller logs for a `.drop`. A handler that
    // wants the peer to know closes the connection itself, before it returns
    // the error — and if someone "fixes" this path into an error code, the two
    // lines below are what fails.
    try t.expectEqual(router.PeerOutcome.nothing, failed.action.peerOutcome());
    // The refusal is still the one thing that reaches a peer, so the assertion
    // above is not the assertion that every action is silent.
    try t.expectEqual(
        router.PeerOutcome.refused,
        dispatchStep(&table, .incoming, .{ .filtered = .reject }).action.peerOutcome(),
    );
}

test "a handler that returns cleanly releases the connection" {
    var recorder: Recorder = .{};
    var entries: [1]router.Entry = undefined;
    const table = try oneHandler("/echo", &entries, &recorder);

    const step = dispatchStep(&table, .{ .handling = recorder.handler() }, .{
        .outcome = .finished,
    });
    try t.expectEqual(router.ConnState.released, step.state);
    // Released is also a drop of the connection — upstream drops it when the
    // future returns — but not a failure, so it is a different action and no
    // warning goes with it.
    try t.expectEqual(router.DispatchAction.release, step.action);
    try t.expectEqual(router.PeerOutcome.nothing, step.action.peerOutcome());
}

test "a failed handshake or a failed on_accepting is a drop with a warning" {
    var recorder: Recorder = .{};
    var entries: [1]router.Entry = undefined;
    const table = try oneHandler("/echo", &entries, &recorder);

    // The handshake never produced an ALPN.
    const handshake = dispatchStep(&table, .negotiating, .{
        .outcome = .{ .failed = .{ .handshake = error.Connecting } },
    });
    try t.expectEqual(router.ConnState{ .dropped = .{
        .failed = .{ .handshake = error.Connecting },
    } }, handshake.state);
    try t.expectEqual(router.PeerOutcome.nothing, handshake.action.peerOutcome());

    // The handler's `on_accepting` failed, which upstream logs under the same
    // line as the default await.
    const accepting = dispatchStep(&table, .{ .accepting = recorder.handler() }, .{
        .outcome = .{ .failed = .{ .accepting = error.MissingRemoteEndpointId } },
    });
    try t.expectEqual(router.ConnState{ .dropped = .{
        .failed = .{ .accepting = error.MissingRemoteEndpointId },
    } }, accepting.state);
    try t.expectEqual(router.PeerOutcome.nothing, accepting.action.peerOutcome());
    try t.expectEqual(@as(usize, 0), recorder.accept_calls);
}

test "each live state accepts only the outcome its own stage produces" {
    var recorder: Recorder = .{};
    var entries: [1]router.Entry = undefined;
    const table = try oneHandler("/echo", &entries, &recorder);

    // `ConnState` order, and the one `Outcome` success arm each state is
    // waiting for. `incoming` owes the filter, not a stage.
    const live = [_]router.ConnState{
        .incoming,
        .negotiating,
        .{ .accepting = recorder.handler() },
        .{ .handling = recorder.handler() },
    };
    const successes = [_]router.Outcome{
        .{ .alpn = "/echo" },
        .{ .connection = .{ .ptr = &recorder } },
        .finished,
    };
    // The one failure each state can produce. The other two are out of order
    // for it, which is what stops a handler failure being reported one stage
    // early.
    const failures = [_]router.Failure{
        .{ .handshake = error.Connecting },
        .{ .accepting = error.NotAllowed },
        .{ .accept = error.Connection },
    };

    for (live, 0..) |state, stage| {
        for (successes, 0..) |outcome, arm| {
            const step = dispatchStep(&table, state, .{ .outcome = outcome });
            // The one stage this state is waiting for moves it on; every other
            // report is a drop that names the event it could not accept.
            if (stage == arm + 1) {
                try t.expect(std.meta.activeTag(step.state) != .dropped);
            } else {
                try t.expectEqual(
                    router.Drop{ .out_of_order = .{ .outcome = outcome } },
                    step.state.dropped,
                );
            }
        }
        for (failures) |failure| {
            const step = dispatchStep(&table, state, .{
                .outcome = .{ .failed = failure },
            });
            // `failures` is in `ConnState` order minus the state that owes no
            // stage, so the state's own failure is one below its index.
            if (stage > 0 and
                std.meta.activeTag(failure) == std.meta.activeTag(failures[stage - 1]))
            {
                try t.expectEqual(router.Drop{ .failed = failure }, step.state.dropped);
            } else {
                try t.expectEqual(
                    router.Drop{ .out_of_order = .{ .outcome = .{ .failed = failure } } },
                    step.state.dropped,
                );
            }
        }
    }
}

test "a terminal connection state absorbs every event" {
    var recorder: Recorder = .{};
    var entries: [1]router.Entry = undefined;
    const table = try oneHandler("/echo", &entries, &recorder);

    // The first ending is the ending, and a later event does not overwrite the
    // record of it.
    const terminal = [_]router.ConnState{
        .{ .retried = .cost_imposition },
        .refused,
        .ignored,
        .released,
        .{ .dropped = .{ .failed = .{ .accept = error.NotAllowed } } },
    };
    const events = [_]router.ConnEvent{
        .{ .filtered = .accept },
        .{ .filtered = .reject },
        .{ .outcome = .finished },
        .{ .outcome = .{ .failed = .{ .accept = error.NotAllowed } } },
    };
    for (terminal) |state| {
        for (events) |event| {
            const step = dispatchStep(&table, state, event);
            try t.expectEqual(state, step.state);
            try t.expectEqual(router.DispatchAction.none, step.action);
        }
    }
}
