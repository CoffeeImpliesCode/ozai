//! The router: ALPN dispatch, the two machines it is, and the whole surface
//! re-exported.
//!
//! The whole surface is re-exported here, so every caller outside
//! `src/router/` keeps importing one name and no caller changes. The
//! declarations live in three modules named for what they are responsible for,
//! and the split is by responsibility rather than by size — one module per
//! machine, plus the table both of them read:
//!
//! - `alpn_table.zig` — what a registration is, the reserved ALPN, and the
//!   lookup a frozen table answers.
//! - `conn_dispatch.zig` — one connection attempt, as a machine.
//! - `shutdown.zig` — the endpoint's shutdown order, and the lease that
//!   carries it.
//!
//! # The original module doc, unchanged
//!
// The router: the ALPN table, the handler vtable it dispatches through, and
// the two machines the router is — one per connection, one per endpoint.
//
// Captured 2026-09-30 from n0-computer/iroh commit
// 187f59e80afdae6bd9866002b33d3365c00b06d8: `ProtocolHandler` at
// `iroh/src/protocol.rs:228-287`; `ProtocolMap` at `protocol.rs:375-408`;
// `RouterBuilder::accept` at `protocol.rs:495-503`; the accept loop and
// `handle_connection` at `protocol.rs:531-672`; the shutdown order at
// `protocol.rs:608-623`; `IncomingFilterOutcome` at `protocol.rs:164-209`;
// `Incoming::{accept, refuse, retry, ignore, remote_addr_validated}` at
// `iroh/src/endpoint/connection.rs:138-230`; the ALPN preference order at
// `iroh/src/endpoint.rs:973-993`; `/iroh-qad/0` at `iroh-relay/src/quic.rs:10`.
// Each is named where it is reproduced.
//
// Nothing here opens a socket, reads a clock, or allocates: the ALPN bytes
// and the entries that hold them are the caller's, a handler is a context
// pointer and three function pointers, and every step is a value. The router's
// whole job is one line of `docs/ARCHITECTURE.md` — it turns a negotiated
// ALPN into a handler call — and what is worth a machine is what surrounds
// the call: the accepts may not be cancelled until every handler has finished
// shutting down, and an `accept` that fails tells the peer nothing.

const std = @import("std");
const alpn_table = @import("alpn_table.zig");
const conn_dispatch = @import("conn_dispatch.zig");
const router_shutdown = @import("shutdown.zig");

/// See `alpn_table.ProtocolHandler`.
pub const ProtocolHandler = alpn_table.ProtocolHandler;
/// See `alpn_table.Accepting`.
pub const Accepting = alpn_table.Accepting;
/// See `alpn_table.Connection`.
pub const Connection = alpn_table.Connection;
/// See `alpn_table.AcceptError`.
pub const AcceptError = alpn_table.AcceptError;
/// See `alpn_table.qad_alpn`.
pub const qad_alpn = alpn_table.qad_alpn;
/// See `alpn_table.Entry`.
pub const Entry = alpn_table.Entry;
/// See `alpn_table.Registered`.
pub const Registered = alpn_table.Registered;
/// See `alpn_table.RegisterError`.
pub const RegisterError = alpn_table.RegisterError;
/// See `alpn_table.Builder`.
pub const Builder = alpn_table.Builder;
/// See `alpn_table.Router`.
pub const Router = alpn_table.Router;
/// See `alpn_table.AlpnIterator`.
pub const AlpnIterator = alpn_table.AlpnIterator;

/// See `conn_dispatch.Retry`.
pub const Retry = conn_dispatch.Retry;
/// See `conn_dispatch.retryMeaning`.
pub const retryMeaning = conn_dispatch.retryMeaning;
/// See `conn_dispatch.Verdict`.
pub const Verdict = conn_dispatch.Verdict;
/// See `conn_dispatch.Failure`.
pub const Failure = conn_dispatch.Failure;
/// See `conn_dispatch.Drop`.
pub const Drop = conn_dispatch.Drop;
/// See `conn_dispatch.PeerOutcome`.
pub const PeerOutcome = conn_dispatch.PeerOutcome;
/// See `conn_dispatch.DispatchAction`.
pub const DispatchAction = conn_dispatch.DispatchAction;
/// See `conn_dispatch.ConnState`.
pub const ConnState = conn_dispatch.ConnState;
/// See `conn_dispatch.ConnEvent`.
pub const ConnEvent = conn_dispatch.ConnEvent;
/// See `conn_dispatch.Outcome`.
pub const Outcome = conn_dispatch.Outcome;
/// See `conn_dispatch.DispatchStep`.
pub const DispatchStep = conn_dispatch.DispatchStep;
/// See `conn_dispatch.dispatchStep`.
pub const dispatchStep = conn_dispatch.dispatchStep;

/// See `shutdown.Shutdown`.
pub const Shutdown = router_shutdown.Shutdown;
/// See `shutdown.Lease`.
pub const Lease = router_shutdown.Lease;
/// See `shutdown.Release`.
pub const Release = router_shutdown.Release;

const t = std.testing;

/// A handler that records what the router called it for. Every test owns one,
/// so the context pointer is the observable "which handler won".
const Recorder = struct {
    on_accepting_calls: usize = 0,
    accept_calls: usize = 0,
    shutdown_calls: usize = 0,
    accept_error: ?AcceptError = null,

    fn onAccepting(ctx: *anyopaque, accepting: Accepting) AcceptError!Connection {
        const self: *Recorder = @ptrCast(@alignCast(ctx));
        _ = accepting;
        self.on_accepting_calls += 1;
        return .{ .ptr = ctx };
    }

    fn accept(ctx: *anyopaque, connection: Connection) AcceptError!void {
        const self: *Recorder = @ptrCast(@alignCast(ctx));
        _ = connection;
        self.accept_calls += 1;
        if (self.accept_error) |err| return err;
    }

    fn shutdown(ctx: *anyopaque) void {
        const self: *Recorder = @ptrCast(@alignCast(ctx));
        self.shutdown_calls += 1;
    }

    fn handler(self: *Recorder) ProtocolHandler {
        return .{
            .ptr = self,
            .on_accepting = Recorder.onAccepting,
            .accept = Recorder.accept,
            .shutdown = Recorder.shutdown,
        };
    }

    /// A handler that implements `accept` and nothing else, which is the shape
    /// upstream's default methods are for: the router runs both defaults and
    /// this one is never called for them.
    fn bare(self: *Recorder) ProtocolHandler {
        return .{
            .ptr = self,
            .on_accepting = null,
            .accept = Recorder.accept,
            .shutdown = null,
        };
    }
};

/// The offer list, into storage the test owns. Bounded by `out` so an
/// under-sized buffer shows up as a wrong count rather than an index panic.
fn offered(router: *const Router, out: [][]const u8) usize {
    var alpns = router.alpns();
    var count: usize = 0;
    while (count < out.len) {
        const alpn = alpns.next() orelse break;
        out[count] = alpn;
        count += 1;
    }
    return count;
}

/// A router with one handler for `alpn`, and the recorder behind it.
fn oneHandler(
    alpn: []const u8,
    entries: []Entry,
    recorder: *Recorder,
) RegisterError!Router {
    var builder = Builder.init(entries);
    _ = try builder.accept(alpn, recorder.handler());
    return builder.build();
}

/// Which handler a lookup found. `*anyopaque` does not compare with a typed
/// pointer, so a test names the handler it expects through this.
fn isContext(handler: ProtocolHandler, context: *Recorder) bool {
    return handler.ptr == @as(*anyopaque, context);
}

test "the handler vtable is four fields and no more" {
    // The plan names the four. A fifth would be a trait method wearing a
    // vtable's name, which is what `AddressLookup` refuses in
    // `discovery/resolve.zig`.
    const fields = @typeInfo(ProtocolHandler).@"struct".field_names;
    try t.expectEqual(@as(usize, 4), fields.len);
    const names = [_][]const u8{ "ptr", "on_accepting", "accept", "shutdown" };
    inline for (fields, names) |field, name| {
        try t.expectEqualStrings(name, field);
    }
}

test "every callback gets the handler's own context back" {
    var recorder: Recorder = .{};
    const handler = recorder.handler();

    const on_accepting = handler.on_accepting orelse return error.TestUnexpectedResult;
    const shutdown = handler.shutdown orelse return error.TestUnexpectedResult;
    const connection = try on_accepting(handler.ptr, .{ .ptr = &recorder });
    try t.expectEqual(handler.ptr, connection.ptr);
    try handler.accept(handler.ptr, connection);
    shutdown(handler.ptr);

    // The context is not copied or replaced, and each entry is called once.
    try t.expectEqual(@as(usize, 1), recorder.on_accepting_calls);
    try t.expectEqual(@as(usize, 1), recorder.accept_calls);
    try t.expectEqual(@as(usize, 1), recorder.shutdown_calls);
}

test "registration order is the offer order" {
    var first: Recorder = .{};
    var second: Recorder = .{};
    var third: Recorder = .{};
    var entries: [3]Entry = undefined;
    var builder = Builder.init(&entries);

    try t.expectEqual(Registered.fresh, try builder.accept("/echo", first.handler()));
    try t.expectEqual(Registered.fresh, try builder.accept("/blob", second.handler()));
    try t.expectEqual(Registered.fresh, try builder.accept("/qad-probe", third.handler()));

    // The order the ALPNs were registered in, which is the order the peer is
    // offered them in, which is the order a server's preference runs.
    var list: [3][]const u8 = undefined;
    const router = builder.build();
    try t.expectEqual(@as(usize, 3), offered(&router, &list));
    try t.expectEqualStrings("/echo", list[0]);
    try t.expectEqualStrings("/blob", list[1]);
    try t.expectEqualStrings("/qad-probe", list[2]);

    // And each one dispatches to the handler it was registered with.
    try t.expect(isContext(router.lookup("/echo").?.handler, &first));
    try t.expect(isContext(router.lookup("/blob").?.handler, &second));
    try t.expect(isContext(router.lookup("/qad-probe").?.handler, &third));
    try t.expectEqual(@as(?*const Entry, null), router.lookup("/nope"));
}

test "an ALPN registered twice is offered twice and dispatches to the newer handler" {
    var older: Recorder = .{};
    var newer: Recorder = .{};
    // Three slots for three registrations: a repeated ALPN takes a second slot
    // rather than replacing the first, because it is offered twice.
    var entries: [3]Entry = undefined;
    var builder = Builder.init(&entries);

    try t.expectEqual(Registered.fresh, try builder.accept("/echo", older.handler()));
    // The second registration names the entry it displaces, so the caller can
    // see that the first one is now unreachable instead of finding out from a
    // peer.
    try t.expectEqual(
        Registered{ .replaced = 0 },
        try builder.accept("/echo", newer.handler()),
    );
    try t.expectEqual(Registered.fresh, try builder.accept("/blob", older.handler()));

    // Both halves of upstream's overwrite, and they disagree on purpose: the
    // peer is offered the ALPN twice, and only the newer handler can be picked.
    var list: [3][]const u8 = undefined;
    const router = builder.build();
    try t.expectEqual(@as(usize, 3), offered(&router, &list));
    try t.expectEqualStrings("/echo", list[0]);
    try t.expectEqualStrings("/echo", list[1]);
    try t.expectEqualStrings("/blob", list[2]);

    try t.expect(isContext(router.lookup("/echo").?.handler, &newer));
    try t.expect(isContext(router.lookup("/blob").?.handler, &older));
    // The displaced entry is still there, holding the ALPN, because upstream
    // pushes onto the offer list unconditionally.
    try t.expect(isContext(router.entries[0].handler, &older));
}

test "the internal ALPN is one constant an application cannot register" {
    var recorder: Recorder = .{};
    var entries: [1]Entry = undefined;
    var builder = Builder.init(&entries);

    // Captured from `iroh-relay/src/quic.rs:10`; the bytes are the contract
    // with every iroh peer that speaks address discovery.
    try t.expectEqualStrings("/iroh-qad/0", qad_alpn);
    try t.expectEqual(@as(usize, 11), qad_alpn.len);

    try t.expectError(error.reserved_alpn, builder.accept(qad_alpn, recorder.handler()));
    // And the refusal changed nothing: no entry, no offer.
    var list: [1][]const u8 = undefined;
    const refused = builder.build();
    try t.expectEqual(@as(usize, 0), offered(&refused, &list));

    // The one way in takes no ALPN, so there is no string to pass wrongly.
    try t.expectEqual(Registered.fresh, try builder.acceptInternal(recorder.handler()));
    const router = builder.build();
    try t.expectEqual(@as(usize, 1), offered(&router, &list));
    try t.expectEqualStrings(qad_alpn, list[0]);
    try t.expect(isContext(router.lookup(qad_alpn).?.handler, &recorder));
}

test "a full table refuses a registration and changes nothing" {
    var recorder: Recorder = .{};
    var entries: [1]Entry = undefined;
    var builder = Builder.init(&entries);

    try t.expectEqual(Registered.fresh, try builder.accept("/echo", recorder.handler()));
    try t.expectError(error.no_space, builder.accept("/blob", recorder.handler()));

    var list: [1][]const u8 = undefined;
    const router = builder.build();
    try t.expectEqual(@as(usize, 1), offered(&router, &list));
    try t.expectEqualStrings("/echo", list[0]);
    try t.expectEqual(@as(?*const Entry, null), router.lookup("/blob"));
}

test "a retry is address validation on a direct path and a cost on a relay" {
    // Same verb, two meanings, and the path is what tells them apart. One type
    // with two values, so a verdict that lost its meaning on the way through
    // the router stops comparing equal to what the path says it should be.
    try t.expectEqual(Retry.source_validation, retryMeaning(.any_path));
    try t.expectEqual(Retry.source_validation, retryMeaning(.custom));
    try t.expectEqual(Retry.cost_imposition, retryMeaning(.relay));
}

test "an ALPN nobody registered is dropped, not refused" {
    var recorder: Recorder = .{};
    var entries: [1]Entry = undefined;
    const router = try oneHandler("/echo", &entries, &recorder);

    const step = dispatchStep(&router, .negotiating, .{
        .outcome = .{ .alpn = "/unknown" },
    });
    // Upstream warns and returns: the peer is told nothing, so this is a drop
    // and not a refusal even though the router does know the ALPN.
    try t.expectEqual(
        ConnState{ .dropped = .{ .unsupported_alpn = "/unknown" } },
        step.state,
    );
    try t.expectEqual(
        DispatchAction{ .drop = .{ .unsupported_alpn = "/unknown" } },
        step.action,
    );
    try t.expectEqual(PeerOutcome.nothing, step.action.peerOutcome());
    try t.expectEqual(@as(usize, 0), recorder.accept_calls);
}

test "the two accepting routes converge on the same call" {
    var with_default: Recorder = .{};
    var with_own: Recorder = .{};
    var entries: [2]Entry = undefined;
    var builder = Builder.init(&entries);
    _ = try builder.accept("/bare", with_default.bare());
    _ = try builder.accept("/own", with_own.handler());
    const router = builder.build();

    // No `on_accepting`: the router awaits the handshake itself, which is
    // upstream's default body.
    const awaited = dispatchStep(&router, .negotiating, .{
        .outcome = .{ .alpn = "/bare" },
    });
    try t.expectEqual(ConnState{ .accepting = with_default.bare() }, awaited.state);
    try t.expectEqual(DispatchAction.await_handshake, awaited.action);
    try t.expectEqual(@as(usize, 0), with_default.on_accepting_calls);

    // With one: the handler is called, and the action names the call rather
    // than the router having made it. Calling it here is what makes the action
    // checkable without a scheduler.
    const called = dispatchStep(&router, .negotiating, .{
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
            const next = dispatchStep(&router, called.state, .{
                .outcome = .{ .connection = connection },
            });
            try t.expectEqual(ConnState{ .handling = handler }, next.state);
            try t.expectEqual(DispatchAction{ .accept = handler }, next.action);
        },
        else => return error.TestUnexpectedResult,
    }
    try t.expectEqual(@as(usize, 0), with_default.on_accepting_calls);
}

test "an accept failure drops the connection and sends no error code" {
    var recorder: Recorder = .{ .accept_error = error.NotAllowed };
    var entries: [1]Entry = undefined;
    const router = try oneHandler("/echo", &entries, &recorder);

    // All the way to a running accept.
    const offered_alpn = dispatchStep(&router, .negotiating, .{
        .outcome = .{ .alpn = "/echo" },
    });
    const handling = dispatchStep(&router, offered_alpn.state, .{
        .outcome = .{ .connection = .{ .ptr = &entries } },
    });
    try t.expectEqual(ConnState{ .handling = recorder.handler() }, handling.state);
    try t.expectEqual(DispatchAction{ .accept = recorder.handler() }, handling.action);

    // And now it fails.
    const failed = dispatchStep(&router, handling.state, .{
        .outcome = .{ .failed = .{ .accept = error.NotAllowed } },
    });
    const drop: Drop = .{ .failed = .{ .accept = error.NotAllowed } };
    try t.expectEqual(ConnState{ .dropped = drop }, failed.state);
    try t.expectEqual(DispatchAction{ .drop = drop }, failed.action);
    // Invariant 19. The connection is dropped, nothing is sent, and the only
    // trace of it is the warning the caller logs for a `.drop`. A handler that
    // wants the peer to know closes the connection itself, before it returns
    // the error — and if someone "fixes" this path into an error code, the two
    // lines below are what fails.
    try t.expectEqual(PeerOutcome.nothing, failed.action.peerOutcome());
    // The refusal is still the one thing that reaches a peer, so the assertion
    // above is not the assertion that every action is silent.
    try t.expectEqual(
        PeerOutcome.refused,
        dispatchStep(&router, .incoming, .{ .filtered = .reject }).action.peerOutcome(),
    );
}

test "a handler that returns cleanly releases the connection" {
    var recorder: Recorder = .{};
    var entries: [1]Entry = undefined;
    const router = try oneHandler("/echo", &entries, &recorder);

    const step = dispatchStep(&router, .{ .handling = recorder.handler() }, .{
        .outcome = .finished,
    });
    try t.expectEqual(ConnState.released, step.state);
    // Released is also a drop of the connection — upstream drops it when the
    // future returns — but not a failure, so it is a different action and no
    // warning goes with it.
    try t.expectEqual(DispatchAction.release, step.action);
    try t.expectEqual(PeerOutcome.nothing, step.action.peerOutcome());
}

test "a failed handshake or a failed on_accepting is a drop with a warning" {
    var recorder: Recorder = .{};
    var entries: [1]Entry = undefined;
    const router = try oneHandler("/echo", &entries, &recorder);

    // The handshake never produced an ALPN.
    const handshake = dispatchStep(&router, .negotiating, .{
        .outcome = .{ .failed = .{ .handshake = error.Connecting } },
    });
    try t.expectEqual(ConnState{ .dropped = .{
        .failed = .{ .handshake = error.Connecting },
    } }, handshake.state);
    try t.expectEqual(PeerOutcome.nothing, handshake.action.peerOutcome());

    // The handler's `on_accepting` failed, which upstream logs under the same
    // line as the default await.
    const accepting = dispatchStep(&router, .{ .accepting = recorder.handler() }, .{
        .outcome = .{ .failed = .{ .accepting = error.MissingRemoteEndpointId } },
    });
    try t.expectEqual(ConnState{ .dropped = .{
        .failed = .{ .accepting = error.MissingRemoteEndpointId },
    } }, accepting.state);
    try t.expectEqual(PeerOutcome.nothing, accepting.action.peerOutcome());
    try t.expectEqual(@as(usize, 0), recorder.accept_calls);
}

test "each live state accepts only the outcome its own stage produces" {
    var recorder: Recorder = .{};
    var entries: [1]Entry = undefined;
    const router = try oneHandler("/echo", &entries, &recorder);

    // `ConnState` order, and the one `Outcome` success arm each state is
    // waiting for. `incoming` owes the filter, not a stage.
    const live = [_]ConnState{
        .incoming,
        .negotiating,
        .{ .accepting = recorder.handler() },
        .{ .handling = recorder.handler() },
    };
    const successes = [_]Outcome{
        .{ .alpn = "/echo" },
        .{ .connection = .{ .ptr = &recorder } },
        .finished,
    };
    // The one failure each state can produce. The other two are out of order
    // for it, which is what stops a handler failure being reported one stage
    // early.
    const failures = [_]Failure{
        .{ .handshake = error.Connecting },
        .{ .accepting = error.NotAllowed },
        .{ .accept = error.Connection },
    };

    for (live, 0..) |state, stage| {
        for (successes, 0..) |outcome, arm| {
            const step = dispatchStep(&router, state, .{ .outcome = outcome });
            // The one stage this state is waiting for moves it on; every other
            // report is a drop that names the event it could not accept.
            if (stage == arm + 1) {
                try t.expect(std.meta.activeTag(step.state) != .dropped);
            } else {
                try t.expectEqual(
                    Drop{ .out_of_order = .{ .outcome = outcome } },
                    step.state.dropped,
                );
            }
        }
        for (failures) |failure| {
            const step = dispatchStep(&router, state, .{
                .outcome = .{ .failed = failure },
            });
            // `failures` is in `ConnState` order minus the state that owes no
            // stage, so the state's own failure is one below its index.
            if (stage > 0 and
                std.meta.activeTag(failure) == std.meta.activeTag(failures[stage - 1]))
            {
                try t.expectEqual(Drop{ .failed = failure }, step.state.dropped);
            } else {
                try t.expectEqual(
                    Drop{ .out_of_order = .{ .outcome = .{ .failed = failure } } },
                    step.state.dropped,
                );
            }
        }
    }
}

test "a terminal connection state absorbs every event" {
    var recorder: Recorder = .{};
    var entries: [1]Entry = undefined;
    const router = try oneHandler("/echo", &entries, &recorder);

    // The first ending is the ending, and a later event does not overwrite the
    // record of it.
    const terminal = [_]ConnState{
        .refused,
        .ignored,
        .released,
        .{ .dropped = .{ .failed = .{ .accept = error.NotAllowed } } },
    };
    const events = [_]ConnEvent{
        .{ .filtered = .accept },
        .{ .filtered = .reject },
        .{ .outcome = .finished },
        .{ .outcome = .{ .failed = .{ .accept = error.NotAllowed } } },
    };
    for (terminal) |state| {
        for (events) |event| {
            const step = dispatchStep(&router, state, event);
            try t.expectEqual(state, step.state);
            try t.expectEqual(DispatchAction.none, step.action);
        }
    }
}

test "the shutdown order is handlers, then cancel, then close" {
    var shutdown = Shutdown.init(2, 3);
    try t.expectEqual(Shutdown.Phase.serving, shutdown.phase);

    // Intake stops, and every handler is told at once.
    const first = shutdown.step(.close_requested);
    try t.expectEqual(Shutdown.Action{ .shutdown_handlers = 2 }, first.action);
    try t.expectEqual(Shutdown.Phase.draining_handlers, first.shutdown.phase);
    shutdown = first.shutdown;

    // The cancel cannot begin while a handler is still shutting down, and
    // neither can the close. These three are the ordering, and each is fed the
    // event that would jump the queue.
    for ([_]Shutdown.Event{ .accepts_cancelled, .endpoint_closed, .close_requested }) |event| {
        const early = shutdown.step(event);
        try t.expectEqual(Shutdown.Action.none, early.action);
        try t.expectEqual(Shutdown.Phase.draining_handlers, early.shutdown.phase);
    }
    // One handler back out of two: still nothing.
    const one = shutdown.step(.handler_finished);
    try t.expectEqual(Shutdown.Action.none, one.action);
    try t.expectEqual(Shutdown.Phase.draining_handlers, one.shutdown.phase);
    try t.expectEqual(@as(usize, 1), one.shutdown.handlers);

    // The last handler, and now the accepts are cancelled.
    const cancel = one.shutdown.step(.handler_finished);
    try t.expectEqual(Shutdown.Action.cancel_accepts, cancel.action);
    try t.expectEqual(Shutdown.Phase.cancelling_accepts, cancel.shutdown.phase);
    try t.expectEqual(@as(usize, 0), cancel.shutdown.handlers);
    // A handler report that arrives after the cancel has nothing to do: there
    // are none left.
    const late = cancel.shutdown.step(.handler_finished);
    try t.expectEqual(Shutdown.Action.none, late.action);
    try t.expectEqual(Shutdown.Phase.cancelling_accepts, late.shutdown.phase);

    // The close cannot begin before the cancellation has landed.
    const too_early = late.shutdown.step(.endpoint_closed);
    try t.expectEqual(Shutdown.Action.none, too_early.action);
    try t.expectEqual(Shutdown.Phase.cancelling_accepts, too_early.shutdown.phase);

    // The cancellation lands, and only now is the endpoint closed.
    const close = late.shutdown.step(.accepts_cancelled);
    try t.expectEqual(Shutdown.Action.close_endpoint, close.action);
    try t.expectEqual(Shutdown.Phase.closing_endpoint, close.shutdown.phase);

    // And the close is what finishes it.
    const closed = close.shutdown.step(.endpoint_closed);
    try t.expectEqual(Shutdown.Action.none, closed.action);
    try t.expectEqual(Shutdown.Phase.closed, closed.shutdown.phase);

    // A second close request is upstream's `Router::shutdown` returning `Ok`
    // when already shut down, not a second shutdown.
    for ([_]Shutdown.Event{
        .close_requested,
        .handler_finished,
        .accept_finished,
        .accepts_cancelled,
        .endpoint_closed,
    }) |event| {
        const again = closed.shutdown.step(event);
        try t.expectEqual(Shutdown.Action.none, again.action);
        try t.expectEqual(Shutdown.Phase.closed, again.shutdown.phase);
    }
}

test "a close with nothing registered still cancels the accepts and closes" {
    // The shape an endpoint over a table with no registrations hands this
    // machine, and the one place the counts have to be read before the phase is
    // chosen. A close that entered `draining_handlers` here would owe a
    // `handler_finished` that nobody can send, and every later event is held
    // while it waits: the accepts are never cancelled and the endpoint is never
    // closed.
    const first = Shutdown.init(0, 0).step(.close_requested);
    try t.expectEqual(Shutdown.Action.cancel_accepts, first.action);
    try t.expectEqual(Shutdown.Phase.cancelling_accepts, first.shutdown.phase);
    try t.expectEqual(@as(usize, 0), first.shutdown.handlers);

    // So the order is reached by the two reports the close still owes, with no
    // handler drain in between to stall in.
    const cancelled = first.shutdown.step(.accepts_cancelled);
    try t.expectEqual(Shutdown.Action.close_endpoint, cancelled.action);
    try t.expectEqual(Shutdown.Phase.closing_endpoint, cancelled.shutdown.phase);
    const closed = cancelled.shutdown.step(.endpoint_closed);
    try t.expectEqual(Shutdown.Phase.closed, closed.shutdown.phase);

    // And accepts that were running are still counted across the cancel, so a
    // caller knows what its cancellation has to account for even though no
    // handler ever reported and the close never waited for one.
    const running = Shutdown.init(0, 2).step(.close_requested);
    try t.expectEqual(Shutdown.Action.cancel_accepts, running.action);
    try t.expectEqual(@as(usize, 2), running.shutdown.accepts);
    try t.expectEqual(@as(usize, 1), running.shutdown.step(.accept_finished).shutdown.accepts);
    try t.expectEqual(@as(usize, 0), running.shutdown.step(.accepts_cancelled).shutdown.accepts);
}

test "an accept finishing counts down and never advances the shutdown" {
    var shutdown = Shutdown.init(1, 2);

    // An accept can finish at any time, including before the shutdown is asked
    // for, and it never moves the machine: upstream's loop takes the finished
    // task from the join set and goes back to its `select!`.
    var step = shutdown.step(.accept_finished);
    try t.expectEqual(Shutdown.Action.none, step.action);
    try t.expectEqual(Shutdown.Phase.serving, step.shutdown.phase);
    try t.expectEqual(@as(usize, 1), step.shutdown.accepts);
    shutdown = step.shutdown;

    step = shutdown.step(.accept_finished);
    try t.expectEqual(@as(usize, 0), step.shutdown.accepts);
    try t.expectEqual(Shutdown.Phase.serving, step.shutdown.phase);
    shutdown = step.shutdown;

    // And after the cancel, including reports past zero: a count that wrapped
    // would read as an enormous number of accepts still running.
    shutdown = shutdown.step(.close_requested).shutdown;
    shutdown = shutdown.step(.handler_finished).shutdown;
    try t.expectEqual(Shutdown.Phase.cancelling_accepts, shutdown.phase);
    for (0..3) |_| {
        const late = shutdown.step(.accept_finished);
        try t.expectEqual(@as(usize, 0), late.shutdown.accepts);
        try t.expectEqual(Shutdown.Phase.cancelling_accepts, late.shutdown.phase);
        shutdown = late.shutdown;
    }
}

test "a lease given up with the endpoint open is reported" {
    // Every phase but the last one is an endpoint nobody closed, and each is
    // reported in the phase it was dropped in, because "you forgot to close"
    // and "you closed in the wrong order" are different bugs.
    const phases = [_]Shutdown.Phase{
        .serving,
        .draining_handlers,
        .cancelling_accepts,
        .closing_endpoint,
    };
    var shutdown = Shutdown.init(1, 1);
    for (phases[0 .. phases.len - 1], phases[1..]) |phase, next_phase| {
        var lease = Lease.acquire(&shutdown);
        try t.expectEqual(Release{ .abandoned = phase }, lease.deinit());
        // On to the next phase by driving the machine, so these are the phases a
        // caller can actually be holding.
        shutdown = switch (next_phase) {
            .draining_handlers => shutdown.step(.close_requested).shutdown,
            .cancelling_accepts => shutdown.step(.close_requested).shutdown
                .step(.handler_finished).shutdown,
            .closing_endpoint => shutdown.step(.close_requested).shutdown
                .step(.handler_finished).shutdown.step(.accepts_cancelled).shutdown,
            // `next_phase` is `phases[1..]`, which holds neither of these.
            .serving, .closed => unreachable,
        };
        try t.expectEqual(next_phase, shutdown.phase);
    }
}

test "a lease given up after the close reports the close, once" {
    var shutdown = Shutdown.init(1, 1);
    var lease = Lease.acquire(&shutdown);

    // The whole shutdown, driven the way the caller has to drive it.
    var step = shutdown.step(.close_requested);
    try t.expectEqual(Shutdown.Action{ .shutdown_handlers = 1 }, step.action);
    step = step.shutdown.step(.handler_finished);
    try t.expectEqual(Shutdown.Action.cancel_accepts, step.action);
    step = step.shutdown.step(.accepts_cancelled);
    try t.expectEqual(Shutdown.Action.close_endpoint, step.action);
    step = step.shutdown.step(.endpoint_closed);
    try t.expectEqual(Shutdown.Phase.closed, step.shutdown.phase);
    shutdown = step.shutdown;

    try t.expectEqual(Release.closed, lease.deinit());
    // The mark is set before the report, so a second exit finds nothing to do
    // and a copy deinited after the original reports the same thing once.
    try t.expectEqual(Release.already_gone, lease.deinit());
    var copy = lease;
    try t.expectEqual(Release.already_gone, copy.deinit());
    // And the copy could not have reported anything else even if it tried: the
    // answer comes out of the shutdown, not out of an argument.
    try t.expectEqual(Shutdown.Phase.closed, shutdown.phase);
}

test "late Retry terminates admission and never reaches a handler" {
    var recorder: Recorder = .{};
    var entries: [1]Entry = undefined;
    const table = try oneHandler("/echo", &entries, &recorder);
    for ([_]Retry{ .source_validation, .cost_imposition }) |meaning| {
        const refused = dispatchStep(&table, .incoming, .{
            .filtered = .{ .retry = meaning },
        });
        try t.expectEqual(ConnState.refused, refused.state);
        try t.expectEqual(DispatchAction.refuse, refused.action);
        // An ALPN completion arriving after refusal cannot resurrect admission.
        const stale = dispatchStep(&table, refused.state, .{
            .outcome = .{ .alpn = "/echo" },
        });
        try t.expectEqual(ConnState.refused, stale.state);
        try t.expectEqual(DispatchAction.none, stale.action);
        try t.expectEqual(@as(usize, 0), recorder.accept_calls);
    }
}
