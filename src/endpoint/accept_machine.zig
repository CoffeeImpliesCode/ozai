//! The accept loop: one event in, one action out, and the two counts a close is
//! built from.
//!
//! Split out of `src/endpoint/endpoint.zig`, which is now the facade over it
//! and two other named modules. The boundary is the state machine itself, and
//! everything that decides is here: `Loop`, the free `spawn` that admits an
//! attempt to the caller's task table or refuses it, and `handlerCount`, which
//! is stated at the only moment both counts can be right. The values it trades
//! in are in `accept_events`, and nothing here opens a socket, reads a clock or
//! takes a runtime.

const std = @import("std");
const router = @import("../router/router.zig");
const filter = @import("incoming_filter.zig");
const accept_events = @import("accept_events.zig");

const Incoming = filter.Incoming;
const IncomingFilter = filter.IncomingFilter;

const Action = accept_events.Action;
const Event = accept_events.Event;
const Reaped = accept_events.Reaped;
const Step = accept_events.Step;
const Task = accept_events.Task;

/// The accept loop.
///
/// Every field is the caller's and the machine holds none of it: `router` points
/// at the table the caller built, `tasks` is the caller's storage, and `shutdown`
/// is the router's own machine. Nothing here reads a clock, a socket or the
/// environment, so a test drives a whole connection — and a whole shutdown —
/// with no runtime at all.
///
/// **One thread steps a loop, and the caller keeps it.** `step` takes the loop
/// by value and hands the next one back, so the caller is the one assigning it
/// — and `acquire`'s lease reads through *this* loop's `shutdown`, so a loop
/// copied somewhere else while a lease is held leaves the lease watching a
/// machine nobody is driving. There is no lock in this struct and no atomic, so
/// two threads stepping one loop is a data race with a deterministic-looking
/// answer, which is the worst kind.
///
/// **`tasks` is the caller's storage and must outlive the loop**, and so must
/// the table in `router` and any `incoming_filter`'s own context: the loop
/// holds pointers into all three and reads them on every step.
pub const Loop = struct {
    /// The table an attempt is dispatched through, and the table whose
    /// registration order the ALPNs were offered in. The caller's.
    router: *const router.Router,
    /// Upstream holds the filter by the loop rather than by the router
    /// (`protocol.rs:106-111`), because the loop is what runs it. Null is
    /// upstream's `None`, and every attempt is accepted.
    incoming_filter: ?IncomingFilter,
    /// The accept tasks being held, over storage the caller owns and never
    /// grows. Upstream's `JoinSet` (`:524`) is unbounded; this is not, and
    /// `spawn` says what a full one does.
    tasks: []Task,
    /// How many of `tasks` are live. The table is dense — a reaped task's slot
    /// is reused — so this is a count and not a bitmap.
    live: usize,
    /// The attempt the filter is being asked about. The filter is application
    /// code, so its answer arrives as an event and the attempt has to be
    /// somewhere while it waits. Null whenever the loop owes no filter, which is
    /// how an attempt is acted on once: upstream's four answers each consume the
    /// `Incoming` (`connection.rs:148`, `:175`, `:185`, `:192`).
    pending: ?Incoming,
    /// The shutdown. `router.Shutdown` is the whole of it, so the ordering
    /// cannot drift from the router's.
    shutdown: router.Shutdown,

    /// A loop over a table, a filter that may be absent, and a task table the
    /// caller sizes. The two counts are stated here and restated at the close,
    /// which is the only moment both can be right — see `beginShutdown`.
    /// **A table with no registrations is a legitimate endpoint, not an empty
    /// one.** Its `handlers` count is zero and its close therefore owes no
    /// handler at all, which `router.Shutdown` answers on the first step rather
    /// than waiting for a `handler_finished` nobody can send. An attempt that
    /// arrives is offered to the filter and, with no filter, accepted; it then
    /// spawns a task that the dispatch drops, saying nothing to the peer, because
    /// no ALPN claims it (`protocol.rs:653-656`). The close still reaches
    /// `closed`.
    pub fn init(
        router_table: *const router.Router,
        incoming_filter: ?IncomingFilter,
        tasks: []Task,
    ) Loop {
        return .{
            .router = router_table,
            .incoming_filter = incoming_filter,
            .tasks = tasks,
            .live = 0,
            .pending = null,
            .shutdown = router.Shutdown.init(handlerCount(router_table), 0),
        };
    }

    /// The only way to hold the report of whether this endpoint was closed, and
    /// **opting in is the caller's decision: `init` is public and every `Loop`
    /// field is public, so a loop can be built, driven and dropped without ever
    /// calling this, and Zig raises nothing.** A loop discarded without a lease
    /// is not reported, so this is not the only way to hold an endpoint — it is
    /// the only way to find out afterwards whether it was closed.
    ///
    /// Upstream logs an error from `EndpointInner`'s `Drop` when `close()` was
    /// never called — "Endpoint dropped without calling `Endpoint::close`.
    /// Aborting ungracefully" (`iroh/src/socket.rs:220-230`) — so dropping an
    /// endpoint without closing is a misuse and not a cleanup. Zig has no
    /// `Drop`, so the report moves to a handle whose
    /// `deinit` is the single exit — and that handle is `router.Lease`, the same
    /// shape as `Clients.OnDisconnectGuard` in `relay/server.zig`, already
    /// specialised to the thing this endpoint has to report, which is a phase of
    /// the shutdown. It is not written again here: the lease reads the very
    /// `Shutdown` this loop drives, and a third copy of a struct with a
    /// `reported` flag would be a second place for two answers to disagree.
    ///
    /// The report itself is `router.Lease.deinit`'s: `.closed` is the one good
    /// answer, `.abandoned` names the phase the loop was left in, and
    /// `.already_gone` is what a second copy of the lease says.
    ///
    /// The loop must not be copied elsewhere while a lease is held, because the
    /// lease reads through this one. Upstream's promise has the same shape and
    /// the same discipline.
    pub fn acquire(self: *Loop) router.Lease {
        return router.Lease.acquire(&self.shutdown);
    }

    /// The accept task for `id`, for the caller to drive. Null when there is
    /// none: before it was spawned, or after it was reaped.
    pub fn task(self: *Loop, id: u64) ?*Task {
        const index = self.indexOf(id) orelse return null;
        return &self.tasks[index];
    }

    /// One step. Pure, and the whole of the loop.
    ///
    /// Every event is named in every phase, so an event added later has to be
    /// classified here rather than absorbed by a wildcard and never reaching the
    /// phase that owed it.
    ///
    /// **One step, one action, one answer.** The caller performs the action and
    /// feeds the event the loop owes back in — `Event`'s own docs say which is
    /// which — and the loop is pure in between, so the same state and the same
    /// event always give the same action. A copy made before the assignment and
    /// kept past it is two loops sharing one task table.
    pub fn step(self: Loop, event: Event) Step {
        return switch (self.shutdown.phase) {
            .serving => self.serving(event),
            // Once the shutdown has begun, every event belongs to the router's
            // machine, which already names each one in each phase
            // (`router.zig:744-787`).
            .draining_handlers,
            .cancelling_accepts,
            .closing_endpoint,
            .closed,
            => self.draining(event),
        };
    }

    /// Intake: upstream's `select!` body, one arm at a time.
    fn serving(self: Loop, event: Event) Step {
        return switch (event) {
            .arrived => |incoming| blk: {
                // An attempt the filter has not answered yet holds the slot. A
                // second arrival is a state upstream's loop cannot be in — it
                // asks its filter about one datagram before it accepts the next
                // — and dropping the attempt that is pending would be a policy
                // invented here, so the new one is not taken. The caller owes
                // the answer first; `Event.arrived` is where that is stated.
                if (self.pending != null) break :blk self.hold();
                var next = self;
                next.pending = incoming;
                break :blk .{ .loop = next, .action = .{ .offer = incoming } };
            },
            .filtered => |answer| self.filtered(answer),
            .reaped => |ended| self.reaped(ended),
            .close_requested => self.beginShutdown(null),
            // Nothing has been asked for yet, and a report from a phase the loop
            // has not entered is not this one's business.
            .handler_finished, .accepts_cancelled, .endpoint_closed => self.hold(),
        };
    }

    /// The filter answered: upstream's four endings and one continuation
    /// (`protocol.rs:573-604`), the continuation being a spawn.
    fn filtered(self: Loop, answer: filter.Answer) Step {
        // A verdict for an attempt the loop is not holding is not this filter's
        // business. Upstream cannot express it: the answer comes from the same
        // call that consumed the attempt.
        const pending = self.pending orelse return self.hold();
        var next = self;
        next.pending = null;
        // The endpoint's two edits to a verdict live in `decide` — the path says
        // what a retry is worth, the flow says whether it can be given one — and
        // what the router then owes is its own answer.
        const routed = router.dispatchStep(
            self.router,
            .incoming,
            .{ .filtered = filter.decide(answer, pending) },
        );
        return switch (routed.action) {
            .negotiate_alpn => spawn(next, pending.id),
            // A retry the endpoint cannot answer with a token is upstream's
            // `Err` arm: `incoming.retry()` did not happen, so the attempt is
            // refused (`protocol.rs:583-586`). The payload the router carried
            // is dropped here because nothing this loop can do reads it back.
            .send_retry => .{ .loop = next, .action = .refuse },
            .refuse => .{ .loop = next, .action = .refuse },
            .ignore => .{ .loop = next, .action = .ignore },
            // A verdict cannot produce anything else: in the `incoming` state
            // the router owes exactly the four actions above
            // (`router.zig:539-553`).
            .on_accepting, .accept, .await_handshake, .release, .drop, .none => next.hold(),
        };
    }

    /// One task came back. Upstream's `join_next` arms (`:545-566`): three
    /// endings carry on and one runs the shutdown.
    fn reaped(self: Loop, ended: Reaped) Step {
        if (self.indexOf(ended.id) == null) return self.hold();
        const next = self.forget(ended.id);
        if (ended.ended == .panicked) return next.beginShutdown(ended);
        return next.hold();
    }

    /// Every event once the shutdown has begun, mapped onto the router's
    /// machine. A reap still frees its slot in every phase: upstream's join set
    /// keeps yielding through the shutdown and is drained at the end
    /// (`:617-622`), and a task the loop counts must not be counted for ever.
    fn draining(self: Loop, event: Event) Step {
        // Named so the arms below are one type rather than four inferred ones: a
        // bare enum literal inside an inferred struct is inferred per arm.
        const Mapped = struct {
            shutdown_event: router.Shutdown.Event,
            loop: Loop,
        };
        const mapped: Mapped = switch (event) {
            .reaped => |ended| .{
                .shutdown_event = .accept_finished,
                .loop = self.forget(ended.id),
            },
            // Intake and the filter have ended. Upstream is no longer calling
            // `endpoint.accept()`, so a datagram arriving now is not accepted,
            // and an answer to a question no longer being asked is not acted on.
            // Both leave the peer with nothing, like every other local ending.
            .arrived, .filtered => return self.hold(),
            .close_requested => .{ .shutdown_event = .close_requested, .loop = self },
            .handler_finished => .{ .shutdown_event = .handler_finished, .loop = self },
            .accepts_cancelled => .{ .shutdown_event = .accepts_cancelled, .loop = self },
            .endpoint_closed => .{ .shutdown_event = .endpoint_closed, .loop = self },
        };
        var next = mapped.loop;
        const shutdown = next.shutdown.step(mapped.shutdown_event);
        next.shutdown = shutdown.shutdown;
        const action: Action = switch (shutdown.action) {
            .none => .none,
            else => |router_owed| .{ .shutdown = .{ .action = router_owed, .panicked = null } },
        };
        return .{ .loop = next, .action = action };
    }

    /// The one way out of serving: upstream's `break` (`:541`, `:551-556`,
    /// `:569-571`) and then `protocols.shutdown().await` (`:609`).
    ///
    /// The router's machine counts the handlers and the accepts it was told
    /// about when it was made and takes them down one report at a time, and the
    /// loop is the only thing that knows how many accepts are running. So both
    /// counts are stated here, at the only moment the two can be right: a
    /// shutdown that is still serving has decided nothing, so restating its
    /// counts cannot lose an ordering.
    fn beginShutdown(self: Loop, cause: ?Reaped) Step {
        var next = self;
        // Upstream's `break` drops whatever the loop was holding, and the one
        // thing it is holding here is the attempt the filter was being asked
        // about. The peer learns nothing, exactly as for every other local
        // ending.
        next.pending = null;
        next.shutdown = router.Shutdown.init(handlerCount(self.router), self.live);
        const shutdown = next.shutdown.step(.close_requested);
        next.shutdown = shutdown.shutdown;
        return .{
            .loop = next,
            .action = .{ .shutdown = .{ .action = shutdown.action, .panicked = cause } },
        };
    }

    /// No step. Absorbing an event that does not apply here is the point: the
    /// ordering lives in which event advances which phase, and an event that
    /// advances nothing is the ordering holding.
    fn hold(self: Loop) Step {
        return .{ .loop = self, .action = .none };
    }

    fn indexOf(self: *const Loop, id: u64) ?usize {
        var index: usize = 0;
        while (index < self.live) : (index += 1) {
            if (self.tasks[index].id == id) return index;
        }
        return null;
    }

    /// One task's slot, freed, and the count down. Absorbs a reap for a task the
    /// loop is not holding: the id is the core's and never reused, so a reap for
    /// one the loop never took is a caller's bookkeeping error, and the honest
    /// answer is the state the caller already has.
    fn forget(self: Loop, id: u64) Loop {
        const index = self.indexOf(id) orelse return self;
        var next = self;
        // The table is dense, so the last task fills the hole: a bounded scan per
        // reap and no free list to keep in step with the count.
        //
        // `indexOf` names a slot only when the table holds one, so `live` is
        // already positive — but that proof is inside the scan and the read is
        // here, so the bound is restated in the expression the read sits in.
        // An empty table has no last task to move, and removing from one is
        // then the no-op the count already says it is.
        if (next.live > 0) {
            next.tasks[index] = next.tasks[next.live - 1];
            next.live -= 1;
        }
        return next;
    }
};

/// Hold an accept task for an attempt, or refuse it if the table is full.
///
/// Upstream's `join_set.spawn` (`protocol.rs:601-603`) spawns a future that
/// starts by awaiting the handshake, which is the router's `negotiating` state
/// and so the state the task is born in.
///
/// A table with no room refuses the connection, and that is a departure worth
/// naming: upstream's `JoinSet` is unbounded and never runs out, so upstream
/// never has to make this choice. Here the alternative is worse, because an
/// attempt that is accepted and then has nowhere to be held is a peer that
/// believes it is connected and is not. Refusing is also what the core does at
/// its own capacity (`vendor/quic/src/quic/connection_manager.zig:602-604`), and
/// a client answered with nothing waits for a timeout that cannot arrive.
fn spawn(next: Loop, id: u64) Step {
    if (next.live == next.tasks.len) return .{ .loop = next, .action = .refuse };
    var spawned = next;
    spawned.tasks[spawned.live] = .{ .id = id, .state = .negotiating };
    spawned.live += 1;
    return .{
        .loop = spawned,
        .action = .{ .spawn = spawned.tasks[spawned.live - 1] },
    };
}

/// How many `shutdown` calls a close owes.
///
/// Upstream awaits one future per *map value* (`protocol.rs:404-407`), and a
/// map holds one value per ALPN: a handler registered twice is shut down once,
/// as the newer one, because the older one is unreachable
/// (`protocol.rs:385-394`, which `router.Builder.push` reproduces). So the count
/// is the number of distinct ALPNs in the table.
///
/// It is counted here rather than read from the router because the router
/// exposes its entries and not the count, and the count is load-bearing in both
/// directions: one too high waits for a `handler_finished` that never comes, and
/// one too low cancels the accepts while a handler is still using the
/// connections its own `accept` is holding.
///
/// **Zero is a real answer.** A table with no registrations hands back a
/// `Shutdown` that owes no handler, and `router.Shutdown` takes that as the
/// cancel being owed immediately — so a caller must not read zero as "wait for
/// a report" and must not hold the close back for one.
pub fn handlerCount(router_table: *const router.Router) usize {
    var distinct: usize = 0;
    for (router_table.entries, 0..) |entry, index| {
        var first = true;
        for (router_table.entries[0..index]) |earlier| {
            if (std.mem.eql(u8, earlier.alpn, entry.alpn)) {
                first = false;
                break;
            }
        }
        if (first) distinct += 1;
    }
    return distinct;
}

/// One attempt through the filter: the two steps a caller takes to get past
/// `.offer`, which is upstream's `filter(&incoming)` (`protocol.rs:574`). Both
/// states are written back, because the loop a caller keeps is the one the
/// filter was asked about.
fn offer(loop: *Loop, incoming: Incoming) !Step {
    const arrived = loop.step(.{ .arrived = incoming });
    try t.expectEqual(Action{ .offer = incoming }, arrived.action);
    loop.* = arrived.loop;
    const answered = loop.step(.{
        .filtered = filter.ask(loop.incoming_filter, arrived.action.offer),
    });
    loop.* = answered.loop;
    return answered;
}

/// The shutdown action a step owes, or null when the step owes no shutdown. It
/// keeps the tests about the ordering from being about the wrapper.
fn owed(action: Action) ?router.Shutdown.Action {
    return switch (action) {
        .shutdown => |shutdown| shutdown.action,
        .offer, .spawn, .refuse, .ignore, .none => null,
    };
}

/// How many of the loop's live slots hold `id`. The count cannot see a task
/// that was moved out of the window, so a duplicate *inside* the window is a
/// table that is not dense, and that is what this is asked about.
fn countHeld(loop: *const Loop, id: u64) usize {
    var held: usize = 0;
    for (loop.tasks[0..loop.live]) |task| {
        if (task.id == id) held += 1;
    }
    return held;
}

/// Calls a handler's `accept`, which is the one long-lived call the loop names
/// and the caller performs.
fn runAccept(
    handler: router.ProtocolHandler,
    connection: router.Connection,
) router.AcceptError!void {
    return handler.accept(handler.ptr, connection);
}

const t = std.testing;

// The stand-ins a caller supplies, named here so the tests below stand as they
// were written.
const Validation = filter.Validation;

const accept_fixture = @import("accept_fixture.zig");
const Handler = accept_fixture.Handler;
const oneHandler = accept_fixture.oneHandler;
const Recorder = accept_fixture.Recorder;
const Proving = accept_fixture.Proving;
const direct = accept_fixture.direct;
const relayed = accept_fixture.relayed;
const withToken = accept_fixture.withToken;

test "a connection is offered to the filter and then dispatched" {
    var handler: Handler = .{};
    var entries: [1]router.Entry = undefined;
    const table = try oneHandler("/echo", &entries, &handler);
    var recorder: Recorder = .{ .answer = .accept };
    var tasks: [1]Task = undefined;
    var loop = Loop.init(&table, recorder.filterer(), &tasks);

    // Upstream takes the attempt from `endpoint.accept()` and asks the filter
    // about it, and the filter saw the attempt whole.
    const step = try offer(&loop, direct(1));
    try t.expectEqual(@as(usize, 1), recorder.calls);
    try t.expectEqual(direct(1), recorder.asked.?);

    // An accepted attempt becomes a task that owes the handshake, and the loop
    // holds it: this is the connection the caller now drives.
    try t.expectEqual(Task{ .id = 1, .state = .negotiating }, step.action.spawn);
    try t.expectEqual(@as(usize, 1), step.loop.live);
    // Nothing was told to the peer and no handler ran: an accepted attempt is a
    // handshake that has not finished.
    try t.expectEqual(router.PeerOutcome.nothing, Action.peerOutcome(step.action));
    try t.expectEqual(@as(usize, 0), handler.accept_calls);
    loop = step.loop;
    // One lookup names the task for the rest of the walk: `Loop` is copied by
    // value, but the table it points at is the caller's own array and is not
    // moved, so the pointer stays the pointer the loop would hand back.
    const held = loop.task(1) orelse return error.TestUnexpectedResult;
    try t.expectEqual(Task{ .id = 1, .state = .negotiating }, held.*);

    // The handshake produces the ALPN the peer negotiated, which is what finds
    // the handler, and the handler takes the connection over.
    var routed = router.dispatchStep(&table, held.state, .{
        .outcome = .{ .alpn = "/echo" },
    });
    held.state = routed.state;
    try t.expectEqual(router.ConnState{ .accepting = handler.handler() }, held.state);
    try t.expectEqual(router.DispatchAction{ .on_accepting = handler.handler() }, routed.action);

    // `on_accepting` is the handler's early take-over, and the caller runs it,
    // because the loop names the call the way the router does. Its answer is
    // the connection the next step is owed.
    const handler_table = routed.action.on_accepting;
    const takeover = handler_table.on_accepting orelse return error.TestUnexpectedResult;
    const connection = try takeover(handler_table.ptr, .{ .ptr = &entries });
    try t.expectEqual(@as(usize, 1), handler.on_accepting_calls);
    try t.expectEqual(@as(usize, 0), handler.accept_calls);

    routed = router.dispatchStep(&table, held.state, .{
        .outcome = .{ .connection = connection },
    });
    held.state = routed.state;
    try t.expectEqual(router.DispatchAction{ .accept = handler.handler() }, routed.action);

    // The handler runs it. Upstream runs it on a task and it may be long-lived;
    // here the caller runs it, which is the difference the whole file is about.
    try runAccept(routed.action.accept, .{ .ptr = &entries });
    try t.expectEqual(@as(usize, 1), handler.accept_calls);

    // It returns, the connection goes back to the endpoint, and the task comes
    // back to the loop.
    const finished = router.dispatchStep(&table, held.state, .{
        .outcome = .finished,
    });
    try t.expectEqual(router.DispatchAction.release, finished.action);
    const reaped = loop.step(.{ .reaped = .{ .id = 1, .ended = .finished } });
    try t.expectEqual(Action.none, reaped.action);
    loop = reaped.loop;
    try t.expectEqual(@as(usize, 0), loop.live);
    try t.expect(loop.task(1) == null);
}

test "the filter's four answers, and what each one does to the loop" {
    var handler: Handler = .{};
    var entries: [1]router.Entry = undefined;
    const table = try oneHandler("/echo", &entries, &handler);
    const cases = [_]struct { answer: filter.Answer, action: Action, peer: router.PeerOutcome }{
        // The handshake is owed and a task is held. Nothing reaches a peer.
        .{
            .answer = .accept,
            .action = .{ .spawn = .{ .id = 1, .state = .negotiating } },
            .peer = .nothing,
        },
        // A retry is a refusal, and that is the surprise worth a row of its
        // own: the token cannot be sent, so the peer is told the connection is
        // refused rather than left to time out. It reads the same as the
        // reject below because it does the same thing, not because the two
        // answers are one.
        .{ .answer = .retry, .action = .refuse, .peer = .refused },
        // The one verdict a peer is told about.
        .{ .answer = .reject, .action = .refuse, .peer = .refused },
        // Silence.
        .{ .answer = .ignore, .action = .ignore, .peer = .nothing },
    };
    try t.expectEqual(@as(usize, 4), cases.len);

    for (cases) |want| {
        var recorder: Recorder = .{ .answer = want.answer };
        var tasks: [1]Task = undefined;
        var loop = Loop.init(&table, recorder.filterer(), &tasks);
        const step = try offer(&loop, direct(1));

        try t.expectEqual(@as(usize, 1), recorder.calls);
        try t.expectEqual(want.action, step.action);
        try t.expectEqual(want.peer, Action.peerOutcome(step.action));
        // Only an accepted attempt is a connection: the other three leave no
        // task behind, and the slot is free for the next one.
        const held: usize = if (want.answer == .accept) 1 else 0;
        try t.expectEqual(held, step.loop.live);
        try t.expectEqual(@as(?Incoming, null), step.loop.pending);
    }
}

test "a retry cannot be sent, so it ends in a refusal on either path" {
    var handler: Handler = .{};
    var entries: [2]router.Entry = undefined;
    var builder = router.Builder.init(&entries);
    _ = try builder.accept("/echo", handler.handler());
    _ = try builder.accept("/blob", handler.handler());
    const table = builder.build();

    // The direct path, and a filter that wants the address proved first. The
    // first attempt proves nothing, so the filter asks for a token — and the
    // core has no hook to send one with, so the attempt is refused and the peer
    // is told.
    var proving: Proving = .{};
    var tasks: [1]Task = undefined;
    var loop = Loop.init(&table, proving.filterer(), &tasks);
    var step = try offer(&loop, direct(1));
    try t.expectEqual(Action.refuse, step.action);
    try t.expectEqual(router.PeerOutcome.refused, Action.peerOutcome(step.action));
    try t.expectEqual(@as(usize, 0), step.loop.live);

    // The second attempt on that flow carries the token the first one was sent.
    // What the core proved on a direct path is an address: this filter is
    // satisfied and the connection is in.
    const proved_direct = withToken(direct(1));
    try t.expectEqual(Validation{ .validated = direct(1).remote }, proved_direct.validation);
    step = try offer(&loop, proved_direct);
    try t.expectEqual(Task{ .id = 1, .state = .negotiating }, step.action.spawn);
    try t.expectEqual(@as(usize, 1), step.loop.live);
    // Two attempts, and the filter has been asked twice.
    try t.expectEqual(@as(usize, 2), proving.calls);
    loop = step.loop;

    // The relay path, and the same filter, is refused exactly as the direct one
    // was: what the endpoint cannot do is the same on both, so it cannot tell a
    // peer two different things about it.
    var relayed_proving: Proving = .{};
    var relay_tasks: [1]Task = undefined;
    var relay_loop = Loop.init(&table, relayed_proving.filterer(), &relay_tasks);
    step = try offer(&relay_loop, relayed(1));
    try t.expectEqual(Action.refuse, step.action);
    try t.expectEqual(router.PeerOutcome.refused, Action.peerOutcome(step.action));
    try t.expectEqual(@as(usize, 0), step.loop.live);

    // The second attempt on a relay path carries the token the first one was
    // sent, and what the core proved there is not an address: the relay vouched
    // for the origin before the endpoint saw the datagram, so the flow has
    // proved only that the client cooperated. The same filter is therefore
    // asked again, and QUIC allows one Retry per flow, so the endpoint refuses
    // — which is what it now does with every retry.
    const proved_relay = withToken(relayed(1));
    try t.expectEqual(Validation.cooperated, proved_relay.validation);
    step = try offer(&relay_loop, proved_relay);
    try t.expectEqual(Action.refuse, step.action);
    try t.expectEqual(router.PeerOutcome.refused, Action.peerOutcome(step.action));
    try t.expectEqual(@as(usize, 0), step.loop.live);
    try t.expectEqual(@as(usize, 2), relayed_proving.calls);

    // So the same verb, the same filter and the same core bit, and the one
    // difference the two meanings still make is the state the filter reads next:
    // the direct path reaches the state its filter wants and the relay path
    // cannot, whatever the endpoint does with the verdict. A filter that
    // collapsed the two would let a relayed peer in on the strength of a token
    // that proved nothing.
    try t.expect(proving.asks(proved_direct) == .accept);
    try t.expect(relayed_proving.asks(proved_relay) == .retry);
}

test "a failing accept drops the connection and sends no error code" {
    var handler: Handler = .{ .accept_error = error.NotAllowed };
    var entries: [1]router.Entry = undefined;
    const table = try oneHandler("/echo", &entries, &handler);
    var tasks: [1]Task = undefined;
    var loop = Loop.init(&table, null, &tasks);

    // All the way to a running accept.
    const step = try offer(&loop, direct(1));
    loop = step.loop;
    const negotiated = router.dispatchStep(&table, step.action.spawn.state, .{
        .outcome = .{ .alpn = "/echo" },
    });
    const running = router.dispatchStep(&table, negotiated.state, .{
        .outcome = .{ .connection = .{ .ptr = &entries } },
    });
    try t.expectEqual(router.ConnState{ .accepting = handler.handler() }, negotiated.state);
    try t.expectEqual(router.ConnState{ .handling = handler.handler() }, running.state);
    try t.expectEqual(router.DispatchAction{ .accept = handler.handler() }, running.action);

    // The handler runs it and it fails. Upstream drops the connection and logs a
    // warning, and sends no error code at all — "no dedicated error code will be
    // sent to the peer, so it's recommended to explicitly close the connection
    // within your accept handler" (`protocol.rs:262-268`). A handler that wants
    // the peer to know calls `close` itself, before returning the error.
    try t.expectError(
        error.NotAllowed,
        runAccept(running.action.accept, .{ .ptr = &entries }),
    );
    const drop: router.Drop = .{ .failed = .{ .accept = error.NotAllowed } };
    const failed = router.dispatchStep(&table, running.state, .{
        .outcome = .{ .failed = .{ .accept = error.NotAllowed } },
    });
    try t.expectEqual(router.ConnState{ .dropped = drop }, failed.state);
    try t.expectEqual(router.DispatchAction{ .drop = drop }, failed.action);
    try t.expectEqual(router.PeerOutcome.nothing, failed.action.peerOutcome());

    // The loop's half of it: the task comes back, its slot is freed, and the
    // only thing the loop owes is the count. No packet and no code, so if
    // someone "fixes" this path into an error code, the two lines below are
    // what fail.
    const reaped = loop.step(.{ .reaped = .{ .id = 1, .ended = .finished } });
    try t.expectEqual(Action.none, reaped.action);
    try t.expectEqual(router.PeerOutcome.nothing, Action.peerOutcome(reaped.action));
    try t.expectEqual(@as(usize, 0), reaped.loop.live);
    // And the one verdict that does reach a peer is still a refusal, so the
    // assertion above is not the assertion that every ending is silent.
    try t.expectEqual(router.PeerOutcome.refused, Action.peerOutcome(.refuse));
}

test "several accept tasks are held at once and torn down in the router's order" {
    // Three ALPNs, so three handlers to drain, and three attempts, so three
    // accepts to cancel. The two counts are separate and both are load-bearing.
    var first: Handler = .{};
    var second: Handler = .{};
    var third: Handler = .{};
    var entries: [3]router.Entry = undefined;
    var builder = router.Builder.init(&entries);
    _ = try builder.accept("/one", first.handler());
    _ = try builder.accept("/two", second.handler());
    _ = try builder.accept("/three", third.handler());
    const table = builder.build();

    var tasks: [3]Task = undefined;
    var loop = Loop.init(&table, null, &tasks);
    try t.expectEqual(@as(usize, 3), loop.shutdown.handlers);

    // Three live accepts at once, which is what makes the ordering matter: a
    // handler's `shutdown` closes connections that its own `accept` is using.
    for (1..4) |id| {
        const step = try offer(&loop, direct(@intCast(id)));
        loop = step.loop;
        try t.expectEqual(@as(usize, id), loop.live);
        try t.expect(loop.task(@intCast(id)) != null);
    }

    // The close. Upstream breaks out of the loop and then runs three statements
    // whose order is the whole of the shutdown.
    var step = loop.step(.close_requested);
    loop = step.loop;
    try t.expectEqual(
        router.Shutdown.Action{ .shutdown_handlers = 3 },
        owed(step.action).?,
    );
    try t.expectEqual(@as(?Reaped, null), step.action.shutdown.panicked);
    try t.expectEqual(router.Shutdown.Phase.draining_handlers, loop.shutdown.phase);
    // The accepts are all still running, and the loop says how many: cancelling
    // them now would cut a graceful close in half.
    try t.expectEqual(@as(usize, 3), loop.live);
    try t.expectEqual(@as(usize, 3), loop.shutdown.accepts);

    // Neither the cancel nor the close can be emitted while a handler drains, and
    // each of the three events that would jump the queue is fed here.
    const jumping = [_]Event{ .accepts_cancelled, .endpoint_closed, .close_requested };
    for (jumping) |early| {
        const held = loop.step(early);
        try t.expectEqual(router.Shutdown.Action.none, owed(held.action) orelse .none);
        try t.expectEqual(router.Shutdown.Phase.draining_handlers, held.loop.shutdown.phase);
    }
    // One handler of three back out: still nothing owed.
    step = loop.step(.handler_finished);
    loop = step.loop;
    try t.expectEqual(router.Shutdown.Action.none, owed(step.action) orelse .none);
    try t.expectEqual(@as(usize, 2), loop.shutdown.handlers);

    // A task finishing in the middle of the drain counts down and advances
    // nothing: upstream takes it out of the set and goes back to the `select!`.
    step = loop.step(.{ .reaped = .{ .id = 2, .ended = .cancelled } });
    loop = step.loop;
    try t.expectEqual(router.Shutdown.Action.none, owed(step.action) orelse .none);
    try t.expectEqual(@as(usize, 2), loop.live);
    try t.expectEqual(@as(usize, 2), loop.shutdown.accepts);
    try t.expect(loop.task(2) == null);

    // Two of three handlers are back, and a task went with them. Still nothing:
    // the count decides, not how many reports have gone by.
    step = loop.step(.handler_finished);
    loop = step.loop;
    try t.expectEqual(router.Shutdown.Action.none, owed(step.action) orelse .none);
    try t.expectEqual(@as(usize, 1), loop.shutdown.handlers);

    // The last handler, and only now are the accepts cancelled.
    step = loop.step(.handler_finished);
    loop = step.loop;
    try t.expectEqual(router.Shutdown.Action.cancel_accepts, owed(step.action).?);
    try t.expectEqual(router.Shutdown.Phase.cancelling_accepts, loop.shutdown.phase);
    // The two accepts still running are what the cancel is for, and the one that
    // was reaped mid-drain is not counted any more.
    try t.expectEqual(@as(usize, 2), loop.live);
    try t.expectEqual(@as(usize, 0), loop.shutdown.handlers);
    // The close cannot come before the cancellation has landed.
    const too_early = loop.step(.endpoint_closed);
    try t.expectEqual(router.Shutdown.Action.none, owed(too_early.action) orelse .none);
    try t.expectEqual(router.Shutdown.Phase.cancelling_accepts, too_early.loop.shutdown.phase);

    // The cancellation lands, and only now is the endpoint closed.
    const closing = loop.step(.accepts_cancelled);
    loop = closing.loop;
    try t.expectEqual(router.Shutdown.Action.close_endpoint, owed(closing.action).?);
    try t.expectEqual(router.Shutdown.Phase.closing_endpoint, loop.shutdown.phase);

    // Upstream's `abort_all` drain: a task still reports, the loop still counts
    // it down, and nothing else is owed.
    const drained = loop.step(.{ .reaped = .{ .id = 1, .ended = .cancelled } });
    loop = drained.loop;
    try t.expectEqual(Action.none, drained.action);
    try t.expectEqual(@as(usize, 1), loop.live);

    // And the close is what finishes it.
    const closed = loop.step(.endpoint_closed);
    loop = closed.loop;
    try t.expectEqual(Action.none, closed.action);
    try t.expectEqual(router.Shutdown.Phase.closed, loop.shutdown.phase);
    // An attempt arriving after the close is not accepted: upstream is no longer
    // asking `endpoint.accept()`.
    const late = loop.step(.{ .arrived = direct(9) });
    try t.expectEqual(Action.none, late.action);
}

test "an endpoint with nothing registered still cancels its accepts and closes" {
    // The shape `handlerCount` answers zero for, and the one place a loop has to
    // be right about a close that owes no handler at all. Entering
    // `draining_handlers` here would wait for a `handler_finished` the loop can
    // never be given, and every event after it is held while it waits.
    var entries: [1]router.Entry = undefined;
    var builder = router.Builder.init(&entries);
    const table = builder.build();
    try t.expectEqual(@as(usize, 0), handlerCount(&table));

    var tasks: [1]Task = undefined;
    var loop = Loop.init(&table, null, &tasks);
    try t.expectEqual(@as(usize, 0), loop.shutdown.handlers);
    try t.expectEqual(router.Shutdown.Phase.serving, loop.shutdown.phase);

    // One attempt, offered and answered with no filter to ask. It is accepted
    // and dispatched, and the dispatch finds no ALPN to send it to — upstream
    // warns and returns there, and the peer is told nothing
    // (`protocol.rs:653-656`).
    var step = try offer(&loop, direct(1));
    loop = step.loop;
    try t.expectEqual(router.Shutdown.Phase.serving, loop.shutdown.phase);
    try t.expectEqual(@as(usize, 1), loop.live);

    // The close, and the whole of it in the two reports it owes: with no
    // handler there is no drain to wait on, so the cancel is the first thing
    // the close asks for.
    step = loop.step(.close_requested);
    loop = step.loop;
    try t.expectEqual(router.Shutdown.Action.cancel_accepts, owed(step.action).?);
    try t.expectEqual(router.Shutdown.Phase.cancelling_accepts, loop.shutdown.phase);
    // The accept the table could not dispatch is still running, and the cancel
    // is what reaps it.
    try t.expectEqual(@as(usize, 1), loop.live);
    try t.expectEqual(@as(usize, 1), loop.shutdown.accepts);

    step = loop.step(.{ .reaped = .{ .id = 1, .ended = .cancelled } });
    loop = step.loop;
    try t.expectEqual(Action.none, step.action);
    try t.expectEqual(@as(usize, 0), loop.live);

    // And the endpoint closes, reached without a single handler report anywhere
    // in the walk.
    step = loop.step(.accepts_cancelled);
    loop = step.loop;
    try t.expectEqual(router.Shutdown.Action.close_endpoint, owed(step.action).?);
    try t.expectEqual(router.Shutdown.Phase.closing_endpoint, loop.shutdown.phase);
    step = loop.step(.endpoint_closed);
    loop = step.loop;
    try t.expectEqual(Action.none, step.action);
    try t.expectEqual(router.Shutdown.Phase.closed, loop.shutdown.phase);

    // So the lease reports the close rather than an endpoint dropped open: the
    // one good answer, reached on the path that owes no handler.
    var lease = loop.acquire();
    try t.expectEqual(router.Release.closed, lease.deinit());
}

test "an endpoint dropped without close is reported" {
    var handler: Handler = .{};
    var entries: [1]router.Entry = undefined;
    const table = try oneHandler("/echo", &entries, &handler);
    var tasks: [1]Task = undefined;
    var loop = Loop.init(&table, null, &tasks);

    // The lease is how the caller opts into the report, and giving it up with
    // the shutdown unfinished is upstream's `Drop` on `EndpointInner`: an
    // error, not a cleanup. The phase is in the answer, because "you forgot to
    // close" and "you closed in the wrong order" are different bugs.
    var lease = loop.acquire();
    try t.expectEqual(router.Release{ .abandoned = .serving }, lease.deinit());
    // The mark is set before the report, so a second exit finds nothing to do
    // and a copy deinited after the original reports the same thing once.
    try t.expectEqual(router.Release.already_gone, lease.deinit());
    var copy = lease;
    try t.expectEqual(router.Release.already_gone, copy.deinit());

    // And an endpoint that was closed properly reports the close, once.
    loop = loop.step(.close_requested).loop;
    loop = loop.step(.handler_finished).loop;
    loop = loop.step(.accepts_cancelled).loop;
    loop = loop.step(.endpoint_closed).loop;
    try t.expectEqual(router.Shutdown.Phase.closed, loop.shutdown.phase);
    var closed_lease = loop.acquire();
    try t.expectEqual(router.Release.closed, closed_lease.deinit());
    try t.expectEqual(router.Release.already_gone, closed_lease.deinit());
}

test "a panicked task starts the shutdown, and the loop says which" {
    var handler: Handler = .{};
    var entries: [1]router.Entry = undefined;
    const table = try oneHandler("/echo", &entries, &handler);
    var tasks: [1]Task = undefined;
    var loop = Loop.init(&table, null, &tasks);
    _ = (try offer(&loop, direct(1))).loop;

    // Upstream logs `error!("Task panicked")` and breaks, which runs the whole
    // shutdown. The slot is still freed: the join set has handed the task back.
    const reaped: Reaped = .{ .id = 1, .ended = .panicked };
    const step = loop.step(.{ .reaped = reaped });
    try t.expectEqual(@as(usize, 0), step.loop.live);
    try t.expectEqual(router.Shutdown.Action{ .shutdown_handlers = 1 }, owed(step.action).?);
    try t.expectEqual(Reaped{ .id = 1, .ended = .panicked }, step.action.shutdown.panicked.?);
    try t.expectEqual(router.Shutdown.Phase.draining_handlers, step.loop.shutdown.phase);
}

test "a full task table refuses the connection rather than losing the peer" {
    var handler: Handler = .{};
    var entries: [1]router.Entry = undefined;
    const table = try oneHandler("/echo", &entries, &handler);
    var tasks: [1]Task = undefined;
    var loop = Loop.init(&table, null, &tasks);

    const first = try offer(&loop, direct(1));
    try t.expectEqual(@as(usize, 1), first.action.spawn.id);
    loop = first.loop;
    try t.expectEqual(@as(usize, 1), loop.live);

    // Upstream's `JoinSet` is unbounded and cannot run out, so it never makes
    // this choice. Here the second peer is refused — told, rather than left to
    // time out on a handshake that was never going to finish.
    const second = try offer(&loop, direct(2));
    try t.expectEqual(Action.refuse, second.action);
    try t.expectEqual(router.PeerOutcome.refused, Action.peerOutcome(second.action));
    // The first task is untouched, and the second is not held: a refused attempt
    // is not a connection.
    try t.expectEqual(@as(usize, 1), second.loop.live);
    try t.expect(loop.task(1) != null);
}

test "a reaped task in the middle leaves the table dense and its survivors held" {
    var handler: Handler = .{};
    var entries: [1]router.Entry = undefined;
    const table = try oneHandler("/echo", &entries, &handler);
    var tasks: [3]Task = undefined;
    var loop = Loop.init(&table, null, &tasks);

    // Three accepts at once, because every other removal in this file took the
    // only task, where the last task *is* the hole and moving it changes
    // nothing. A hole that is not the last slot is what tells a swap from a
    // shift, and a shift is the copy-direction bug this project has shipped
    // twice already and never once tested.
    for (1..4) |id| {
        const step = try offer(&loop, direct(@intCast(id)));
        loop = step.loop;
    }
    try t.expectEqual(@as(usize, 3), loop.live);

    // The middle one comes back, and the last task fills its hole.
    const reaped = loop.step(.{ .reaped = .{ .id = 2, .ended = .finished } });
    loop = reaped.loop;
    try t.expectEqual(Action.none, reaped.action);
    try t.expectEqual(@as(usize, 2), loop.live);
    try t.expect(loop.task(2) == null);

    // The count says nothing about *which* task survived, so the two that must
    // still be held are named: the first, and the one that was last and has
    // been moved down into the hole.
    try t.expect(loop.task(1) != null);
    try t.expect(loop.task(3) != null);
    try t.expectEqual(@as(u64, 1), loop.tasks[0].id);
    try t.expectEqual(@as(u64, 3), loop.tasks[1].id);

    // Each is held once. A removal that copied the last task into the hole and
    // left the count alone would show two of id three in the window, and a
    // removal that shifted instead of swapped would show id two.
    try t.expectEqual(@as(usize, 1), countHeld(&loop, 1));
    try t.expectEqual(@as(usize, 1), countHeld(&loop, 3));
    try t.expectEqual(@as(usize, 0), countHeld(&loop, 2));

    // And down to empty one reap at a time, with the survivor still held at
    // every count: a removal that moved the count and nothing else would pass
    // the assertions above and fail this one.
    const second = loop.step(.{ .reaped = .{ .id = 1, .ended = .cancelled } });
    loop = second.loop;
    try t.expectEqual(@as(usize, 1), loop.live);
    try t.expect(loop.task(1) == null);
    try t.expect(loop.task(3) != null);
    try t.expectEqual(@as(u64, 3), loop.tasks[0].id);
    try t.expectEqual(@as(usize, 1), countHeld(&loop, 3));

    // The last removal takes the last task, and an empty table has no last one
    // to move: what is left is the count, and it is zero.
    const last = loop.step(.{ .reaped = .{ .id = 3, .ended = .finished } });
    loop = last.loop;
    try t.expectEqual(@as(usize, 0), loop.live);
    try t.expect(loop.task(3) == null);
    try t.expectEqual(@as(usize, 0), countHeld(&loop, 3));

    // A reap for a task already reaped is still the caller's error, and it is
    // answered from an empty table — the one place where `live - 1` would
    // underflow if the removal ran anyway.
    loop = loop.step(.{ .reaped = .{ .id = 3, .ended = .finished } }).loop;
    try t.expectEqual(@as(usize, 0), loop.live);
    try t.expect(loop.task(3) == null);
}

test "a reap for a task the loop never took changes nothing" {
    var handler: Handler = .{};
    var entries: [1]router.Entry = undefined;
    const table = try oneHandler("/echo", &entries, &handler);
    var tasks: [1]Task = undefined;
    var loop = Loop.init(&table, null, &tasks);
    _ = (try offer(&loop, direct(1))).loop;

    // The id is the core's and never reused, so a reap for one the loop did not
    // take is the caller's error, and the honest answer is the state the caller
    // already has — not a count that wraps.
    const stranger = loop.step(.{ .reaped = .{ .id = 99, .ended = .finished } });
    try t.expectEqual(Action.none, stranger.action);
    try t.expectEqual(@as(usize, 1), stranger.loop.live);
    try t.expectEqual(router.Shutdown.Phase.serving, stranger.loop.shutdown.phase);
}

test "a handler registered twice is shut down once" {
    var handler: Handler = .{};
    var entries: [2]router.Entry = undefined;
    var builder = router.Builder.init(&entries);
    _ = try builder.accept("/echo", handler.handler());
    _ = try builder.accept("/echo", handler.handler());
    const table = builder.build();

    // Upstream awaits one future per map value, and a map holds one value per
    // ALPN: the displaced entry is unreachable and is not shut down. A count of
    // two would wait for a `handler_finished` that never comes.
    try t.expectEqual(@as(usize, 2), table.entries.len);
    try t.expectEqual(@as(usize, 1), handlerCount(&table));
    var tasks: [1]Task = undefined;
    const loop = Loop.init(&table, null, &tasks);
    try t.expectEqual(@as(usize, 1), loop.shutdown.handlers);
}
