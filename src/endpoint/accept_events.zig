//! What happened to the accept loop, and what the loop owes its caller for it.
//!
//! Split out of `src/endpoint/endpoint.zig`, which is now the facade over it
//! and two other named modules. The boundary is drawn between a value and the
//! machine that consumes it: `Task`, `Reaped`, `Ended` and `Event` are the
//! caller's side, `Action`, `ShutdownStep` and `Step` are the loop's answer,
//! and every one of them is a value rather than a call. That is what makes the
//! loop drivable without a runtime, so the types that make it drivable belong
//! together and not with the `if`s.

const router = @import("../router/router.zig");
const filter = @import("incoming_filter.zig");

const Incoming = filter.Incoming;
const Loop = @import("accept_machine.zig").Loop;

/// One long-lived `accept`, held as a value.
///
/// Upstream spawns `token.run_until_cancelled(handle_connection(...))` onto a
/// `JoinSet` (`protocol.rs:601-603`), and that future may outlive the handshake
/// and the connection with it (`protocol.rs:258-261`). That is the whole reason
/// the shutdown has an ordering, and it is why a task here is a value with an
/// explicit lifetime rather than a thread: the caller drives `state` with the
/// router's own `dispatchStep` and reports what happened, and the loop counts
/// what is running so the cancel knows what it is cancelling.
pub const Task = struct {
    /// The core's connection id, which is what a reaped task is named by, and
    /// never reused (`transport/quic_bridge.zig:230-233`).
    id: u64,
    /// The router's per-connection machine, running on this task. The caller
    /// drives it while the task is held; the loop only ever reads the id.
    state: router.ConnState,
};

/// How a task's future ended, which is all `join_next` hands back.
pub const Reaped = struct {
    /// The task that ended.
    id: u64,
    /// Which of upstream's four arms this was (`protocol.rs:545-566`).
    ended: Ended,
};

/// Upstream's four `join_next` outcomes, and only one of them stops the loop.
pub const Ended = enum {
    /// `Ok(Some(()))` — the future returned. Upstream traces and carries on
    /// (`:558-560`).
    finished,
    /// `Ok(None)`, or an error for which `is_cancelled` — the handler cancel
    /// token stopped it. Upstream traces and carries on (`:561-564`).
    cancelled,
    /// A task failure that is not a cancellation. Upstream logs
    /// `error!("Task panicked")` and **breaks**, which runs the whole shutdown
    /// (`:551-556`). The one ending that stops intake.
    panicked,
};

/// One thing that happened to the accept loop.
///
/// Named after the arm of upstream's `select!` that produces it, so the four
/// ways out of that loop stay four ways into this machine.
pub const Event = union(enum) {
    /// `endpoint.accept()` produced an attempt (`:568-570`).
    ///
    /// **One attempt at a time, and the outstanding `offer` is answered first.**
    /// While one attempt is pending, an attempt that arrives is not taken:
    /// `serving` answers `Action.none`, the arriving `Incoming` is dropped and
    /// the pending one is kept, because a second arrival is a state upstream's
    /// `select!` cannot be in — it asks its filter about one datagram before it
    /// accepts the next. So a caller must feed the `Event.filtered` that the
    /// outstanding `Action.offer` owes before it reads another attempt. An
    /// attempt lost this way leaves the peer with nothing, exactly as for every
    /// other local ending: `Action.none` is `.nothing` to `peerOutcome`, so the
    /// loss is invisible to a counter built from it. Nothing here invents a
    /// refusal for the case, and the comment in `serving` says why.
    arrived: Incoming,
    /// The filter answered (`:574`). Owed only while an attempt is pending.
    filtered: filter.Answer,
    /// A join-set entry came back (`:545`).
    reaped: Reaped,
    /// The run token fired, the application asked to close, a task panicked, or
    /// `endpoint.accept()` returned nothing because the endpoint is closed
    /// (`:541`, `:551-556`, `:569-571`).
    close_requested,
    /// `protocols.shutdown().await` returned (`:609`).
    handler_finished,
    /// `handler_cancel_token.cancel()` landed, so every `accept` future is gone
    /// (`:611`).
    accepts_cancelled,
    /// `endpoint.close().await` returned (`:613`).
    endpoint_closed,
};

/// The one thing the accept loop owes its caller.
///
/// Nothing here sends an error code on a handler's behalf, and nothing here
/// decides a protocol: an action is a command the caller's runtime performs or a
/// report it logs, and the loop is the only thing in the project that knows the
/// order they may happen in.
///
/// **Every action is performed by the thread that called `Loop.step`, before
/// that step's own answer is fed back in.** The loop is pure, so the command
/// has to leave it: a caller that takes an action and never answers it has left
/// the loop waiting on an event that will not come, and a caller that answers an
/// event it did not perform is answering a step that never happened. Which
/// answer each action owes is that action's own doc, and none of them is
/// optional except `none`.
///
/// **Arguments are borrowed for the length of that call.** `offer` carries the
/// attempt the loop is holding and `spawn` the task the loop has just written
/// into the caller's own storage; both are the caller's to read now and not to
/// keep, because the loop moves the moment it is answered — `offer`'s attempt
/// is spent by the answer, and `spawn`'s slot is the caller's task table, which
/// a later reap may reuse.
pub const Action = union(enum) {
    /// Ask the filter about this attempt — the payload, so a caller never has to
    /// remember which one it fed in — and report the answer as
    /// `Event.filtered`. The two steps a caller takes to get past one datagram
    /// (`protocol.rs:568-574`).
    ///
    /// The caller's answer is `Event.filtered`, and it is owed: an attempt the
    /// loop is holding is acted on once, and only once the verdict arrives.
    offer: Incoming,
    /// Take this accept task and drive it to the end. Upstream
    /// `join_set.spawn` (`:601-603`).
    ///
    /// The caller drives the task — `Node` runs it through
    /// `router.dispatchStep` and reports the outcome — and owes
    /// `Event.reaped` when it ends, which is what frees the slot. A task the
    /// caller never reaps is a slot the loop will not reuse and a count it
    /// cannot get right at the close.
    spawn: Task,
    /// Refuse: the peer is told at once, and this is the only way anything here
    /// can tell a peer anything. Upstream `incoming.refuse()` (`:588`).
    refuse,
    /// Send nothing, and say nothing. Upstream `incoming.ignore()` (`:592`),
    /// which is also the one ending upstream does not log.
    ignore,
    /// The shutdown's next step, which is the router's own machine: the
    /// handlers, then the cancel, then the close, in that order.
    ///
    /// **This is where a handler is called.** The caller performs the router's
    /// step and feeds back the completion event it owes: a
    /// `shutdown_handlers` of *n* is answered with *n* `handler_finished`, and
    /// each `ProtocolHandler.shutdown` runs on the caller's thread, inside that
    /// step, before the accepts are cancelled. See `ProtocolHandler`'s note for
    /// what a handler may not do from there.
    shutdown: ShutdownStep,
    /// Nothing: this event is not this phase's business, or the step is already
    /// done. Upstream's `trace!` arms (`:559-565`).
    none,

    /// What the peer learns from this action.
    ///
    /// The loop owes a peer two things and no more, and they are the router's
    /// two: a refusal, and nothing else. Every local ending leaves the peer
    /// with nothing to time out on, which is invariant 19 and upstream's
    /// `warn!`-and-drop — a retry verdict among them, which is refused here
    /// because the token it asks for cannot be sent; see the module doc.
    /// Exhaustive, so an action added later has to decide this rather than
    /// inherit it.
    pub fn peerOutcome(action: Action) router.PeerOutcome {
        return switch (action) {
            .refuse => .refused,
            .offer, .spawn, .ignore, .shutdown, .none => .nothing,
        };
    }
};

/// One step of the shutdown: the router's action, and what started it.
///
/// The machine is `router.Shutdown`, so the ordering is the router's and not
/// this file's. What is left to say is *why* the shutdown began, which upstream
/// says with a log line and this says with a value: a panicked task is the only
/// beginning that is not somebody's request.
pub const ShutdownStep = struct {
    /// The one thing owed next, in the router's words.
    action: router.Shutdown.Action,
    /// The task that panicked, when a panic is what started this. Upstream
    /// `error!("Task panicked")` and then `break` (`:551-554`).
    ///
    /// Non-null only on the first step of a shutdown begun by a panic.
    /// A caller-requested shutdown carries null from its first step onward.
    /// Later draining steps always carry null, so a caller logs the panic
    /// from the first `Action.shutdown` only when this marker is present.
    /// The later `shutdown_handlers`, `cancel_accepts` and `close_endpoint`
    /// steps do not repeat it.
    ///
    panicked: ?Reaped,
};

/// One step: the next state and the one thing to do about it.
pub const Step = struct {
    loop: Loop,
    action: Action,
};