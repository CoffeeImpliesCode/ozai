//! The endpoint's shutdown, as a machine: the order its three steps run in, the
//! counts that decide which phase is entered, and the lease that has to be
//! given up by closing.
//!
//! Split out of `router/router.zig`, which is now the facade over this and two
//! other named modules. The boundary is the endpoint rather than the
//! connection: this is one machine per endpoint where `conn_dispatch.zig` is
//! one per connection, and the ordering the whole shutdown exists for is an
//! ordering between handlers and the accepts they may still be using. It names
//! nothing of either, which is what makes it checkable alone — the table is the
//! caller's, and the machine holds no table.

/// The router's shutdown, as a value.
///
/// Upstream runs these steps at the bottom of the accept loop once the loop
/// stops (`protocol.rs:608-613`), in this order:
///
/// 1. `protocols.shutdown().await` — every handler's `shutdown`, awaited, so a
///    handler gets to close its connections gracefully.
/// 2. `handler_cancel_token.cancel()` — the `accept` futures stop.
/// 3. `endpoint.close().await` — the endpoint closes, which force-closes
///    whatever is left.
///
/// The order is the point, and an ordering bug here is a use-after-free. A
/// handler's `shutdown` closes connections that its own `accept` is still
/// using, so cancelling the accepts first cuts a graceful close in half;
/// closing the endpoint force-closes live connections, so closing before the
/// accepts are cancelled does the same damage a step later and without a
/// warning. Upstream says as much in the other direction, on the tail after the
/// close: the accepts are cancelled so that the `abort_all` which follows is
/// "a noop" (`protocol.rs:614-615`).
///
/// That tail is not a fourth step here. It exists to clean up tasks the cancel
/// already stopped, and the three steps above are where the order lives.
pub const Shutdown = struct {
    /// Which step is owed. Each phase owes exactly one action, and a phase
    /// only advances when the step before it has been reported done, so the
    /// cancel cannot be emitted while a handler is still shutting down and the
    /// close cannot be emitted before the cancel.
    phase: Phase = .serving,
    /// Registered handlers, which become running when the shutdown starts and
    /// reach zero when the last of them has returned. The count is not in the
    /// phase because the table is the caller's and the machine holds no table.
    ///
    /// **Zero means the close owes no report at all**, and the machine takes
    /// that as a fact on the first step rather than as a phase to wait in.
    handlers: usize = 0,
    /// `accept` futures still running. This is what a cancel has to account
    /// for, and it is why the state is more than the phase: a router with three
    /// accepts running and one that has been told they are gone are the same
    /// phase and a different fact.
    ///
    /// **`accepts` does not gate anything.** The cancel is one step whatever
    /// the count is, exactly as `cancel()` is one call upstream
    /// (`protocol.rs:611`); the count is what a caller reads to know how many
    /// accept futures its own cancel has to account for, and it saturates at
    /// zero rather than wrapping.
    accepts: usize = 0,

    pub const Phase = enum {
        /// The accept loop is taking connections. Upstream's `select!` body
        /// before the cancel token fires.
        ///
        /// Nothing waits here, and a close taken with no handler registered
        /// passes straight through this phase to the cancel rather than resting
        /// in the drain (`beginShutdown`). Upstream's `protocols.shutdown().await`
        /// over an empty map returns at once and the cancel follows it
        /// (`protocol.rs:609-611`), so the two agree on what happens and only
        /// the representation differs.
        serving,
        /// Intake has stopped and the handlers are draining. Upstream
        /// `protocols.shutdown().await`.
        draining_handlers,
        /// Every handler has returned. The accepts are still running and are
        /// owed their cancellation. Upstream `handler_cancel_token.cancel()`.
        cancelling_accepts,
        /// The accepts are cancelled. The endpoint is owed its close. Upstream
        /// `endpoint.close().await`.
        closing_endpoint,
        /// Closed. Terminal.
        closed,
    };

    /// One thing that happened to the shutdown.
    pub const Event = union(enum) {
        /// The application asked to close, or the accept loop stopped because
        /// the endpoint closed under it. Upstream `Router::shutdown` cancels
        /// the run token and awaits the task (`protocol.rs:435-452`), and the
        /// loop also breaks when `endpoint.accept()` returns nothing
        /// (`protocol.rs:569-571`).
        close_requested,
        /// A handler's `shutdown` returned.
        handler_finished,
        /// An `accept` returned, finished or was cancelled. This is the live
        /// count going down, and it never advances the shutdown: upstream's
        /// loop takes a finished task from the join set and goes back to
        /// `select!` (`protocol.rs:545-565`).
        accept_finished,
        /// The cancellation landed: every `accept` future is gone.
        ///
        /// Upstream does not wait for this separately — `cancel()` is
        /// synchronous and `endpoint.close()` follows it — but a machine that
        /// is to be checkable without a scheduler has to be *told* the step
        /// happened. Otherwise the close is emitted in the same breath as the
        /// cancel and the ordering stops being observable at all.
        accepts_cancelled,
        /// `endpoint.close()` returned.
        endpoint_closed,
    };

    /// The one thing the shutdown owes.
    pub const Action = union(enum) {
        /// Call `shutdown` on every registered handler and await all of them,
        /// concurrently (`protocol.rs:404-407`).
        shutdown_handlers: usize,
        /// Cancel the `accept` futures.
        cancel_accepts,
        /// Close the endpoint.
        close_endpoint,
        /// Nothing: this event is not this phase's business, or the step is
        /// already done. Upstream's `trace!` arms (`protocol.rs:559-565`).
        none,
    };

    pub const Step = struct {
        shutdown: Shutdown,
        action: Action,
    };

    /// A router that has not been asked to close, with `handlers` registered and
    /// `accepts` running. The counts are the caller's to know and the machine's
    /// to keep.
    ///
    /// **`handlers == 0` is a legitimate answer, not an empty one.** It is what
    /// an endpoint over a table with no registrations hands here, and it makes
    /// the first close step emit the cancel directly — see `beginShutdown`. A
    /// caller that reads it as "drain nothing, then wait" has read it wrong:
    /// there is no report to wait for and the machine will not invent one.
    pub fn init(handlers: usize, accepts: usize) Shutdown {
        return .{ .handlers = handlers, .accepts = accepts };
    }

    /// One step. Pure, and the whole of the ordering.
    ///
    /// Every event is named in every phase and nothing falls through, so an
    /// event added later has to be classified here rather than being absorbed
    /// by a wildcard and never reaching the phase that owed it.
    pub fn step(self: Shutdown, event: Event) Step {
        return switch (self.phase) {
            .serving => switch (event) {
                .close_requested => beginShutdown(self),
                .accept_finished => .{ .shutdown = self.fewerAccepts(), .action = .none },
                // Nothing has been asked for yet, and a report from a phase
                // that has not been entered is not this one's business.
                .handler_finished, .accepts_cancelled, .endpoint_closed => self.hold(),
            },
            .draining_handlers => switch (event) {
                .handler_finished => handlerFinished(self),
                .accept_finished => .{ .shutdown = self.fewerAccepts(), .action = .none },
                // The whole ordering is this arm: the cancel waits for the
                // handlers and the close waits for the cancel, so neither of
                // these can begin early.
                .close_requested, .accepts_cancelled, .endpoint_closed => self.hold(),
            },
            .cancelling_accepts => switch (event) {
                .accepts_cancelled => .{
                    .shutdown = .{ .phase = .closing_endpoint, .accepts = 0 },
                    .action = .close_endpoint,
                },
                .accept_finished => .{ .shutdown = self.fewerAccepts(), .action = .none },
                .close_requested, .handler_finished, .endpoint_closed => self.hold(),
            },
            .closing_endpoint => switch (event) {
                .endpoint_closed => .{
                    .shutdown = .{ .phase = .closed },
                    .action = .none,
                },
                .accept_finished, .close_requested, .handler_finished, .accepts_cancelled => {
                    return self.hold();
                },
            },
            .closed => self.hold(),
        };
    }

    /// No step. Absorbing an event that does not apply here is the point: the
    /// ordering lives in which event advances which phase, and an event that
    /// advances nothing is the ordering holding.
    fn hold(self: Shutdown) Step {
        return .{ .shutdown = self, .action = .none };
    }

    /// One handler returned, and either there are others still draining or
    /// every handler is done and the accepts are owed their cancellation.
    ///
    /// The count goes down on *every* report, not only on the last: an arm that
    /// held the state unchanged until the end would never reach zero, the
    /// cancel would never be emitted, and the endpoint would never close.
    fn handlerFinished(self: Shutdown) Step {
        // A report past zero is a handler the count never had, and holding is
        // the only honest answer: there is nothing left to drain. `beginShutdown`
        // is why that arm is unreachable on the way in — a close taken with no
        // handler registered never enters the phase this runs in.
        if (self.handlers == 0) return self.hold();
        var next = self;
        next.handlers -= 1;
        if (next.handlers > 0) return .{ .shutdown = next, .action = .none };
        return .{
            .shutdown = .{ .phase = .cancelling_accepts, .accepts = self.accepts },
            .action = .cancel_accepts,
        };
    }

    /// A close, and the first thing it owes.
    ///
    /// **The counts decide the phase, and the phase is settled before the
    /// action is named.** A close with a handler registered owes
    /// `shutdown_handlers` and then one `handler_finished` per handler, and it
    /// cannot leave `.draining_handlers` until every one of those has been
    /// reported. A close with *no* handler registered owes no report at all, so
    /// entering that phase with a `shutdown_handlers` of zero would be a phase
    /// nothing can leave: `handler_finished` past zero is held, because there
    /// is nothing left to drain, and the cancel this close owes is never
    /// emitted — the endpoint stays open for ever.
    ///
    /// So the zero case is decided here, on the counts, rather than left to a
    /// caller to notice: no handler means the cancel is owed the moment the
    /// close is asked for, and the machine says so in one step. `accepts`
    /// crosses either way, because the cancel has to account for them whatever
    /// the handlers did.
    ///
    /// Upstream cannot reach the shape this avoids. `protocols.shutdown()`
    /// awaits one future per *map value* (`protocol.rs:404-407`), and a map
    /// with no values has nothing to await, so the cancel at `:611` is the very
    /// next statement to run. `handlerCount` is what makes the count knowable
    /// on this side, and it is the same count the phase it feeds would have
    /// waited for.
    fn beginShutdown(self: Shutdown) Step {
        if (self.handlers == 0) return .{
            .shutdown = .{ .phase = .cancelling_accepts, .accepts = self.accepts },
            .action = .cancel_accepts,
        };
        return .{
            .shutdown = .{
                .phase = .draining_handlers,
                .handlers = self.handlers,
                .accepts = self.accepts,
            },
            .action = .{ .shutdown_handlers = self.handlers },
        };
    }

    /// One `accept` returned. Saturating: a report past zero is a task the count
    /// never had, and a wrapped count would read as "an enormous number of
    /// accepts is still running".
    fn fewerAccepts(self: Shutdown) Shutdown {
        var next = self;
        next.accepts = if (self.accepts == 0) 0 else self.accepts - 1;
        return next;
    }
};

/// The endpoint lease, which has to be given up by closing.
///
/// Upstream logs an error from `EndpointInner`'s `Drop` when `close()` was
/// never called: dropping an endpoint without closing is a misuse, not a
/// cleanup. Zig has no `Drop`, so the report moves to `deinit` and the guarantee
/// is carried by a type rather than by discipline:
///
/// - `acquire` is the only way to hold a lease, so nothing is bound to an
///   endpoint without one.
/// - `deinit` is the only way to give it up, and it reads the answer out of the
///   shutdown the lease watches rather than out of an argument, so a caller
///   cannot talk its way out of it. `.abandoned` is upstream's drop error, with
///   the phase it was dropped in.
/// - the mark is set before the report, so a second `deinit` finds nothing to
///   do — the same discipline as `OnDisconnectGuard` in `relay/server.zig`.
///
/// The shutdown must outlive the lease, because `deinit` reads it. That is the
/// half of "the endpoint must never outlive its guard" a type can carry; the
/// other half stays a discipline, because Zig has no move semantics and both
/// `phase` and the lease's own fields are readable and writable by anyone
/// holding the struct.
pub const Lease = struct {
    shutdown: *Shutdown,
    reported: bool,

    /// The only way to hold a lease.
    pub fn acquire(shutdown: *Shutdown) Lease {
        return .{ .shutdown = shutdown, .reported = false };
    }

    /// The single exit. `.closed` is the one good answer, and the only way to
    /// reach it is to have driven the shutdown to `closed` — which is the only
    /// way the endpoint is closed.
    // `reported` is the readable report-once tombstone; Z030 only recognizes
    // its fixed vocabulary of lifecycle field names, not this marker.
    // ziglint-ignore: Z030
    pub fn deinit(self: *Lease) Release {
        const already = self.reported;
        self.reported = true;
        if (already) return .already_gone;
        if (self.shutdown.phase == .closed) return .closed;
        return .{ .abandoned = self.shutdown.phase };
    }
};

/// What giving up a lease found.
pub const Release = union(enum) {
    /// The endpoint was closed. The one good exit.
    closed,
    /// The lease was given up with the endpoint still open, in this phase.
    /// This is the drop upstream logs an error for, and the phase is in the
    /// answer because "you forgot to close" and "you closed in the wrong
    /// order" are different bugs.
    abandoned: Shutdown.Phase,
    /// Already reported. A lease is a plain struct and can be copied, so a
    /// second copy can be deinited; the mark is set before the report, exactly
    /// as `OnDisconnectGuard::deinit` does it.
    already_gone,
};
