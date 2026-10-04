//! Server-side admission and accept-task turns over the node's existing storage.

const std = @import("std");
const node_mod = @import("node.zig");
const node_dispatch = @import("node_dispatch.zig");
const dispatch_mod = @import("../router/dispatch.zig");
const router = @import("../router/router.zig");
const endpoint = @import("../endpoint/endpoint.zig");
const incoming_filter = @import("../endpoint/incoming_filter.zig");
const base_ula = @import("../base/ula.zig");
const Conn = @import("../transport/quic_conn.zig").Conn;
const Instant = @import("../transport/quic_conn.zig").Instant;
const Connection = @import("node_protocol.zig").Connection;
const Error = @import("node_error.zig").Error;

/// Give the endpoint every accepted connection it has not been told about.
///
/// A dialled connection is not an attempt: this node asked for it and
/// already knows who the peer is, which is what `Endpoint::accept` never
/// returns. So the walk is over server-side connections only, and the
/// filter sees exactly what a remote peer sent.
pub fn admit(io: std.Io, self: *node_mod.Node, at: Instant, random: std.Random) Error!bool {
    var moved = false;
    var index: usize = 0;
    while (self.bridge.connectionAt(index)) |conn| : (index += 1) {
        if (!conn.entry.conn.is_server) continue;
        // Closing connections cannot accept another task, including after
        // retiring a lane removed its id from the offered set.
        switch (conn.entry.conn.state) {
            .closing, .draining, .terminated => continue,
            else => {},
        }
        if (self.offered.contains(conn.id())) continue;
        try self.offered.put(self.gpa, conn.id(), {});
        const peer = conn.peer() orelse continue;
        self.stats.attempts += 1;
        try node_dispatch.feed(self, io, .{
            .arrived = .{
                .id = conn.id(),
                .remote = peer,
                .local = self.socket.address,
                .classification = base_ula.classify(peer),
                // The core's own answer about this flow's address, read here
                // and not cached: a flow that came with a valid Retry or
                // NEW_TOKEN, or whose peer has since sent a Handshake packet,
                // is what `proved` answers `.validated` for, and an unproved
                // flow stays `.unvalidated` rather than naming an identity
                // this node cannot back. What a registered filter does with
                // it is that filter's question, not this walk's.
                .validation = incoming_filter.proved(base_ula.classify(peer), peer, conn.isValidated()),
            },
        }, at, random);
        moved = true;
    }
    return moved;
}

/// Walk every accept task, and run each one as far as it can go.
///
/// Upstream spawns a task per accept (`protocol.rs:601-603`) and the loop
/// reads them off a `JoinSet`. Here the table is the endpoint's own and
/// this is the walk: a task is a value, so driving it is one
/// `dispatch_mod.dispatchStep` and one report, in this pass rather than in a
/// thread of its own.
pub fn drive(io: std.Io, self: *node_mod.Node, at: Instant, random: std.Random) Error!bool {
    var moved = false;
    var index: usize = 0;
    while (index < self.accept.live) {
        const id = self.accept.tasks[index].id;
        const conn = node_mod.connFor(self, id) orelse {
            // The core took it out of its table, so the future this task was
            // running for has returned: upstream's `join_next` arm for a
            // connection that ended (`protocol.rs:558-560`). `forget` frees
            // the slot and moves the last task into the hole, so `index`
            // must not advance.
            try node_dispatch.feed(self, io, .{
                .reaped = .{ .id = id, .ended = .finished },
            }, at, random);
            moved = true;
            continue;
        };
        if (!try runTask(io, self, at, random, &self.accept.tasks[index], conn)) {
            index += 1;
            continue;
        }
        try node_dispatch.feed(self, io, .{
            .reaped = .{ .id = id, .ended = .finished },
        }, at, random);
        moved = true;
    }
    return moved;
}

/// Move one accept task as far as it can go, and say whether it is done.
///
/// A task's steps are the handshake producing an ALPN, the handler's
/// `on_accepting`, and then its `accept` — once, and once more per later
/// pass for as long as the handler answers `.more`. The first turn runs
/// inside the pass that reached it; **the turns after it run in later
/// passes**, which is what makes a handler that waits for a peer's bytes a
/// thing this runtime can host: a connection a handler is still serving
/// keeps its accept task live, and the task is only reaped when the handler
/// says it is finished or the connection starts closing or draining.
///
/// **The protocol a task is under is the handshake's to decide and this
/// file's to report.** The accept loop never reads a connection, so the
/// ALPN exists nowhere but here, and the caller that drove the task is the
/// only thing that can tell the loop which configured protocol claims it.
/// That is what puts a `Task.protocol` on the task and makes
/// `laneCount` and `laneIds` answer about one protocol rather than about
/// the whole window.
///
/// Feeding from inside the walk is safe and not merely convenient:
/// `Event.routed` records the routing and owes nothing back, so no slot is
/// freed, no task is moved and `task` names the same one when the walk
/// reads it again.
pub fn runTask(
    io: std.Io,
    self: *node_mod.Node,
    at: Instant,
    random: std.Random,
    task: *endpoint.Task,
    conn: Conn,
) Error!bool {
    // A failed handshake or peer close ends the task immediately; the
    // core retains the connection only to finish its close/drain timers.
    switch (conn.entry.conn.state) {
        .closing, .draining, .terminated => return true,
        else => {},
    }
    // A handler that answered `.more` is waiting here, and this pass is
    // where its next turn happens. Nothing else runs for this task: the
    // handshake was reported on the pass that routed it and the router's
    // machine is already in `.handling`.
    switch (task.state) {
        .handling => |handler| return continueTask(self, task, handler, conn),
        else => {},
    }
    if (!conn.established()) return false;
    // Read once: the protocol this handshake negotiated is both the event the
    // router's machine is waiting for and the report the accept loop needs,
    // and asking the core twice for one value is how two answers start to
    // exist for it.
    const alpn = conn.negotiatedAlpn() orelse {
        // **A handshake that selected no protocol is refused here, and this is
        // the only thing standing between it and a lane.** RFC 7301 §3.2's
        // `no_application_protocol` is the core refusing an empty
        // intersection of an offer that *was* made
        // (`vendor/quic/src/quic/tls13.zig:3169-3178`), and it lives inside
        // the ALPN extension's parse: a ClientHello advertising no protocol
        // never reaches that walk at all (`tls13.zig:3100-3114`). The core
        // names this case twice over — "A ClientHello carrying no ALPN
        // extension is the other case and nothing is echoed in it either …
        // neither end fails" (`tls13.zig:1432-1435`), and a server that has
        // selected nothing, "an offer list with no entry in common, or no ALPN
        // extension at all", answers EncryptedExtensions with an empty
        // selection and carries on (`tls13.zig:2304-2310`, `:3379-3396`). So
        // such a connection is established, this walk holds a task for it,
        // and `Connection.negotiatedAlpn` would answer it with this node's own
        // first configured protocol (`tls13.zig:2060-2063`) — a name no peer
        // offered, and the second answer for one question
        // `Router.dispatch`'s own note rules out ("a peer that asks for an ALPN
        // this list does not name never reaches a connection at all",
        // `src/router/router.zig:389-395`). `Conn.negotiatedAlpn` asks the
        // handshake instead and answers null, and that null is the refusal
        // here, in place of a claim.
        //
        // **The outcome an unroutable connection already gets, and nothing is
        // invented for it**: counted where a refusal is counted, logged, and
        // dropped without a peer response, leaving the connection to the
        // core's own close and drain timers. No `Event.routed` is fed, because
        // there is no protocol to report and the endpoint owes nothing for a
        // task that carries none.
        self.stats.protocols_refused += 1;
        std.log.warn(
            "node {f}: connection {d} negotiated no protocol and no protocol is serving it",
            .{ self.bridge.nodeId(), conn.id() },
        );
        return true;
    };
    try node_dispatch.feed(self, io, .{ .routed = .{ .id = task.id, .alpn = alpn } }, at, random);
    // A claim and not a report: an ALPN no configured protocol claims
    // leaves the task unrouted and owes this file nothing (`Routed`'s own
    // note), so the counter says how many tasks carry a protocol rather
    // than how many were told about.
    if (task.protocol != null) self.stats.tasks_routed += 1;

    // A transport/table disagreement or a lane retired while a handshake
    // was in flight must not hand this connection to an absent handler.
    // Count and drop it without a peer response, matching upstream's
    // warn-and-return (`protocol.rs:653-656`).
    const claim = switch (self.table.dispatch(alpn)) {
        .protocol => |found| found,
        .refused => null,
    };
    if (claim == null or !self.lane_lifetimes[claim.?.index].serving()) {
        self.stats.protocols_refused += 1;
        std.log.warn(
            "node {f}: connection {d} selected {s} and no protocol is serving it",
            .{ self.bridge.nodeId(), conn.id(), alpn },
        );
        return true;
    }

    // **The handle the handler is handed, and it is this connection rather
    // than the node.** It is built once per turn on this frame and is
    // borrowed for the call that carries it: the core owns the connection
    // and frees it in `Bridge.sweep`, and the next pass builds a new handle
    // from whatever the core still holds.
    var handle: Connection = .{ .conn = conn, .protocol = claim.?.index };
    var event: router.ConnEvent = .{ .outcome = .{ .alpn = alpn } };
    while (true) {
        const stepped = dispatch_mod.dispatchStep(&self.table, task.state, event);
        task.state = stepped.state;
        switch (stepped.action) {
            .await_handshake => {
                // The handshake is done, which is all this action awaited;
                // reporting the connection is what moves the machine on.
                event = .{ .outcome = .{ .connection = .{ .ptr = @ptrCast(&handle) } } };
            },
            // Unreachable for this node: every registration names no
            // `on_accepting`, so `negotiatingStep` answers `.alpn` with
            // `.await_handshake` instead. The arm is here because the
            // switch is exhaustive over a public union, and the first
            // protocol registered with a handler that does take a
            // pre-handshake connection would land in it.
            .on_accepting => |chosen| {
                // The action carries a handler that has one — that is the
                // only way `negotiatingStep` emits it.
                const call = chosen.on_accepting orelse unreachable;
                event = .{ .outcome = if (call(
                    chosen.ptr,
                    .{ .ptr = @ptrCast(&handle) },
                )) |connection|
                    .{ .connection = connection }
                else |err|
                    .{ .failed = .{ .accepting = err } } };
            },
            .accept => |chosen| {
                // The router's `accept` has no way to return a step, so the
                // lane behind `chosen` records what its handler answered
                // and the line below reads it back in the same call.
                chosen.accept(chosen.ptr, .{ .ptr = @ptrCast(&handle) }) catch |err| {
                    event = .{ .outcome = .{ .failed = .{ .accept = err } } };
                    continue;
                };
                switch (self.lanes[handle.protocol].answered) {
                    // Still serving this connection: the task stays live and
                    // `drive` comes back here on a later pass, which is the
                    // only way a handler waits for a peer without a thread.
                    .more => return false,
                    .finished => event = .{ .outcome = .finished },
                }
            },
            // Terminal: the handler is done or the connection is gone, and
            // the caller reaps the task.
            .release, .drop => return true,
            // A state this walk cannot be in. `runTask` is entered from
            // `.negotiating` and runs a task to one of the terminal arms
            // above inside the call, so an action from any other state
            // means the loop handed over a task it had already driven.
            .negotiate_alpn, .send_retry, .refuse, .ignore, .none => return false,
        }
    }
}

/// Give a handler its next turn on a connection it is still serving, and
/// say whether the task is done.
///
/// **This is the continuation seam, and it is this file's rather than the
/// router's.** `router.ConnState.handling` already holds the handler for a
/// connection whose `accept` has been called and has not come back — the
/// arm exists for exactly that (`router.zig`'s own note on what a
/// long-lived `accept` means without a thread) — so a handler that answers
/// `.more` needs no state of its own: the task's machine is the answer, and
/// the pass that reads it is the caller. `router.ProtocolHandler.accept`
/// returns `void` because it is upstream's future flattened onto a
/// signature, and the step itself rides on the lane.
///
/// The handler's `.finished` releases the task and a refusal drops it. So does
/// a protocol that stopped being served: a lane whose own close has begun has
/// already been given its handler's shutdown, and a turn on it is a turn on
/// state that is gone. `runTask` also ends it when the connection starts
/// closing or draining, before the core's timers finally reap the borrowed
/// connection entry.
pub fn continueTask(
    self: *node_mod.Node,
    task: *endpoint.Task,
    handler: router.ProtocolHandler,
    conn: Conn,
) Error!bool {
    // The lane is the one `Event.routed` recorded on this task. Null would
    // mean a task in `.handling` that was never routed, and the machine
    // reaches `.handling` only through a claim, so this is the claim's
    // index restated.
    const index = task.protocol orelse return true;
    // **The same guard the first turn already has, on the same number.**
    // `retire` shuts the handler down before it cancels this protocol's
    // accepts, and its own note says a send error propagates after the state
    // changes already performed — so a cancellation that fails leaves this
    // very task held, in `.handling`, under a handler whose state is gone.
    // Claiming nothing further is the whole of the answer: the connection is
    // the core's to reap, and a task that owes no turn is done.
    //
    // **`serving` is what tells a shut-down lane from a live one, and it is the
    // bit `node_close.laneStats` already reports for this index.** `.serving`
    // is the one phase of `Lifetime` in which this protocol's handler is still
    // standing; every other phase is a close that has already run
    // `shutdownLane` on this index, and `retire` runs that shutdown in the same
    // between-passes call that leaves the phase. So a lane still serving is
    // still turned, and one whose handler is gone is not — on the same number
    // the first turn refused on.
    //
    // **It is load-bearing, and what says so is a handler's own turn counter.**
    // A task left held here is turned again on the very next pass, so without
    // this guard a lane whose retirement failed half way is called once more
    // after its own shutdown ran — which is the regression
    // `node_retirement_tests` exists to hold, as `alpha.turns` not growing on
    // the pass after the interrupted retirement.
    if (!self.lane_lifetimes[index].serving()) return true;
    var handle: Connection = .{ .conn = conn, .protocol = index };
    handler.accept(handler.ptr, .{ .ptr = @ptrCast(&handle) }) catch |err| {
        const stepped = dispatch_mod.dispatchStep(&self.table, task.state, .{
            .outcome = .{ .failed = .{ .accept = err } },
        });
        task.state = stepped.state;
        return true;
    };
    if (self.lanes[index].answered == .more) return false;
    const stepped = dispatch_mod.dispatchStep(&self.table, task.state, .{
        .outcome = .finished,
    });
    task.state = stepped.state;
    // `.finished` in `.handling` is `.released`, and that is the only action
    // it can produce; a different one would mean the task was not in the
    // state the switch above read it in.
    std.debug.assert(stepped.action == .release);
    return true;
}
