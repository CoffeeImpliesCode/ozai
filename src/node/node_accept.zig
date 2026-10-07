//! The endpoint's accept loop, and the two operations it leaves to its caller.
//!
//! `endpoint/endpoint.zig` is a function of `(state, event)` that hands back
//! the two things it deliberately does not do itself: `Action.spawn` and the
//! `cancel_accepts` inside `Action.shutdown`. This is the caller it was waiting
//! for. `admit` offers every accepted connection to the filter, `drive` runs
//! every accept task as far as this pass can, `feed` is the loop's own step,
//! and `perform` is where each action is carried out.

const std = @import("std");

const node_mod = @import("node.zig");
const node_config = @import("node_config.zig");
const node_close = @import("node_close.zig");
const node_relay_release = @import("node_relay_release.zig");
const node_transport = @import("node_transport.zig");

const bridge_mod = @import("../transport/quic_bridge.zig");
const base_ula = @import("../base/ula.zig");
const router = @import("../router/router.zig");
const incoming_filter = @import("../endpoint/incoming_filter.zig");
const endpoint = @import("../endpoint/endpoint.zig");

const Node = node_mod.Node;
const Error = node_config.Error;
const Conn = bridge_mod.Conn;
const Instant = bridge_mod.Instant;

/// How many accept tasks a node can hold.
///
/// A bound, and a node that reaches it **refuses** the connection rather than
/// dropping it: `endpoint.zig`'s `spawn` says why, and the reason is that an
/// attempt accepted and then held nowhere is a peer that believes it is
/// connected and is not.
pub const max_accepts = 64;

/// How many protocols a node registers, which is one.
///
/// The bridge offers one: `quic_bridge.Config.alpn` builds a one-element
/// `alpn_list` and the core negotiates from that list
/// (`quic_bridge.zig:222-225`). A node whose transport offered two while its
/// router dispatched one would have a table and a wire that disagree, so the
/// second protocol arrives with a second bridge field rather than as a list
/// `node.zig` fills.
///
/// **Raising this is the cheap half of wiring `/iroh-qad/0` and it is not
/// enough on its own.** The core's `TlsConfig.alpn` is `[]const []const u8`
/// and its matcher walks every entry, so `[2]` in
/// `transport/bridge_manager.zig:82` and `transport/dial_client.zig:82` would
/// carry two names with no vendor patch. What does not follow is a working
/// QAD route: `vendor/quic/` has no OBSERVED_ADDRESS frame and no
/// `address_discovery` transport parameter, and it is read-only here. A node
/// that raised this alone would offer a protocol it cannot serve.
/// `router/qad_route.zig` records that decision and what closes it.
pub const max_alpns = 1;

/// The deepest chain of endpoint events one `feed` can enqueue.
///
/// The shutdown is the longest: `close_requested`, one `handler_finished` per
/// registered handler, `accepts_cancelled`, `endpoint_closed`. With one
/// registered handler that is four, and an arrival is two.
pub const max_pending_events = 8;

/// What one action the endpoint owes is answered with.
///
/// One action can owe more than one report: `shutdown_handlers` owes one
/// `handler_finished` per registered handler, and every one of them is the
/// same event. So the answer is a counted event rather than a list, because a
/// list would be storage this function does not own, and the router's machine
/// consumes nothing else.
pub const Answer = struct {
    event: endpoint.Event,
    count: usize = 1,
};

/// Give the endpoint every accepted connection it has not been told about.
///
/// A dialled connection is not an attempt: this node asked for it and
/// already knows who the peer is, which is what `Endpoint::accept` never
/// returns. So the walk is over server-side connections only, and the
/// filter sees exactly what a remote peer sent.
pub fn admit(self: *Node, io: std.Io, at: Instant, random: std.Random) Error!bool {
    var moved = false;
    var index: usize = 0;
    while (self.bridge.connectionAt(index)) |conn| : (index += 1) {
        if (!conn.entry.conn.is_server) continue;
        if (self.offered.contains(conn.id())) continue;
        try self.offered.put(self.gpa, conn.id(), {});
        const peer = conn.peer() orelse continue;
        self.stats.attempts += 1;
        try feed(self, io, .{
            .arrived = .{
                .id = conn.id(),
                .remote = peer,
                .local = self.socket.address,
                .classification = base_ula.classify(peer),
                .validation = if (conn.initialValidation() == .unvalidated)
                    .unvalidated
                else
                    incoming_filter.proved(base_ula.classify(peer), peer),
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
/// `router.dispatchStep` and one report, in this pass rather than in a
/// thread of its own.
pub fn drive(self: *Node, io: std.Io, at: Instant, random: std.Random) Error!bool {
    var moved = false;
    var index: usize = 0;
    while (index < self.accept.live) {
        const id = self.accept.tasks[index].id;
        const conn = node_transport.connFor(self, id) orelse {
            // The core took it out of its table, so the future this task was
            // running for has returned: upstream's `join_next` arm for a
            // connection that ended (`protocol.rs:558-560`). `forget` frees
            // the slot and moves the last task into the hole, so `index`
            // must not advance.
            try feed(self, io, .{
                .reaped = .{ .id = id, .ended = .finished },
            }, at, random);
            moved = true;
            continue;
        };
        if (!runTask(self, &self.accept.tasks[index], conn)) {
            index += 1;
            continue;
        }
        try feed(self, io, .{
            .reaped = .{ .id = id, .ended = .finished },
        }, at, random);
        moved = true;
    }
    return moved;
}

/// Move one accept task as far as it can go, and say whether it is done.
///
/// A task's steps are the handshake producing an ALPN, the handler's
/// `on_accepting`, and the handler's `accept`. Every one of them is a call
/// this node makes itself, so the whole of a task runs inside one pass;
/// the only thing it waits for between passes is the handshake, and that is
/// `conn.established()`.
pub fn runTask(self: *Node, task: *endpoint.Task, conn: Conn) bool {
    if (!conn.established()) return false;
    var event: router.ConnEvent = .{
        .outcome = .{ .alpn = conn.entry.conn.negotiatedAlpn() },
    };
    while (true) {
        const stepped = router.dispatchStep(&self.table, task.state, event);
        task.state = stepped.state;
        switch (stepped.action) {
            .await_handshake => {
                // The handshake is done, which is all this action awaited;
                // reporting the connection is what moves the machine on.
                event = .{ .outcome = .{ .connection = .{ .ptr = @ptrCast(self) } } };
            },
            // Unreachable for this node: its handler registers no
            // `on_accepting`, so `negotiatingStep` answers `.alpn` with
            // `.await_handshake` instead. The arm is here because the
            // switch is exhaustive over a public union and a second
            // protocol would land in it.
            .on_accepting => |chosen| {
                // The action carries a handler that has one — that is the
                // only way `negotiatingStep` emits it.
                const call = chosen.on_accepting orelse unreachable;
                event = .{ .outcome = if (call(
                    chosen.ptr,
                    .{ .ptr = @ptrCast(self) },
                )) |connection|
                    .{ .connection = connection }
                else |err|
                    .{ .failed = .{ .accepting = err } } };
            },
            .accept => |chosen| {
                event = .{ .outcome = if (chosen.accept(
                    chosen.ptr,
                    .{ .ptr = @ptrCast(self) },
                )) |_|
                    .finished
                else |err|
                    .{ .failed = .{ .accept = err } } };
            },
            // Terminal: the handler is done or the connection is gone, and
            // the caller reaps the task.
            .release, .drop => return true,
            // A state this walk cannot be in. `runTask` is entered from
            // `.negotiating` and runs a task to one of the terminal arms
            // above inside the call, so an action from any other state
            // means the loop handed over a task it had already driven.
            .negotiate_alpn, .refuse, .ignore, .none => return false,
        }
    }
}

/// Feed one event to the accept loop and perform everything it answers
/// with.
///
/// The loop is a function of `(state, event)` and answers with one action,
/// so the caller performs the action and reports the event the action is
/// answered with. Some actions owe more than one report, which is what
/// `Answer.count` is for.
pub fn feed(
    self: *Node,
    io: ?std.Io,
    first: endpoint.Event,
    at: ?Instant,
    random: std.Random,
) Error!void {
    var pending: [max_pending_events]endpoint.Event = undefined;
    var count: usize = 1;
    var head: usize = 0;
    pending[0] = first;
    while (head < count) : (head += 1) {
        const stepped = self.accept.step(pending[head]);
        self.accept = stepped.loop;
        const owed = (try perform(self, io, stepped.action, at, random)) orelse continue;
        var index: usize = 0;
        while (index < owed.count) : (index += 1) {
            std.debug.assert(count < pending.len);
            pending[count] = owed.event;
            count += 1;
        }
    }
}

/// Perform one action the endpoint owes, and say what it is answered with.
///
/// This is the caller `endpoint.zig` says it is waiting for, and the two
/// operations it deliberately leaves out of its own signature are here:
/// `spawn` and `cancel_accepts`.
pub fn perform(
    self: *Node,
    io: ?std.Io,
    action: endpoint.Action,
    at: ?Instant,
    random: std.Random,
) Error!?Answer {
    switch (action) {
        // Two datagrams' worth of steps for one arrival: ask the filter, and
        // report its answer as `Event.filtered` (`protocol.rs:568-574`).
        .offer => |incoming| {
            // No filter, which is upstream's `Option<IncomingFilter>` set
            // to `None`: `incoming_filter.ask` answers `.accept` for every
            // attempt (`connection.rs:148`). A caller that wants one
            // registers it on the `Loop`.
            return .{ .event = .{
                .filtered = incoming_filter.ask(null, incoming),
            } };
        },
        .spawn => |task| {
            // Upstream `join_set.spawn` (`protocol.rs:601-603`). The slot
            // is the endpoint's own — `spawn` wrote it before handing the
            // action over — so what is performed is the drive, which
            // `drive` does on the next pass, or this one if the handshake is
            // already through.
            self.stats.spawned += 1;
            std.debug.assert(self.accept.task(task.id) != null);
            return null;
        },
        // Retry is only valid in the pre-allocation initial policy.
        .refuse => {
            self.stats.refusals += 1;
            return null;
        },
        .ignore => {
            self.stats.ignores += 1;
            return null;
        },
        .shutdown => |owed| return try node_close.performShutdown(self, io, owed, at, random),
        .none => return null,
    }
}

/// The handler the router dispatches to. One handler, registered under the
/// one ALPN the bridge offers; see `max_alpns`.
pub fn handler(self: *Node) router.ProtocolHandler {
    return .{
        .ptr = @ptrCast(self),
        // Null is upstream's default body: the router awaits the handshake
        // itself and reports the same two outcomes under the same log line
        // (`router.zig`'s `ProtocolHandler.on_accepting`).
        .on_accepting = null,
        .accept = acceptConnection,
        .shutdown = shutdownHandler,
    };
}

/// `ProtocolHandler::accept`: one connection handed to this node's protocol.
///
/// Upstream's runs until the connection ends (`protocol.rs:258-261`), which is
/// what makes the shutdown ordering load-bearing — a handler's `shutdown`
/// closes connections its own `accept` is still using. There is nothing to run
/// here: the gossip wire format does not exist yet (see `node.zig`'s module
/// doc), so a
/// body that looped would be a lie about what this node serves. It counts the
/// connection and returns, and `Stats.handler_connections` is what a caller
/// reads.
pub fn acceptConnection(ptr: *anyopaque, connection: router.Connection) router.AcceptError!void {
    // The handle a handler is given is the node itself, and asserting it is
    // what turns "the endpoint mints the handle" into a checked claim.
    std.debug.assert(connection.ptr == ptr);
    const self: *Node = @ptrCast(@alignCast(ptr));
    self.stats.handler_connections += 1;
}

/// `ProtocolHandler::shutdown`: called once per close, before any accept is
/// cancelled (`router.zig`'s `ProtocolHandler.shutdown`).
///
/// The gossip layer's timers are dropped here rather than in `deinit`, because
/// this is the point upstream's ordering is about: a handler is given its
/// shutdown while the accepts that might still be using it are still running,
/// and never after.
pub fn shutdownHandler(ptr: *anyopaque) void {
    const self: *Node = @ptrCast(@alignCast(ptr));
    self.stats.handler_shutdowns += 1;
    self.timers.clearRetainingCapacity();
    // The relay is this handler's own state, and it is given up here rather
    // than in `deinit`: this is the phase upstream gives a handler's resources
    // in — while the accepts that might still be using them are running, and
    // never after. `close_endpoint` closes the connections the clients were
    // on, so every disconnect is reported before a single socket write.
    node_relay_release.relayClose(self);
}

/// Whether one of these ALPNs was registered before this one.
///
/// `router.Builder.push` displaces an older registration and keeps the newer
/// one, so the shutdown owes one `shutdown` per *distinct* ALPN and not one
/// per entry. `endpoint.handlerCount` counts the same thing; this is the same
/// rule at the same place, spelled out because `performShutdown` needs both
/// halves and reading the count from two functions would be a second answer.
pub fn namedBefore(earlier: []const router.Entry, alpn: []const u8) bool {
    for (earlier) |entry| {
        if (std.mem.eql(u8, entry.alpn, alpn)) return true;
    }
    return false;
}
