//! The shutdown, in the order `router.Shutdown` enforces: the handlers, then
//! the cancel, then the close.
//!
//! `close` resumes rather than refusing, `finish` is that resumption, and
//! `dispose` is the backstop behind it for a `run` with no runtime and no
//! instant. The two actions the machine asks for — shutting the handlers down
//! and closing the endpoint — are performed here rather than in the accept
//! loop's `perform`, because what they do is this file's own state and not an
//! accept task's.

const std = @import("std");

const node_mod = @import("node.zig");
const node_config = @import("node_config.zig");
const node_accept = @import("node_accept.zig");
const node_transport = @import("node_transport.zig");

const bridge_mod = @import("../transport/quic_bridge.zig");
const endpoint = @import("../endpoint/endpoint.zig");
const tcp_client = @import("../relay/tcp_client.zig");

const Self = node_mod.Node;
const Error = node_config.Error;
const Answer = node_accept.Answer;
const Instant = bridge_mod.Instant;

/// The pass bound on a close that does not finish in one pass.
///
pub const max_close_steps = 8;

/// Wind the node down, in the order `router.Shutdown` enforces.
///
/// Every step of that machine answers the event that drove it, so a close
/// from `.serving` is one pass; `finish` is what the rest of it looks like.
///
/// **It resumes rather than refusing.** A close that stopped part way — a
/// send that failed in `close_endpoint`, the one step that needs a runtime —
/// leaves the machine in `.closing_endpoint` with the descriptor open, and
/// the next `close` picks that phase up and finishes it. So a caller that
/// gets an error out of a close knows two things: which send failed, and
/// that a later close with a working socket will complete the shutdown.
/// `run` does not rely on that — its error path ends in `dispose`, which
/// cannot fail.
///
/// **What it guarantees on return is the machine at `.closed`**: the
/// handler's own state released, every accept task cancelled, the
/// descriptor shut. A return is only reached there, because every other
/// exit is an error the caller has been handed.
///
/// **This is `run`'s close, and a caller picks one or the other.**
/// `run` closes on its way out, so a `close` after it is the no-op the
/// `.closed` phase makes it. Calling `close` on a node a `run` is passing
/// right now is a re-entry into the pass driving the machine; `Node` says
/// what that means.
///
/// **`error.Canceled` leaves the phase it reached, not a lost node.** The
/// resume above is what a later `close` picks up, so an `Io` that cancels
/// one close does not need to cancel the next; `run` is the caller that
/// turns either answer into a disposal before it returns.
pub fn close(self: *Self, io: std.Io, at: Instant, random: std.Random) Error!void {
    if (self.accept.shutdown.phase == .closed) return;
    try finish(self, io, at, random);
}

/// Drive the shutdown out of whatever phase it is in, feeding each phase
/// what it is waiting for until it reaches `closed`.
///
/// **`close` resumes rather than refusing, and this is why.** A close that
/// stopped part way — a send that failed in `close_endpoint` — leaves the
/// machine in `closing_endpoint` with the descriptor open, and returning
/// there because the phase is no longer `serving` would leave a node nothing
/// could ever finish. So one iteration per phase, each feeding that phase
/// its own event, which is what `max_close_steps` bounds.
///
/// One phase is different: the machine emits `close_endpoint` on the event
/// before it and never twice, so a close resumed at `closing_endpoint` is
/// performing the action that failed rather than being told it is owed.
pub fn finish(self: *Self, io: ?std.Io, at: ?Instant, random: std.Random) Error!void {
    var steps: usize = 0;
    while (self.accept.shutdown.phase != .closed) {
        std.debug.assert(steps < max_close_steps);
        steps += 1;
        switch (self.accept.shutdown.phase) {
            .serving => try node_accept.feed(self, io, .close_requested, at, random),
            .draining_handlers => try node_accept.feed(self, io, .handler_finished, at, random),
            .cancelling_accepts => try node_accept.feed(self, io, .accepts_cancelled, at, random),
            .closing_endpoint => {
                // The one phase whose action can have failed. The machine
                // emits `close_endpoint` on the event before this phase and
                // never emits it twice, so it is performed again here
                // unless the flag says it already completed — which is the
                // difference between a close that is progressing and one
                // that is being resumed.
                if (!self.endpoint_closed) {
                    const owed = try performShutdown(
                        self,
                        io,
                        .{ .action = .close_endpoint, .panicked = null },
                        at,
                        random,
                    );
                    // The one answer this action has. Asserted rather than
                    // read: a second one would mean the machine and this
                    // loop disagree about what advances the phase.
                    std.debug.assert(owed != null);
                    std.debug.assert(std.meta.activeTag(owed.?.event) == .endpoint_closed);
                }
                try node_accept.feed(self, io, .endpoint_closed, at, random);
            },
            .closed => unreachable,
        }
    }
}

/// The shutdown with nothing graceful left to do: no runtime, no instant,
/// and so no connection closes — the handler released, every accept reaped,
/// the descriptor shut, the machine at `closed`.
///
/// **This is the backstop behind `run`'s promise**, and `run` reaches it
/// two ways: a clock it never read, and a graceful close it could not
/// perform. What it gives up is not reportable — it sends nothing, so there
/// is no error and no count — and what it does not give up is local:
/// `deinit` finds a closed endpoint, a lease that reports it, and the core
/// connections its own walk already handles.
///
/// It cannot fail. With no `Io` to ask and no instant to stamp, every step
/// is a counter or a call into this node's own state, so an error here would
/// be a claim this module cannot make. It panics rather than leave a
/// half-disposed node behind a swallowed error.
pub fn dispose(self: *Self) void {
    // ZBC cannot follow null inputs through handlers; panic marks impossible shutdown failure.
    // zbc-disable-next-line: catch-error-panic
    finish(self, null, null, self.generator()) catch |err| std.debug.panic(
        "a shutdown with no runtime and no instant failed: {t}",
        .{err},
    );
    std.debug.assert(self.accept.shutdown.phase == .closed);
    std.debug.assert(!self.socket_open);
}

/// The shutdown, in the order `router.Shutdown` enforces: the handlers,
/// then the cancel, then the close.
///
/// Each phase is performed and then reported, so the ordering is not a
/// comment but a sequence this function has to get right — a cancel issued
/// while a handler is still shutting down is a use-after-free
/// (`router.zig:642-650`).
pub fn performShutdown(
    self: *Self,
    io: ?std.Io,
    owed: endpoint.ShutdownStep,
    at: ?Instant,
    random: std.Random,
) Error!?Answer {
    if (owed.panicked) |reaped| std.log.err(
        "node: accept task {d} failed and started the shutdown",
        .{reaped.id},
    );
    switch (owed.action) {
        // Upstream awaits one future per registered handler
        // (`protocol.rs:404-407`) before anything is cancelled. None of them
        // is a future here, so they are called in one pass and each is
        // reported: the machine counts handlers, and it only emits the
        // cancel when the count reaches zero.
        .shutdown_handlers => |count| {
            var distinct: usize = 0;
            for (self.table.entries, 0..) |entry, index| {
                if (node_accept.namedBefore(self.table.entries[0..index], entry.alpn)) continue;
                distinct += 1;
                const shut = entry.handler.shutdown orelse continue;
                shut(entry.handler.ptr);
            }
            std.debug.assert(distinct == count);
            return .{ .event = .handler_finished, .count = count };
        },
        // Upstream `handler_cancel_token.cancel()` (`protocol.rs:611`).
        // An accept here is a value in the loop's own table and the thing
        // that would have been cancelled is the handler state on that
        // connection, so cancelling means reaping every task — and every
        // task has already been driven to its end by `drive`, which is why
        // there is nothing running here to interrupt.
        .cancel_accepts => {
            var index = self.accept.live;
            while (index > 0) {
                index -= 1;
                const id = self.accept.tasks[index].id;
                const stepped = self.accept.step(.{
                    .reaped = .{ .id = id, .ended = .cancelled },
                });
                self.accept = stepped.loop;
                // A reap in this phase is the live count going down and
                // never advances the machine. Asserted rather than ignored,
                // because an advance here would skip the close.
                std.debug.assert(stepped.action == .none);
                std.debug.assert(self.offered.remove(id));
                self.stats.accepts_cancelled += 1;
            }
            return .{ .event = .accepts_cancelled };
        },
        // Upstream `endpoint.close()` (`protocol.rs:613`), which
        // force-closes whatever the accepts left. This node's endpoint is
        // its socket and the connections the core holds, so both go:
        // `closeConnections` stamps and writes, and `shutdownSocket`
        // releases the descriptor.
        //
        // **The descriptor is released on every path and the connections
        // only where there is an instant to stamp them with.** A null
        // instant is the disposal path — `dispose` is its only caller — and
        // a connection close is the one thing here that needs a clock
        // reading. Those connections are then left to `deinit`'s own walk.
        // Releasing the descriptor is the part that cannot be deferred to
        // anything, so it is not.
        .close_endpoint => {
            if (io) |runtime| {
                if (at) |stamp| try closeConnections(self, runtime, stamp, random);
            }
            self.endpoint_closed = true;
            node_transport.shutdownSocket(self);
            return .{ .event = .endpoint_closed };
        },
        .none => return null,
    }
}

/// Stamp a close on every connection the core holds and write it out, so
/// each peer is told rather than left to time out.
///
/// **A failure here leaves the machine in `closing_endpoint` and the
/// descriptor open**, and that is reported rather than papered over:
/// `finish` re-performs this step on the next close, and `dispose` is the
/// backstop behind both.
pub fn closeConnections(self: *Self, io: std.Io, at: Instant, random: std.Random) Error!void {
    var index: usize = 0;
    while (self.bridge.connectionAt(index)) |conn| : (index += 1) {
        conn.entry.conn.close(0, "", at);
        for (try conn.drain(self.egress, self.out, at, random)) |egress| {
            try node_transport.send(self, io, egress.to, egress.send);
        }
    }
    // Relay sends enqueue framed output; keep the endpoint live until every byte is written.
    try self.relay_runtime.flush(io);
}

const CloseOutput = struct {
    blocked: bool = true,
    writes: usize = 0,
    closes: usize = 0,

    fn read(_: std.Io, _: *anyopaque, _: []u8) tcp_client.Error!usize {
        return error.UnexpectedMessage;
    }

    fn write(
        _: std.Io,
        context: *anyopaque,
        bytes: []const u8,
    ) tcp_client.Error!usize {
        const self: *CloseOutput = @ptrCast(@alignCast(context));
        std.debug.assert(self.closes == 0);
        self.writes += 1;
        if (self.blocked) return error.WouldBlock;
        return @min(bytes.len, 5);
    }

    fn close(context: *anyopaque) void {
        const self: *CloseOutput = @ptrCast(@alignCast(context));
        self.closes += 1;
    }
};

test "relay close backpressure keeps endpoint live and repeated close resumes output" {
    // The borrowed carrier outlives shutdown; blocked bytes must survive until the next close.
    const key = @import("../base/key.zig");
    var output: CloseOutput = .{};
    const node = try Self.create(std.testing.allocator, std.testing.io, .{
        .secret = try key.SecretKey.fromSeed(@splat(42)),
    }, 4242);
    defer node.deinit();
    node.relay_runtime.client = .{
        .address = node.socket.address,
        .connection = .{
            .stream = undefined,
            .transport = .{
                .context = &output,
                .read = CloseOutput.read,
                .write = CloseOutput.write,
                .close = CloseOutput.close,
            },
        },
        .secret = try key.SecretKey.fromSeed(@splat(43)),
        .host_len = 0,
        .state = .ready,
    };
    try node.relay_runtime.client.?.send(node.nodeId(), "final close datagram");
    const at: Instant = 1_000 * std.time.ns_per_s;
    try std.testing.expectError(error.WouldBlock, node.close(
        std.testing.io,
        at,
        node.generator(),
    ));
    try std.testing.expectEqual(.closing_endpoint, node.accept.shutdown.phase);
    try std.testing.expect(node.socket_open);
    try std.testing.expect(!node.endpoint_closed);
    try std.testing.expect(node.relay_runtime.client.?.connection.busy());
    try std.testing.expectEqual(@as(usize, 0), output.closes);
    try std.testing.expectError(error.WouldBlock, node.close(
        std.testing.io,
        at,
        node.generator(),
    ));
    output.blocked = false;
    try node.close(std.testing.io, at, node.generator());
    try std.testing.expectEqual(.closed, node.accept.shutdown.phase);
    try std.testing.expect(!node.socket_open);
    try std.testing.expect(node.endpoint_closed);
    try std.testing.expect(!node.relay_runtime.client.?.connection.busy());
    try std.testing.expectEqual(@as(usize, 0), output.closes);
    const writes = output.writes;
    try node.close(std.testing.io, at, node.generator());
    try std.testing.expectEqual(writes, output.writes);
}
