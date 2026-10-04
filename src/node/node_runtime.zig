const std = @import("std");
const node_mod = @import("node.zig");
const node_config = @import("node_config.zig");
const Error = @import("node_error.zig").Error;
const Instant = @import("../transport/quic_conn.zig").Instant;
const NodeId = @import("../base/key.zig").NodeId;
const hyparview = @import("../gossip/hyparview.zig");
const ingress = @import("node_ingress.zig");
const accept_mod = @import("node_accept.zig");
const egress = @import("node_egress.zig");
const gossip_mod = @import("node_gossip.zig");
const relay_admit = @import("node_relay_serve_admit.zig");
const relay_client = @import("node_relay_client.zig");
const close_mod = @import("node_close.zig");

/// Attempt each configured peer once and join gossip using the caller's instant and generator.
/// Unreachable peers are counted, not fatal; join is latched only after a successful feed.
/// A failed start is not transactional: retry explicitly or close and discard the node.
pub fn start(self: *node_mod.Node, at: Instant, random: std.Random) Error!void {
    for (self.config.peers) |peer| {
        if (self.dialled.contains(peer.id)) continue;
        try self.dialled.put(self.gpa, peer.id, {});
        const reached = self.dialer.dial(
            peer.addr,
            peer.id,
            node_mod.address(self),
            &self.map,
            at,
            random,
        ) catch |err| {
            // A refused peer is still an attempted dial, not a refusal to start.
            self.stats.dials_refused += 1;
            std.log.warn("node: {f} was not reached: {t}", .{ peer.id, err });
            continue;
        };
        switch (peer.addr) {
            .ip => |target| std.debug.assert(reached.route.socket.order(target) == .eq),
            .relay, .custom => {},
        }
        self.stats.dials += 1;
        // The peer id a gossip request names is the one this dial was pinned
        // to, and this is the only place this node has ever known it: an
        // accepted connection arrives with no identity at all (the bridge is
        // built with no `expect_peer`), so a peer's name comes from the gossip
        // protocol it speaks and not from the transport it arrived on.
        self.connections.put(peer.id, reached.conn) catch |err| switch (err) {
            error.ConnectionIndexFull => std.log.warn(
                "node: {f} was dialled and cannot be named by gossip: {t}",
                .{ peer.id, err },
            ),
        };
    }
    if (self.joined) return;
    if (self.config.peers.len > hyparview.max_bootstrap) {
        return error.BootstrapListTooLong;
    }
    var ids: [hyparview.max_bootstrap]NodeId = undefined;
    for (self.config.peers, 0..) |peer, index| {
        ids[index] = peer.id;
    }
    // Even an empty bootstrap list must join; latch only after the feed succeeds.
    try gossip_mod.feedGossip(self, .{
        .command = .{ .join = try hyparview.Peers.init(ids[0..self.config.peers.len]) },
    }, try gossip_mod.gossipNow(at));
    self.joined = true;
}

/// Drive one pass with explicit, unstored I/O and the caller's instant and generator.
/// Order is receive, sweep, admit, drive, relay, drain, expire, then gossip.
/// Errors, including cancellation, may follow consumed input; close rather than replay the pass.
/// Expired connections remain allocated until the next sweep.
pub fn step(io: std.Io, self: *node_mod.Node, at: Instant, random: std.Random) Error!bool {
    self.stats.steps += 1;
    var moved = try ingress.take(io, self, at, random);
    // Sweep before indexed admission; relay writes must precede this pass's drain.
    self.bridge.sweep();
    moved = try accept_mod.admit(io, self, at, random) or moved;
    moved = try accept_mod.drive(io, self, at, random) or moved;
    moved = try relay(self, at, random) or moved;
    moved = try egress.drain(io, self, at, random) or moved;
    moved = try egress.expire(io, self, at, random) or moved;
    moved = try gossip_mod.gossip(self, at) or moved;
    return moved;
}

/// Wait using explicit, unstored I/O, parking any consumed datagram for the next intake.
/// Existing parked input is retained; timeout is not an error.
/// Cancellation is forwarded and requires closing the node. Raw poll is bounded by timeout;
/// runtime cancellation alone does not wake it, while Socket.stop does.
pub fn wait(io: std.Io, self: *node_mod.Node, timeout_ms: i32) Error!void {
    if (self.held != null) return;
    const got = self.socket.receive(
        io,
        self.buf,
        &self.control,
        timeout_ms,
    ) catch |err| switch (err) {
        error.WouldBlock => return,
        else => return err,
    };
    // The kernel already consumed this datagram; intake cannot receive it again.
    self.held = got;
}

/// Finish shutdown without I/O or an instant, releasing resources without stamping a close.
/// This non-failing backstop requires the shutdown machine closed and the socket released.
pub fn dispose(self: *node_mod.Node) void {
    close_mod.finish(self, null, null, node_mod.generator(self)) catch |err| std.debug.panic(
        "a shutdown with no runtime and no instant failed: {t}",
        .{err},
    );
    std.debug.assert(self.accept.shutdown.phase == .closed);
    std.debug.assert(!self.socket_open);
}

/// Run with explicit, unstored I/O; check stop before starting dials on the first pass.
/// Read time only in this outer loop and stamp graceful shutdown with its latest instant.
/// Close on every exit, including a failed clock read; preserve the original loop error.
/// Stop responsiveness is bounded by poll_interval_ms. One thread and one run per node.
pub fn run(io: std.Io, self: *node_mod.Node, stop: *const node_mod.Stop) Error!void {
    // Register cleanup before the clock: creation already owns an open descriptor.
    var at: ?Instant = null;
    errdefer windDown(io, self, at);
    var dialled = false;
    while (true) {
        const now = try instantOf(io);
        at = now;
        if (stop.expired(now)) {
            try close_mod.close(io, self, now, node_mod.generator(self));
            break;
        }
        // A preexisting stop must close without starting any dials.
        if (!dialled) {
            dialled = true;
            try start(self, now, node_mod.generator(self));
        }
        _ = try step(io, self, now, node_mod.generator(self));
        try wait(io, self, node_config.poll_interval_ms);
    }
}

/// Clean up a failed loop without replacing its error; report graceful-close failures.
/// With a supplied instant, attempt bounded graceful shutdown under cancellation protection,
/// restoring the previous protection afterward. Always dispose any remaining open state.
/// A null instant skips graceful close rather than inventing a close timestamp.
pub fn windDown(io: std.Io, self: *node_mod.Node, at: ?Instant) void {
    if (at) |stamp| {
        const protection = io.swapCancelProtection(.blocked);
        defer _ = io.swapCancelProtection(protection);
        // Cleanup reports its own failure without replacing the loop's original error.
        close_mod.close(io, self, stamp, node_mod.generator(self)) catch |err| std.log.err(
            "node {f} could not be closed gracefully after its loop ended: {t}",
            .{ node_mod.nodeId(self), err },
        );
    }
    if (self.accept.shutdown.phase != .closed) dispose(self);
}

fn relay(self: *node_mod.Node, at: Instant, random: std.Random) Error!bool {
    return switch (self.config.relay.role) {
        .off => false,
        .serve => try relay_admit.serve(self, at, random),
        .client => try relay_client.converse(self, at, random),
    };
}

/// Read the outer driver's clock, rejecting instants the transport cannot represent.
pub fn instantOf(io: std.Io) Error!Instant {
    const stamp = std.Io.Clock.awake.now(io);
    return std.math.cast(Instant, stamp.nanoseconds) orelse error.InstantOutOfRange;
}
