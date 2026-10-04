const std = @import("std");
const node_mod = @import("node.zig");
const config = @import("node_config.zig");
const protocol = @import("node_protocol.zig");
const Error = @import("node_error.zig").Error;
const connection_close = @import("node_connection_close.zig");
const dispatch = @import("node_dispatch.zig");
const lane = @import("node_lane.zig");
const quic_conn = @import("../transport/quic_conn.zig");

/// Shut down handlers, cancel accepts, and close the endpoint in machine order.
/// Success leaves the machine closed and the descriptor shut; another close is a no-op.
/// A send failure or cancellation preserves the reached phase for a later retry.
/// Call between passes, not while the runtime is driving this node.
pub fn close(io: std.Io, self: *node_mod.Node, at: quic_conn.Instant, random: std.Random) Error!void {
    if (self.accept.shutdown.phase == .closed) return;
    try finish(self, io, at, random);
}

/// Finish from the current phase, including retrying a failed close_endpoint action.
/// Null Io or instant performs local disposal without sending connection closes.
/// A stamped QUIC close starts draining; termination still follows the core's 3-PTO timer.
pub fn finish(self: *node_mod.Node, io: ?std.Io, at: ?quic_conn.Instant, random: std.Random) Error!void {
    var steps: usize = 0;
    while (self.accept.shutdown.phase != .closed) {
        std.debug.assert(steps < config.max_close_steps);
        steps += 1;
        switch (self.accept.shutdown.phase) {
            .serving => try dispatch.feed(self, io, .close_requested, at, random),
            .draining_handlers => try dispatch.feed(self, io, .handler_finished, at, random),
            .cancelling_accepts => try dispatch.feed(self, io, .accepts_cancelled, at, random),
            .closing_endpoint => {
                // The machine emits this action only once; retry it after a failed send.
                if (!self.endpoint_closed) {
                    const owed = try dispatch.performShutdown(
                        self,
                        io,
                        .{ .action = .close_endpoint, .panicked = null },
                        at,
                        random,
                    );
                    std.debug.assert(owed != null);
                    std.debug.assert(std.meta.activeTag(owed.?.event) == .endpoint_closed);
                }
                try dispatch.feed(self, io, .endpoint_closed, at, random);
            },
            .closed => unreachable,
        }
    }
}

/// Return the configured registration count, including lanes that have been retired.
pub fn protocols(self: *const node_mod.Node) usize {
    return self.table.configured();
}

/// Read one registration's counters without copying its lane.
/// The returned ALPN remains borrowed from the caller's configured registration.
/// Return null for an index outside the configured table.
pub fn laneStats(self: *const node_mod.Node, index: usize) ?protocol.LaneStats {
    if (index >= self.table.entries.len) return null;
    const entry = &self.lanes[index];
    return .{
        .alpn = entry.alpn,
        .standard = entry.standard,
        .turns = entry.turns,
        .finished = entry.finished,
        .shutdowns = entry.shutdowns,
        .serving = self.lane_lifetimes[index].serving(),
        .live = self.accept.laneCount(index),
    };
}

/// Withdraw this ALPN before shutting its handler down, then cancel only its accepts.
/// Other lanes and their established connections continue serving.
/// Unselected handshakes observe the withdrawn offer; already-selected ones close
/// through cancellation. Call between passes while no handshake reads the offer list.
/// Return NoSuchProtocol for an unconfigured ALPN and ProtocolRetired for a shut lane.
/// Socket-send errors propagate after the state changes already performed.
pub fn retire(io: std.Io, self: *node_mod.Node, alpn: []const u8, at: quic_conn.Instant) Error!void {
    const claim = switch (self.table.dispatch(alpn)) {
        .protocol => |found| found,
        .refused => return error.NoSuchProtocol,
    };
    const index = claim.index;
    if (self.lanes[index].shut) return error.ProtocolRetired;

    // Withdraw before notifying the handler so no handshake enters a closing lane.
    _ = self.bridge.withdrawAlpn(alpn);
    const draining = self.lane_lanes.stepClaiming(alpn, .close_requested) orelse
        return error.NoSuchProtocol;
    std.debug.assert(draining.action == .shutdown_handler);
    lane.shutdownLane(self, index);

    const cancelling = self.lane_lanes.stepClaiming(alpn, .handler_finished) orelse
        return error.NoSuchProtocol;
    std.debug.assert(cancelling.action == .cancel_accepts);
    try cancelLane(io, self, at, index);

    const closed = self.lane_lanes.stepClaiming(alpn, .accepts_cancelled) orelse
        return error.NoSuchProtocol;
    std.debug.assert(closed.action == .closed);
}

pub fn cancelLane(io: std.Io, self: *node_mod.Node, at: quic_conn.Instant, index: usize) Error!void {
    var ids: [config.max_accepts]u64 = undefined;
    const count = self.accept.laneIds(index, &ids);
    var position: usize = 0;
    while (position < count) : (position += 1) {
        const id = ids[position];
        const stepped = self.accept.step(.{
            .reaped = .{ .id = id, .ended = .cancelled },
        });
        self.accept = stepped.loop;
        std.debug.assert(stepped.action == .none);
        // The removal is the work; only its result is asserted. A call inside
        // `std.debug.assert` is not evaluated in ReleaseFast or ReleaseSmall,
        // which would leave this lane's task in the map for the node's life.
        const removed = self.offered.remove(id);
        std.debug.assert(removed);
        self.stats.accepts_cancelled += 1;
        if (node_mod.connFor(self, id)) |conn| try connection_close.closeOne(io, self, conn, at);
    }
}
