const std = @import("std");
const node_mod = @import("node.zig");
const node_protocol = @import("node_protocol.zig");
const router = @import("../router/router.zig");
const node_relay_registry = @import("node_relay_registry.zig");

pub fn laneAccept(ptr: *anyopaque, connection: router.Connection) router.AcceptError!void {
    const lane: *node_mod.Lane = @ptrCast(@alignCast(ptr));
    std.debug.assert(connection.ptr != ptr);
    const handle: *const node_protocol.Connection = @ptrCast(@alignCast(connection.ptr));
    lane.turns += 1;
    lane.answered = try lane.turn(handle);
    if (lane.answered == .finished) {
        lane.finished += 1;
        lane.owner.stats.handler_connections += 1;
    }
}

pub fn laneShutdown(ptr: *anyopaque) void {
    const lane: *node_mod.Lane = @ptrCast(@alignCast(ptr));
    const node = lane.owner;
    lane.shutdowns += 1;
    node.stats.handler_shutdowns += 1;
    if (lane.caller) |handler| {
        if (handler.shutdown) |call| call(handler.ptr);
        return;
    }
    switch (lane.standard orelse return) {
        .gossip => node.topics.clearTimers(),
        .relay => node_relay_registry.relayClose(node),
    }
}

/// Run one protocol's handler shutdown, exactly once, whatever it releases.
pub fn shutdownLane(self: *node_mod.Node, index: usize) void {
    if (self.lanes[index].shut) return;
    self.lanes[index].shut = true;
    laneShutdown(@ptrCast(&self.lanes[index]));
}
