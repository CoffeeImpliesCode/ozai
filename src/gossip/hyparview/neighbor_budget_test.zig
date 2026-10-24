const std = @import("std");
const swarm = @import("../hyparview.zig");
const codec = @import("../codec.zig");
const testNodeId = @import("../plumtree/test_node_id.zig").testNodeId;
const budget_peer = @import("budget_test_peer.zig");
const t = std.testing;

test "Neighbor4096 rejects Join before membership commit" {
    const own: [4090]u8 = @splat(0x83);
    const contact = [_]u8{0x84};
    var state = try swarm.State.init(
        try testNodeId(1),
        try swarm.PeerData.fromBytes(&own),
        .{},
        .init(42),
    );
    var out: swarm.Actions(swarm.SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    var input: [4100]u8 = undefined;
    const decoded = try budget_peer.receiveIncoming(.{ .swarm = .{ .join = &contact } }, &input);
    const candidate: codec.Message = .{ .swarm = .{ .neighbor = .{
        .priority = .high,
        .data = state.myData(),
    } } };
    var output: [4100]u8 = undefined;
    try t.expectEqual(@as(usize, 4096), codec.encodedLen(candidate));
    try t.expectError(error.FrameTooLarge, codec.encode(candidate, &output));
    const result = state.handle(.{ .recv_message = .{
        .from = try testNodeId(2),
        .message = decoded.swarm,
    } }, &out);
    try t.expectEqual(@as(usize, 0), state.activeView().len);
    try t.expectEqual(@as(usize, 0), state.passiveView().len);
    try t.expectEqual(@as(usize, 0), state.peer_data.count());
    try t.expectEqual(@as(usize, 0), state.pending_neighbor_requests.count());
    try t.expectEqual(@as(usize, 0), out.count());
    try t.expectEqualSlices(u8, &own, state.myData().?);
    try t.expectError(error.MessageTooLarge, result);
}

test "Neighbor4095 accepts tiny Join with full own4089 data" {
    const own: [4089]u8 = @splat(0x8c);
    const contact = [_]u8{0x8d};
    var state = try swarm.State.init(
        try testNodeId(1),
        try swarm.PeerData.fromBytes(&own),
        .{},
        .init(42),
    );
    var out: swarm.Actions(swarm.SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    var input: [4100]u8 = undefined;
    const decoded = try budget_peer.receiveIncoming(.{ .swarm = .{ .join = &contact } }, &input);
    try state.handle(.{ .recv_message = .{
        .from = try testNodeId(2),
        .message = decoded.swarm,
    } }, &out);
    try t.expect(state.active_view.contains(try testNodeId(2)));
    try t.expect(state.pending_neighbor_requests.contains(try testNodeId(2)));
    try t.expectEqualSlices(u8, &contact, state.peer_data.get(try testNodeId(2)).?.slice());
    var output: [4100]u8 = undefined;
    var neighbors: usize = 0;
    for (out.slice()) |action| {
        if (action == .send_message) {
            const message: codec.Message = .{ .swarm = action.send_message.message };
            try t.expect(message.swarm == .neighbor);
            try t.expectEqual(@as(usize, 4095), codec.encodedLen(message));
            const received = try codec.decode(try codec.encode(message, &output));
            try t.expectEqualSlices(u8, &own, received.swarm.neighbor.data.?);
            neighbors += 1;
        }
    }
    try t.expectEqual(@as(usize, 1), neighbors);
}
