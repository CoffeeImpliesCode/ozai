const std = @import("std");
const swarm = @import("../hyparview.zig");
const codec = @import("../codec.zig");
const testNodeId = @import("../plumtree/test_node_id.zig").testNodeId;
const budget_peer = @import("budget_test_peer.zig");
const t = std.testing;

test "last writable ForwardJoin keeps complete contact data" {
    const contact: [4057]u8 = @splat(0x68);
    var state = try swarm.State.init(try testNodeId(1), null, .{}, .init(42));
    var out: swarm.Actions(swarm.SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    try state.handle(.{ .recv_message = .{
        .from = try testNodeId(2),
        .message = .{ .join = null },
    } }, &out);
    out.clear();
    try state.handle(.{ .recv_message = .{
        .from = try testNodeId(3),
        .message = .{ .join = &contact },
    } }, &out);
    try t.expect(state.active_view.contains(try testNodeId(3)));
    try t.expectEqualSlices(u8, &contact, state.peer_data.get(try testNodeId(3)).?.slice());
    var forwarded: usize = 0;
    var frame: [4100]u8 = undefined;
    for (out.slice()) |action| {
        if (action == .send_message) {
            const message: codec.Message = .{ .swarm = action.send_message.message };
            const encoded = try codec.encode(message, &frame);
            if (message.swarm == .forward_join) {
                try t.expectEqual(@as(usize, 4095), codec.encodedLen(message));
                const decoded = try codec.decode(encoded);
                try t.expectEqualSlices(u8, &contact, decoded.swarm.forward_join.peer.data.?);
                forwarded += 1;
            }
        }
    }
    try t.expectEqual(@as(usize, 1), forwarded);
}

fn forwardInclusive(length: usize, ttl: u16, reject: bool) !void {
    const bytes: [4058]u8 = @splat(0x86);
    const contact = bytes[0..length];
    var state = try swarm.State.init(try testNodeId(1), null, .{
        .passive_random_walk_length = .{ .value = ttl },
    }, .init(42));
    var out: swarm.Actions(swarm.SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    try budget_peer.seedNeighbor(&state, try testNodeId(2), null, &out);
    try budget_peer.seedNeighbor(&state, try testNodeId(3), null, &out);
    var input: [4100]u8 = undefined;
    const incoming: codec.Message = .{ .swarm = .{ .forward_join = .{
        .peer = .{ .id = try testNodeId(4), .data = contact },
        .ttl = .{ .value = ttl },
    } } };
    try t.expectEqual(@as(usize, 4096), codec.encodedLen(incoming));
    const decoded = try budget_peer.receiveIncoming(incoming, &input);
    try t.expectEqualSlices(u8, contact, decoded.swarm.forward_join.peer.data.?);
    var output: [4100]u8 = undefined;
    const proposed: codec.Message = .{ .swarm = .{ .forward_join = .{
        .peer = decoded.swarm.forward_join.peer,
        .ttl = .{ .value = ttl - 1 },
    } } };
    try t.expectEqual(@as(usize, if (reject) 4096 else 4095), codec.encodedLen(proposed));
    if (reject) try t.expectError(error.FrameTooLarge, codec.encode(proposed, &output));
    const rng_before = state.rng;
    const result = state.handle(.{ .recv_message = .{
        .from = try testNodeId(2),
        .message = decoded.swarm,
    } }, &out);
    if (reject) {
        try t.expectEqual(@as(usize, 0), state.passiveView().len);
        try t.expect(state.peer_data.get(try testNodeId(4)) == null);
        try t.expectEqualDeep(rng_before, state.rng);
        try t.expectEqual(@as(usize, 2), state.activeView().len);
        try t.expect(!state.pending_neighbor_requests.contains(try testNodeId(4)));
        try t.expectEqual(@as(usize, 0), out.count());
        try t.expectError(error.MessageTooLarge, result);
    } else {
        try result;
        try t.expect(state.passive_view.contains(try testNodeId(4)));
        try t.expectEqualSlices(u8, contact, state.peer_data.get(try testNodeId(4)).?.slice());
        var forwards: usize = 0;
        for (out.slice()) |action| {
            if (action == .send_message) {
                try t.expectEqualSlices(
                    u8,
                    &(try testNodeId(3)).toBytes(),
                    &action.send_message.to.toBytes(),
                );
                const message: codec.Message = .{ .swarm = action.send_message.message };
                try t.expectEqual(@as(usize, 4095), codec.encodedLen(message));
                const received = try codec.decode(try codec.encode(message, &output));
                try t.expectEqual(ttl - 1, received.swarm.forward_join.ttl.value);
                try t.expectEqualSlices(u8, contact, received.swarm.forward_join.peer.data.?);
                forwards += 1;
            }
        }
        try t.expectEqual(@as(usize, 1), forwards);
    }
}

test "inclusive ForwardJoin4058 TTL127 rejects before passive RNG output" {
    try forwardInclusive(4058, 127, true);
}

test "inclusive ForwardJoin4057 TTL128 reforward127 preserves data" {
    try forwardInclusive(4057, 128, false);
}
