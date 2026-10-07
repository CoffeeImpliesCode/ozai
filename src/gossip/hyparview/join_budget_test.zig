const std = @import("std");
const swarm = @import("../hyparview.zig");
const codec = @import("../codec.zig");
const testNodeId = @import("../plumtree/test_node_id.zig").testNodeId;
const budget_peer = @import("budget_test_peer.zig");
const t = std.testing;

test "valid Join cannot commit an unwritable ForwardJoin" {
    const contact: [4090]u8 = @splat(0x67);
    const join: codec.Message = .{ .swarm = .{ .join = &contact } };
    var frame: [4132]u8 = undefined;
    try t.expectEqual(@as(usize, 4095), codec.encodedLen(join));
    const encoded = try codec.encode(join, &frame);
    const decoded = try codec.decode(encoded);
    try t.expectEqualSlices(u8, &contact, decoded.swarm.join.?);
    var state = try swarm.State.init(try testNodeId(1), null, .{}, .init(42));
    var out: swarm.Actions(swarm.SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    try state.handle(.{ .recv_message = .{
        .from = try testNodeId(2), .message = .{ .join = null },
    } }, &out);
    out.clear();
    const forward: codec.Message = .{ .swarm = .{ .forward_join = .{
        .peer = .{ .id = try testNodeId(3), .data = decoded.swarm.join },
        .ttl = state.config.active_random_walk_length,
    } } };
    try t.expectEqual(@as(usize, 4128), codec.encodedLen(forward));
    try t.expectError(error.FrameTooLarge, codec.encode(forward, &frame));
    const result = state.handle(.{ .recv_message = .{
        .from = try testNodeId(3), .message = decoded.swarm,
    } }, &out);
    try t.expect(!state.active_view.contains(try testNodeId(3)));
    try t.expect(state.peer_data.get(try testNodeId(3)) == null);
    try t.expectEqual(@as(usize, 1), state.activeView().len);
    try t.expectEqual(@as(usize, 0), out.count());
    try t.expectError(error.MessageTooLarge, result);
}

test "receive capacity still admits Join without a forwarding recipient" {
    const contact: [4090]u8 = @splat(0x69);
    var state = try swarm.State.init(try testNodeId(1), null, .{}, .init(42));
    var out: swarm.Actions(swarm.SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    try state.handle(.{ .recv_message = .{
        .from = try testNodeId(2), .message = .{ .join = &contact },
    } }, &out);
    try t.expect(state.active_view.contains(try testNodeId(2)));
    try t.expectEqualSlices(u8, &contact, state.peer_data.get(try testNodeId(2)).?.slice());
    var frame: [4100]u8 = undefined;
    for (out.slice()) |action| {
        if (action == .send_message) {
            const message: codec.Message = .{ .swarm = action.send_message.message };
            try t.expect(message.swarm != .forward_join);
            const encoded = try codec.encode(message, &frame);
            try t.expectEqual(codec.encodedLen(message) + 4, encoded.len);
        }
    }
}

test "local Join4096 rejects before output" {
    const data: [4091]u8 = @splat(0x81);
    var state = try swarm.State.init(
        try testNodeId(1),
        try swarm.PeerData.fromBytes(&data),
        .{},
        .init(42),
    );
    var out: swarm.Actions(swarm.SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    const candidate: codec.Message = .{ .swarm = .{ .join = state.myData() } };
    var output: [4100]u8 = undefined;
    try t.expectEqual(@as(usize, 4096), codec.encodedLen(candidate));
    try t.expectError(error.FrameTooLarge, codec.encode(candidate, &output));
    const result = state.handle(.{ .request_join = try testNodeId(2) }, &out);
    try t.expectEqual(@as(usize, 0), out.count());
    try t.expectEqual(@as(usize, 0), state.activeView().len);
    try t.expectEqualSlices(u8, &data, state.myData().?);
    try t.expectError(error.MessageTooLarge, result);
}

test "local Join4095 preserves full contact data" {
    const data: [4090]u8 = @splat(0x82);
    var state = try swarm.State.init(
        try testNodeId(1),
        try swarm.PeerData.fromBytes(&data),
        .{},
        .init(42),
    );
    var out: swarm.Actions(swarm.SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    try state.handle(.{ .request_join = try testNodeId(2) }, &out);
    var output: [4100]u8 = undefined;
    var sends: usize = 0;
    for (out.slice()) |action| {
        if (action == .send_message) {
            const message: codec.Message = .{ .swarm = action.send_message.message };
            try t.expectEqual(@as(usize, 4095), codec.encodedLen(message));
            const decoded = try codec.decode(try codec.encode(message, &output));
            try t.expectEqualSlices(u8, &data, decoded.swarm.join.?);
            sends += 1;
        }
    }
    try t.expectEqual(@as(usize, 1), sends);
}

fn joinTtl(ttl: u16, reject: bool) !void {
    const contact: [4057]u8 = @splat(0x85);
    var state = try swarm.State.init(try testNodeId(1), null, .{
        .active_random_walk_length = .{ .value = ttl },
    }, .init(42));
    var out: swarm.Actions(swarm.SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    try budget_peer.seedNeighbor(&state, try testNodeId(2), null, &out);
    var input: [4100]u8 = undefined;
    const decoded = try budget_peer.receiveIncoming(.{ .swarm = .{ .join = &contact } }, &input);
    const candidate: codec.Message = .{ .swarm = .{ .forward_join = .{
        .peer = .{ .id = try testNodeId(3), .data = decoded.swarm.join },
        .ttl = .{ .value = ttl },
    } } };
    var output: [4100]u8 = undefined;
    try t.expectEqual(@as(usize, if (reject) 4096 else 4095), codec.encodedLen(candidate));
    if (reject) try t.expectError(error.FrameTooLarge, codec.encode(candidate, &output));
    const result = state.handle(.{ .recv_message = .{
        .from = try testNodeId(3), .message = decoded.swarm,
    } }, &out);
    if (reject) {
        try t.expectEqual(@as(usize, 1), state.activeView().len);
        try t.expect(!state.active_view.contains(try testNodeId(3)));
        try t.expect(state.peer_data.get(try testNodeId(3)) == null);
        try t.expect(!state.pending_neighbor_requests.contains(try testNodeId(3)));
        try t.expectEqual(@as(usize, 0), out.count());
        try t.expectError(error.MessageTooLarge, result);
    } else {
        try result;
        try t.expectEqualSlices(u8, &contact, state.peer_data.get(try testNodeId(3)).?.slice());
        var forwards: usize = 0;
        for (out.slice()) |action| {
            if (action == .send_message) {
                const message: codec.Message = .{ .swarm = action.send_message.message };
                const received = try codec.decode(try codec.encode(message, &output));
                if (received.swarm == .forward_join) {
                    try t.expectEqual(@as(usize, 4095), codec.encodedLen(message));
                    try t.expectEqual(ttl, received.swarm.forward_join.ttl.value);
                    try t.expectEqualSlices(u8, &contact, received.swarm.forward_join.peer.data.?);
                    forwards += 1;
                }
            }
        }
        try t.expectEqual(@as(usize, 1), forwards);
    }
}

test "Join4057 TTL128 rejects ForwardJoin4096 before commit" {
    try joinTtl(128, true);
}

test "Join4057 TTL127 emits complete ForwardJoin4095" {
    try joinTtl(127, false);
}

test "inclusive Join4091 remains receivable without forward recipient" {
    const contact: [4091]u8 = @splat(0x89);
    const own = [_]u8{0x8a};
    var state = try swarm.State.init(
        try testNodeId(1),
        try swarm.PeerData.fromBytes(&own),
        .{},
        .init(42),
    );
    var out: swarm.Actions(swarm.SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    var input: [4100]u8 = undefined;
    const incoming: codec.Message = .{ .swarm = .{ .join = &contact } };
    try t.expectEqual(@as(usize, 4096), codec.encodedLen(incoming));
    const decoded = try budget_peer.receiveIncoming(incoming, &input);
    try state.handle(.{ .recv_message = .{
        .from = try testNodeId(2), .message = decoded.swarm,
    } }, &out);
    try t.expect(state.active_view.contains(try testNodeId(2)));
    try t.expectEqualSlices(u8, &contact, state.peer_data.get(try testNodeId(2)).?.slice());
    var output: [4100]u8 = undefined;
    var neighbors: usize = 0;
    for (out.slice()) |action| {
        if (action == .send_message) {
            const message: codec.Message = .{ .swarm = action.send_message.message };
            try t.expect(message.swarm == .neighbor);
            const received = try codec.decode(try codec.encode(message, &output));
            try t.expectEqualSlices(u8, &own, received.swarm.neighbor.data.?);
            neighbors += 1;
        }
    }
    try t.expectEqual(@as(usize, 1), neighbors);
}
