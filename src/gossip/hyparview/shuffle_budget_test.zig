const std = @import("std");
const swarm = @import("../hyparview.zig");
const codec = @import("../codec.zig");
const testNodeId = @import("../plumtree/test_node_id.zig").testNodeId;
const budget_peer = @import("budget_test_peer.zig");
const t = std.testing;

fn localShuffle(length: usize, reject: bool) !void {
    const bytes: [4025]u8 = @splat(0x87);
    const contact = bytes[0..length];
    var state = try swarm.State.init(try testNodeId(1), null, .{
        .shuffle_active_view_count = 1,
        .shuffle_passive_view_count = 0,
    }, .init(42));
    var out: swarm.Actions(swarm.SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    try budget_peer.seedNeighbor(&state, try testNodeId(2), null, &out);
    try state.handle(.{ .update_peer_data = try swarm.PeerData.fromBytes(contact) }, &out);
    out.clear();
    const candidate: codec.Message = .{ .swarm = .{ .shuffle = .{
        .origin = try testNodeId(1),
        .nodes = try swarm.PeerInfos.init(&.{.{ .id = try testNodeId(1), .data = state.myData() }}),
        .ttl = state.config.shuffle_random_walk_length,
    } } };
    var output: [4100]u8 = undefined;
    try t.expectEqual(@as(usize, if (reject) 4096 else 4095), codec.encodedLen(candidate));
    if (reject) try t.expectError(error.FrameTooLarge, codec.encode(candidate, &output));
    const result = state.handle(.{ .timer_expired = .do_shuffle }, &out);
    try t.expectEqualSlices(u8, contact, state.myData().?);
    if (reject) {
        try t.expectEqual(@as(usize, 0), out.count());
        try t.expectError(error.MessageTooLarge, result);
    } else {
        try result;
        var sends: usize = 0;
        for (out.slice()) |action| {
            if (action == .send_message) {
                const message: codec.Message = .{ .swarm = action.send_message.message };
                try t.expectEqual(@as(usize, 4095), codec.encodedLen(message));
                const decoded = try codec.decode(try codec.encode(message, &output));
                try t.expectEqual(@as(u8, 1), decoded.swarm.shuffle.nodes.count);
                try t.expectEqualSlices(u8, contact, decoded.swarm.shuffle.nodes.slice()[0].data.?);
                sends += 1;
            }
        }
        try t.expectEqual(@as(usize, 1), sends);
    }
}

test "local self Shuffle4025 refuses unwritable4096 action" {
    try localShuffle(4025, true);
}

test "local self Shuffle4024 emits complete4095 action" {
    try localShuffle(4024, false);
}

fn storedReply(length: usize, reject: bool) !void {
    const bytes: [4058]u8 = @splat(0x88);
    const contact = bytes[0..length];
    var state = try swarm.State.init(try testNodeId(1), null, .{
        .passive_view_capacity = 0,
    }, .init(42));
    var out: swarm.Actions(swarm.SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    var input: [4100]u8 = undefined;
    const join = try budget_peer.receiveIncoming(.{ .swarm = .{ .join = contact } }, &input);
    try state.handle(.{ .recv_message = .{
        .from = try testNodeId(2),
        .message = join.swarm,
    } }, &out);
    try t.expectEqualSlices(u8, contact, state.peer_data.get(try testNodeId(2)).?.slice());
    out.clear();
    const reply: codec.Message = .{ .swarm = .{ .shuffle_reply = .{
        .nodes = try swarm.PeerInfos.init(&.{.{ .id = try testNodeId(2), .data = contact }}),
    } } };
    var output: [4100]u8 = undefined;
    try t.expectEqual(@as(usize, if (reject) 4096 else 4095), codec.encodedLen(reply));
    if (reject) try t.expectError(error.FrameTooLarge, codec.encode(reply, &output));
    const shuffle = try budget_peer.receiveIncoming(.{ .swarm = .{ .shuffle = .{
        .origin = try testNodeId(3),
        .nodes = try swarm.PeerInfos.init(&.{.{ .id = try testNodeId(3), .data = null }}),
        .ttl = .{ .value = 0 },
    } } }, &input);
    const result = state.handle(.{ .recv_message = .{
        .from = try testNodeId(2),
        .message = shuffle.swarm,
    } }, &out);
    try t.expectEqualSlices(u8, contact, state.peer_data.get(try testNodeId(2)).?.slice());
    try t.expectEqual(@as(usize, 1), state.activeView().len);
    if (reject) {
        try t.expectEqual(@as(usize, 0), out.count());
        try t.expectError(error.MessageTooLarge, result);
    } else {
        try result;
        var sends: usize = 0;
        for (out.slice()) |action| {
            if (action == .send_message) {
                const message: codec.Message = .{ .swarm = action.send_message.message };
                try t.expectEqual(@as(usize, 4095), codec.encodedLen(message));
                const decoded = try codec.decode(try codec.encode(message, &output));
                try t.expectEqual(@as(u8, 1), decoded.swarm.shuffle_reply.nodes.count);
                try t.expectEqualSlices(
                    u8,
                    contact,
                    decoded.swarm.shuffle_reply.nodes.slice()[0].data.?,
                );
                sends += 1;
            }
        }
        try t.expectEqual(@as(usize, 1), sends);
    }
}

test "stored4058 expired Shuffle refuses ShuffleReply4096 action" {
    try storedReply(4058, true);
}

test "stored4057 expired Shuffle emits complete ShuffleReply4095" {
    try storedReply(4057, false);
}
