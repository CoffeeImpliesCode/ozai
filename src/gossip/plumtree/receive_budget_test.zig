const std = @import("std");
const tree = @import("../plumtree.zig");
const codec = @import("../codec.zig");
const testNodeId = @import("test_node_id.zig").testNodeId;
const t = std.testing;

fn receiveInclusive(message: codec.Message, buffer: []u8) !codec.Message {
    // Receive permits the inclusive boundary that the strict sender cannot write.
    const length = codec.encodedLen(message);
    try t.expect(length <= codec.max_message_size);
    std.mem.writeInt(u32, buffer[0..4], @intCast(length), .big);
    var writer = @import("../../wire/postcard.zig").Writer.init(buffer[4..]);
    try codec.encodeBody(message, &writer);
    try t.expectEqual(length, writer.finish().len);
    return codec.decode(buffer[0 .. 4 + length]);
}

fn receiveBudget(length: usize, scope: tree.DeliveryScope, reject: bool) !void {
    const bytes: [4060]u8 = @splat(0x91);
    const content = bytes[0..length];
    const id = tree.MessageId.fromContent(content);
    const incoming: codec.Message = .{ .gossip = .{ .gossip = .{
        .id = id,
        .content = content,
        .scope = scope,
    } } };
    try t.expectEqual(@as(usize, if (reject) 4097 else 4096), codec.encodedLen(incoming));
    var state: tree.State = .init(try testNodeId(1), .{});
    try state.addEager(try testNodeId(2));
    try state.addEager(try testNodeId(3));
    try state.addLazy(try testNodeId(4));
    var out: tree.Actions(tree.OutEvent) = .init(t.allocator);
    defer out.deinit();
    var input: [4101]u8 = undefined;
    if (reject) {
        std.mem.writeInt(u32, input[0..4], 4097, .big);
        var writer = @import("../../wire/postcard.zig").Writer.init(input[4..]);
        try codec.encodeBody(incoming, &writer);
        try t.expectEqual(@as(usize, 4097), writer.finish().len);
    }
    // Over-budget bodies cannot decode, but the public state API must reject them too.
    const message = if (reject) incoming else try receiveInclusive(incoming, &input);
    const result = state.handle(.{ .recv_message = .{
        .from = try testNodeId(2),
        .message = message.gossip,
    } }, 0, &out);
    try t.expectEqual(@as(usize, 0), state.cache.count());
    try t.expectEqual(@as(usize, 0), state.lazy_push_queue_len);
    try t.expect(!state.dispatch_timer_scheduled);
    try t.expect(state.eager_push_peers.contains(try testNodeId(2)));
    try t.expect(state.eager_push_peers.contains(try testNodeId(3)));
    try t.expect(state.lazy_push_peers.contains(try testNodeId(4)));
    if (reject) {
        try t.expectEqual(@as(usize, 0), state.received_messages.count());
        try t.expectEqual(@as(usize, 0), out.count());
        try t.expectError(error.MessageTooLarge, result);
    } else {
        try result;
        try t.expectEqual(@as(usize, if (scope == .swarm) 1 else 0), state.received_messages.count());
        if (scope == .swarm) try t.expect(state.received_messages.contains(id));
        var delivered: usize = 0;
        var output: [4100]u8 = undefined;
        for (out.slice()) |action| {
            switch (action) {
                .emit_event => |event| {
                    try t.expectEqualSlices(u8, content, event.content);
                    try t.expectEqual(try testNodeId(2), event.delivered_from);
                    try t.expectEqualDeep(scope, event.scope);
                    delivered += 1;
                },
                .send_message => |send| {
                    const candidate: codec.Message = .{ .gossip = send.message };
                    try t.expect(codec.encodedLen(candidate) < codec.max_message_size);
                    _ = try codec.encode(candidate, &output);
                    try t.expect(send.message != .gossip);
                    try t.expect(send.message != .i_have);
                },
                .schedule_timer => |timer| {
                    try t.expect(timer.timer != .dispatch_lazy_push);
                },
            }
        }
        try t.expectEqual(@as(usize, 1), delivered);
    }
}

test "inclusive neighbors4059 delivers without derived state" {
    try receiveBudget(4059, .neighbors, false);
}

test "inclusive swarm4057 round128 delivers and records ID" {
    try receiveBudget(4057, .{ .swarm = .{ .value = 128 } }, false);
}

test "direct swarm4059 round0 body4097 rejects before mutation" {
    try receiveBudget(4059, .{ .swarm = .zero }, true);
}

test "direct neighbors4060 body4097 rejects before mutation" {
    try receiveBudget(4060, .neighbors, true);
}

test "inclusive swarm4056 round65535 wraps into writable4094 forward" {
    const content: [4056]u8 = @splat(0x95);
    const id = tree.MessageId.fromContent(&content);
    const incoming: codec.Message = .{ .gossip = .{ .gossip = .{
        .id = id,
        .content = &content,
        .scope = .{ .swarm = .{ .value = 65535 } },
    } } };
    try t.expectEqual(@as(usize, 4096), codec.encodedLen(incoming));
    var input: [4100]u8 = undefined;
    const decoded = try receiveInclusive(incoming, &input);
    var state: tree.State = .init(try testNodeId(1), .{});
    try state.addEager(try testNodeId(2));
    try state.addEager(try testNodeId(3));
    var out: tree.Actions(tree.OutEvent) = .init(t.allocator);
    defer out.deinit();
    try state.handle(.{ .recv_message = .{
        .from = try testNodeId(2),
        .message = decoded.gossip,
    } }, 0, &out);
    try t.expectEqual(@as(usize, 1), state.received_messages.count());
    try t.expect(state.received_messages.contains(id));
    try t.expectEqual(@as(usize, 1), state.cache.count());
    const cached = state.cache.get(id).?;
    try t.expectEqualSlices(u8, &content, cached.content);
    try t.expectEqual(@as(u16, 0), cached.scope.swarm.value);
    try t.expectEqual(@as(usize, 4094), codec.encodedLen(.{ .gossip = .{ .gossip = cached } }));
    var delivered: usize = 0;
    var forwards: usize = 0;
    var output: [4100]u8 = undefined;
    for (out.slice()) |action| {
        if (action == .emit_event) {
            try t.expectEqualSlices(u8, &content, action.emit_event.content);
            try t.expectEqual(try testNodeId(2), action.emit_event.delivered_from);
            try t.expectEqual(@as(u16, 65535), action.emit_event.scope.swarm.value);
            delivered += 1;
        }
        if (action == .send_message) {
            try t.expectEqual(try testNodeId(3), action.send_message.to);
            const message: codec.Message = .{ .gossip = action.send_message.message };
            try t.expectEqual(@as(usize, 4094), codec.encodedLen(message));
            const received = try codec.decode(try codec.encode(message, &output));
            try t.expectEqualSlices(u8, &content, received.gossip.gossip.content);
            try t.expectEqual(@as(u16, 0), received.gossip.gossip.scope.swarm.value);
            forwards += 1;
        }
    }
    try t.expectEqual(@as(usize, 1), delivered);
    try t.expectEqual(@as(usize, 1), forwards);
}
