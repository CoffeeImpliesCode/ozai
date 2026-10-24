const std = @import("std");
const tree = @import("../plumtree.zig");
const codec = @import("../codec.zig");
const testNodeId = @import("test_node_id.zig").testNodeId;
const t = std.testing;

fn receivedRoundGrowth(length: usize, round: u16) !void {
    const content: [4057]u8 = @splat(0x6a);
    const payload = content[0..length];
    const id = tree.MessageId.fromContent(payload);
    var state: tree.State = .init(try testNodeId(1), .{});
    try state.addEager(try testNodeId(3));
    try state.addLazy(try testNodeId(4));
    var out: tree.Actions(tree.OutEvent) = .init(t.allocator);
    defer out.deinit();
    try state.handle(.{ .recv_message = .{
        .from = try testNodeId(4),
        .message = .{ .i_have = try tree.IHaves.init(&.{.{
            .id = id,
            .round = .zero,
        }}) },
    } }, 0, &out);
    try t.expectEqual(@as(usize, 1), state.missing_messages_len);
    out.clear();
    const incoming: codec.Message = .{ .gossip = .{ .gossip = .{
        .id = id,
        .content = payload,
        .scope = .{ .swarm = .{ .value = round } },
    } } };
    var input: [4100]u8 = undefined;
    try t.expectEqual(@as(usize, 4095), codec.encodedLen(incoming));
    const encoded = try codec.encode(incoming, &input);
    const decoded = try codec.decode(encoded);
    try state.handle(.{ .recv_message = .{
        .from = try testNodeId(2),
        .message = decoded.gossip,
    } }, 0, &out);
    var output: [4100]u8 = undefined;
    var delivered = false;
    var grafted = false;
    var pruned = false;
    for (out.slice()) |action| switch (action) {
        .send_message => |send| {
            try t.expect(send.message != .i_have);
            switch (send.message) {
                .graft => |graft| {
                    try t.expect(graft.id == null);
                    try t.expectEqualSlices(u8, &(try testNodeId(4)).toBytes(), &send.to.toBytes());
                    grafted = true;
                },
                .prune => {
                    try t.expectEqualSlices(u8, &(try testNodeId(2)).toBytes(), &send.to.toBytes());
                    pruned = true;
                },
                else => {},
            }
            const outgoing: codec.Message = .{ .gossip = send.message };
            try t.expect(codec.encodedLen(outgoing) < codec.max_message_size);
            const written = try codec.encode(outgoing, &output);
            try t.expectEqual(codec.encodedLen(outgoing) + 4, written.len);
        },
        .emit_event => |event| {
            try t.expectEqualSlices(u8, payload, event.content);
            delivered = true;
        },
        else => {},
    };
    try t.expect(delivered);
    try t.expect(grafted);
    try t.expect(pruned);
    try t.expectEqual(@as(usize, 0), state.missing_messages_len);
    try t.expect(state.received_messages.contains(id));
    try t.expectEqual(@as(usize, 0), state.cache.count());
    try t.expectEqual(@as(usize, 0), state.lazy_push_queue_len);
}

test "received round127 growth refuses unwritable eager lazy cache" {
    try receivedRoundGrowth(4057, 127);
}

test "received round16383 growth refuses unwritable eager lazy cache" {
    try receivedRoundGrowth(4056, 16383);
}

test "Graft cannot resend an unwritable receive-capacity cache entry" {
    const content: [4057]u8 = @splat(0x6b);
    const id = tree.MessageId.fromContent(&content);
    var state: tree.State = .init(try testNodeId(1), .{});
    var out: tree.Actions(tree.OutEvent) = .init(t.allocator);
    defer out.deinit();
    try state.handle(.{ .recv_message = .{
        .from = try testNodeId(2),
        .message = .{ .gossip = .{
            .id = id,
            .content = &content,
            .scope = .{ .swarm = .{ .value = 127 } },
        } },
    } }, 0, &out);
    out.clear();
    const result = state.handle(.{ .recv_message = .{
        .from = try testNodeId(3),
        .message = .{ .graft = .{ .id = id, .round = .{ .value = 128 } } },
    } }, 0, &out);
    var frame: [4100]u8 = undefined;
    for (out.slice()) |action| {
        if (action == .send_message) {
            const message: codec.Message = .{ .gossip = action.send_message.message };
            try t.expect(codec.encodedLen(message) < codec.max_message_size);
            const encoded = try codec.encode(message, &frame);
            try t.expectEqual(codec.encodedLen(message) + 4, encoded.len);
        }
    }
    try result;
}

test "stored round128 Graft rejects before requester eager mutation" {
    const content: [4057]u8 = @splat(0x8b);
    const id = tree.MessageId.fromContent(&content);
    var state: tree.State = .init(try testNodeId(1), .{});
    try state.addLazy(try testNodeId(3));
    const cached: tree.Gossip = .{
        .id = id,
        .content = &content,
        .scope = .{ .swarm = .{ .value = 128 } },
    };
    try state.cache.put(cached, 1_000_000);
    try t.expectEqual(@as(usize, 1), state.cache.count());
    try t.expectEqualSlices(u8, &content, state.cache.get(id).?.content);
    try t.expectEqual(@as(u16, 128), state.cache.get(id).?.scope.swarm.value);
    var output: [4100]u8 = undefined;
    const candidate: codec.Message = .{ .gossip = .{ .gossip = cached } };
    try t.expectEqual(@as(usize, 4096), codec.encodedLen(candidate));
    try t.expectError(error.FrameTooLarge, codec.encode(candidate, &output));
    var out: tree.Actions(tree.OutEvent) = .init(t.allocator);
    defer out.deinit();
    const result = state.handle(.{ .recv_message = .{
        .from = try testNodeId(3),
        .message = .{ .graft = .{ .id = id, .round = .{ .value = 128 } } },
    } }, 0, &out);
    for (out.slice()) |action| {
        if (action == .send_message) {
            try t.expect(action.send_message.message != .gossip);
            const message: codec.Message = .{ .gossip = action.send_message.message };
            const written = try codec.encode(message, &output);
            try t.expectEqual(codec.encodedLen(message) + 4, written.len);
        }
    }
    try t.expect(!state.eager_push_peers.contains(try testNodeId(3)));
    try t.expect(state.lazy_push_peers.contains(try testNodeId(3)));
    try t.expectEqual(@as(usize, 1), state.cache.count());
    try t.expectEqualSlices(u8, &content, state.cache.get(id).?.content);
    try t.expectError(error.MessageTooLarge, result);
}
