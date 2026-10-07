const std = @import("std");
const tree = @import("../plumtree.zig");
const codec = @import("../codec.zig");
const testNodeId = @import("test_node_id.zig").testNodeId;
const t = std.testing;

fn rejectedBroadcast(length: usize) !void {
    var content: [4059]u8 = @splat(0x5a);
    const payload = content[0..length];
    var state: tree.State = .init(try testNodeId(1), .{});
    try state.addEager(try testNodeId(2));
    var out: tree.Actions(tree.OutEvent) = .init(t.allocator);
    defer out.deinit();
    const candidate: codec.Message = .{ .gossip = .{ .gossip = .{
        .id = tree.MessageId.fromContent(payload),
        .content = payload,
        .scope = .{ .swarm = .zero },
    } } };
    try t.expectEqual(length + 38, codec.encodedLen(candidate));
    var frame: [4101]u8 = undefined;
    try t.expectError(error.FrameTooLarge, codec.encode(candidate, &frame));
    const result = state.broadcast(payload, .swarm, 0, &out);
    try t.expectEqual(@as(usize, 0), state.cache.count());
    try t.expectEqual(@as(usize, 0), state.received_messages.count());
    try t.expectEqual(@as(usize, 0), out.count());
    try t.expectError(error.MessageTooLarge, result);
}

test "broadcast 4058 refuses before cache mutation" {
    try rejectedBroadcast(4058);
}

test "broadcast 4059 refuses before cache mutation" {
    try rejectedBroadcast(4059);
}

test "broadcast last writable payload remains deliverable" {
    const content: [4057]u8 = @splat(0x59);
    var state: tree.State = .init(try testNodeId(1), .{});
    try state.addEager(try testNodeId(2));
    var out: tree.Actions(tree.OutEvent) = .init(t.allocator);
    defer out.deinit();
    try state.broadcast(&content, .swarm, 0, &out);
    try t.expectEqual(@as(usize, 1), state.cache.count());
    var sent: usize = 0;
    var frame: [4100]u8 = undefined;
    for (0..out.count()) |index| {
        const action = out.at(index);
        if (action == .send_message) {
            const message: codec.Message = .{ .gossip = action.send_message.message };
            try t.expectEqual(@as(usize, 4095), codec.encodedLen(message));
            const encoded = try codec.encode(message, &frame);
            const decoded = try codec.decode(encoded);
            try t.expectEqualSlices(u8, &content, decoded.gossip.gossip.content);
            sent += 1;
        }
    }
    try t.expectEqual(@as(usize, 1), sent);
}

fn neighborsBroadcast(length: usize, reject: bool) !void {
    const bytes: [4059]u8 = @splat(0x96);
    const content = bytes[0..length];
    const message: codec.Message = .{ .gossip = .{ .gossip = .{
        .id = tree.MessageId.fromContent(content), .content = content, .scope = .neighbors,
    } } };
    try t.expectEqual(@as(usize, if (reject) 4096 else 4095), codec.encodedLen(message));
    var state: tree.State = .init(try testNodeId(1), .{});
    try state.addEager(try testNodeId(2));
    try state.addLazy(try testNodeId(3));
    var out: tree.Actions(tree.OutEvent) = .init(t.allocator);
    defer out.deinit();
    const result = state.broadcast(content, .neighbors, 0, &out);
    try t.expectEqual(@as(usize, 0), state.cache.count());
    try t.expectEqual(@as(usize, 0), state.received_messages.count());
    try t.expectEqual(@as(usize, 0), state.lazy_push_queue_len);
    try t.expect(!state.dispatch_timer_scheduled);
    if (reject) {
        try t.expectEqual(@as(usize, 0), out.count());
        try t.expectError(error.MessageTooLarge, result);
    } else {
        try result;
        try t.expectEqual(@as(usize, 1), out.count());
        const action = out.at(0);
        try t.expect(action == .send_message);
        try t.expectEqual(try testNodeId(2), action.send_message.to);
        var output: [4100]u8 = undefined;
        const candidate: codec.Message = .{ .gossip = action.send_message.message };
        try t.expectEqual(@as(usize, 4095), codec.encodedLen(candidate));
        const decoded = try codec.decode(try codec.encode(candidate, &output));
        try t.expect(decoded.gossip.gossip.scope == .neighbors);
        try t.expectEqualSlices(u8, content, decoded.gossip.gossip.content);
    }
}

test "local neighbors4058 writes full body4095 without tree state" {
    try neighborsBroadcast(4058, false);
}

test "local neighbors4059 refuses before eager output or cache" {
    try neighborsBroadcast(4059, true);
}

fn localBroadcastAdmission(scope: tree.Scope, length: usize) !void {
    // Admission must precede the first-event timer, not just the payload cache.
    const bytes: [4059]u8 = @splat(0xa1);
    var state: tree.State = .init(try testNodeId(1), .{
        .message_cache_retention = 10,
        .message_id_retention = 20,
        .cache_evict_interval = 25,
    });
    try state.addEager(try testNodeId(2));
    try state.addLazy(try testNodeId(3));
    var out: tree.Actions(tree.OutEvent) = .init(t.allocator);
    defer out.deinit();
    const rejected = bytes[0..length];
    try t.expectError(error.MessageTooLarge, state.handle(.{ .broadcast = .{
        .content = rejected, .scope = scope,
    } }, 100, &out));
    try t.expectEqual(@as(usize, 0), out.count());
    try t.expect(!state.started);
    try t.expectEqual(@as(usize, 0), state.cache.count());
    try t.expectEqual(@as(usize, 0), state.received_messages.count());
    try t.expectEqual(@as(usize, 0), state.lazy_push_queue_len);
    try t.expect(!state.dispatch_timer_scheduled);

    const content = "accepted after first local refusal";
    try state.handle(.{ .broadcast = .{
        .content = content, .scope = scope,
    } }, 100, &out);
    try t.expect(state.started);
    var evictions: usize = 0;
    var dispatches: usize = 0;
    var payloads: usize = 0;
    for (out.slice()) |action| {
        switch (action) {
            .schedule_timer => |schedule| switch (schedule.timer) {
                .evict_cache => {
                    try t.expectEqual(@as(u64, 25), schedule.after);
                    evictions += 1;
                },
                .dispatch_lazy_push => {
                    try t.expect(scope == .swarm);
                    dispatches += 1;
                },
                .send_graft => return error.UnexpectedGraftTimer,
            },
            .send_message => |send| {
                try t.expectEqual(try testNodeId(2), send.to);
                try t.expect(send.message == .gossip);
                const gossip = send.message.gossip;
                try t.expectEqual(tree.MessageId.fromContent(content), gossip.id);
                try t.expectEqualSlices(u8, content, gossip.content);
                switch (scope) {
                    .swarm => {
                        try t.expect(gossip.scope == .swarm);
                        try t.expectEqual(@as(u16, 0), gossip.scope.swarm.value);
                    },
                    .neighbors => try t.expect(gossip.scope == .neighbors),
                }
                payloads += 1;
            },
            .emit_event => return error.UnexpectedLocalDelivery,
        }
    }
    try t.expectEqual(@as(usize, 1), evictions);
    try t.expectEqual(@as(usize, 1), payloads);
    try t.expectEqual(@as(usize, if (scope == .swarm) 1 else 0), dispatches);
    try t.expectEqual(@as(usize, if (scope == .swarm) 3 else 2), out.count());
    try t.expectEqual(@as(usize, if (scope == .swarm) 1 else 0), state.cache.count());
    try t.expectEqual(
        @as(usize, if (scope == .swarm) 1 else 0),
        state.received_messages.count(),
    );

    // Fire the published sweep: a real timer maintains and rearms both caches.
    out.clear();
    try state.handle(.{ .timer_expired = .evict_cache }, 125, &out);
    try t.expectEqual(@as(usize, 0), state.cache.count());
    try t.expectEqual(@as(usize, 0), state.received_messages.count());
    try t.expectEqual(@as(usize, 1), out.count());
    const maintenance = out.at(0);
    try t.expect(maintenance == .schedule_timer);
    try t.expect(maintenance.schedule_timer.timer == .evict_cache);
    try t.expectEqual(@as(u64, 25), maintenance.schedule_timer.after);
}

test "first handle broadcast swarm4058 refuses before initialization" {
    try localBroadcastAdmission(.swarm, 4058);
}

test "first handle broadcast neighbors4059 refuses before initialization" {
    try localBroadcastAdmission(.neighbors, 4059);
}
