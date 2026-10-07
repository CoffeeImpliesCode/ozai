//! Local broadcast refusal leaves startup untouched; later acceptance expires through Node.step.
const std = @import("std");
const swarm = @import("../gossip/hyparview.zig");
const node_mod = @import("node.zig");
const bridge_peer = @import("../transport/bridge_peer.zig");
const key = @import("../base/key.zig");
const test_peer = @import("node_gossip_test_peer.zig");
const testNodeId = @import("../gossip/plumtree/test_node_id.zig").testNodeId;
const t = std.testing;

test "Node broadcast first refusal preserves timer initialization" {
    const topics = [_]swarm.TopicId{swarm.TopicId.fromBytes(@splat(0x72))};
    var secret = try key.SecretKey.fromSeed(bridge_peer.server_seed);
    defer secret.deinit();
    const node = try node_mod.Node.create(t.allocator, t.io, .{
        .secret = secret,
        .gossip_topics = &topics,
    }, 920);
    defer test_peer.closeNode(node);
    try node.gossip_topics[0].gossip.addEager(try testNodeId(2));
    const content: [4059]u8 = @splat(0x5a);
    for ([_]usize{ 4058, 4059 }) |length| {
        const result = node.broadcast(topics[0], content[0..length], bridge_peer.start);
        try t.expectEqual(@as(usize, 0), node.gossip_topics[0].gossip.cache.count());
        try t.expectEqual(@as(usize, 0), node.gossip_topics[0].gossip.received_messages.count());
        try t.expect(!node.gossip_topics[0].gossip.started);
        try t.expect(!node.gossip_topics[0].gossip.dispatch_timer_scheduled);
        try t.expectEqual(@as(usize, 0), node.timers.items.len);
        try t.expectEqual(@as(u64, 0), node.gossip.queued);
        try t.expectEqual(@as(u64, 0), node.gossip.sent);
        try t.expectEqual(@as(u64, 0), node.gossip.refused.frame_too_large);
        try t.expectError(error.MessageTooLarge, result);
    }
    try node.broadcast(topics[0], "accepted after refusal", bridge_peer.start);
    try t.expect(node.gossip_topics[0].gossip.started);
    try t.expectEqual(@as(usize, 1), node.gossip_topics[0].gossip.cache.count());
    try t.expectEqual(@as(usize, 1), node.gossip_topics[0].gossip.received_messages.count());
    try t.expect(node.gossip_topics[0].gossip.dispatch_timer_scheduled);
    var cache_timers: usize = 0;
    var dispatch_timers: usize = 0;
    var cache_due: swarm.Nanos = 0;
    // Membership timers are independent of the two promised gossip timers.
    for (node.timers.items) |pending| {
        if (pending.topic_index != 0) continue;
        switch (pending.timer) {
            .gossip => |timer| switch (timer) {
                .evict_cache => {
                    cache_timers += 1;
                    cache_due = pending.due;
                    try t.expect(pending.due > 0);
                },
                .dispatch_lazy_push => {
                    dispatch_timers += 1;
                    try t.expect(pending.due > 0);
                },
                else => {},
            },
            else => {},
        }
    }
    try t.expectEqual(@as(usize, 1), cache_timers);
    try t.expectEqual(@as(usize, 1), dispatch_timers);

    const cache_expires = @as(swarm.Nanos, @intCast(bridge_peer.start)) +
        node.gossip_topics[0].gossip.config.message_cache_retention;
    const stepped_time = @max(cache_due, cache_expires);
    const bridge = @import("../transport/quic_bridge.zig");
    const stepped_at: bridge.Instant = @intCast(stepped_time);
    try t.expect(try node.step(t.io, stepped_at, node.generator()));
    try t.expectEqual(@as(usize, 0), node.gossip_topics[0].gossip.cache.count());
    try t.expect(node.gossip_topics[0].gossip.started);
    try t.expect(!node.gossip_topics[0].gossip.dispatch_timer_scheduled);
    cache_timers = 0;
    dispatch_timers = 0;
    for (node.timers.items) |pending| {
        if (pending.topic_index != 0) continue;
        switch (pending.timer) {
            .gossip => |timer| switch (timer) {
                .evict_cache => {
                    cache_timers += 1;
                    try t.expect(pending.due > stepped_time);
                },
                .dispatch_lazy_push => dispatch_timers += 1,
                else => {},
            },
            else => {},
        }
    }
    try t.expectEqual(@as(usize, 1), cache_timers);
    try t.expectEqual(@as(usize, 0), dispatch_timers);
}
