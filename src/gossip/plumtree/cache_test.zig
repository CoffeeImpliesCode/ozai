//! The two caches, the sorted order of the iTree sets, and the payload bounds.

const std = @import("std");
const actions = @import("actions.zig");
const limits = @import("limits.zig");
const wire = @import("message.zig");
const message_id = @import("message_id.zig");
const tree = @import("state.zig");
const test_node_id = @import("test_node_id.zig");
const vectors = @import("blake3_vectors.zig");

const t = std.testing;

const Actions = actions.Actions;
const max_content = limits.max_content;
const Round = wire.Round;
const OutEvent = wire.OutEvent;
const MessageId = message_id.MessageId;
const State = tree.State;
const testNodeId = test_node_id.testNodeId;
const blake3Input = vectors.blake3Input;
const blake3_vectors = vectors.blake3_vectors;
const messageIdFromHex = vectors.messageIdFromHex;

// Upstream `plumtree::test::cache_is_evicted`: the payload cache holds a
// message for `message_cache_retention` and not one tick longer.
test "the payload cache is evicted on its own clock" {
    const me = try testNodeId(1);
    const peer = try testNodeId(2);
    const content = try blake3Input(2);
    defer t.allocator.free(content);
    const id = messageIdFromHex(blake3_vectors[2].hash);

    var state: State = .init(me, .{});
    var out: Actions(OutEvent) = .init(t.allocator);
    defer out.deinit();

    try state.handle(.{ .neighbor_up = peer }, 0, &out);
    try state.handle(.{ .recv_message = .{ .from = peer, .message = .{ .gossip = .{
        .id = id,
        .content = content,
        .scope = .{ .swarm = .{ .value = 1 } },
    } } } }, 0, &out);
    try t.expectEqual(@as(usize, 1), state.cache.count());

    out.clear();
    const one_interval = state.config.cache_evict_interval;
    try state.handle(.{ .timer_expired = .evict_cache }, one_interval, &out);
    try t.expectEqual(@as(usize, 1), state.cache.count());

    out.clear();
    try state.handle(
        .{ .timer_expired = .evict_cache },
        one_interval + state.config.message_cache_retention,
        &out,
    );
    try t.expectEqual(@as(usize, 0), state.cache.count());
    // The id is still remembered: `message_id_retention` is three times
    // `message_cache_retention`, which is what stops a late graft being
    // answered with a payload we have already forgotten but still recognise.
    try t.expectEqual(@as(usize, 1), state.received_messages.count());
}

// The eager and lazy sets are sorted, and a fan-out follows that order, so
// two implementations agree on who is asked first.
test "the iTree sets are sorted" {
    const me = try testNodeId(9);
    var state: State = .init(me, .{});
    var out: Actions(OutEvent) = .init(t.allocator);
    defer out.deinit();

    for ([_]u8{ 5, 1, 8, 3 }) |index| try state.addEager(try testNodeId(index));
    try t.expectEqual(@as(usize, 4), state.eagerPeers().len);
    var at: usize = 1;
    while (at < state.eagerPeers().len) : (at += 1) {
        try t.expect(state.eagerPeers()[at - 1].order(state.eagerPeers()[at]) == .lt);
    }

    const content = try blake3Input(1);
    defer t.allocator.free(content);
    out.clear();
    try state.broadcast(content, .swarm, 0, &out);
    // Four payloads and one dispatch timer, the timer first because the lazy
    // push is queued before the eager one goes out.
    try t.expectEqual(@as(usize, 5), out.count());
    try t.expect(out.at(0) == .schedule_timer);
    at = 2;
    while (at < out.count()) : (at += 1) {
        const before = out.at(at - 1).send_message.to;
        const after = out.at(at).send_message.to;
        try t.expect(before.order(after) == .lt);
    }
}

// A payload over the cache's bound is refused rather than truncated, because
// a truncated payload with the right id is a message nobody can verify.
test "a payload over the bound is refused" {
    const me = try testNodeId(1);
    const content = try t.allocator.alloc(u8, max_content + 1);
    defer t.allocator.free(content);
    @memset(content, 0x5a);

    var state: State = .init(me, .{});
    var out: Actions(OutEvent) = .init(t.allocator);
    defer out.deinit();

    try t.expectError(
        error.MessageTooLarge,
        state.broadcast(content, .swarm, 0, &out),
    );
    try t.expectEqual(@as(usize, 0), state.cache.count());
}

// The receive path bounds the payload as well, and the bound belongs in the
// cache: an oversized gossip off the wire must be refused there, never
// truncated into an entry whose id is the hash of a longer message.
test "a received payload over the bound is refused" {
    const me = try testNodeId(1);
    const content = try t.allocator.alloc(u8, max_content + 1);
    defer t.allocator.free(content);
    @memset(content, 0x5a);

    var state: State = .init(me, .{});
    var out: Actions(OutEvent) = .init(t.allocator);
    defer out.deinit();

    try t.expectError(
        error.MessageTooLarge,
        state.handle(.{ .recv_message = .{ .from = try testNodeId(2), .message = .{ .gossip = .{
            .id = MessageId.fromContent(content),
            .content = content,
            .scope = .{ .swarm = Round.zero },
        } } } }, 0, &out),
    );
    try t.expectEqual(@as(usize, 0), state.cache.count());
}

// `max_content + 1` fits a `u16` and this does not, so the two bounds are
// separate arms and this pins the narrowing one. With the ceiling alone and a
// bare `@intCast`, this length truncates to zero in an unchecked build and
// traps in this one — either way the entry ends up an empty payload under the
// hash of 65536 bytes.
test "a received payload too long to record is refused" {
    const me = try testNodeId(1);
    const content = try t.allocator.alloc(u8, std.math.maxInt(u16) + 1);
    defer t.allocator.free(content);
    @memset(content, 0x5a);

    var state: State = .init(me, .{});
    var out: Actions(OutEvent) = .init(t.allocator);
    defer out.deinit();

    try t.expectError(
        error.MessageTooLarge,
        state.handle(.{ .recv_message = .{ .from = try testNodeId(2), .message = .{ .gossip = .{
            .id = MessageId.fromContent(content),
            .content = content,
            .scope = .{ .swarm = Round.zero },
        } } } }, 0, &out),
    );
    try t.expectEqual(@as(usize, 0), state.cache.count());
}

test "received frame storage may be reused after actions are consumed" {
    const codec = @import("../codec.zig");
    const original = @as([2048]u8, @splat(0x42));
    const id = MessageId.fromContent(&original);
    var frame: [codec.max_message_size + codec.max_prefix_size]u8 = undefined;
    const encoded = try codec.encode(.{ .gossip = .{ .gossip = .{
        .id = id,
        .content = &original,
        .scope = .{ .swarm = Round.zero },
    } } }, &frame);
    var state: State = .init(try testNodeId(1), .{});
    var out: Actions(OutEvent) = .init(t.allocator);
    defer out.deinit();
    try state.handle(.{ .recv_message = .{
        .from = try testNodeId(2),
        .message = (try codec.decode(encoded)).gossip,
    } }, 0, &out);
    // Immediate emitted/forwarded actions can borrow the input. Once consumed,
    // only cache storage remains, and it must own the entire accepted content.
    out.clear();
    @memset(&frame, 0xa5);
    const cached = state.cache.get(id) orelse return error.MissingCachedContent;
    try t.expectEqualSlices(u8, &original, cached.content);
    try t.expect(cached.validate());
}
