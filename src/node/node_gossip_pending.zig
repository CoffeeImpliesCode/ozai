//! Encoded action storage while authenticated bootstrap streams become writable.
const std = @import("std");
const codec = @import("../gossip/codec.zig");
const key = @import("../base/key.zig");
const NodeId = key.NodeId;
const SecretKey = key.SecretKey;
const capacity = 128;

pub const Error = error{ FrameTooLarge, BufferFull };
pub const Queue = struct {
    entries: [capacity]Entry = undefined,
    len: usize = 0,
    occupied: [capacity]bool = @splat(false),
    head: ?usize = null,
    tail: ?usize = null,

    pub const Entry = struct {
        to: NodeId,
        topic_index: usize,
        bytes: [codec.max_message_size + 4]u8 = undefined,
        len: usize,
        next: ?usize = null,
    };

    pub fn push(self: *Queue, to: NodeId, topic_index: usize, message: codec.Message) Error!void {
        if (self.len == capacity) return error.BufferFull;
        const index = std.mem.indexOfScalar(bool, &self.occupied, false) orelse unreachable;
        const entry = &self.entries[index];
        const encoded = codec.encode(message, &entry.bytes) catch |err| return switch (err) {
            error.FrameTooLarge => error.FrameTooLarge,
            else => error.BufferFull,
        };
        entry.to = to;
        entry.topic_index = topic_index;
        entry.len = encoded.len;
        entry.next = null;
        self.occupied[index] = true;
        if (self.tail) |tail| self.entries[tail].next = index else self.head = index;
        self.tail = index;
        self.len += 1;
    }

    pub fn remove(self: *Queue, index: usize) void {
        std.debug.assert(index < capacity);
        std.debug.assert(self.occupied[index]);
        var previous: ?usize = null;
        var cursor = self.head;
        while (cursor) |current| {
            if (current == index) break;
            previous = current;
            cursor = self.entries[current].next;
        }
        std.debug.assert(cursor != null);
        const next = self.entries[index].next;
        if (previous) |before| self.entries[before].next = next else self.head = next;
        if (self.tail == index) self.tail = previous;
        self.occupied[index] = false;
        self.len -= 1;
    }

    pub fn contains(self: *const Queue, peer: NodeId, topic_index: usize) bool {
        var cursor = self.head;
        while (cursor) |index| {
            const entry = &self.entries[index];
            if (entry.topic_index == topic_index and entry.to.order(peer) == .eq) return true;
            cursor = entry.next;
        }
        return false;
    }

    pub fn blockedBefore(self: *const Queue, index: usize) bool {
        const wanted = &self.entries[index];
        var cursor = self.head;
        while (cursor) |earlier| {
            if (earlier == index) return false;
            const entry = &self.entries[earlier];
            if (entry.topic_index == wanted.topic_index and
                entry.to.order(wanted.to) == .eq) return true;
            cursor = entry.next;
        }
        unreachable;
    }

    pub fn forget(self: *Queue, peer: NodeId) void {
        var cursor = self.head;
        while (cursor) |index| {
            const next = self.entries[index].next;
            if (self.entries[index].to.order(peer) == .eq) self.remove(index);
            cursor = next;
        }
    }
};

test "pending gossip copies borrowed payload and refuses bounded overflow" {
    const t = std.testing;
    const queue = try t.allocator.create(Queue);
    defer t.allocator.destroy(queue);
    queue.* = .{};
    var secret = try SecretKey.fromSeed([_]u8{5} ** 32);
    defer secret.deinit();
    var payload = [_]u8{ 1, 2, 3 };
    const plumtree = @import("../gossip/plumtree.zig");
    const message: codec.Message = .{ .gossip = .{ .gossip = .{
        .id = plumtree.MessageId.fromContent(&payload),
        .content = &payload,
        .scope = .neighbors,
    } } };
    try queue.push(secret.nodeId(), 0, message);
    payload[0] = 9;
    const entry = &queue.entries[0];
    const decoded = try codec.decode(entry.bytes[0..entry.len]);
    try t.expectEqualSlices(u8, &.{ 1, 2, 3 }, decoded.gossip.gossip.content);
    const prune: codec.Message = .{ .gossip = .{ .prune = {} } };
    for (1..capacity) |_| try queue.push(secret.nodeId(), 0, prune);
    try t.expectError(error.BufferFull, queue.push(secret.nodeId(), 0, prune));
    queue.forget(secret.nodeId());
    try t.expectEqual(@as(usize, 0), queue.len);
}

test "pending gossip keeps FIFO order per peer and topic" {
    const t = std.testing;
    const queue = try t.allocator.create(Queue);
    defer t.allocator.destroy(queue);
    queue.* = .{};
    var a = try SecretKey.fromSeed([_]u8{6} ** 32);
    defer a.deinit();
    var b = try SecretKey.fromSeed([_]u8{7} ** 32);
    defer b.deinit();
    const message: codec.Message = .{ .gossip = .{ .prune = {} } };
    try queue.push(a.nodeId(), 0, message);
    try queue.push(b.nodeId(), 0, message);
    try queue.push(a.nodeId(), 0, message);
    try t.expect(queue.blockedBefore(2));
    queue.remove(1);
    try t.expect(queue.blockedBefore(2));
    queue.remove(0);
    try t.expect(!queue.blockedBefore(2));
    try t.expectEqual(@as(?usize, 2), queue.head);
}
