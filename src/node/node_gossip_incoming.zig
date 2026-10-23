//! Bounded UNI assembly keyed by connection and stream, independent of outbound route selection.
//! Every live authenticated gossip connection retains partial input across route-learning scans.
//! Decoded slices are consumed before the frame is reused.
const std = @import("std");
const Node = @import("node.zig").Node;
const Error = @import("node_config.zig").Error;
const bridge = @import("../transport/quic_bridge.zig");
const wire = @import("node_gossip_wire.zig");
const driver = @import("node_gossip.zig");
const codec = @import("../gossip/codec.zig");
const hyparview = @import("../gossip/hyparview.zig");
const NodeId = @import("../base/key.zig").NodeId;
const conn_index = @import("conn_index.zig");
const ConnId = conn_index.ConnId;
const Assembly = @import("node_gossip_receive.zig").Assembly;
const ReceiveStream = @import("quic").stream.ReceiveStream;
const capacity = conn_index.max_peers * 4;

pub const Table = struct {
    entries: [capacity]Entry = undefined,
    len: usize = 0,
    const Entry = struct {
        conn: ConnId,
        stream_id: u64,
        topic_index: ?usize = null,
        assembly: Assembly = .{},
    };

    fn acquire(self: *Table, conn: ConnId, stream_id: u64) ?*Entry {
        for (self.entries[0..self.len]) |*entry| {
            if (entry.conn == conn and entry.stream_id == stream_id) return entry;
        }
        if (self.len == capacity) return null;
        self.entries[self.len] = .{ .conn = conn, .stream_id = stream_id };
        self.len += 1;
        return &self.entries[self.len - 1];
    }

    fn remove(self: *Table, conn: ConnId, stream_id: u64) void {
        for (self.entries[0..self.len], 0..) |entry, index| {
            if (entry.conn != conn or entry.stream_id != stream_id) continue;
            self.len -= 1;
            self.entries[index] = self.entries[self.len];
            return;
        }
    }

    pub fn forget(self: *Table, conn: ConnId) void {
        var index: usize = 0;
        while (index < self.len) {
            if (self.entries[index].conn != conn) {
                index += 1;
                continue;
            }
            self.len -= 1;
            self.entries[index] = self.entries[self.len];
        }
    }
};

pub fn receive(self: *Node, now: hyparview.Nanos) Error!bool {
    var moved = false;
    var conn_position: usize = 0;
    while (self.bridge.connectionAt(conn_position)) |conn| : (conn_position += 1) {
        if (!conn.established()) continue;
        if (!std.mem.eql(u8, conn.entry.conn.negotiatedAlpn(), "/iroh-gossip/1")) continue;
        const peer = wire.peerOf(conn) orelse continue;
        // Only authenticated peer-initiated UNI streams enter the gossip decoder.
        var iterator = conn.entry.conn.streams.recv_streams.iterator();
        while (iterator.next()) |item| {
            moved = try receiveStream(self, conn, item.value_ptr.*, peer, now) or moved;
        }
    }
    return moved;
}

fn receiveStream(
    self: *Node,
    conn: bridge.Conn,
    stream: *ReceiveStream,
    peer: NodeId,
    now: hyparview.Nanos,
) Error!bool {
    if (stream.reset_err != null or stream.released or stream.stop_sending_err != null) {
        discardStopped(self, conn, stream);
        self.gossip.incoming.remove(conn.id(), stream.stream_id);
        return false;
    }
    const entry = self.gossip.incoming.acquire(conn.id(), stream.stream_id) orelse {
        reject(self, conn, stream);
        return false;
    };
    var moved = false;
    var bad = false;
    // Bound per-turn work; further contiguous input remains in QUIC's receive buffer.
    for (0..64) |_| {
        const chunk = stream.read() orelse break;
        // FrameSorter.pop transfers a detached allocation; Assembly.push copies its bytes.
        // Codec/driver borrow the assembly, so only this defer releases the read allocation.
        // zwanzig-disable-next-line: store-violations-engine
        defer self.gpa.free(chunk);
        moved = true;
        if (!try receiveChunk(self, entry, peer, chunk, now)) {
            bad = true;
            break;
        }
    }
    // FIN may be buffered; partial frames are rejected only after unread runs are drained.
    const ended = stream.allReceived() and stream.peekLen() == null;
    if (ended and !bad) {
        entry.assembly.finish() catch |err| {
            // A truncated peer frame is a protocol rejection, not a node-wide failure.
            std.log.debug("rejecting gossip stream {d} at FIN: {s}", .{
                stream.stream_id, @errorName(err),
            });
            bad = true;
        };
        if (entry.topic_index == null) bad = true;
    }
    if (bad) reject(self, conn, stream);
    if (bad or ended) {
        self.gossip.incoming.remove(conn.id(), stream.stream_id);
        conn.entry.conn.streams.releaseRecvStream(stream.stream_id);
    }
    return moved;
}

// false tells receiveStream to STOP_SENDING, release assembly state, and count rejection.
// Driver failures still propagate; only malformed peer input takes the rejection path.
fn receiveChunk(
    self: *Node,
    entry: *Table.Entry,
    peer: NodeId,
    chunk: []const u8,
    now: hyparview.Nanos,
) Error!bool {
    var offset: usize = 0;
    while (offset < chunk.len) {
        const progress = entry.assembly.push(chunk[offset..]) catch |err| {
            std.log.debug("rejecting gossip frame assembly: {s}", .{@errorName(err)});
            return false;
        };
        offset += progress.consumed;
        if (!entry.assembly.complete) continue;
        if (entry.topic_index) |topic_index| {
            const message = codec.decode(entry.assembly.frame()) catch |err| {
                std.log.debug("rejecting gossip message: {s}", .{@errorName(err)});
                return false;
            };
            try driver.feedGossip(self, topic_index, .{ .recv_message = .{
                .from = peer,
                .message = message,
            } }, now);
            self.gossip.received += 1;
            entry.assembly.release();
        } else {
            const topic = entry.assembly.takeHeader() catch |err| {
                std.log.debug("rejecting gossip stream header: {s}", .{@errorName(err)});
                return false;
            };
            entry.topic_index = topicIndex(self.config.gossip_topics, topic) orelse return false;
        }
    }
    return true;
}

fn reject(self: *Node, conn: bridge.Conn, stream: *ReceiveStream) void {
    stream.stopSending(0);
    conn.entry.conn.streams.releaseRecvStream(stream.stream_id);
    self.gossip.rejected += 1;
}

fn discardStopped(self: *Node, conn: bridge.Conn, stream: *ReceiveStream) void {
    // STOP_SENDING does not discard buffered bytes. Consume them on each pass and retry
    // release at FIN/reset.
    for (0..64) |_| {
        const chunk = stream.read() orelse break;
        self.gpa.free(chunk);
    }
    if (stream.allReceived() and stream.peekLen() == null)
        conn.entry.conn.streams.releaseRecvStream(stream.stream_id);
}

fn topicIndex(topics: []const hyparview.TopicId, topic: hyparview.TopicId) ?usize {
    for (topics, 0..) |configured, index| {
        if (configured.eql(topic)) return index;
    }
    return null;
}

test "gossip topic dispatch rejects another subscribed name without consuming its state" {
    const a = hyparview.TopicId.fromBytes([_]u8{1} ** 32);
    const b = hyparview.TopicId.fromBytes([_]u8{2} ** 32);
    try std.testing.expectEqual(@as(?usize, 1), topicIndex(&.{ a, b }, b));
    try std.testing.expectEqual(@as(?usize, null), topicIndex(&.{a}, b));
}
