//! Bounded UNI stream receive assembly. No decoded borrow escapes one synchronous feed.
const std = @import("std");
const Node = @import("node.zig").Node;
const Error = @import("node_config.zig").Error;
const bridge = @import("../transport/quic_bridge.zig");
const wire = @import("node_gossip_wire.zig");
const driver = @import("node_gossip.zig");
const codec = @import("../gossip/codec.zig");
const hyparview = @import("../gossip/hyparview.zig");
const ConnId = @import("conn_index.zig").ConnId;
const Assembly = @import("node_gossip_receive.zig").Assembly;
const ReceiveStream = @import("quic").stream.ReceiveStream;
const capacity = @import("conn_index.zig").max_peers * 4;

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
        var iterator = conn.entry.conn.streams.recv_streams.iterator();
        while (iterator.next()) |item| {
            const stream = item.value_ptr.*;
            if (stream.reset_err != null or stream.released or stream.stop_sending_err != null) {
                discardStopped(self, conn, stream);
                self.gossip.incoming.remove(conn.id(), stream.stream_id);
                continue;
            }
            const entry = self.gossip.incoming.acquire(conn.id(), stream.stream_id) orelse {
                reject(self, conn, stream);
                continue;
            };
            var bad = false;
            // Bound per-turn work; excess remains in QUIC's flow-controlled receive buffer.
            for (0..64) |_| {
                const chunk = stream.read() orelse break;
                {
                    defer self.gpa.free(chunk);
                    moved = true;
                    var offset: usize = 0;
                    while (offset < chunk.len) {
                        const progress = entry.assembly.push(chunk[offset..]) catch {
                            bad = true;
                            break;
                        };
                        offset += progress.consumed;
                        if (!entry.assembly.complete) continue;
                        if (entry.topic_index == null) {
                            const topic = entry.assembly.takeHeader() catch {
                                bad = true;
                                break;
                            };
                            entry.topic_index = topicIndex(self.config.gossip_topics, topic);
                            if (entry.topic_index == null) {
                                bad = true;
                                break;
                            }
                        } else {
                            const message = codec.decode(entry.assembly.frame()) catch {
                                bad = true;
                                break;
                            };
                            try driver.feedGossip(self, entry.topic_index.?, .{ .recv_message = .{
                                .from = peer,
                                .message = message,
                            } }, now);
                            self.gossip.received += 1;
                            entry.assembly.release();
                        }
                    }
                }
                if (bad) break;
            }
            // Drain all bytes before inspecting FIN; allReceived may be true while data remains buffered.
            const ended = stream.allReceived() and stream.peekLen() == null;
            if (ended and !bad) {
                entry.assembly.finish() catch { bad = true; };
                if (entry.topic_index == null) bad = true;
            }
            if (bad) reject(self, conn, stream);
            if (bad or ended) {
                self.gossip.incoming.remove(conn.id(), stream.stream_id);
                conn.entry.conn.streams.releaseRecvStream(stream.stream_id);
            }
        }
    }
    return moved;
}

fn reject(self: *Node, conn: bridge.Conn, stream: *ReceiveStream) void {
    stream.stopSending(0);
    conn.entry.conn.streams.releaseRecvStream(stream.stream_id);
    self.gossip.rejected += 1;
}

fn discardStopped(self: *Node, conn: bridge.Conn, stream: *ReceiveStream) void {
    // STOP_SENDING does not discard bytes already in reassembly. Read and free them on each pass,
    // then retry release after FIN/reset makes the core stream disposable.
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
