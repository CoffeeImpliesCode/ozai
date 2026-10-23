//! Authenticated peer routing and bounded, topic-specific unidirectional gossip streams.
const std = @import("std");
const Node = @import("node.zig").Node;
const Error = @import("node_config.zig").Error;
const conn_index = @import("conn_index.zig");
const node_transport = @import("node_transport.zig");
const bridge = @import("../transport/quic_bridge.zig");
const NodeId = @import("../base/key.zig").NodeId;
const codec = @import("../gossip/codec.zig");
const incoming = @import("node_gossip_incoming.zig");
const pending = @import("node_gossip_pending.zig");
const hyparview = @import("../gossip/hyparview.zig");
const ConnId = conn_index.ConnId;
const max_peers = conn_index.max_peers;

pub const max_topics = 4;
pub const max_streams = max_peers * max_topics;
pub const max_queued_bytes = 64 * 1024;
pub const frame_room = codec.max_message_size + 4;
pub const Outcome = enum {
    sent,
    queued,
    no_route,
    not_established,
    no_stream_room,
    frame_too_large,
    no_room,
    unencodable,
    core_refused,
};
pub const Refused = struct {
    no_route: u64 = 0,
    not_established: u64 = 0,
    no_stream_room: u64 = 0,
    frame_too_large: u64 = 0,
    no_room: u64 = 0,
    unencodable: u64 = 0,
    core_refused: u64 = 0,
};
pub const StalePeers = struct {
    peers: [max_peers]NodeId = undefined,
    len: usize = 0,
};
pub const Wire = struct {
    conns: conn_index.ConnIndex(max_peers) = conn_index.ConnIndex(max_peers).init(),
    streams: Streams = .{},
    incoming: incoming.Table = .{},
    pending: pending.Queue = .{},
    queued: u64 = 0,
    frame: [frame_room + 36]u8 = undefined,
    room: usize = frame_room,
    sent: u64 = 0,
    bytes: u64 = 0,
    received: u64 = 0,
    rejected: u64 = 0,
    refused: Refused = .{},
    initial_sent: [max_topics]bool = @splat(false),
};

/// Keep one authenticated outbound route per peer until its connection closes or is swept.
/// Receive assembly and send-stream records belong to connections, not the selected peer route.
pub fn learn(self: *Node) void {
    var stream_index: usize = 0;
    while (stream_index < self.gossip.streams.len) {
        const id = self.gossip.streams.entries[stream_index].conn;
        if (node_transport.connFor(self, id)) |conn| {
            if (!conn.closed()) {
                stream_index += 1;
                continue;
            }
        }
        self.gossip.streams.forget(id);
    }
    var incoming_index: usize = 0;
    while (incoming_index < self.gossip.incoming.len) {
        const id = self.gossip.incoming.entries[incoming_index].conn;
        if (node_transport.connFor(self, id)) |conn| {
            if (!conn.closed()) {
                incoming_index += 1;
                continue;
            }
        }
        self.gossip.incoming.forget(id);
    }
    var index: usize = 0;
    while (self.bridge.connectionAt(index)) |conn| : (index += 1) {
        if (!conn.established()) continue;
        if (conn.closed()) continue;
        if (!std.mem.eql(u8, conn.entry.conn.negotiatedAlpn(), "/iroh-gossip/1")) continue;
        const peer = peerOf(conn) orelse continue;
        if (self.gossip.conns.connFor(peer)) |current| {
            if (node_transport.connFor(self, current)) |selected| {
                if (!selected.closed()) continue;
            }
        }
        // A surviving connection replaces a dead route without forgetting that peer.
        // Live connections retain their independent stream state across every scan.
        const bound = self.gossip.conns.bind(peer, conn.id()) catch continue;
        switch (bound) {
            .fresh, .replaced => {},
        }
    }
}

/// Report peers only when no live route survives after learn selects replacement connections.
pub fn takeStalePeers(self: *Node) StalePeers {
    var stale: StalePeers = .{};
    var index: usize = 0;
    while (index < self.gossip.conns.len) {
        const route = self.gossip.conns.entries[index];
        if (node_transport.connFor(self, route.conn)) |conn| {
            if (!conn.closed()) {
                index += 1;
                continue;
            }
        }
        stale.peers[stale.len] = route.peer;
        stale.len += 1;
        forget(self, route.peer);
    }
    return stale;
}

/// Forget peer routing and its streams, partial input, and pending sends.
pub fn forget(self: *Node, peer: NodeId) void {
    self.gossip.pending.forget(peer);
    const conn = self.gossip.conns.remove(peer) orelse return;
    self.gossip.streams.forget(conn);
    self.gossip.incoming.forget(conn);
}

pub fn send(self: *Node, topic_index: usize, to: NodeId, message: codec.Message) Outcome {
    if (self.gossip.pending.contains(to, topic_index)) return queue(self, topic_index, to, message);
    const outcome = trySend(self, topic_index, to, message);
    switch (outcome) {
        .no_route, .not_established, .no_stream_room, .no_room => {
            return queue(self, topic_index, to, message);
        },
        else => return outcome,
    }
}

fn queue(self: *Node, topic_index: usize, to: NodeId, message: codec.Message) Outcome {
    self.gossip.pending.push(to, topic_index, message) catch |err|
        return refuse(self, switch (err) {
            error.FrameTooLarge => .frame_too_large,
            error.BufferFull => .no_room,
        });
    self.gossip.queued += 1;
    return .queued;
}

/// Retry eligible pending actions in FIFO order per peer/topic after
/// authentication and credit updates.
pub fn flush(self: *Node) bool {
    var moved = false;
    var cursor = self.gossip.pending.head;
    while (cursor) |index| {
        const entry = &self.gossip.pending.entries[index];
        cursor = entry.next;
        if (self.gossip.pending.blockedBefore(index)) continue;
        // Queue.push stores only successfully encoded frames in owned, immutable bytes.
        // Decode failure here is corrupt internal state, never malformed peer input.
        // ZBC cannot carry successful queue encoding into this decode of owned bytes.
        // zbc-disable-next-line: catch-error-panic
        const message = codec.decode(entry.bytes[0..entry.len]) catch |err|
            std.debug.panic("corrupt encoded pending gossip frame: {s}", .{@errorName(err)});
        const outcome = trySend(self, entry.topic_index, entry.to, message);
        switch (outcome) {
            .no_route, .not_established, .no_stream_room, .no_room => {},
            else => {
                self.gossip.pending.remove(index);
                moved = true;
            },
        }
    }
    return moved;
}

fn trySend(self: *Node, topic_index: usize, to: NodeId, message: codec.Message) Outcome {
    std.debug.assert(topic_index < self.config.gossip_topics.len);
    const conn_id = self.gossip.conns.connFor(to) orelse return refuse(self, .no_route);
    const conn = node_transport.connFor(self, conn_id) orelse return refuse(self, .no_route);
    if (!conn.established()) return refuse(self, .not_established);
    const existing = self.gossip.streams.find(conn_id, topic_index);
    const prefix: usize = if (existing) |entry| (if (entry.header_sent) 0 else 36) else 36;
    const room = self.gossip.frame[prefix..][0..self.gossip.room];
    const bytes = codec.encode(message, room) catch |err| return refuse(self, switch (err) {
        error.FrameTooLarge => .frame_too_large,
        error.BufferFull => .no_room,
        else => .unencodable,
    });
    if (prefix != 0) {
        const header = codec.StreamHeader.init(self.config.gossip_topics[topic_index]);
        const encoded = codec.encodeStreamHeader(header, self.gossip.frame[0..36]) catch
            return refuse(self, .unencodable);
        std.debug.assert(encoded.len == 36);
    }
    const stream_id = if (existing) |entry| entry.stream_id else blk: {
        if (self.gossip.streams.len == max_streams) return refuse(self, .no_stream_room);
        const stream = conn.entry.conn.openUniStream() catch |err|
            return refuse(self, switch (err) {
                error.StreamLimitError => .no_stream_room,
                else => .core_refused,
            });
        self.gossip.streams.put(conn_id, topic_index, stream.stream_id);
        break :blk stream.stream_id;
    };
    const stream = conn.entry.conn.streams.getSendStream(stream_id) orelse
        return refuse(self, .core_refused);
    const outstanding = stream.write_offset -| stream.ack_offset;
    const frame_len = prefix + bytes.len;
    const outstanding_limit: u64 = @intCast(max_queued_bytes);
    if (outstanding > outstanding_limit or
        frame_len > max_queued_bytes - @as(usize, @intCast(outstanding)))
        return refuse(self, .no_room);
    stream.writeData(self.gossip.frame[0..frame_len]) catch
        return refuse(self, .core_refused);
    const sent_entry = self.gossip.streams.find(conn_id, topic_index) orelse
        std.debug.panic("sent gossip stream missing from routing table", .{});
    sent_entry.header_sent = true;
    self.gossip.sent += 1;
    self.gossip.bytes += frame_len;
    return .sent;
}

pub fn receive(self: *Node, now: hyparview.Nanos) Error!bool {
    return incoming.receive(self, now);
}

fn refuse(self: *Node, outcome: Outcome) Outcome {
    switch (outcome) {
        .sent, .queued => unreachable,
        .no_route => self.gossip.refused.no_route += 1,
        .not_established => self.gossip.refused.not_established += 1,
        .no_stream_room => self.gossip.refused.no_stream_room += 1,
        .frame_too_large => self.gossip.refused.frame_too_large += 1,
        .no_room => self.gossip.refused.no_room += 1,
        .unencodable => self.gossip.refused.unencodable += 1,
        .core_refused => self.gossip.refused.core_refused += 1,
    }
    return outcome;
}

pub fn peerOf(conn: bridge.Conn) ?NodeId {
    const handshake = conn.entry.conn.tls13_hs orelse return null;
    const bytes = handshake.peerNodeId() orelse return null;
    return NodeId.fromBytes(bytes) catch null;
}

const Streams = struct {
    entries: [max_streams]Entry = undefined,
    len: usize = 0,
    const Entry = struct {
        conn: ConnId,
        topic_index: usize,
        stream_id: u64,
        header_sent: bool = false,
    };

    fn find(self: *Streams, conn: ConnId, topic_index: usize) ?*Entry {
        for (self.entries[0..self.len]) |*entry| {
            if (entry.conn == conn and entry.topic_index == topic_index) return entry;
        }
        return null;
    }

    fn put(self: *Streams, conn: ConnId, topic_index: usize, stream_id: u64) void {
        std.debug.assert(self.len < self.entries.len);
        self.entries[self.len] = .{
            .conn = conn,
            .topic_index = topic_index,
            .stream_id = stream_id,
        };
        self.len += 1;
    }

    fn forget(self: *Streams, conn: ConnId) void {
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
