//! One endpoint of the gossip swarm: its transport, its `TopicState`, and the
//! framing bookkeeping that turns the state machine's sends into bytes.
//!
//! The framing half is here rather than in the swarm because it is this
//! node's: `readStream`, `flushStream` and `drainFrames` move the bytes of one
//! (node, peer) link — off the peer's stream into this node's receive buffer,
//! out of it into the state machine, and back the other way — and every one of
//! them reads or writes a queue this struct owns. The swarm owns when they
//! run, not what they carry.
//!
//! Everything here is written as it was: `readStream`, `flushStream` and
//! `drainFrames` were `Mesh` methods whose bodies never mention a field of the
//! struct they hang off, so they are top-level functions over `*Mesh` now and
//! nothing in their bodies changed.

const std = @import("std");
const ozai = @import("ozai");

const t = std.testing;

const gossip = ozai.gossip_hyparview;
const plumtree = ozai.gossip_plumtree;
const postcard = ozai.postcard;

const codec = @import("protocol_codec.zig");
const swarm = @import("protocol_swarm.zig");
const wire = @import("protocol_wire.zig");

const Wire = wire.Wire;
const Counters = wire.Counters;
const Conn = wire.Conn;
const NodeId = ozai.NodeId;
const SecretKey = ozai.SecretKey;

/// Nodes in the gossip mesh. More than two, and small enough that every node
/// can hold every other in its active view under the default capacity of five,
/// so a converged swarm is a statement about membership and not about capacity.
pub const node_count = 4;
pub const max_nodes = node_count;

/// How many unread bytes one link's receive buffer may hold when a round ends.
/// A bound, not a policy: over it, the reader is not keeping up, which is a
/// finding and not something to grow around.
pub const max_backlog = codec.max_frame * 64;

/// One timer either layer asked for, with the instant it comes due.
///
/// The `Timer` is a copy rather than a borrow: the union carries a `MessageId`
/// and a `NodeId` by value, so nothing here points into a state that moves.
pub const PendingTimer = struct {
    due: gossip.Nanos,
    timer: gossip.Timer,
};

// ---------------------------------------------------------------------------
// The gossip mesh
// ---------------------------------------------------------------------------

/// One endpoint of the mesh: its transport, its `TopicState`, and the framing
/// bookkeeping that turns the state machine's sends into bytes.
pub const Node = struct {
    wire: Wire,
    topic: gossip.TopicState,
    /// What this node advertises as its own contact data, and the bytes the
    /// assertions compare a peer's copy against.
    advert: []u8,
    port_buf: [6]u8 = undefined,

    /// The `Conn` a dial returned, for the peers this node dialled.
    dialled: [max_nodes]?Conn,

    /// Encoded frames waiting for a stream on the link to this peer.
    outbound: [max_nodes]std.ArrayList(u8),
    /// Bytes read off that peer's stream and not yet framed out.
    inbound: [max_nodes]std.ArrayList(u8),
    timers: std.ArrayList(PendingTimer),

    /// The first payload this node was delivered, copied out of the frame it
    /// arrived in, so a second delivery of the same payload is visible.
    delivered_content: [plumtree.max_content]u8 = undefined,
    delivered_len: usize = 0,
    stats: Counters = .{},
    frames_written: usize = 0,
    frames_read: usize = 0,
    peer_data_seen: usize = 0,
    neighbor_up: usize = 0,
    neighbor_down: usize = 0,
    delivered: usize = 0,
    duplicated: usize = 0,

    /// Stand the node up: its identity, its topic, and the wire it dials on.
    ///
    /// `pub` because `protocol_loopback_test.zig` calls it across the file
    /// boundary the split that gave this module its own name introduced.
    pub fn init(
        self: *Node,
        index: usize,
        alpn: []const u8,
        rng: gossip.Rng,
        config: gossip.TopicConfig,
        seed: u64,
    ) !void {
        var identity: [SecretKey.seed_length]u8 = @splat(0x5e);
        identity[0] = @intCast(index);
        var secret = try SecretKey.fromSeed(identity);
        // `Wire.init` copies the key: it keeps this one in `self.secret`, and
        // `Bridge.create` and `Dialer.create` each derive their own seed bytes
        // from the `Config` they are handed. So this stack copy is the one no
        // owner shares, and `defer` rather than `errdefer` is its guard — an
        // errdefer wiped a copy nothing else pointed at, and left the key live
        // in this stack slot on every run that succeeded.
        defer secret.deinit();
        self.* = .{
            .wire = undefined,
            .topic = undefined,
            .advert = undefined,
            .dialled = [_]?Conn{null} ** max_nodes,
            .outbound = [_]std.ArrayList(u8){.empty} ** max_nodes,
            .inbound = [_]std.ArrayList(u8){.empty} ** max_nodes,
            .timers = .empty,
        };
        errdefer self.deinitBuffers();
        // `expect_peer` is null: this bridge accepts from every node with a
        // higher index, and one pin cannot name three peers. The pin that is
        // enforced is the dialer's, which is per-dial, and the identity
        // assertions read it off the handshake.
        try self.wire.init(nodeName(index), index, secret, null, alpn, seed);
        // The wire is up from here, and it owns everything `Wire.init`
        // allocated: a socket, a bridge, a dialer, an address map and four
        // buffers. Every step below unwinds through it, because the only other
        // unwind this function has is the buffer list — and a config the state
        // machine refuses is an error it can return with a whole wire live.
        errdefer self.wire.deinit();

        // A `u16` port is at most five digits and `port_buf` is six, so the only
        // way `bufPrint` refuses here is a format this file owns.
        self.advert = try std.fmt.bufPrint(&self.port_buf, "{d}", .{
            self.wire.socket.address.port,
        });
        const data = try gossip.PeerData.fromBytes(self.advert);
        self.topic = try gossip.TopicState.init(self.wire.id, data, config, rng);
    }

    fn deinitBuffers(self: *Node) void {
        for (&self.outbound) |*queue| queue.deinit(t.allocator);
        for (&self.inbound) |*queue| queue.deinit(t.allocator);
        self.timers.deinit(t.allocator);
    }

    /// Take the node down: its queues and timers first, then its wire.
    ///
    /// `pub` because `protocol_swarm.zig` and `protocol_loopback_test.zig`
    /// call it across the file boundary the split gave this module its name.
    pub fn deinit(self: *Node) void {
        self.deinitBuffers();
        self.wire.deinit();
        self.* = undefined;
    }

    /// This node is the client on every link to a higher index, which is what
    /// makes the two stream ids a function of role rather than of bookkeeping.
    fn clientOf(self: *const Node, peer: usize) bool {
        return self.wire.index < peer;
    }

    /// The stream this side writes, and the one it reads.
    ///
    /// RFC 9000 §2.1: a client-initiated bidirectional stream is `4n` and a
    /// server-initiated one is `4n + 1`. One stream per side makes those ids
    /// `0` and `1`, so both ends can name both without either being told.
    fn sendStream(self: *const Node, peer: usize) u64 {
        return if (self.clientOf(peer)) 0 else 1;
    }

    fn recvStream(self: *const Node, peer: usize) u64 {
        return if (self.clientOf(peer)) 1 else 0;
    }

    /// The connection to the node at `index`.
    ///
    /// Found by the peer address on the active path rather than held: an
    /// accepted connection has no other way in, and each peer holds a distinct
    /// ephemeral port, so the port *is* the peer's identity on this mesh.
    /// `pub` because `protocol_loopback_test.zig` and `protocol_properties.zig`
    /// call it across the file boundary the split that gave this module its
    /// own name introduced.
    pub fn connTo(self: *Node, index: usize, ports: [max_nodes]u16) ?Conn {
        if (index == self.wire.index) return null;
        if (self.dialled[index]) |conn| return conn;
        var walk: usize = 0;
        while (self.wire.bridge.connectionAt(walk)) |conn| : (walk += 1) {
            const peer = conn.peer() orelse continue;
            if (peer.port == ports[index]) return conn;
        }
        return null;
    }

    /// `pub` because `protocol_loopback_test.zig` calls it across the file
    /// boundary the split that gave this module its own name introduced.
    pub fn up(self: *Node, index: usize, ports: [max_nodes]u16) bool {
        const conn = self.connTo(index, ports) orelse return false;
        return conn.established();
    }
};

pub fn nodeName(index: usize) []const u8 {
    return switch (index) {
        0 => "node-0",
        1 => "node-1",
        2 => "node-2",
        else => "node-3",
    };
}

/// Copy whatever a peer wrote on its stream into this link's receive
/// buffer. Nothing is decoded here: a stream delivers whatever chunks the
/// packets held, and a frame boundary is not a packet boundary.
pub fn readStream(mesh: *swarm.Mesh, node: *Node, peer: usize) !bool {
    const conn = node.connTo(peer, mesh.ports) orelse return false;
    if (!conn.established()) return false;
    const stream = conn.entry.conn.streams.getStream(node.recvStream(peer)) orelse
        return false;
    var moved = false;
    while (stream.recv.read()) |chunk| {
        // `read` hands the chunk over rather than lending it, and the
        // append below is its last reader. Armed ahead of the `try`, so
        // the backlog return and a refused append give it back too.
        defer t.allocator.free(chunk);
        moved = true;
        try node.inbound[peer].appendSlice(t.allocator, chunk);
        if (node.inbound[peer].items.len > max_backlog) {
            std.debug.print(
                "\n  {s} holds {d} bytes from {s} it has not framed\n",
                .{ node.wire.name, node.inbound[peer].items.len, mesh.nodes[peer].wire.name },
            );
            return error.ReceiveBacklog;
        }
    }
    return moved;
}

/// Frame out everything complete in the receive buffer and hand each frame
/// to the state machine, then write this link's queued frames onto the
/// stream.
///
/// The two halves are separate calls on purpose: a decoded message borrows
/// `mesh.frame`, so it is consumed by `feed` before the next frame is
/// copied in, and every send the state machine produced has been encoded
/// into a queue by then.
pub fn flushStream(mesh: *swarm.Mesh, node: *Node, peer: usize) !bool {
    const moved = try drainFrames(mesh, node, peer);
    if (node.outbound[peer].items.len == 0) return moved;
    const conn = node.connTo(peer, mesh.ports) orelse return moved;
    if (!conn.established()) return moved;
    const id = node.sendStream(peer);
    if (conn.entry.conn.streams.getStream(id) == null) {
        _ = try conn.entry.conn.openStream();
    }
    const stream = conn.entry.conn.streams.getStream(id) orelse return error.NoStream;
    const payload = node.outbound[peer].items;
    try stream.send.writeData(payload);
    node.frames_written += countFrames(payload);
    node.outbound[peer].clearRetainingCapacity();
    return true;
}

/// Hand every complete frame in the link's receive buffer to this node.
pub fn drainFrames(mesh: *swarm.Mesh, node: *Node, peer: usize) !bool {
    var moved = false;
    while (true) {
        const items = node.inbound[peer].items;
        if (items.len == 0) return moved;
        var reader = postcard.Reader.init(items);
        // A varint that has not finished arriving is the ordinary case of a
        // frame split across two packets, and it is not a refusal: the
        // bytes are still coming. The other two ways a `u64` varint fails
        // are not, and a peer can send one — swallowing those would park
        // the frame on the link until `max_backlog` fires rather than
        // saying what it was.
        const length = reader.readU64() catch |err| switch (err) {
            error.UnexpectedEnd => return moved,
            else => return err,
        };
        if (length > codec.max_frame) {
            std.debug.print(
                "\n  {s} was told a frame of {d} bytes from {s}\n",
                .{ node.wire.name, length, mesh.nodes[peer].wire.name },
            );
            return error.FrameTooLong;
        }
        const whole = std.math.cast(usize, length) orelse return error.FrameTooLong;
        if (whole > reader.remaining()) return moved;
        const payload = reader.buffer[reader.offset..][0..whole];
        reader.offset += whole;
        const consumed = reader.offset;
        @memcpy(mesh.frame[0..whole], payload);
        moved = true;
        node.frames_read += 1;

        _ = try swarm.feed(mesh, node, .{
            .recv_message = .{
                .from = mesh.nodes[peer].wire.id,
                .message = try codec.decodeMessage(mesh.frame[0..whole]),
            },
        }, node.wire.index);

        // Re-read the slice: `feed` may have reallocated another link's
        // queue, and this one only ever shrinks here.
        const rest = node.inbound[peer].items.len - consumed;
        @memmove(node.inbound[peer].items[0..rest], node.inbound[peer].items[consumed..]);
        node.inbound[peer].items.len = rest;
    }
}

/// How many frames a run of encoded bytes holds, for the report only. It stops
/// at the first thing it cannot read rather than refusing: it is a counter in
/// a diagnostic, not a decoder.
fn countFrames(bytes: []const u8) usize {
    var reader = postcard.Reader.init(bytes);
    var count: usize = 0;
    while (reader.remaining() > 0) {
        const length = reader.readU64() catch break;
        if (length > reader.remaining()) break;
        reader.offset += @intCast(length);
        count += 1;
    }
    return count;
}
