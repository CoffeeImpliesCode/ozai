//! The gossip send path: a message the layer asked to be sent, encoded by the
//! project codec and written on the connection that peer is spoken on.
//!
//! `node.zig`'s module doc named this gap and named the call that closes it.
//! `gossip/codec.zig` was a production wire codec with its own tests and fuzz
//! target, and nothing in `src/node/` called it, so every `send_message`
//! stopped at a counter and a name. This file is that call — `codec.encode`,
//! once, on the message the layer produced, into a frame this node's own
//! stream carries — and the codec is the only encoder of a gossip message
//! anywhere in the tree.
//!
//! # What "the connection table" is, here
//!
//! Three tables, each with one job, none of them a second copy of another:
//!
//! - `conn_index.ConnIndex` — peer to connection id. That module's own doc
//!   describes the role: a bounded directory "held by the node and asked once
//!   per send", and this is the once-per-send.
//! - `Streams` below — connection id to the stream its frames go out on,
//!   opened on the first frame owed on a connection and kept for its life.
//! - `Node.map` — the addresses, which name nobody on a direct path
//!   (`transport/dial.zig`'s own note on `ownerOf`).
//!
//! # Which peer a connection belongs to
//!
//! `learn` is that turn, and it walks the core's own connection table whenever
//! the node runs its gossip pass. The bridge publishes a peer's *address*
//! (`bridge_conn.Conn`) and not its identity, so the node id comes off the
//! handshake: `peerNodeId` is the accessor `transport/dial.zig`'s module doc
//! names for exactly this question — "a dialled connection names its peer by
//! node id, `tls13_hs.?.peerNodeId()`" — and `test/protocol_loopback_test.zig`
//! reads it on both ends of a link. A `Conn.peerNodeId` on the bridge is the
//! seam that would take that read out of this file; `vendor/quic` is unchanged
//! either way.
//!
//! # Every refusal is named, and no refusal fails a pass
//!
//! `Outcome` is exhaustive over the ways a frame can fail to reach a stream,
//! and `Wire.refused` counts each one under its own name. That is
//! `AGENTS.md` §2's fail-closed answered where the decisions are made: one
//! peer that cannot be written to is a fact about that peer and not a fault of
//! the node, so it is counted and named rather than raised. The caller in
//! `node_gossip.feedGossip` puts the peer's name in the ring whatever the
//! answer was, so a refused peer is a named peer.
//!
//! # One pass late on the wire, and why it stays that way
//!
//! `Node.step` runs the gossip pass after `node_transport.drain`, so a frame
//! written here is collected by the core now and put on the wire by the next
//! pass's drain. The relay pass sits *before* `drain` for the round trip it
//! saves (`node.zig`'s module doc, "The relay, and where it sits in the
//! loop"), and the gossip pass cannot move there: `expire` runs after `drain`
//! and feeds the layer its `peer_disconnected`, so a gossip pass in front of
//! it would run before the peers that pass exists to tell it about had gone.
//! One pass of a local loop is the whole of the cost.
//!
//! # What this file does not write
//!
//! **No stream header.** `codec.encodeStreamHeader` needs a `TopicId`, and a
//! node holds none: `Config` (`node_config.zig`) carries `TopicConfig` — the
//! two layers' settings — and no topic name, because upstream's topic actor is
//! identified by which actor it is and this node has exactly one. So a frame
//! is written where a stream would carry one, and a reader of this node's
//! streams is a reader of frames rather than of a header followed by frames.
//! That is the same gap `gossip_actions.zig` names from the other end —
//! nothing here maps a frame's topic onto a state — and it closes when a topic
//! id reaches `Config`, not before.

const std = @import("std");
const node_mod = @import("node.zig");
const conn_index = @import("conn_index.zig");
const node_transport = @import("node_transport.zig");

const bridge_mod = @import("../transport/quic_bridge.zig");
const base_key = @import("../base/key.zig");
const codec = @import("../gossip/codec.zig");

const Node = node_mod.Node;
const Conn = bridge_mod.Conn;
const ConnId = conn_index.ConnId;
const NodeId = base_key.NodeId;
const Stream = bridge_mod.Stream;
const max_peers = conn_index.max_peers;

/// The most room one encoded frame occupies: the codec's byte budget and the
/// length prefix in front of it. `codec/limits.zig` says why the budget is on
/// the body and not on the frame.
pub const frame_room: usize = codec.max_message_size + codec.max_prefix_size;

/// What one send was.
///
/// **One arm per way it can fail, and the failures are named rather than
/// merged** because they are different facts about different halves: the
/// codec refused the message (`frame_too_large`, `no_room`, `unencodable`),
/// the directory could not name a connection (`no_route`,
/// `not_established`), or the transport could not carry the frame
/// (`no_stream_room`, `core_refused`). A caller that reads only `sent` cannot
/// tell a peer that never answered from a message this node could not write,
/// and an operator reading only a total could not either.
pub const Outcome = enum {
    /// The codec wrote the frame and the stream took it.
    sent,
    /// The directory names no connection for this peer, or names one the core
    /// has finished with. **The entry is dropped** when it is the second: a
    /// directory pointing at a connection the core has freed is a peer whose
    /// every later send would refuse the same way.
    no_route,
    /// The connection is live and has not finished its handshake, so it holds
    /// no stream grant and there is no stream to write on. A later pass gets a
    /// different answer, which is why this is a refusal and not an error.
    not_established,
    /// The core would not open a stream on it: the peer has granted no more
    /// bidirectional streams than this end has already used.
    no_stream_room,
    /// The codec refused the message over its own byte budget
    /// (`error.FrameTooLarge`). Nothing was written.
    frame_too_large,
    /// This node's frame room cannot hold the frame (`error.BufferFull`).
    /// Nothing was written and nothing was truncated: a truncated frame is a
    /// frame the peer decodes as a different message.
    no_room,
    /// Some other refusal the codec named. It is logged by name before the
    /// counter moves, so the reason is never only a number.
    unencodable,
    /// The core refused the bytes or the stream. The bridge has already
    /// logged its own answer, and it is the one failure here that is a fault
    /// rather than a fact about the peer.
    core_refused,
};

/// How many sends each refusal stopped. One field per `Outcome` other than
/// `.sent`, and a field rather than an array indexed by `@intFromEnum` so a
/// reader does not have to count enum arms to find the number it is reading.
pub const Refused = struct {
    /// See `Outcome.no_route`.
    no_route: u64 = 0,
    /// See `Outcome.not_established`.
    not_established: u64 = 0,
    /// See `Outcome.no_stream_room`.
    no_stream_room: u64 = 0,
    /// See `Outcome.frame_too_large`.
    frame_too_large: u64 = 0,
    /// See `Outcome.no_room`.
    no_room: u64 = 0,
    /// See `Outcome.unencodable`.
    unencodable: u64 = 0,
    /// See `Outcome.core_refused`.
    core_refused: u64 = 0,
};

/// The node's gossip send state: the directory, the streams, the frame room,
/// and what the send path did with them.
///
/// Every field is a value this node owns and every one of them is storage, so
/// there is nothing to release and `Node.deinit` needs no answer from here.
pub const Wire = struct {
    /// Peer to connection. See the module doc.
    conns: conn_index.ConnIndex(max_peers) = conn_index.ConnIndex(max_peers).init(),
    /// Connection to the stream its frames go out on.
    streams: Streams = .{},
    /// Where a frame is encoded. Never grown: `room` is the part of it a frame
    /// may use.
    frame: [frame_room]u8 = undefined,
    /// How much of `frame` a frame may occupy. It is `frame_room` unless a
    /// caller narrows it, and narrowing is the only thing a caller may do with
    /// it — a message that does not fit is `Outcome.no_room`, never a
    /// truncation.
    ///
    /// **The state machines' own bounds keep this ceiling from being reached
    /// by a message they produce.** The widest is a `Shuffle` at
    /// `max_shuffle_nodes` records of `peer_data_max` bytes each — about
    /// 2.3 KiB against a 4 KiB budget — so `frame_too_large` is a bound the
    /// layers below this one hold rather than one this file enforces, and
    /// `node.zig`'s refusal test narrows the room to reach `no_room` at all.
    room: usize = frame_room,
    /// Frames written to a stream, and the bytes they were.
    sent: u64 = 0,
    bytes: u64 = 0,
    /// Sends that did not happen, by name. `sent` and these add up to every
    /// `send_message` the layer produced, which is what keeps the node's
    /// `gossip_membership_asked` and `gossip_broadcast_asked` honest: those
    /// count what was asked for, these say what became of each ask.
    refused: Refused = .{},
};

/// Bind every connection this node holds to the peer whose identity its
/// handshake proved.
///
/// A connection with no handshake answer is left alone rather than guessed
/// at, and a bind `conn_index` refuses is left unbound: a node with more live
/// connections than the directory's bound routes the first `max_peers` of them
/// and refuses the rest by name, which is the same answer a full directory
/// gives anywhere else in this project.
pub fn learn(self: *Node) void {
    var index: usize = 0;
    while (self.bridge.connectionAt(index)) |conn| : (index += 1) {
        if (!conn.established()) continue;
        const peer = peerOf(conn) orelse continue;
        const bound = self.gossip.conns.bind(peer, conn.id()) catch continue;
        switch (bound) {
            .fresh => {},
            // The connection this peer was on is one this node has stopped
            // using, and the stream it was written on belongs to it.
            .replaced => |displaced| self.gossip.streams.forget(displaced),
        }
    }
}

/// Forget a peer, and with it the stream its connection was written on.
///
/// This is the only way a peer leaves the directory, and `conn_index.remove`'s
/// own rule is why: a peer leaves because a caller said so, and the caller
/// learns which connection it had to finish with.
pub fn forget(self: *Node, peer: NodeId) void {
    const conn = self.gossip.conns.remove(peer) orelse return;
    self.gossip.streams.forget(conn);
}

/// Encode `message` and write it on the connection `to` is spoken on.
///
/// The codec is the only encoder here: the frame is `codec.encode`'s own
/// output, length prefix included, and nothing in this tree writes around it.
/// Nothing is allocated and no clock is read; `io` is not a parameter because
/// this does no I/O of its own — the bytes go into the core's stream buffer
/// and the socket is written by the next pass's drain.
pub fn send(self: *Node, to: NodeId, message: codec.Message) Outcome {
    const room = self.gossip.frame[0..self.gossip.room];
    const bytes = codec.encode(message, room) catch |err| return refuse(self, encoded(err));
    var routed = route(self, to);
    switch (routed) {
        .refused => |reason| return refuse(self, reason),
        .stream => |*stream| stream.write(bytes) catch return refuse(self, .core_refused),
    }
    self.gossip.sent += 1;
    self.gossip.bytes += bytes.len;
    return .sent;
}

/// The stream `to` is spoken on, opened on the first frame owed on its
/// connection.
///
/// **A connection the core has swept is dropped from the directory rather than
/// refused against.** The core frees the entry in the sweep that runs at the
/// top of the next pass, so a handle taken from one would be a pointer into
/// freed memory — the fault `conn_index.ConnId`'s own doc refuses a pointer
/// for. Answering `no_route` and dropping the entry keeps both halves true:
/// this node never writes to a connection that is gone, and a peer it can no
/// longer reach stops being one it claims to reach.
fn route(self: *Node, to: NodeId) union(enum) { stream: Stream, refused: Outcome } {
    const id = self.gossip.conns.connFor(to) orelse return .{ .refused = .no_route };
    if (self.gossip.streams.find(id)) |stream| return .{ .stream = stream };
    const conn = node_transport.connFor(self, id) orelse {
        _ = self.gossip.conns.remove(to);
        return .{ .refused = .no_route };
    };
    if (!conn.established()) return .{ .refused = .not_established };
    const stream = bridge_mod.Stream.open(conn) catch |err| return .{ .refused = opened(err) };
    self.gossip.streams.put(id, stream);
    return .{ .stream = stream };
}

/// What the codec's own refusal is called here.
///
/// The two it names for a frame are kept apart because they are different
/// facts: `FrameTooLarge` is the message and `BufferFull` is this node's room,
/// and both are ordinary answers an operator reads off a counter. Anything
/// else the codec refused is a fault this project has no name for, so it is
/// logged before its counter moves — a reason is never only a number.
fn encoded(err: codec.Error) Outcome {
    return switch (err) {
        error.FrameTooLarge => .frame_too_large,
        error.BufferFull => .no_room,
        else => blk: {
            std.log.warn("node: the gossip codec refused a message: {t}", .{err});
            break :blk .unencodable;
        },
    };
}

/// What a refused stream open is called here.
///
/// `NoStreamRoom` is the protocol saying "not yet" — the peer has granted no
/// more streams, which a later transport-parameter update raises — and
/// everything else is the core refusing for a reason it has already logged.
fn opened(err: bridge_mod.Error) Outcome {
    return switch (err) {
        error.NoStreamRoom => .no_stream_room,
        else => .core_refused,
    };
}

/// Count one refusal under its own name, and hand the name back.
///
/// `sent` is not a refusal and has no counter, so the arm that would move one
/// is a state this function is never called in rather than a branch that
/// quietly counts nothing.
fn refuse(self: *Node, outcome: Outcome) Outcome {
    switch (outcome) {
        .sent => unreachable,
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

/// Which node id a connection's peer proved it holds.
///
/// Null for a connection whose handshake has not finished, and null for one
/// that proved nothing — a server whose client sent no certificate answers
/// `peerNodeId` with null (`vendor/quic/src/quic/tls13.zig`'s own note on the
/// accessor). Such a peer is not routed to, and a send to it is refused by
/// name rather than written to the wrong connection.
fn peerOf(conn: Conn) ?NodeId {
    const handshake = conn.entry.conn.tls13_hs orelse return null;
    const bytes = handshake.peerNodeId() orelse return null;
    return NodeId.fromBytes(bytes) catch null;
}

/// One outbound stream per connection, opened on the first frame owed on it.
///
/// A stream is a borrowed handle into storage the core owns, so an entry here
/// is read only through `find`, and `find` is reached only after the core's
/// own connection table has answered for that connection id. `forget` is how
/// an entry leaves: a rebind and a peer going away both name the connection
/// they displace, and this drops its stream rather than leaving a handle to
/// storage nobody owns.
const Streams = struct {
    entries: [max_peers]Entry = undefined,
    /// How many of `entries` are in use. Only `[0..len]` is ever read, so an
    /// entry past it is `undefined` rather than empty.
    len: usize = 0,

    const Entry = struct {
        /// The connection this stream is on, which is the key.
        conn: ConnId,
        /// The stream frames for that connection go out on.
        stream: Stream,
    };

    /// The stream `conn` writes on, or null for a connection with none yet.
    /// A scan, for `conn_index.zig`'s reason: the whole table is `max_peers`
    /// entries and the work it saves is dwarfed by the frame it is for.
    fn find(self: *const Streams, conn: ConnId) ?Stream {
        for (self.entries[0..self.len]) |entry| {
            if (entry.conn == conn) return entry.stream;
        }
        return null;
    }

    /// Keep `stream` as `conn`'s. One stream per routed connection and no
    /// more: `put` is reached only for a peer `conns` holds, `ConnIndex`
    /// refuses a bind past `max_peers`, and `forget` gives a displaced
    /// connection's slot back, so there is at most one slot per directory
    /// entry. A full table here would be a directory larger than the bound
    /// `ConnIndex` refuses to grow, which is why this asserts rather than
    /// carrying an arm nothing can reach.
    fn put(self: *Streams, conn: ConnId, stream: Stream) void {
        std.debug.assert(self.len < self.entries.len);
        self.entries[self.len] = .{ .conn = conn, .stream = stream };
        self.len += 1;
    }

    /// Give back the stream `conn` was written on. A connection with no stream
    /// here moves nothing, so a path that runs twice — a rebind naming the
    /// connection it displaced, and the `peerGone` that follows — is harmless.
    fn forget(self: *Streams, conn: ConnId) void {
        for (self.entries[0..self.len], 0..) |entry, index| {
            if (entry.conn != conn) continue;
            self.entries[index] = self.entries[self.len - 1];
            self.len -= 1;
            return;
        }
    }
};
