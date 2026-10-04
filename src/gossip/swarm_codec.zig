//! The membership half of the gossip wire: `topic::Message::Swarm`, which is
//! upstream's `hyparview::Message` and its six arms.
//!
//! Split out of `codec.zig` by responsibility, not by convenience: this module
//! owns the arms that carry peers and their contact data, and it imports only
//! `postcard` and the message types. The tag table it writes is upstream's
//! declaration order, because a postcard discriminant is an arm's position.
//! See `codec.zig` for the provenance, the 1373 captured frames these layouts
//! were checked against, and the framing this module's output goes inside.
//!
//! Sources, all in `n0-computer/iroh-gossip` 0.101.0: `src/proto/hyparview.rs`
//! for the six arms and `Priority`, and `src/proto/topic.rs` for the envelope.
//! The capture is `vector-captures/gossip-upstream-gaps` (run_seed 1): 479
//! `Shuffle`, 360 `Neighbor`, 188 `Join`, 104 `ForwardJoin`, 80
//! `ShuffleReply` and 10 `Disconnect`, all of which decode here with no byte
//! left over.
//!
//! # `Disconnect` carries a second bool nothing reads
//!
//! Upstream's `Disconnect { alive, _respond }` marks `_respond` obsolete and
//! keeps it for wire compatibility. It is written as `false` — the capture
//! carries `false` in all ten frames — and read for its position and nothing
//! else. Dropping it shifts every later byte and leaves the receiver reading
//! `alive` as the pair; ignoring it on the way in would silently repair a frame
//! a peer can send wrong.
//!
//! # A decoded slice borrows the reader's input
//!
//! A `Join`'s data, a `Neighbor`'s data and each `PeerInfo`'s data point into
//! the buffer behind the reader. Nothing is copied, so nothing allocates, and
//! the borrow lasts until that buffer is overwritten or dropped — not until the
//! next decode. A driver that queues a decoded message across another decode
//! must copy, exactly as `plumtree.Actions` says of its own outputs.

const std = @import("std");
const postcard = @import("../wire/postcard.zig");
const key = @import("../base/key.zig");
const hyparview = @import("hyparview.zig");

const NodeId = key.NodeId;
const PeerInfo = hyparview.PeerInfo;
const PeerInfos = hyparview.PeerInfos;
const SwarmMessage = hyparview.SwarmMessage;

/// `hyparview::Message`, upstream declaration order. The arm order *is* the
/// wire, and the capture carries every one of these six arms.
pub const SwarmTag = enum(u32) {
    join = 0,
    forward_join = 1,
    shuffle = 2,
    shuffle_reply = 3,
    neighbor = 4,
    disconnect = 5,
};

/// Every way this module refuses. `postcard.Error` is included rather than
/// restated: a varint that never ends is a refusal a peer can provoke like any
/// other, and this module adds only the two rules of its own.
pub const Error = postcard.Error || error{
    /// A peer list longer than `hyparview.max_shuffle_nodes`. The frame could
    /// carry the entries; the inline list this decodes into could not.
    ShuffleNodeListTooLong,
    /// A node id that is not a canonical curve point. Upstream does not check
    /// it; `key.NodeId` insists, and a `NodeId` this module invents is one a
    /// caller may sort, compare and verify a signature against.
    NotANodeId,
};

/// One `Swarm` payload: the tag and then the arm's fields.
pub fn encodeSwarm(writer: *postcard.Writer, message: SwarmMessage) Error!void {
    switch (message) {
        .join => |data| {
            try writer.writeVariant(SwarmTag.join);
            try encodePeerData(writer, data);
        },
        .forward_join => |join| {
            try writer.writeVariant(SwarmTag.forward_join);
            try encodePeerInfo(writer, join.peer);
            try writer.writeU16(join.ttl.value);
        },
        .shuffle => |shuffle| {
            try writer.writeVariant(SwarmTag.shuffle);
            try writer.writeArray(NodeId.byte_length, &shuffle.origin.toBytes());
            try encodePeerInfos(writer, shuffle.nodes.slice());
            try writer.writeU16(shuffle.ttl.value);
        },
        .shuffle_reply => |reply| {
            try writer.writeVariant(SwarmTag.shuffle_reply);
            try encodePeerInfos(writer, reply.nodes.slice());
        },
        .neighbor => |neighbor| {
            try writer.writeVariant(SwarmTag.neighbor);
            // `hyparview.Priority` is declared high-then-low, so its own
            // discriminant is the wire one and needs no table of its own.
            try writer.writeVariant(neighbor.priority);
            try encodePeerData(writer, neighbor.data);
        },
        .disconnect => |disconnect| {
            try writer.writeVariant(SwarmTag.disconnect);
            try writer.writeBool(disconnect.alive);
            try writer.writeBool(false); // the obsolete `_respond`; see the module doc
        },
    }
}

/// One `Swarm` payload back, with every data slice borrowed from the reader's
/// input. See the module doc for how long that borrow lasts.
pub fn decodeSwarm(reader: *postcard.Reader) Error!SwarmMessage {
    return switch (try reader.readVariant(SwarmTag)) {
        .join => .{ .join = try decodePeerData(reader) },
        .forward_join => .{ .forward_join = .{
            .peer = try decodePeerInfo(reader),
            .ttl = .{ .value = try reader.readU16() },
        } },
        .shuffle => .{ .shuffle = .{
            .origin = try decodeNodeId(reader),
            .nodes = try decodePeerInfos(reader),
            .ttl = .{ .value = try reader.readU16() },
        } },
        .shuffle_reply => .{ .shuffle_reply = .{ .nodes = try decodePeerInfos(reader) } },
        .neighbor => .{ .neighbor = .{
            .priority = try reader.readVariant(hyparview.Priority),
            .data = try decodePeerData(reader),
        } },
        .disconnect => separated: {
            const alive = try reader.readBool();
            _ = try reader.readBool(); // `_respond`, validated as a bool and dropped
            break :separated .{ .alive = alive };
        },
    };
}

fn decodeNodeId(reader: *postcard.Reader) Error!NodeId {
    // The house rule for a node id off the wire, and the reason this is a
    // refusal at all: `NodeId.fromBytes` is the only constructor that checks,
    // and a `NodeId` made any other way may be 32 bytes that are not a point.
    // The 32 bytes are raw, with no length prefix in front of them: upstream's
    // non-human-readable `PublicKey` serde is exactly that.
    return NodeId.fromBytes(try reader.readArray(NodeId.byte_length)) catch error.NotANodeId;
}

fn encodePeerData(writer: *postcard.Writer, data: ?[]const u8) Error!void {
    try writer.writeOption(data != null);
    if (data) |bytes| try writer.writeBytes(bytes);
}

fn decodePeerData(reader: *postcard.Reader) Error!?[]const u8 {
    if (!try reader.readOption()) return null;
    return reader.readBytes();
}

fn encodePeerInfo(writer: *postcard.Writer, peer: PeerInfo) Error!void {
    try writer.writeArray(NodeId.byte_length, &peer.id.toBytes());
    try encodePeerData(writer, peer.data);
}

fn decodePeerInfo(reader: *postcard.Reader) Error!PeerInfo {
    return .{ .id = try decodeNodeId(reader), .data = try decodePeerData(reader) };
}

fn encodePeerInfos(writer: *postcard.Writer, list: []const PeerInfo) Error!void {
    try writer.writeLen(list.len);
    for (list) |peer| try encodePeerInfo(writer, peer);
}

fn decodePeerInfos(reader: *postcard.Reader) Error!PeerInfos {
    // The bound is proved here rather than by `readLen`, which only proves the
    // frame could hold the entries: this list is inline and eight long.
    const count = try reader.readLen();
    if (count > hyparview.max_shuffle_nodes) return error.ShuffleNodeListTooLong;
    var list: PeerInfos = undefined;
    list.count = @intCast(count);
    for (list.items[0..count]) |*peer| peer.* = try decodePeerInfo(reader);
    return list;
}
