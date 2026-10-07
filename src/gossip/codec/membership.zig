//! The membership layer's half of the wire: six messages, the bytes each of
//! them occupies, and the bytes that carry them.
//!
//! Every arm here is upstream `hyparview::Message` in upstream's order, and
//! every field is upstream's field in upstream's order, because postcard writes
//! a struct as its fields in declaration order and a peer reads them back that
//! way. `tags.zig` owns the discriminants; this file owns everything after the
//! arm tag.
//!
//! The one message whose Zig form is not upstream's field for field is
//! `Disconnect`, and it is one byte: see `respond_byte`.
//!
//! The protocol-wide story — the framing, the stream header, the byte budget and
//! every divergence from upstream — is in `../codec.zig`, which is the module
//! callers import. This file is one piece of it.

const gossip = @import("../hyparview.zig");
const key = @import("../../base/key.zig");
const limits = @import("limits.zig");
const postcard = @import("../../wire/postcard.zig");
const tags = @import("tags.zig");

const NodeId = key.NodeId;
const PeerInfo = gossip.PeerInfo;
const PeerInfos = gossip.PeerInfos;
const Priority = tags.Priority;
const Swarm = tags.Swarm;
const SwarmMessage = gossip.SwarmMessage;
const Error = limits.Error;
const max_shuffle_nodes = gossip.max_shuffle_nodes;
const node_id_length = NodeId.byte_length;
const option_length = limits.option_length;
const tag_length = limits.tag_length;
const varintLen = limits.varintLen;

/// What the obsolete `respond` field of a `Disconnect` is written as.
///
/// Upstream retains the obsolete field for wire compatibility and every
/// sender writes false. State does not use it, so decode consumes the byte.
pub const respond_byte: bool = false;

/// `alive` and then the obsolete field. The two bytes are the whole message
/// upstream declares (`hyparview.rs:168-175`), so the size is fixed.
const disconnect_len: usize = 2;

/// The bytes `encode` will write for `message`, its arm tag included.
///
/// A caller sizes a buffer with this, which is why it is exact rather than an
/// upper bound: `codec_test.zig` holds it against what `encode` wrote for every
/// arm of both layers.
pub fn encodedLen(message: SwarmMessage) usize {
    return tag_length + switch (message) {
        .join => |data| peerDataLen(data),
        .forward_join => |forward| peerInfoLen(forward.peer) + varintLen(forward.ttl.value),
        .shuffle => |shuffle| shuffleLen(shuffle),
        .shuffle_reply => |reply| peerInfoListLen(reply.nodes),
        // The priority's own tag, then the optional payload a `Join` carries.
        .neighbor => |neighbor| tag_length + peerDataLen(neighbor.data),
        .disconnect => disconnect_len,
    };
}

/// Writes `message` into `writer`, its arm tag included.
///
/// `writer` is the caller's cursor and is never grown: a message that does not
/// fit is `error.BufferFull`, and it may have left a prefix behind, so a caller
/// restarts rather than resuming. Nothing in the result refers to `message`, so
/// the payload buffers it was encoded from may be reused the moment this returns.
pub fn encode(message: SwarmMessage, writer: *postcard.Writer) Error!void {
    switch (message) {
        .join => |data| {
            try writer.writeVariant(Swarm.join);
            try writeData(writer, data);
        },
        .forward_join => |forward| {
            try writer.writeVariant(Swarm.forward_join);
            try writeInfo(writer, forward.peer);
            try writer.writeU16(forward.ttl.value);
        },
        .shuffle => |shuffle| {
            try writer.writeVariant(Swarm.shuffle);
            try writer.writeArray(node_id_length, &shuffle.origin.toBytes());
            try writeInfoList(writer, shuffle.nodes);
            try writer.writeU16(shuffle.ttl.value);
        },
        .shuffle_reply => |reply| {
            try writer.writeVariant(Swarm.shuffle_reply);
            try writeInfoList(writer, reply.nodes);
        },
        .neighbor => |neighbor| {
            try writer.writeVariant(Swarm.neighbor);
            try writer.writeVariant(switch (neighbor.priority) {
                .high => Priority.high,
                .low => Priority.low,
            });
            try writeData(writer, neighbor.data);
        },
        .disconnect => |disconnect| {
            try writer.writeVariant(Swarm.disconnect);
            try writer.writeBool(disconnect.alive);
            try writer.writeBool(respond_byte);
        },
    }
}

/// Reads one membership message from `writer`, which must sit at its arm tag.
///
/// A tag with no declared arm is `error.UnknownVariant`, refused by
/// `wire/postcard.zig` before this switch sees it, so nothing is skipped and
/// nothing is defaulted: a peer that sends a message this build does not have
/// ends the read rather than continuing at the next byte.
pub fn decode(writer: *postcard.Reader) Error!SwarmMessage {
    return switch (try writer.readVariant(Swarm)) {
        .join => .{ .join = try readData(writer) },
        .forward_join => .{ .forward_join = .{
            .peer = try readInfo(writer),
            .ttl = .{ .value = try writer.readU16() },
        } },
        .shuffle => .{ .shuffle = .{
            .origin = try readNodeId(writer),
            .nodes = try readInfoList(writer),
            .ttl = .{ .value = try writer.readU16() },
        } },
        .shuffle_reply => .{ .shuffle_reply = .{ .nodes = try readInfoList(writer) } },
        .neighbor => .{ .neighbor = .{
            .priority = try readPriority(writer),
            .data = try readData(writer),
        } },
        .disconnect => blk: {
            const alive = try writer.readBool();
            // The obsolete field: read so the frame is accounted for, and
            // dropped because `Disconnect` has nowhere to put it.
            _ = try writer.readBool();
            break :blk .{ .disconnect = .{ .alive = alive } };
        },
    };
}

fn shuffleLen(shuffle: gossip.Shuffle) usize {
    const list = peerInfoListLen(shuffle.nodes);
    return node_id_length + list + varintLen(shuffle.ttl.value);
}

/// A `PeerInfo`: the peer's 32 bytes, then whatever contact data came with it.
fn peerInfoLen(info: PeerInfo) usize {
    return node_id_length + peerDataLen(info.data);
}

/// An `Option<PeerData>`: the option tag, then a length and the bytes.
///
/// `peer_data_max` is not applied here. The bound belongs to the table that
/// holds the value — `PeerDataMap.put` refuses a longer record with
/// `error.PeerDataTooLong` — and a second copy of it in the codec would be a
/// third place for the number to disagree with itself, on the way in and again on
/// the way out. The frame's own budget is the bound this file does apply.
fn peerDataLen(data: ?[]const u8) usize {
    const payload: usize = if (data) |bytes| limits.byteStringLen(bytes) else 0;
    return option_length + payload;
}

/// A `Vec<PeerInfo>`: the count, then that many records.
fn peerInfoListLen(list: PeerInfos) usize {
    var total: usize = varintLen(list.count);
    for (list.slice()) |info| total += peerInfoLen(info);
    return total;
}

fn writeData(writer: *postcard.Writer, data: ?[]const u8) Error!void {
    try writer.writeOption(data != null);
    if (data) |bytes| try writer.writeBytes(bytes);
}

fn writeInfo(writer: *postcard.Writer, info: PeerInfo) Error!void {
    try writer.writeArray(node_id_length, &info.id.toBytes());
    try writeData(writer, info.data);
}

fn writeInfoList(writer: *postcard.Writer, list: PeerInfos) Error!void {
    const items = list.slice();
    try writer.writeLen(items.len);
    for (items) |info| try writeInfo(writer, info);
}

fn readData(writer: *postcard.Reader) Error!?[]const u8 {
    if (!try writer.readOption()) return null;
    return try writer.readBytes();
}

fn readInfo(writer: *postcard.Reader) Error!PeerInfo {
    return .{ .id = try readNodeId(writer), .data = try readData(writer) };
}

fn readInfoList(writer: *postcard.Reader) Error!PeerInfos {
    const count = try writer.readLen();
    // A peer's vector count cannot index beyond the frame-fitting array.
    if (count > max_shuffle_nodes) return error.ShuffleNodeListTooLong;
    var items: [max_shuffle_nodes]PeerInfo = undefined;
    for (items[0..count]) |*info| {
        info.* = try readInfo(writer);
    }
    return PeerInfos.init(items[0..count]);
}

fn readNodeId(writer: *postcard.Reader) Error!NodeId {
    return NodeId.fromBytes(try writer.readArray(node_id_length));
}

fn readPriority(writer: *postcard.Reader) Error!gossip.Priority {
    return switch (try writer.readVariant(Priority)) {
        .high => .high,
        .low => .low,
    };
}
