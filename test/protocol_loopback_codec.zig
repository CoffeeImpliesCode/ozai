//! The test-only gossip codec: one plausible postcard encoding, kept in its own
//! module so it cannot be mistaken for the project's wire format.
//!
//! # What this is not
//!
//! `src/gossip/codec.zig` is the production wire format, and it is checked
//! against 1373 frames `n0-computer/iroh-gossip` 0.101.0 emitted, captured in
//! `vector-captures/gossip-upstream-gaps`. **Nothing here agrees with it byte for
//! byte.** The clearest divergence is `DeliveryScope`: upstream tags Swarm
//! before Neighbors, and the tags below are the other way round, so a frame
//! written here is not a frame the production codec would read.
//!
//! It exists because the loopback harness needs bytes on a socket before it can
//! drive the state machines at all, and a codec is the smallest thing that
//! supplies them. Both ends of every link in that harness are driven from this
//! one file, so the inversion cannot show up there — which is the reason it is
//! written down here instead of being left to be discovered.
//!
//! # Two choices that are deliberate
//!
//! Every discriminant is an explicit tag byte rather than a union's declaration
//! order, so reordering an arm under `src/gossip/` cannot silently change these
//! bytes. And every slice a decoded message carries is borrowed out of the
//! frame it was decoded from, which is the borrow rule both gossip layers
//! document — so a caller must consume a frame inside one call, or copy.
//!
//! # Reach
//!
//! Imported by `test/protocol_loopback_test.zig` and by nothing else. This is
//! test-only code: no module under `src/` depends on it, and no golden vector
//! claims anything about its bytes.

const ozai = @import("ozai");

const gossip = ozai.gossip_hyparview;
const plumtree = ozai.gossip_plumtree;
const postcard = ozai.postcard;
const NodeId = ozai.NodeId;

/// The largest frame this codec will produce or accept.
///
/// A `Shuffle` is the biggest membership message: `max_shuffle_nodes` peer
/// records of up to `peer_data_max` bytes each, plus the fixed fields. 8 KiB
/// leaves room for every arm of both layers' message sets with the project's
/// own bounds in force, and a frame over it is reported rather than truncated.
pub const max_frame = 8 * 1024;

// ---------------------------------------------------------------------------
// The codec
// ---------------------------------------------------------------------------

/// What this codec refuses. `postcard.Error` and `KeyError` are included
/// rather than restated: a varint that does not end and a node id that is not
/// on the curve are both refusals a peer can provoke.
pub const WireError = postcard.Error || ozai.KeyError || gossip.Error || plumtree.Error ||
    error{
        /// A frame declared more bytes than `max_frame` allows.
        FrameTooLong,
        /// A tag byte this build has no arm for.
        UnknownVariant,
        /// A peer list longer than `max_shuffle_nodes`.
        PeerListTooLong,
        /// An `IHave` list longer than `max_ihaves_per_message`.
        IHaveListTooLong,
    };

/// The two arms of `hyparview.Message`, named rather than derived from the
/// union's field order.
const msg_swarm: u8 = 0;
const msg_gossip: u8 = 1;

/// The arms of `hyparview.SwarmMessage`.
const swarm_join: u8 = 0;
const swarm_forward_join: u8 = 1;
const swarm_shuffle: u8 = 2;
const swarm_shuffle_reply: u8 = 3;
const swarm_neighbor: u8 = 4;
const swarm_disconnect: u8 = 5;

/// The arms of `plumtree.Message`.
const tree_gossip: u8 = 0;
const tree_prune: u8 = 1;
const tree_graft: u8 = 2;
const tree_i_have: u8 = 3;

/// `hyparview.Priority`, as a tag byte.
const priority_high: u8 = 0;
const priority_low: u8 = 1;

/// `plumtree.DeliveryScope`, as a tag byte.
const scope_neighbors: u8 = 0;
const scope_swarm: u8 = 1;

/// Encode a protocol message into `out`, and return what it wrote.
fn encodeMessage(message: gossip.Message, out: []u8) WireError![]const u8 {
    var w = postcard.Writer.init(out);
    switch (message) {
        .swarm => |swarm| {
            try w.writeU8(msg_swarm);
            try encodeSwarm(&w, swarm);
        },
        .gossip => |tree| {
            try w.writeU8(msg_gossip);
            try encodeTree(&w, tree);
        },
    }
    return w.finish();
}

/// Decode a protocol message from `frame`.
///
/// Every slice the returned value carries is borrowed from `frame` and is only
/// valid until the caller reuses it. That is the borrow rule both gossip
/// layers document, and it is why the mesh consumes a frame inside one call.
pub fn decodeMessage(frame: []const u8) WireError!gossip.Message {
    var r = postcard.Reader.init(frame);
    return switch (try r.readU8()) {
        msg_swarm => .{ .swarm = try decodeSwarm(&r) },
        msg_gossip => .{ .gossip = try decodeTree(&r) },
        else => error.UnknownVariant,
    };
}

fn encodeSwarm(w: *postcard.Writer, message: gossip.SwarmMessage) WireError!void {
    switch (message) {
        .join => |data| {
            try w.writeU8(swarm_join);
            try encodeData(w, data);
        },
        .forward_join => |forward| {
            try w.writeU8(swarm_forward_join);
            try encodeInfo(w, forward.peer);
            try w.writeU16(forward.ttl.value);
        },
        .shuffle => |shuffle| {
            try w.writeU8(swarm_shuffle);
            try encodeId(w, shuffle.origin);
            try encodeInfos(w, shuffle.nodes);
            try w.writeU16(shuffle.ttl.value);
        },
        .shuffle_reply => |reply| {
            try w.writeU8(swarm_shuffle_reply);
            try encodeInfos(w, reply.nodes);
        },
        .neighbor => |neighbor| {
            try w.writeU8(swarm_neighbor);
            try w.writeU8(switch (neighbor.priority) {
                .high => priority_high,
                .low => priority_low,
            });
            try encodeData(w, neighbor.data);
        },
        .disconnect => |disconnect| {
            try w.writeU8(swarm_disconnect);
            try w.writeBool(disconnect.alive);
        },
    }
}

fn decodeSwarm(r: *postcard.Reader) WireError!gossip.SwarmMessage {
    return switch (try r.readU8()) {
        swarm_join => .{ .join = try decodeData(r) },
        swarm_forward_join => .{ .forward_join = .{
            .peer = try decodeInfoOf(r),
            .ttl = .{ .value = try r.readU16() },
        } },
        swarm_shuffle => .{ .shuffle = .{
            .origin = try decodeId(r),
            .nodes = try decodeInfos(r),
            .ttl = .{ .value = try r.readU16() },
        } },
        swarm_shuffle_reply => .{ .shuffle_reply = .{ .nodes = try decodeInfos(r) } },
        swarm_neighbor => .{ .neighbor = .{
            .priority = switch (try r.readU8()) {
                priority_high => .high,
                priority_low => .low,
                else => return error.UnknownVariant,
            },
            .data = try decodeData(r),
        } },
        swarm_disconnect => .{ .disconnect = .{ .alive = try r.readBool() } },
        else => error.UnknownVariant,
    };
}

fn encodeTree(w: *postcard.Writer, message: plumtree.Message) WireError!void {
    switch (message) {
        .gossip => |payload| {
            try w.writeU8(tree_gossip);
            try w.writeArray(plumtree.id_length, &payload.id.bytes);
            try w.writeBytes(payload.content);
            switch (payload.scope) {
                .neighbors => try w.writeU8(scope_neighbors),
                .swarm => |round| {
                    try w.writeU8(scope_swarm);
                    try w.writeU16(round.value);
                },
            }
        },
        .prune => try w.writeU8(tree_prune),
        .graft => |graft| {
            try w.writeU8(tree_graft);
            try w.writeOption(graft.id != null);
            if (graft.id) |id| try w.writeArray(plumtree.id_length, &id.bytes);
            try w.writeU16(graft.round.value);
        },
        .i_have => |ihaves| {
            try w.writeU8(tree_i_have);
            const items = ihaves.slice();
            try w.writeLen(items.len);
            for (items) |have| {
                try w.writeArray(plumtree.id_length, &have.id.bytes);
                try w.writeU16(have.round.value);
            }
        },
    }
}

fn decodeTree(r: *postcard.Reader) WireError!plumtree.Message {
    return switch (try r.readU8()) {
        tree_gossip => blk: {
            const id = plumtree.MessageId{ .bytes = try r.readArray(plumtree.id_length) };
            const content = try r.readBytes();
            const scope: plumtree.DeliveryScope = switch (try r.readU8()) {
                scope_neighbors => .neighbors,
                scope_swarm => .{ .swarm = .{ .value = try r.readU16() } },
                else => return error.UnknownVariant,
            };
            break :blk .{ .gossip = .{ .id = id, .content = content, .scope = scope } };
        },
        tree_prune => .{ .prune = {} },
        tree_graft => blk: {
            var id: ?plumtree.MessageId = null;
            if (try r.readOption()) {
                id = .{ .bytes = try r.readArray(plumtree.id_length) };
            }
            break :blk .{ .graft = .{
                .id = id,
                .round = .{ .value = try r.readU16() },
            } };
        },
        tree_i_have => blk: {
            const count = try r.readLen();
            if (count > plumtree.max_ihaves_per_message) return error.IHaveListTooLong;
            var items: [plumtree.max_ihaves_per_message]plumtree.IHave = undefined;
            for (items[0..count]) |*have| {
                have.* = .{
                    .id = .{ .bytes = try r.readArray(plumtree.id_length) },
                    .round = .{ .value = try r.readU16() },
                };
            }
            break :blk .{ .i_have = try plumtree.IHaves.init(items[0..count]) };
        },
        else => error.UnknownVariant,
    };
}

fn encodeId(w: *postcard.Writer, id: NodeId) WireError!void {
    try w.writeArray(NodeId.byte_length, &id.toBytes());
}

fn decodeId(r: *postcard.Reader) WireError!NodeId {
    return NodeId.fromBytes(try r.readArray(NodeId.byte_length));
}

fn encodeData(w: *postcard.Writer, data: ?[]const u8) WireError!void {
    try w.writeOption(data != null);
    if (data) |bytes| try w.writeBytes(bytes);
}

fn decodeData(r: *postcard.Reader) WireError!?[]const u8 {
    if (!try r.readOption()) return null;
    const bytes = try r.readBytes();
    return bytes;
}

fn encodeInfo(w: *postcard.Writer, info: gossip.PeerInfo) WireError!void {
    try encodeId(w, info.id);
    try encodeData(w, info.data);
}

fn encodeInfos(w: *postcard.Writer, list: gossip.PeerInfos) WireError!void {
    const items = list.slice();
    try w.writeLen(items.len);
    for (items) |info| try encodeInfo(w, info);
}

fn decodeInfoOf(r: *postcard.Reader) WireError!gossip.PeerInfo {
    return .{ .id = try decodeId(r), .data = try decodeData(r) };
}

fn decodeInfos(r: *postcard.Reader) WireError!gossip.PeerInfos {
    const count = try r.readLen();
    if (count > gossip.max_shuffle_nodes) return error.PeerListTooLong;
    var items: [gossip.max_shuffle_nodes]gossip.PeerInfo = undefined;
    for (items[0..count]) |*info| {
        info.* = .{ .id = try decodeId(r), .data = try decodeData(r) };
    }
    return gossip.PeerInfos.init(items[0..count]);
}

/// A frame around a message: a `varint(u64)` length, then that many bytes.
///
/// The length prefix is the whole of the framing, and it is postcard's own —
/// `writeBytes` writes a `varint(u64)` length and then the bytes verbatim,
/// which is exactly the frame, and `readLen` is its reader. Nothing here
/// invents a width, and the prefix is what makes a byte stream a message
/// stream: a stream can then carry many messages, and a frame split across two
/// packets is a frame the reader waits for rather than a message it guessed.
pub fn encodeFrame(
    message: gossip.Message,
    body: []u8,
    out: []u8,
) WireError![]const u8 {
    const payload = try encodeMessage(message, body);
    if (payload.len > max_frame) return error.FrameTooLong;
    var w = postcard.Writer.init(out);
    try w.writeBytes(payload);
    return w.finish();
}

/// One timer either layer asked for, with the instant it comes due.
///
/// The `Timer` is a copy rather than a borrow: the union carries a `MessageId`
/// and a `NodeId` by value, so nothing here points into a state that moves.
pub const PendingTimer = struct {
    due: gossip.Nanos,
    timer: gossip.Timer,
};