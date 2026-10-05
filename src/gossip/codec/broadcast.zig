//! The broadcast layer's half of the wire: four messages, the bytes each of
//! them occupies, and the bytes that carry them.
//!
//! Every arm here is upstream `plumtree::Message` in upstream's order, and every
//! field is upstream's field in upstream's order, because postcard writes a
//! struct as its fields in declaration order and a peer reads them back that
//! way. `tags.zig` owns the discriminants; this file owns everything after the
//! arm tag.
//!
//! `Gossip.content` is a `Bytes` upstream and a `[]const u8` here, and both are
//! postcard's length-prefixed byte string, so a decoded message borrows the frame
//! it was cut from. That borrow is the same one both layers document: it lives as
//! long as the caller's buffer and not as long as this reader.
//!
//! The protocol-wide story — the framing, the stream header, the byte budget and
//! every divergence from upstream — is in `../codec.zig`, which is the module
//! callers import. This file is one piece of it.

const limits = @import("limits.zig");
const plumtree = @import("../plumtree.zig");
const postcard = @import("../../wire/postcard.zig");
const tags = @import("tags.zig");

const DeliveryScope = plumtree.DeliveryScope;
const Graft = plumtree.Graft;
const IHaves = plumtree.IHaves;
const Message = plumtree.Message;
const MessageId = plumtree.MessageId;
const Scope = tags.Scope;
const Tree = tags.Tree;
const Error = limits.Error;
const id_length = plumtree.id_length;
const max_ihaves_per_message = plumtree.max_ihaves_per_message;
const option_length = limits.option_length;
const tag_length = limits.tag_length;
const varintLen = limits.varintLen;

/// A `Prune` is a tag and nothing else (`plumtree.rs:135`), so its size is the
/// arm tag on its own.
const prune_len: usize = 0;

/// The bytes `encode` will write for `message`, its arm tag included.
///
/// A caller sizes a buffer with this, which is why it is exact rather than an
/// upper bound: `codec_test.zig` holds it against what `encode` wrote for every
/// arm of both layers, and `chunk.zig` cuts a list against it.
pub fn encodedLen(message: Message) usize {
    return tag_length + switch (message) {
        .gossip => |payload| payloadLen(payload),
        .prune => prune_len,
        .graft => |graft| graftLen(graft),
        .i_have => |ihaves| iHaveListLen(ihaves),
    };
}

/// Writes `message` into `writer`, its arm tag included.
///
/// `writer` is the caller's cursor and is never grown: a message that does not
/// fit is `error.BufferFull`, and it may have left a prefix behind, so a caller
/// restarts rather than resuming. The bytes are copied out of `message` and
/// nothing in the writer's result refers to it, so the payload buffers it was
/// encoded from may be reused the moment this returns.
pub fn encode(message: Message, writer: *postcard.Writer) Error!void {
    switch (message) {
        .gossip => |payload| {
            try writer.writeVariant(Tree.gossip);
            try writer.writeArray(id_length, &payload.id.bytes);
            try writer.writeBytes(payload.content);
            try writeScope(writer, payload.scope);
        },
        .prune => try writer.writeVariant(Tree.prune),
        .graft => |graft| {
            try writer.writeVariant(Tree.graft);
            try writer.writeOption(graft.id != null);
            if (graft.id) |message_id| try writer.writeArray(id_length, &message_id.bytes);
            try writer.writeU16(graft.round.value);
        },
        .i_have => |ihaves| {
            try writer.writeVariant(Tree.i_have);
            const items = ihaves.slice();
            try writer.writeLen(items.len);
            for (items) |have| try writeIHave(writer, have);
        },
    }
}

/// Reads one broadcast message from `writer`, which must sit at its arm tag.
///
/// A tag with no declared arm is `error.UnknownVariant`, refused by
/// `wire/postcard.zig` before this switch sees it, so nothing is skipped and
/// nothing is defaulted: a peer that sends a message this build does not have
/// ends the read rather than continuing at the next byte.
pub fn decode(writer: *postcard.Reader) Error!Message {
    return switch (try writer.readVariant(Tree)) {
        .gossip => blk: {
            const id = try readMessageId(writer);
            const content = try writer.readBytes();
            break :blk .{ .gossip = .{
                .id = id,
                .content = content,
                .scope = try readScope(writer),
            } };
        },
        .prune => .{ .prune = {} },
        .graft => blk: {
            var id: ?MessageId = null;
            if (try writer.readOption()) id = try readMessageId(writer);
            const round = try writer.readU16();
            break :blk .{ .graft = .{ .id = id, .round = .{ .value = round } } };
        },
        .i_have => .{ .i_have = try readIHaveList(writer) },
    };
}

/// A `Gossip`: the message id, the content, and the scope it was sent under.
fn payloadLen(payload: plumtree.Gossip) usize {
    const scope = scopeLen(payload.scope);
    return id_length + limits.byteStringLen(payload.content) + scope;
}

/// A `DeliveryScope`: its own tag, and a `u16` round when the scope has one.
fn scopeLen(scope: DeliveryScope) usize {
    return switch (scope) {
        .swarm => |round| tag_length + varintLen(round.value),
        .neighbors => tag_length,
    };
}

fn graftLen(graft: Graft) usize {
    const asked_for: usize = if (graft.id != null) id_length else 0;
    return option_length + asked_for + varintLen(graft.round.value);
}

/// A `Vec<IHave>`: the count, then that many ids and rounds.
fn iHaveListLen(list: IHaves) usize {
    var total: usize = varintLen(list.count);
    for (list.slice()) |have| total += haveLen(have);
    return total;
}

fn haveLen(have: plumtree.IHave) usize {
    return id_length + varintLen(have.round.value);
}

fn writeScope(writer: *postcard.Writer, scope: DeliveryScope) Error!void {
    switch (scope) {
        .swarm => |round| {
            try writer.writeVariant(Scope.swarm);
            try writer.writeU16(round.value);
        },
        .neighbors => try writer.writeVariant(Scope.neighbors),
    }
}

fn writeIHave(writer: *postcard.Writer, have: plumtree.IHave) Error!void {
    try writer.writeArray(id_length, &have.id.bytes);
    try writer.writeU16(have.round.value);
}

fn readScope(writer: *postcard.Reader) Error!DeliveryScope {
    return switch (try writer.readVariant(Scope)) {
        .swarm => .{ .swarm = .{ .value = try writer.readU16() } },
        .neighbors => .neighbors,
    };
}

fn readMessageId(writer: *postcard.Reader) Error!MessageId {
    return MessageId.fromBytes(try writer.readArray(id_length));
}

fn readIHaveList(writer: *postcard.Reader) Error!IHaves {
    const count = try writer.readLen();
    // The bound is proved here, at the slice, because nothing above this line
    // proves it: the count is a peer's claim about how many entries follow, and
    // a claim of seventeen would index past the array below.
    if (count > max_ihaves_per_message) return error.IHaveListTooLong;
    var items: [max_ihaves_per_message]plumtree.IHave = undefined;
    for (items[0..count]) |*have| {
        const id = try readMessageId(writer);
        have.* = .{ .id = id, .round = .{ .value = try writer.readU16() } };
    }
    return IHaves.init(items[0..count]);
}
