//! The broadcast half of the gossip wire: `topic::Message::Gossip`, which is
//! upstream's `plumtree::Message` and its four arms.
//!
//! Split out of `codec.zig` by responsibility, not by convenience: this module
//! owns the arms that carry payloads and message ids, and it imports only
//! `postcard`, `plumtree`, and `hyparview`'s topic id length.
//! The tag tables it writes are upstream's declaration order, because a
//! postcard discriminant is an arm's position.
//! See `codec.zig` for the provenance, the 1373 captured frames these layouts
//! were checked against, and the framing this module's output goes inside.
//!
//! Sources, all in `n0-computer/iroh-gossip` 0.101.0: `src/proto/plumtree.rs`
//! for the four arms, `Graft`, `IHave` and the chunk arithmetic at `:449-456`,
//! and `src/proto/topic.rs` for the envelope. The capture is
//! `vector-captures/gossip-upstream-gaps` (run_seed 1): 120 `Gossip`, 18
//! `IHave`, 11 `Prune` and 3 `Graft`, all of which decode here with no byte
//! left over.
//!
//! # `DeliveryScope` is `Swarm` 0 and `Neighbors` 1
//!
//! Upstream declares the swarm scope first, and the capture carries one frame
//! of each, so the order is evidence and not a guess. An implementation that
//! inverts these two tags decodes every `Gossip` it receives as the wrong
//! scope, which is a broadcast delivered to the wrong audience rather than an
//! error.
//!
//! # A payload is bounded by the frame budget, and an `IHave` list by bytes
//!
//! `max_content` here is upstream's payload ceiling, which upstream expresses
//! as the frame budget rather than as a second constant; `codec.max_message_size`
//! is that budget, and the test suite pins the two to the same value because
//! this module cannot import `codec` without a cycle.
//!
//! `ihaveChunkLen` is the opposite rule. Upstream cuts an `IHave` batch by
//! *bytes*, not by count, and `plumtree`'s own chunker cuts by count — so the
//! byte arithmetic lives here, where the encoded sizes are, and
//! `ihaveBatchLimit` is the smaller of that budget and the count the inline
//! list can hold.
//!
//! # A decoded payload borrows the reader's input
//!
//! A `Gossip`'s `content` points into the buffer behind the reader. Nothing is
//! copied, so nothing allocates, and the borrow lasts until that buffer is
//! overwritten or dropped — not until the next decode. A driver that queues a
//! decoded message across another decode must copy, exactly as
//! `plumtree.Actions` says of its own outputs.

const std = @import("std");
const postcard = @import("../wire/postcard.zig");
const plumtree = @import("plumtree.zig");
const hyparview = @import("hyparview.zig");

const TreeMessage = plumtree.Message;

/// Upstream's `postcard_header_size()` (`proto/state.rs:48-58`): a 32-byte
/// topic id and the outer discriminant.
const header_bytes = hyparview.topic_id_length + 1;

/// The `- 1 - 2` of upstream's chunk arithmetic: the `plumtree` discriminant
/// and the element count in front of the entries.
const ihave_overhead = 3;

/// postcard's `MaxSize` over `MessageId([u8; 32]) + Round(u16)`, which is
/// upstream's `IHave::POSTCARD_MAX_SIZE`.
const ihave_entry_max = plumtree.id_length + 3;

/// `plumtree::Message`, upstream declaration order.
pub const TreeTag = enum(u32) {
    gossip = 0,
    prune = 1,
    graft = 2,
    i_have = 3,
};

/// `plumtree::DeliveryScope`, upstream declaration order. See the module doc
/// for why this order is not the one a reader would guess.
pub const ScopeTag = enum(u32) { swarm = 0, neighbors = 1 };

/// The largest `Gossip` payload this codec will write or read, which is
/// upstream's frame budget: its largest captured payload is 4058 bytes inside a
/// 4096-byte frame. `plumtree.max_content` is 1024 and is the *cache* bound —
/// how much one cached message may hold, not what the wire allows — so a codec
/// that used it here would refuse 120 of the 1373 captured frames.
pub const max_content: usize = 4096;

/// Every way this module refuses. The postcard half is included rather than
/// restated, and this module adds only the two rules of its own.
pub const Error = postcard.Error || error{
    /// A `Gossip` payload over `max_content`.
    MessageTooLarge,
    /// An `IHave` list longer than `plumtree.max_ihaves_per_message`.
    IHaveListTooLong,
};

/// One `Gossip` payload: the tag and then the arm's fields.
pub fn encodeTree(writer: *postcard.Writer, message: TreeMessage) Error!void {
    switch (message) {
        .gossip => |payload| {
            try writer.writeVariant(TreeTag.gossip);
            try writer.writeArray(plumtree.id_length, &payload.id.bytes);
            if (payload.content.len > max_content) return error.MessageTooLarge;
            try writer.writeBytes(payload.content);
            switch (payload.scope) {
                .swarm => |round| {
                    try writer.writeVariant(ScopeTag.swarm);
                    try writer.writeU16(round.value);
                },
                .neighbors => try writer.writeVariant(ScopeTag.neighbors),
            }
        },
        .prune => try writer.writeVariant(TreeTag.prune),
        .graft => |graft| {
            try writer.writeVariant(TreeTag.graft);
            try writer.writeOption(graft.id != null);
            if (graft.id) |present| try writer.writeArray(plumtree.id_length, &present.bytes);
            try writer.writeU16(graft.round.value);
        },
        .i_have => |ihaves| {
            try writer.writeVariant(TreeTag.i_have);
            const items = ihaves.slice();
            try writer.writeLen(items.len);
            for (items) |entry| {
                try writer.writeArray(plumtree.id_length, &entry.id.bytes);
                try writer.writeU16(entry.round.value);
            }
        },
    }
}

/// One `Gossip` payload back, with the content borrowed from the reader's
/// input. See the module doc for how long that borrow lasts.
pub fn decodeTree(reader: *postcard.Reader) Error!TreeMessage {
    return switch (try reader.readVariant(TreeTag)) {
        .gossip => .{ .gossip = .{
            .id = .{ .bytes = try reader.readArray(plumtree.id_length) },
            .content = try reader.readBytes(),
            .scope = try decodeScope(reader),
        } },
        .prune => .prune,
        .graft => .{ .graft = .{
            .id = if (try reader.readOption())
                .{ .bytes = try reader.readArray(plumtree.id_length) }
            else
                null,
            .round = .{ .value = try reader.readU16() },
        } },
        .i_have => .{ .i_have = try decodeIHaves(reader) },
    };
}

fn decodeScope(reader: *postcard.Reader) Error!plumtree.DeliveryScope {
    return switch (try reader.readVariant(ScopeTag)) {
        .swarm => .{ .swarm = .{ .value = try reader.readU16() } },
        .neighbors => .neighbors,
    };
}

fn decodeIHaves(reader: *postcard.Reader) Error!plumtree.IHaves {
    const count = try reader.readLen();
    if (count > plumtree.max_ihaves_per_message) return error.IHaveListTooLong;
    var list: plumtree.IHaves = undefined;
    list.count = @intCast(count);
    for (list.items[0..count]) |*entry| {
        entry.id = .{ .bytes = try reader.readArray(plumtree.id_length) };
        entry.round = .{ .value = try reader.readU16() };
    }
    return list;
}

/// How many `IHave`s one message may carry under a `max`-byte budget.
///
/// Upstream `proto/plumtree.rs:449-456`:
/// `(max_message_size - postcard_header_size() - 1 - 2) / IHave::POSTCARD_MAX_SIZE`.
/// Its three runtime terms are the constants above, and the capture pins the
/// result: with a 512-byte budget upstream emitted 13-entry frames, which is
/// what this returns for 512.
pub fn ihaveChunkLen(max: usize) usize {
    // One entry is the floor: a chunk of zero would not drain the queue it was
    // cut from, which is a stall rather than a smaller message.
    return @max(1, (max -| (header_bytes + ihave_overhead)) / ihave_entry_max);
}

/// The chunk length ozai can actually put in one message: the byte budget and
/// the inline list bound, whichever is smaller. At the 4096-byte default the
/// budget allows 116 and `plumtree.max_ihaves_per_message` allows 16, so a
/// dispatch timer stops at 16 and never reaches the budget.
pub fn ihaveBatchLimit(max: usize) usize {
    return @min(ihaveChunkLen(max), plumtree.max_ihaves_per_message);
}
