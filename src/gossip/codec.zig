//! The gossip wire: one frame of a topic's stream, byte for byte.
//!
//! postcard is a byte format, not a dependency. Upstream
//! `n0-computer/iroh-gossip` 0.101.0 (crates.io checksum
//! `4e1dc4b05f73e7a1b9e83b531eb63c3fd671b0af3aeb13b59c546dd7ca747515`)
//! encodes every message it sends, so a peer that knows nothing about ozai
//! still has to read what this writes. Everything below is reproduced from
//! upstream's declarations *in declaration order*: a postcard discriminant is
//! an arm's position, so reordering two arms renumbers the wire while the
//! types still look right.
//!
//! Sources, all in 0.101.0:
//!
//! - `src/proto/topic.rs` — `Message { Swarm, Gossip }`, the frame payload.
//! - `src/proto/hyparview.rs` — the six membership arms and `Priority`.
//! - `src/proto/plumtree.rs` — the four broadcast arms, `DeliveryScope`,
//!   `Graft`, `IHave`, and the chunk arithmetic at `:449-456`.
//! - `src/net/util.rs:58-61,336,359,365,377,384,390` — `StreamHeader`,
//!   `write_frame` and `read_frame`.
//!
//! # What is in this file and what is not
//!
//! This module is the framing and the envelope: the tag that chooses a layer,
//! the `StreamHeader` that opens a topic's stream, the `u32` big-endian prefix
//! every frame carries, and the frame-level encode and decode a driver calls.
//! The two layers' arms live beside it and import only `postcard` and the
//! message types, which is what keeps this file free of cycle risk:
//! `swarm_codec.zig` for `hyparview`'s six arms and `tree_codec.zig` for
//! `plumtree`'s four. Their tag tables are re-exported here, so a caller that
//! wants the whole wire needs one import.
//!
//! # What the bytes were checked against
//!
//! 1373 frames captured from upstream's own state machine
//! (`vector-captures/gossip-upstream-gaps`, run_seed 1): 479 `Shuffle`, 360
//! `Neighbor`, 188 `Join`, 120 `Gossip`, 104 `ForwardJoin`, 80
//! `ShuffleReply`, 18 `IHave`, 11 `Prune`, 10 `Disconnect`, 3 `Graft`. All
//! 1373 decode here with no byte left over, and every layout below is the one
//! that fact forced. The two rules the capture could not emit — the
//! `StreamHeader` frame and the length prefix itself, both private to
//! `net::util` — are the two this file takes from the source instead, and
//! `manifest.json` records why there are no bytes for them.
//!
//! # The two ends disagree about `max_message_size`, and that is the rule
//!
//! `write_frame` refuses a payload of `max_message_size` bytes or more
//! (`net/util.rs:384`); `read_frame` accepts one of `max_message_size` or less
//! (`:365`). The asymmetry is upstream's and is reproduced rather than tidied:
//! a frame of exactly `max` bytes is one this side will not send and the other
//! side will accept. The capture emits payloads of 4093, 4094, 4095 and 4096
//! bytes under a 4096-byte budget (`boundary`), so the boundary is traffic and
//! not a hypothetical.
//!
//! # A decoded slice borrows the frame it was decoded from
//!
//! Every `[]const u8` a decode hands back points into the caller's buffer: a
//! `Join`'s and a `Neighbor`'s `PeerData`, each `PeerInfo`'s data, and a
//! `Gossip`'s content. Nothing is copied, so nothing allocates, and the borrow
//! lasts until that buffer is overwritten or dropped — not until the next
//! decode. A driver that queues a decoded message across another decode must
//! copy, exactly as `plumtree.Actions` says of its own outputs.

const std = @import("std");
const postcard = @import("../wire/postcard.zig");
const hyparview = @import("hyparview.zig");
const swarm_codec = @import("swarm_codec.zig");
const tree_codec = @import("tree_codec.zig");

const Message = hyparview.Message;
const TopicId = hyparview.TopicId;

/// `hyparview::Message`'s tag table, re-exported so the whole wire is one
/// import. See `swarm_codec.SwarmTag` for the arm order it encodes.
pub const SwarmTag = swarm_codec.SwarmTag;
/// `plumtree::Message`'s tag table. See `tree_codec.TreeTag`.
pub const TreeTag = tree_codec.TreeTag;
/// `plumtree::DeliveryScope`'s tag table. See `tree_codec.ScopeTag`.
pub const ScopeTag = tree_codec.ScopeTag;
/// The largest payload a `Gossip` may carry. See `tree_codec.max_content`.
pub const max_content = tree_codec.max_content;
/// Upstream's byte-budgeted `IHave` chunk length. See `tree_codec.ihaveChunkLen`.
pub const ihaveChunkLen = tree_codec.ihaveChunkLen;
/// The chunk length one `IHave` message can actually carry here.
pub const ihaveBatchLimit = tree_codec.ihaveBatchLimit;

/// `topic::Message`. The arm order *is* the wire.
const TopicTag = enum(u32) { swarm = 0, gossip = 1 };

/// Upstream `topic::Config::max_message_size`, and the budget every frame on a
/// topic stream is written under. It is a constant here because the field it
/// is upstream is `hyparview.TopicConfig.max_message_size`, and that is the one
/// field of upstream's topic config this codec owns.
pub const max_message_size: usize = 4096;

/// The smallest budget ozai accepts. 512 is not a round number invented here:
/// the capture ran a whole swarm at `max_message_size=512` (`chunk_probe`) and
/// upstream's own chunk arithmetic stayed positive there.
pub const min_max_message_size: usize = 512;

/// Bytes in front of every frame payload. Big-endian and fixed-width: this is
/// tokio's `write_u32` on the write side, not postcard, so it is not a varint.
pub const frame_prefix_length: usize = 4;

/// Every way this codec refuses: the two layers' rules, the postcard rules, and
/// the two that belong to the frame itself. Each member names one rule rather
/// than one symptom.
pub const Error = swarm_codec.Error || tree_codec.Error || error{
    /// A frame payload at the budget on the write side, over it on the read
    /// side. The two tests differ; see `writeFramePrefix`.
    FrameTooLarge,
    /// A frame budget below `min_max_message_size`.
    MessageSizeTooSmall,
};

/// The first frame of every per-topic uni-stream: which topic the frames that
/// follow belong to. Upstream `net::util::StreamHeader`, `pub(crate)` and
/// unconstructible from outside the crate (`net.rs:43` keeps `mod util`
/// private), which is why the capture has no bytes for it.
pub const StreamHeader = struct {
    topic_id: TopicId,
};

/// A stream's first frame: a length prefix and the topic id.
///
/// The prefix is written here rather than left to the caller because a stream
/// that opens with 32 unframed bytes is a stream whose first message length
/// nothing in this codec can check.
pub fn encodeStreamHeader(buffer: []u8, topic: TopicId) Error![]u8 {
    var writer = postcard.Writer.init(buffer);
    try writeFramePrefix(&writer, hyparview.topic_id_length);
    try writer.writeArray(hyparview.topic_id_length, &topic.bytes);
    return writer.finish();
}

/// The topic a stream's first frame names.
///
/// `bytes` may hold every frame that follows; only this frame's payload is
/// consumed. That payload must be exactly `topic_id_length` bytes, since that
/// is the whole of the header upstream sends.
pub fn decodeStreamHeader(bytes: []const u8) Error!StreamHeader {
    var reader = postcard.Reader.init(bytes);
    var body = postcard.Reader.init(try readFrame(&reader));
    const topic_id: TopicId = .{ .bytes = try body.readArray(hyparview.topic_id_length) };
    try body.finish();
    return .{ .topic_id = topic_id };
}

/// The frame prefix in front of a payload of `payload_len` bytes.
///
/// Refuses `payload_len >= max_message_size`, which is upstream's own test at
/// `net/util.rs:384` and one byte stricter than the read side. The four bytes
/// are big-endian and fixed-width; `writeU32` would be a varint and would not
/// be the same format.
pub fn writeFramePrefix(writer: *postcard.Writer, payload_len: usize) Error!void {
    if (payload_len >= max_message_size) return error.FrameTooLarge;
    var prefix: [frame_prefix_length]u8 = undefined;
    std.mem.writeInt(u32, &prefix, @intCast(payload_len), .big);
    try writer.writeArray(frame_prefix_length, &prefix);
}

/// One frame's payload, borrowed from the reader's input.
///
/// Accepts a declared length of `max_message_size` or less
/// (`net/util.rs:365`) — the one frame `writeFramePrefix` will not write. The
/// payload is `length` raw bytes with nothing in front of them, which is
/// postcard's private `take` and not `readBytes`: that reads a varint length
/// this frame does not carry.
pub fn readFrame(reader: *postcard.Reader) Error![]const u8 {
    const raw = try reader.readArray(frame_prefix_length);
    const length = std.mem.readInt(u32, &raw, .big);
    if (length > max_message_size) return error.FrameTooLarge;
    if (reader.remaining() < length) return error.UnexpectedEnd;
    const payload = reader.buffer[reader.offset..][0..length];
    reader.offset += length;
    return payload;
}

/// One whole frame — prefix and payload — in a caller's buffer. The bytes
/// returned are the whole frame, ready to hand to a stream.
pub fn encodeFrame(buffer: []u8, message: Message) Error![]u8 {
    if (buffer.len <= frame_prefix_length) return error.BufferFull;
    var body = postcard.Writer.init(buffer[frame_prefix_length..]);
    try encodeMessage(&body, message);
    const payload = body.finish();
    // Proved against the budget after the payload exists rather than before:
    // the length is what the message encodes to, and guessing it first would
    // put the cap on the wrong side of the encode.
    if (payload.len >= max_message_size) return error.FrameTooLarge;
    std.mem.writeInt(u32, buffer[0..frame_prefix_length], @intCast(payload.len), .big);
    return buffer[0 .. frame_prefix_length + payload.len];
}

/// One whole frame back into a message. Every byte behind the prefix must be
/// consumed: a frame with a byte left over is two messages sharing one length,
/// and the second one is then unreadable. The frames that follow in `bytes`
/// are left where they are, so a reader over one stream buffer calls this once
/// per frame.
pub fn decodeFrame(bytes: []const u8) Error!Message {
    var reader = postcard.Reader.init(bytes);
    var body = postcard.Reader.init(try readFrame(&reader));
    const message = try decodeMessage(&body);
    try body.finish();
    return message;
}

/// One message, as the payload of one frame: the layer tag and then that
/// layer's arm.
pub fn encodeMessage(writer: *postcard.Writer, message: Message) Error!void {
    switch (message) {
        .swarm => |swarm| {
            try writer.writeVariant(TopicTag.swarm);
            try swarm_codec.encodeSwarm(writer, swarm);
        },
        .gossip => |tree| {
            try writer.writeVariant(TopicTag.gossip);
            try tree_codec.encodeTree(writer, tree);
        },
    }
}

/// One message back, with every slice borrowed from the reader's input. See the
/// module doc for how long that borrow lasts.
pub fn decodeMessage(reader: *postcard.Reader) Error!Message {
    return switch (try reader.readVariant(TopicTag)) {
        .swarm => .{ .swarm = try swarm_codec.decodeSwarm(reader) },
        .gossip => .{ .gossip = try tree_codec.decodeTree(reader) },
    };
}

/// A frame budget this codec will work under.
pub fn validateMaxMessageSize(max: usize) Error!void {
    if (max < min_max_message_size) return error.MessageSizeTooSmall;
}
