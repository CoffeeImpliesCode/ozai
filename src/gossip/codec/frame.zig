//! The frame: a length prefix, a message body, and the header a stream opens
//! with.
//!
//! # The prefix is postcard's own
//!
//! A frame is a `varint(u64)` length and then that many bytes, which is what
//! `wire/postcard.zig` writes for a length-prefixed byte string: `writeLen` is
//! what `writeBytes` writes and `readBytes` is what reads it back. Nothing here
//! invents a width, and the prefix is what makes a byte stream a message stream —
//! a frame split across two reads is a frame the reader waits for rather than a
//! message it guessed at.
//!
//! **Upstream's prefix is not this one, and a peer from the reference will not
//! read these frames.** `read_lp` reads a `u32` and `write_frame` writes one
//! (`net/util.rs:369`, `:392`), so upstream frames are a fixed four-byte
//! big-endian length and these are a varint. The house wire format is the one
//! `wire/postcard.zig` implements and the one `test/protocol_codec.zig` already
//! frames with, and a second framing beside it would be two rules for the same
//! bytes. `../codec.zig` says what closing that gap would take.
//!
//! # What a stream is
//!
//! A stream is a header frame and then message frames, all framed the same way.
//! The topic travels once, in the header, and every payload after it is 32 bytes
//! smaller than upstream's, which repeats it in every frame.
//!
//! Nothing here allocates, reads a clock, or touches a socket: `encode` appends
//! to a buffer the caller owns and `decode` borrows slices out of the frame it
//! was handed, which is the borrow rule both gossip layers document.

const broadcast = @import("broadcast.zig");
const gossip = @import("../hyparview.zig");
const limits = @import("limits.zig");
const membership = @import("membership.zig");
const postcard = @import("../../wire/postcard.zig");
const tags = @import("tags.zig");

const Layer = tags.Layer;
const Message = gossip.Message;
const TopicId = gossip.TopicId;
const Error = limits.Error;
const max_message_size = limits.max_message_size;
const tag_length = limits.tag_length;
const topic_id_length = gossip.topic_id_length;

/// What a receiver needs before any payload: the topic this stream carries.
///
/// Upstream `net/util.rs:53-55` is `struct StreamHeader { topic_id: TopicId }`,
/// written as the first frame of a stream by `SendLoop::write_message` and once
/// per stream (`net/util.rs:299-310`). It exists because the topic is not in the
/// frame: `RecvStreamState::next` puts `self.header.topic_id` back on every
/// message it reads (`net/util.rs:176-180`), so the topic travels once and each
/// payload after it is 32 bytes shorter than it would otherwise be.
pub const StreamHeader = struct {
    /// The swarm every message on this stream belongs to.
    topic_id: TopicId,

    /// The whole of the header's body: 32 bytes, and nothing else.
    pub const encoded_size = topic_id_length;

    pub fn init(topic_id: TopicId) StreamHeader {
        return .{ .topic_id = topic_id };
    }
};

/// The bytes a message body occupies, its layer tag included.
///
/// The body is what the byte budget is measured against, which is upstream's own
/// measure: `write_frame` compares `postcard::experimental::serialized_size`
/// with `max_message_size` (`net/util.rs:379`) and neither it nor `read_lp`
/// counts the prefix.
pub fn encodedLen(message: Message) usize {
    return tag_length + switch (message) {
        .swarm => |inner| membership.encodedLen(inner),
        .gossip => |inner| broadcast.encodedLen(inner),
    };
}

/// Writes `message` into `out` as a frame and hands back what it wrote.
///
/// `out` is the caller's buffer and is never grown, so a frame that does not fit
/// is `error.BufferFull` and a frame over the byte budget is
/// `error.FrameTooLarge` with nothing written. The returned slice is
/// `out[0..written]`, the same memory rather than a copy of it, and every slice
/// in the message is copied out of `message` first, so the buffers it was
/// encoded from may be reused the moment this returns.
pub fn encode(message: Message, out: []u8) Error![]const u8 {
    const body_len = encodedLen(message);
    if (body_len > max_message_size) return error.FrameTooLarge;
    var writer = postcard.Writer.init(out);
    try writer.writeLen(body_len);
    try encodeBody(message, &writer);
    return writer.finish();
}

/// Writes a message's body: the layer tag, then the arm.
pub fn encodeBody(message: Message, writer: *postcard.Writer) Error!void {
    switch (message) {
        .swarm => |inner| {
            try writer.writeVariant(Layer.swarm);
            try membership.encode(inner, writer);
        },
        .gossip => |inner| {
            try writer.writeVariant(Layer.gossip);
            try broadcast.encode(inner, writer);
        },
    }
}

/// Reads one frame: its length prefix, then exactly that many bytes of body.
///
/// **One frame in, one message out.** A buffer carrying two frames is
/// `error.TrailingBytes`, because the prefix says where the first frame ended and
/// a caller reading a stream has to act on that rather than have this function
/// guess where the next one begins.
///
/// The refusals are three rules and not one symptom: a prefix longer than the
/// bytes present is `error.BadLength` from `readBytes`, a body left over after
/// the message has been read is `error.TrailingBytes`, and a body over the byte
/// budget is `error.FrameTooLarge` before any of it is decoded. Every slice the
/// returned message carries is borrowed from `frame`.
pub fn decode(frame: []const u8) Error!Message {
    var reader = postcard.Reader.init(frame);
    const body = try reader.readBytes();
    if (body.len > max_message_size) return error.FrameTooLarge;
    try reader.finish();
    return decodeBody(body);
}

/// Reads a body this codec wrote, with no length prefix in front of it.
///
/// Exposed for a caller that has already split a stream, and for a test that
/// wants to hand a decoder bytes no encoder here produced — a tag no declared arm
/// names, a peer list one entry too long. A body with a byte left over after the
/// message is `error.TrailingBytes`: a declared shape that ends early is not a
/// message. Every slice the returned message carries is borrowed from `body`.
pub fn decodeBody(body: []const u8) Error!Message {
    var reader = postcard.Reader.init(body);
    const message: Message = switch (try reader.readVariant(Layer)) {
        .swarm => .{ .swarm = try membership.decode(&reader) },
        .gossip => .{ .gossip = try broadcast.decode(&reader) },
    };
    try reader.finish();
    return message;
}

/// Writes `header` into `out` as a frame and hands back what it wrote.
///
/// Framed exactly as a message is, because it is read by the same rule and a
/// reader with two framings has two things to get right. A caller sizing a
/// buffer for it sizes it with `limits.max_header_size`.
pub fn encodeStreamHeader(header: StreamHeader, out: []u8) Error![]const u8 {
    var writer = postcard.Writer.init(out);
    try writer.writeLen(StreamHeader.encoded_size);
    try writer.writeArray(topic_id_length, &header.topic_id.bytes);
    return writer.finish();
}

/// Reads a stream header frame.
///
/// A body that is not exactly `topic_id_length` bytes is `error.BadHeaderSize`:
/// the header has no length of its own to trust and no second field to skip to,
/// so a body of any other size is not a header. The topic id is copied out, so
/// nothing in the result borrows from `frame`.
pub fn decodeStreamHeader(frame: []const u8) Error!StreamHeader {
    var reader = postcard.Reader.init(frame);
    const body = try reader.readBytes();
    try reader.finish();
    if (body.len != StreamHeader.encoded_size) return error.BadHeaderSize;
    var bytes: [topic_id_length]u8 = undefined;
    @memcpy(&bytes, body);
    return StreamHeader.init(TopicId.fromBytes(bytes));
}
