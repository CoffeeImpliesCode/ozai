//! The writing half of a relay frame: what it costs in bytes, whether it may be
//! written at all, the buffer it is appended into, and the QUIC varint its header
//! is spelled with.
//!
//! **This module is the reason a frame that does not fit is an error and not a
//! resize.** `relay/frame_codec.zig` writes into a buffer the caller owns and
//! never grows one, because one scratch buffer has to serve a whole connection
//! and a resize the caller never agreed to is an allocation hiding inside a
//! codec. The same rule and the same shape as `wire/postcard.zig`'s writer, and
//! the same reason upstream does not need either: upstream writes into a
//! `BytesMut` that grows (`relay.rs:328`, `handshake.rs:558-561`), so a frame
//! that is too large there is a large allocation rather than a fault.
//!
//! The widths are big-endian raw bytes because this format's widths are
//! big-endian raw bytes. postcard's `writeU16` would varint them into something a
//! peer cannot read.
//!
//! The varint is QUIC's and not postcard's: `noq_proto::VarInt::encode` and
//! `noq_proto::VarInt::decode`, loop for loop, at
//! `noq-proto-1.3.0/src/varint.rs`. `relay/frame_types.zig` holds the two length
//! functions that decide a frame type's own header width; `readVarInt` is here
//! because it is the only reader there is.
//!
//! The vocabulary `encodedLen` and `checkEncodable` measure is
//! `relay/frame_types.zig`'s. Between the three modules every rule has one home:
//! what a frame may be is the type module's, what it costs and whether it may go
//! out are here, and how a `Message` becomes those bytes and comes back is
//! `relay/frame_codec.zig`'s.
//!
//! Nothing here reads a clock, the environment, or a global, and nothing
//! allocates. Everything here is public because `relay/frame_codec.zig` is its
//! one caller and that is a module boundary rather than a second consumer.

const std = @import("std");
const key = @import("../base/key.zig");
const frame = @import("frame_types.zig");

const DatagramFrame = frame.DatagramFrame;
const Datagrams = frame.Datagrams;
const Error = frame.Error;
const Message = frame.Message;
const NodeId = key.NodeId;
const ServerChallenge = frame.ServerChallenge;
const ServerDeniesAuth = frame.ServerDeniesAuth;
const Signature = key.Signature;
const max_packet_size = frame.max_packet_size;
const max_text_length = frame.max_text_length;

/// The bytes `encode` will write for `message`, exactly.
///
/// Upstream keeps an `encoded_len` beside every `write_to` and asserts the two
/// agree. A size that is a guess is a size a caller sizes a buffer from.
///
/// **Six of this union's fourteen arms carry a length their type does not fix**,
/// and `encode` bounds each before it writes: a denial's reason and a health
/// problem by `max_text_length`, and the four datagram frames' payload by
/// `max_packet_size`. That payload is every byte after the frame type and not
/// the contents, so the four are not bounded alike — 65503 bytes of contents in
/// a single datagram, 65501 in a batch, which spends two of the bound on its
/// segment size. **A caller sizing one buffer for every frame it sends sizes it
/// for the frame and not for the contents, and takes
/// `max_packet_size + FrameType.client_to_relay_datagram_batch.encodedLen()`,
/// which `ServerDeniesAuth.max_frame_length` does not come near.** The other
/// eight arms are fixed by their own type, and `checkEncodable` is where both
/// halves of that statement are kept.
///
/// **It is what a buffer is sized from, and for every message `encode` accepts it
/// is exactly the byte count.** For one `encode` refuses it is what the frame
/// would have been: text over `max_text_length` still counts its bytes, and a
/// batch with no segment size or a zero one still counts the two that would have
/// carried it. So `encodedLen` never understates a frame that can be written, and
/// a caller may treat it as a lower bound on a buffer for a message it has not
/// checked.
pub fn encodedLen(message: Message) usize {
    const payload: usize = switch (message) {
        .server_challenge => ServerChallenge.challenge_length,
        .client_auth => NodeId.byte_length + Signature.byte_length,
        .server_confirms_auth => 0,
        .server_denies_auth => |denial| frame.postcardVarIntLen(denial.reason.len) +
            denial.reason.len,
        .client_to_relay_datagram,
        .relay_to_client_datagram,
        => |frame| DatagramFrame.header_length + frame.datagrams.contents.len,
        .client_to_relay_datagram_batch,
        .relay_to_client_datagram_batch,
        => |frame| DatagramFrame.header_length + Datagrams.segment_size_length +
            frame.datagrams.contents.len,
        .endpoint_gone => NodeId.byte_length,
        .ping, .pong => 8,
        .health => |problem| problem.len,
        .restarting => 2 * @sizeOf(u32),
        .status => 1,
    };
    return std.meta.activeTag(message).encodedLen() + payload;
}

/// Appends frame bytes to a caller-owned buffer.
///
/// The same shape as `wire/postcard.zig`'s writer and for the same reason: it
/// grows nothing, so encoding into a buffer too small is `error.BufferFull` rather
/// than a resize the caller never agreed to. The widths are big-endian raw bytes
/// because this format's widths are big-endian raw bytes, and postcard's
/// `writeU16` would varint them into something a peer cannot read.
///
/// Every method is public because `relay/frame_codec.zig`'s `encode` is the one
/// caller, and that is a module boundary rather than a second consumer.
pub const Writer = struct {
    buffer: []u8,
    length: usize,

    pub fn init(buffer: []u8) Writer {
        return .{ .buffer = buffer, .length = 0 };
    }

    /// The part of the buffer not yet written, for a caller that has to hand it to
    /// another codec.
    pub fn rest(self: Writer) []u8 {
        return self.buffer[self.length..];
    }

    pub fn advance(self: *Writer, count: usize) void {
        self.length += count;
    }

    pub fn finish(self: Writer) []const u8 {
        return self.buffer[0..self.length];
    }

    pub fn write(self: *Writer, bytes: []const u8) Error!void {
        const free = self.rest();
        if (free.len < bytes.len) return error.BufferFull;
        @memcpy(free[0..bytes.len], bytes);
        self.length += bytes.len;
    }

    pub fn writeU8(self: *Writer, value: u8) Error!void {
        return self.write(&.{value});
    }

    pub fn writeU16Be(self: *Writer, value: u16) Error!void {
        var bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &bytes, value, .big);
        return self.write(&bytes);
    }

    pub fn writeU32Be(self: *Writer, value: u32) Error!void {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, value, .big);
        return self.write(&bytes);
    }

    /// `noq_proto::VarInt::encode` (`noq-proto-1.3.0/src/varint.rs`).
    pub fn writeVarInt(self: *Writer, value: u64) Error!void {
        const length = frame.varIntLen(value);
        if (length == 1) return self.writeU8(@intCast(value));
        if (length == 2) return self.writeU16Be(0b01 << 14 | @as(u16, @intCast(value)));
        if (length == 4) return self.writeU32Be(0b10 << 30 | @as(u32, @intCast(value)));
        return self.writeU64Be(0b11 << 62 | value);
    }

    pub fn writeU64Be(self: *Writer, value: u64) Error!void {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, value, .big);
        return self.write(&bytes);
    }
};

pub fn writeDatagramHeader(writer: *Writer, frame: DatagramFrame) Error!void {
    try writer.write(&frame.node_id.toBytes());
    try writer.writeU8(if (frame.datagrams.ecn) |codepoint| codepoint.toBits() else 0);
}

/// Every bound `message` has to meet, checked before a byte of it is written.
///
/// **This is the sweep.** Six of the fourteen arms of `Message` carry a length
/// their own type does not fix, in three kinds, and each is refused here by
/// name: a `server_denies_auth` reason and a v1 `health` problem, both
/// relay-authored text, by `max_text_length`, and the four datagram frames'
/// payload by `max_packet_size`.
///
/// The other eight are the frame type's own width and cannot be anything else:
/// the challenge's sixteen bytes, the client auth's node id and signature, the
/// empty confirmation, the endpoint id, ping's and pong's eight bytes, the two
/// durations, and the status discriminant. **A fifteenth arm carrying a
/// peer-supplied length is the case this function exists to catch, and the
/// switch below is where it lands** — an arm with no bound here is an arm whose
/// length nothing checks.
///
/// The datagram bound is on the payload `decode` measures — every byte after the
/// frame type, and not the contents alone — so it is the rule `decode` already
/// applies to a payload it is handed (`relay.rs:404` and `:544`), now applied on
/// the way out too, and this module cannot emit a frame its own decoder refuses
/// for being too long. That is `max_packet_size` over a node id, an ECN byte and,
/// on a batch, a segment size: 65503 bytes of contents in a single datagram, 65501
/// in a batch. Upstream checks it on decode only, because its `write_to` writes
/// into a `BytesMut` that grows (`relay.rs:328`): a frame that is too large there
/// is a large allocation rather than a fault.
///
/// What is not a length is out of scope here, with one exception that is a real
/// hole: relay-authored text is written as it was handed, so a reason or a
/// problem that is not UTF-8 would be a frame this module emits and will not
/// read back. So this is the sweep that closes it — the two text arms check
/// `std.unicode.utf8ValidateSlice` and refuse `error.InvalidUtf8`, the name
/// `decode` already answers with, because a codec that refuses on the way in
/// and writes on the way out is not a codec.
///
/// It runs before the writer exists so that a refusal leaves `out` as the caller
/// handed it over. A caller that kept the frame type and lost the payload would
/// find a partial frame in its own buffer, and a partial denial is a denial
/// whose reason stops early.
/// Public because `relay/frame_codec.zig`'s `encode` calls it before it creates
/// the writer, and that is a module boundary rather than a second consumer.
pub fn checkEncodable(message: Message) Error!void {
    switch (message) {
        .server_denies_auth => |denial| {
            if (denial.reason.len > ServerDeniesAuth.max_reason_length) {
                return error.TextTooLong;
            }
            if (!std.unicode.utf8ValidateSlice(denial.reason)) return error.InvalidUtf8;
        },
        .health => |problem| {
            if (problem.len > max_text_length) return error.TextTooLong;
            if (!std.unicode.utf8ValidateSlice(problem)) return error.InvalidUtf8;
        },
        .client_to_relay_datagram,
        .relay_to_client_datagram,
        => |frame| {
            if (frame.datagrams.segment_size != null) return error.InvalidFrame;
            const contents_limit = max_packet_size - DatagramFrame.header_length;
            if (frame.datagrams.contents.len > contents_limit) return error.FrameTooLarge;
        },
        .client_to_relay_datagram_batch,
        .relay_to_client_datagram_batch,
        => |frame| {
            const contents_limit = max_packet_size - DatagramFrame.header_length -
                Datagrams.segment_size_length;
            if (frame.datagrams.contents.len > contents_limit) return error.FrameTooLarge;
        },
        .server_challenge,
        .client_auth,
        .server_confirms_auth,
        .endpoint_gone,
        .ping,
        .pong,
        .restarting,
        .status,
        => {},
    }
}

/// Reads a QUIC varint from `bytes[*offset..]`, leaving the offset after it.
///
/// `noq_proto::VarInt::decode` (`noq-proto-1.3.0/src/varint.rs`), loop for loop.
/// One rejection, and it is upstream's `UnexpectedEnd` at `relay.rs:105`: a first
/// byte naming a two-, four- or eight-byte varint with fewer bytes behind it.
/// There is no second rejection because a QUIC varint is self-describing — every
/// one of the 2^62 values has exactly one encoding, and unlike postcard there is
/// no over-long spelling to reject.
/// Public because `relay/frame_codec.zig`'s `decode` reads the frame type with
/// it, and that is a module boundary rather than a second consumer.
pub fn readVarInt(bytes: []const u8, offset: *usize) Error!u64 {
    const rest = bytes[offset.*..];
    if (rest.len == 0) return error.UnexpectedEnd;
    const length: usize = @as(usize, 1) << @intCast(rest[0] >> 6);
    if (rest.len < length) return error.UnexpectedEnd;
    var value: u64 = rest[0] & 0b0011_1111;
    for (rest[1..length]) |byte| value = (value << 8) | byte;
    offset.* += length;
    return value;
}

const std_testing = std.testing;

test "varint: the QUIC rules, at every width" {
    // `noq-proto-1.3.0/src/varint.rs` is the reference for all four widths, and the
    // frame type table only ever uses the first, so the other three are pinned here
    // against the encoder and the decoder agreeing on them.
    var scratch: [8]u8 = undefined;
    var out: [16]u8 = undefined;
    const widths = [_]struct { value: u64, hex: []const u8 }{
        .{ .value = 0, .hex = "00" },
        .{ .value = 13, .hex = "0d" },
        .{ .value = 63, .hex = "3f" },
        .{ .value = 64, .hex = "40 40" },
        .{ .value = 16383, .hex = "7f ff" },
        .{ .value = 16384, .hex = "80 00 40 00" },
        .{ .value = 1073741823, .hex = "bf ff ff ff" },
        .{ .value = 1073741824, .hex = "c0 00 00 00 40 00 00 00" },
    };
    for (widths) |width| {
        const expected = try parseHex(&scratch, width.hex);
        try std_testing.expectEqual(expected.len, frame.varIntLen(width.value));
        var writer = Writer.init(&out);
        try writer.writeVarInt(width.value);
        try expectHex(expected, writer.finish());
        var offset: usize = 0;
        try std_testing.expectEqual(width.value, try readVarInt(&out, &offset));
        try std_testing.expectEqual(expected.len, offset);
    }
}
