//! The byte layer the relay frame is written and read through: the QUIC
//! variable-length integer, and a writer that appends into a buffer the caller
//! owns and never grows.
//!
//! Captured from n0-computer/iroh at commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8:
//!
//! - `noq-proto` 1.3.0, `src/varint.rs` — the varint the frame type is written
//!   with, and `VarInt::size` and `VarInt::decode` for its width and its read.
//!
//! # The frame type is not a postcard varint
//!
//! The header is a QUIC variable-length integer: `noq_proto::VarInt::encode`,
//! called from `common.rs:83`. It is not a postcard varint. The two agree for
//! every value a `FrameType` can take — 0 through 13 is below 64, and below 64 a
//! QUIC varint is one raw byte, exactly as a postcard varint is — so every byte
//! this module emits is the same byte under either reading, and every captured
//! vector behind `relay/frame_roundtrip.zig` is satisfied by both. They part company on
//! the way in: `40 00` is a two-byte QUIC varint spelling 0 and a two-byte
//! postcard varint spelling 64, and `80 00` is a QUIC varint that declares eight
//! bytes against a postcard varint spelling 0. A decoder that took the postcard
//! spelling would read a peer that has not sent a frame type at all.
//!
//! postcard is used one level up, for the one field upstream postcard-encodes,
//! the denial reason in frame 3 (`handshake.rs:561` hands it to
//! `postcard::to_io`), so `postcardVarIntLen` is here for a caller sizing a
//! buffer for one and nothing else.
//!
//! # What this layer refuses
//!
//! Two things, and both are `Error`'s arms under the same names: a varint that
//! ran out before its declared width was behind it, and a write that did not fit
//! in the buffer it was handed. Everything after the header is raw bytes at a
//! fixed width: `put_u8`, `put_u16` and `put_u32` in `relay.rs:263`, all
//! big-endian, and no length prefix anywhere. A segment size of 6 is `00 06` and
//! not a varint.
//!
//! `Writer` is the same shape as `wire/postcard.zig`'s writer and for the same
//! reason: it grows nothing, so writing into a buffer too small is
//! `error.BufferFull` rather than a resize the caller never agreed to. The
//! widths are big-endian raw bytes because this format's widths are big-endian
//! raw bytes, and postcard's `writeU16` would varint them into something a peer
//! cannot read. Nothing here allocates, reads a clock, or touches a global.

const std = @import("std");

const std_testing = std.testing;
const vectors = @import("frame_vectors.zig");

/// Every way the byte layer refuses, which is the two ways it can.
///
/// **A subset of `frame_types.Error`, under the same names, and both of them are
/// the codec's own arms.** This module sits below the frame vocabulary and
/// cannot name its error set without depending on it, so it declares the two it
/// can actually return and every caller of it widens them — which is sound
/// because a narrower set propagates into a wider one unchanged.
const Error = error{
    /// A varint named a width its bytes did not reach.
    UnexpectedEnd,
    /// A write with no room left in the buffer it was handed.
    BufferFull,
};

/// How many bytes a QUIC varint of `value` takes.
///
/// `noq_proto::VarInt::size` (`noq-proto-1.3.0/src/varint.rs`). The two-bit
/// length lives in the top of the first byte, so the value is `1 << len` bits
/// narrower than the field it is stored in.
pub fn varIntLen(value: u64) usize {
    if (value < 1 << 6) return 1;
    if (value < 1 << 14) return 2;
    if (value < 1 << 30) return 4;
    return 8;
}

/// Reads a QUIC varint from `bytes[*offset..]`, leaving the offset after it.
///
/// `noq_proto::VarInt::decode` (`noq-proto-1.3.0/src/varint.rs`), loop for loop.
/// One rejection, and it is upstream's `UnexpectedEnd` at `relay.rs:105`: a first
/// byte naming a two-, four- or eight-byte varint with fewer bytes behind it.
/// There is no second rejection because a QUIC varint is self-describing — every
/// one of the 2^62 values has exactly one encoding, and unlike postcard there is
/// no over-long spelling to reject.
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

/// postcard's `varint(usize)`, which is a `varint(u64)` on a target that can hold
/// a length at all.
pub fn postcardVarIntLen(length: usize) usize {
    var rest: u64 = @intCast(length);
    var count: usize = 1;
    while (rest >= 0x80) {
        rest >>= 7;
        count += 1;
    }
    return count;
}

/// Appends frame bytes to a caller-owned buffer.
///
/// The same shape as `wire/postcard.zig`'s writer and for the same reason: it
/// grows nothing, so encoding into a buffer too small is `error.BufferFull` rather
/// than a resize the caller never agreed to. The widths are big-endian raw bytes
/// because this format's widths are big-endian raw bytes, and postcard's
/// `writeU16` would varint them into something a peer cannot read.
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
        const length = varIntLen(value);
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

// --- tests

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
        const expected = try vectors.parseHex(&scratch, width.hex);
        try std_testing.expectEqual(expected.len, varIntLen(width.value));
        var writer = Writer.init(&out);
        try writer.writeVarInt(width.value);
        try vectors.expectHex(expected, writer.finish());
        var offset: usize = 0;
        try std_testing.expectEqual(width.value, try readVarInt(&out, &offset));
        try std_testing.expectEqual(expected.len, offset);
    }
}