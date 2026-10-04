//! RFC 9000 §16: the QUIC variable-length integer, over the four entry points
//! `vendor/quic/src/quic/packet.zig` publishes for it — `readVarInt`,
//! `readVarIntUsize`, `varIntLength` and `writeVarInt`.
//!
//! §16 is small enough to state in full, which is what makes it worth a
//! permanent target rather than a corpus entry. The two most significant bits
//! of the first byte name the length; the rest of that byte and the remaining
//! bytes of the length are a big-endian integer. Table 1 then fixes each
//! length's usable bits — 6, 14, 30 and 62 — and so the largest value each
//! width can carry. Everything asserted below is derived from that table and
//! from Appendix A.1's worked examples, written out in this file; nothing is
//! read back out of the decoder it is checking.
//!
//! A varint is the one wire field every other QUIC length is spelled in, so a
//! defect here is a defect in the length of every frame, every transport
//! parameter and every packet header, and it is reached from the fuzzer by
//! random first bytes alone: half of all two-byte prefixes decode as 4-byte
//! or 8-byte varints.
//!
//! Nothing in this family allocates: §16 reads bytes and returns a `u64`.

const std = @import("std");
const quic = @import("quic");
const packet = quic.packet;

pub const Error = error{
    TestUnexpectedResult,
    TestExpectedEqual,
    TestExpectedError,
    TestUnexpectedError,
};

/// RFC 9000 §16 Table 1: the two most significant bits name the length.
fn rfcWidth(first_byte: u8) usize {
    return @as(usize, 1) << @intCast(first_byte >> 6);
}

/// The largest value each width can carry, from the "Usable Bits" column.
fn rfcMax(width: usize) u64 {
    return switch (width) {
        1 => 63,
        2 => 16383,
        4 => 1073741823,
        8 => 4611686018427387903,
        else => unreachable,
    };
}

/// §16's own definition, applied to bytes: the first byte with its two most
/// significant bits removed, then the remaining bytes of the length read as a
/// big-endian integer. Null when the bytes are not a whole encoding.
fn rfcDecode(bytes: []const u8) ?u64 {
    const width = rfcWidth(bytes[0]);
    if (bytes.len < width) return null;
    var value: u64 = bytes[0] & 0x3f;
    for (bytes[1..width]) |b| value = (value << 8) | b;
    return value;
}

/// The shortest encoding §16 permits for `value`: the smallest width whose
/// usable-bit range holds it. A wider encoding of the same value is legal on
/// the wire — RFC 9000 Appendix A.1 encodes 37 as both `25` and `40 25` — so
/// this is a lower bound on what a decode consumed, not an equality.
fn rfcMinimalWidth(value: u64) usize {
    if (value <= rfcMax(1)) return 1;
    if (value <= rfcMax(2)) return 2;
    if (value <= rfcMax(4)) return 4;
    return 8;
}

/// §16's encoding written out from the table: the length prefix in the top two
/// bits, the value's remaining bits big-endian beneath it. Returns the width.
fn rfcEncode(value: u64, out: *[8]u8) usize {
    const width = rfcMinimalWidth(value);
    const prefix: u64 = switch (width) {
        1 => 0,
        2 => 1,
        4 => 2,
        else => 3,
    };
    out[0] = @intCast((prefix << 6) | (value >> @intCast((width - 1) * 8)));
    var i: usize = 1;
    while (i < width) : (i += 1) {
        out[i] = @intCast((value >> @intCast((width - i - 1) * 8)) & 0xff);
    }
    return width;
}

/// RFC 9000 Appendix A.1's five worked examples, which are the RFC's own
/// statement of what this encoding means. These are RFC-derived fixtures, not
/// captures: nothing here was produced by another implementation.
const anchors = [_]struct { bytes: [8]u8, len: usize, value: u64 }{
    .{ .bytes = .{ 0x25, 0, 0, 0, 0, 0, 0, 0 }, .len = 1, .value = 37 },
    .{ .bytes = .{ 0x40, 0x25, 0, 0, 0, 0, 0, 0 }, .len = 2, .value = 37 },
    .{ .bytes = .{ 0x7b, 0xbd, 0, 0, 0, 0, 0, 0 }, .len = 2, .value = 15293 },
    .{ .bytes = .{ 0x9d, 0x7f, 0x3e, 0x7d, 0, 0, 0, 0 }, .len = 4, .value = 494878333 },
    .{ .bytes = .{ 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c }, .len = 8, .value = 151288809941952652 },
};

/// Re-derive every anchor from the RFC's table and check the entry points
/// against that derivation, once per input.
fn checkAnchors() Error!void {
    for (anchors) |anchor| {
        const slice = anchor.bytes[0..anchor.len];
        if (rfcWidth(slice[0]) != anchor.len) return error.TestExpectedEqual;
        const derived = rfcDecode(slice) orelse return error.TestUnexpectedResult;
        if (derived != anchor.value) return error.TestExpectedEqual;

        var reader = quic.io_compat.fixedBufferStream(slice);
        const decoded = packet.readVarInt(&reader) catch return error.TestUnexpectedError;
        if (decoded != anchor.value) return error.TestExpectedEqual;
        if (reader.seek != anchor.len) return error.TestExpectedEqual;
        // `varIntLength` is the canonical width, and RFC 9000 A.1 deliberately
        // spells 37 both ways: `25` and `40 25`. So the table's own width is
        // the canonical one or one group wider, never narrower.
        if (packet.varIntLength(anchor.value) > anchor.len) return error.TestExpectedEqual;

        // The encoder must spell the value back canonically, and that is not
        // always the spelling A.1 prints: the RFC gives 37 as both `25` and
        // `40 25`, so the anchor carrying the two-byte form is checked against
        // the one-byte form instead.
        const canonical_width = packet.varIntLength(anchor.value);
        var out: [8]u8 = undefined;
        const width = rfcEncode(anchor.value, &out);
        if (width != canonical_width) return error.TestExpectedEqual;
        if (anchor.len == canonical_width and !std.mem.eql(u8, out[0..width], slice)) {
            return error.TestExpectedEqual;
        }
    }
    // §16 caps a varint at 2^62-1 and names no encoding above it, so the
    // encoder must refuse rather than drop the top bits of a larger value.
    var full: [8]u8 = undefined;
    var writer = quic.io_compat.fixedBufferStream(&full);
    if (packet.writeVarInt(&writer, rfcMax(8) + 1)) |_| {
        return error.TestExpectedError;
    } else |err| switch (err) {
        error.VarIntTooLarge => {},
        // The writer is eight bytes wide and a refused varint writes nothing,
        // so the buffer cannot be the refusal here.
        error.NoSpaceLeft => return error.TestExpectedError,
    }
    if (writer.seek != 0) return error.TestExpectedEqual;
}

/// One varint at `offset`, with `width` fixed by §16 from the first byte.
fn checkVarint(bytes: []const u8, offset: usize, width: usize) Error!void {
    const slice = bytes[offset..];
    if (slice.len < width) return expectTruncated(slice);

    var reader = quic.io_compat.fixedBufferStream(slice);
    const value = packet.readVarInt(&reader) catch |err| switch (err) {
        // The slice holds `width` bytes and §16 asks for exactly those, so the
        // only error the one-armed entry point can reach here is the truncated
        // read, and reaching it means it consumed a different span than §16
        // describes.
        error.EndOfStream => return error.TestUnexpectedError,
    };

    // Oracle: value. §16's definition, computed in this file.
    const derived = rfcDecode(slice) orelse return error.TestUnexpectedResult;
    if (value != derived) return error.TestExpectedEqual;

    // Oracle: consumed span. The prefix names the length, so the cursor must
    // have moved exactly that far and no further.
    if (reader.seek != width) return error.TestExpectedEqual;

    // Oracle: usable bits. No width carries a value past its Table 1 range.
    if (value > rfcMax(width)) return error.TestExpectedEqual;

    // Oracle: minimal width. `varIntLength` sizes the shortest legal encoding,
    // so it cannot exceed what the wire actually spent.
    const minimal = rfcMinimalWidth(value);
    if (packet.varIntLength(value) != minimal) return error.TestExpectedEqual;
    if (minimal > width) return error.TestExpectedEqual;

    try checkEncoding(value, minimal);

    // Oracle: the second published reader. It is the same value through a
    // different name, so it must agree on every legal encoding.
    var sized = quic.io_compat.fixedBufferStream(slice);
    const as_usize = packet.readVarIntUsize(&sized) catch |err| switch (err) {
        // The slice holds `width` bytes and the reader above took exactly
        // those, so the second reader cannot run out where the first did not.
        error.EndOfStream => return error.TestUnexpectedError,
        error.VarIntTooLarge => {
            // §16 tops out at 2^62-1, so only a target narrower than 64 bits
            // can refuse one — and then exactly the values above its maximum.
            if (@bitSizeOf(usize) >= 64) return error.TestUnexpectedError;
            if (value <= std.math.maxInt(usize)) return error.TestExpectedError;
            return;
        },
    };
    if (sized.seek != reader.seek) return error.TestExpectedEqual;
    if (@as(u64, as_usize) != value) return error.TestExpectedEqual;
}

/// Oracle: the encoder, against §16's spelling of the same value, and against
/// a re-decode of what it wrote.
fn checkEncoding(value: u64, minimal: usize) Error!void {
    var mine: [8]u8 = undefined;
    if (rfcEncode(value, &mine) != minimal) return error.TestExpectedEqual;

    var theirs: [8]u8 = undefined;
    var writer = quic.io_compat.fixedBufferStream(&theirs);
    packet.writeVarInt(&writer, value) catch return error.TestUnexpectedError;
    if (writer.seek != minimal) return error.TestExpectedEqual;
    if (!std.mem.eql(u8, theirs[0..minimal], mine[0..minimal])) {
        return error.TestExpectedEqual;
    }

    var reader = quic.io_compat.fixedBufferStream(theirs[0..minimal]);
    const again = packet.readVarInt(&reader) catch return error.TestUnexpectedError;
    if (again != value) return error.TestExpectedEqual;
    if (reader.seek != minimal) return error.TestExpectedEqual;
}

/// A slice too short for the encoding its first byte names: the read must
/// fail, and `error.EndOfStream` is the whole of the error set here.
fn expectTruncated(slice: []const u8) Error!void {
    var reader = quic.io_compat.fixedBufferStream(slice);
    if (packet.readVarInt(&reader)) |value| {
        _ = value;
        return error.TestExpectedError;
    } else |err| switch (err) {
        error.EndOfStream => {},
    }
}

/// Oracle: two varints through one cursor. A coalesced packet's lengths are
/// read one after another from the same stream, so a decode that consumed the
/// wrong span shows up as the second read starting at the wrong byte — which
/// the second decode's own value oracle then rejects.
pub fn check(input: []const u8) Error!void {
    try checkAnchors();
    if (input.len == 0) return expectTruncated(input);

    const width = rfcWidth(input[0]);
    try checkVarint(input, 0, width);
    if (input.len > width) try checkVarint(input, width, rfcWidth(input[width]));
}
