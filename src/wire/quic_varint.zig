//! The QUIC variable-length integer of RFC 9000 §16, as pure bytes over a
//! caller's slice.
//!
//! # Why this file is here and not beside a codec
//!
//! `src/wire/` already holds `postcard.zig`, the other byte-level encoding this
//! tree reproduces, and a QUIC variable-length integer is the same kind of
//! thing: an encoding a transport specification fixes, naming no discovery,
//! gossip or relay concept. It sits *below* every layer that spells bytes
//! rather than beside them, which is why `src/net/`, `src/relay/` and
//! `src/node/` all reach down into `src/wire/` and it reaches up into nothing.
//! `postcard.zig` imports `std` alone and so does this file, so the import
//! direction `net → wire` cannot cycle.
//!
//! Three codecs spelled these bytes — `src/net/qad.zig`, `src/net/qnt.zig` and
//! `src/node/node_relay_frame.zig` — and the rule was the same rule in all
//! three, so it is written once here.
//!
//! **A fourth copy is still standing, in `src/relay/frame_writer.zig`, and it
//! is left there on purpose.** Its refusals are upstream's own names —
//! `UnexpectedEnd` is `relay.rs:105`, `BufferFull` is the relay writer's — and
//! `src/relay/frame_types.zig` narrows and widens error sets around them by
//! name. Folding it in means renaming those two arms across
//! `frame_decode.zig`, `frame_encode.zig` and `frame_roundtrip.zig` and losing
//! the provenance they carry, which is a change to the relay codec rather than
//! to this deduplication.
//!
//! # What the rule is
//!
//! Two prefix bits in the first byte say the width — `00` for one byte, `01`
//! for two, `10` for four, `11` for eight — and the value is what is left of
//! it. Four widths, one spelling for every value below `max_value`, and two
//! refusals: a buffer with no room, and a slice that ended inside the integer.
//!
//! There is no third refusal, and that is a property rather than an omission:
//! a QUIC variable-length integer is self-describing, so every value below
//! `max_value` has exactly one spelling and an over-long spelling of a smaller
//! value does not exist to be rejected. A postcard varint admits those, which
//! is why `postcard.zig` has `BadVarint` and this file does not.
//!
//! **`put` does not range-check its value.** A `u64` at or above `max_value`
//! has no spelling — the top two bits of the widest form are the width — so
//! every caller checks that first, which is the check `qad.encode` makes
//! against `max_sequence` and `qnt.encode` makes against `max_value`. It is
//! stated rather than asserted because it is a caller's rule and a fault in one
//! is a fault in that codec's own test, not something this file can provoke on
//! its own.
//!
//! Sources: RFC 9000 §16 for the rule, and `noq-proto` 1.3.0 (`src/varint.rs`
//! — `VarInt::size`, `VarInt::encode`, `VarInt::decode`) for the byte vectors
//! the test below asserts. That is the reference `src/relay/frame_writer.zig`
//! and `src/net/qad.zig` already cite, and the widths here were read out of it
//! rather than inferred.

const std = @import("std");

const t = std.testing;

/// The widest a QUIC variable-length integer is, RFC 9000 §16, and so the room
/// a caller has to leave in front of an integer whose width is not known until
/// it has been written.
pub const max_length: usize = 8;

/// The largest value a variable-length integer can carry: the top two bits of
/// the widest form are the width, so the value is 62 bits and no more.
pub const max_value: u64 = (@as(u64, 1) << 62) - 1;

/// The values the four widths divide at, RFC 9000 §16: three inside the
/// one-byte form, then each boundary and the value just below it.
///
/// Published because every codec that spells varints sweeps these and a fourth
/// copy of the table in one of them would be a fourth copy of §16. It is a
/// table of the specification's rather than of any test's, which is why it
/// lives here and not beside the tests that walk it.
pub const boundaries = [_]u64{
    0,
    1,
    42,
    63,
    64,
    16_383,
    16_384,
    (1 << 30) - 1,
    1 << 30,
    max_value,
};

/// Why a write refuses. One arm, and it is a subset of every codec's own
/// `Error`, so `put` propagates into a wider set unchanged.
pub const WriteError = error{
    /// The caller's buffer cannot hold the whole integer. Raised before the
    /// bytes that did fit mean anything, so a caller that retries with a
    /// bigger buffer must discard what a failed `put` wrote.
    NoRoom,
};

/// Why a read refuses. Separate from `WriteError` for the reason
/// `qad.zig` keeps its `RoleError` separate from its `Error`: a transport
/// parameter's value and a packet frame are read at different moments by
/// different peers, and a caller reading both wants to tell the two refusals
/// apart rather than widen one set to hold the other's arm.
pub const ReadError = error{
    /// The slice ended before the width the first byte named was behind it.
    Truncated,
};

/// How many bytes the variable-length integer for `value` takes.
///
/// RFC 9000 §16: two prefix bits in the first byte say the width, and the value
/// is what is left of it.
pub fn length(value: u64) usize {
    if (value < 1 << 6) return 1;
    if (value < 1 << 14) return 2;
    if (value < 1 << 30) return 4;
    return max_length;
}

/// Write `value` as a variable-length integer at the front of `out`, and say
/// how wide it was.
///
/// `noq_proto::VarInt::encode`, and `noq_proto::VarInt::size` for the width.
/// Nothing here writes one byte for a value that needs more, and nothing here
/// reads a width it did not write.
pub fn put(out: []u8, value: u64) WriteError!usize {
    const width = length(value);
    if (out.len < width) return error.NoRoom;
    const prefix: u64 = switch (width) {
        1 => 0b00,
        2 => 0b01,
        4 => 0b10,
        else => 0b11,
    };
    const shift: u6 = @intCast(8 * width - 2);
    const wide = value | (prefix << shift);
    switch (width) {
        1 => out[0] = @intCast(wide),
        2 => {
            var bytes: [2]u8 = undefined;
            std.mem.writeInt(u16, &bytes, @intCast(wide), .big);
            @memcpy(out[0..2], bytes[0..]);
        },
        4 => {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, @intCast(wide), .big);
            @memcpy(out[0..4], bytes[0..]);
        },
        else => {
            var bytes: [max_length]u8 = undefined;
            std.mem.writeInt(u64, &bytes, wide, .big);
            @memcpy(out[0..max_length], bytes[0..]);
        },
    }
    return width;
}

/// Read the variable-length integer at `bytes[offset..]`, leaving `offset`
/// after it. A refusal leaves `offset` where it was.
///
/// `noq_proto::VarInt::decode`, loop for loop. One rejection: a first byte
/// naming a two-, four- or eight-byte integer with fewer bytes behind it.
pub fn get(bytes: []const u8, offset: *usize) ReadError!u64 {
    const rest = bytes[offset.*..];
    if (rest.len == 0) return error.Truncated;
    const width: usize = @as(usize, 1) << @intCast(rest[0] >> 6);
    if (rest.len < width) return error.Truncated;
    var value: u64 = rest[0] & 0b0011_1111;
    for (rest[1..width]) |byte| value = (value << 8) | byte;
    offset.* += width;
    return value;
}

// --- tests

/// The exact bytes each boundary spells: `noq-proto` 1.3.0, `src/varint.rs`,
/// over the width table RFC 9000 §16 draws.
const vectors = [_]struct { value: u64, bytes: []const u8 }{
    .{ .value = 0, .bytes = &.{0x00} },
    .{ .value = 1, .bytes = &.{0x01} },
    .{ .value = 42, .bytes = &.{0x2a} },
    .{ .value = 63, .bytes = &.{0x3f} },
    .{ .value = 64, .bytes = &.{ 0x40, 0x40 } },
    .{ .value = 16_383, .bytes = &.{ 0x7f, 0xff } },
    .{ .value = 16_384, .bytes = &.{ 0x80, 0x00, 0x40, 0x00 } },
    .{ .value = (1 << 30) - 1, .bytes = &.{ 0xbf, 0xff, 0xff, 0xff } },
    .{ .value = 1 << 30, .bytes = &.{ 0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00 } },
    .{ .value = max_value, .bytes = &.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } },
};

test "every width, its bytes, its refusals and its fixed point" {
    var scratch: [max_length]u8 = undefined;
    const untouched = @as([max_length]u8, @splat(0xaa));

    // `inline for` over both tables, so a boundary added to one and not the
    // other is a compile error rather than a boundary nothing sweeps.
    inline for (vectors, boundaries) |vector, boundary| {
        try t.expectEqual(boundary, vector.value);
        try t.expectEqual(vector.bytes.len, length(vector.value));

        const written = try put(&scratch, vector.value);
        try t.expectEqualSlices(u8, vector.bytes, scratch[0..written]);

        // Reads back, and the cursor says where it stopped.
        var offset: usize = 0;
        try t.expectEqual(vector.value, try get(vector.bytes, &offset));
        try t.expectEqual(vector.bytes.len, offset);

        // The encoding is a fixed point: the value names the bytes, not the
        // spelling that happened to be chosen for them. Read from the front
        // again, since the cursor is at the end by now.
        offset = 0;
        const again = try put(&scratch, try get(vector.bytes, &offset));
        try t.expectEqualSlices(u8, vector.bytes, scratch[0..again]);

        // Every buffer narrower than the width is refused rather than
        // truncated, and the refused buffer is the caller's own bytes after.
        var room: usize = 0;
        while (room < written) : (room += 1) {
            var partial = untouched;
            try t.expectError(error.NoRoom, put(partial[0..room], vector.value));
            try t.expectEqualSlices(u8, &untouched, &partial);
        }

        // Every prefix that ends inside the integer is Truncated, and a
        // refusal leaves the cursor where it was — so a caller walking a
        // buffer cannot resume from a position no integer was read at.
        var cut: usize = 0;
        while (cut < vector.bytes.len) : (cut += 1) {
            offset = 0;
            try t.expectError(error.Truncated, get(vector.bytes[0..cut], &offset));
            try t.expectEqual(@as(usize, 0), offset);
        }
    }

    // A cursor into the middle of a slice, because every caller that reads
    // more than one integer hands the same cursor back: `qad.decode` reads a
    // type and then a sequence, `qnt.decode` reads five.
    const frame = [_]u8{ 0x80, 0x9f, 0x81, 0xa8, 0x2a, 0x43, 0xe8 };
    var offset: usize = 4;
    try t.expectEqual(@as(u64, 42), try get(&frame, &offset));
    try t.expectEqual(@as(usize, 5), offset);
    try t.expectEqual(@as(u64, 1000), try get(&frame, &offset));
    try t.expectEqual(frame.len, offset);

    // And a cursor at the end is Truncated rather than a read of nothing.
    offset = frame.len;
    try t.expectError(error.Truncated, get(&frame, &offset));
    try t.expectEqual(frame.len, offset);
}
