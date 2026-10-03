//! postcard: the wire format every ozai record is serialised through.
//!
//! postcard is not a dependency to adopt; it is a byte format to reproduce.
//! iroh encodes its tickets, its discovery records and its relay payloads with
//! postcard, and all of them have to survive a peer that knows nothing about
//! ozai. So this module is written against the published specification rather
//! than against postcard's own API, and every byte sequence the tests assert on
//! is a vector captured from upstream with the file it lives in, the crate
//! version and the commit written beside it.
//!
//! Sources, all at commit `872b9082589ebd1384a1b95ca232b1727bcddd29` of
//! `jamesmunns/postcard` — the repository the `postcard-rs` org redirects to —
//! where `source/postcard/Cargo.toml` is version 1.1.3. `iroh` 1.3.0 asks for
//! `postcard = "1.1.1"` and the wire format has been stable since v1.0.0, so
//! this commit is a version iroh accepts:
//!
//! - `spec/src/wire-format.md` — the format itself, including the unsigned and
//!   signed boundary tables and the canonicalization rules.
//! - `source/postcard/tests/loopback.rs` — postcard's own byte-for-byte
//!   round-trip vectors.
//! - `source/postcard-core/src/varint.rs` — the zigzag definitions.
//! - `source/postcard/src/de/deserializer.rs` — what a decoder accepts and what
//!   it rejects, which is where the error set below comes from.
//!
//! Two field rules are worth stating here because they are the ones a
//! reimplementation gets wrong. `u8` and `i8` are one raw byte and are *not*
//! varint-encoded, so `u8(255)` is `[0xFF]` and not `[0xFF, 0x01]`. And a
//! signed integer is zigzag-then-varint, which is not signed LEB128: Zig 0.16
//! has no `std.math.VarInt`, and the nearest thing,
//! `std.Io.Reader.takeLeb128`, decodes a signed type as sign-extended LEB128
//! rather than as zigzag and would drag `std.Io` into a codec that has to stay
//! pure. The loops below are postcard's own.
//!
//! A `Writer` appends to a caller-supplied buffer and a `Reader` consumes a
//! caller-supplied one; neither takes an allocator, because neither needs one.
//! Every method on one has a counterpart on the other under the same name, and
//! the two sets are the whole format: a field is written with the writer method
//! and read with the reader method of the same name. A sequence is `writeLen`
//! followed by that many elements and a string is `writeStr`, and there is no
//! separate sequence method because the two are the same bytes.
//!
//! A `Reader` hands back borrowed slices into its input. That input is the
//! caller's buffer rather than a frame of this module's, so the borrow outlives
//! the reader — the offset into it does not. See `CustomAddr.parse` for the
//! same borrow, argued at greater length.

const std = @import("std");

/// Every way a postcard value can fail to encode or decode.
///
/// Each member names one rule rather than one symptom, so a caller can tell a
/// frame that is merely short from a frame whose declared shape is impossible.
pub const Error = error{
    /// The input ran out in the middle of a value.
    UnexpectedEnd,
    /// A varint kept its continuation bit set for every byte the target type
    /// has room for, so the value is longer than the type is wide.
    BadVarint,
    /// A varint's last byte carried more value bits than the target type has,
    /// so the number does not fit.
    ValueOutOfRange,
    /// A length prefix that the remaining input cannot possibly satisfy. Not
    /// the same as `UnexpectedEnd`: the buffer is not short, the frame claims
    /// to carry more than it holds.
    BadLength,
    /// A `bool` byte other than 0 or 1.
    BadBool,
    /// An `Option` tag other than 0 or 1.
    BadOptionTag,
    /// An enum discriminant no declared arm names. Only an exhaustive enum
    /// can produce it; a non-exhaustive one accepts every tag its tag type
    /// represents. See `Reader.readVariant`.
    UnknownVariant,
    /// Bytes where a string was expected that are not UTF-8.
    InvalidUtf8,
    /// A writer with no room left in the buffer it was handed.
    BufferFull,
    /// Bytes left over after the message was read. `Reader.finish` is how a
    /// caller asserts there were none; without it two different messages can
    /// share one encoding and one of them is then simply unreadable.
    TrailingBytes,
};

/// The longest legal `varint(T)`: `ceil(bits / 7)`.
///
/// postcard varint-encodes `u16` and wider only — `u8` and `i8` are a single
/// raw byte — so there is no `varint(u8)` to get wrong.
pub fn varintMax(comptime Int: type) usize {
    comptime std.debug.assert(@typeInfo(Int) == .int);
    const bits = @typeInfo(Int).int.bits;
    comptime std.debug.assert(bits >= 16);
    return @divFloor(bits + 6, 7);
}

/// The largest value the last byte of a `varint(T)` may carry.
///
/// Every byte before the last carries seven bits, so the last one carries the
/// remaining `bits % 7` and nothing more. This is what makes an over-long
/// encoding detectable rather than merely unusual.
pub fn varintMaxLastByte(comptime Int: type) u8 {
    comptime std.debug.assert(@typeInfo(Int) == .int);
    const spare: u32 = @intCast(@typeInfo(Int).int.bits % 7);
    return @intCast((@as(u32, 1) << @intCast(spare)) - 1);
}

/// Appends postcard-encoded fields to a caller-owned buffer.
///
/// A `Writer` cannot grow its buffer and does not allocate: encoding into a
/// buffer too small is `error.BufferFull`, never a resize behind the caller's
/// back. `finish` returns the written prefix and leaves the rest of the buffer
/// alone, so one scratch buffer serves every encode in a scope.
///
/// A writer is a cursor into a buffer it does not own. Two writers over the
/// same buffer are two cursors and both write; a `Writer` that outlives the
/// buffer, or one that is copied and used after the original has moved on,
/// writes through a pointer the caller no longer holds.
///
/// `error.BufferFull` may leave a committed prefix and an advanced cursor,
/// including part of a varint or a byte string's length without its payload.
/// Do not retry a field from that cursor. Restart the message with `init`.
pub const Writer = struct {
    /// The caller's buffer, borrowed for as long as the writer is used and
    /// never resized: an encode that does not fit is `error.BufferFull`.
    buffer: []u8,
    /// How much of `buffer` has been written. Every method advances it, and
    /// `init` sets it to zero.
    length: usize,

    /// Encode into `buffer`, overwriting from its first byte.
    pub fn init(buffer: []u8) Writer {
        return .{ .buffer = buffer, .length = 0 };
    }

    /// The bytes written so far.
    pub fn finish(self: Writer) []u8 {
        return self.buffer[0..self.length];
    }

    /// Bytes still available. Zero means the next field, whatever its size,
    /// fails with `error.BufferFull`.
    pub fn remaining(self: Writer) usize {
        return self.buffer.len - self.length;
    }

    /// `bool`: one byte, 0 for false and 1 for true. Nothing else is a bool.
    pub fn writeBool(self: *Writer, value: bool) Error!void {
        try self.writeU8(@intFromBool(value));
    }

    /// `u8`: one raw byte. postcard does not varint the widths that fit in a
    /// byte, which is why this is not `writeVarint(u8, …)`.
    pub fn writeU8(self: *Writer, value: u8) Error!void {
        try self.append(&.{value});
    }

    /// `i8`: one raw byte in two's complement form.
    pub fn writeI8(self: *Writer, value: i8) Error!void {
        try self.writeU8(@bitCast(value));
    }

    /// `varint(u16)`: one to three bytes, low bits first.
    /// Needs the encoded width, at most `varintMax(u16)`. `BufferFull` may leave
    /// a partial varint; follow the writer's restart rule.
    pub fn writeU16(self: *Writer, value: u16) Error!void {
        try self.writeVarint(u16, value);
    }

    /// `varint(u16)` over the zigzag encoding, so -1 is the single byte 0x01.
    pub fn writeI16(self: *Writer, value: i16) Error!void {
        try self.writeVarint(u16, zigZag(value));
    }

    /// `varint(u32)`: one to five bytes, at most `varintMax(u32)` of buffer.
    pub fn writeU32(self: *Writer, value: u32) Error!void {
        try self.writeVarint(u32, value);
    }

    /// `varint(u32)` over the zigzag encoding.
    pub fn writeI32(self: *Writer, value: i32) Error!void {
        try self.writeVarint(u32, zigZag(value));
    }

    /// `varint(u64)`: one to ten bytes, at most `varintMax(u64)` of buffer.
    pub fn writeU64(self: *Writer, value: u64) Error!void {
        try self.writeVarint(u64, value);
    }

    /// `varint(u64)` over the zigzag encoding.
    pub fn writeI64(self: *Writer, value: i64) Error!void {
        try self.writeVarint(u64, zigZag(value));
    }

    /// A length or element count, as `varint(usize)`.
    ///
    /// A sequence is this followed by that many elements, and a byte string or
    /// a string is this followed by that many bytes. One method covers all
    /// three because postcard gives all three the same bytes.
    pub fn writeLen(self: *Writer, length: usize) Error!void {
        try self.writeVarint(u64, length);
    }

    /// A length-prefixed byte string. The bytes are copied verbatim and are
    /// not required to be anything in particular.
    pub fn writeBytes(self: *Writer, bytes: []const u8) Error!void {
        try self.writeLen(bytes.len);
        try self.append(bytes);
    }

    /// A length-prefixed UTF-8 string, which on the wire is the same length
    /// prefix and the same bytes as `writeBytes`. Only the reader tells them
    /// apart, by validating UTF-8.
    pub fn writeStr(self: *Writer, text: []const u8) Error!void {
        return self.writeBytes(text);
    }

    /// The one-byte `Option` tag: 0 for none, 1 for some.
    ///
    /// The payload belongs to the caller. postcard hands the deserializer
    /// straight back to read the payload itself, and a method here that took
    /// `?T` would have to be generic over a decoder it cannot name.
    pub fn writeOption(self: *Writer, present: bool) Error!void {
        try self.writeU8(@intFromBool(present));
    }

    /// An enum discriminant, which postcard declares as `varint(u32)`
    /// whatever the Zig tag type happens to be.
    ///
    /// Zig 0.16 has no `anyenum`, so the guard that `writeVariant` takes an
    /// enum lives here rather than in the type.
    pub fn writeVariant(self: *Writer, tag: anytype) Error!void {
        if (@typeInfo(@TypeOf(tag)) != .@"enum") {
            @compileError("writeVariant takes an enum value, not " ++ @typeName(@TypeOf(tag)));
        }
        const discriminant = std.math.cast(u32, @intFromEnum(tag)) orelse
            return error.ValueOutOfRange;
        try self.writeVarint(u32, discriminant);
    }

    /// A fixed-size byte array, inline: `n` bytes and no length prefix, so
    /// `readArray` knows how many to take from `n` alone.
    pub fn writeArray(self: *Writer, comptime n: usize, bytes: *const [n]u8) Error!void {
        try self.append(bytes);
    }

    fn append(self: *Writer, bytes: []const u8) Error!void {
        const rest = self.buffer[self.length..];
        if (rest.len < bytes.len) return error.BufferFull;
        @memcpy(rest[0..bytes.len], bytes);
        self.length += bytes.len;
    }

    /// postcard's encoder, loop for loop: little-endian groups of seven bits,
    /// the high bit of every non-final byte set. `Unsigned` is the width being
    /// encoded, not the width of the value.
    ///
    /// The last byte is the one where the *whole* remaining value fits in seven
    /// bits, not the one where the low byte does: 16384 has a low byte of zero
    /// and still needs three bytes.
    fn writeVarint(self: *Writer, comptime Unsigned: type, value: Unsigned) Error!void {
        var rest = value;
        for (0..varintMax(Unsigned)) |_| {
            const byte: u8 = @truncate(rest);
            if (rest < 0x80) {
                try self.writeU8(byte);
                return;
            }
            try self.writeU8(byte | 0x80);
            rest >>= 7;
        }
        // `varintMax` bytes carry every bit of `Unsigned`, so the loop above
        // returns on its last iteration whatever the value is. Declared rather
        // than `unreachable` so that this stays total if that arithmetic moves.
        return error.ValueOutOfRange;
    }
};

/// Consumes postcard-encoded fields from a caller-owned buffer.
///
/// Every method is total: arbitrary bytes produce an error from `Error` or a
/// value, and nothing else. There is no `unreachable` on any decode path,
/// because the only input to this module that is not chosen by us is a peer's
/// bytes.
///
/// A reader is a cursor into a buffer it does not own, and copying one copies
/// the cursor: two readers over the same buffer are independent positions,
/// each advancing its own `offset`. A slice a read handed out points into
/// `buffer`, so it stays valid for as long as the caller's buffer does and is
/// not affected by where the reader has since moved.
pub const Reader = struct {
    /// The caller's bytes, borrowed for as long as the reader is used. Any
    /// slice a read returns points into this buffer.
    buffer: []const u8,
    /// How far into `buffer` the next read starts. Every method advances it,
    /// and `init` sets it to zero; it is public because a framed protocol has
    /// to record where the frame ended.
    offset: usize,

    /// Decode from `bytes`, starting at its first byte.
    pub fn init(bytes: []const u8) Reader {
        return .{ .buffer = bytes, .offset = 0 };
    }

    /// Bytes not yet consumed.
    pub fn remaining(self: Reader) usize {
        return self.buffer.len - self.offset;
    }

    /// The end of a message: every byte of the input must have been consumed.
    ///
    /// A decoder that ignores its own remainder is what lets two different
    /// messages share one encoding, so this is explicit and not automatic. A
    /// caller reading a framed protocol may legitimately skip it; a caller
    /// reading a value may not.
    pub fn finish(self: Reader) Error!void {
        if (self.remaining() != 0) return error.TrailingBytes;
    }

    /// One byte: 0 or 1, and `error.BadBool` for anything else. An empty
    /// input is `error.UnexpectedEnd` rather than `BadBool`.
    pub fn readBool(self: *Reader) Error!bool {
        return switch (try self.readU8()) {
            0 => false,
            1 => true,
            else => error.BadBool,
        };
    }

    /// One raw byte, not a varint: postcard does not varint the widths that
    /// fit in a byte. `0xff` is 255.
    pub fn readU8(self: *Reader) Error!u8 {
        return (try self.take(1))[0];
    }

    /// One raw byte read as two's complement, so `0xff` is -1.
    pub fn readI8(self: *Reader) Error!i8 {
        return @bitCast(try self.readU8());
    }

    /// `varint(u16)`: one to three bytes. An encoding longer than that is
    /// `error.BadVarint`; one that terminates inside three bytes but carries
    /// more than a `u16` holds is `error.ValueOutOfRange`.
    pub fn readU16(self: *Reader) Error!u16 {
        return self.readVarint(u16);
    }

    /// `varint(u16)` read back through the zigzag decoding.
    pub fn readI16(self: *Reader) Error!i16 {
        return unZigZag(try self.readVarint(u16));
    }

    /// `varint(u32)`: one to five bytes, with the same two refusals as
    /// `readU16`.
    pub fn readU32(self: *Reader) Error!u32 {
        return self.readVarint(u32);
    }

    /// `varint(u32)` read back through the zigzag decoding.
    pub fn readI32(self: *Reader) Error!i32 {
        return unZigZag(try self.readVarint(u32));
    }

    /// `varint(u64)`: one to ten bytes, with the same two refusals as
    /// `readU16`.
    pub fn readU64(self: *Reader) Error!u64 {
        return self.readVarint(u64);
    }

    /// `varint(u64)` read back through the zigzag decoding.
    pub fn readI64(self: *Reader) Error!i64 {
        return unZigZag(try self.readVarint(u64));
    }

    /// A length or element count, as `varint(usize)`.
    ///
    /// postcard declares this a `varint(usize)` and leaves it to the target to
    /// say what a `usize` is, so it is read at the widest width a peer may send
    /// and then narrowed here. A count wider than `usize` cannot index anything
    /// on this target, and one wider than the bytes that follow is a frame that
    /// cannot be the frame it claims to be. Both are `BadLength`, not
    /// `UnexpectedEnd`: the buffer is not short.
    pub fn readLen(self: *Reader) Error!usize {
        const length = try self.readVarint(u64);
        const narrow = std.math.cast(usize, length) orelse return error.BadLength;
        if (narrow > self.remaining()) return error.BadLength;
        return narrow;
    }

    /// A length-prefixed byte string. The result borrows the reader's input,
    /// which is the caller's buffer, so it outlives the reader. The offset into
    /// that buffer does not outlive a reader that has been moved or copied.
    pub fn readBytes(self: *Reader) Error![]const u8 {
        const length = try self.readLen();
        return self.take(length);
    }

    /// A length-prefixed UTF-8 string. Same bytes as `readBytes`, plus the
    /// validation postcard's deserializer does.
    pub fn readStr(self: *Reader) Error![]const u8 {
        const bytes = try self.readBytes();
        if (!std.unicode.utf8ValidateSlice(bytes)) return error.InvalidUtf8;
        return bytes;
    }

    /// The one-byte `Option` tag. `true` means a payload follows, written by
    /// the caller; see `Writer.writeOption`.
    pub fn readOption(self: *Reader) Error!bool {
        return switch (try self.readU8()) {
            0 => false,
            1 => true,
            else => error.BadOptionTag,
        };
    }

    /// An enum discriminant, read as `varint(u32)` whatever the Zig tag type
    /// is.
    ///
    /// The two kinds of `Variant` read differently, and the difference is in
    /// the type rather than in this function. A **non-exhaustive** enum —
    /// one declared with a `_` field — has an unnamed arm for every tag its
    /// tag type can represent, so a discriminant this build has no *named*
    /// arm for decodes successfully into that unnamed value; only a number the
    /// tag type cannot hold is `error.UnknownVariant`. An **exhaustive** enum
    /// has no such arm, so a discriminant with no declared arm is
    /// `error.UnknownVariant`.
    ///
    /// A caller decoding into a non-exhaustive enum therefore gets values it
    /// cannot switch exhaustively on: `switch` on the result needs an `else`,
    /// and `std.enums.tagName` returns null for a tag it does not name.
    pub fn readVariant(self: *Reader, comptime Variant: type) Error!Variant {
        comptime {
            if (@typeInfo(Variant) != .@"enum") {
                @compileError("Variant must be an enum type");
            }
        }
        const discriminant = try self.readVarint(u32);
        return std.enums.fromInt(Variant, discriminant) orelse error.UnknownVariant;
    }

    /// A fixed-size byte array, inline: `n` bytes with no length prefix.
    pub fn readArray(self: *Reader, comptime n: usize) Error![n]u8 {
        var out: [n]u8 = undefined;
        @memcpy(&out, try self.take(n));
        return out;
    }

    fn take(self: *Reader, count: usize) Error![]const u8 {
        const rest = self.buffer[self.offset..];
        if (rest.len < count) return error.UnexpectedEnd;
        self.offset += count;
        return rest[0..count];
    }

    /// postcard's decoder, loop for loop.
    ///
    /// Two rejections, and they are different rules. A varint whose
    /// continuation bit is still set on the last byte the width allows is
    /// longer than the type is wide: `BadVarint`, because no number of extra
    /// bytes makes it fit. One that terminates within the width but whose last
    /// byte carries more than the `bits % 7` bits left over is a number the
    /// type cannot hold: `ValueOutOfRange`. postcard reports both as
    /// `DeserializeBadVarint`; ozai separates them because the second one is a
    /// wrong value and the first one is a wrong encoding.
    ///
    /// postcard does not enforce canonicalization, so `[0x80, 0x00]` is a
    /// legitimate spelling of 0. The encoder is canonical, which is what keeps
    /// two spellings of one value from producing two tickets.
    fn readVarint(self: *Reader, comptime Unsigned: type) Error!Unsigned {
        const last_index = varintMax(Unsigned) - 1;
        var out: Unsigned = 0;
        for (0..varintMax(Unsigned)) |index| {
            const byte = try self.readU8();
            const shift: std.math.Log2Int(Unsigned) = @intCast(7 * index);
            out |= (@as(Unsigned, byte & 0x7f)) << shift;
            if (byte & 0x80 != 0) continue;
            if (index == last_index and byte > varintMaxLastByte(Unsigned)) {
                return error.ValueOutOfRange;
            }
            return out;
        }
        return error.BadVarint;
    }
};

/// postcard's zigzag: `(v << 1) ^ (v >> (bits - 1))`, with the sign extension
/// turned into a mask so every step is unsigned arithmetic.
fn zigZag(value: anytype) @Int(.unsigned, @bitSizeOf(@TypeOf(value))) {
    const Signed = @TypeOf(value);
    comptime std.debug.assert(@typeInfo(Signed) == .int);
    comptime std.debug.assert(@typeInfo(Signed).int.signedness == .signed);
    // A type, not a value: `@Int` builds one, which is why it is spelled in
    // PascalCase here and next to the `@TypeOf` bindings above and below.
    // zwanzig-disable-next-line: identifier-style
    const Unsigned = @Int(.unsigned, @bitSizeOf(Signed));
    const raw: Unsigned = @bitCast(value);
    const sign: Unsigned = 0 -% (raw >> @intCast(@bitSizeOf(Signed) - 1));
    return (raw << 1) ^ sign;
}

/// The inverse of `zigZag`: `(n >> 1) ^ -(n & 1)`.
fn unZigZag(value: anytype) @Int(.signed, @bitSizeOf(@TypeOf(value))) {
    const Unsigned = @TypeOf(value);
    comptime std.debug.assert(@typeInfo(Unsigned) == .int);
    comptime std.debug.assert(@typeInfo(Unsigned).int.signedness == .unsigned);
    const mask: Unsigned = 0 -% (value & 1);
    return @bitCast((value >> 1) ^ mask);
}

const testing = std.testing;

// Golden vectors throughout the tests below: `jamesmunns/postcard` (the `pc`
// crate), version 1.1.3, commit 872b9082589ebd1384a1b95ca232b1727bcddd29,
// fetched 2026-09-30. Each test names the file the bytes come from.

// `spec/src/wire-format.md`, "Unsigned Integer Encoding", at commit
// 872b9082589ebd1384a1b95ca232b1727bcddd29. postcard 1.1.3.
test "golden: the spec u16 unsigned table" {
    const vectors = [_]struct { value: u16, bytes: []const u8 }{
        .{ .value = 0, .bytes = &.{0x00} },
        .{ .value = 127, .bytes = &.{0x7f} },
        .{ .value = 128, .bytes = &.{ 0x80, 0x01 } },
        .{ .value = 16383, .bytes = &.{ 0xff, 0x7f } },
        .{ .value = 16384, .bytes = &.{ 0x80, 0x80, 0x01 } },
        .{ .value = 16385, .bytes = &.{ 0x81, 0x80, 0x01 } },
        .{ .value = 65535, .bytes = &.{ 0xff, 0xff, 0x03 } },
    };
    for (vectors) |vector| {
        var buffer: [varintMax(u16)]u8 = undefined;
        var writer = Writer.init(&buffer);
        try writer.writeU16(vector.value);
        try testing.expectEqualSlices(u8, vector.bytes, writer.finish());

        var reader = Reader.init(vector.bytes);
        try testing.expectEqual(vector.value, try reader.readU16());
        try reader.finish();
    }
}

// `spec/src/wire-format.md`, "Signed Integer Encoding", at commit
// 872b9082589ebd1384a1b95ca232b1727bcddd29. postcard 1.1.3.
test "golden: the spec i16 zigzag table" {
    const vectors = [_]struct { value: i16, bytes: []const u8 }{
        .{ .value = 0, .bytes = &.{0x00} },
        .{ .value = -1, .bytes = &.{0x01} },
        .{ .value = 1, .bytes = &.{0x02} },
        .{ .value = 63, .bytes = &.{0x7e} },
        .{ .value = -64, .bytes = &.{0x7f} },
        .{ .value = 64, .bytes = &.{ 0x80, 0x01 } },
        .{ .value = -65, .bytes = &.{ 0x81, 0x01 } },
        .{ .value = 32767, .bytes = &.{ 0xfe, 0xff, 0x03 } },
        .{ .value = -32768, .bytes = &.{ 0xff, 0xff, 0x03 } },
    };
    for (vectors) |vector| {
        var buffer: [varintMax(u16)]u8 = undefined;
        var writer = Writer.init(&buffer);
        try writer.writeI16(vector.value);
        try testing.expectEqualSlices(u8, vector.bytes, writer.finish());

        var reader = Reader.init(vector.bytes);
        try testing.expectEqual(vector.value, try reader.readI16());
        try reader.finish();
    }
}

// `spec/src/wire-format.md`, "Canonicalization", at commit
// 872b9082589ebd1384a1b95ca232b1727bcddd29. postcard 1.1.3. The two
// "rejected because too long" rows and the "rejected because too large" row
// are the whole over-long rule; the rest is what an over-tolerant decoder
// would quietly accept.
test "golden: the spec canonicalization table" {
    const accepted = [_][]const u8{
        &.{0x00},
        &.{ 0x80, 0x00 },
        &.{ 0x80, 0x80, 0x00 },
        &.{ 0xff, 0xff, 0x03 },
    };
    for (accepted) |bytes| {
        var reader = Reader.init(bytes);
        _ = try reader.readU16();
        try reader.finish();
    }

    try testing.expectError(error.BadVarint, expectU16(&.{ 0x80, 0x80, 0x80, 0x00 }));
    try testing.expectError(error.ValueOutOfRange, expectU16(&.{ 0xff, 0xff, 0x07 }));
    try testing.expectError(error.BadVarint, expectU16(&.{ 0xff, 0xff, 0x83, 0x00 }));
}

// `source/postcard/tests/loopback.rs`, `std_io_loopback` and `loopback`, at
// commit 872b9082589ebd1384a1b95ca232b1727bcddd29. postcard 1.1.3.
test "golden: the loopback scalar vectors" {
    const vectors = [_][]const u8{
        &.{0x00}, //                                   false
        &.{0x01}, //                                   true
        &.{0x05}, //                                   5u8
        &.{ 0xc7, 0xcb, 0x02 }, //                     0xa5c7u16
        &.{ 0x92, 0xe8, 0xac, 0xed, 0x0c }, //         0xcdab3412u32
        &.{ 0xef, 0x9b, 0xaf, 0x85, 0x89, 0xcf, 0x95, 0x9a, 0x12 }, // 0x1234...u64
    };

    {
        var reader = Reader.init(vectors[0]);
        try testing.expectEqual(false, try reader.readBool());
        try reader.finish();
    }
    {
        var reader = Reader.init(vectors[1]);
        try testing.expectEqual(true, try reader.readBool());
        try reader.finish();
    }
    {
        var reader = Reader.init(vectors[2]);
        try testing.expectEqual(@as(u8, 5), try reader.readU8());
        try reader.finish();
    }
    {
        var reader = Reader.init(vectors[3]);
        try testing.expectEqual(@as(u16, 0xa5c7), try reader.readU16());
        try reader.finish();
    }
    {
        var reader = Reader.init(vectors[4]);
        try testing.expectEqual(@as(u32, 0xcdab3412), try reader.readU32());
        try reader.finish();
    }
    {
        var reader = Reader.init(vectors[5]);
        try testing.expectEqual(@as(u64, 0x1234567890abcdef), try reader.readU64());
        try reader.finish();
    }

    var buffer: [32]u8 = undefined;
    for ([_]u64{ 5, 0xa5c7, 0xcdab3412, 0x1234567890abcdef }) |value| {
        var writer = Writer.init(&buffer);
        try writer.writeU64(value);
        var back = Reader.init(writer.finish());
        try testing.expectEqual(value, try back.readU64());
        try back.finish();
    }
}

// `source/postcard/tests/loopback.rs`, `loopback`, at commit
// 872b9082589ebd1384a1b95ca232b1727bcddd29. postcard 1.1.3.
test "golden: the loopback signed vectors" {
    const vectors = [_]struct { value: i16, bytes: []const u8 }{
        .{ .value = 32767, .bytes = &.{ 0xfe, 0xff, 0x03 } },
        .{ .value = -32768, .bytes = &.{ 0xff, 0xff, 0x03 } },
    };
    for (vectors) |vector| {
        var buffer: [varintMax(u16)]u8 = undefined;
        var writer = Writer.init(&buffer);
        try writer.writeI16(vector.value);
        try testing.expectEqualSlices(u8, vector.bytes, writer.finish());

        var reader = Reader.init(vector.bytes);
        try testing.expectEqual(vector.value, try reader.readI16());
        try reader.finish();
    }
}

// postcard publishes no byte vector for `i8`, `i32` or `i64`: its loopback
// tests exercise `i16` and nothing else. These follow the two upstream
// statements the wider widths are defined by — `spec/src/wire-format.md`
// "`i8` is stored as a single byte, in two's complement form", and the
// `zig_zag_i32` / `zig_zag_i64` definitions in
// `source/postcard-core/src/varint.rs` — both at commit
// 872b9082589ebd1384a1b95ca232b1727bcddd29. Derived, not captured.
test "signed widths postcard publishes no byte vector for" {
    var buffer: [32]u8 = undefined;

    {
        var writer = Writer.init(&buffer);
        try writer.writeI8(-1);
        try testing.expectEqualSlices(u8, &.{0xff}, writer.finish());
        var reader = Reader.init(&.{0xff});
        try testing.expectEqual(@as(i8, -1), try reader.readI8());
        try reader.finish();
    }
    {
        // Small values stay one byte at every width, which is the whole point
        // of the zigzag: without it -1 as an `i32` would cost five.
        var writer = Writer.init(&buffer);
        try writer.writeI32(-1);
        try testing.expectEqualSlices(u8, &.{0x01}, writer.finish());
        var reader = Reader.init(&.{0x01});
        try testing.expectEqual(@as(i32, -1), try reader.readI32());
        try reader.finish();
    }
    {
        var writer = Writer.init(&buffer);
        try writer.writeI64(std.math.minInt(i64));
        try testing.expectEqualSlices(u8, &.{
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
        }, writer.finish());
        var reader = Reader.init(&.{
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
        });
        try testing.expectEqual(std.math.minInt(i64), try reader.readI64());
        try reader.finish();
    }
    {
        var writer = Writer.init(&buffer);
        try writer.writeI32(0x7fffffff);
        try testing.expectEqualSlices(u8, &.{ 0xfe, 0xff, 0xff, 0xff, 0x0f }, writer.finish());
        var reader = Reader.init(&.{ 0xfe, 0xff, 0xff, 0xff, 0x0f });
        try testing.expectEqual(@as(i32, 0x7fffffff), try reader.readI32());
        try reader.finish();
    }
}

// `source/postcard/tests/loopback.rs`, `loopback`, `BasicU8S` at commit
// 872b9082589ebd1384a1b95ca232b1727bcddd29. postcard 1.1.3. Four fields of
// three different widths, in declaration order, is the whole of "a struct is
// its fields in order".
test "golden: the loopback struct vector" {
    const expected = [_]u8{
        0xcd, 0xd7, 0x02, // st: u16 = 0xabcd
        0xfe, //           ei: u8  = 0xfe
        0xba, 0xb9, 0xb7, 0xde, 0x9a, 0xe4, 0x90, 0x9a, 0x12, // sf: u64
        0xac, 0xd9, 0xb2, 0xe5, 0x0a, //             tt: u32 = 0xacacacac
    };
    var buffer: [32]u8 = undefined;
    var writer = Writer.init(&buffer);
    try writer.writeU16(0xabcd);
    try writer.writeU8(0xfe);
    try writer.writeU64(0x12344321abcddcba);
    try writer.writeU32(0xacacacac);
    try testing.expectEqualSlices(u8, &expected, writer.finish());

    var reader = Reader.init(&expected);
    try testing.expectEqual(@as(u16, 0xabcd), try reader.readU16());
    try testing.expectEqual(@as(u8, 0xfe), try reader.readU8());
    try testing.expectEqual(@as(u64, 0x12344321abcddcba), try reader.readU64());
    try testing.expectEqual(@as(u32, 0xacacacac), try reader.readU32());
    try reader.finish();
}

const BasicEnum = enum(u32) { bib, bim, bap };
const DataEnum = enum(u32) { bib, bim, bap, kim, chi, sho };

// `source/postcard/tests/loopback.rs`, `loopback`, `BasicEnum` and `DataEnum`
// at commit 872b9082589ebd1384a1b95ca232b1727bcddd29. postcard 1.1.3. A
// variant is a `varint(u32)` discriminant followed by its payload, so each of
// these pins the tag and something behind it.
test "golden: the loopback enum vectors" {
    var buffer: [32]u8 = undefined;

    {
        var writer = Writer.init(&buffer);
        try writer.writeVariant(BasicEnum.bim);
        try testing.expectEqualSlices(u8, &.{0x01}, writer.finish());
        var reader = Reader.init(&.{0x01});
        try testing.expectEqual(BasicEnum.bim, try reader.readVariant(BasicEnum));
        try reader.finish();
    }
    {
        // DataEnum::Bim(u64::MAX)
        var writer = Writer.init(&buffer);
        try writer.writeVariant(DataEnum.bib);
        try writer.writeU16(65535);
        try testing.expectEqualSlices(u8, &.{ 0x00, 0xff, 0xff, 0x03 }, writer.finish());
    }
    {
        // DataEnum::Bap(u8::MAX): the u8 payload is one raw byte, not `[ff, 01]`.
        var writer = Writer.init(&buffer);
        try writer.writeVariant(DataEnum.bap);
        try writer.writeU8(255);
        try testing.expectEqualSlices(u8, &.{ 0x02, 0xff }, writer.finish());
    }
    {
        // DataEnum::Bim(u64::MAX): the widest legal varint(u64).
        var writer = Writer.init(&buffer);
        try writer.writeVariant(DataEnum.bim);
        try writer.writeU64(std.math.maxInt(u64));
        try testing.expectEqualSlices(u8, &.{
            0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
        }, writer.finish());
        var reader = Reader.init(&.{
            0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
        });
        try testing.expectEqual(DataEnum.bim, try reader.readVariant(DataEnum));
        try testing.expectEqual(std.math.maxInt(u64), try reader.readU64());
        try reader.finish();
    }
    {
        // DataEnum::Kim(EnumStruct { eight: 0xf0, sixt: 0xacac })
        var writer = Writer.init(&buffer);
        try writer.writeVariant(DataEnum.kim);
        try writer.writeU8(0xf0);
        try writer.writeU16(0xacac);
        try testing.expectEqualSlices(u8, &.{ 0x03, 0xf0, 0xac, 0xd9, 0x02 }, writer.finish());
    }
    {
        // DataEnum::Chi { a: 0x0f, b: 0xc7c7c7c7 }
        var writer = Writer.init(&buffer);
        try writer.writeVariant(DataEnum.chi);
        try writer.writeU8(0x0f);
        try writer.writeU32(0xc7c7c7c7);
        const expected = [_]u8{ 0x04, 0x0f, 0xc7, 0x8f, 0x9f, 0xbe, 0x0c };
        try testing.expectEqualSlices(u8, &expected, writer.finish());
    }
    {
        // DataEnum::Sho(0x6969, 0x07)
        var writer = Writer.init(&buffer);
        try writer.writeVariant(DataEnum.sho);
        try writer.writeU16(0x6969);
        try writer.writeU8(0x07);
        try testing.expectEqualSlices(u8, &.{ 0x05, 0xe9, 0xd2, 0x01, 0x07 }, writer.finish());
    }
}

// `source/postcard/tests/loopback.rs`, `loopback`, at commit
// 872b9082589ebd1384a1b95ca232b1727bcddd29. postcard 1.1.3. A sequence is a
// count and then that many elements; a byte array and a string are the same
// shape. `FnvIndexMap` is a sequence of pairs, which is the same count again.
test "golden: the loopback sequence, string and char vectors" {
    var buffer: [64]u8 = undefined;

    {
        // heapless::Vec<[0x01, 0x02, 0x03, 0x04]>
        var writer = Writer.init(&buffer);
        try writer.writeLen(4);
        for ([_]u8{ 1, 2, 3, 4 }) |element| try writer.writeU8(element);
        try testing.expectEqualSlices(u8, &.{ 0x04, 0x01, 0x02, 0x03, 0x04 }, writer.finish());

        var reader = Reader.init(&.{ 0x04, 0x01, 0x02, 0x03, 0x04 });
        const count = try reader.readLen();
        try testing.expectEqual(@as(usize, 4), count);
        for (0..count) |index| try testing.expectEqual(index + 1, try reader.readU8());
        try reader.finish();
    }
    {
        // heapless::String "helLO!"
        var writer = Writer.init(&buffer);
        try writer.writeStr("helLO!");
        const expected = [_]u8{ 0x06, 'h', 'e', 'l', 'L', 'O', '!' };
        try testing.expectEqualSlices(u8, &expected, writer.finish());

        var reader = Reader.init(&.{ 0x06, 'h', 'e', 'l', 'L', 'O', '!' });
        try testing.expectEqualStrings("helLO!", try reader.readStr());
        try reader.finish();
    }
    {
        // std::ffi::CString "heLlo", which postcard carries as a byte buffer
        // rather than a string.
        var writer = Writer.init(&buffer);
        try writer.writeBytes("heLlo");
        try testing.expectEqualSlices(u8, &.{ 0x05, 'h', 'e', 'L', 'l', 'o' }, writer.finish());

        var reader = Reader.init(&.{ 0x05, 'h', 'e', 'L', 'l', 'o' });
        try testing.expectEqualStrings("heLlo", try reader.readBytes());
        try reader.finish();
    }
    {
        // FnvIndexMap { 1: 5, 2: 6, 3: 7, 4: 8 }
        var writer = Writer.init(&buffer);
        try writer.writeLen(4);
        for ([_]u8{ 1, 2, 3, 4 }) |key| {
            try writer.writeU8(key);
            try writer.writeU8(key + 4);
        }
        const expected = [_]u8{ 0x04, 0x01, 0x05, 0x02, 0x06, 0x03, 0x07, 0x04, 0x08 };
        try testing.expectEqualSlices(u8, &expected, writer.finish());
    }
    {
        // A `char` is a string on the wire, so these are string vectors of one
        // to four UTF-8 bytes.
        const chars = [_]struct { text: []const u8, bytes: []const u8 }{
            .{ .text = "z", .bytes = &.{ 0x01, 0x7a } },
            .{ .text = "\u{00a2}", .bytes = &.{ 0x02, 0xc2, 0xa2 } },
            .{ .text = "\u{10348}", .bytes = &.{ 0x04, 0xf0, 0x90, 0x8d, 0x88 } },
            .{ .text = "\u{1f97a}", .bytes = &.{ 0x04, 0xf0, 0x9f, 0xa5, 0xba } },
        };
        for (chars) |char| {
            var writer = Writer.init(&buffer);
            try writer.writeStr(char.text);
            try testing.expectEqualSlices(u8, char.bytes, writer.finish());

            var reader = Reader.init(char.bytes);
            try testing.expectEqualStrings(char.text, try reader.readStr());
            try reader.finish();
        }
    }
}

// `source/postcard/tests/loopback.rs`, `loopback`, `NewTypeStruct` and
// `TupleStruct` at commit 872b9082589ebd1384a1b95ca232b1727bcddd29.
// postcard 1.1.3. A tuple and a fixed-size array are inline: no count, and
// `u8` is one byte apiece whatever its value.
test "golden: the loopback tuple and inline vectors" {
    var buffer: [16]u8 = undefined;

    {
        var writer = Writer.init(&buffer);
        try writer.writeU32(5);
        try testing.expectEqualSlices(u8, &.{0x05}, writer.finish());
    }
    {
        // (0x12u8, 0xc7a5u16)
        var writer = Writer.init(&buffer);
        try writer.writeU8(0x12);
        try writer.writeU16(0xc7a5);
        try testing.expectEqualSlices(u8, &.{ 0x12, 0xa5, 0x8f, 0x03 }, writer.finish());

        var reader = Reader.init(&.{ 0x12, 0xa5, 0x8f, 0x03 });
        try testing.expectEqual(@as(u8, 0x12), try reader.readU8());
        try testing.expectEqual(@as(u16, 0xc7a5), try reader.readU16());
        try reader.finish();
    }
    {
        // ((0xa0, 0x1234))
        var writer = Writer.init(&buffer);
        try writer.writeU8(0xa0);
        try writer.writeU16(0x1234);
        try testing.expectEqualSlices(u8, &.{ 0xa0, 0xb4, 0x24 }, writer.finish());
    }
    {
        var writer = Writer.init(&buffer);
        try writer.writeArray(4, &.{ 1, 2, 3, 4 });
        try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, writer.finish());

        var reader = Reader.init(&.{ 1, 2, 3, 4 });
        try testing.expectEqual([4]u8{ 1, 2, 3, 4 }, try reader.readArray(4));
        try reader.finish();
    }
}

test "varint width limits match the spec table" {
    try testing.expectEqual(@as(usize, 3), varintMax(u16));
    try testing.expectEqual(@as(usize, 5), varintMax(u32));
    try testing.expectEqual(@as(usize, 10), varintMax(u64));
    try testing.expectEqual(@as(usize, 19), varintMax(u128));
    try testing.expectEqual(@as(u8, 3), varintMaxLastByte(u16));
    try testing.expectEqual(@as(u8, 15), varintMaxLastByte(u32));
    try testing.expectEqual(@as(u8, 1), varintMaxLastByte(u64));
}

test "varint boundary table" {
    const u32_vectors = [_]struct { value: u32, bytes: []const u8 }{
        .{ .value = 0, .bytes = &.{0x00} },
        .{ .value = 1, .bytes = &.{0x01} },
        .{ .value = 127, .bytes = &.{0x7f} },
        .{ .value = 128, .bytes = &.{ 0x80, 0x01 } },
        .{ .value = 255, .bytes = &.{ 0xff, 0x01 } },
        .{ .value = 256, .bytes = &.{ 0x80, 0x02 } },
        .{ .value = 65535, .bytes = &.{ 0xff, 0xff, 0x03 } },
        .{ .value = 65536, .bytes = &.{ 0x80, 0x80, 0x04 } },
        .{ .value = 16777215, .bytes = &.{ 0xff, 0xff, 0xff, 0x07 } },
        .{ .value = 2147483647, .bytes = &.{ 0xff, 0xff, 0xff, 0xff, 0x07 } },
        .{ .value = std.math.maxInt(u32), .bytes = &.{ 0xff, 0xff, 0xff, 0xff, 0x0f } },
    };
    const u64_vectors = [_]struct { value: u64, bytes: []const u8 }{
        .{ .value = 0, .bytes = &.{0x00} },
        .{ .value = 1, .bytes = &.{0x01} },
        .{ .value = 127, .bytes = &.{0x7f} },
        .{ .value = 128, .bytes = &.{ 0x80, 0x01 } },
        .{ .value = 255, .bytes = &.{ 0xff, 0x01 } },
        .{ .value = 256, .bytes = &.{ 0x80, 0x02 } },
        .{ .value = 65535, .bytes = &.{ 0xff, 0xff, 0x03 } },
        .{ .value = 65536, .bytes = &.{ 0x80, 0x80, 0x04 } },
        .{ .value = 4294967295, .bytes = &.{ 0xff, 0xff, 0xff, 0xff, 0x0f } },
        // 63 bits is exactly nine whole groups of seven, so this is nine bytes
        // and not ten: the tenth group would carry nothing. It is
        // `maxInt(i64)`, not `maxInt(u64)` — the latter is the u64 maximum and
        // is the row below.
        .{ .value = 0x7fff_ffff_ffff_ffff, .bytes = &.{
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
        } },
        .{ .value = 0xffff_ffff_ffff_ffff, .bytes = &.{
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
        } },
    };

    for (u32_vectors) |vector| {
        var buffer: [varintMax(u32)]u8 = undefined;
        var writer = Writer.init(&buffer);
        try writer.writeU32(vector.value);
        try testing.expectEqualSlices(u8, vector.bytes, writer.finish());

        var reader = Reader.init(vector.bytes);
        try testing.expectEqual(vector.value, try reader.readU32());
        try reader.finish();
    }
    for (u64_vectors) |vector| {
        var buffer: [varintMax(u64)]u8 = undefined;
        var writer = Writer.init(&buffer);
        try writer.writeU64(vector.value);
        try testing.expectEqualSlices(u8, vector.bytes, writer.finish());

        var reader = Reader.init(vector.bytes);
        try testing.expectEqual(vector.value, try reader.readU64());
        try reader.finish();
    }
}

test "an over-long varint is rejected, not truncated" {
    // One byte past the widest legal encoding, at every width.
    try testing.expectError(error.BadVarint, expectU16(&.{ 0x80, 0x80, 0x80, 0x00 }));
    try testing.expectError(error.BadVarint, expectU32(&.{ 0x80, 0x80, 0x80, 0x80, 0x80, 0x00 }));
    const u64_overlong = [_]u8{ 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00 };
    try testing.expectError(error.BadVarint, expectU64(&u64_overlong));
    // Last byte wider than the type, at every width.
    try testing.expectError(error.ValueOutOfRange, expectU16(&.{ 0xff, 0xff, 0x04 }));
    try testing.expectError(error.ValueOutOfRange, expectU32(&.{ 0xff, 0xff, 0xff, 0xff, 0x10 }));
    const u64_too_large = [_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02 };
    try testing.expectError(error.ValueOutOfRange, expectU64(&u64_too_large));
    // Every continuation bit set, with nothing to terminate them.
    try testing.expectError(error.BadVarint, expectU64(&[_]u8{0x80} ** varintMax(u64)));
    // And one byte short of that, which runs out before it can be judged.
    try testing.expectError(error.UnexpectedEnd, expectU64(&[_]u8{0x80} ** (varintMax(u64) - 1)));
}

test "a bool byte other than 0 or 1 is rejected" {
    for ([_]u8{ 0x02, 0x7f, 0x80, 0xff }) |byte| {
        var reader = Reader.init(&.{byte});
        try testing.expectError(error.BadBool, reader.readBool());
    }
    for ([_]bool{ false, true }) |value| {
        var buffer: [1]u8 = undefined;
        var writer = Writer.init(&buffer);
        try writer.writeBool(value);
        var reader = Reader.init(writer.finish());
        try testing.expectEqual(value, try reader.readBool());
        try reader.finish();
    }
}

test "an unknown enum discriminant is rejected by an exhaustive enum" {
    // Three, the first past the last BasicEnum; a u16-wide value, which is one
    // legal `varint(u16)` and one legal `varint(u32)`; and a full u32, which is
    // a well-formed discriminant of a type this build has no arm for.
    for ([_][]const u8{
        &.{0x03},
        &.{ 0xff, 0xff, 0x03 },
        &.{ 0xff, 0xff, 0xff, 0xff, 0x0f },
    }) |bytes| {
        var reader = Reader.init(bytes);
        try testing.expectError(error.UnknownVariant, reader.readVariant(BasicEnum));
    }
}

test "a non-exhaustive enum accepts a tag it has no named arm for" {
    // The `_` field is an unnamed arm for every tag the tag type can hold, so
    // a peer may name one this build has never heard of and the read still
    // succeeds. The caller is left holding a value no name matches, which is
    // what the `switch`/`tagName` sentence in `readVariant` is about.
    const Open = enum(u32) { known, _ };
    const cases = [_]struct { bytes: []const u8, value: u32, named: bool }{
        // The named arm, the first tag past it, and a full u32.
        .{ .bytes = &.{0x00}, .value = 0, .named = true },
        .{ .bytes = &.{0x07}, .value = 7, .named = false },
        .{ .bytes = &.{ 0xff, 0xff, 0xff, 0xff, 0x0f }, .value = std.math.maxInt(u32), .named = false },
    };
    for (cases) |case| {
        var reader = Reader.init(case.bytes);
        const tag = try reader.readVariant(Open);
        try testing.expectEqual(case.value, @intFromEnum(tag));
        try testing.expectEqual(case.named, std.enums.tagName(Open, tag) != null);
        try reader.finish();
    }

    // The tag type is the boundary: an `enum(u8)` cannot represent 300, so
    // that one is still `UnknownVariant` even though the enum is open.
    const Narrow = enum(u8) { known, _ };
    var narrow_reader = Reader.init(&.{ 0xac, 0x02 }); // 300
    try testing.expectError(error.UnknownVariant, narrow_reader.readVariant(Narrow));
}

test "an open enum's unknown tag survives a write and a read" {
    const Open = enum(u32) { known, _ };
    var buffer: [16]u8 = undefined;
    var writer = Writer.init(&buffer);
    try writer.writeVariant(@as(Open, @enumFromInt(7)));
    try testing.expectEqualSlices(u8, &.{0x07}, writer.finish());

    var reader = Reader.init(writer.finish());
    try testing.expectEqual(@as(u32, 7), @intFromEnum(try reader.readVariant(Open)));
    try reader.finish();
}

test "an invalid utf-8 string is rejected" {
    // A lone continuation byte, a two-byte sequence with no continuation, an
    // over-long encoding of `/`, and a surrogate half. Each carries a length
    // that matches its payload, so the rejection is the encoding and not the
    // length.
    const bad = [_][]const u8{
        &.{ 0x01, 0x80 },
        &.{ 0x02, 0xc2, 0x41 },
        &.{ 0x02, 0xc0, 0xaf },
        &.{ 0x03, 0xed, 0xa0, 0x80 },
    };
    for (bad) |bytes| {
        var reader = Reader.init(bytes);
        try testing.expectError(error.InvalidUtf8, reader.readStr());
    }
    // The same bytes are a legal byte string, which is the difference between
    // `readStr` and `readBytes`.
    var reader = Reader.init(&.{ 0x01, 0x80 });
    try testing.expectEqualSlices(u8, &.{0x80}, try reader.readBytes());
    try reader.finish();
}

test "an option tag other than 0 or 1 is rejected" {
    for ([_]u8{ 0x02, 0xff }) |byte| {
        var reader = Reader.init(&.{byte});
        try testing.expectError(error.BadOptionTag, reader.readOption());
    }
    {
        var buffer: [8]u8 = undefined;
        var writer = Writer.init(&buffer);
        try writer.writeOption(false);
        try testing.expectEqualSlices(u8, &.{0x00}, writer.finish());
        var reader = Reader.init(writer.finish());
        try testing.expectEqual(false, try reader.readOption());
        try reader.finish();
    }
    {
        var buffer: [8]u8 = undefined;
        var writer = Writer.init(&buffer);
        try writer.writeOption(true);
        try writer.writeU32(7);
        try testing.expectEqualSlices(u8, &.{ 0x01, 0x07 }, writer.finish());
        var reader = Reader.init(writer.finish());
        try testing.expectEqual(true, try reader.readOption());
        try testing.expectEqual(@as(u32, 7), try reader.readU32());
        try reader.finish();
    }
}

test "trailing bytes are detected" {
    {
        var reader = Reader.init(&.{ 0x01, 0x02, 0x03 });
        try testing.expectEqual(true, try reader.readBool());
        try testing.expectEqual(error.TrailingBytes, reader.finish());
    }
    {
        // A reader with nothing left over is finished by definition.
        var reader = Reader.init(&.{0x01});
        try testing.expectEqual(true, try reader.readBool());
        try reader.finish();
    }
    {
        // An empty message is finished, and is not the same as one byte short.
        var reader = Reader.init(&.{});
        try reader.finish();
    }
}

test "every field type round trips" {
    var buffer: [128]u8 = undefined;

    {
        var writer = Writer.init(&buffer);
        try writer.writeU8(200);
        try testing.expectEqualSlices(u8, &.{200}, writer.finish());
        var reader = Reader.init(&.{200});
        try testing.expectEqual(@as(u8, 200), try reader.readU8());
        try reader.finish();
    }
    {
        var writer = Writer.init(&buffer);
        try writer.writeI8(-128);
        try testing.expectEqualSlices(u8, &.{0x80}, writer.finish());
        var reader = Reader.init(&.{0x80});
        try testing.expectEqual(@as(i8, -128), try reader.readI8());
        try reader.finish();
    }
    {
        var writer = Writer.init(&buffer);
        try writer.writeU16(std.math.maxInt(u16));
        var reader = Reader.init(writer.finish());
        try testing.expectEqual(std.math.maxInt(u16), try reader.readU16());
        try reader.finish();
    }
    {
        var writer = Writer.init(&buffer);
        try writer.writeI16(std.math.minInt(i16));
        var reader = Reader.init(writer.finish());
        try testing.expectEqual(std.math.minInt(i16), try reader.readI16());
        try reader.finish();
    }
    {
        var writer = Writer.init(&buffer);
        try writer.writeU32(std.math.maxInt(u32));
        var reader = Reader.init(writer.finish());
        try testing.expectEqual(std.math.maxInt(u32), try reader.readU32());
        try reader.finish();
    }
    {
        var writer = Writer.init(&buffer);
        try writer.writeI32(std.math.minInt(i32));
        var reader = Reader.init(writer.finish());
        try testing.expectEqual(std.math.minInt(i32), try reader.readI32());
        try reader.finish();
    }
    {
        var writer = Writer.init(&buffer);
        try writer.writeU64(std.math.maxInt(u64));
        var reader = Reader.init(writer.finish());
        try testing.expectEqual(std.math.maxInt(u64), try reader.readU64());
        try reader.finish();
    }
    {
        var writer = Writer.init(&buffer);
        try writer.writeI64(std.math.minInt(i64));
        var reader = Reader.init(writer.finish());
        try testing.expectEqual(std.math.minInt(i64), try reader.readI64());
        try reader.finish();
    }
    {
        var writer = Writer.init(&buffer);
        try writer.writeBytes(&.{ 0x00, 0xff, 0x80 });
        var reader = Reader.init(writer.finish());
        try testing.expectEqualSlices(u8, &.{ 0x00, 0xff, 0x80 }, try reader.readBytes());
        try reader.finish();
    }
    {
        var writer = Writer.init(&buffer);
        try writer.writeStr("");
        try testing.expectEqualSlices(u8, &.{0x00}, writer.finish());
        var reader = Reader.init(&.{0x00});
        try testing.expectEqualStrings("", try reader.readStr());
        try reader.finish();
    }
    {
        // A sequence is a count and then that many elements, and the count is
        // only meaningful once they are there.
        var writer = Writer.init(&buffer);
        try writer.writeLen(3);
        for ([_]u8{ 1, 2, 3 }) |element| try writer.writeU8(element);
        var reader = Reader.init(writer.finish());
        try testing.expectEqual(@as(usize, 3), try reader.readLen());
        for (0..3) |index| try testing.expectEqual(index + 1, try reader.readU8());
        try reader.finish();
    }
    {
        var writer = Writer.init(&buffer);
        try writer.writeVariant(DataEnum.chi);
        var reader = Reader.init(writer.finish());
        try testing.expectEqual(DataEnum.chi, try reader.readVariant(DataEnum));
        try reader.finish();
    }
    {
        var writer = Writer.init(&buffer);
        try writer.writeArray(32, &[_]u8{0xab} ** 32);
        var reader = Reader.init(writer.finish());
        try testing.expectEqual([_]u8{0xab} ** 32, try reader.readArray(32));
        try reader.finish();
    }
}

test "two spellings of one value collapse onto the same bytes" {
    // postcard does not enforce canonicalization, so `[0x80, 0x00]` is a
    // legitimate second spelling of 0. The encoder is canonical, so decoding
    // either and re-encoding has to give the same bytes or two spellings of one
    // value produce two tickets.
    var reader = Reader.init(&.{ 0x80, 0x00 });
    const value = try reader.readU16();
    try reader.finish();
    try testing.expectEqual(@as(u16, 0), value);

    var buffer: [varintMax(u16)]u8 = undefined;
    var writer = Writer.init(&buffer);
    try writer.writeU16(value);
    try testing.expectEqualSlices(u8, &.{0x00}, writer.finish());
}

test "a writer with no room reports it rather than growing" {
    {
        var buffer: [1]u8 = undefined;
        var writer = Writer.init(&buffer);
        try writer.writeU8(0x01);
        try testing.expectError(error.BufferFull, writer.writeU8(0x02));
        // The byte that did fit is kept and the length is not advanced past it.
        try testing.expectEqualSlices(u8, &.{0x01}, writer.finish());
        try testing.expectEqual(@as(usize, 0), writer.remaining());
    }
    {
        var buffer: [1]u8 = undefined;
        var writer = Writer.init(&buffer);
        try testing.expectError(error.BufferFull, writer.writeU16(0x1234));
        // The first group of the varint fitted; the second did not.
        try testing.expectEqualSlices(u8, &.{0xb4}, writer.finish());
    }
    {
        // A length prefix that fits is written even when the payload behind it
        // cannot: the buffer ran out, not the message.
        var buffer: [3]u8 = undefined;
        var writer = Writer.init(&buffer);
        try testing.expectError(error.BufferFull, writer.writeBytes(&.{ 1, 2, 3, 4 }));
        try testing.expectEqualSlices(u8, &.{0x04}, writer.finish());
    }
}

test "every proper prefix of a message is a declared error" {
    const u8_message = [_]u8{0xff};
    try expectNoPrefixDecodes(Reader.readU8, &u8_message);
    try expectNoPrefixDecodes(Reader.readI8, &u8_message);
    try expectNoPrefixDecodes(Reader.readBool, &u8_message);

    const u16_message = [_]u8{ 0xc7, 0xcb, 0x02 };
    try expectNoPrefixDecodes(Reader.readU16, &u16_message);
    try expectNoPrefixDecodes(Reader.readI16, &u16_message);

    const u32_message = [_]u8{ 0x92, 0xe8, 0xac, 0xed, 0x0c };
    try expectNoPrefixDecodes(Reader.readU32, &u32_message);
    try expectNoPrefixDecodes(Reader.readI32, &u32_message);

    const u64_message = [_]u8{ 0xef, 0x9b, 0xaf, 0x85, 0x89, 0xcf, 0x95, 0x9a, 0x12 };
    try expectNoPrefixDecodes(Reader.readU64, &u64_message);
    try expectNoPrefixDecodes(Reader.readI64, &u64_message);

    const len_message = [_]u8{ 0x04, 0x01, 0x02, 0x03, 0x04 };
    try expectNoPrefixDecodes(Reader.readLen, &len_message);

    const bytes_message = [_]u8{ 0x02, 0xc2, 0xa2 };
    try expectNoPrefixDecodes(Reader.readBytes, &bytes_message);
    try expectNoPrefixDecodes(Reader.readStr, &bytes_message);

    // A tag on its own is a complete field, so the message here is the tag
    // alone and its only proper prefix is empty.
    const option_message = [_]u8{0x01};
    try expectNoPrefixDecodes(readOptionOnly, &option_message);

    // A discriminant padded out to three bytes is still one discriminant, and
    // every proper prefix of it is an unterminated varint.
    const variant_message = [_]u8{ 0x81, 0x80, 0x00 };
    try expectNoPrefixDecodes(readVariantOnly, &variant_message);
    var reader = Reader.init(&variant_message);
    try testing.expectEqual(DataEnum.bim, try reader.readVariant(DataEnum));
    try reader.finish();

    const array_message = [_]u8{ 1, 2, 3, 4 };
    try expectNoPrefixDecodes(readArrayOnly, &array_message);
}

test "arbitrary bytes never panic and never leave the error set" {
    const corpus = [_][]const u8{
        &.{},
        &.{0x00},
        &.{0xff},
        &.{0x80},
        &.{0x02},
        &.{ 0x80, 0x00 },
        &.{ 0x01, 0xff },
        &.{ 0x05, 0x01 },
        &[_]u8{0x80} ** varintMax(u64),
        &[_]u8{0xff} ** varintMax(u64),
        &[_]u8{0xff} ** (varintMax(u64) + 1),
        &.{ 0xff, 0xff, 0xff, 0xff, 0x0f, 0xff, 0xff, 0xff, 0xff, 0x0f },
        &.{ 0x04, 0x01, 0x02, 0x03 },
        &.{ 0x01, 0xc2, 0xa2 },
        &.{ 0x0a, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a },
    };
    for (corpus) |bytes| {
        try expectDeclaredErrors(Reader.readU8, bytes);
        try expectDeclaredErrors(Reader.readI8, bytes);
        try expectDeclaredErrors(Reader.readBool, bytes);
        try expectDeclaredErrors(Reader.readU16, bytes);
        try expectDeclaredErrors(Reader.readI16, bytes);
        try expectDeclaredErrors(Reader.readU32, bytes);
        try expectDeclaredErrors(Reader.readI32, bytes);
        try expectDeclaredErrors(Reader.readU64, bytes);
        try expectDeclaredErrors(Reader.readI64, bytes);
        try expectDeclaredErrors(Reader.readLen, bytes);
        try expectDeclaredErrors(Reader.readBytes, bytes);
        try expectDeclaredErrors(Reader.readStr, bytes);
        try expectDeclaredErrors(readOptionOnly, bytes);
        try expectDeclaredErrors(readVariantOnly, bytes);
        try expectDeclaredErrors(readArrayOnly, bytes);
        // Reading a field and finishing must also land in the error set, and
        // must not read past the end on the way.
        try expectDeclaredFinishErrors(bytes);
    }
}

fn readOptionOnly(reader: *Reader) Error!bool {
    return reader.readOption();
}

fn readVariantOnly(reader: *Reader) Error!DataEnum {
    return reader.readVariant(DataEnum);
}

fn readArrayOnly(reader: *Reader) Error![4]u8 {
    return reader.readArray(4);
}

fn expectU16(bytes: []const u8) Error!u16 {
    var reader = Reader.init(bytes);
    return reader.readU16();
}

fn expectU32(bytes: []const u8) Error!u32 {
    var reader = Reader.init(bytes);
    return reader.readU32();
}

fn expectU64(bytes: []const u8) Error!u64 {
    var reader = Reader.init(bytes);
    return reader.readU64();
}

/// Every proper prefix of a canonical encoding must fail, and must fail through
/// the error set rather than by reading past the end. The prefix is not the
/// whole message, so there is nothing in it for the field to return.
fn expectNoPrefixDecodes(read: anytype, encoded: []const u8) !void {
    for (0..encoded.len) |length| {
        var reader = Reader.init(encoded[0..length]);
        if (read(&reader)) |_| {
            return error.TestUnexpectedResult;
        } else |_| {}
    }
}

/// Whatever the bytes, a reader returns a value or returns an error from
/// `Error`, and the return type proves the second half. What is left is that it
/// terminates and leaves the reader usable, so the sweep calls each reader
/// twice: an offset that ran past the end would fault on the second call's
/// `self.buffer[self.offset..]`.
fn expectDeclaredErrors(read: anytype, bytes: []const u8) !void {
    var reader = Reader.init(bytes);
    if (read(&reader)) |_| {} else |_| {}
    if (read(&reader)) |_| {} else |_| {}
}

/// Reading one field and then finishing, which is what a caller does on a
/// framed message where a decode failure has to leave the reader accounted for.
fn expectDeclaredFinishErrors(bytes: []const u8) !void {
    var reader = Reader.init(bytes);
    if (reader.readU8()) |_| {} else |_| {}
    if (reader.finish()) |_| {} else |_| {}
}
