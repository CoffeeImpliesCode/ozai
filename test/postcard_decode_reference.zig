//! What postcard's bytes have to be before they are a value, written from
//! `spec/src/wire-format.md` at commit
//! 872b9082589ebd1384a1b95ca232b1727bcddd29 of `jamesmunns/postcard` and from
//! nothing else.
//!
//! This is the leaf of the postcard harness. It imports no codec and holds no
//! state, and it answers one question — may these bytes be read? — once for
//! each of the fifteen read methods `test/postcard_scalar_oracle.zig` offers,
//! and once more for the leading varint of a whole message in
//! `test/postcard_record_oracle.zig`. Each function answers with the rule
//! `bytes` breaks, or null when it breaks none.
//!
//! Nothing here asks `src/wire/postcard.zig` what a decode should have said,
//! because an oracle built out of the decoder agrees with the bug it is meant to
//! catch. That is also why the widths below are computed from the type instead
//! of taken from the codec's `varintMax`: one rule, two computations, so a
//! decoder that miscounts its groups disagrees with this file rather than with
//! itself.
//!
//! `Refusal` is this file's own vocabulary for the answers. An oracle turns one
//! of these names into what the decoder returned and compares the two, so a
//! decoder that renames a rule fails the comparison instead of quietly
//! rewriting the oracle.

const std = @import("std");

/// Why some bytes are not a value, one member per rule the specification names.
///
/// Declared here rather than taken from `postcard.Error` so that a codec which
/// dropped, renamed or added a rule cannot change what these references say.
/// `verdict` in the scalar oracle maps one name onto the other, so a rename is
/// a compile error there and never a quiet agreement.
pub const Refusal = error{
    UnexpectedEnd,
    BadBool,
    BadOptionTag,
    BadVarint,
    ValueOutOfRange,
    BadLength,
    UnknownVariant,
    InvalidUtf8,
};

/// The most groups a `varint(Unsigned)` can hold: `ceil(bits / 7)`.
///
/// postcard varint-encodes `u16` and wider only — `u8` and `i8` are one raw
/// byte — so every width here is two bits or more, which is what leaves a last
/// group that can be too narrow for a whole byte of value.
pub fn maxGroups(comptime Unsigned: type) usize {
    return @divFloor(@bitSizeOf(Unsigned) + 6, 7);
}

/// The largest value the last group of a `varint(Unsigned)` may carry.
///
/// Every group before it carries seven bits, so the last one carries what the
/// type has left — two bits of a `u16`, four of a `u32`, one of a `u64` — and
/// nothing more. This is what makes an over-long encoding detectable rather
/// than merely unusual.
fn maxLastByte(comptime Unsigned: type) u8 {
    const spare: u4 = @intCast(@bitSizeOf(Unsigned) - 7 * (maxGroups(Unsigned) - 1));
    const mask: u9 = (@as(u9, 1) << spare) - 1;
    return @truncate(mask);
}

/// A raw byte: one byte, whatever its value. `u8` and `i8` are the two widths
/// postcard does not varint, which is the rule a reimplementation gets wrong.
pub fn referenceByte(bytes: []const u8) ?Refusal {
    if (bytes.len == 0) return error.UnexpectedEnd;
    return null;
}

/// A `bool` is one byte and only 0 or 1 is one.
pub fn referenceBool(bytes: []const u8) ?Refusal {
    if (bytes.len == 0) return error.UnexpectedEnd;
    if (bytes[0] > 1) return error.BadBool;
    return null;
}

/// An `Option` tag is one byte and only 0 or 1 is one.
pub fn referenceOption(bytes: []const u8) ?Refusal {
    if (bytes.len == 0) return error.UnexpectedEnd;
    if (bytes[0] > 1) return error.BadOptionTag;
    return null;
}

/// The two varint rules, which are different rules.
///
/// A terminator one group past the width is `BadVarint`, because no spelling
/// makes the number fit the type. A terminator inside the last group carrying
/// more value bits than the type has is `ValueOutOfRange`, because the number is
/// one the type cannot hold. The last group of a `varint(Unsigned)` carries
/// `maxLastByte` and no more, which is what makes the second rule checkable at
/// all.
///
/// Computed as a scan bounded by the width, which is the rule the spec states
/// rather than the loop a decoder happens to run: same rule, two computations.
/// A decoder that miscounts its groups disagrees here instead of agreeing with
/// itself.
pub fn referenceVarint(comptime Unsigned: type, bytes: []const u8) ?Refusal {
    const width = maxGroups(Unsigned);
    var index: usize = 0;
    while (index < width and index < bytes.len) : (index += 1) {
        const byte = bytes[index];
        if (byte & 0x80 != 0) continue;
        if (index == width - 1 and byte > maxLastByte(Unsigned)) return error.ValueOutOfRange;
        return null;
    }
    // No terminator inside the width: the loop left through the width, so the
    // number is too long, or through the input, so there was never enough of
    // it to say.
    if (bytes.len >= width) return error.BadVarint;
    return error.UnexpectedEnd;
}

/// A length or a count is a `varint(usize)`, read at the widest width a peer
/// may send, and then two rules of its own: a count wider than `usize` cannot
/// index anything on this target, and one wider than the bytes that follow is a
/// frame that cannot be the frame it claims to be. Both are `BadLength` rather
/// than `UnexpectedEnd`, because the buffer is not short.
pub fn referenceLen(bytes: []const u8) ?Refusal {
    if (referenceVarint(u64, bytes)) |reason| return reason;
    const scanned = scanVarint(bytes);
    const length = std.math.cast(usize, scanned.value) orelse return error.BadLength;
    if (length > bytes.len - scanned.len) return error.BadLength;
    return null;
}

/// A string is the same bytes as a byte string and one validation, and the
/// validation is the only thing between the two.
///
/// The slice is the payload the prefix *names*, not the rest of the input: a
/// message that ends in a well-formed string and then one bad byte is a message
/// with a field behind it, not a string that failed. The fuzzer found that, on
/// a length of one and a tail holding a `u64`; `referenceLen` above has already
/// established that the slice is inside the input.
pub fn referenceStr(bytes: []const u8) ?Refusal {
    if (referenceLen(bytes)) |reason| return reason;
    const scanned = scanVarint(bytes);
    const length = std.math.cast(usize, scanned.value) orelse return error.BadLength;
    if (!std.unicode.utf8ValidateSlice(bytes[scanned.len..][0..length])) {
        return error.InvalidUtf8;
    }
    return null;
}

/// A fixed-size array is inline: `width` bytes and no length prefix, so its
/// width is the only thing that bounds it.
pub fn referenceArray(comptime width: usize, bytes: []const u8) ?Refusal {
    if (bytes.len < width) return error.UnexpectedEnd;
    return null;
}

/// A discriminant is a `varint(u32)` whatever the Zig tag type is, and a number
/// `Discriminant` has no arm for is `UnknownVariant` rather than a value
/// invented for it. The arm list is the caller's type, so it is an argument here
/// and not a table in this file.
pub fn referenceVariant(comptime Discriminant: type, bytes: []const u8) ?Refusal {
    if (referenceVarint(u32, bytes)) |reason| return reason;
    const scanned = scanVarint(bytes);
    const discriminant = std.math.cast(u32, scanned.value) orelse return error.ValueOutOfRange;
    if (std.enums.fromInt(Discriminant, discriminant) == null) return error.UnknownVariant;
    return null;
}

/// The number the leading varint spells, and how many bytes it took.
///
/// Only ever called once `referenceVarint` has said the bytes are one, which is
/// what bounds the loop to a width of ten and the shift with it. The bound is
/// written down because a shift of seven bits per byte over an unbounded buffer
/// is an overflow panic and a fuzz target should not be one.
fn scanVarint(bytes: []const u8) struct { value: u64, len: usize } {
    var value: u64 = 0;
    for (bytes[0..@min(bytes.len, 10)], 0..) |byte, index| {
        value |= @as(u64, byte & 0x7f) << @intCast(7 * index);
        if (byte & 0x80 == 0) return .{ .value = value, .len = index + 1 };
    }
    unreachable; // `referenceVarint` rejected these bytes, which is the only way here.
}
