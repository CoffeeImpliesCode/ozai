//! The fifteen single-field oracles: what the bytes have to be before a read
//! method may accept them, that a value survives its own encoding, and that
//! two spellings of one value are still one value.
//!
//! `test/postcard_fuzz.zig` is the driver that offers the bytes, and
//! `test/postcard_record_oracle.zig` is the same three oracles over a whole
//! message. This module holds the per-shape tables and the three checks, and
//! holds no I/O of its own: a reader's end is judged against the verdicts of
//! `test/postcard_decode_reference.zig`, which imports no codec and is written
//! from `spec/src/wire-format.md` rather than from `src/wire/postcard.zig`. An
//! oracle that called the decoder to find out what the decoder should have said
//! would agree with the bug it is meant to catch, so `verdict` below is the only
//! place the two vocabularies meet.
//!
//! 1. **Rejection**, which is the strictest of the three and the one that
//!    matters, because this decoder is the attack surface every other wire
//!    format sits on. Each read method is offered the whole input and its
//!    outcome is compared against its reference, so the *reason* a decode was
//!    refused is checked and not only the fact of it: a decoder that accepted
//!    an illegal encoding or refused a legal one is caught although neither
//!    panics. The reader's offset is checked to be still inside the input, and
//!    every read is made twice, because the second call is where an offset that
//!    walked off the end faults.
//! 2. **Round trip.** A value that decoded is encoded, decoded again and
//!    encoded again, and the two encodings are compared byte for byte. The
//!    fixed point is the second encoding and never the input, because postcard
//!    does not enforce canonicalization: `[0x80, 0x00]` is a legal second
//!    spelling of zero, and it is the encoder that collapses it.
//! 3. **Stability.** Every value the format can spell more than one way is
//!    spelled a second way — the same varint one group longer, which is the
//!    rule `src/wire/postcard.zig` documents — and the decoder has to reach
//!    the same value and the encoder the same bytes from it. This is the
//!    oracle that keeps two spellings of one value from becoming two tickets.
//!
//! The groups below are the fifteen read methods the codec has, one per group,
//! and a read method with no group is a rule the fuzzer never offers the bytes
//! to.

const std = @import("std");
const ozai = @import("ozai");
const Reader = ozai.postcard.Reader;
const Writer = ozai.postcard.Writer;
const Error = ozai.postcard.Error;
const ref = @import("postcard_decode_reference.zig");
const t = std.testing;

/// The widest input the driver reads into, and so the widest input any oracle
/// is offered. `Decoded` in the record oracle holds the elements a count names
/// in a fixed array of this width, so a count past it is refused rather than
/// indexed, and long enough for a `Record` to fit, since every field of one
/// has a floor of its own and a shorter window would make the record path dead
/// code. A decode borrows the input, so the widest decoded `str` is this long.
pub const input_buffer_len = 128;

/// The ceiling on a canonical re-encoding, and it is the record that binds it:
/// a record's fixed fields cost at most 74 bytes — three for the leading
/// `varint(u16)`, ten each for the two `varint(u64)`, the element count and the
/// two length prefixes, five each for the discriminant and the option payload,
/// one each for the `u8`, the `bool` and the option tag, and eight for the
/// inline array — and the three payloads behind the prefixes cannot be longer
/// together than the input they were read from, so 202 bytes is the ceiling
/// that follows and 203 is the same message with one varint group widened. One
/// field on its own is bounded by the input it came from and one group.
pub const reencode_len = 256;

/// The three-arm enum of postcard's own loopback test, `BasicEnum`, copied
/// here because the fuzz target is a module root of its own and the copy in
/// `src/wire/postcard.zig` is not exported. A three-arm type is the smallest
/// one with a discriminant to refuse, and `bim` is arm one rather than arm
/// zero so that a decoder reading a discriminant as a length has something to
/// get wrong. The record oracle reads the same type in its own message.
pub const Probe = enum(u32) { bib, bim, bap };

/// One read method and its matching write method, and the two oracles that
/// need both.
///
/// `read` and `encode` are the pair the format says are one field, so a case
/// that names them names a whole field type. `condemn` is a reference verdict
/// in the reference module's own `Refusal` vocabulary, which is what makes the
/// rejection oracle check the reason rather than the fact; `verdict` is how one
/// of those refusals becomes an error to compare against. `spell` is the
/// varint width the format can spell this value two ways at, which is what the
/// stability oracle needs and which a format that enforced canonicalization
/// would not have.
///
/// `encode` and `spell` are nullable because a length prefix is not a field: it
/// is the prefix of one, and a bare `readLen` result has no encoding that
/// decodes on its own, because the count is judged against the bytes behind it
/// and `writeLen` writes none. The `bytes` and `str` cases are where a count's
/// round trip lives, and the one case that has no `encode` is the one whose
/// whole behaviour is a rejection rule.
fn Case(comptime T: type) type {
    return struct {
        name: []const u8,
        read: *const fn (*Reader) Error!T,
        condemn: *const fn (bytes: []const u8) ?ref.Refusal,
        encode: ?*const fn (*Writer, T) Error!void = null,
        spell: ?*const fn (canonical: []const u8, out: []u8) ?[]const u8 = null,
    };
}

/// The reference's verdict in the decoder's error set.
///
/// The only place this module knows what `postcard.Error` names, written as a
/// switch rather than a cast so that a decoder which renamed or dropped a rule
/// stops the build here instead of quietly changing what an oracle compares.
pub fn verdict(refusal: ?ref.Refusal) ?ozai.postcard.Error {
    return switch (refusal orelse return null) {
        error.UnexpectedEnd => error.UnexpectedEnd,
        error.BadBool => error.BadBool,
        error.BadOptionTag => error.BadOptionTag,
        error.BadVarint => error.BadVarint,
        error.ValueOutOfRange => error.ValueOutOfRange,
        error.BadLength => error.BadLength,
        error.UnknownVariant => error.UnknownVariant,
        error.InvalidUtf8 => error.InvalidUtf8,
    };
}

/// A reference bound to the width its field is read at.
///
/// Three references take their width — or the arms a discriminant may name — as
/// a comptime parameter, which a one-argument function pointer cannot carry,
/// so the shapes that need one name the binding here instead. Each binding is a
/// function value with nothing in it but the shape: no closure to allocate and
/// no state to carry, because the shape is an argument and not a capture.
fn varintRefusal(comptime Unsigned: type) *const fn ([]const u8) ?ref.Refusal {
    return struct {
        fn condemn(bytes: []const u8) ?ref.Refusal {
            return ref.referenceVarint(Unsigned, bytes);
        }
    }.condemn;
}

fn variantRefusal(comptime Discriminant: type) *const fn ([]const u8) ?ref.Refusal {
    return struct {
        fn condemn(bytes: []const u8) ?ref.Refusal {
            return ref.referenceVariant(Discriminant, bytes);
        }
    }.condemn;
}

fn arrayRefusal(comptime width: usize) *const fn ([]const u8) ?ref.Refusal {
    return struct {
        fn condemn(bytes: []const u8) ?ref.Refusal {
            return ref.referenceArray(width, bytes);
        }
    }.condemn;
}

/// The fifteen read methods, one table per shape and one case per read method.
///
/// A case says which oracles it has rather than leaving them out: `null` is a
/// claim that this field has no such encoding and no second spelling, and the
/// oracles below act on it. The tables are literals because a case is a field's
/// whole behaviour, and a builder over six arguments would say the same thing
/// more slowly.
const u8_cases = [_]Case(u8){.{
    .name = "u8",
    .read = Reader.readU8,
    .condemn = ref.referenceByte,
    .encode = Writer.writeU8,
}};

/// `i8` is a table of its own rather than a second row of the `u8` one: the
/// two are the same byte on the wire and not the same type in a case, and a
/// group is one type so that one loop covers it.
const i8_cases = [_]Case(i8){.{
    .name = "i8",
    .read = Reader.readI8,
    .condemn = ref.referenceByte,
    .encode = Writer.writeI8,
}};

const tag_cases = [_]Case(bool){
    .{
        .name = "bool",
        .read = Reader.readBool,
        .condemn = ref.referenceBool,
        .encode = Writer.writeBool,
    },
    .{
        .name = "option",
        .read = Reader.readOption,
        .condemn = ref.referenceOption,
        .encode = Writer.writeOption,
    },
};

/// The varint widths, one table each rather than a table of pairs. A group is
/// one value type, and `u16` and `i16` are not one type however much of a
/// `varint(u16)` they share; the zigzag is the whole of the difference between
/// them, and the reference and the second spelling are the same on both sides
/// of it, which is the point and is the second parameter of every row here.
const u16_cases = varintCases(u16, u16, Reader.readU16, Writer.writeU16);
const i16_cases = varintCases(i16, u16, Reader.readI16, Writer.writeI16);
const u32_cases = varintCases(u32, u32, Reader.readU32, Writer.writeU32);
const i32_cases = varintCases(i32, u32, Reader.readI32, Writer.writeI32);
const u64_cases = varintCases(u64, u64, Reader.readU64, Writer.writeU64);
const i64_cases = varintCases(i64, u64, Reader.readI64, Writer.writeI64);

/// The one case of a varint width, which is all a signed and an unsigned
/// group differ by: same read and write pair per side, same reference, same
/// second spelling, and a name the value type already spells.
fn varintCases(
    comptime T: type,
    comptime Unsigned: type,
    comptime read: *const fn (*Reader) Error!T,
    comptime encode: *const fn (*Writer, T) Error!void,
) [1]Case(T) {
    return .{.{
        .name = @typeName(T),
        .read = read,
        .encode = encode,
        .condemn = varintRefusal(Unsigned),
        .spell = widerSpelling(Unsigned),
    }};
}

/// A count, in a group of its own because it is a number and not a slice, and
/// with no `encode`: `readLen` judges the count against the bytes behind it,
/// so a count on its own is not a message and re-encoding one would produce
/// bytes no reader could read back. Everything a count can be wrong about is a
/// rejection, and that is the one thing this case is for; the two rules the
/// count adds over a `varint(u64)` — wider than `usize`, wider than the bytes
/// that follow — are exactly what `referenceLen` recomputes.
const len_cases = [_]Case(usize){.{
    .name = "len",
    .read = Reader.readLen,
    .condemn = ref.referenceLen,
}};

/// A length-prefixed byte string and a length-prefixed string, which are the
/// same bytes with one validation between them, so the pair is what shows the
/// difference and what checks that `readStr` is the only one that has it.
const slice_cases = [_]Case([]const u8){
    .{
        .name = "bytes",
        .read = Reader.readBytes,
        .condemn = ref.referenceLen,
        .encode = Writer.writeBytes,
        .spell = widerSpelling(u64),
    },
    .{
        .name = "str",
        .read = Reader.readStr,
        .condemn = ref.referenceStr,
        .encode = Writer.writeStr,
        .spell = widerSpelling(u64),
    },
};

const variant_cases = [_]Case(Probe){.{
    .name = "variant",
    .read = readProbe,
    .condemn = variantRefusal(Probe),
    .encode = writeProbe,
    .spell = widerSpelling(u32),
}};

/// The inline array, which is the one field with no length prefix: `readArray`
/// knows its width from `N` alone, so a decode that wanted the count to bound
/// it would be borrowing a rule the format does not give it.
const array_cases = [_]Case([8]u8){.{
    .name = "array",
    .read = readArray8,
    .condemn = arrayRefusal(8),
    .encode = writeArray8,
}};

/// All fifteen read methods, one call per group. The composite is the record
/// oracle's half and is not repeated here: a field is offered the whole input,
/// and so is the message.
pub fn checkAllFields(bytes: []const u8) !void {
    try checkField(u8_cases, bytes);
    try checkField(i8_cases, bytes);
    try checkField(tag_cases, bytes);
    try checkField(u16_cases, bytes);
    try checkField(i16_cases, bytes);
    try checkField(u32_cases, bytes);
    try checkField(i32_cases, bytes);
    try checkField(u64_cases, bytes);
    try checkField(i64_cases, bytes);
    try checkField(len_cases, bytes);
    try checkField(slice_cases, bytes);
    try checkField(variant_cases, bytes);
    try checkField(array_cases, bytes);
}

/// One group of cases over one input. The group is homogeneous in its value
/// type, so the two loops are written once and instantiated once per type and
/// nothing about a group is known at run time.
fn checkField(comptime Group: anytype, bytes: []const u8) !void {
    for (Group[0..]) |case| {
        try checkRejection(case, bytes);
        try checkRoundTrip(case, bytes);
    }
}

/// The rejection oracle, over one read method and one input.
///
/// Three things, and only one of them is a fact about the error. Every read
/// method is typed `Error!T`, so an undeclared error cannot reach here at all;
/// what the fuzzer can catch is a *wrong* declared one, and that is the
/// comparison against `condemn`. The other two are about the buffer: the
/// offset is a number this oracle can look at, where the next call can only
/// fault on it, and making the call twice is where an offset that ran past the
/// end faults, because `take` slices the buffer at the offset the first call
/// left behind.
fn checkRejection(case: anytype, bytes: []const u8) !void {
    var reader = Reader.init(bytes);
    if (case.read(&reader)) |_| {
        if (case.condemn(bytes)) |reason| {
            blame(case.name, "accepted an illegal encoding", reason);
            return error.IllegalEncodingAccepted;
        }
    } else |err| {
        const reason = verdict(case.condemn(bytes));
        if (reason == null) {
            blame(case.name, "refused a legal encoding", err);
            return error.LegalEncodingRefused;
        }
        try t.expectEqual(reason.?, err);
    }
    try t.expect(reader.offset <= bytes.len);

    if (case.read(&reader)) |_| {} else |_| {}
    try t.expect(reader.offset <= bytes.len);

    // A framed caller reads a field and then asks whether the frame is
    // accounted for, and `finish` is how it asks. The answer is a value or
    // `TrailingBytes`, and either way the offset has to still be inside.
    if (reader.finish()) |_| {} else |_| {}
    try t.expect(reader.offset <= bytes.len);
}

/// A finding, said once: which case, what it did, and the error either the
/// decoder or the reference gave for it.
fn blame(name: []const u8, finding: []const u8, reason: anyerror) void {
    std.debug.print("postcard fuzz: {s} {s}: {s}\n", .{ name, finding, @errorName(reason) });
}

/// The round trip and the stability, over one read method and one input.
///
/// The two share an encoding because they are the same fact seen twice: a value
/// that came from the wire, and the same value the wire was allowed to spell
/// another way.
fn checkRoundTrip(case: anytype, bytes: []const u8) !void {
    // A case with no encoder is a length prefix, which the `Case` doc says
    // why, and its rejection oracle above is the whole of what can be asked.
    const encode = case.encode orelse return;
    var reader = Reader.init(bytes);
    const value = case.read(&reader) catch return;

    var canonical_buf: [reencode_len]u8 = undefined;
    const canonical = try encodeCase(encode, value, &canonical_buf);

    var recoder = Reader.init(canonical);
    const recoded = try case.read(&recoder);
    try recoder.finish();
    if (!valuesEql(value, recoded)) {
        std.debug.print("postcard fuzz: {s} did not survive its own encoding\n", .{case.name});
        return error.ValueRoundTripMismatch;
    }

    var again_buf: [reencode_len]u8 = undefined;
    try t.expectEqualSlices(u8, canonical, try encodeCase(encode, recoded, &again_buf));

    // Oracle: stability. A case with no second spelling is a case the format
    // spells one way, and there is nothing left to check.
    const spell = case.spell orelse return;
    var alt_buf: [reencode_len]u8 = undefined;
    const other = spell(canonical, &alt_buf) orelse return;
    var alt_reader = Reader.init(other);
    const alt_value = try case.read(&alt_reader);
    try alt_reader.finish();
    if (!valuesEql(value, alt_value)) {
        std.debug.print("postcard fuzz: {s} read two spellings as two values\n", .{case.name});
        return error.SpellingValueMismatch;
    }

    var alt_out: [reencode_len]u8 = undefined;
    try t.expectEqualSlices(u8, canonical, try encodeCase(encode, alt_value, &alt_out));
}

/// The value's own spelling, written into a buffer the caller owns. The fixed
/// point is the second of these encodings and never the input, because
/// postcard does not enforce canonicalization.
fn encodeCase(encode: anytype, value: anytype, out: *[reencode_len]u8) Error![]const u8 {
    var writer = Writer.init(out);
    try encode(&writer, value);
    return writer.finish();
}

/// One value against another.
///
/// A slice borrows the buffer it was read from, so the two are different
/// slices of different buffers and only the bytes behind them are comparable.
/// Everything else is compared through its bytes for the same reason: one
/// comparison, and no way for a new field to be left out of it by accident.
/// The record oracle compares its fields through this one function.
pub fn valuesEql(a: anytype, b: @TypeOf(a)) bool {
    if (@TypeOf(a) == []const u8) return std.mem.eql(u8, a, b);
    return std.mem.eql(u8, std.mem.asBytes(&a), std.mem.asBytes(&b));
}

/// The same message with its first varint spelled one group longer.
///
/// The extra group goes immediately after the terminator and carries nothing,
/// which is exactly why postcard can accept it: the specification does not
/// enforce canonicalization, so `[0x80, 0x00]` and `[0x00]` are both zero.
/// It goes there rather than at the end of the message because that is what
/// makes it the same message: on a length prefix the tail behind the varint is
/// the payload, and a zero group at the end of one would be read as part of
/// the number that follows it.
///
/// Null when `canonical` opens with no varint at all, and when the leading
/// varint is already as long as its width allows — one group further would be
/// the `BadVarint` the rejection oracle is built out of. The record oracle
/// widens a whole message's leading varint with it.
pub fn widerSpelling(comptime Unsigned: type) fn ([]const u8, []u8) ?[]const u8 {
    return struct {
        fn spell(canonical: []const u8, out: []u8) ?[]const u8 {
            var end: usize = 0;
            while (end < canonical.len and canonical[end] & 0x80 != 0) : (end += 1) {}
            if (end == canonical.len) return null;
            if (end + 1 >= ref.maxGroups(Unsigned)) return null;
            if (out.len < canonical.len + 1) return null;
            @memcpy(out[0..end], canonical[0..end]);
            out[end] = canonical[end] | 0x80;
            out[end + 1] = 0x00;
            @memcpy(out[end + 2 .. canonical.len + 1], canonical[end + 1 ..]);
            return out[0 .. canonical.len + 1];
        }
    }.spell;
}

// `Reader.readVariant` and `Writer.writeArray` both take a comptime parameter,
// which a function pointer cannot carry, so those two are bound here and the
// rest are named directly in the tables above.

fn readProbe(reader: *Reader) Error!Probe {
    return reader.readVariant(Probe);
}

fn writeProbe(writer: *Writer, value: Probe) Error!void {
    return writer.writeVariant(value);
}

fn readArray8(reader: *Reader) Error![8]u8 {
    return reader.readArray(8);
}

fn writeArray8(writer: *Writer, value: [8]u8) Error!void {
    return writer.writeArray(8, &value);
}
