//! Fuzz target for postcard, the codec every other wire format is serialised
//! through.
//!
//! One target file and one corpus directory per decoder: `zig build fuzz`
//! replays the corpus, and `zig build fuzz --fuzz=<N>` hands the same corpus
//! to Zig's coverage-guided fuzzer and lets it mutate for N iterations. A
//! decoder is only worth this once the same bytes have been shown not to
//! panic, and this one is the bottom of the stack: a ticket, a pkarr record, a
//! relay frame and a `RangeSpec` are all postcard underneath, so a byte that
//! reaches the wrong field here reaches the wrong field in all of them.
//!
//! postcard is a codec and not a message, so there is no single type to
//! decode. There are fifteen read methods and their fifteen write
//! counterparts, and this file offers the bytes to all of them three ways.
//!
//! 1. **Rejection**, which is the strictest of the three and the one that
//!    matters, because this decoder is the attack surface every other wire
//!    format sits on. Each read method is offered the whole input and its
//!    outcome is compared against a reference written from
//!    `spec/src/wire-format.md` rather than from `Reader`, so the *reason* a
//!    decode was refused is checked and not only the fact of it: a decoder
//!    that accepted an illegal encoding or refused a legal one is caught
//!    although neither panics. The reader's offset is checked to be still
//!    inside the input, and every read is made twice, because the second call
//!    is where an offset that walked off the end faults.
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
//! A `Record` holds one message of every shape the codec has, so the fuzzer
//! also walks fields in sequence, a count and the elements it names, a
//! trailing byte, and a whole message that has a second spelling. The next
//! decoder's target is this file with the per-field loop and the record
//! replaced by that decoder's one message type.
//!
//! Nothing here tightens the decoder. A panic, a wrong error, or an encoding
//! that decodes when the spec says it should not is a finding about
//! `src/wire/postcard.zig`, and the answer is to report it.

const std = @import("std");
const ozai = @import("ozai");
const postcard = ozai.postcard;
const Reader = postcard.Reader;
const Writer = postcard.Writer;
const Error = postcard.Error;
const t = std.testing;

/// Seeds are the bytes a peer would hand over as a postcard message.
///
/// `captured_struct` and `captured_string` are vectors from
/// `jamesmunns/postcard` at commit 872b9082589ebd1384a1b95ca232b1727bcddd29 —
/// `loopback`'s `BasicU8S` struct and its `heapless::String "helLO!"` — so a
/// mutation starts from something upstream actually wrote. `captured_record`
/// is a message of every shape the codec has, its first three fields carrying
/// the values upstream's `BasicU8S` used, and `captured_record_trailing_byte`
/// is that with one byte behind it, which is a second message rather than a
/// longer one. `captured_record_zero` is that record with every varint zero and
/// every string empty, which is the cheapest valid record there is — eighteen
/// one-byte fields — so a mutation of it has more room than any other seed here
/// to land on another valid record.
///
/// The rest are the shapes the decoder has a rule for and a fuzzer would not
/// reach on its own: nothing at all, one byte, a varint truncated at each of
/// the three widths, an unterminated varint at the widest width, a varint one
/// group past the width, a length prefix of `0xFF` groups with nothing behind
/// it, a length prefix wider than the buffer can ever satisfy, an element
/// count with no elements, a `bool` byte of two, an `Option` tag of two, a
/// discriminant this build has no arm for, a string whose length is right and
/// whose bytes are not UTF-8, and the documented second spelling of zero.
///
/// `str_then_varint` is the one the fuzzer found, and it is a finding about
/// this file rather than about the decoder: a well-formed string with a
/// `varint` behind it is a message with a field behind it, and the reference
/// that judged a string by the whole tail instead of the payload it named
/// called it `InvalidUtf8`. It is here because a corpus is the record of what
/// the oracles got wrong as much as of what the decoder does.
///
/// `bool_two` and `option_two` are the same byte, which is the point: one rule
/// and two methods, and a target that reached only one of them would not know
/// the other has it.
///
/// `test/corpus/postcard/` is the record, and a file there is live only once it
/// is named here.
const corpus = [_][]const u8{
    @embedFile("corpus/postcard/empty"), // 0 bytes: no field at all
    @embedFile("corpus/postcard/one_byte"), // 0xff: a u8, and no varint terminator
    @embedFile("corpus/postcard/captured_struct"), // upstream: a whole BasicU8S
    @embedFile("corpus/postcard/captured_string"), // upstream: "helLO!"
    @embedFile("corpus/postcard/captured_record"), // one of every shape
    @embedFile("corpus/postcard/captured_record_trailing_byte"), // that, and one byte
    @embedFile("corpus/postcard/captured_record_zero"), // a record of nothing at all
    @embedFile("corpus/postcard/noncanonical_zero"), // 0 as two groups
    @embedFile("corpus/postcard/u16_truncated"), // the loopback u16, one byte short
    @embedFile("corpus/postcard/u32_truncated"), // the loopback u32, one byte short
    @embedFile("corpus/postcard/u64_truncated"), // the loopback u64, one byte short
    @embedFile("corpus/postcard/overlong_varint"), // ten groups, none of which ends it
    @embedFile("corpus/postcard/u64_too_large"), // a tenth group of two
    @embedFile("corpus/postcard/length_no_payload"), // a u32 length of 2^32-1
    @embedFile("corpus/postcard/length_wider_than_buffer"), // a u64 length of 2^64-1
    @embedFile("corpus/postcard/count_no_elements"), // a count, and nothing behind it
    @embedFile("corpus/postcard/bool_two"), // 2, which is not a bool
    @embedFile("corpus/postcard/option_two"), // 2, which is not an Option tag
    @embedFile("corpus/postcard/unknown_variant"), // one past the last arm
    @embedFile("corpus/postcard/invalid_utf8"), // a length that fits, bytes that do not
    @embedFile("corpus/postcard/str_then_varint"), // the fuzzer found this one
};

/// Long enough for a `Record` to fit, since every field of one has a floor of
/// its own and a shorter window would make the record path dead code, and long
/// enough for a mutated input to still reach a length check it was not grown
/// for. A decode borrows the input, so the widest decoded `str` is this long.
const input_buffer_len = 128;

/// A record's fixed fields cost at most 74 bytes: three for the leading
/// `varint(u16)`, ten each for the two `varint(u64)`, the element count and
/// the two length prefixes, five each for the discriminant and the option
/// payload, one each for the `u8`, the `bool` and the option tag, and eight for
/// the inline array. The three payloads behind the prefixes cannot be longer
/// together than the input they were read from, so 202 bytes is the ceiling
/// that follows and 203 is the same message with one varint group widened.
const reencode_len = 256;

comptime {
    // A seed longer than the window the fuzzer reads into would be cut short
    // on its way to the oracle, and the length checks would never see the rest.
    for (corpus) |seed| std.debug.assert(seed.len <= input_buffer_len);
}

/// The fuzzer keeps one of these by pointer for the whole run, so it is empty
/// by design: everything the oracle needs is comptime.
const Context = struct {};

test "postcard decode" {
    // A fuzz test is a plain test to a plain build. Without `-ffuzz` the runner
    // walks the corpus instead of handing it to the fuzzer, which is what makes
    // a bare `zig build fuzz` a bounded gate rather than an empty step.
    try t.fuzz(Context{}, testOne, .{ .corpus = &corpus });
}

fn testOne(_: Context, smith: *t.Smith) anyerror!void {
    var buffer: [input_buffer_len]u8 = undefined;
    // `in` is the corpus entry verbatim while the corpus is replayed, and null
    // when the fuzzer drives, in which case `slice` consumes its input.
    const bytes = if (smith.in) |replay| replay else buffer[0..smith.slice(&buffer)];
    try check(bytes);
}

/// One read method and its matching write method, and the two oracles that
/// need both.
///
/// `read` and `encode` are the pair the format says are one field, so a case
/// that names them names a whole field type. `condemn` is a reference verdict
/// written from the spec, which is what makes the rejection oracle check the
/// reason rather than the fact. `spell` produces a second legal encoding of
/// one message, which is what the stability oracle needs and which a format
/// that enforced canonicalization would not have.
///
/// Both `encode` and `spell` are optional because a length prefix is not a
/// field: it is the prefix of one, and a bare `readLen` result has no encoding
/// that decodes on its own, because the count is judged against the bytes
/// behind it and `writeLen` writes none. The `bytes` and `str` cases are
/// where a count's round trip lives, and the one case that has no `encode` is
/// the one whose whole behaviour is a rejection rule.
fn Case(comptime T: type) type {
    return struct {
        name: []const u8,
        read: *const fn (*Reader) Error!T,
        condemn: *const fn (bytes: []const u8) ?Error,
        encode: ?*const fn (*Writer, T) Error!void = null,
        spell: ?*const fn (canonical: []const u8, out: []u8) ?[]const u8 = null,
    };
}

const u8_cases = [_]Case(u8){
    .{ .name = "u8", .read = Reader.readU8, .encode = Writer.writeU8, .condemn = referenceByte },
};

/// `i8` is a table of its own rather than a second row of the `u8` one: the
/// two are the same byte on the wire and not the same type in a case, and a
/// group is one type so that one loop covers it.
const i8_cases = [_]Case(i8){
    .{ .name = "i8", .read = Reader.readI8, .encode = Writer.writeI8, .condemn = referenceByte },
};

const tag_cases = [_]Case(bool){
    .{
        .name = "bool",
        .read = Reader.readBool,
        .encode = Writer.writeBool,
        .condemn = referenceBool,
    },
    .{
        .name = "option",
        .read = Reader.readOption,
        .encode = Writer.writeOption,
        .condemn = referenceOption,
    },
};

/// The varint widths, one table each rather than a table of pairs. A group is
/// one value type, and `u16` and `i16` are not one type however much of a
/// `varint(u16)` they share; the zigzag is the whole of the difference between
/// them, and the reference and the second spelling are the same on both sides
/// of it, which is the point.
const u16_cases = [_]Case(u16){
    .{
        .name = "u16",
        .read = Reader.readU16,
        .encode = Writer.writeU16,
        .condemn = referenceU16,
        .spell = widerSpelling(u16),
    },
};

const i16_cases = [_]Case(i16){
    .{
        .name = "i16",
        .read = Reader.readI16,
        .encode = Writer.writeI16,
        .condemn = referenceU16,
        .spell = widerSpelling(u16),
    },
};

const u32_cases = [_]Case(u32){
    .{
        .name = "u32",
        .read = Reader.readU32,
        .encode = Writer.writeU32,
        .condemn = referenceU32,
        .spell = widerSpelling(u32),
    },
};

const i32_cases = [_]Case(i32){
    .{
        .name = "i32",
        .read = Reader.readI32,
        .encode = Writer.writeI32,
        .condemn = referenceU32,
        .spell = widerSpelling(u32),
    },
};

const u64_cases = [_]Case(u64){
    .{
        .name = "u64",
        .read = Reader.readU64,
        .encode = Writer.writeU64,
        .condemn = referenceU64,
        .spell = widerSpelling(u64),
    },
};

const i64_cases = [_]Case(i64){
    .{
        .name = "i64",
        .read = Reader.readI64,
        .encode = Writer.writeI64,
        .condemn = referenceU64,
        .spell = widerSpelling(u64),
    },
};

/// A count, in a group of its own because it is a number and not a slice, and
/// with no `encode`: `readLen` judges the count against the bytes behind it,
/// so a count on its own is not a message and re-encoding one would produce
/// bytes no reader could read back. Everything a count can be wrong about is a
/// rejection, and that is the one thing this case is for; the two rules the
/// count adds over a `varint(u64)` — wider than `usize`, wider than the bytes
/// that follow — are exactly what `referenceLen` recomputes.
const len_cases = [_]Case(usize){
    .{ .name = "len", .read = Reader.readLen, .condemn = referenceLen },
};

/// A length-prefixed byte string and a length-prefixed string, which are the
/// same bytes with one validation between them, so the pair is what shows the
/// difference and what checks that `readStr` is the only one that has it.
const slice_cases = [_]Case([]const u8){
    .{
        .name = "bytes",
        .read = Reader.readBytes,
        .encode = Writer.writeBytes,
        .condemn = referenceLen,
        .spell = widerSpelling(u64),
    },
    .{
        .name = "str",
        .read = Reader.readStr,
        .encode = Writer.writeStr,
        .condemn = referenceStr,
        .spell = widerSpelling(u64),
    },
};

const variant_cases = [_]Case(Probe){
    .{
        .name = "variant",
        .read = readProbe,
        .encode = writeProbe,
        .condemn = referenceVariant,
        .spell = widerSpelling(u32),
    },
};

/// The inline array, which is the one field with no length prefix: `readArray`
/// knows its width from `N` alone, so a decode that wanted the count to bound
/// it would be borrowing a rule the format does not give it.
const array_cases = [_]Case([8]u8){
    .{
        .name = "array",
        .read = readArray8,
        .encode = writeArray8,
        .condemn = referenceArray,
    },
};

/// One group of cases over one input. The group is homogeneous in its value
/// type, so the two loops are written once and instantiated once per type and
/// nothing about a group is known at run time.
fn checkField(comptime Group: anytype, bytes: []const u8) !void {
    for (Group[0..]) |case| {
        try checkRejection(case, bytes);
        try checkRoundTrip(case, bytes);
    }
}

/// All fifteen read methods, then the composite. One call per group, and the
/// groups are the checklist: a read method with no group is a rule the fuzzer
/// never offers the bytes to.
fn check(bytes: []const u8) !void {
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
    try checkRecord(bytes);
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
            std.debug.print("postcard fuzz: {s} accepted an illegal encoding: {s}\n", .{
                case.name,
                @errorName(reason),
            });
            return error.IllegalEncodingAccepted;
        }
    } else |err| {
        const reason = case.condemn(bytes);
        if (reason == null) {
            std.debug.print("postcard fuzz: {s} refused a legal encoding: {s}\n", .{
                case.name,
                @errorName(err),
            });
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
    var writer = Writer.init(&canonical_buf);
    try encode(&writer, value);
    const canonical = writer.finish();

    var recoder = Reader.init(canonical);
    const recoded = try case.read(&recoder);
    try recoder.finish();
    if (!valuesEql(value, recoded)) {
        std.debug.print("postcard fuzz: {s} did not survive its own encoding\n", .{case.name});
        return error.ValueRoundTripMismatch;
    }

    var again: [reencode_len]u8 = undefined;
    var rewriter = Writer.init(&again);
    try encode(&rewriter, recoded);
    try t.expectEqualSlices(u8, canonical, rewriter.finish());

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
    var alt_writer = Writer.init(&alt_out);
    try encode(&alt_writer, alt_value);
    try t.expectEqualSlices(u8, canonical, alt_writer.finish());
}

/// One value against another.
///
/// A slice borrows the buffer it was read from, so the two are different
/// slices of different buffers and only the bytes behind them are comparable.
/// Everything else is compared through its bytes for the same reason: one
/// comparison, and no way for a new field to be left out of it by accident.
fn valuesEql(a: anytype, b: @TypeOf(a)) bool {
    if (@TypeOf(a) == []const u8) return std.mem.eql(u8, a, b);
    return std.mem.eql(u8, std.mem.asBytes(&a), std.mem.asBytes(&b));
}

// The references below, one per rule in `spec/src/wire-format.md` at commit
// 872b9082589ebd1384a1b95ca232b1727bcddd29. Each returns why `bytes` cannot be
// read, or null when it can. They are written from the specification rather
// than from `src/wire/postcard.zig` on purpose: an oracle that called the
// decoder to find out what the decoder should have said would agree with the
// bug it is meant to catch. A rule the references do not cover has no case
// pointing at it, so the table above is the checklist of what is checked.

/// A raw byte: one byte, whatever its value. `u8` and `i8` are the two widths
/// postcard does not varint, which is the rule a reimplementation gets wrong.
fn referenceByte(bytes: []const u8) ?Error {
    if (bytes.len == 0) return error.UnexpectedEnd;
    return null;
}

/// A `bool` is one byte and only 0 or 1 is one.
fn referenceBool(bytes: []const u8) ?Error {
    if (bytes.len == 0) return error.UnexpectedEnd;
    if (bytes[0] > 1) return error.BadBool;
    return null;
}

/// An `Option` tag is one byte and only 0 or 1 is one.
fn referenceOption(bytes: []const u8) ?Error {
    if (bytes.len == 0) return error.UnexpectedEnd;
    if (bytes[0] > 1) return error.BadOptionTag;
    return null;
}

fn referenceU16(bytes: []const u8) ?Error {
    return referenceVarint(u16, bytes);
}

fn referenceU32(bytes: []const u8) ?Error {
    return referenceVarint(u32, bytes);
}

fn referenceU64(bytes: []const u8) ?Error {
    return referenceVarint(u64, bytes);
}

/// The two varint rules, which are different rules.
///
/// A terminator one group past the width is `BadVarint`, because no spelling
/// makes the number fit the type. A terminator inside the last group carrying
/// more value bits than the type has is `ValueOutOfRange`, because the number
/// is one the type cannot hold. The last group of a `varint(T)` carries
/// `bits % 7` bits and no more, which is what makes the second rule checkable
/// at all.
///
/// Computed as a scan bounded by the width, where `readVarint` counts to the
/// width and reads as it goes: the same rule, two computations, so a decoder
/// that miscounts its groups disagrees here instead of agreeing with itself.
fn referenceVarint(comptime Unsigned: type, bytes: []const u8) ?Error {
    const width = postcard.varintMax(Unsigned);
    var index: usize = 0;
    while (index < width and index < bytes.len) : (index += 1) {
        const byte = bytes[index];
        if (byte & 0x80 != 0) continue;
        if (index == width - 1 and byte > postcard.varintMaxLastByte(Unsigned)) {
            return error.ValueOutOfRange;
        }
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
fn referenceLen(bytes: []const u8) ?Error {
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
/// message that ends in a well-formed string and then one bad byte is a
/// message with a field behind it, not a string that failed. The fuzzer found
/// that, on a length of one and a tail holding a `u64`; `referenceLen` above
/// has already established that the slice is inside the input.
fn referenceStr(bytes: []const u8) ?Error {
    if (referenceLen(bytes)) |reason| return reason;
    const scanned = scanVarint(bytes);
    const length = std.math.cast(usize, scanned.value) orelse return error.BadLength;
    if (!std.unicode.utf8ValidateSlice(bytes[scanned.len..][0..length])) {
        return error.InvalidUtf8;
    }
    return null;
}

/// A fixed-size array is inline: no length prefix, so its width is the only
/// thing that bounds it.
fn referenceArray(bytes: []const u8) ?Error {
    if (bytes.len < 8) return error.UnexpectedEnd;
    return null;
}

/// A discriminant is a `varint(u32)` whatever the Zig tag type is, and a
/// number this build has no arm for is `UnknownVariant` rather than a value
/// invented for it.
fn referenceVariant(bytes: []const u8) ?Error {
    if (referenceVarint(u32, bytes)) |reason| return reason;
    const scanned = scanVarint(bytes);
    const discriminant = std.math.cast(u32, scanned.value) orelse return error.ValueOutOfRange;
    if (std.enums.fromInt(Probe, discriminant) == null) return error.UnknownVariant;
    return null;
}

/// The number the leading varint spells, and how many bytes it took.
///
/// Only ever called once `referenceVarint` has said the bytes are one, which is
/// what bounds the loop to a width of ten and the shift with it. The bound is
/// written down because a shift of seven bits per byte over an unbounded
/// buffer is an overflow panic and a fuzz target should not be one.
fn scanVarint(bytes: []const u8) struct { value: u64, len: usize } {
    var value: u64 = 0;
    for (bytes[0..@min(bytes.len, 10)], 0..) |byte, index| {
        value |= @as(u64, byte & 0x7f) << @intCast(7 * index);
        if (byte & 0x80 == 0) return .{ .value = value, .len = index + 1 };
    }
    unreachable; // `referenceVarint` rejected these bytes, which is the only way here.
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
/// the `BadVarint` the rejection oracle is built out of.
fn widerSpelling(comptime Unsigned: type) fn ([]const u8, []u8) ?[]const u8 {
    return struct {
        fn spell(canonical: []const u8, out: []u8) ?[]const u8 {
            var end: usize = 0;
            while (end < canonical.len and canonical[end] & 0x80 != 0) : (end += 1) {}
            if (end == canonical.len) return null;
            if (end + 1 >= postcard.varintMax(Unsigned)) return null;
            if (out.len < canonical.len + 1) return null;
            @memcpy(out[0..end], canonical[0..end]);
            out[end] = canonical[end] | 0x80;
            out[end + 1] = 0x00;
            @memcpy(out[end + 2 .. canonical.len + 1], canonical[end + 1 ..]);
            return out[0 .. canonical.len + 1];
        }
    }.spell;
}

/// The three-arm enum of postcard's own loopback test, `BasicEnum`, copied
/// here because the fuzz target is a module root of its own and the copy in
/// `src/wire/postcard.zig` is not exported. A three-arm type is the smallest
/// one with a discriminant to refuse, and `bim` is arm one rather than arm
/// zero so that a decoder reading a discriminant as a length has something to
/// get wrong.
const Probe = enum(u32) { bib, bim, bap };

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

/// A message with one field of every shape the codec has.
///
/// The order is the one `writeRecord` writes in and no other. The first field
/// is a varint, which upstream's own `BasicU8S` also opens with, and it is
/// what gives the whole message a second spelling at offset zero: a record
/// beginning with a raw byte would have no varint to widen, and the stability
/// oracle would have nothing to widen.
const Record = struct {
    st: u16,
    count: usize,
    ei: u8,
    sf: u64,
    flag: bool,
    tag: Probe,
    payload: u64,
    text: []const u8,
    blob: []const u8,
    present: bool,
    some: u32,
    tagged: [8]u8,
};

/// A record and the elements its count named.
///
/// A sequence is a count and then that many elements, and the loop that reads
/// them is the caller's rather than a method on `Reader`, so the harness holds
/// them itself. The bound on the count is `readLen`'s — the bytes that follow —
/// and the array is sized from the same number, so the two cannot disagree.
const Decoded = struct {
    record: Record,
    elements: [input_buffer_len]u8,
    count: usize,
};

/// The record, field by field, in `writeRecord`'s order and nowhere else.
fn decodeRecord(reader: *Reader) Error!Decoded {
    var out: Decoded = undefined;
    out.record.st = try reader.readU16();
    out.count = try reader.readLen();
    // A peer names any count it likes, and this harness holds the elements in
    // a fixed array, so a count past it is refused here rather than indexed.
    // `readLen` bounds the count by the bytes that follow, which is the same
    // bound, and that rule is fuzzed on its own by the `len` case; what is
    // left for the record is the composition, not the rule.
    if (out.count > out.elements.len) return error.BadLength;
    for (out.elements[0..out.count]) |*element| element.* = try reader.readU8();
    out.record.ei = try reader.readU8();
    out.record.sf = try reader.readU64();
    out.record.flag = try reader.readBool();
    out.record.tag = try reader.readVariant(Probe);
    out.record.payload = try reader.readU64();
    out.record.text = try reader.readStr();
    out.record.blob = try reader.readBytes();
    out.record.present = try reader.readOption();
    out.record.some = if (out.record.present) try reader.readU32() else 0;
    out.record.tagged = try reader.readArray(8);
    // A record is a whole message, so it is finished here rather than by the
    // caller: bytes left over are a second message, and a decoder that ignored
    // its own remainder is what lets two messages share one encoding.
    try reader.finish();
    return out;
}

fn writeRecord(writer: *Writer, decoded: Decoded) Error!void {
    const record = decoded.record;
    try writer.writeU16(record.st);
    try writer.writeLen(decoded.count);
    for (decoded.elements[0..decoded.count]) |element| try writer.writeU8(element);
    try writer.writeU8(record.ei);
    try writer.writeU64(record.sf);
    try writer.writeBool(record.flag);
    try writer.writeVariant(record.tag);
    try writer.writeU64(record.payload);
    try writer.writeStr(record.text);
    try writer.writeBytes(record.blob);
    try writer.writeOption(record.present);
    if (record.present) try writer.writeU32(record.some);
    try writer.writeArray(8, &record.tagged);
}

/// Every field, through `std.meta.fields` so that a field added to `Record` is
/// compared without this having to be edited, and the count and its elements
/// alongside them because a count that does not match the elements behind it is
/// a record no encoder could have written.
fn recordsEql(a: Decoded, b: Decoded) bool {
    if (a.count != b.count) return false;
    if (!std.mem.eql(u8, a.elements[0..a.count], b.elements[0..b.count])) return false;
    inline for (std.meta.fields(Record)) |field| {
        if (!valuesEql(@field(a.record, field.name), @field(b.record, field.name))) return false;
    }
    return true;
}

/// The three oracles again, over a whole message rather than one field.
///
/// A record is a whole message, so unlike a framed field it is finished: bytes
/// left over are a second message, and `decodeRecord` is where that is said.
fn checkRecord(bytes: []const u8) !void {
    var reader = Reader.init(bytes);
    const decoded = decodeRecord(&reader) catch |err| {
        // A composite's failure is one field's failure, and the tables above
        // have already judged every field's reason against a reference. What
        // a record can say that no field can is *where* it stopped, and the
        // leading varint pins that: a varint the reference condemns is
        // condemned before a single later field is read, so the record has to
        // fail with exactly that reason and not one of its own.
        if (referenceU16(bytes)) |reason| try t.expectEqual(reason, err);
        return;
    };

    var canonical_buf: [reencode_len]u8 = undefined;
    var writer = Writer.init(&canonical_buf);
    try writeRecord(&writer, decoded);
    const canonical = writer.finish();

    // Oracle: extent. The canonical spelling of a message is never longer than
    // the message it was read from — a varint is at its shortest and a length
    // prefix at its smallest — so a re-encoding that outgrew the input is a
    // decode that inflated something on the way in.
    try t.expect(canonical.len <= bytes.len);

    var recoder = Reader.init(canonical);
    const recoded = try decodeRecord(&recoder);
    if (!recordsEql(decoded, recoded)) {
        std.debug.print("postcard fuzz: a record did not survive its own encoding\n", .{});
        return error.RecordRoundTripMismatch;
    }

    var again: [reencode_len]u8 = undefined;
    var rewriter = Writer.init(&again);
    try writeRecord(&rewriter, recoded);
    try t.expectEqualSlices(u8, canonical, rewriter.finish());

    // Oracle: stability, over the whole message. The leading `varint(u16)` is
    // one group wider and nothing else changes, so the same record has to come
    // back out of it and has to encode to the bytes above.
    var alt_buf: [reencode_len]u8 = undefined;
    const other = widerSpelling(u16)(canonical, &alt_buf) orelse return;
    var alt_reader = Reader.init(other);
    const alt_decoded = try decodeRecord(&alt_reader);
    if (!recordsEql(decoded, alt_decoded)) {
        std.debug.print("postcard fuzz: a record read two spellings as two records\n", .{});
        return error.RecordSpellingMismatch;
    }

    var alt_out: [reencode_len]u8 = undefined;
    var alt_writer = Writer.init(&alt_out);
    try writeRecord(&alt_writer, alt_decoded);
    try t.expectEqualSlices(u8, canonical, alt_writer.finish());
}
