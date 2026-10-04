//! The whole-message oracles: one message of every shape the codec has, and
//! the three oracles over it that no single field can reach.
//!
//! `test/postcard_scalar_oracle.zig` offers the bytes to one read method at a
//! time, which is where a field's own rejection, round trip and second
//! spelling are judged. A `Record` here holds one message of every shape the
//! codec has, so the fuzzer also walks fields in sequence, a count and the
//! elements it names, a trailing byte, and a whole message that has a second
//! spelling — the composition rather than the rules, which the field oracle
//! already holds each of to.
//!
//! The three oracles here are the field ones again plus one of its own: a
//! record is a whole message, so unlike a framed field it is *finished*, and
//! bytes left over are a second message rather than a longer one. Nothing here
//! is a second decoder: the reads are `ozai.postcard`'s, and the references
//! this judges them against are `test/postcard_decode_reference.zig`'s, reached
//! through the scalar module's `verdict`.

const std = @import("std");
const ozai = @import("ozai");
const postcard = ozai.postcard;
const Reader = postcard.Reader;
const Writer = postcard.Writer;
const Error = postcard.Error;
const scalar = @import("postcard_scalar_oracle.zig");
const ref = @import("postcard_decode_reference.zig");
const t = std.testing;

const Probe = scalar.Probe;
const input_buffer_len = scalar.input_buffer_len;
const reencode_len = scalar.reencode_len;

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
/// and the array is sized from the same window the driver reads into, so the
/// two cannot disagree.
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
    // bound, and that rule is fuzzed on its own by the `len` case in the
    // scalar module; what is left for the record is the composition, not the
    // rule.
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
/// a record no encoder could have written. The fields are compared through the
/// scalar module's one comparison, for the reason it gives there.
fn recordsEql(a: Decoded, b: Decoded) bool {
    if (a.count != b.count) return false;
    if (!std.mem.eql(u8, a.elements[0..a.count], b.elements[0..b.count])) return false;
    inline for (std.meta.fields(Record)) |field| {
        const left = @field(a.record, field.name);
        const right = @field(b.record, field.name);
        if (!scalar.valuesEql(left, right)) return false;
    }
    return true;
}

/// The three oracles again, over a whole message rather than one field.
///
/// A record is a whole message, so unlike a framed field it is finished: bytes
/// left over are a second message, and `decodeRecord` is where that is said.
pub fn checkRecord(bytes: []const u8) !void {
    var reader = Reader.init(bytes);
    const decoded = decodeRecord(&reader) catch |err| {
        // A composite's failure is one field's failure, and the scalar
        // module has already judged every field's reason against a reference.
        // What a record can say that no field can is *where* it stopped, and
        // the leading varint pins that: a varint the reference condemns is
        // condemned before a single later field is read, so the record has to
        // fail with exactly that reason and not one of its own.
        const reason = scalar.verdict(ref.referenceVarint(u16, bytes));
        if (reason) |refusal| try t.expectEqual(refusal, err);
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
    const other = scalar.widerSpelling(u16)(canonical, &alt_buf) orelse return;
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
