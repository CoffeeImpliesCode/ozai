//! The DNS answer a pkarr packet's body is: `_iroh.<z32>`, its `TXT` records,
//! and nothing else.
//!
//! `discovery/pkarr.zig` deliberately treats the body as opaque bytes: it signs
//! whatever it is handed and verifies whatever it is given, which is right for
//! the signature and useless for the network. A relay stores the body and a
//! resolver reads records out of it, so somebody has to write one and somebody
//! has to read one. That is this file, and it is one file rather than two
//! because the reader is `lookup_answer.readAnswer` with two arguments
//! supplied here — the transaction and the name — and a second decoder would
//! be a second, disagreeing reader for one grammar.
//!
//! # The two arguments the existing decoder needs, and where they come from
//!
//! `lookup_answer.readAnswer` matches a reply to a question: the `ID` it must
//! echo and the name whose records count. A pkarr body is a reply to no
//! question, so both are fixed rather than asked:
//!
//! * **`ID` is zero.** `discovery/pkarr.zig`'s captured body starts
//!   `0000 8000`, and `readHeader` checks the `ID` first; the zero is what a
//!   body that never had a question carries.
//! * **The name is the signer's own.** The body is published by the node the
//!   packet names, so the records are under `_iroh.<signer's z32>` and nowhere
//!   else. `writeName` builds that name and `readBody` asks under it.
//!
//! # What the bytes are, and the one that pins them
//!
//! ```text
//! 0000 8000 0000 0001 0000 0000   ID 0, QR, no question, one answer
//! 05 5f69726f68                     "_iroh"
//! 34 <52 z32 characters>
//! 00                                the root label
//! 0010 0001 0000001e 001b 1a ...    TXT, IN, TTL 30, RDLENGTH 27, 26 + bytes
//! ```
//!
//!
//! **Records after the first carry a compression pointer, not the name again.**
//! `discovery/pkarr.zig`'s four-record captured packet writes `c00c` — a
//! pointer to offset 12, the header — for every record after the first, which
//! is what makes a 1000-byte body hold four records rather than one. RFC 1035
//! §4.1.4 requires every decoder to understand it and permits every encoder to
//! emit it, and `lookup_name.readName` is the decoder that does.
//!
//! # A record longer than 255 octets is several character strings
//!
//! RFC 1035 §3.3.14's `<character-string>` is one length octet and at most 255
//! octets, and `txt.max_record_length` is 274 — the relay arm with a
//! 253-character host. So the longest legal record cannot be one character
//! string, and a record is written as as many 255-octet strings as it needs.
//! That is not a workaround: RFC 1035 §3.3.14 says a `TXT` record is "one or
//! more" of them, and `lookup_answer.appendTxt` already concatenates a record's
//! strings with nothing between them, which is upstream's own reading
//! (`iroh-dns/src/dns.rs`, `TxtRecordData`). A record over the cap is split
//! here and joined there, and neither side has to know about the other.
//!
//! # Purity
//!
//! No clock, no socket, no allocator, no global. The name is a parameter or
//! caller scratch, the records are a borrowed `RecordSet`, and the output is
//! the caller's buffer. The reader allocates exactly what
//! `lookup_answer.readAnswer` allocates — the records copied into `alloc` —
//! and `Answer.deinit` gives it back.

const std = @import("std");
const key = @import("../base/key.zig");

const resolve = @import("resolve.zig");
const pkarr = @import("pkarr.zig");
const txt = @import("txt.zig");

const host_wire = @import("host_wire.zig");
const lookup_io = @import("lookup_io.zig");
const lookup_name = @import("lookup_name.zig");
const wire = @import("lookup_wire.zig");

/// The `TTL` a written record carries, in whole seconds.
///
/// 30, and 30 is not a guess: it is the `0000001e` in the reference
/// implementation's own captured body, and `discovery/pkarr.zig`'s test
/// comment says the same of its vector. Nothing in this tree reads it back — a
/// pkarr relay decides its own retention and a resolver copies the record — so
/// the value is pinned to what was captured rather than to what would be
/// sensible.
pub const record_ttl_s: u32 = 30;

/// The offset a body's name is written at: the end of the header, and so the
/// offset every record after the first names in its compression pointer.
///
/// `discovery/pkarr.zig`'s four-record captured packet writes `c00c`, which is
/// this number and not a guess about where a name might land.
pub const name_offset: usize = wire.header_length;

/// RFC 1035 §4.1.4's compression pointer: the two high bits set and an offset
/// in the low fourteen. Reached from `lookup_name.name_pointer`, which owns the
/// encoding rule; this is the two-octet width that encoding needs.
pub const pointer_length: usize = 2;

/// RFC 1035 §3.3.14's ceiling on one `<character-string>`: at most 255 octets
/// behind its length octet.
///
/// Below `txt.max_record_length`, which is 274, and that is the whole reason a
/// record longer than this is written as several strings; see the module doc.
pub const max_string_length: usize = 255;

/// Why bytes are not this question's body, or are not one a body may be.
pub const Error = wire.WireError || error{
    /// More records than one body's `ANCOUNT` can carry, or than
    /// `lookup_wire.max_section_records` allows before a walk gives up. A body
    /// with more is a body no reader in this tree will walk, so it is refused
    /// rather than written.
    TooManyRecords,
    /// The records are empty. A pkarr packet with no records publishes a name
    /// and nothing about the node behind it, which is what
    /// `resolve.PkarrPublisher.writeTxtStrings` already answers
    /// `error.NothingPublished` for on the reading side.
    NoRecords,
    /// The body is longer than `pkarr.max_dns_length`, so there is no signable
    /// form of a packet carrying it.
    BodyTooLarge,
};

/// Why a body is not a set of records.
///
/// `lookup_io.Error`, which is `Error` plus `error.OutOfMemory`: the reader
/// copies the records into the caller's allocator, which the writer never does.
/// One name for both halves' union is on `lookup_io`; this is the spelling at
/// the seam where the two meet.
pub const DecodeError = lookup_io.Error;

/// The name a body is published under: `_iroh.<z32>.`, with no origin.
///
/// The origin-free form is upstream's: a publisher signs for itself, and
/// `discovery/pkarr.zig`'s captured body carries exactly this name. An origin
/// would be a DNS TXT question's business (`discovery/dns.zig`'s `queryName`)
/// and not a pkarr body's.
pub fn nameLength() usize {
    return resolve.iroh_txt_name.len + 1 + key.NodeId.z32_length + 1;
}

/// The name `node_id`'s records are published under, written into `out`.
///
/// The result borrows `out`, so a caller that hands the name to a reader which
/// outlives the statement needs storage that outlives the reader; the returned
/// slice is a borrow and says so.
pub fn writeName(out: []u8, node_id: key.NodeId) wire.WireError![]const u8 {
    if (out.len < nameLength()) return error.BufferTooSmall;
    const label = node_id.toZ32();
    var at: usize = 0;
    @memcpy(out[at..][0..resolve.iroh_txt_name.len], resolve.iroh_txt_name);
    at += resolve.iroh_txt_name.len;
    out[at] = '.';
    at += 1;
    @memcpy(out[at..][0..label.len], &label);
    at += label.len;
    out[at] = '.';
    return out[0 .. at + 1];
}

/// How many bytes `writeBody` writes for `records` under `name`.
///
/// Exact rather than an upper bound: the reader reads a `u16` `ANCOUNT` and a
/// `u16` `RDLENGTH` per record, so a buffer sized from anything but this
/// arithmetic and the cap is a buffer whose shortness is a guess.
pub fn bodyLength(name: []const u8, records: txt.RecordSet) usize {
    var set = records;
    var total: usize = wire.header_length + name.len + 1;
    var at: usize = 0;
    while (set.next()) |record| {
        // The first record carries the name; every record after it carries the
        // two-octet pointer the captured four-record packet uses.
        total += (if (at == 0) 0 else pointer_length) +
            host_wire.fixed_length + rdataLength(record);
        at += 1;
    }
    return total;
}

/// Write the answer a pkarr packet's body is: `name`, then one `TXT` record per
/// record of `records`, and return what was written.
///
/// `out` needs `bodyLength(name, records)` bytes or more, and the result
/// borrows `out`. The three refusals are the three ways the arithmetic above
/// can come apart: more records than a body's counts can carry, no records at
/// all, and a body the packet cap will not take.
pub fn writeBody(
    out: []u8,
    name: []const u8,
    records: txt.RecordSet,
) Error![]const u8 {
    var set = records;
    var count: u16 = 0;
    var needed: usize = wire.header_length + name.len + 1;
    while (set.next()) |record| {
        count += 1;
        if (count > wire.max_section_records) return error.TooManyRecords;
        needed += (if (count == 1) 0 else pointer_length) +
            host_wire.fixed_length + rdataLength(record);
    }
    // Checked before the count reaches `u16`'s own ceiling, so an answer this
    // writes always has a count a reader can read back.
    if (count == 0) return error.NoRecords;
    if (needed > pkarr.max_dns_length) return error.BodyTooLarge;
    if (out.len < needed) return error.BufferTooSmall;

    // §4.1.1's header, and the captured one field for field: `ID` zero, `QR`
    // and nothing else, no question section, `count` answers, and no
    // authority or additional section. `AA` is clear because the reference
    // body has it clear, and a pkarr relay is not the authority for
    // `_iroh.<z32>` in the sense the bit means.
    wire.put16(out, 0, 0);
    wire.put16(out, 2, wire.flag_response);
    wire.put16(out, 4, 0);
    wire.put16(out, 6, count);
    wire.put16(out, 8, 0);
    wire.put16(out, 10, 0);

    const name_bytes = try lookup_name.writeName(name, out[wire.header_length..]);
    var at = wire.header_length + name_bytes;
    var written: u16 = 0;
    set = records;
    while (set.next()) |record| {
        written += 1;
        // RFC 1035 §4.1.4's pointer for every record after the first, aimed at
        // the header so it lands on the name the first one wrote.
        if (written > 1) {
            out[at] = lookup_name.name_pointer;
            out[at + 1] = @intCast(name_offset);
            at += pointer_length;
        }
        wire.put16(out, at, wire.type_txt);
        wire.put16(out, at + 2, wire.class_in);
        wire.put32(out, at + 4, record_ttl_s);
        const rdata = rdataLength(record);
        wire.put16(out, at + 8, @intCast(rdata));
        at += host_wire.fixed_length;
        writeStrings(out[at..][0..rdata], record);
        at += rdata;
    }
    return out[0..at];
}

/// How many octets one record's `RDATA` takes on the wire: the record's own
/// bytes, plus one length octet for every `<character-string>` it is written
/// as. See `writeStrings` and the module doc for why that is more than one
/// length octet at all.
fn rdataLength(record: []const u8) usize {
    if (record.len == 0) return 1;
    // The quotient is spelled out rather than taken from `divCeil`, because
    // `divCeil` refuses a zero denominator and `max_string_length` is a
    // `pub const` of 255 that no caller can change: the only error it can
    // return is one this line cannot produce, and paying for the error union to
    // discard it would be a claim about a constant instead of arithmetic about
    // the bytes. `record.len / d` rounds down and the remainder is what decides
    // whether there is a string past it, which is the ceiling exactly.
    const strings = record.len / max_string_length +
        @intFromBool(record.len % max_string_length != 0);
    return record.len + strings;
}

/// §3.3.14's `<character-string>`s for one record: a length octet and that
/// many octets, as many of them as the record needs. `out` is
/// `rdataLength(record)` octets wide, and the two agree because they are the
/// same rule read from either end.
fn writeStrings(out: []u8, record: []const u8) void {
    // A record with no octets is one empty string rather than none, because
    // §3.3.14 says a `TXT` record is "one or more" of them, and a zero-length
    // `RDATA` is not a record at all.
    if (record.len == 0) {
        out[0] = 0;
        return;
    }

    var at: usize = 0;
    var from: usize = 0;
    while (from < record.len) {
        // Named `usize` because `@min` narrows its result to the smallest type
        // that fits both of its arguments, and a `u8` `take` makes `1 + take`
        // arithmetic in eight bits — which overflows for the one record long
        // enough to need a second string, at exactly the length the split is
        // for.
        const take: usize = @min(max_string_length, record.len - from);
        out[at] = @intCast(take);
        @memcpy(out[at + 1 ..][0..take], record[from..][0..take]);
        at += 1 + take;
        from += take;
    }
}

/// Read the records out of `dns`, the body of a packet `node_id` signed.
///
/// `name` and `owner` are scratch of `nameLength()` and
/// `lookup_io.max_name_length` bytes; neither outlives the call, because every
/// value `readAnswer` hands back is copied into `alloc`.
///
/// The transaction is zero and the name is the signer's own; see the module doc
/// for why both are fixed rather than asked.
pub fn readBody(
    alloc: std.mem.Allocator,
    dns: []const u8,
    node_id: key.NodeId,
    name: []u8,
    owner: []u8,
) DecodeError!lookup_io.Answer {
    const asked = try writeName(name, node_id);
    return lookup_io.readAnswer(alloc, dns, asked, 0, owner);
}

const t = std.testing;
const support = @import("lookup_test_support.zig");
test "golden: the written body is the reference implementation's own bytes" {
    var secret = try key.SecretKey.fromSeed(support.captured_seed);
    defer secret.deinit();
    var name: [nameLength()]u8 = undefined;
    const asked = try writeName(&name, secret.nodeId());

    var out: [pkarr.max_dns_length]u8 = undefined;
    const written = try writeBody(&out, asked, .init(support.captured_record));
    try t.expectEqualSlices(u8, try support.hexBytes(&out, support.captured_answer_hex), written);
}

test "every record after the first is a pointer, and a long record is several strings" {
    const secret = try key.SecretKey.fromSeed(support.captured_seed);
    var name: [nameLength()]u8 = undefined;
    const asked = try writeName(&name, secret.nodeId());

    // Three records, one of them over §3.3.14's 255-octet ceiling.
    const first_record = "relay=https://one.example./";
    const longest = "addr=" ++ "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const last_record = "relay=https://two.example./";
    var records: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&records);
    try writer.writeAll(first_record ++ "\x00");
    try writer.writeAll(longest);
    try writer.writeAll("\x00" ++ last_record ++ "\x00");

    var out: [pkarr.max_dns_length]u8 = undefined;
    const written = try writeBody(&out, asked, .init(writer.buffered()));
    try t.expectEqual(bodyLength(asked, .init(writer.buffered())), written.len);
    // The header's count is the number of records, and a body this size is
    // under the cap the writer checks against.
    try t.expectEqual(@as(u16, 3), wire.be16(written, 6));

    // The second record's owner is the pointer, so the body grows by two octets
    // rather than by the name's sixty — and it sits behind the first record,
    // which carries its own name in full and whose `RDATA` is one length octet
    // longer than the record it carries.
    const pointer_at = wire.header_length + asked.len + 1 +
        host_wire.fixed_length + first_record.len + 1;
    try t.expectEqual(lookup_name.name_pointer, written[pointer_at]);
    try t.expectEqual(@as(u8, wire.header_length), written[pointer_at + 1]);

    // And the long record is read back as one record, joined.
    var read_name: [nameLength()]u8 = undefined;
    var owner: [wire.max_name_length]u8 = undefined;
    const read = try readBody(t.allocator, written, secret.nodeId(), &read_name, &owner);
    defer read.deinit(t.allocator);
    const set = switch (read) {
        .records => |value| value,
        else => return error.ExpectedRecords,
    };
    var seen: usize = 0;
    var walk = set;
    while (walk.next()) |record| : (seen += 1) {
        switch (seen) {
            0 => try t.expectEqualStrings(first_record, record),
            1 => try t.expectEqualStrings(longest, record),
            2 => try t.expectEqualStrings(last_record, record),
            else => {},
        }
    }
    try t.expectEqual(@as(usize, 3), seen);
}

test "the three refusals are the three ways the arithmetic comes apart" {
    const secret = try key.SecretKey.fromSeed(support.captured_seed);
    var name: [nameLength()]u8 = undefined;
    const asked = try writeName(&name, secret.nodeId());
    var out: [pkarr.max_dns_length]u8 = undefined;

    // Nothing to publish is not a body.
    try t.expectError(error.NoRecords, writeBody(&out, asked, .init("")));
    // More records than `ANCOUNT` can carry is a body no reader walks.
    const overflow = &@as([(wire.max_section_records + 1) * 2]u8, @bitCast(
        @as([wire.max_section_records + 1][2]u8, @splat(.{ 'a', 0 })),
    ));
    try t.expectError(error.TooManyRecords, writeBody(&out, asked, .init(overflow)));
    // And a short buffer is refused before anything is written.
    try t.expectError(
        error.BufferTooSmall,
        writeBody(out[0..4], asked, .init(support.captured_record)),
    );
}
