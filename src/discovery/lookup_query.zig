//! The question half of a lookup: one RFC 1035 query framed into a buffer, and
//! the bound that says how big that buffer has to be.
//!
//! `lookup_name.zig` encodes the name and `lookup_wire.zig` holds the header's
//! constants; what is left here is the query itself — counts, flags, one
//! question, and the OPT record a query advertises its receive size with.
//! Nothing here reads a reply, and nothing here opens anything.

const std = @import("std");

const dns = @import("dns.zig");
const names = @import("lookup_name.zig");
const wire = @import("lookup_wire.zig");

/// Bytes a query for a presentation `name` of this length occupies.
///
/// `name.len + 1` for the wire name: every dot in the text becomes a length
/// octet, and the name's own trailing dot becomes the terminator RFC 1035
/// §4.1.2 spells "the zero length octet for the null label of the root". The
/// root name is one octet and so comes in under this bound.
pub fn queryLength(name: []const u8) usize {
    return wire.header_length + name.len + 1 + wire.question_length + wire.opt_length;
}

/// What one query is, as far as the wire is concerned.
pub const Query = struct {
    /// RFC 1035 §4.1.1's `ID`, which the answer must echo. Drawn by the caller
    /// from its own generator; see `Retrieval.begin`.
    id: u16,
    /// `QTYPE`. TXT and nothing else: a lookup asks for records, and a name
    /// that answers with something else has published nothing here.
    qtype: u16 = wire.type_txt,
    /// The datagram size to advertise in an OPT record, or null for RFC 1035's
    /// 512-byte message with no OPT at all. Null is the default because it is
    /// what a query carrying no negotiation looks like; `Retrieval` asks for
    /// 1232 because a real answer needs it.
    udp_payload: ?u16 = null,
};

/// Frame one query for `name` into `out`, and hand back what was written.
///
/// `name` is the presentation form with its trailing dot — `discovery/dns.zig`'s
/// `queryName` writes one — and `out` needs `queryLength(name)` bytes.
///
/// No pointers are written, which RFC 1035 §4.1.4 permits ("Programs are free
/// to avoid using pointers in messages they generate") and which keeps this
/// function free of the offset bookkeeping a pointer needs. The reader in
/// `lookup_answer.zig` understands them either way, because every implementation
/// must.
pub fn writeQuery(name: []const u8, query: Query, out: []u8) wire.WireError![]const u8 {
    const payload = query.udp_payload;
    if (out.len < wire.header_length) return error.BufferTooSmall;
    wire.put16(out, 0, query.id);
    // `RD` and nothing else: `QR` is 0 because this is a question, and the
    // three `Z` bits are 0 because §4.1.1 requires it in all queries.
    wire.put16(out, 2, wire.flag_recursion_desired);
    wire.put16(out, 4, 1);
    wire.put16(out, 6, 0);
    wire.put16(out, 8, 0);
    wire.put16(out, 10, if (payload != null) 1 else 0);
    const written = try names.writeName(name, out[wire.header_length..]);
    var at = wire.header_length + written;
    if (at + wire.question_length > out.len) return error.BufferTooSmall;
    wire.put16(out, at, query.qtype);
    wire.put16(out, at + 2, wire.class_in);
    at += wire.question_length;
    // The OPT record, and only for a query that advertises a size: the count
    // above says one additional record, so the record has to be written
    // whenever the count was raised.
    if (payload) |advertised| {
        if (at + wire.opt_length > out.len) return error.BufferTooSmall;
        out[at] = 0;
        wire.put16(out, at + 1, wire.type_opt);
        wire.put16(out, at + 3, advertised);
        wire.put32(out, at + 5, 0);
        wire.put16(out, at + 9, 0);
        at += wire.opt_length;
    }
    return out[0..at];
}

const t = std.testing;
const support = @import("lookup_test_support.zig");

test "golden: a query is the RFC's own bytes" {
    const name = "www.example.com.";
    var out: [queryLength(name)]u8 = undefined;
    var expected: [wire.reply_length]u8 = undefined;
    // `IN A`, so `QTYPE` is 1 and not this file's TXT default: the vector is
    // the RFC's own query and nothing about it is ours to change.
    const written = try writeQuery(name, .{ .id = 0, .qtype = 1 }, &out);
    try support.expectHex(try support.hexBytes(&expected, support.rfc8484_hex), written);
    try t.expectEqual(@as(usize, 33), written.len);

    // The long-label query, which is the same layout with a 62-octet label in
    // place of three three-octet ones.
    const long = "a.62characterlabel-makes-base64url-distinct-from-standard-" ++
        "base64.example.com.";
    var long_out: [queryLength(long)]u8 = undefined;
    var long_expected: [wire.reply_length]u8 = undefined;
    const long_written = try writeQuery(long, .{ .id = 0, .qtype = 1 }, &long_out);
    try support.expectHex(
        try support.hexBytes(&long_expected, support.rfc8484_long_hex),
        long_written,
    );
    try t.expectEqual(@as(usize, 94), long_written.len);
    // The same layout for the question this file actually asks, which differs
    // from the RFC's in two fields and two bytes of name: `ID` and `QTYPE`.
    var asked: [support.asked_len]u8 = undefined;
    const text = dns.queryName(&asked, try support.nodeOf(support.upstream_id), dns.prod_origin);
    var framed: [support.asked_bytes]u8 = undefined;
    const ask_wire = try writeQuery(text, .{ .id = 0x1234 }, &framed);
    try t.expectEqual(
        wire.header_length + support.asked_len + 1 + wire.question_length,
        ask_wire.len,
    );
    try t.expectEqual(
        wire.type_txt,
        wire.be16(ask_wire, wire.header_length + support.asked_len + 1),
    );
    try t.expectEqual(
        wire.class_in,
        wire.be16(ask_wire, wire.header_length + support.asked_len + 3),
    );
    try t.expectEqual(@as(u16, 0), wire.be16(ask_wire, 10));
}

test "the header is the one RFC 1035 draws, field by field" {
    var name: [support.asked_len]u8 = undefined;
    const text = dns.queryName(&name, try support.nodeOf(support.upstream_id), dns.prod_origin);
    // `discovery/dns.zig` holds this string against upstream's own test; here
    // it is the bytes that leave, which is a different claim.
    try t.expectEqualStrings(
        "_iroh.dgjpkxyn3zyrk3zfads5duwdgbqpkwbjxfj4yt7rezidr3fijccy.dns.iroh.link.",
        text,
    );

    var out: [support.asked_bytes]u8 = undefined;
    const framed = try writeQuery(text, .{
        .id = 0x1234,
        .udp_payload = wire.max_udp_payload,
    }, &out);
    try t.expectEqual(@as(u16, 0x1234), wire.be16(framed, 0));
    // `RD` alone: `QR` is 0 because this is a question and §4.1.1 requires the
    // three `Z` bits to be zero in all queries.
    try t.expectEqual(wire.flag_recursion_desired, wire.be16(framed, 2));
    try t.expectEqual(@as(u16, 1), wire.be16(framed, 4));
    try t.expectEqual(@as(u16, 0), wire.be16(framed, 6));
    try t.expectEqual(@as(u16, 0), wire.be16(framed, 8));
    // One additional record, which is the OPT advertising what this node can
    // receive. Without it the limit is §4.2.1's 512 bytes.
    try t.expectEqual(@as(u16, 1), wire.be16(framed, 10));
    try t.expectEqual(queryLength(text), framed.len);

    const opt = wire.header_length + support.asked_len + 1 + wire.question_length;
    try t.expectEqual(@as(u8, 0), framed[opt]);
    try t.expectEqual(wire.type_opt, wire.be16(framed, opt + 1));
    try t.expectEqual(wire.max_udp_payload, wire.be16(framed, opt + 3));
    // RFC 6891 §6.1.3 puts the version in the TTL's high byte and it is zero.
    try t.expectEqual(@as(u32, 0), wire.be32(framed, opt + 5));
    try t.expectEqual(@as(u16, 0), wire.be16(framed, opt + 9));

    // And the name that goes out reads back as the name that was asked for,
    // which is the round trip the answer decoder is asked to make.
    var owner: [wire.max_name_length]u8 = undefined;
    const decoded = try names.readName(framed, wire.header_length, &owner);
    try t.expectEqualStrings(text, owner[0..decoded.written]);
}

test "a name has to be a name" {
    var out: [support.asked_bytes]u8 = undefined;
    try t.expectError(error.UnterminatedName, writeQuery("example.com", .{ .id = 0 }, &out));
    try t.expectError(error.EmptyLabel, writeQuery("a..b.", .{ .id = 0 }, &out));
    try t.expectError(error.BufferTooSmall, writeQuery("a.b.", .{ .id = 0 }, out[0..4]));
    // 63 octets is RFC 1035 §2.3.4's cap and one more is refused: a length
    // octet over 63 is indistinguishable from a pointer's first octet.
    _ = try writeQuery("a." ++ "x" ** wire.max_label_length ++ ".example.com.", .{ .id = 0 }, &out);
    try t.expectError(error.LabelTooLong, writeQuery(
        "a." ++ "x" ** (wire.max_label_length + 1) ++ ".example.com.",
        .{ .id = 0 },
        &out,
    ));
    // The root, and nothing else: one zero octet, and a name of zero characters
    // is still a name. It comes in under `queryLength`, which is a bound.
    const root = try writeQuery(".", .{ .id = 7 }, &out);
    try t.expectEqual(wire.header_length + wire.question_length + 1, root.len);
    try t.expectEqual(@as(u8, 0), root[wire.header_length]);
    try t.expect(root.len < queryLength("."));
    try t.expectEqual(@as(usize, 32), queryLength("a.b."));
}