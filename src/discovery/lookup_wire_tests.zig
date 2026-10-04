//! The tests `discovery/lookup_wire.zig` is held to: RFC 8484's own query
//! vectors, a header read field by field, the names a query can be handed, and
//! one witness for every arm of the closed set `WireError`.
//!
//! The arm table is here rather than in the module because it is what keeps
//! that set closed: an arm added to `WireError` without a message producing it
//! is a compile error. Two of its arms cannot be produced by the codec alone —
//! `ForeignSource` is a fact about who sent a datagram, not about its bytes —
//! so this file reaches the decoder and the seam too, and takes its scripted
//! datagram from `lookup_test_support.zig`.

const dns = @import("dns.zig");
const wire = @import("lookup_wire.zig");
const answer = @import("lookup_answer.zig");
const seam = @import("lookup_io.zig");
const support = @import("lookup_test_support.zig");

// The subjects these tests name the way the module under test names them,
// bound once here rather than qualified at every call: a test that says
// `writeQuery` is a claim about the codec, and the arm table below needs the
// decoder and the seam too, so three imports answer for four vocabularies.
const t = support.t;
const upstream_id = support.upstream_id;
const asked_len = support.asked_len;
const asked_bytes = support.asked_bytes;
const Scripted = support.Scripted;
const nameserver = support.nameserver;
const elsewhere = support.elsewhere;
const Prng = support.Prng;
const rfc8484_hex = support.rfc8484_hex;
const rfc8484_long_hex = support.rfc8484_long_hex;
const hexBytes = support.hexBytes;
const nodeOf = support.nodeOf;
const expectHex = support.expectHex;
const sweep_name = support.sweep_name;

const WireError = wire.WireError;
const queryLength = wire.queryLength;
const writeQuery = wire.writeQuery;
const header_length = wire.header_length;
const question_length = wire.question_length;
const type_txt = wire.type_txt;
const class_in = wire.class_in;
const type_opt = wire.type_opt;
const flag_response = wire.flag_response;
const flag_truncated = wire.flag_truncated;
const flag_recursion_desired = wire.flag_recursion_desired;
const max_label_length = wire.max_label_length;
const max_name_length = wire.max_name_length;
const max_udp_payload = wire.max_udp_payload;
const reply_length = wire.reply_length;
const be16 = wire.be16;
const be32 = wire.be32;
const put16 = wire.put16;

const readAnswer = answer.readAnswer;
const readName = answer.readName;
const Retrieval = seam.Retrieval;

test "golden: a query is the RFC's own bytes" {
    const name = "www.example.com.";
    var out: [queryLength(name)]u8 = undefined;
    var expected: [reply_length]u8 = undefined;
    // `IN A`, so `QTYPE` is 1 and not this file's TXT default: the vector is
    // the RFC's own query and nothing about it is ours to change.
    const written = try writeQuery(name, .{ .id = 0, .qtype = 1 }, &out);
    try expectHex(try hexBytes(&expected, rfc8484_hex), written);
    try t.expectEqual(@as(usize, 33), written.len);

    // The long-label query, which is the same layout with a 62-octet label in
    // place of three three-octet ones.
    const long = "a.62characterlabel-makes-base64url-distinct-from-standard-" ++
        "base64.example.com.";
    var long_out: [queryLength(long)]u8 = undefined;
    var long_expected: [reply_length]u8 = undefined;
    const long_written = try writeQuery(long, .{ .id = 0, .qtype = 1 }, &long_out);
    try expectHex(try hexBytes(&long_expected, rfc8484_long_hex), long_written);
    try t.expectEqual(@as(usize, 94), long_written.len);
    // The same layout for the question this file actually asks, which differs
    // from the RFC's in two fields and two bytes of name: `ID` and `QTYPE`.
    var asked: [asked_len]u8 = undefined;
    const text = dns.queryName(&asked, try nodeOf(upstream_id), dns.prod_origin);
    var wire: [asked_bytes]u8 = undefined;
    const ask_wire = try writeQuery(text, .{ .id = 0x1234 }, &wire);
    try t.expectEqual(header_length + asked_len + 1 + question_length, ask_wire.len);
    try t.expectEqual(type_txt, be16(ask_wire, header_length + asked_len + 1));
    try t.expectEqual(class_in, be16(ask_wire, header_length + asked_len + 3));
    try t.expectEqual(@as(u16, 0), be16(ask_wire, 10));
}

test "the header is the one RFC 1035 draws, field by field" {
    var name: [asked_len]u8 = undefined;
    const text = dns.queryName(&name, try nodeOf(upstream_id), dns.prod_origin);
    // `discovery/dns.zig` holds this string against upstream's own test; here
    // it is the bytes that leave, which is a different claim.
    try t.expectEqualStrings(
        "_iroh.dgjpkxyn3zyrk3zfads5duwdgbqpkwbjxfj4yt7rezidr3fijccy.dns.iroh.link.",
        text,
    );

    var out: [asked_bytes]u8 = undefined;
    const wire = try writeQuery(text, .{
        .id = 0x1234,
        .udp_payload = max_udp_payload,
    }, &out);
    try t.expectEqual(@as(u16, 0x1234), be16(wire, 0));
    // `RD` alone: `QR` is 0 because this is a question and §4.1.1 requires the
    // three `Z` bits to be zero in all queries.
    try t.expectEqual(flag_recursion_desired, be16(wire, 2));
    try t.expectEqual(@as(u16, 1), be16(wire, 4));
    try t.expectEqual(@as(u16, 0), be16(wire, 6));
    try t.expectEqual(@as(u16, 0), be16(wire, 8));
    // One additional record, which is the OPT advertising what this node can
    // receive. Without it the limit is §4.2.1's 512 bytes.
    try t.expectEqual(@as(u16, 1), be16(wire, 10));
    try t.expectEqual(queryLength(text), wire.len);

    const opt = header_length + asked_len + 1 + question_length;
    try t.expectEqual(@as(u8, 0), wire[opt]);
    try t.expectEqual(type_opt, be16(wire, opt + 1));
    try t.expectEqual(max_udp_payload, be16(wire, opt + 3));
    // RFC 6891 §6.1.3 puts the version in the TTL's high byte and it is zero.
    try t.expectEqual(@as(u32, 0), be32(wire, opt + 5));
    try t.expectEqual(@as(u16, 0), be16(wire, opt + 9));

    // And the name that goes out reads back as the name that was asked for,
    // which is the round trip the answer decoder is asked to make.
    var owner: [max_name_length]u8 = undefined;
    const decoded = try readName(wire, header_length, &owner);
    try t.expectEqualStrings(text, owner[0..decoded.written]);
}

test "a name has to be a name" {
    var out: [asked_bytes]u8 = undefined;
    try t.expectError(error.UnterminatedName, writeQuery("example.com", .{ .id = 0 }, &out));
    try t.expectError(error.EmptyLabel, writeQuery("a..b.", .{ .id = 0 }, &out));
    try t.expectError(error.BufferTooSmall, writeQuery("a.b.", .{ .id = 0 }, out[0..4]));
    // 63 octets is RFC 1035 §2.3.4's cap and one more is refused: a length
    // octet over 63 is indistinguishable from a pointer's first octet.
    _ = try writeQuery("a." ++ "x" ** max_label_length ++ ".example.com.", .{ .id = 0 }, &out);
    try t.expectError(
        error.LabelTooLong,
        writeQuery("a." ++ "x" ** (max_label_length + 1) ++ ".example.com.", .{ .id = 0 }, &out),
    );
    // The root, and nothing else: one zero octet, and a name of zero characters
    // is still a name. It comes in under `queryLength`, which is a bound.
    const root = try writeQuery(".", .{ .id = 7 }, &out);
    try t.expectEqual(header_length + question_length + 1, root.len);
    try t.expectEqual(@as(u8, 0), root[header_length]);
    try t.expect(root.len < queryLength("."));
    try t.expectEqual(@as(usize, 32), queryLength("a.b."));
}

/// Every arm of the wire's closed error set, and what provokes it.
///
/// The set is closed and this table is held to it at comptime, so an arm added
/// to `WireError` without a message that produces it is a compile error rather
/// than a gap somebody notices later. The other direction is what the test
/// below checks: a witness whose arm has moved fails on its own line, naming
/// the one that moved.
const wire_arms = [_]struct { tag: WireError, fault: WireFault }{
    .{ .tag = error.BufferTooSmall, .fault = .short_output },
    .{ .tag = error.LabelTooLong, .fault = .overlong_label },
    .{ .tag = error.EmptyLabel, .fault = .doubled_dot },
    .{ .tag = error.UnterminatedName, .fault = .no_root_dot },
    .{ .tag = error.ShortMessage, .fault = .shorter_than_a_header },
    .{ .tag = error.BadName, .fault = .reserved_lead },
    .{ .tag = error.NotAResponse, .fault = .question_not_answer },
    .{ .tag = error.ForeignTransaction, .fault = .another_id },
    .{ .tag = error.ForeignSource, .fault = .another_server },
    .{ .tag = error.MalformedResponse, .fault = .{ .response_code = 1 } },
    .{ .tag = error.ServiceFailure, .fault = .{ .response_code = 2 } },
    .{ .tag = error.NameError, .fault = .{ .response_code = 3 } },
    .{ .tag = error.Unimplemented, .fault = .{ .response_code = 4 } },
    .{ .tag = error.ServiceRefused, .fault = .{ .response_code = 5 } },
    .{ .tag = error.UnknownResponseCode, .fault = .{ .response_code = 9 } },
    .{ .tag = error.Truncated, .fault = .truncated_bit },
};

/// What one arm of the wire's closed error set is provoked by.
const WireFault = union(enum) {
    /// A query into a buffer too small for what it was handed.
    short_output,
    /// A label over RFC 1035 §2.3.4's 63 octets.
    overlong_label,
    /// An empty label between two dots.
    doubled_dot,
    /// A name whose trailing dot is missing.
    no_root_dot,
    /// Fewer bytes than a header.
    shorter_than_a_header,
    /// A name lead octet of `01` or `10`, the two encodings §4.1.4 reserves.
    reserved_lead,
    /// `QR` clear: a question where an answer was wanted.
    question_not_answer,
    /// An `ID` that is not the one this question was asked under.
    another_id,
    /// A datagram from a server other than the one asked.
    another_server,
    /// `RCODE` 1..5, and the reserved range above them.
    response_code: u16,
    /// The `TC` bit.
    truncated_bit,
};

comptime {
    if (wire_arms.len != @typeInfo(WireError).error_set.?.len) {
        @compileError("a WireError arm has no witness, or a witness is for an arm that is gone");
    }
    for (wire_arms, 0..) |arm, index| {
        for (wire_arms[index + 1 ..]) |later| {
            if (arm.tag == later.tag) @compileError("two witnesses name one WireError arm");
        }
    }
}

test "every arm of the wire's closed error set has a message that produces it" {
    inline for (wire_arms) |arm| {
        var owner: [max_name_length]u8 = undefined;
        switch (arm.fault) {
            .short_output => {
                var out: [asked_bytes]u8 = undefined;
                try t.expectError(arm.tag, writeQuery("a.b.", .{ .id = 0 }, out[0..4]));
            },
            .overlong_label => {
                const long = "a." ++ "x" ** (max_label_length + 1) ++ ".example.com.";
                var out: [queryLength(long)]u8 = undefined;
                try t.expectError(arm.tag, writeQuery(long, .{ .id = 0 }, &out));
            },
            .doubled_dot => {
                var out: [asked_bytes]u8 = undefined;
                try t.expectError(arm.tag, writeQuery("a..b.", .{ .id = 0 }, &out));
            },
            .no_root_dot => {
                var out: [asked_bytes]u8 = undefined;
                try t.expectError(arm.tag, writeQuery("example.com", .{ .id = 0 }, &out));
            },
            .shorter_than_a_header => {
                var message: [header_length - 1]u8 = @splat(0);
                try t.expectError(
                    arm.tag,
                    readAnswer(t.allocator, &message, sweep_name, 0, &owner),
                );
            },
            .reserved_lead => {
                var message: [header_length + 1]u8 = @splat(0);
                put16(&message, 2, flag_response);
                put16(&message, 6, 1);
                message[header_length] = 0x40;
                try t.expectError(
                    arm.tag,
                    readAnswer(t.allocator, &message, sweep_name, 0, &owner),
                );
            },
            .question_not_answer => {
                var message: [header_length]u8 = @splat(0);
                try t.expectError(
                    arm.tag,
                    readAnswer(t.allocator, &message, sweep_name, 0, &owner),
                );
            },
            .another_id => {
                var message: [header_length]u8 = @splat(0);
                put16(&message, 2, flag_response);
                try t.expectError(
                    arm.tag,
                    readAnswer(t.allocator, &message, sweep_name, 1, &owner),
                );
            },
            .another_server => {
                var engine: Prng = Prng.init(31);
                var script: Scripted = .{ .from = elsewhere };
                var retrieval = Retrieval.begin(script.datagram(), nameserver, engine.random());
                var message: [header_length]u8 = @splat(0);
                put16(&message, 0, retrieval.id);
                put16(&message, 2, flag_response);
                var wire: [asked_bytes]u8 = undefined;
                var reply: [reply_length]u8 = undefined;
                script.reply = &message;
                try t.expectError(arm.tag, retrieval.ask(t.allocator, t.io, .{
                    .name = sweep_name,
                    .wire = &wire,
                    .reply = &reply,
                    .deadline_ms = 1000,
                }));
            },
            .response_code => |code| {
                var message: [header_length]u8 = @splat(0);
                put16(&message, 2, flag_response | code);
                try t.expectError(
                    arm.tag,
                    readAnswer(t.allocator, &message, sweep_name, 0, &owner),
                );
            },
            .truncated_bit => {
                var message: [header_length]u8 = @splat(0);
                put16(&message, 2, flag_response | flag_truncated);
                try t.expectError(
                    arm.tag,
                    readAnswer(t.allocator, &message, sweep_name, 0, &owner),
                );
            },
        }
    }
}
