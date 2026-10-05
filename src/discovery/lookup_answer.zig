//! The reply half of a lookup: one RFC 1035 answer read out of a datagram, with
//! the records it carried copied into the caller's allocator.
//!
//! The header is checked before a byte of it is walked — the transaction, `QR`,
//! `TC`, the `RCODE`, then the counts — because a message that is not this
//! question's answer is a different fact from one that is malformed, and a
//! caller acts differently on the two. `lookup_query.zig` is the other
//! direction, and neither of them opens anything.

const std = @import("std");

const dns = @import("dns.zig");
const key = @import("../base/key.zig");
const resolve = @import("resolve.zig");

const names = @import("lookup_name.zig");
const wire = @import("lookup_wire.zig");

/// `RCODE`, the low four bits of the flags. RFC 1035 §4.1.1.
const rcode_bits: u16 = 0x000f;

/// What reading one answer can fail with: the wire's failures and the
/// allocator's, and nothing else.
///
/// `OutOfMemory` is here because the answer is copied into `alloc` and that copy
/// is the fourth of the seam's four things. The socket's three arms are absent
/// because a decoder that opens nothing cannot reach them: `lookup_datagram`'s
/// `SocketError` joins this set one level up, in `lookup_retrieval.zig`, which
/// is the only module above both halves and so the only place the union is
/// closed. That is the direction the dependency runs.
pub const Error = wire.WireError || error{OutOfMemory};

/// What one lookup came to, with the answer already copied out of the read
/// buffer.
///
/// Three arms, and `lookup_io.zig`'s module doc is why there is no fourth:
/// "cannot resolve at all" and "resolved to nothing" are the vocabulary
/// `item.Resolution` keeps apart, and a timeout belongs to neither.
pub const Answer = union(enum) {
    /// The name exists and carried no record this question asked for. A fact
    /// about the world, and the one `discovery/dns.zig` already calls "a node
    /// that published nothing".
    nothing,
    /// The question went out and nothing answered inside the deadline.
    ///
    /// Its own arm rather than either of the others; see `lookup_io.zig`'s
    /// module doc. It is an arm and not an error so that a caller which forgets
    /// it cannot lose it: `switch` over this union has to name it.
    timeout,
    /// The records, one per NUL, owned by `alloc`.
    records: resolve.RecordSet,

    /// Hand the copy back. A no-op on the two arms that hold no bytes, so a
    /// caller need not know which one it got before it can clean up.
    pub fn deinit(self: Answer, alloc: std.mem.Allocator) void {
        switch (self) {
            .records => |set| alloc.free(set.bytes),
            .nothing, .timeout => {},
        }
    }

    /// Whether this answer holds the records it was asked for, which is the
    /// only arm a caller can hand to `resolve.parseTxt` as an answer rather
    /// than as an event.
    pub fn hasRecords(self: Answer) bool {
        return self == .records;
    }
};

/// Read one answer out of `message` and copy what it carried into `alloc`.
///
/// `name` is the presentation name that was asked about and `id` the
/// transaction it was asked under; a message that is not that question's
/// answer is refused rather than read. `owner` is scratch for one decoded owner
/// name and needs `max_name_length` bytes.
///
/// Records come out in the order the answer listed them, one `key=value` per
/// NUL, which is `resolve.RecordSet`'s own shape: upstream reads them with
/// `packet.txt_records(IROH_TXT_NAME)` and joins a record's character strings
/// before the record is read. A record whose owner name is not the name asked
/// about is skipped rather than refused — §4.1.1's `AA` note says an answer
/// "may have multiple owner names because of aliases", and refusing the whole
/// message over an alias we did not ask to chase would lose the records behind
/// it.
pub fn readAnswer(
    alloc: std.mem.Allocator,
    message: []const u8,
    name: []const u8,
    id: u16,
    owner: []u8,
) Error!Answer {
    const counts = try readHeader(message, id);
    var at: usize = wire.header_length;
    for (0..counts.questions) |_| {
        at = (try names.readName(message, at, &.{})).end;
        if (at + wire.question_length > message.len) return error.ShortMessage;
        at += wire.question_length;
    }
    var records: std.ArrayList(u8) = .empty;
    defer records.deinit(alloc);
    for (0..counts.answers) |_| {
        at = try walkRecord(alloc, message, at, name, owner, &records);
    }
    // The authority and additional sections carry no `_iroh` records, and the
    // OPT this query advertised is answered with one in the second of them.
    // Walking them is still the only way to know the message was not cut short
    // inside one — and they are walked without collecting, because a TXT record
    // in an authority section is somebody else's authority and not this node's
    // address.
    for (0..counts.authorities + counts.additionals) |_| {
        at = try skipRecord(message, at);
    }
    if (records.items.len == 0) return .nothing;
    return .{ .records = .init(try records.toOwnedSlice(alloc)) };
}

/// What one header says, once the fields this file acts on have been checked.
const Counts = struct {
    questions: u16,
    answers: u16,
    authorities: u16,
    additionals: u16,
};

/// Read the header and refuse anything that is not this question's answer.
///
/// The order is the order the checks can be made in: the length, then the `ID`
/// — a foreign transaction is not a malformed message and must not be reported
/// as one — then `QR`, then `TC`, then the counts.
fn readHeader(message: []const u8, id: u16) wire.WireError!Counts {
    if (message.len < wire.header_length) return error.ShortMessage;
    if (wire.be16(message, 0) != id) return error.ForeignTransaction;
    const flags = wire.be16(message, 2);
    if (flags & wire.flag_response == 0) return error.NotAResponse;
    if (flags & wire.flag_truncated != 0) return error.Truncated;
    switch (flags & rcode_bits) {
        0 => {},
        1 => return error.MalformedResponse,
        2 => return error.ServiceFailure,
        3 => return error.NameError,
        4 => return error.Unimplemented,
        5 => return error.ServiceRefused,
        else => return error.UnknownResponseCode,
    }
    var counts: Counts = .{
        .questions = wire.be16(message, 4),
        .answers = wire.be16(message, 6),
        .authorities = wire.be16(message, 8),
        .additionals = wire.be16(message, 10),
    };
    inline for (.{
        &counts.questions,
        &counts.answers,
        &counts.authorities,
        &counts.additionals,
    }) |count| {
        if (count.* > wire.max_section_records) return error.ShortMessage;
    }
    return counts;
}

/// Walk one resource record and hand back the offset just past it.
///
/// RFC 1035 §4.1.3's shape: `NAME`, then `TYPE`, `CLASS`, `TTL` and `RDLENGTH`
/// as two, two, four and two octets, then `RDLENGTH` octets of `RDATA`. A TXT
/// record for the name asked about contributes its records; every other record
/// contributes its length and nothing else.
fn walkRecord(
    alloc: std.mem.Allocator,
    message: []const u8,
    at: usize,
    name: []const u8,
    owner: []u8,
    records: *std.ArrayList(u8),
) Error!usize {
    const decoded = try names.readName(message, at, owner);
    const fixed = try recordBody(message, decoded.end);
    const kind = wire.be16(message, decoded.end);
    const class = wire.be16(message, decoded.end + 2);
    const rdlength = wire.be16(message, decoded.end + 8);
    const ours = kind == wire.type_txt and
        class == wire.class_in and
        std.ascii.eqlIgnoreCase(owner[0..decoded.written], name);
    if (ours) try appendTxt(alloc, message[fixed..][0..rdlength], records);
    return fixed + rdlength;
}

/// Walk one record without reading what it holds, for the sections that cannot
/// carry this question's answer.
fn skipRecord(message: []const u8, at: usize) wire.WireError!usize {
    const decoded = try names.readName(message, at, &.{});
    const fixed = try recordBody(message, decoded.end);
    return fixed + wire.be16(message, decoded.end + 8);
}

/// `TYPE`, `CLASS`, `TTL` and `RDLENGTH` end here: the offset the `RDATA`
/// starts at, checked against the message so a `RDLENGTH` past the end is a
/// short message and not a read out of bounds.
fn recordBody(message: []const u8, at: usize) wire.WireError!usize {
    const fixed = at + 2 + 2 + 4 + 2;
    if (fixed > message.len) return error.ShortMessage;
    const rdlength = wire.be16(message, at + 8);
    if (fixed + rdlength > message.len) return error.ShortMessage;
    return fixed;
}

/// Join one TXT record's character strings into one record of the answer set.
///
/// RFC 1035 §3.3.14: "One or more `<character-string>`s", each a length octet
/// and that many octets. Upstream concatenates a record's strings with nothing
/// between them and one record becomes one `key=value` (`iroh-dns/src/dns.rs`,
/// `TxtRecordData`), so the strings of one record join and the NUL between
/// records is this list's own separator — which is exactly `resolve.RecordSet`'s
/// shape, and the reason a publisher's output and a resolver's input are the
/// same value.
fn appendTxt(
    alloc: std.mem.Allocator,
    rdata: []const u8,
    records: *std.ArrayList(u8),
) Error!void {
    var at: usize = 0;
    while (at < rdata.len) {
        const length = rdata[at];
        at += 1;
        if (at + length > rdata.len) return error.ShortMessage;
        try records.appendSlice(alloc, rdata[at..][0..length]);
        at += length;
    }
    try records.append(alloc, 0);
}

const t = std.testing;
const support = @import("lookup_test_support.zig");

test "golden: a captured answer decodes into the records it carried" {
    var buffer: [wire.reply_length]u8 = undefined;
    const answer = try support.hexBytes(&buffer, support.captured_answer_hex);

    var secret = try key.SecretKey.fromSeed(support.captured_seed);
    defer secret.deinit();
    var name: [wire.max_name_length]u8 = undefined;
    const asked = support.capturedName(secret.nodeId(), &name);

    var owner: [wire.max_name_length]u8 = undefined;
    const read = try readAnswer(t.allocator, answer, asked, 0, &owner);
    defer read.deinit(t.allocator);
    const records = switch (read) {
        .records => |set| set,
        else => return error.ExpectedRecords,
    };
    // The reference implementation's own record, with the character strings
    // inside one TXT record read as one value.
    try t.expectEqualStrings(support.captured_record, records.bytes);

    // The node the packet is about is the key that signed it, and the name the
    // answer was read under is that key's z32 — read back by the same parser
    // `discovery/dns.zig` uses on a record name.
    try t.expectEqual(secret.nodeId(), try dns.endpointIdFromName(asked));
}

test "a datagram that is not this question's answer is refused" {
    var buffer: [wire.reply_length]u8 = undefined;
    const answer = try support.hexBytes(&buffer, support.captured_answer_hex);
    var secret = try key.SecretKey.fromSeed(support.captured_seed);
    defer secret.deinit();
    var name: [wire.max_name_length]u8 = undefined;
    const asked = support.capturedName(secret.nodeId(), &name);
    var owner: [wire.max_name_length]u8 = undefined;

    // Another query's transaction, which RFC 1035 §4.1.1's `ID` exists to
    // catch: the answer is real and it is not ours.
    try t.expectError(
        error.ForeignTransaction,
        readAnswer(t.allocator, answer, asked, 1, &owner),
    );

    // This one's own transaction, read against a name it is not about: the
    // records are not silently attributed to a node that never published them.
    var other: [wire.max_name_length]u8 = @splat('x');
    other[0] = '_';
    const wrong = try readAnswer(
        t.allocator,
        answer,
        other[0..asked.len],
        0,
        &owner,
    );
    defer wrong.deinit(t.allocator);
    try t.expectEqual(Answer.nothing, wrong);

    // A question arriving where an answer was wanted.
    var query: [wire.header_length]u8 = @splat(0);
    wire.put16(&query, 4, 1);
    try t.expectError(error.NotAResponse, readAnswer(t.allocator, &query, asked, 0, &owner));

    // An answer that did not fit its datagram, which is the one a TCP retry
    // would be for.
    var cut: [wire.reply_length]u8 = undefined;
    const truncated = try support.hexBytes(&cut, support.captured_answer_hex);
    wire.put16(truncated[0..], 2, wire.flag_response | wire.flag_truncated);
    try t.expectError(error.Truncated, readAnswer(t.allocator, truncated[0..], asked, 0, &owner));
}

test "every response code is named, and a name that loops is refused" {
    const name = "_iroh.example.";
    var owner: [wire.max_name_length]u8 = undefined;
    var message: [wire.header_length]u8 = @splat(0);

    // RFC 1035 §4.1.1's six codes, each with the answer this file gives rather
    // than one generic "no", which is the point of naming them.
    const cases = [_]struct { code: u16, expect: ?anyerror }{
        .{ .code = 0, .expect = null },
        .{ .code = 1, .expect = error.MalformedResponse },
        .{ .code = 2, .expect = error.ServiceFailure },
        .{ .code = 3, .expect = error.NameError },
        .{ .code = 4, .expect = error.Unimplemented },
        .{ .code = 5, .expect = error.ServiceRefused },
    };
    inline for (cases) |case| {
        wire.put16(&message, 2, wire.flag_response | case.code);
        const read = readAnswer(t.allocator, &message, name, 0, &owner);
        if (case.expect) |wanted| {
            try t.expectError(wanted, read);
        } else {
            try t.expectEqual(Answer.nothing, try read);
        }
    }
    // And the reserved range above them, which is not "no error".
    for (6..16) |code| {
        wire.put16(&message, 2, wire.flag_response | @as(u16, @intCast(code)));
        try t.expectError(
            error.UnknownResponseCode,
            readAnswer(t.allocator, &message, name, 0, &owner),
        );
    }

    // A name whose pointer points forward can never end, so §4.1.4's "prior
    // occurrence" is checked rather than followed. Every other encoding of the
    // two high bits is reserved and has no length to read.
    var looping: [wire.header_length + 2]u8 = @splat(0);
    wire.put16(&looping, 0, 0);
    wire.put16(&looping, 2, wire.flag_response);
    wire.put16(&looping, 6, 1);
    const at = wire.header_length;
    const alias = looping[0 .. wire.header_length + 2];
    looping[at] = names.name_pointer;
    looping[at + 1] = @intCast(at);
    try t.expectError(error.BadName, readAnswer(t.allocator, alias, name, 0, &owner));
    looping[at] = 0x40;
    try t.expectError(error.BadName, readAnswer(t.allocator, alias, name, 0, &owner));
    looping[at] = 0x80;
    try t.expectError(error.BadName, readAnswer(t.allocator, alias, name, 0, &owner));

    // A message cut short inside a record is refused rather than read past.
    var cut: [wire.header_length + 4]u8 = @splat(0);
    wire.put16(&cut, 0, 0);
    wire.put16(&cut, 2, wire.flag_response);
    wire.put16(&cut, 6, 1);
    cut[wire.header_length] = 0;
    try t.expectError(
        error.ShortMessage,
        readAnswer(t.allocator, cut[0 .. at + 4], name, 0, &owner),
    );
    try t.expectError(error.ShortMessage, readAnswer(t.allocator, cut[0..4], name, 0, &owner));

    // A count a 64-octet message cannot hold is a header to refuse, not a loop.
    wire.put16(&cut, 2, wire.flag_response);
    wire.put16(&cut, 6, wire.max_section_records + 1);
    try t.expectError(
        error.ShortMessage,
        readAnswer(t.allocator, cut[0 .. at + 4], name, 0, &owner),
    );
}

test "a compression pointer is followed and a bad one is refused" {
    // RFC 1035 §4.1.4's own example: the name `F.ISI.ARPA` written out, and
    // `FOO.F.ISI.ARPA` written as one label and a pointer back to it. A reader
    // has to expand the alias to the name the writer meant, and the pointer is
    // the whole difficulty. Here the pointed-at name is the question, which is
    // where a real answer keeps it.
    var message: [64]u8 = @splat(0);
    wire.put16(&message, 0, 0);
    wire.put16(&message, 2, wire.flag_response);
    wire.put16(&message, 4, 1);
    wire.put16(&message, 6, 1);
    var at: usize = question_at;
    var labels = std.mem.splitScalar(u8, spelled, '.');
    while (labels.next()) |label| {
        if (label.len == 0) continue;
        message[at] = @intCast(label.len);
        @memcpy(message[at + 1 ..][0..label.len], label);
        at += 1 + label.len;
    }
    message[at] = 0;
    at += 1;
    wire.put16(&message, at, wire.type_txt);
    wire.put16(&message, at + 2, wire.class_in);
    at += wire.question_length;
    try t.expectEqual(alias_at, at);

    // One label and the pointer, which is the whole of §4.1.4's alias.
    message[at] = 3;
    @memcpy(message[at + 1 ..][0..3], "foo");
    at += 4;
    message[at] = names.name_pointer;
    message[at + 1] = @intCast(question_at);
    at += 2;
    wire.put16(&message, at, wire.type_txt);
    wire.put16(&message, at + 2, wire.class_in);
    wire.put32(&message, at + 4, 30);
    wire.put16(&message, at + 8, 4);
    at += 10;
    message[at] = 3;
    @memcpy(message[at + 1 ..][0..3], "bar");
    at += 4;

    var owner: [wire.max_name_length]u8 = undefined;
    const decoded = try names.readName(message[0 .. alias_at + 6], alias_at, &owner);
    try t.expectEqualStrings("foo.f.isi.arpa.", owner[0..decoded.written]);
    // The name ends after the two pointer octets, which is where the record's
    // `TYPE` starts — and getting that wrong is how a parser reads a type out
    // of a pointer.
    try t.expectEqual(alias_at + 6, decoded.end);

    // And the whole message reads: past the pointer, through the names it
    // expands to, and into the record the pointer stands in for.
    const read = try readAnswer(t.allocator, message[0..at], "foo.f.isi.arpa.", 0, &owner);
    defer read.deinit(t.allocator);
    try t.expectEqualStrings("bar\x00", switch (read) {
        .records => |set| set.bytes,
        else => return error.ExpectedRecords,
    });

    // A pointer past the message, and one that points at itself.
    var bad: [wire.header_length + 2]u8 = undefined;
    bad[wire.header_length] = names.name_pointer;
    bad[wire.header_length + 1] = 200;
    try t.expectError(error.BadName, names.readName(&bad, wire.header_length, &owner));
    bad[wire.header_length + 1] = 0;
    try t.expectError(error.BadName, names.readName(&bad, wire.header_length, &owner));
    // A label whose length runs past the message.
    var cut: [wire.header_length + 2]u8 = @splat(0);
    cut[wire.header_length] = 40;
    try t.expectError(
        error.ShortMessage,
        names.readName(cut[0 .. wire.header_length + 2], wire.header_length, &owner),
    );
    // A pointer with no second octet at all.
    var lone: [wire.header_length + 1]u8 = @splat(0);
    lone[wire.header_length] = names.name_pointer;
    try t.expectError(error.ShortMessage, names.readName(&lone, wire.header_length, &owner));
}

/// The name RFC 1035 §4.1.4's example writes out, and where this message keeps
/// it: as the question, which is where a real answer points back at.
const spelled = "f.isi.arpa.";
const question_at = wire.header_length;
const alias_at = question_at + spelled.len + 1 + wire.question_length;
