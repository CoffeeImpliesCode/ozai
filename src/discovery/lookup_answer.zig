//! RFC 1035's answer side: one datagram read, checked, and copied into
//! records.
//!
//! Pure, and separate from the transport for the reason
//! `discovery/lookup_io.zig`'s module doc gives: a wire codec opens no socket.
//! What comes in is the bytes a socket handed back, the name the question was
//! asked under, and the transaction it was asked with; what goes out is an
//! `Answer` whose records are copies. That copy is a real cost and a real
//! reason: `discovery/resolve.zig`'s `RecordSet` is a value a service holds
//! after this call has returned, and a read buffer does not outlive the call
//! that filled it.
//!
//! # Three answers, and the third is not an error
//!
//! `Answer` is `nothing`, `records` or `timeout`, and
//! `discovery/lookup_io.zig`'s module doc is the argument for a timeout being
//! neither of the other two. It is an arm and not an error so that a caller
//! which forgets it cannot lose it: a `switch` over the union has to name it.
//!
//! # What is refused rather than read
//!
//! A message that is not this question's answer is refused and not decoded:
//! another transaction's `ID`, a question where an answer was wanted, an
//! `RCODE` this module names, and the `TC` bit. Truncation is the refusal
//! deliberately not turned into an empty answer set — "this node published
//! nothing" is a different fact, and the retry a truncated answer wants is
//! over TCP, which a datagram socket does not have.
//!
//! `error.ForeignSource` is the one arm this module cannot check, because who
//! sent a datagram is not in its bytes. `Retrieval.ask` compares the source
//! address against the server the question was asked of before calling here.
//!
//! # Aliases are skipped, not refused
//!
//! A record whose owner name is not the name asked about contributes its
//! length and nothing else. RFC 1035 §4.1.1's `AA` note says an answer "may
//! have multiple owner names because of aliases", and refusing the whole
//! message over an alias nobody asked to chase would lose the records behind
//! it. Records come out in the order the answer listed them, one `key=value`
//! per NUL, which is `record.RecordSet`'s own shape.

const std = @import("std");
const record = @import("resolve_record.zig");
const wire = @import("lookup_wire.zig");

/// Everything decoding one answer can fail with: the wire's refusals, and the
/// allocator the records are copied into. `OutOfMemory` is here because that
/// copy is what this module allocates for; nothing else here allocates.
///
/// The seam's `Error` is this plus `SocketError`, spelled there as a sum of
/// this and its own, so the dependency runs one way: nothing here knows a
/// socket exists.
pub const DecodeError = wire.WireError || error{OutOfMemory};

// The wire's vocabulary, bound once so the walk below reads as the RFC's
// rather than as this file's reach for a sibling's constants. Every one of
// these is a bound or a bit from RFC 1035, and a single definition of each is
// what keeps two decoders from drifting apart.
const WireError = wire.WireError;
const header_length = wire.header_length;
const question_length = wire.question_length;
const type_txt = wire.type_txt;
const class_in = wire.class_in;
const flag_response = wire.flag_response;
const flag_truncated = wire.flag_truncated;
const max_section_records = wire.max_section_records;
const rcode_bits = wire.rcode_bits;
const name_label = wire.name_label;
const name_pointer = wire.name_pointer;
const be16 = wire.be16;
const be32 = wire.be32;

/// What one lookup came to, with the answer already copied out of the read
/// buffer.
///
/// Three arms, and the module doc is why there is no fourth: "cannot resolve at
/// all" and "resolved to nothing" are the vocabulary `item.Resolution` keeps
/// apart, and a timeout belongs to neither.
pub const Answer = union(enum) {
    /// The name exists and carried no record this question asked for. A fact
    /// about the world, and the one `discovery/dns.zig` already calls "a node
    /// that published nothing".
    nothing,
    /// The question went out and nothing answered inside the deadline.
    ///
    /// Its own arm rather than either of the others; see the module doc. It is
    /// an arm and not an error so that a caller which forgets it cannot lose it:
    /// `switch` over this union has to name it.
    timeout,
    /// The records, one per NUL, owned by `alloc`.
    records: record.RecordSet,

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
/// NUL, which is `record.RecordSet`'s own shape: upstream reads them with
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
) DecodeError!Answer {
    const counts = try readHeader(message, id);
    var at: usize = header_length;
    for (0..counts.questions) |_| {
        at = (try readName(message, at, &.{})).end;
        if (at + question_length > message.len) return error.ShortMessage;
        at += question_length;
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
///
/// Published because a second reader of the same message has to refuse the same
/// things in the same order: `ID`, then `QR`, then `TC`, then the counts. A copy
/// of this check is how one lookup starts believing a forged answer.
pub const Counts = struct {
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
pub fn readHeader(message: []const u8, id: u16) WireError!Counts {
    if (message.len < header_length) return error.ShortMessage;
    if (be16(message, 0) != id) return error.ForeignTransaction;
    const flags = be16(message, 2);
    if (flags & flag_response == 0) return error.NotAResponse;
    if (flags & flag_truncated != 0) return error.Truncated;
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
        .questions = be16(message, 4),
        .answers = be16(message, 6),
        .authorities = be16(message, 8),
        .additionals = be16(message, 10),
    };
    inline for (.{
        &counts.questions,
        &counts.answers,
        &counts.authorities,
        &counts.additionals,
    }) |count| {
        if (count.* > max_section_records) return error.ShortMessage;
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
) DecodeError!usize {
    const decoded = try readName(message, at, owner);
    const fixed = try recordBody(message, decoded.end);
    const kind = be16(message, decoded.end);
    const class = be16(message, decoded.end + 2);
    const rdlength = be16(message, decoded.end + 8);
    const ours = kind == type_txt and
        class == class_in and
        std.ascii.eqlIgnoreCase(owner[0..decoded.written], name);
    if (ours) try appendTxt(alloc, message[fixed..][0..rdlength], records);
    return fixed + rdlength;
}

/// Walk one record without reading what it holds, for the sections that cannot
/// carry this question's answer. Published because walking a section without
/// reading it is its own claim — that the message was not cut short inside a
/// record the answer section does not hold — and a walker that checks it
/// differently checks it wrongly.
pub fn skipRecord(message: []const u8, at: usize) WireError!usize {
    const decoded = try readName(message, at, &.{});
    const fixed = try recordBody(message, decoded.end);
    return fixed + be16(message, decoded.end + 8);
}

/// `TYPE`, `CLASS`, `TTL` and `RDLENGTH` end here: the offset the `RDATA`
/// starts at, checked against the message so a `RDLENGTH` past the end is a
/// short message and not a read out of bounds. Published for the same reason as
/// `skipRecord`: the check belongs to whoever walks a record, and there should
/// be one walker of records here.
pub fn recordBody(message: []const u8, at: usize) WireError!usize {
    const fixed = at + 2 + 2 + 4 + 2;
    if (fixed > message.len) return error.ShortMessage;
    const rdlength = be16(message, at + 8);
    if (fixed + rdlength > message.len) return error.ShortMessage;
    return fixed;
}

/// Join one TXT record's character strings into one record of the answer set.
///
/// RFC 1035 §3.3.14: "One or more `<character-string>`s", each a length octet
/// and that many octets. Upstream concatenates a record's strings with nothing
/// between them and one record becomes one `key=value` (`iroh-dns/src/dns.rs`,
/// `TxtRecordData`), so the strings of one record join and the NUL between
/// records is this list's own separator — which is exactly `record.RecordSet`'s
/// shape, and the reason a publisher's output and a resolver's input are the
/// same value.
fn appendTxt(
    alloc: std.mem.Allocator,
    rdata: []const u8,
    records: *std.ArrayList(u8),
) DecodeError!void {
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

/// Published with `readName` because a caller decoding one name — a `CNAME`'s
/// target, say — has to name what it got back, and a second decoder written to
/// avoid that import is a second thing to get compression pointers wrong.
pub const Decoded = struct {
    /// Just past the name in the message, which is *not* where the walk
    /// finished when a pointer was taken: a pointer is two octets and the rest
    /// of the name is elsewhere, so this is the position after those two.
    end: usize,
    /// The presentation form written into the caller's buffer, trailing dot
    /// included. Zero when the caller asked for no name.
    written: usize,
};

/// Decode the name at `at` into `out`, in presentation form.
///
/// An `out` of length zero decodes without materialising, which is what walking
/// past a question is. The walk needs no step counter because RFC 1035 §4.1.4's
/// pointer names a *prior* occurrence: a target at or after the pointer's own
/// offset is `BadName`, so every jump moves strictly backwards while labels
/// move forwards, and neither can revisit a byte.
///
/// Published because the codec's own round trip is a claim worth making against
/// this function and not only against `readAnswer`: a name written by
/// `lookup_wire.writeQuery` has to decode back to the name that was asked for.
pub fn readName(message: []const u8, at: usize, out: []u8) WireError!Decoded {
    const capture = out.len != 0;
    var cursor = at;
    var written: usize = 0;
    var end: ?usize = null;
    while (true) {
        if (cursor >= message.len) return error.ShortMessage;
        const lead = message[cursor];
        switch (lead & name_pointer) {
            name_pointer => {
                if (cursor + 1 >= message.len) return error.ShortMessage;
                const target = (@as(usize, lead & ~name_pointer) << 8) | message[cursor + 1];
                if (target >= message.len or target >= cursor) return error.BadName;
                if (end == null) end = cursor + 2;
                cursor = target;
            },
            name_label => {
                cursor += 1;
                if (lead == 0) {
                    // Every label already wrote the dot that follows it, so the
                    // root's terminator adds one only for a name that was the
                    // root all along — which is how `"."` comes out of a name
                    // with no labels rather than an empty string.
                    if (capture and written == 0) try writeByte(out, &written, '.');
                    // `end` is null only when no pointer was taken, and then it
                    // is this cursor: a name that ends at its own terminator
                    // ends one past it, which is where a record's `TYPE` is.
                    return .{ .end = end orelse cursor, .written = written };
                }
                if (cursor + lead > message.len) return error.ShortMessage;
                if (capture) {
                    try writeBytes(out, &written, message[cursor..][0..lead]);
                    try writeByte(out, &written, '.');
                }
                cursor += lead;
            },
            // `01` and `10` are reserved by §4.1.4 and there is no length to
            // read out of them, so a name using one is refused.
            else => return error.BadName,
        }
    }
}

fn writeByte(out: []u8, at: *usize, value: u8) WireError!void {
    if (at.* >= out.len) return error.BufferTooSmall;
    out[at.*] = value;
    at.* += 1;
}

fn writeBytes(out: []u8, at: *usize, bytes: []const u8) WireError!void {
    if (at.* + bytes.len > out.len) return error.BufferTooSmall;
    @memcpy(out[at.*..][0..bytes.len], bytes);
    at.* += bytes.len;
}
