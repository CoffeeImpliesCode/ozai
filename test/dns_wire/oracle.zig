//! What a DNS answer's bytes say, worked out without asking the decoder.
//!
//! `discovery/lookup_io.zig` copies out the records of one `_iroh` name from
//! bytes a nameserver chose. This file is a second implementation of RFC 1035
//! §4.1, written on purpose, and it never calls `readAnswer`: an oracle that did
//! would agree with whatever the decoder did, which is the one thing an oracle
//! must not do. A disagreement between the two is a finding about one of them.
//!
//! Three verdicts live here, and none of them is "did not crash":
//!
//! * `headerVerdict` — a header that decides by itself names one arm of
//!   `WireError`, so the decoder has to name that same arm;
//! * `walkVerdict` — bytes that decode publish exactly the record block the
//!   second walk produces, byte for byte, and bytes that do not decode publish
//!   nothing at all;
//! * `checkRoundTrip` — records a publisher wrote come back exactly as written,
//!   with each `TXT` record's character strings joined by nothing.
//!
//! The message bytes come from `dns_wire/seeds.zig`, which owns the writer and
//! the seed corpus; this file owns reading them back.

const std = @import("std");
const ozai = @import("ozai");
const lookup = ozai.discovery_lookup_io;
const t = std.testing;
const seeds = @import("seeds.zig");

/// What a second walk of the bytes says about them.
pub const Verdict = union(enum) {
    /// Nothing in the header decides the message on its own; the sections still
    /// have to be walked.
    undecided,
    /// A header field condemns the message by itself, and names the arm.
    condemned: lookup.WireError,
    /// The bytes do not decode: a name, a length or an `RDLENGTH` runs out of
    /// the message, or a name is one of §4.1.4's reserved encodings.
    malformed,
    /// The bytes decode, and the records this question asked about are these.
    well_formed: []const u8,
};

/// What the header alone decides, in the order RFC 1035 §4.1.1 gives the
/// fields and the decoder acts on them: the length, the `ID`, `QR`, `TC`, the
/// response code, then the four counts.
///
/// Nothing in the sections can overturn one of these, so each names its own arm
/// rather than a generic refusal, and a message that trips several is still the
/// first one.
fn headerVerdict(bytes: []const u8) Verdict {
    if (bytes.len < lookup.header_length) return .{ .condemned = error.ShortMessage };
    if (be16(bytes, 0) != 0) return .{ .condemned = error.ForeignTransaction };
    const flags = be16(bytes, 2);
    if (flags & lookup.flag_response == 0) return .{ .condemned = error.NotAResponse };
    if (flags & lookup.flag_truncated != 0) return .{ .condemned = error.Truncated };
    switch (flags & 0x000f) {
        0 => {},
        1 => return .{ .condemned = error.MalformedResponse },
        2 => return .{ .condemned = error.ServiceFailure },
        3 => return .{ .condemned = error.NameError },
        4 => return .{ .condemned = error.Unimplemented },
        5 => return .{ .condemned = error.ServiceRefused },
        else => return .{ .condemned = error.UnknownResponseCode },
    }
    for ([_]u16{ 4, 6, 8, 10 }) |offset| {
        if (be16(bytes, offset) > lookup.max_section_records) {
            return .{ .condemned = error.ShortMessage };
        }
    }
    return .undecided;
}

/// Walk the four sections a second time, and either find the records a
/// well-formed answer publishes or report that its bytes do not decode.
fn walkVerdict(bytes: []const u8, owner: []u8, records: []u8) Verdict {
    var at: usize = lookup.header_length;
    for (0..be16(bytes, 4)) |_| {
        const end = skipName(bytes, at) orelse return .malformed;
        if (end + 4 > bytes.len) return .malformed;
        at = end + 4;
    }
    var written: usize = 0;
    for (0..be16(bytes, 6)) |_| {
        at = walkAnswer(bytes, at, owner, records, &written) orelse return .malformed;
    }
    // The authority and additional sections are walked without being read, and
    // walking them is what proves the message was not cut short inside one.
    for (0..be16(bytes, 8) + be16(bytes, 10)) |_| {
        at = skipName(bytes, at) orelse return .malformed;
        if (at + 10 > bytes.len) return .malformed;
        const rdlength = be16(bytes, at + 8);
        at += 10;
        if (at + rdlength > bytes.len) return .malformed;
        at += rdlength;
    }
    return .{ .well_formed = records[0..written] };
}

/// Walk one answer record, collecting its records when it is a `TXT` record in
/// the Internet class for the name this question asked about.
fn walkAnswer(
    bytes: []const u8,
    at: usize,
    owner: []u8,
    records: []u8,
    written: *usize,
) ?usize {
    const decoded = decodeName(bytes, at, owner) orelse return null;
    if (decoded.end + 10 > bytes.len) return null;
    const rdlength = be16(bytes, decoded.end + 8);
    const fixed = decoded.end + 10;
    if (fixed + rdlength > bytes.len) return null;
    const ours = be16(bytes, decoded.end) == lookup.type_txt and
        be16(bytes, decoded.end + 2) == lookup.class_in and
        std.ascii.eqlIgnoreCase(owner[0..decoded.written], seeds.asked);
    if (!ours) return fixed + rdlength;

    const rdata = bytes[fixed..][0..rdlength];
    var in_rdata: usize = 0;
    while (in_rdata < rdata.len) {
        const length = rdata[in_rdata];
        in_rdata += 1;
        if (in_rdata + length > rdata.len) return null;
        if (written.* + length >= records.len) return null;
        @memcpy(records[written.*..][0..length], rdata[in_rdata..][0..length]);
        written.* += length;
        in_rdata += length;
    }
    if (written.* >= records.len) return null;
    records[written.*] = 0;
    written.* += 1;
    return fixed + rdlength;
}

/// Where a decoded name ends, and how much of it was written.
const Decoded = struct {
    /// Just past the name in the message, which is after a pointer's two octets
    /// when one was taken and not where the pointer led.
    end: usize,
    written: usize,
};

/// Decode the name at `at` into `out` in presentation form, or null when the
/// bytes do not decode.
///
/// The three cases §4.1.4 allows, written out again: a label, a pointer to a
/// strictly earlier offset, and the root. `out` is the decoder's own
/// `max_name_length` scratch, so a name that will not fit it is a refusal here
/// too rather than a name reported as well formed.
fn decodeName(bytes: []const u8, at: usize, out: []u8) ?Decoded {
    var cursor = at;
    var written: usize = 0;
    var end: ?usize = null;
    while (true) {
        if (cursor >= bytes.len) return null;
        const lead = bytes[cursor];
        switch (lead & seeds.pointer_mask) {
            seeds.pointer_lead => {
                if (cursor + 1 >= bytes.len) return null;
                const target = (@as(usize, lead & ~seeds.pointer_mask) << 8) | bytes[cursor + 1];
                if (target >= bytes.len or target >= cursor) return null;
                if (end == null) end = cursor + 2;
                cursor = target;
            },
            seeds.label_lead => {
                cursor += 1;
                if (lead == 0) {
                    // Every label wrote the dot that follows it, so the root
                    // adds one only for a name that was the root all along.
                    if (written == 0 and !writeByte(out, &written, '.')) return null;
                    return .{ .end = end orelse cursor, .written = written };
                }
                if (cursor + lead > bytes.len) return null;
                if (written + lead + 1 > out.len) return null;
                @memcpy(out[written..][0..lead], bytes[cursor..][0..lead]);
                written += lead;
                out[written] = '.';
                written += 1;
                cursor += lead;
            },
            // `01` and `10` are reserved and carry no length to read.
            else => return null,
        }
    }
}

/// Walk past one name without materialising it, which is what walking a
/// question or a trailing section needs.
fn skipName(bytes: []const u8, at: usize) ?usize {
    var cursor = at;
    while (true) {
        if (cursor >= bytes.len) return null;
        const lead = bytes[cursor];
        switch (lead & seeds.pointer_mask) {
            seeds.pointer_lead => {
                if (cursor + 1 >= bytes.len) return null;
                const target = (@as(usize, lead & ~seeds.pointer_mask) << 8) | bytes[cursor + 1];
                if (target >= bytes.len or target >= cursor) return null;
                cursor = target;
            },
            seeds.label_lead => {
                cursor += 1;
                if (lead == 0) return cursor;
                if (cursor + lead > bytes.len) return null;
                cursor += lead;
            },
            else => return null,
        }
    }
}

fn writeByte(out: []u8, at: *usize, value: u8) bool {
    if (at.* >= out.len) return false;
    out[at.*] = value;
    at.* += 1;
    return true;
}

fn be16(bytes: []const u8, at: usize) u16 {
    return std.mem.readInt(u16, bytes[at..][0..2], .big);
}

/// Three oracles over one input: what the header decides, what the bytes decode
/// to, and whether the answer the decoder published is the one the second walk
/// says it must be.
pub fn check(bytes: []const u8) !void {
    var owner: [lookup.max_name_length]u8 = undefined;
    // The block a well-formed answer publishes: the joined character strings
    // of every matching record plus one NUL each. Twice the record ceiling is
    // slack over the true bound, so a buffer that ran out here could never be
    // mistaken for bytes that do not decode.
    var records: [seeds.input_buffer_len + 2 * lookup.max_section_records]u8 = undefined;

    // Oracle: a header that decides by itself names its own arm.
    switch (headerVerdict(bytes)) {
        .condemned => |arm| {
            try t.expectError(arm, lookup.readAnswer(t.allocator, bytes, seeds.asked, 0, &owner));
            return;
        },
        .undecided => {},
        .malformed, .well_formed => return error.HeaderVerdictIsNotAHeaderVerdict,
    }

    switch (walkVerdict(bytes, &owner, &records)) {
        .malformed => {
            // Oracle: bytes that do not decode publish nothing. There is no
            // answer to publish, so the only question is whether one is.
            if (lookup.readAnswer(t.allocator, bytes, seeds.asked, 0, &owner)) |answer| {
                answer.deinit(t.allocator);
                return error.MalformedMessagePublishedAnAnswer;
            } else |_| {}
        },
        .well_formed => |expected| {
            const answer = try lookup.readAnswer(t.allocator, bytes, seeds.asked, 0, &owner);
            defer answer.deinit(t.allocator);
            // Oracle: the accepted value, byte for byte. An empty block is a
            // name that exists and published nothing, which is an `Answer` of
            // its own and not an answer with no records in it.
            if (expected.len == 0) {
                try t.expectEqual(lookup.Answer.nothing, answer);
                return;
            }
            const set = switch (answer) {
                .records => |value| value,
                else => return error.WellFormedMessageWasNotAnAnswer,
            };
            try t.expectEqualStrings(expected, set.bytes);
            // Oracle: ownership. A read buffer a socket overwrites does not
            // outlive the call, so the records cannot be a window into it.
            const owned = @intFromPtr(set.bytes.ptr);
            const source = @intFromPtr(bytes.ptr);
            try t.expect(owned < source or owned + set.bytes.len <= source);
        },
        .condemned, .undecided => return error.WalkVerdictIsNotAWalkVerdict,
    }
}

/// Oracle: a publisher's records come back exactly as it wrote them.
///
/// Built out of the fuzzer's own bytes rather than out of a message, so this
/// holds whatever the input was: up to three NUL-free runs of it become three
/// `TXT` records under one spelled-out name, and the decoder has to reproduce
/// them as one NUL-joined block in the order they were written. A decoder that
/// dropped a character string, put a separator between two of them, reordered
/// the records, or attributed one to another name fails here whatever the
/// input bytes were.
pub fn checkRoundTrip(bytes: []const u8) !void {
    var texts: [3][]const u8 = undefined;
    var count: usize = 0;
    var rest = bytes;
    while (count < texts.len) {
        const end = std.mem.indexOfScalar(u8, rest, 0) orelse rest.len;
        // A character string's length is one octet, so a longer run cannot be
        // one, and an empty run would join to nothing.
        if (end == 0 or end > seeds.max_character_string) break;
        texts[count] = rest[0..end];
        count += 1;
        if (end == rest.len) break;
        rest = rest[end + 1 ..];
    }
    if (count == 0) return;

    var buffer: [seeds.input_buffer_len]u8 = undefined;
    var writer = seeds.Writer.init(&buffer);
    writer.header(0, lookup.flag_response, 1, @intCast(count), 0, 0);
    writer.question();
    var expected: [3 * (seeds.max_character_string + 1)]u8 = undefined;
    var expected_len: usize = 0;
    for (texts[0..count]) |text| {
        writer.name(seeds.asked);
        writer.txt(&.{text});
        @memcpy(expected[expected_len..][0..text.len], text);
        expected_len += text.len;
        expected[expected_len] = 0;
        expected_len += 1;
    }

    var owner: [lookup.max_name_length]u8 = undefined;
    const answer = try lookup.readAnswer(
        t.allocator,
        writer.bytes[0..writer.at],
        seeds.asked,
        0,
        &owner,
    );
    defer answer.deinit(t.allocator);
    const set = switch (answer) {
        .records => |value| value,
        else => return error.RoundTripAnswerWasNotRecords,
    };
    try t.expectEqualStrings(expected[0..expected_len], set.bytes);
}
