//! How a DNS message is written, and the named corpus of shapes a lookup must
//! refuse or accept.
//!
//! This is one responsibility: producing wire bytes, on purpose, from a named
//! shape. It is the seed corpus of `test/dns_fuzz.zig` and the message builder
//! its accepted-value oracle constructs a canonical answer with, and those two
//! are the same job — a message that is *written* rather than mutated. The
//! oracle's other half, the walk that reads bytes back, is `dns_wire/oracle.zig`
//! and imports this file rather than duplicating any of it.
//!
//! Built rather than `@embedFile`d, for the reason the shapes matter: an
//! embedded corpus is bytes with no name on them, and what each seed is here is
//! the whole of what this corpus says.

const std = @import("std");
const ozai = @import("ozai");
const lookup = ozai.discovery_lookup_io;

/// The name every seed and every fuzzer input is read under. Spelled out
/// because the oracle compares owner names against it and a name that varied
/// per run would make a record match or not match by accident.
pub const asked = "_iroh.example.";

/// Long enough to overrun every bound the decoder checks — a name pointer's
/// fourteen bits reach 16383 and a `RDLENGTH` is 65535, so anything shorter
/// would let a length check pass without ever reaching the bytes behind it —
/// and short enough to stay on the fuzzer's stack. RFC 6891 §6.2.3's figure is
/// also what a real answer is read into.
pub const input_buffer_len = lookup.reply_length;

/// RFC 1035 §4.1.4's name encodings, spelled here rather than imported. This is
/// the encoding a reader has to agree with, so it may not be read out of the
/// code under test.
pub const label_lead: u8 = 0x00;
pub const pointer_lead: u8 = 0xc0;
pub const pointer_mask: u8 = 0xc0;

/// RFC 1035 §3.3.14: a character string's length is one octet.
pub const max_character_string = 255;

/// How many character strings one record here carries at most, which is what
/// sizes the scratch `Writer.txt` builds them in.
const texts_per_record = 8;

/// A DNS message written into a buffer, byte by byte.
///
/// What a seed *is* — a name that points at itself, a count past what a
/// datagram could hold, a character string longer than its `RDATA` — is then
/// named on the line that makes it.
pub const Writer = struct {
    bytes: []u8,
    at: usize = 0,

    pub fn init(bytes: []u8) Writer {
        @memset(bytes, 0);
        return .{ .bytes = bytes, .at = lookup.header_length };
    }

    pub fn header(self: *Writer, id: u16, flags: u16, qd: u16, an: u16, ns: u16, ar: u16) void {
        std.mem.writeInt(u16, self.bytes[0..][0..2], id, .big);
        std.mem.writeInt(u16, self.bytes[2..][0..2], flags, .big);
        std.mem.writeInt(u16, self.bytes[4..][0..2], qd, .big);
        std.mem.writeInt(u16, self.bytes[6..][0..2], an, .big);
        std.mem.writeInt(u16, self.bytes[8..][0..2], ns, .big);
        std.mem.writeInt(u16, self.bytes[10..][0..2], ar, .big);
    }

    pub fn octet(self: *Writer, value: u8) void {
        self.bytes[self.at] = value;
        self.at += 1;
    }

    pub fn pair(self: *Writer, value: u16) void {
        std.mem.writeInt(u16, self.bytes[self.at..][0..2], value, .big);
        self.at += 2;
    }

    pub fn slice(self: *Writer, value: []const u8) void {
        @memcpy(self.bytes[self.at..][0..value.len], value);
        self.at += value.len;
    }

    /// One label, which is its length octet and then its octets.
    pub fn label(self: *Writer, value: []const u8) void {
        self.octet(@intCast(value.len));
        self.slice(value);
    }

    /// A presentation name with its trailing dot, written as labels and the
    /// root's terminator.
    pub fn name(self: *Writer, value: []const u8) void {
        var labels = std.mem.splitScalar(u8, value, '.');
        while (labels.next()) |part| {
            if (part.len == 0) continue;
            self.label(part);
        }
        self.octet(label_lead);
    }

    /// §4.1.4's pointer to an offset this message already holds.
    pub fn pointer(self: *Writer, target: usize) void {
        self.octet(pointer_lead | @as(u8, @intCast(target >> 8)));
        self.octet(@intCast(target & 0xff));
    }

    /// The question a lookup asks, and the one name every later pointer needs
    /// to find already written: the question sits at the first octet after the
    /// header, which is what every pointer below aims at.
    pub fn question(self: *Writer) void {
        self.name(asked);
        self.pair(lookup.type_txt);
        self.pair(lookup.class_in);
    }

    /// One record's `TYPE`, `CLASS`, `TTL` and `RDLENGTH`, then its `RDATA`,
    /// with the length patched once the `RDATA` has said how long it is.
    pub fn record(self: *Writer, kind: u16, class: u16, ttl: u32, rdata: []const u8) void {
        const fixed = self.at;
        self.at += 10;
        const start = self.at;
        self.slice(rdata);
        std.mem.writeInt(u16, self.bytes[fixed..][0..2], kind, .big);
        std.mem.writeInt(u16, self.bytes[fixed + 2 ..][0..2], class, .big);
        std.mem.writeInt(u32, self.bytes[fixed + 4 ..][0..4], ttl, .big);
        std.mem.writeInt(u16, self.bytes[fixed + 8 ..][0..2], @intCast(self.at - start), .big);
    }

    /// One `TXT` record's character strings: a length octet each and nothing
    /// between them, which is §3.3.14's "one or more".
    pub fn txt(self: *Writer, strings: []const []const u8) void {
        var rdata: [texts_per_record * (max_character_string + 1)]u8 = undefined;
        var length: usize = 0;
        for (strings) |string| {
            rdata[length] = @intCast(string.len);
            length += 1;
            @memcpy(rdata[length..][0..string.len], string);
            length += string.len;
        }
        self.record(lookup.type_txt, lookup.class_in, 30, rdata[0..length]);
    }
};

/// One seed's shape, and the line that builds it.
///
/// These are the shapes a mutation cannot be relied on to produce: an empty
/// input is not a mutation of anything, and a name that points at itself is two
/// octets that a mutation of a real answer would have to land on exactly. The
/// `shape` strings are the corpus's own documentation — nothing reads them at
/// run time, and a seed without a sentence saying why it exists is a seed
/// nobody will look at again.
const seeds = [_]struct { shape: []const u8, fill: *const fn (*Writer) void }{
    .{ .shape = "no bytes at all: there is no header to decide from", .fill = seedEmpty },
    .{ .shape = "a response header that says it has nothing", .fill = seedHeaderOnly },
    .{ .shape = "one question and no records: a name that published nothing", .fill = seedNothing },
    .{ .shape = "a name that points at itself", .fill = seedSelfPointer },
    .{
        .shape = "a pointer to an offset after the name it stands in for",
        .fill = seedForwardPointer,
    },
    .{ .shape = "a name encoding RFC 1035 §4.1.4 reserves", .fill = seedReservedLead },
    .{ .shape = "more records than this file will walk", .fill = seedCountsOver },
    .{ .shape = "the TC bit over three records", .fill = seedTruncated },
    .{ .shape = "a character string longer than the RDATA holding it", .fill = seedBadTxtLength },
    .{ .shape = "an additional record cut inside its fixed part", .fill = seedCutAdditional },
    .{ .shape = "as many records as the walk will accept", .fill = seedManyRecords },
    .{
        .shape = "records of several character strings each, reached by pointer",
        .fill = seedMultiString,
    },
};

pub const seed_count = seeds.len;

comptime {
    if (seed_count == 0) @compileError("a corpus with no seeds never reaches the decoder");
}

fn seedEmpty(writer: *Writer) void {
    writer.at = 0;
}

fn seedHeaderOnly(writer: *Writer) void {
    writer.header(0, lookup.flag_response, 0, 0, 0, 0);
}

fn seedNothing(writer: *Writer) void {
    writer.header(0, lookup.flag_response, 1, 0, 0, 0);
    writer.question();
}

fn seedSelfPointer(writer: *Writer) void {
    writer.header(0, lookup.flag_response, 0, 1, 0, 0);
    writer.at = lookup.header_length;
    writer.pointer(lookup.header_length);
}

fn seedForwardPointer(writer: *Writer) void {
    writer.header(0, lookup.flag_response, 0, 1, 0, 0);
    writer.at = lookup.header_length;
    writer.label("fwd");
    writer.pointer(writer.at);
}

fn seedReservedLead(writer: *Writer) void {
    writer.header(0, lookup.flag_response, 0, 1, 0, 0);
    writer.at = lookup.header_length;
    writer.octet(0x40);
}

fn seedCountsOver(writer: *Writer) void {
    writer.header(0, lookup.flag_response, 0, lookup.max_section_records + 1, 0, 0);
}

fn seedTruncated(writer: *Writer) void {
    writer.header(0, lookup.flag_response | lookup.flag_truncated, 1, 3, 0, 0);
    writer.question();
    for (0..3) |_| {
        writer.pointer(lookup.header_length);
        writer.txt(&.{"relay=https://use1-1.relay.iroh.network./"});
    }
}

fn seedBadTxtLength(writer: *Writer) void {
    writer.header(0, lookup.flag_response, 1, 1, 0, 0);
    writer.question();
    writer.pointer(lookup.header_length);
    const rdata_at = writer.at + 10;
    writer.record(lookup.type_txt, lookup.class_in, 30, &.{5});
    // The record is whole and its `RDLENGTH` agrees with it. What does not
    // agree is the character string inside it, which is §3.3.14's "that many
    // octets" read as a length the `RDATA` does not hold.
    writer.bytes[rdata_at] = 200;
}

fn seedCutAdditional(writer: *Writer) void {
    writer.header(0, lookup.flag_response, 1, 1, 0, 1);
    writer.question();
    writer.pointer(lookup.header_length);
    writer.txt(&.{"relay=https://use1-1.relay.iroh.network./"});
    // The additional record's root label and eight of its ten fixed octets.
    writer.octet(label_lead);
    writer.at += 8;
}

fn seedManyRecords(writer: *Writer) void {
    writer.header(0, lookup.flag_response, 1, lookup.max_section_records, 0, 0);
    writer.question();
    for (0..lookup.max_section_records) |_| {
        writer.pointer(lookup.header_length);
        writer.txt(&.{"a"});
    }
}

fn seedMultiString(writer: *Writer) void {
    writer.header(0, lookup.flag_response, 1, 3, 0, 0);
    writer.question();
    writer.pointer(lookup.header_length);
    writer.txt(&.{ "relay=https://use1-1.", "relay.iroh.network./" });
    writer.pointer(lookup.header_length);
    writer.txt(&.{ "addr=192.168.96.145:", "60165" });
    writer.pointer(lookup.header_length);
    writer.txt(&.{"addr=213.208.157.87:60165"});
}

/// Build every seed into `storage` and its length into `lengths`.
pub fn buildSeeds(
    storage: *[seed_count][input_buffer_len]u8,
    lengths: *[seed_count]usize,
) void {
    for (seeds, 0..) |seed, index| {
        var writer = Writer.init(storage[index][0..]);
        seed.fill(&writer);
        std.debug.assert(writer.at <= writer.bytes.len);
        lengths[index] = writer.at;
    }
}
