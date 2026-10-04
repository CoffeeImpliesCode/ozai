//! What the three `lookup_*` test files share: a scripted datagram, the wire
//! vectors the codec and the decoder are both held against, and the answer
//! shapes the decoder's sweeps build in a test's own buffer.
//!
//! A fixture and not a test file: nothing here asserts anything, and every
//! name is `pub` because its user is some other file. The datagram is a fake,
//! so a whole retrieval runs with no nameserver and no network — which is
//! what lets these tests sit in the socket-free root.

const std = @import("std");
const addr = @import("../base/addr.zig");
const dns = @import("dns.zig");
const resolve = @import("resolve.zig");
const record = @import("resolve_record.zig");
const wire = @import("lookup_wire.zig");
const seam = @import("lookup_io.zig");

// The seam's and the wire's vocabulary, bound once here for the reason the
// fixtures below read the way they do: a scripted socket is the seam's, and a
// built message is the wire's.
const SocketError = seam.SocketError;
const Datagram = seam.Datagram;
const queryLength = wire.queryLength;
const header_length = wire.header_length;
const type_txt = wire.type_txt;
const class_in = wire.class_in;
const type_opt = wire.type_opt;
const name_pointer = wire.name_pointer;
const flag_response = wire.flag_response;
const put16 = wire.put16;
const put32 = wire.put32;

pub const t = std.testing;
pub const key = @import("../base/key.zig");

/// The node `discovery/dns.zig` holds against upstream's own test.
pub const upstream_id = "1992d53c02cdc04566e5c0edb1ce83305cd550297953a047a445ea3264b54b18";

/// The name and the size the questions below are framed at.
pub const asked_len = dns.queryNameLength(dns.prod_origin);
pub const asked_bytes = queryLength("x" ** asked_len);

/// A datagram socket that answers from a script, which is how every test below
/// runs a whole lookup with no nameserver and no network.
///
/// `sent` keeps what the last `ask` put on the wire, so a test reads the bytes
/// that actually left rather than trusting that a function was called.
pub const Scripted = struct {
    sent: [asked_bytes]u8 = undefined,
    sent_len: usize = 0,
    sent_to: addr.SocketAddr = undefined,
    sends: u32 = 0,
    /// The answer the next `receive` hands back, or null for a socket that
    /// answers nothing.
    reply: ?[]u8 = null,
    /// Who the scripted answer comes from. Off the server by default, so a test
    /// has to name the server before a reply is acceptable.
    from: addr.SocketAddr,
    /// How many times the abort handle reached the socket.
    stops: u32 = 0,
    /// What the last `receive` was asked to wait for, so a test can read the
    /// deadline that was actually threaded down.
    deadline_ms: ?i32 = null,
    cancel_during_receive: ?resolve.Cancellation = null,
    /// Refusals the socket reports instead of doing its work. One per call and
    /// one per arm of `SocketError`, so every arm of the seam's own error set
    /// has a call that produces it rather than a mapping nobody took.
    refuse_send: bool = false,
    refuse_receive: bool = false,

    fn send(
        ctx: *anyopaque,
        // `ctx` is the vtable slot itself, not an ordinary parameter:
        // `Datagram.send` names it first and a reordered one is a different
        // function type. Z023 reads `*anyopaque` as a plain runtime value.
        // ziglint-ignore: Z023
        _: std.Io,
        to: addr.SocketAddr,
        bytes: []const u8,
    ) SocketError!void {
        const self: *Scripted = @ptrCast(@alignCast(ctx));
        if (self.refuse_send) return error.Refused;
        if (bytes.len > self.sent.len) return error.Refused;
        @memcpy(self.sent[0..bytes.len], bytes);
        self.sent_len = bytes.len;
        self.sent_to = to;
        self.sends += 1;
    }

    fn receive(
        ctx: *anyopaque,
        // `ctx` is the vtable slot itself, not an ordinary parameter:
        // `Datagram.receive` names it first and a reordered one is a different
        // function type. Z023 reads `*anyopaque` as a plain runtime value.
        // ziglint-ignore: Z023
        _: std.Io,
        into: []u8,
        deadline_ms: ?i32,
    ) SocketError!Datagram.Reply {
        const self: *Scripted = @ptrCast(@alignCast(ctx));
        self.deadline_ms = deadline_ms;
        if (self.refuse_receive) return error.Refused;
        if (self.cancel_during_receive) |cancellation| {
            cancellation.fire();
            return error.Empty;
        }
        const answer = self.reply orelse return error.Empty;
        if (answer.len > into.len) return error.Refused;
        @memcpy(into[0..answer.len], answer);
        return .{ .bytes = into[0..answer.len], .from = self.from };
    }

    fn stop(ctx: *anyopaque) void {
        const self: *Scripted = @ptrCast(@alignCast(ctx));
        self.stops += 1;
        // What a real socket does: a datagram nobody will read is dropped, so
        // there is nothing left for a second receive to hand back either.
        self.reply = null;
    }

    pub fn datagram(self: *Scripted) Datagram {
        return .{
            .ctx = @ptrCast(@alignCast(self)),
            .send = send,
            .receive = receive,
            .stop = stop,
        };
    }
};

/// The server a scripted socket answers for, and a different one it answers
/// from, because a TXT answer is unsigned.
pub const nameserver: addr.SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 53 };
pub const elsewhere: addr.SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 2 } }, .port = 53 };

/// An engine, so the transaction id is the same every run.
pub const Prng = std.Random.DefaultPrng;

/// The query RFC 8484 §4.1.1 prints, byte for byte: an `IN A` question for
/// `www.example.com`, `ID` zero, no EDNS0. Thirty-three octets, which is
/// `queryLength` less the OPT record, and every octet of it is the RFC's.
pub const rfc8484_hex =
    "00000100000100000000000003777777076578616d706c6503636f6d0000010001";

/// The same section's second query, and the better of the two here: its label
/// is 62 octets, one under RFC 1035 §2.3.4's 63, so it pins the longest label
/// this encoder can be handed from a primary source rather than from a
/// boundary this file chose. Ninety-four octets, and `queryLength` over its
/// 77-character name comes to 94 less the OPT record — the same arithmetic the
/// first vector confirms, on a second name.
pub const rfc8484_long_hex =
    "00000100000100000000000001613e36326368617261637465726c6162656c2d" ++
    "6d616b65732d62617365363475726c2d64697374696e63742d66726f6d2d7374" ++
    "616e646172642d626173653634076578616d706c6503636f6d0000010001";

/// The DNS answer inside `discovery/pkarr.zig`'s `small_dns_hex`, which is the
/// body of a packet the `pkarr` crate v8.0.2 produced (`pubky/pkarr`
/// `pkarr/src/types/signed_packet.rs` at
/// aa4011cabc3676d533dd3c633dc0801c94bfca86). One TXT record under
/// `_iroh.<z32>`, TTL 30, holding one `relay=` record: a real answer from the
/// reference implementation, and not a hand-built one.
pub const captured_answer_hex =
    "000080000000000100000000055f69726f6834376a66676161396e75746a7969" ++
    "787a696b623774676d736639676b77713769717a3439387a72316e6435696731" ++
    "666e673465737900001000010000001e001b1a72656c61793d68747470733a2f" ++
    "2f6578616d706c652e636f6d2f";

/// The one record that answer carried, in `record.RecordSet`'s own shape.
pub const captured_record = "relay=https://example.com/\x00";

/// The seed that packet was signed with, and so the node its name is about.
pub const captured_seed = [_]u8{7} ** key.SecretKey.seed_length;

/// The name in `captured_answer_hex`: `_iroh.<z32>.` with no origin, which is
/// what a publisher signs for itself.
pub fn capturedName(secret: key.NodeId, out: []u8) []const u8 {
    const label = secret.toZ32();
    @memcpy(out[0..record.iroh_txt_name.len], record.iroh_txt_name);
    out[record.iroh_txt_name.len] = '.';
    @memcpy(out[record.iroh_txt_name.len + 1 ..][0..label.len], &label);
    out[record.iroh_txt_name.len + 1 + label.len] = '.';
    return out[0 .. record.iroh_txt_name.len + 2 + label.len];
}

pub fn hexBytes(out: []u8, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return error.OddHexLength;
    if (out.len < hex.len / 2) return error.BufferTooSmall;
    return std.fmt.hexToBytes(out[0 .. hex.len / 2], hex);
}

/// The node a wire vector is about, from the hex constant the vector names.
/// Fallible: a literal that is not a canonical curve point is a typo in the
/// vector, and the test that carries it should say so rather than take the
/// process down on the way to saying anything at all.
pub fn nodeOf(hex: []const u8) key.KeyError!key.NodeId {
    return key.NodeId.parseHex(hex);
}

pub fn expectHex(expected: []const u8, actual: []const u8) !void {
    if (std.mem.eql(u8, expected, actual)) return;
    var buffer: [dump_bytes]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    // `std`'s formatter rather than a hand-rolled dump: this only runs when a
    // wire vector has moved, and what a reader needs then is the bytes.
    writer.print("expected {d}: {x}\n     got {d}: {x}\n", .{
        expected.len,
        expected[0..@min(expected.len, max_dumped_bytes)],
        actual.len,
        actual[0..@min(actual.len, max_dumped_bytes)],
    }) catch return error.WireFormatMismatch;
    std.debug.print("{s}", .{writer.buffered()});
    return error.WireFormatMismatch;
}

/// How much of a mismatch is printed, and the buffer it is printed into.
pub const max_dumped_bytes = 48;
pub const dump_bytes = 2 * (4 + 2 * max_dumped_bytes) + 8;

/// The name the messages below are read under.
///
/// Spelled out rather than drawn from a node id: what these shapes are about
/// is which records belong to the name a question asked about, not about whose
/// node id that label spells.
pub const sweep_name = "_iroh.example.";

/// What `sweptAnswer` publishes: three records, the character strings of each
/// TXT record joined with nothing between them and the records separated from
/// each other by one NUL.
pub const swept_records =
    "relay=https://use1-1.relay.iroh.network./\x00" ++
    "addr=192.168.96.145:60165\x00" ++
    "addr=213.208.157.87:60165\x00";

/// The first record's two character strings, which join into the first record
/// of `swept_records` and are the joining RFC 1035 §3.3.14 allows.
pub const swept_first_strings =
    [_][]const u8{ "relay=https://use1-1.", "relay.iroh.network./" };

/// A message assembled in a test's own buffer.
///
/// The vectors elsewhere in this file are captured or printed. This is for the
/// shapes there is no capture of, and it names every field it writes so a
/// change to a header layout does not move every expectation with it.
pub const Message = struct {
    bytes: []u8,
    at: usize = 0,

    fn init(bytes: []u8) Message {
        @memset(bytes, 0);
        return .{ .bytes = bytes, .at = header_length };
    }

    fn header(self: *Message, id: u16, flags: u16, qd: u16, an: u16, ns: u16, ar: u16) void {
        put16(self.bytes, 0, id);
        put16(self.bytes, 2, flags);
        put16(self.bytes, 4, qd);
        put16(self.bytes, 6, an);
        put16(self.bytes, 8, ns);
        put16(self.bytes, 10, ar);
    }

    fn octet(self: *Message, value: u8) void {
        self.bytes[self.at] = value;
        self.at += 1;
    }

    fn pair(self: *Message, value: u16) void {
        put16(self.bytes, self.at, value);
        self.at += 2;
    }

    fn slice(self: *Message, value: []const u8) void {
        @memcpy(self.bytes[self.at..][0..value.len], value);
        self.at += value.len;
    }

    /// One label, which is its length octet and then its octets.
    fn label(self: *Message, value: []const u8) void {
        self.octet(@intCast(value.len));
        self.slice(value);
    }

    /// A presentation name with its trailing dot, written as labels and the
    /// root's terminator.
    fn name(self: *Message, value: []const u8) void {
        var labels = std.mem.splitScalar(u8, value, '.');
        while (labels.next()) |part| {
            if (part.len == 0) continue;
            self.label(part);
        }
        self.octet(0);
    }

    /// RFC 1035 §4.1.4's pointer to an offset this message already holds.
    fn pointer(self: *Message, target: usize) void {
        self.octet(name_pointer | @as(u8, @intCast(target >> 8)));
        self.octet(@intCast(target & 0xff));
    }

    /// One record's `TYPE`, `CLASS`, `TTL` and `RDLENGTH`, then its `RDATA`.
    fn record(self: *Message, kind: u16, class: u16, ttl: u32, rdata: []const u8) void {
        const fixed = self.at;
        self.at += 10;
        const start = self.at;
        self.slice(rdata);
        put16(self.bytes, fixed, kind);
        put16(self.bytes, fixed + 2, class);
        put32(self.bytes, fixed + 4, ttl);
        put16(self.bytes, fixed + 8, @intCast(self.at - start));
    }

    /// One TXT record's character strings, RFC 1035 §3.3.14's "one or more":
    /// a length octet each and nothing between them. The owner name goes on
    /// first, and a compression pointer counts as a name.
    fn txt(self: *Message, strings: []const []const u8) void {
        const fixed = self.at;
        self.at += 10;
        const start = self.at;
        for (strings) |string| {
            self.octet(@intCast(string.len));
            self.slice(string);
        }
        put16(self.bytes, fixed, type_txt);
        put16(self.bytes, fixed + 2, class_in);
        put32(self.bytes, fixed + 4, 30);
        put16(self.bytes, fixed + 8, @intCast(self.at - start));
    }
};

/// A built answer, and the two offsets a test cuts it at.
pub const Swept = struct {
    bytes: []u8,
    /// Where the alias record begins, which is after three records have already
    /// been copied out.
    alias_at: usize,
    /// Where the additional section begins.
    additional_at: usize,
};

/// The answer every sweep below runs against.
///
/// One question, then four answer records: three TXT records under the name
/// asked about — the first spelling that name out and the next two reaching it
/// through a compression pointer, which is what a real server does with a name
/// the message already holds — and one TXT record under a name this question
/// did not ask about. Then the two records it does not get: the same TXT shape
/// under this name again, but in the authority section, and an OPT record in
/// the additional section.
///
/// An alias is skipped rather than refused, and a TXT record in somebody
/// else's authority section is walked without being read, so both of them are
/// answers to something other than this question and neither may reach it.
pub fn sweptAnswer(buffer: []u8) Swept {
    var message = Message.init(buffer);
    message.header(0, flag_response, 1, 4, 1, 1);
    message.name(sweep_name);
    message.pair(type_txt);
    message.pair(class_in);

    message.name(sweep_name);
    message.txt(&swept_first_strings);
    message.pointer(header_length);
    message.txt(&.{"addr=192.168.96.145:60165"});
    message.pointer(header_length);
    message.txt(&.{ "addr=213.208.157.87:", "60165" });

    const alias_start = message.at;
    message.name("other.example.");
    message.txt(&.{"relay=https://elsewhere.example./"});

    message.name(sweep_name);
    message.txt(&.{"addr=203.0.113.9:41601"});

    const additional_at = message.at;
    message.octet(0);
    message.record(type_opt, 0, 0, "");

    return .{
        .bytes = buffer[0..message.at],
        .alias_at = alias_start,
        .additional_at = additional_at,
    };
}
