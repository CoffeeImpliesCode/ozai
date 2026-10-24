//! The bytes and the seam the wire and retrieval tests both stand on: captured
//! vectors, a scripted datagram socket, and the three helpers that compare them.
//!
//! Nothing here is a lookup. A test in `lookup_query.zig` or `lookup_answer.zig`
//! needs a name to ask about and a reference implementation's answer to read;
//! a test in `lookup_retrieval.zig` needs a socket that answers from a script.
//! Both needs are the same fixtures, so both import this rather than each
//! growing its own copy.

const std = @import("std");

const addr = @import("../base/addr.zig");
const key = @import("../base/key.zig");
const dns = @import("dns.zig");
const resolve = @import("resolve.zig");

const seam = @import("lookup_datagram.zig");
const query = @import("lookup_query.zig");

/// The node `discovery/dns.zig` holds against upstream's own test.
pub const upstream_id = "1992d53c02cdc04566e5c0edb1ce83305cd550297953a047a445ea3264b54b18";

/// The name and the size the questions are framed at.
pub const asked_len = dns.queryNameLength(dns.prod_origin);
pub const asked_bytes = query.queryLength(&@as([asked_len:0]u8, @splat('x')));

/// A datagram socket that answers from a script, which is how every seam test
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

    pub fn send(
        ctx: *anyopaque,
        // `ctx` is the vtable slot itself, not an ordinary parameter:
        // `Datagram.send` names it first and a reordered one is a different
        // function type. Z023 reads `*anyopaque` as a plain runtime value.
        // ziglint-ignore: Z023
        _: std.Io,
        to: addr.SocketAddr,
        bytes: []const u8,
    ) seam.SocketError!void {
        const self: *Scripted = @ptrCast(@alignCast(ctx));
        if (bytes.len > self.sent.len) return error.Refused;
        @memcpy(self.sent[0..bytes.len], bytes);
        self.sent_len = bytes.len;
        self.sent_to = to;
        self.sends += 1;
    }

    pub fn receive(
        ctx: *anyopaque,
        // `ctx` is the vtable slot itself, not an ordinary parameter:
        // `Datagram.receive` names it first and a reordered one is a different
        // function type. Z023 reads `*anyopaque` as a plain runtime value.
        // ziglint-ignore: Z023
        _: std.Io,
        into: []u8,
        deadline_ms: ?i32,
    ) seam.SocketError!seam.Datagram.Reply {
        const self: *Scripted = @ptrCast(@alignCast(ctx));
        self.deadline_ms = deadline_ms;
        if (self.cancel_during_receive) |cancellation| {
            cancellation.fire();
            return error.Empty;
        }
        const answer = self.reply orelse return error.Empty;
        if (answer.len > into.len) return error.Refused;
        @memcpy(into[0..answer.len], answer);
        return .{ .bytes = into[0..answer.len], .from = self.from };
    }

    pub fn stop(ctx: *anyopaque) void {
        const self: *Scripted = @ptrCast(@alignCast(ctx));
        self.stops += 1;
        // What a real socket does: a datagram nobody will read is dropped, so
        // there is nothing left for a second receive to hand back either.
        self.reply = null;
    }

    pub fn datagram(self: *Scripted) seam.Datagram {
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
/// boundary this milestone chose. Ninety-four octets, and `queryLength` over its
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

/// The one record that answer carried, in `resolve.RecordSet`'s own shape.
pub const captured_record = "relay=https://example.com/\x00";

/// The seed that packet was signed with, and so the node its name is about.
pub const captured_seed = @as([key.SecretKey.seed_length]u8, @splat(7));

/// The name in `captured_answer_hex`: `_iroh.<z32>.` with no origin, which is
/// what a publisher signs for itself.
pub fn capturedName(secret: key.NodeId, out: []u8) []const u8 {
    const label = secret.toZ32();
    @memcpy(out[0..resolve.iroh_txt_name.len], resolve.iroh_txt_name);
    out[resolve.iroh_txt_name.len] = '.';
    @memcpy(out[resolve.iroh_txt_name.len + 1 ..][0..label.len], &label);
    out[resolve.iroh_txt_name.len + 1 + label.len] = '.';
    return out[0 .. resolve.iroh_txt_name.len + 2 + label.len];
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
const max_dumped_bytes = 48;
const dump_bytes = 2 * (4 + 2 * max_dumped_bytes) + 8;
