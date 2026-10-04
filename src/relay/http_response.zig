//! The `101` a relay answers a WebSocket upgrade with, and the accept key that
//! goes in it.
//!
//! `http_upgrade.zig` reads the request; this module writes the answer. The two
//! halves share one rule and no code: RFC 6455 §4.2.2 fixes what a `101` must
//! contain, and this module writes exactly that into a buffer the caller owns.
//! It does not open a socket, allocate, or read a clock — the TLS seam and the
//! byte pump are Wave 2's other slices.
//!
//! # The accept key is arithmetic, not a security claim
//!
//! RFC 6455 §4.2.2 step 5: SHA-1 of the client's `Sec-WebSocket-Key` followed by
//! the fixed GUID `258EAFA5-E914-47DA-95CA-C5AB0DC85B11`, then base64. That is
//! SHA-1 and no other hash, and the reason is that it proves a response belongs
//! to a handshake that actually happened rather than proving anything about the
//! peer's identity. **It is checked, so a proxy that rewrites the key cannot be
//! impersonated by a cached response; it is not, so nothing here is a substitute
//! for the TLS that authenticates the relay.** The RFC prints the worked example
//! in §1.3 and the test below carries those bytes.

const std = @import("std");
const frame = @import("frame_types.zig");
const upgrade = @import("http_upgrade.zig");

const ProtocolVersion = frame.ProtocolVersion;
const Request = upgrade.Request;
const std_testing = std.testing;

/// Every way a response can fail to be written.
///
/// One arm, and `BufferFull` is the only thing that can go wrong: every byte this
/// module writes is counted in `max_response_bytes`, and the length is checked
/// before the writer exists. The request's own refusals are `http_upgrade`'s and
/// are not restated here — a request that parsed has none of them left.
pub const Error = error{
    /// The caller's buffer has no room for the response.
    BufferFull,
};

/// The GUID RFC 6455 §1.3 and §4.2.2 append to the key before hashing.
pub const accept_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// The bytes a `Sec-WebSocket-Accept` value is: base64 of a twenty-byte digest,
/// which is `calcSize` of the digest and not a number anyone typed.
pub const accept_key_length =
    std.base64.standard.Encoder.calcSize(std.crypto.hash.Sha1.digest_length);

/// The longest sub-protocol name `ProtocolVersion.name` returns, counted from
/// the enum rather than written down beside it, so adding a version that names
/// itself longer cannot make `max_response_bytes` a number that is wrong.
const longest_protocol_name: usize = blk: {
    var longest: usize = 0;
    for (std.enums.values(ProtocolVersion)) |version| {
        longest = @max(longest, ProtocolVersion.name(version).len);
    }
    break :blk longest;
};

/// The most bytes `buildResponse` writes: a status line, four field lines, and
/// the blank line that ends the head.
///
/// Counted from the pieces rather than measured once, because a bound a caller
/// sizes a buffer from that is written down twice is a bound that goes stale in
/// one of the two places.
pub const max_response_bytes = "HTTP/1.1 101 Switching Protocols\r\n".len +
    "Upgrade: websocket\r\n".len +
    "Connection: Upgrade\r\n".len +
    "Sec-WebSocket-Accept: ".len + accept_key_length + "\r\n".len +
    "Sec-WebSocket-Protocol: ".len + longest_protocol_name + "\r\n".len +
    "\r\n".len;

/// Writes the `101` answer to `request` into `out` and hands back what it wrote.
///
/// The slice it returns is `out[0..written]` — the same memory, not a copy — so
/// it aliases the caller's buffer and is invalidated by whatever the caller next
/// writes there. **The response is written only after the length is checked**, so
/// `error.BufferFull` leaves `out` exactly as the caller handed it over: a
/// half-written `101` is a response a peer may accept.
///
/// The sub-protocol named back is the one `frame.negotiate` settled on, which
/// is `request.protocol` and nothing chosen here — this module decides no
/// version, it writes the one the request already carries.
pub fn buildResponse(request: Request, out: []u8) Error![]const u8 {
    if (out.len < max_response_bytes) return error.BufferFull;
    var accept: [accept_key_length]u8 = undefined;
    acceptKey(request.key, &accept);
    var writer = Writer.init(out);
    writer.put("HTTP/1.1 101 Switching Protocols\r\n");
    writer.put("Upgrade: websocket\r\n");
    writer.put("Connection: Upgrade\r\n");
    writer.put("Sec-WebSocket-Accept: ");
    writer.put(&accept);
    writer.put("\r\nSec-WebSocket-Protocol: ");
    writer.put(ProtocolVersion.name(request.protocol));
    writer.put("\r\n\r\n");
    return writer.finish();
}

/// The `Sec-WebSocket-Accept` value for a client's `Sec-WebSocket-Key`.
///
/// Hashed as two updates rather than by joining the key and the GUID into one
/// buffer: the concatenation is fifty-two bytes at most and joining it would be
/// a buffer this module does not otherwise need. The result is twenty-eight bytes
/// and every one of them is written.
pub fn acceptKey(key: []const u8, out: *[accept_key_length]u8) void {
    var digest: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
    var hasher = std.crypto.hash.Sha1.init(.{});
    hasher.update(key);
    hasher.update(accept_guid);
    hasher.final(&digest);
    _ = std.base64.standard.Encoder.encode(out[0..], &digest);
}

/// Writes into a buffer the caller owns, and never grows it.
///
/// **No method can fail**, because `buildResponse` has already checked
/// `max_response_bytes` against the buffer and every byte it writes is counted
/// in that number — so an infallible writer is not a lost refusal, it is the
/// bound moved to the one place that can enforce it.
const Writer = struct {
    buf: []u8,
    at: usize = 0,

    fn init(buf: []u8) Writer {
        return .{ .buf = buf };
    }

    fn put(self: *Writer, bytes: []const u8) void {
        @memcpy(self.buf[self.at..][0..bytes.len], bytes);
        self.at += bytes.len;
    }

    fn finish(self: *const Writer) []const u8 {
        return self.buf[0..self.at];
    }
};

// ---------------------------------------------------------------------------
// Tests. The bytes come from RFC 6455 §1.3 and §4; nothing here is claimed to
// be a capture of upstream, because upstream writes these bytes through a
// library.
// ---------------------------------------------------------------------------

/// RFC 6455 §1.3's key and its answer: the one worked example the RFC prints.
const rfc_key = "dGhlIHNhbXBsZSBub25jZQ==";
const rfc_accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

/// RFC 6455 §1.3's request head, spelled with this tree's sub-protocol.
const rfc_request =
    "GET /relay HTTP/1.1\r\n" ++
    "Host: server.example.com\r\n" ++
    "Upgrade: websocket\r\nConnection: Upgrade\r\n" ++
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
    "Sec-WebSocket-Version: 13\r\n" ++
    "Sec-WebSocket-Protocol: iroh-relay-v2\r\n" ++
    "\r\n";

/// `rfc_request` with its sub-protocol field replaced, for the two versions.
fn withProtocol(protocol: []const u8) []const u8 {
    return "GET /relay HTTP/1.1\r\nHost: server.example.com\r\n" ++
        "Upgrade: websocket\r\nConnection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "Sec-WebSocket-Protocol: " ++ protocol ++ "\r\n\r\n";
}

test "golden: RFC 6455 §1.3, the accept key" {
    var accept: [accept_key_length]u8 = undefined;
    acceptKey(rfc_key, &accept);
    try std_testing.expectEqualStrings(rfc_accept, &accept);

    // And through a whole request and response, so the key is proved on the path
    // a relay takes rather than only against the hash.
    var buffer: [max_response_bytes]u8 = undefined;
    const response = try buildResponse(
        try upgrade.parseRequest(rfc_request),
        &buffer,
    );
    try std_testing.expect(std.mem.indexOf(u8, response, rfc_accept) != null);
}

test "golden: the 101 response is the four field lines and the blank line" {
    const request = try upgrade.parseRequest(rfc_request);
    try std_testing.expectEqualStrings("server.example.com", request.host);
    try std_testing.expectEqualStrings(rfc_key, request.key);
    try std_testing.expectEqual(ProtocolVersion.v2, request.protocol);

    var buffer: [max_response_bytes]u8 = undefined;
    const response = try buildResponse(request, &buffer);
    const want = "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "Sec-WebSocket-Protocol: iroh-relay-v2\r\n" ++
        "\r\n";
    try std_testing.expectEqualStrings(want, response);
    // The bound is the length of what was written, counted by this module's own
    // arithmetic rather than by this test — so a field line added later and not
    // added to `max_response_bytes` fails here instead of overflowing a caller.
    try std_testing.expect(max_response_bytes > response.len);
}

test "both versions are emittable and each names itself" {
    // The response is the only place a version's name reaches the wire, so a
    // version whose name this module could not fit is a version whose response
    // would be short. Both are written, and the bound held for each.
    for (std.enums.values(ProtocolVersion)) |version| {
        const request = try upgrade.parseRequest(withProtocol(ProtocolVersion.name(version)));
        try std_testing.expectEqual(version, request.protocol);
        var buffer: [max_response_bytes]u8 = undefined;
        const response = try buildResponse(request, &buffer);
        try std_testing.expect(std.mem.indexOf(
            u8,
            response,
            ProtocolVersion.name(version),
        ) != null);
    }
}

test "error inventory: every declared arm is reached by concrete bytes" {
    const arms = [_]Error{error.BufferFull};
    try std_testing.expectEqual(@typeInfo(Error).error_set.?.len, arms.len);

    // The bound is checked before the writer exists, so a buffer one byte short
    // leaves the caller's buffer untouched rather than half-written.
    const request = try upgrade.parseRequest(rfc_request);
    var short: [max_response_bytes - 1]u8 = @splat(0xaa);
    try std_testing.expectError(error.BufferFull, buildResponse(request, &short));
    for (short) |byte| try std_testing.expectEqual(@as(u8, 0xaa), byte);
}
