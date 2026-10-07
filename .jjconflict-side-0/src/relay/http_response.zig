//! The `101` response that answers a relay upgrade, and the accept value inside
//! it.
//!
//! RFC 6455 section 4.2.2 step 5 is the one step of the handshake with anything
//! to compute, and it is where a relay that got the rest right can still be
//! wrong in a way a client cannot explain.
//!
//! ```text
//! Sec-WebSocket-Accept = base64( SHA1( Sec-WebSocket-Key + "258EAFA5-…" ) )
//! ```
//!
//! **The concatenated value is the field value, not what it decodes to.** The
//! section says "the field value of the |Sec-WebSocket-Key| field … taking the
//! value of the header field to be the string of octets", and the field value is
//! the base64 text: `dGhlIHNhbXBsZSBub25jZQ==` and not the sixteen bytes it
//! stands for. That is why `relay/http_request.zig` copies the decoded sixteen
//! bytes out for the length rule and keeps the text for this.
//!
//! The response is written into a buffer the caller owns and never grown, the
//! same rule `relay/frame_encode.zig` follows: a response too large for its
//! buffer is `error.BufferFull` and not a resize the caller never agreed to.
//! Nothing here allocates, reads a clock, or reaches for a global.

const std = @import("std");
const http_upgrade_types = @import("http_upgrade_types.zig");
const vectors = @import("ws_frame_vectors.zig");

const Error = http_upgrade_types.Error;
const Version = http_upgrade_types.Version;
const accept_length = http_upgrade_types.accept_length;
const websocket_guid = http_upgrade_types.websocket_guid;
const crlf = "\r\n";
const std_testing = std.testing;

/// What `build` can fail with.
///
/// The request's own `Error` rides along because the sub-protocol this
/// response names is the one `http_upgrade.parse` settled on, so a caller
/// holding both halves of a handshake sees one vocabulary. `BufferFull` is the
/// one refusal the response itself has, and it is a member rather than a
/// widening of `Error`: `http_upgrade_types.Error` is what a *request* can be
/// refused with, and a response that cannot fit its caller's buffer is not a
/// malformed request.
const BuildError = Error || error{BufferFull};

const Sha1 = std.crypto.hash.Sha1;

/// The status line and the two fixed fields, a comptime literal with static
/// lifetime so it is never borrowed from anything that has to outlive a caller
/// and never freed.
const status_line = "HTTP/1.1 101 Switching Protocols" ++ crlf ++
    "Upgrade: websocket" ++ crlf ++
    "Connection: Upgrade" ++ crlf;

/// The one field whose value is computed.
const accept_field = "Sec-WebSocket-Accept: ";

/// The sub-protocol field, whose presence depends on the request's.
///
/// **It goes out only when the request named one.** RFC 6455 section 4.2.2
/// step 10 says a server that returns a `Sec-WebSocket-Protocol` when the
/// client sent none makes the client fail the connection, so answering RFC 6455
/// section 1.3's own example request with this field would be a bug that only a
/// conforming client could see.
const protocol_field = "Sec-WebSocket-Protocol: ";

/// The accept value for the `Sec-WebSocket-Key` field value `key_text`.
///
/// RFC 6455 section 4.2.2 step 5, over SHA-1 as the section names it. **SHA-1
/// is not a choice and not a weakness here**: the input is a nonce the client
/// chose, the output proves only that this end read the client's field value and
/// not somebody else's, and the RFC fixes the digest. A caller looking for
/// collision resistance is looking for the wrong property.
///
/// **A value, not a slice.** The digest goes into a local and the base64 into a
/// local, so `key_text` may be a borrow of a buffer the caller is about to reuse
/// and nothing here outlives the call.
pub fn accept(key_text: []const u8) [accept_length]u8 {
    var hasher = Sha1.init(.{});
    hasher.update(key_text);
    hasher.update(websocket_guid);
    var digest: [Sha1.digest_length]u8 = undefined;
    hasher.final(&digest);
    var out: [accept_length]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&out, &digest);
    return out;
}

/// How many bytes `build` writes for a response that answers `version`.
///
/// A size a caller sizes a buffer from, and exact for every version and for
/// the no-sub-protocol case.
///
/// **It does not depend on the key**, so a caller may size one buffer before it
/// has read the request and get the right answer for any of them. The two
/// upstream version names are the same length, so `v1` and `v2` size alike and
/// a caller comparing them learns that from the return value rather than from a
/// table.
pub fn responseLen(version: ?Version) usize {
    // The sub-protocol field, its name and its own `crlf` are counted only when
    // the request named one: `build` leaves the field out for a null version,
    // and a size that counted an absent header would send a caller one buffer
    // length short of what it asks for and make `build` refuse a buffer it had
    // just sized correctly.
    const named: usize = if (version) |chosen|
        protocol_field.len + chosen.name().len + crlf.len
    else
        0;
    return status_line.len + accept_field.len + accept_length + crlf.len +
        named + crlf.len;
}

/// Writes the `101` response into `out` and hands back what it wrote.
///
/// `out` is the caller's buffer and is never grown. `error.BufferFull` is the
/// only refusal: there is nothing else about a response to get wrong, because
/// every field is either fixed text or the accept value, and the accept value
/// cannot fail.
///
/// `version` is null when the request named no sub-protocol, and the field is
/// then left out rather than named empty: an empty `Sec-WebSocket-Protocol` is a
/// different header from an absent one and a client reads the difference.
///
/// **What it borrows.** `key_text` is read and nothing in the result refers to
/// it, so a caller may reuse the request buffer as soon as this returns. The
/// slice handed back is `out[0..written]` — the same memory rather than a copy —
/// so it aliases `out` and is invalidated by whatever the caller writes next.
pub fn build(
    out: []u8,
    version: ?Version,
    key_text: []const u8,
) BuildError![]const u8 {
    if (out.len < responseLen(version)) return error.BufferFull;
    const accept_value = accept(key_text);
    var length: usize = 0;
    length += put(out, length, status_line);
    length += put(out, length, accept_field);
    length += put(out, length, &accept_value);
    length += put(out, length, crlf);
    if (version) |chosen| {
        length += put(out, length, protocol_field);
        length += put(out, length, chosen.name());
        length += put(out, length, crlf);
    }
    length += put(out, length, crlf);
    return out[0..length];
}

/// `text` at `at` in `out`, and how many bytes that was.
///
/// A copy rather than a `std.Io.Writer`, because nothing here is I/O: `out` is
/// the caller's buffer and `build` has already proved the whole response fits,
/// so a writer would be a second answer to a question this file has answered.
fn put(out: []u8, at: usize, text: []const u8) usize {
    @memcpy(out[at..][0..text.len], text);
    return text.len;
}

// --- tests

test "RFC 6455 section 1.3: the accept value, directly" {
    // The one pair of strings in the RFC that is quoted rather than derived. A
    // relay that concatenates the sixteen decoded bytes instead of the field
    // value produces a different digest and fails here first, which is why this
    // assertion sits above the whole-message one rather than inside it.
    const accept_value = accept(vectors.handshake_key);
    try std_testing.expectEqualSlices(u8, vectors.handshake_accept, &accept_value);
    try std_testing.expectEqual(@as(usize, 28), accept_value.len);
    try std_testing.expectEqual(@as(usize, 28), accept_length);

    // The GUID is the RFC's own, and it is the only part of the computation that
    // is not derived from the key, so a wrong constant shows here.
    try std_testing.expectEqualStrings("258EAFA5-E914-47DA-95CA-C5AB0DC85B11", websocket_guid);

    // A different key gives a different accept, which is what makes the value a
    // check on the handshake rather than a constant to copy.
    try std_testing.expect(
        !std.mem.eql(u8, vectors.handshake_accept, &accept("dGhlIHNhbXBsZSBub25jZR==")),
    );
    // And an empty key is hashed rather than refused: `accept` answers a value
    // and decides nothing, so the length rule stays where it is — in the parse.
    try std_testing.expectEqual(@as(usize, 28), accept("").len);
}

test "the response is a fixed size and refuses a short buffer" {
    // Every field of the response is fixed width except the version's own name,
    // so one size answers for either version and a caller may size a buffer
    // before it has read the request.
    var out: [256]u8 = undefined;
    for ([_]?Version{ null, .v1, .v2 }) |version| {
        const response = try build(&out, version, vectors.handshake_key);
        try std_testing.expectEqual(responseLen(version), response.len);
        try std_testing.expect(
            std.mem.indexOf(u8, response, "101 Switching Protocols\r\n") != null,
        );
    }

    // One byte short is refused and writes nothing, the same rule
    // `relay/ws_frame.zig` follows for a frame and for the same reason: one
    // scratch buffer serves a whole connection and it is never grown.
    var short: [64]u8 = undefined;
    @memset(&short, 0xee);
    try std_testing.expectError(error.BufferFull, build(&short, .v2, vectors.handshake_key));
    for (short) |byte| try std_testing.expectEqual(@as(u8, 0xee), byte);
    try std_testing.expectError(error.BufferFull, build(&.{}, .v1, vectors.handshake_key));

    // The buffer that is exactly big enough is not short, which is the other half
    // of the claim.
    const exact = try std_testing.allocator.alloc(u8, responseLen(.v2));
    defer std_testing.allocator.free(exact);
    try std_testing.expectEqual(
        responseLen(.v2),
        (try build(exact, .v2, vectors.handshake_key)).len,
    );
}
