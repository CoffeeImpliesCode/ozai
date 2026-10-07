//! The RFC 6455 opening handshake: the request this relay accepts and the
//! response it answers with.
//!
//! This file is the facade every caller imports. It holds no logic of its own
//! and re-exports three siblings, which together are the whole handshake:
//!
//! - `http_upgrade_types.zig` — the vocabulary: `Request`, the error set, the
//!   path, the limits and the version token.
//! - `http_request.zig` — the `GET` parse, with the case folded exactly where
//!   the RFCs fold it.
//! - `http_response.zig` — the accept computation and the `101` build.
//!
//! # What is verified here and what is not
//!
//! RFC 6455 section 1.3 prints one complete request, one complete response and
//! the one pair of strings a handshake is checked by, and those are the goldens
//! the module's tests are pinned to. **No bytes from an iroh relay's own `101`
//! exist to pin against**, because upstream answers the upgrade through a
//! library that writes the response line itself; so what these tests establish
//! is conformance to RFC 6455 and to RFC 9110's grammar, and interoperability
//! with an iroh relay is a claim this tree does not make.
//!
//! Each half is checked beside the code that does it: `http_request.zig` holds
//! the rules a request is refused by, `http_response.zig` the accept value and
//! the size of the `101`. **The two tests left here are the boundary ones** —
//! the RFC's printed request answered with the RFC's printed response, and one
//! version settled by the parse and named by the build — because each crosses
//! both halves, and neither half on its own can say the two agree.
//!
//! # What is not here
//!
//! The relay's `iroh-relay-key-material-auth` header. Upstream postcard-encodes
//! it into a base64url field on the request (`relay/client.zig`'s
//! `KeyMaterialAuth` says so), and `relay/client.zig` holds the credential with
//! a note that the header encoding is the HTTP seam's business. **That encoding
//! is still missing here**, for the reason it was missing there: upstream
//! publishes no captured bytes of one, and an encoder with nothing to pin to
//! would be an interop claim with nothing behind it. A request carrying the
//! field is parsed and the field ignored rather than refused, which is what a
//! relay that does not implement a credential does.
//!
//! Nothing here opens a socket, reads a clock, or allocates.

const http_request = @import("http_request.zig");
const http_response = @import("http_response.zig");
const http_upgrade_types = @import("http_upgrade_types.zig");
const vectors = @import("ws_frame_vectors.zig");

// The vocabulary.

pub const Error = http_upgrade_types.Error;
pub const Request = http_upgrade_types.Request;
pub const Version = http_upgrade_types.Version;
pub const relay_path = http_upgrade_types.relay_path;
pub const http_version = http_upgrade_types.http_version;
pub const websocket_version_token = http_upgrade_types.websocket_version_token;
pub const websocket_guid = http_upgrade_types.websocket_guid;
pub const key_length = http_upgrade_types.key_length;
pub const accept_length = http_upgrade_types.accept_length;
pub const max_fields = http_upgrade_types.max_fields;
pub const max_field_length = http_upgrade_types.max_field_length;
pub const max_header_length = http_upgrade_types.max_header_length;

// The two halves.

pub const parse = http_request.parse;
pub const accept = http_response.accept;
pub const responseLen = http_response.responseLen;
pub const build = http_response.build;

// --- tests
const std = @import("std");
const std_testing = std.testing;

// The request fixtures live with the parse they build requests for; aliased here
// so the two boundary tests below read the way they always have.
const base_fields = http_request.base_fields;
const request = http_request.request;

// **Stays here:** it spans `http_request.parse` and `http_response.build`, and a
// test that says the two halves agree belongs to neither half on its own.
test "RFC 6455 section 1.3: the request and the response, whole" {
    // The section prints both messages. Parsing the printed request and building
    // the printed response is the round trip that says the two halves agree,
    // rather than each being right about a case it chose for itself. The printed
    // request carries no `Sec-WebSocket-Protocol`, so the printed response must
    // carry none either — RFC 6455 section 4.2.2 step 10 makes a server that
    // names one anyway fail a conforming client.
    const request_text =
        "GET /relay HTTP/1.1\r\n" ++
        "Host: server.example.com\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "\r\n";
    const expected_response =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "\r\n";

    const parsed = try parse(request_text);
    try std_testing.expectEqualStrings(vectors.handshake_key, parsed.key_text);
    try std_testing.expectEqual(@as(usize, request_text.len), parsed.header_length);
    // The sixteen bytes the key decodes to are "the sample nonce", and the
    // response hashes the text rather than them.
    try std_testing.expectEqualSlices(u8, "the sample nonce", &parsed.key);
    try std_testing.expectEqual(@as(?Version, null), parsed.version);

    var out: [256]u8 = undefined;
    const response = try build(&out, parsed.version, parsed.key_text);
    try std_testing.expectEqualStrings(expected_response, response);
    try std_testing.expectEqual(responseLen(null), response.len);

    // The same handshake with the field named, so the difference between a
    // response that names a sub-protocol and one that does not is a value rather
    // than an assumption.
    const named = try parse(request(base_fields ++ "Sec-WebSocket-Protocol: iroh-relay-v2\r\n"));
    const named_response = try build(&out, named.version, named.key_text);
    try std_testing.expectEqualSlices(
        u8,
        expected_response[0 .. expected_response.len - 2],
        named_response[0 .. expected_response.len - 2],
    );
    try std_testing.expectEqualStrings(
        "Sec-WebSocket-Protocol: iroh-relay-v2\r\n\r\n",
        named_response[expected_response.len - 2 ..],
    );
    try std_testing.expectEqual(responseLen(.v2), named_response.len);
}

// **Stays here:** `parse` settles the version and `build` names it, so the claim is
// that one decision survives the crossing rather than that either half made it.
test "negotiation: the largest version both ends speak, in either token order" {
    // RFC 6455 section 4.2.1 step 9 and `relay/frame.zig`'s `negotiate` are one
    // rule: the server answers with the largest version it can speak. iroh
    // advertises newest first, so a first-match would pin every connection to the
    // oldest version both ends speak and keep `Health` alive forever. Two token
    // orders, one answer, and only a `max()` gives it twice.
    const newest = request(
        base_fields ++ "Sec-WebSocket-Protocol: iroh-relay-v2, iroh-relay-v1\r\n",
    );
    const oldest = request(
        base_fields ++ "Sec-WebSocket-Protocol: iroh-relay-v1, iroh-relay-v2\r\n",
    );
    try std_testing.expectEqual(@as(?Version, .v2), (try parse(newest)).version);
    try std_testing.expectEqual(@as(?Version, .v2), (try parse(oldest)).version);

    // One version on its own, and a token this build does not speak dropped
    // rather than failed on, which is upstream's `filter_map` and the reason a
    // client may advertise a version a particular relay has never heard of.
    try std_testing.expectEqual(
        @as(?Version, .v1),
        (try parse(request(base_fields ++ "Sec-WebSocket-Protocol: iroh-relay-v1\r\n"))).version,
    );
    try std_testing.expectEqual(
        @as(?Version, .v2),
        (try parse(request(
            base_fields ++ "Sec-WebSocket-Protocol:  iroh-relay-v1 ,\troh-not, iroh-relay-v2 \r\n",
        ))).version,
    );

    // Nothing this build speaks is `error.NoSupportedProtocol`, and the relay
    // closes rather than choosing: the version it picked would be one the client
    // never offered.
    try std_testing.expectError(
        error.NoSupportedProtocol,
        parse(request(base_fields ++ "Sec-WebSocket-Protocol: iroh-relay-v3\r\n")),
    );
    try std_testing.expectError(
        error.NoSupportedProtocol,
        parse(request(base_fields ++ "Sec-WebSocket-Protocol: iroh-relay\r\n")),
    );

    // The response names the version the request settled on, so the two are one
    // decision and not two, and it is omitted when the request named none.
    var out: [256]u8 = undefined;
    const parsed = try parse(newest);
    const response = try build(&out, parsed.version, parsed.key_text);
    try std_testing.expect(
        std.mem.endsWith(u8, response, "Sec-WebSocket-Protocol: iroh-relay-v2\r\n\r\n"),
    );
    // The two upstream names are the same length, so a caller comparing the two
    // sizes learns that from the value rather than from a table.
    try std_testing.expectEqual(responseLen(.v1), responseLen(.v2));
    try std_testing.expect(responseLen(.v2) > responseLen(null));
}
