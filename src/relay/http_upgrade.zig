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
//! below. **No bytes from an iroh relay's own `101` exist to pin against**,
//! because upstream answers the upgrade through a library that writes the
//! response line itself; so what these tests establish is conformance to RFC 6455
//! and to RFC 9110's grammar, and interoperability with an iroh relay is a claim
//! this tree does not make.
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

/// The four fields every request these tests build carries, so that one case
/// varying field does not have to restate the other three.
const base_fields =
    "Upgrade: websocket\r\n" ++
    "Connection: Upgrade\r\n" ++
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
    "Sec-WebSocket-Version: 13\r\n";

/// A well-formed request whose fields are `fields` and nothing else.
///
/// **Comptime, because the concatenation would otherwise be a temporary.** `++`
/// on runtime values builds an anonymous buffer, and a request the test keeps
/// past the call that built it must not name one that is gone. A `comptime`
/// parameter makes every request here a slice of the binary's own text and turns
/// a runtime call site into a compile error rather than a dangling one.
fn request(comptime fields: []const u8) []const u8 {
    return "GET /relay HTTP/1.1\r\n" ++ fields ++ "\r\n";
}

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

test "the request rules, each refused by name" {
    // Every arm of `Error` this parse can reach, one request each, in the order
    // `parse` checks them. A request that breaks two is answered by the earlier
    // one, and the last case says so.
    try std_testing.expectError(error.MalformedRequestLine, parse("GET /relay\r\n\r\n"));
    try std_testing.expectError(error.MalformedRequestLine, parse("GET\r\n\r\n"));
    try std_testing.expectError(error.MethodNotGet, parse("POST /relay HTTP/1.1\r\n\r\n"));
    try std_testing.expectError(error.PathNotFound, parse("GET /elsewhere HTTP/1.1\r\n\r\n"));
    try std_testing.expectError(error.BadHttpVersion, parse("GET /relay HTTP/1.0\r\n\r\n"));
    try std_testing.expectError(error.MalformedField, parse(request("nocolon\r\n")));
    try std_testing.expectError(error.MalformedField, parse(request("bad name: value\r\n")));
    try std_testing.expectError(error.MalformedField, parse(request(": value\r\n")));

    // The method, the target and the version are case-sensitive even though
    // field names are not.
    try std_testing.expectError(error.MethodNotGet, parse("get /relay HTTP/1.1\r\n\r\n"));
    try std_testing.expectEqual(@as(?Version, null), (try parse(request(
        "upgrade: WebSocket\r\n" ++
            "cOnNeCtIoN: UpGrAdE\r\n" ++
            "SEC-WEBSOCKET-KEY: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
            "sec-websocket-version: 13\r\n",
    ))).version);

    // The upgrade tokens fold, which RFC 6455 section 4.2.1 says explicitly, and
    // both may be a comma-separated list with the token anywhere in it.
    try std_testing.expectError(
        error.UpgradeNotWebsocket,
        parse(request("Upgrade: h2c\r\nConnection: Upgrade\r\n")),
    );
    try std_testing.expectError(
        error.ConnectionNotUpgrade,
        parse(request("Upgrade: websocket\r\nConnection: keep-alive\r\n")),
    );
    try std_testing.expectEqual(@as(?Version, null), (try parse(request(
        "Upgrade: h2c, WebSocket\r\nConnection: keep-alive, UpGrAdE\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
            "Sec-WebSocket-Version: 13\r\n",
    ))).version);

    // The version token is exactly `13`, not a number that parses as one.
    // `inline`, because `request` takes its fields at comptime: a runtime token
    // concatenated into the request would need a buffer this loop does not have,
    // and every token here is a literal anyway.
    inline for ([_][]const u8{ "8", "14", "v13" }) |token| {
        try std_testing.expectError(
            error.BadWebSocketVersion,
            parse(request(
                "Upgrade: websocket\r\nConnection: Upgrade\r\n" ++
                    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
                    "Sec-WebSocket-Version: " ++ token ++ "\r\n",
            )),
        );
    }
    // A token padded with spaces is the same token: RFC 9110 section 5.6.3 puts
    // optional whitespace around a field value and it is not part of the value,
    // so `parse` trims before it compares and these two are answered.
    inline for ([_][]const u8{ " 13", "13 " }) |token| {
        try std_testing.expectEqual(
            @as(?Version, null),
            (try parse(request(
                "Upgrade: websocket\r\nConnection: Upgrade\r\n" ++
                    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
                    "Sec-WebSocket-Version: " ++ token ++ "\r\n",
            ))).version,
        );
    }

    // The key is base64 of exactly sixteen bytes, checked on the decoded length
    // and not on the text's: twelve bytes is a shorter valid base64, seventeen is
    // a longer one, and neither is sixteen.
    const bad_keys = [_][]const u8{
        "dGhlIHNhbXBsZQ==",
        "dG9vIGxvbmdrZXIgc3RyaW5n",
        "not base64!!",
        "",
    };
    // `inline` for the same reason the version tokens above are: `request` takes
    // its fields at comptime, and every key here is a literal.
    inline for (bad_keys) |key| {
        try std_testing.expectError(
            error.BadWebSocketKey,
            parse(request(
                "Upgrade: websocket\r\nConnection: Upgrade\r\n" ++
                    "Sec-WebSocket-Key: " ++ key ++ "\r\n" ++
                    "Sec-WebSocket-Version: 13\r\n",
            )),
        );
    }

    // A field this relay reads as a singleton may not repeat, and its absence is
    // a malformed request rather than a default.
    try std_testing.expectError(
        error.DuplicateField,
        parse(request(
            "Upgrade: websocket\r\nConnection: Upgrade\r\n" ++
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
                "Sec-WebSocket-Version: 13\r\n",
        )),
    );
    try std_testing.expectError(
        error.DuplicateField,
        parse(request(base_fields ++ "Sec-WebSocket-Protocol: iroh-relay-v1\r\n" ++
            "Sec-WebSocket-Protocol: iroh-relay-v2\r\n")),
    );
    try std_testing.expectError(
        error.MalformedField,
        parse(request("Upgrade: websocket\r\nConnection: Upgrade\r\n")),
    );

    // The bounds. `max_fields` and `max_field_length` are numbers this relay
    // chose, so these refusals are of a policy rather than of the RFC.
    try std_testing.expectError(error.FieldTooLong, parse(request(
        "X: " ++ "y" ** (max_field_length + 1) ++ "\r\n",
    )));
    try std_testing.expectError(error.HeaderTooLong, parse(
        "GET /relay HTTP/1.1\r\nX: " ++ "y" ** (max_header_length + 1) ++ "\r\n\r\n",
    ));
    // `max_fields` counts the whole block, and `base_fields` is four of them, so
    // the bound is `max_fields` less four. Field names need not be distinct for
    // this to be a bound on the count, so one repeated line is the whole of the
    // over case and one fewer is the case just under it.
    const filler_line = "X-Filler: v\r\n";
    const base_field_count = 4;
    try std_testing.expectError(error.TooManyFields, parse(
        "GET /relay HTTP/1.1\r\n" ++
            (filler_line ** (max_fields - base_field_count + 1)) ++
            base_fields ++ "\r\n",
    ));
    try std_testing.expectEqual(@as(?Version, null), (try parse(
        "GET /relay HTTP/1.1\r\n" ++
            (filler_line ** (max_fields - base_field_count)) ++
            base_fields ++ "\r\n",
    )).version);

    // A block with no blank line has not finished, which is `error.UnexpectedEnd`
    // rather than a parse of whatever was there.
    try std_testing.expectError(error.UnexpectedEnd, parse(""));
    try std_testing.expectError(error.UnexpectedEnd, parse("GET /relay HTTP/1.1\r\n"));
    try std_testing.expectError(
        error.UnexpectedEnd,
        parse("GET /relay HTTP/1.1\r\nUpgrade: websocket\r\n"),
    );

    // And the order: a request that breaks the request line and the upgrade
    // checks is answered by the request line, and one that breaks the upgrade
    // check and the key rule is answered by the upgrade check.
    try std_testing.expectError(
        error.MethodNotGet,
        parse("POST /relay HTTP/1.1\r\nUpgrade: h2c\r\n\r\n"),
    );
    try std_testing.expectError(
        error.UpgradeNotWebsocket,
        parse(request("Upgrade: h2c\r\nSec-WebSocket-Key: nope\r\n")),
    );
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
