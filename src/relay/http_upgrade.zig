//! The request half of the HTTP/1.1 upgrade that carries a relay connection:
//! `GET /relay` in, and a `Request` out.
//!
//! Upstream reaches a relay over `GET /relay` with `Upgrade: websocket` and
//! `Sec-Websocket-Protocol` (`iroh-relay/src/http_server.rs`, `http.rs`;
//! `iroh-relay/src/client.rs` dials the other way). `http_response.zig` writes
//! the `101` that answers one; this module reads it. It does not open a socket,
//! allocate, or read a clock — the TLS seam and the byte pump are Wave 2's other
//! slices, and everything a caller needs from this one is a struct of borrowed
//! slices.
//!
//! # The sub-protocol is `frame.negotiate`'s decision
//!
//! This module validates that `Sec-WebSocket-Version` is `13` and that the
//! sub-protocol field names a version this build speaks; it does not choose.
//! The choice is `relay/frame.zig`'s `negotiate`, which is a `max()` over the
//! tokens and not a first match — iroh advertises newest first (`http.rs:68`),
//! so first-match would pin every connection to the oldest version both ends
//! speak and keep `Health` alive forever. Calling that from here rather than
//! reimplementing it is why there is exactly one `max()` in the tree.
//!
//! **A bare LF is not a line ending.** RFC 7230 §3.5 defines one as CRLF, and a
//! parser that also accepted LF would disagree with every other parser about
//! where a header ends — which is the disagreement request smuggling is made of,
//! so `nextLine` refuses a bare LF rather than tolerating it.
//!
//! Nothing here is borrowed past the call: every slice in `Request` points into
//! the caller's request buffer, nothing is retained, and two threads may parse
//! two requests out of two buffers at once.

const std = @import("std");
const frame = @import("frame_types.zig");
const head = @import("http_head.zig");

const ProtocolVersion = frame.ProtocolVersion;
const std_testing = std.testing;

/// Every way an upgrade request can be refused.
///
/// **Every refusal is a named arm rather than a `Malformed` catch-all.** The
/// caller answers a client, and "your `Sec-WebSocket-Key` decoded to 12 bytes"
/// and "this build speaks neither sub-protocol you offered" are different
/// answers with different causes; one arm would force the caller to parse a
/// message to find out which happened. `http_head.Error`'s seven arms are the
/// same seven names, because the scanner's refusals are this parse's refusals.
pub const Error = error{
    /// No CRLF-terminated request line, so not even the method is known.
    MissingRequestLine,
    /// The request line is not three space-separated tokens.
    MalformedRequestLine,
    /// A method other than `GET`. RFC 6455 §4.1.
    MethodNotGet,
    /// A target other than `/relay`. RFC 6455 §4.1 and §4.2.1.
    WrongTarget,
    /// An HTTP version other than `1.1`.
    NotHttp11,
    /// A field line with no colon, or a head that never ends.
    MalformedHeader,
    /// A field the RFC gives one value of, sent twice. Choosing one of them is
    /// how a request-smuggling disagreement starts, so this is refused rather
    /// than resolved.
    DuplicateHeader,
    /// No `Host`. RFC 6455 §4.1 requires it; HTTP/1.1 requires it of every
    /// request, and a relay that answered one without it would be answering a
    /// request it cannot tell was aimed at it.
    MissingHost,
    /// No `Upgrade: websocket`, or a `Connection` without the `Upgrade` token.
    /// RFC 6455 §4.1.
    NotWebSocketUpgrade,
    /// No `Sec-WebSocket-Key`.
    MissingKey,
    /// A `Sec-WebSocket-Key` that is not base64 decoding to sixteen bytes.
    /// RFC 6455 §4.1: "a base64-encoded value that, when decoded, is 16 bytes in
    /// length".
    InvalidKey,
    /// No `Sec-WebSocket-Version`.
    MissingVersion,
    /// A `Sec-WebSocket-Version` other than `13`. RFC 6455 §4.1 fixes the
    /// version at 13 and RFC 6455 §4.4 says the server answers 426 with the
    /// versions it does speak, which is the caller's business and not this
    /// module's.
    UnsupportedVersion,
    /// No `Sec-WebSocket-Protocol`. There is no default: a relay connection
    /// with no version is a connection where a `Health` frame may or may not
    /// exist, and both ends have to be able to say which.
    MissingProtocol,
    /// A `Sec-WebSocket-Protocol` naming no version this build speaks.
    UnsupportedProtocol,
    /// A request over `max_request_bytes`.
    RequestTooLong,
};

/// The only WebSocket version RFC 6455 defines (§4.1, §4.2.1).
pub const websocket_version = 13;

/// `websocket_version` as it appears in the field, rendered rather than typed,
/// so the number and the string a peer sends cannot become two values.
const version_text = std.fmt.comptimePrint("{d}", .{websocket_version});

/// The most request bytes `parseRequest` reads.
///
/// RFC 6455 sets no limit and HTTP/1.1 sets none either, so this number is this
/// tree's policy rather than the standard's, and it is a policy about a
/// head of headers that is complete long before it: an iroh upgrade request is
/// under 400 bytes. A relay that refused the eighth kilobyte of an unterminated
/// head has refused nothing a real client sends, and refused it before reading
/// it.
pub const max_request_bytes = 8 * 1024;

/// A parsed upgrade request.
///
/// **Every slice borrows the caller's request buffer** and none refers to
/// anything else, so a `Request` is valid for exactly as long as the bytes it
/// was parsed from and parsing allocates nothing. `protocol` is a value, so it
/// outlives the buffer; the two slices do not.
pub const Request = struct {
    /// The `Host` field, borrowed. What the client believes it is talking to.
    host: []const u8,
    /// The `Sec-WebSocket-Key` field, borrowed. The input to `acceptKey`, and
    /// the only thing from the request a caller needs after the parse.
    key: []const u8,
    /// What `frame.negotiate` settled on, which is every frame's version for
    /// the life of the connection.
    protocol: ProtocolVersion,
};

/// Reads one upgrade request from the start of `bytes`.
///
/// `bytes` is a request head: a request line, field lines, and the blank line.
/// Anything after the blank line is a peer's body or a pipelined request and is
/// left alone, because this module answers a head and never a stream.
///
/// Every refusal is checked before the next field is read, and the whole parse
/// allocates nothing: a request either produces a `Request` of borrowed slices
/// or a named error and nothing in between.
pub fn parseRequest(bytes: []const u8) Error!Request {
    if (bytes.len > max_request_bytes) return error.RequestTooLong;
    var rest = bytes;
    // The scanner's refusals are this parse's refusals under the same names, so
    // they cross unchanged; writing them out twice here is what keeps `Error` an
    // explicit set a caller can match on without importing the scanner.
    try head.checkRequestLine(head.nextLine(&rest) orelse return error.MissingRequestLine);
    var fields = head.Fields{};
    while (head.nextLine(&rest) orelse return error.MalformedHeader) |line| {
        if (!try fields.read(line)) break;
    }

    // A `Host` of nothing but whitespace trims to nothing, and nothing is not a
    // host: the field was sent, but there is no authority in it to answer.
    const host = fields.host orelse return error.MissingHost;
    if (host.len == 0) return error.MissingHost;
    const upgrade = fields.upgrade orelse return error.NotWebSocketUpgrade;
    if (!std.ascii.eqlIgnoreCase(upgrade, "websocket")) return error.NotWebSocketUpgrade;
    const connection = fields.connection orelse return error.NotWebSocketUpgrade;
    if (!head.connectionCarriesUpgrade(connection)) return error.NotWebSocketUpgrade;
    const key = fields.key orelse return error.MissingKey;
    if (!keyDecodesToSixteenBytes(key)) return error.InvalidKey;
    const version = fields.version orelse return error.MissingVersion;
    if (!std.mem.eql(u8, version, version_text)) return error.UnsupportedVersion;
    const offered = fields.protocol orelse return error.MissingProtocol;
    return .{
        .host = host,
        .key = key,
        .protocol = frame.negotiate(offered) orelse return error.UnsupportedProtocol,
    };
}

/// Whether a `Sec-WebSocket-Key` is base64 decoding to sixteen bytes.
///
/// The decoded bytes are discarded: this module authenticates nothing and the
/// key's only use is `http_response.acceptKey`'s hash, so a decoder's output has
/// no further reader here. The length is checked against `calcSizeForSlice`
/// before decoding, so a key that would decode to more than the sixteen bytes
/// this stack buffer holds is refused rather than overflowing it.
fn keyDecodesToSixteenBytes(key: []const u8) bool {
    var decoded: [16]u8 = undefined;
    const size = std.base64.standard.Decoder.calcSizeForSlice(key) catch return false;
    if (size != decoded.len) return false;
    std.base64.standard.Decoder.decode(decoded[0..], key) catch return false;
    return true;
}

// ---------------------------------------------------------------------------
// Tests. The bytes come from RFC 6455 §1.3 and §4, and from an iroh upgrade
// request's shape; nothing here is claimed to be a capture of upstream, because
// upstream writes these bytes through a library.
// ---------------------------------------------------------------------------

test "golden: RFC 6455 §1.3's request head, parsed" {
    // §1.3's head, spelled with this tree's sub-protocol, so the parser is proved
    // against the one worked example the RFC prints rather than only against its
    // own writer.
    const request = try parseRequest(
        "GET /relay HTTP/1.1\r\n" ++
            "Host: server.example.com\r\n" ++
            "Upgrade: websocket\r\nConnection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
            "Sec-WebSocket-Version: 13\r\n" ++
            "Sec-WebSocket-Protocol: iroh-relay-v2\r\n\r\n",
    );
    try std_testing.expectEqualStrings("server.example.com", request.host);
    try std_testing.expectEqualStrings("dGhlIHNhbXBsZSBub25jZQ==", request.key);
    try std_testing.expectEqual(ProtocolVersion.v2, request.protocol);
}

test "negotiate: the largest version offered, not the first one" {
    // The half this module deliberately does not implement: `frame.negotiate`
    // is the `max()`, and the two orders below are the case the two differ on.
    const newest_first = try parseRequest(withProtocol("iroh-relay-v2, iroh-relay-v1"));
    try std_testing.expectEqual(ProtocolVersion.v2, newest_first.protocol);
    const oldest_first = try parseRequest(withProtocol("iroh-relay-v1, iroh-relay-v2"));
    try std_testing.expectEqual(ProtocolVersion.v2, oldest_first.protocol);
    // Unknown tokens are dropped rather than refused: a client may advertise
    // versions this build has never heard of, and the ones it did name are
    // still what both ends can speak.
    const mixed = try parseRequest(withProtocol("chat, iroh-relay-v1, iroh-relay-v9"));
    try std_testing.expectEqual(ProtocolVersion.v1, mixed.protocol);
    // A field of nothing this build speaks is a refusal, and not a default
    // version: answering a client that offered nothing in common would start a
    // connection on a version the client never agreed to.
    try std_testing.expectError(
        error.UnsupportedProtocol,
        parseRequest(withProtocol("chat")),
    );
    try std_testing.expectError(
        error.MissingProtocol,
        parseRequest(
            "GET /relay HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n" ++
                "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
                "Sec-WebSocket-Version: 13\r\n\r\n",
        ),
    );
}

test "headers: field names fold case, values are trimmed, Connection is a list" {
    // RFC 6455 spells `Sec-WebSocket-Version` and `Sec-Websocket-Protocol` with
    // different capitalisation in different sections, so folding case is what
    // makes one spelling of the rule rather than two.
    const lower = "GET /relay HTTP/1.1\r\n" ++
        "host: server.example.com\r\n" ++
        "upgrade: websocket\r\n" ++
        "connection: keep-alive, Upgrade\r\n" ++
        "sec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "sec-websocket-version: 13\r\n" ++
        "SEC-WEBSOCKET-PROTOCOL: iroh-relay-v1\r\n" ++
        "\r\n";
    const request = try parseRequest(lower);
    try std_testing.expectEqualStrings("server.example.com", request.host);
    try std_testing.expectEqual(ProtocolVersion.v1, request.protocol);
    // `Connection: keep-alive, Upgrade` carries the token in a comma list rather
    // than as its whole value, which `http_head`'s test proves directly; what
    // matters here is that a request written that way parses.
    // A `Host` of nothing but whitespace is empty, and an empty value is still a
    // value: `trim` removes the space rather than leaving it to be sent.
    try std_testing.expectError(error.MissingHost, parseRequest(
        "GET /relay HTTP/1.1\r\nHost:  \r\nUpgrade: websocket\r\n" ++
            "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
            "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: iroh-relay-v1\r\n\r\n",
    ));
}

test "error inventory: every declared arm is reached by concrete bytes" {
    // Checked against the type rather than trusted, so an arm added to `Error`
    // without a case here fails the build, and an arm listed that `Error` does
    // not declare fails the same way.
    const arms = [_]Error{
        error.MissingRequestLine,
        error.MalformedRequestLine,
        error.MethodNotGet,
        error.WrongTarget,
        error.NotHttp11,
        error.MalformedHeader,
        error.DuplicateHeader,
        error.MissingHost,
        error.NotWebSocketUpgrade,
        error.MissingKey,
        error.InvalidKey,
        error.MissingVersion,
        error.UnsupportedVersion,
        error.MissingProtocol,
        error.UnsupportedProtocol,
        error.RequestTooLong,
    };
    try std_testing.expectEqual(@typeInfo(Error).error_set.?.len, arms.len);

    // One case per arm, as a whole request rather than a fragment, so each fails
    // on the field it names. The head is composed from its parts because a case
    // that differs from a valid request in one field says which field.
    const line = "GET /relay HTTP/1.1\r\n";
    const valid_key = "dGhlIHNhbXBsZSBub25jZQ==";
    const host = "Host: h\r\n";
    const websocket = "Upgrade: websocket\r\nConnection: Upgrade\r\n";
    const key = "Sec-WebSocket-Key: " ++ valid_key ++ "\r\n";
    const version = "Sec-WebSocket-Version: 13\r\n";
    const protocol = "Sec-WebSocket-Protocol: iroh-relay-v1\r\n";
    const end = "\r\n";
    const cases = [_]struct { request: []const u8, expected: Error }{
        // A request line that is not `GET /relay HTTP/1.1`, in each of its ways.
        .{ .request = "", .expected = error.MissingRequestLine },
        .{ .request = "GET\r\n" ++ end, .expected = error.MalformedRequestLine },
        .{ .request = "PUT /relay HTTP/1.1\r\n" ++ end, .expected = error.MethodNotGet },
        .{ .request = "GET / HTTP/1.1\r\n" ++ end, .expected = error.WrongTarget },
        .{ .request = "GET /relay HTTP/1.0\r\n" ++ end, .expected = error.NotHttp11 },
        // A field line with no colon, a head that never ends, and a field the
        // RFC gives one value of sent twice.
        .{ .request = line ++ host ++ "nocolon\r\n" ++ end, .expected = error.MalformedHeader },
        .{ .request = line ++ host, .expected = error.MalformedHeader },
        .{ .request = line ++ "Host: a\r\nHOST: b\r\n" ++ websocket ++ key ++
            version ++ protocol ++ end, .expected = error.DuplicateHeader },
        // Three requests that never asked to be upgraded, which RFC 6455 §4.1
        // makes the same request: one this build cannot speak.
        .{ .request = line ++ host ++ "Connection: Upgrade\r\n" ++ key ++
            version ++ protocol ++ end, .expected = error.NotWebSocketUpgrade },
        .{ .request = line ++ host ++ "Upgrade: websocket\r\nConnection: close\r\n" ++
            key ++ version ++ protocol ++ end, .expected = error.NotWebSocketUpgrade },
        .{ .request = line ++ host ++ "Upgrade: h2c\r\nConnection: Upgrade\r\n" ++
            key ++ version ++ protocol ++ end, .expected = error.NotWebSocketUpgrade },
        // A `Host` of nothing but whitespace trims to nothing, and nothing is
        // not a host.
        .{ .request = line ++ "Host:  \r\n" ++ websocket ++ key ++
            version ++ protocol ++ end, .expected = error.MissingHost },
        // A key that is not sixteen bytes of base64: too short, and not base64 at
        // all. The decoder is reached before the length is believed, so a key
        // that would decode past the sixteen bytes on the stack is refused too.
        .{ .request = line ++ host ++ websocket ++
            "Sec-WebSocket-Key: dG9vLXNob3J0\r\n" ++ version ++
            protocol ++ end, .expected = error.InvalidKey },
        .{ .request = line ++ host ++ websocket ++
            "Sec-WebSocket-Key: not base64 at all!!\r\n" ++ version ++
            protocol ++ end, .expected = error.InvalidKey },
        // A version other than 13, and a sub-protocol naming nothing this build
        // speaks.
        .{ .request = line ++ host ++ websocket ++ key ++
            "Sec-WebSocket-Version: 8\r\n" ++ protocol ++
            end, .expected = error.UnsupportedVersion },
        .{ .request = line ++ host ++ websocket ++ key ++ version ++
            "Sec-WebSocket-Protocol: chat\r\n" ++ end, .expected = error.UnsupportedProtocol },
    };
    for (cases) |case| try std_testing.expectError(case.expected, parseRequest(case.request));

    // The four refusals that are about a field being absent, read off one body
    // so the head is written once rather than four times.
    try std_testing.expectError(error.MissingHost, parseRequest(withFields(.{
        .host = null,
        .key = null,
        .version = null,
        .protocol = null,
    })));
    try std_testing.expectError(error.MissingKey, parseRequest(withFields(.{
        .host = "h",
        .key = null,
        .version = null,
        .protocol = null,
    })));
    try std_testing.expectError(error.MissingVersion, parseRequest(withFields(.{
        .host = "h",
        .key = valid_key,
        .version = null,
        .protocol = null,
    })));
    try std_testing.expectError(error.MissingProtocol, parseRequest(withFields(.{
        .host = "h",
        .key = valid_key,
        .version = "13",
        .protocol = null,
    })));

    // A request over the bound is refused before a byte of it is read.
    try std_testing.expectError(error.RequestTooLong, parseRequest("x" ** (max_request_bytes + 1)));
}

/// A complete, valid upgrade head with its sub-protocol field replaced, for the
/// negotiation cases. Every other field is one a real request carries.
fn withProtocol(protocol: []const u8) []const u8 {
    return "GET /relay HTTP/1.1\r\nHost: server.example.com\r\n" ++
        "Upgrade: websocket\r\nConnection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "Sec-WebSocket-Protocol: " ++ protocol ++ "\r\n\r\n";
}

/// The four fields the refusals are about.
const Wanted = struct {
    host: ?[]const u8,
    key: ?[]const u8,
    version: ?[]const u8,
    protocol: ?[]const u8,
};

/// The four fields a case varies, each set or absent; every other field of a
/// real upgrade request is written here so the refusal a case reaches is the
/// one it names.
fn withFields(fields: Wanted) []const u8 {
    return "GET /relay HTTP/1.1\r\n" ++ field("Host", fields.host) ++
        "Upgrade: websocket\r\nConnection: Upgrade\r\n" ++
        field("Sec-WebSocket-Key", fields.key) ++
        field("Sec-WebSocket-Version", fields.version) ++
        field("Sec-WebSocket-Protocol", fields.protocol) ++ "\r\n";
}

fn field(name: []const u8, value: ?[]const u8) []const u8 {
    const text = value orelse return "";
    return name ++ ": " ++ text ++ "\r\n";
}
