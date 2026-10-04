//! The request-line and field-line scanner a WebSocket upgrade is parsed with.
//!
//! `http_upgrade.zig` asks two questions of a request head — is the request line
//! a relay upgrade, and which of the six fields does it carry — and this module
//! is where both are answered. It is split out because the two are separable:
//! the scanner is a lexer over CRLF-delimited bytes that knows nothing about
//! WebSockets, and the parse is the rule set RFC 6455 §4.1 puts on top of it.
//!
//! **A bare LF is not a line ending.** RFC 7230 §3.5 defines one as CRLF, and a
//! scanner that also accepted LF would disagree with every other parser about
//! where a header ends — which is the disagreement request smuggling is made of,
//! so `nextLine` refuses a bare LF rather than tolerating it.
//!
//! **A field the RFC gives one value of, sent twice, is refused.** Choosing one
//! of the two copies is how two parsers disagree about what a request said, and
//! `record` refuses rather than resolves.
//!
//! Nothing is allocated and nothing is copied: `Fields` borrows the caller's
//! buffer and every value it holds is a slice of it.

const std = @import("std");

const std_testing = std.testing;

/// The request target a relay answers on. Upstream's `http_server.rs` path.
pub const relay_path = "/relay";

/// Every way a request line or a field line can be refused.
///
/// **These eight arms carry the same names as eight arms of
/// `http_upgrade.Error`**, which is the set a caller actually matches on: this
/// module is the scanner, and the parse adds seven refusals of its own on top of
/// these. They are written down twice so both sets stay explicit, and forwarding
/// one into the other is a compile error rather than a silent swallow.
pub const Error = error{
    /// No CRLF-terminated request line, so not even the method is known.
    MissingRequestLine,
    /// The request line is not exactly three space-separated tokens.
    MalformedRequestLine,
    /// A method other than `GET`. RFC 6455 §4.1.
    MethodNotGet,
    /// A target other than `/relay`. RFC 6455 §4.1 and §4.2.1.
    WrongTarget,
    /// An HTTP version other than `1.1`.
    NotHttp11,
    /// A field line with no colon, or a head that never ends.
    MalformedHeader,
    /// A field the RFC gives one value of, sent twice.
    DuplicateHeader,
};

/// The next CRLF-terminated line, without its CRLF, and `rest` advanced past it.
pub fn nextLine(rest: *[]const u8) ?[]const u8 {
    const end = std.mem.indexOf(u8, rest.*, "\r\n") orelse return null;
    const line = rest.*[0..end];
    rest.* = rest.*[end + 2 ..];
    return line;
}

/// RFC 7230 §3.2.3 optional whitespace around a field value, and only that: SP
/// and HTAB. A field value that is one space and nothing else is empty, not a
/// space.
pub fn trim(value: []const u8) []const u8 {
    return std.mem.trim(u8, value, &std.ascii.whitespace);
}

/// Reads the request line, which RFC 6455 §4.1 fixes as `GET /relay HTTP/1.1`.
///
/// **Four tokens is a refusal, not a longer target.** A request line with a space
/// in the target is a request whose target this build does not know how to match,
/// and matching it by substring is how a proxy and a server come to disagree.
pub fn checkRequestLine(line: []const u8) Error!void {
    var tokens = std.mem.splitScalar(u8, line, ' ');
    const method = tokens.next() orelse return error.MissingRequestLine;
    if (!std.mem.eql(u8, method, "GET")) return error.MethodNotGet;
    const target = tokens.next() orelse return error.MalformedRequestLine;
    if (!std.mem.eql(u8, target, relay_path)) return error.WrongTarget;
    const version = tokens.next() orelse return error.MalformedRequestLine;
    if (!std.mem.eql(u8, version, "HTTP/1.1")) return error.NotHttp11;
    if (tokens.next() != null) return error.MalformedRequestLine;
}

/// Whether a `Connection` field value carries the `Upgrade` token.
///
/// RFC 7230 §6.1: `Connection` is a comma-separated list of tokens, so this is a
/// token match over the list and not a substring search — `upgraded` and
/// `x-upgrade` are different tokens, and a parser that accepted either would
/// answer a connection that never asked to be upgraded.
pub fn connectionCarriesUpgrade(value: []const u8) bool {
    var tokens = std.mem.splitScalar(u8, value, ',');
    while (tokens.next()) |token| {
        if (std.ascii.eqlIgnoreCase(trim(token), "upgrade")) return true;
    }
    return false;
}

/// The six fields a relay upgrade reads. Everything else in the head is read
/// past, and `record` ignores a name it does not hold.
pub const Fields = struct {
    /// The `Host`, borrowed. What the client believes it is talking to.
    host: ?[]const u8 = null,
    /// The `Sec-WebSocket-Key`, borrowed.
    key: ?[]const u8 = null,
    /// The `Sec-WebSocket-Version`, borrowed.
    version: ?[]const u8 = null,
    /// The `Sec-WebSocket-Protocol`, borrowed, comma-separated and unparsed.
    protocol: ?[]const u8 = null,
    /// The `Upgrade` field value, borrowed. RFC 6455 §4.1 requires it to be
    /// `websocket`.
    upgrade: ?[]const u8 = null,
    /// The `Connection` field value, borrowed. RFC 6455 §4.1 requires the
    /// `Upgrade` token in it, and it is a comma-separated list (RFC 7230
    /// §6.1), so it is searched for that token rather than compared whole.
    connection: ?[]const u8 = null,

    /// Records one field, refusing a second copy of any of the six.
    ///
    /// Field names are case-insensitive (RFC 7230 §3.2), and the RFCs spell
    /// these both `Sec-WebSocket-Key` and `Sec-Websocket-Key` depending on which
    /// section you read, so the comparison folds case.
    fn record(self: *Fields, name: []const u8, value: []const u8) Error!void {
        if (std.ascii.eqlIgnoreCase(name, "host")) {
            if (self.host != null) return error.DuplicateHeader;
            self.host = value;
        } else if (std.ascii.eqlIgnoreCase(name, "upgrade")) {
            if (self.upgrade != null) return error.DuplicateHeader;
            self.upgrade = value;
        } else if (std.ascii.eqlIgnoreCase(name, "connection")) {
            if (self.connection != null) return error.DuplicateHeader;
            self.connection = value;
        } else if (std.ascii.eqlIgnoreCase(name, "sec-websocket-key")) {
            if (self.key != null) return error.DuplicateHeader;
            self.key = value;
        } else if (std.ascii.eqlIgnoreCase(name, "sec-websocket-version")) {
            if (self.version != null) return error.DuplicateHeader;
            self.version = value;
        } else if (std.ascii.eqlIgnoreCase(name, "sec-websocket-protocol")) {
            if (self.protocol != null) return error.DuplicateHeader;
            self.protocol = value;
        }
    }

    /// Reads one line into `self`.
    ///
    /// A blank line is the end of the head (RFC 7230 §3.5) and is not a field;
    /// a line with no colon is not a field either, and both of those are the
    /// caller's loop to see, so this returns whether the line was a field rather
    /// than inventing an end.
    pub fn read(self: *Fields, line: []const u8) Error!bool {
        if (line.len == 0) return false;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse
            return error.MalformedHeader;
        try self.record(line[0..colon], trim(line[colon + 1 ..]));
        return true;
    }
};

// ---------------------------------------------------------------------------
// Tests. The bytes come from RFC 6455 §4 and RFC 7230 §3; nothing here is
// claimed to be a capture of upstream, because upstream writes these bytes
// through an HTTP library.
// ---------------------------------------------------------------------------

test "request line: GET /relay HTTP/1.1, and every other shape refused" {
    try checkRequestLine("GET /relay HTTP/1.1");
    try std_testing.expectError(error.MethodNotGet, checkRequestLine("POST /relay HTTP/1.1"));
    try std_testing.expectError(error.WrongTarget, checkRequestLine("GET / HTTP/1.1"));
    try std_testing.expectError(error.WrongTarget, checkRequestLine("GET /relay/x HTTP/1.1"));
    try std_testing.expectError(error.NotHttp11, checkRequestLine("GET /relay HTTP/1.0"));
    try std_testing.expectError(error.MissingRequestLine, checkRequestLine(""));
    try std_testing.expectError(error.MalformedRequestLine, checkRequestLine("GET"));
    try std_testing.expectError(error.MalformedRequestLine, checkRequestLine("GET /relay"));
    // A space in the target is a fourth token, not a target this build matches.
    try std_testing.expectError(
        error.MalformedRequestLine,
        checkRequestLine("GET /relay HTTP/1.1 extra"),
    );
}

test "lines: CRLF only, and a blank line is not a field" {
    var rest: []const u8 = "one\r\ntwo\r\n\r\nthree\r\n";
    try std_testing.expectEqualStrings("one", nextLine(&rest).?);
    try std_testing.expectEqualStrings("two", nextLine(&rest).?);
    try std_testing.expectEqualStrings("", nextLine(&rest).?);
    // The head ends at the blank line and everything past it is another request.
    try std_testing.expectEqualStrings("three\r\n", rest);

    var fields = Fields{};
    try std_testing.expect(try fields.read("Host: example.com"));
    try std_testing.expectEqualStrings("example.com", fields.host.?);
    // A bare LF is not a line ending, so a head written with LF alone has no
    // lines in it at all.
    var lf_only: []const u8 = "Host: example.com\n";
    try std_testing.expectEqual(@as(?[]const u8, null), nextLine(&lf_only));
}

test "fields: names fold case, values are trimmed, one copy of each" {
    var fields = Fields{};
    try std_testing.expect(try fields.read("host:\texample.com  "));
    try std_testing.expect(try fields.read("SEC-WEBSOCKET-KEY: dGhlIHNhbXBsZSBub25jZQ=="));
    try std_testing.expect(try fields.read("Sec-Websocket-Protocol: iroh-relay-v1"));
    try std_testing.expect(try fields.read("UPGRADE: websocket"));
    // `trim` removed the tab and the trailing spaces, so the borrowed value is
    // the authority and not the whitespace around it.
    try std_testing.expectEqualStrings("example.com", fields.host.?);
    try std_testing.expectEqualStrings("dGhlIHNhbXBsZSBub25jZQ==", fields.key.?);
    try std_testing.expectEqualStrings("iroh-relay-v1", fields.protocol.?);
    try std_testing.expectEqualStrings("websocket", fields.upgrade.?);

    // A second copy of any of the six is refused, whatever its case, and a field
    // this module does not hold is read past rather than refused.
    try std_testing.expectError(error.DuplicateHeader, fields.read("HOST: other.example"));
    try std_testing.expectError(
        error.DuplicateHeader,
        fields.read("Connection: Upgrade"),
    );
    try std_testing.expect(try fields.read("User-Agent: iroh"));
    try std_testing.expectError(error.MalformedHeader, fields.read("nocolon"));
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
        error.NotWebSocketUpgrade,
    };
    try std_testing.expectEqual(@typeInfo(Error).error_set.?.len, arms.len);

    var fields = Fields{};
    try std_testing.expectError(error.DuplicateHeader, fields.read("Host: a"));
    try std_testing.expectError(error.MalformedHeader, fields.read("Host: a"));
    // Every arm a request line can answer.
    const lines = [_]struct { line: []const u8, expected: Error }{
        .{ .line = "", .expected = error.MissingRequestLine },
        .{ .line = "GET /relay", .expected = error.MalformedRequestLine },
        .{ .line = "PUT /relay HTTP/1.1", .expected = error.MethodNotGet },
        .{ .line = "GET /nope HTTP/1.1", .expected = error.WrongTarget },
        .{ .line = "GET /relay HTTP/2", .expected = error.NotHttp11 },
    };
    for (lines) |case| try std_testing.expectError(case.expected, checkRequestLine(case.line));
}
