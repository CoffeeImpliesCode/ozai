//! The `GET` request that opens a relay WebSocket, parsed out of bytes.
//!
//! The vocabulary is `relay/http_upgrade_types.zig` and the answer is
//! `relay/http_response.zig`. This file walks a header block, folds the case the
//! RFC folds and only that, and refuses a request in the order RFC 6455
//! section 4.2.1 gives the steps.
//!
//! # What is borrowed and what is copied out
//!
//! `Request.key_text` is a slice of the buffer `parse` was handed and
//! `Request.key` is the sixteen bytes it decodes to, copied out. The split is
//! not tidiness: **the response hashes the field value and not what it decodes
//! to** (RFC 6455 section 4.2.2 step 5), so a parse that kept only the decoded
//! bytes could not answer, and one that kept only the text could not check the
//! length rule. `Request.header_length` says how much of the buffer the block
//! took, so a caller can prove nothing follows the handshake.
//!
//! # The loop has a bound and the walk is total
//!
//! Every loop here is over a slice that shrinks and every one has a ceiling:
//! `max_fields` fields, `max_field_length` bytes per line, `max_header_length`
//! bytes of block. A caller can hand this a stream of a million blank lines and
//! it answers rather than spinning.

const std = @import("std");
const frame_types = @import("frame_types.zig");
const http_upgrade_types = @import("http_upgrade_types.zig");

const std_testing = std.testing;

const Error = http_upgrade_types.Error;
const Request = http_upgrade_types.Request;
const Version = http_upgrade_types.Version;
const crlf = "\r\n";
const key_length = http_upgrade_types.key_length;
const max_field_length = http_upgrade_types.max_field_length;
const max_fields = http_upgrade_types.max_fields;
const max_header_length = http_upgrade_types.max_header_length;

/// One field as the block spells it: the name as written and the value trimmed of
/// optional whitespace, both borrowed from the request buffer.
const Field = struct {
    name: []const u8,
    value: []const u8,
};

/// What a lookup of one field name found, and how many times.
///
/// The count is not decoration: RFC 9110 section 5.3 lets a field repeat and be
/// combined, so a caller reading a value that means one thing has to know
/// whether it came more than once.
const Found = struct {
    value: ?[]const u8 = null,
    count: usize = 0,
};

/// The fields of one header block, in a table whose length is its own bound.
const Fields = struct {
    table: [max_fields]Field = undefined,
    len: usize = 0,

    /// Every occurrence of `name`, folded, and how many there were.
    fn occurrences(self: Fields, name: []const u8) Found {
        var found: Found = .{};
        for (self.table[0..self.len]) |field| {
            if (!std.ascii.eqlIgnoreCase(field.name, name)) continue;
            if (found.count == 0) found.value = field.value;
            found.count += 1;
        }
        return found;
    }

    /// Whether any occurrence of `name` carries `token` in any of its
    /// comma-separated values, folded. This is the shape `Upgrade` and
    /// `Connection` have, and both may legally repeat.
    fn anyHas(self: Fields, name: []const u8, token: []const u8) bool {
        for (self.table[0..self.len]) |field| {
            if (!std.ascii.eqlIgnoreCase(field.name, name)) continue;
            var rest = field.value;
            while (true) {
                const comma = std.mem.findScalar(u8, rest, ',');
                const part = if (comma) |at| rest[0..at] else rest;
                if (std.ascii.eqlIgnoreCase(trimOws(part), token)) return true;
                const at = comma orelse return false;
                rest = rest[at + 1 ..];
            }
        }
        return false;
    }
};

/// A parsed header block and how many bytes of the request it took, the
/// terminating blank line included.
const Block = struct {
    fields: Fields,
    length: usize,
};

/// Parses one upgrade request from the front of `bytes`.
///
/// `bytes` must begin at the request line. Anything past the blank line that
/// ends the header block is left alone and is not this function's business: an
/// upgrade request has no body, and a caller reading from a socket may already
/// hold the first bytes of the stream behind it.
pub fn parse(bytes: []const u8) Error!Request {
    if (bytes.len > max_header_length) return error.HeaderTooLong;
    const request_line_end = std.mem.indexOf(u8, bytes, crlf) orelse
        return error.UnexpectedEnd;
    try checkRequestLine(bytes[0..request_line_end]);
    const block = try parseFields(bytes[request_line_end + crlf.len ..]);
    const fields = block.fields;

    // RFC 6455 section 4.2.1 in its own order: the request must be one this
    // relay serves, must be one that asks to upgrade, and must carry the fields
    // that make an upgrade possible.
    if (!fields.anyHas("upgrade", "websocket")) return error.UpgradeNotWebsocket;
    if (!fields.anyHas("connection", "upgrade")) return error.ConnectionNotUpgrade;

    const version_field = try single(fields, "sec-websocket-version");
    if (!std.mem.eql(u8, version_field, http_upgrade_types.websocket_version_token)) {
        return error.BadWebSocketVersion;
    }
    const key_field = try single(fields, "sec-websocket-key");
    const key = try decodeKey(key_field);
    // The sub-protocol is optional in RFC 6455 and the section's own example
    // request omits it, so a request without the field is one this relay
    // answers rather than one it refuses. A field that is present and names
    // nothing this build speaks is the other thing entirely.
    const protocol = fields.occurrences("sec-websocket-protocol");
    if (protocol.count > 1) return error.DuplicateField;
    const version: ?Version = if (protocol.value) |value|
        frame_types.negotiate(value) orelse return error.NoSupportedProtocol
    else
        null;

    return .{
        .key_text = key_field,
        .key = key,
        .version = version,
        .header_length = request_line_end + crlf.len + block.length,
    };
}

/// The value of a field this relay reads as a singleton, refusing a repeat and
/// refusing its absence.
///
/// RFC 9110 section 5.3 lets a field repeat and be combined into one list, and
/// `Sec-WebSocket-Version`, `Sec-WebSocket-Key` and `Sec-WebSocket-Protocol` are
/// each values that mean one thing: a request carrying two of them is not one
/// this build can answer, and one carrying none has not asked to upgrade.
fn single(fields: Fields, name: []const u8) Error![]const u8 {
    const found = fields.occurrences(name);
    if (found.count > 1) return error.DuplicateField;
    return found.value orelse return error.MalformedField;
}

/// The sixteen bytes `text` is the base64 of.
///
/// **Exactly sixteen, checked on the decoded length and not on the text's.**
/// Sixteen bytes is four base64 quanta with one quantum of padding, and the text
/// alone cannot say how many bytes a valid spelling carries, so
/// `calcSizeForSlice` is what answers the rule without decoding first.
fn decodeKey(text: []const u8) Error![key_length]u8 {
    const size = std.base64.standard.Decoder.calcSizeForSlice(text) catch
        return error.BadWebSocketKey;
    if (size != key_length) return error.BadWebSocketKey;
    var out: [key_length]u8 = undefined;
    std.base64.standard.Decoder.decode(&out, text) catch return error.BadWebSocketKey;
    return out;
}

/// `GET`, this relay's path, `HTTP/1.1`, and nothing else.
///
/// All three tokens are case-sensitive, which is what RFC 9110 sections 9.1, 7.1
/// and 2.3 say they are. Only field names and the two upgrade tokens fold, and
/// they are folded in `Fields`.
fn checkRequestLine(line: []const u8) Error!void {
    const method_end = std.mem.indexOfScalar(u8, line, ' ') orelse
        return error.MalformedRequestLine;
    if (!std.mem.eql(u8, line[0..method_end], "GET")) return error.MethodNotGet;
    const rest = line[method_end + 1 ..];
    const target_end = std.mem.indexOfScalar(u8, rest, ' ') orelse
        return error.MalformedRequestLine;
    if (!std.mem.eql(u8, rest[0..target_end], http_upgrade_types.relay_path)) {
        return error.PathNotFound;
    }
    if (!std.mem.eql(u8, rest[target_end + 1 ..], http_upgrade_types.http_version)) {
        return error.BadHttpVersion;
    }
}

/// Every field of the block behind the request line, up to and including its
/// blank line.
fn parseFields(rest: []const u8) Error!Block {
    var fields: Fields = .{};
    var cursor = rest;
    var consumed: usize = 0;
    while (true) {
        const at = std.mem.indexOf(u8, cursor, crlf) orelse return error.UnexpectedEnd;
        const line = cursor[0..at];
        consumed += at + crlf.len;
        cursor = cursor[at + crlf.len ..];
        if (line.len == 0) return .{ .fields = fields, .length = consumed };
        if (fields.len == max_fields) return error.TooManyFields;
        if (line.len > max_field_length) return error.FieldTooLong;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse
            return error.MalformedField;
        const name = line[0..colon];
        if (name.len == 0 or !isToken(name)) return error.MalformedField;
        fields.table[fields.len] = .{ .name = name, .value = trimOws(line[colon + 1 ..]) };
        fields.len += 1;
    }
}

/// The optional whitespace RFC 9110 section 5.6.3 allows around a field value.
fn trimOws(value: []const u8) []const u8 {
    return std.mem.trim(u8, value, " \t");
}

/// Whether `name` is a token, RFC 9110 section 5.6.2.
///
/// A field name that is not a token is a request this build will not answer, and
/// the alternative — folding it and hoping — is how two spellings of one field
/// become two fields.
fn isToken(name: []const u8) bool {
    for (name) |c| {
        if (std.ascii.isAlphanumeric(c)) continue;
        if (std.mem.indexOfScalar(u8, "!#$%&'*+-.^_`|~", c) != null) continue;
        return false;
    }
    return true;
}

// --- tests

/// The four fields every request these tests build carries, so that one case
/// varying field does not have to restate the other three.
pub const base_fields =
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
pub fn request(comptime fields: []const u8) []const u8 {
    return "GET /relay HTTP/1.1\r\n" ++ fields ++ "\r\n";
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
