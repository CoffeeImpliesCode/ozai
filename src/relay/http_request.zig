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
                const comma = std.mem.indexOfScalar(u8, rest, ',');
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
