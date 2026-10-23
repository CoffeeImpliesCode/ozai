const std = @import("std");
const upgrade = @import("http_upgrade.zig");
const tcp_session = @import("tcp_session.zig");
const Session = tcp_session.Session;

/// Returns the offset after the first complete HTTP header, or null for incomplete input.
pub fn headerEnd(bytes: []const u8) ?usize {
    const end = std.mem.find(u8, bytes, "\r\n\r\n") orelse return null;
    return end + 4;
}

/// Validates the relay-v2 WebSocket response against the request's expected accept value.
pub fn verifyResponse(bytes: []const u8, expected_accept: []const u8) tcp_session.Error!void {
    if (bytes.len > upgrade.max_header_length) return error.InvalidUpgrade;
    var lines = std.mem.splitSequence(u8, bytes, "\r\n");
    const status = lines.next() orelse return error.InvalidUpgrade;
    if (!std.mem.eql(u8, status, "HTTP/1.1 101 Switching Protocols")) return error.InvalidUpgrade;
    var accepted = false;
    var upgraded = false;
    var connected = false;
    var version = false;
    var count: usize = 0;
    while (lines.next()) |line| {
        if (line.len == 0) break;
        count += 1;
        if (count > upgrade.max_fields or
            line.len > upgrade.max_field_length) return error.InvalidUpgrade;
        const colon = std.mem.findScalar(u8, line, ':') orelse return error.InvalidUpgrade;
        const name = line[0..colon];
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(name, "Sec-WebSocket-Accept")) {
            if (accepted or !std.mem.eql(u8, value, expected_accept)) return error.InvalidUpgrade;
            accepted = true;
        } else if (std.ascii.eqlIgnoreCase(name, "Upgrade")) {
            if (upgraded or !std.ascii.eqlIgnoreCase(value, "websocket"))
                return error.InvalidUpgrade;
            upgraded = true;
        } else if (std.ascii.eqlIgnoreCase(name, "Connection")) {
            if (connected) return error.InvalidUpgrade;
            var tokens = std.mem.splitScalar(u8, value, ',');
            while (tokens.next()) |token| {
                if (std.ascii.eqlIgnoreCase(
                    std.mem.trim(u8, token, " \t"),
                    "upgrade",
                )) connected = true;
            }
            if (!connected) return error.InvalidUpgrade;
        } else if (std.ascii.eqlIgnoreCase(name, "Sec-WebSocket-Protocol")) {
            if (version or !std.mem.eql(u8, value, "iroh-relay-v2")) return error.InvalidUpgrade;
            version = true;
        } else if (std.ascii.eqlIgnoreCase(name, "Sec-WebSocket-Extensions")) {
            return error.InvalidUpgrade;
        }
    }
    if (!accepted or !upgraded or !connected or !version) return error.InvalidUpgrade;
}

/// Writes an upgrade request into the borrowed session's transmit buffer without sending it.
/// Updates accept before formatting; failures report unavailable randomness or a full buffer.
pub fn request(
    session: *Session,
    io: std.Io,
    host: []const u8,
    accept: *[upgrade.accept_length]u8,
) tcp_session.Error!void {
    var nonce: [16]u8 = undefined;
    io.randomSecure(&nonce) catch return error.RandomUnavailable;
    var key_text: [24]u8 = undefined;
    const encoded_key = std.base64.standard.Encoder.encode(&key_text, &nonce);
    accept.* = upgrade.accept(encoded_key);
    const request_bytes = std.fmt.bufPrint(
        &session.tx,
        "GET /relay HTTP/1.1\r\nHost: {s}\r\nUpgrade: websocket\r\n" ++
            "Connection: Upgrade\r\nSec-WebSocket-Key: {s}\r\n" ++
            "Sec-WebSocket-Version: 13\r\n" ++
            "Sec-WebSocket-Protocol: iroh-relay-v2\r\n\r\n",
        .{ host, encoded_key },
    ) catch return error.BufferFull;
    session.tx_end = request_bytes.len;
}

test "upgrade response validates selected protocol and challenge binding" {
    const expected = upgrade.accept("dGhlIHNhbXBsZSBub25jZQ==");
    var response_buffer: [512]u8 = undefined;
    const correct = try upgrade.build(&response_buffer, .v2, "dGhlIHNhbXBsZSBub25jZQ==");
    try verifyResponse(correct, &expected);
    try std.testing.expectError(error.InvalidUpgrade, verifyResponse(correct, &(.{0} ** 28)));
    const wrong_version = try upgrade.build(&response_buffer, .v1, "dGhlIHNhbXBsZSBub25jZQ==");
    try std.testing.expectError(error.InvalidUpgrade, verifyResponse(wrong_version, &expected));
}
