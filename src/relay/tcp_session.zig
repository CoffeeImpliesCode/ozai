const std = @import("std");
const tcp = @import("../transport/tcp.zig");
const frame = @import("frame.zig");
const ws = @import("ws_frame.zig");
const upgrade = @import("http_upgrade.zig");

pub const Error = tcp.OpenError || tcp.ConnectError || tcp.ReadError || tcp.WriteError ||
    tcp.ListenError || tcp.AcceptError || frame.Error || ws.Error || upgrade.Error ||
    error{ InvalidHost, InvalidUpgrade, UnexpectedMessage, Closed, RandomUnavailable,
        SignatureInvalid, InvalidCloseFrame };
pub const capacity = frame.max_packet_size + 1;

pub const Session = struct {
    stream: tcp.Tcp,
    rx: [capacity + ws.max_header_length]u8 = undefined,
    rx_len: usize = 0,
    eof: bool = false,
    tx: [capacity + ws.max_header_length]u8 = undefined,
    tx_pos: usize = 0,
    tx_end: usize = 0,
    pending_payload: ?usize = null,
    message: [capacity]u8 = undefined,
    message_len: usize = 0,
    fragmented: bool = false,
    text_message: bool = false,
    complete: bool = false,

    pub fn busy(self: *const Session) bool {
        return self.tx_pos != self.tx_end or self.pending_payload != null;
    }

    pub fn consume(self: *Session, count: usize) void {
        std.mem.copyForwards(u8, self.rx[0 .. self.rx_len - count], self.rx[count..self.rx_len]);
        self.rx_len -= count;
    }

    pub fn read(self: *Session, io: std.Io) Error!void {
        if (self.eof) return;
        if (self.rx_len == self.rx.len) return;
        const count = self.stream.read(io, self.rx[self.rx_len..], 0) catch |err| switch (err) {
            error.WouldBlock => return,
            else => return err,
        };
        if (count == 0) {
            self.eof = true;
            return;
        }
        self.rx_len += count;
    }

    pub fn flush(self: *Session, io: std.Io, role: ws.Role) Error!void {
        if (self.pending_payload) |length| {
            var mask: ws.MaskKey = .{0} ** 4;
            if (role == .client) io.randomSecure(&mask) catch return error.RandomUnavailable;
            const header_len = ws.headerLen(length, role == .client);
            const start = ws.max_header_length - header_len;
            const written = try ws.writeHeader(self.tx[start..ws.max_header_length], .{
                .fin = true, .opcode = .binary, .masked = role == .client,
                .payload_length = length, .mask_key = mask, .header_length = header_len,
            });
            std.debug.assert(written == header_len);
            if (role == .client) ws.mask(mask, self.tx[ws.max_header_length..][0..length]);
            self.tx_pos = start;
            self.tx_end = ws.max_header_length + length;
            self.pending_payload = null;
        }
        if (self.tx_pos == self.tx_end) return;
        const count = self.stream.write(io, self.tx[self.tx_pos..self.tx_end], 0) catch |err| switch (err) {
            error.WouldBlock => return,
            else => return err,
        };
        if (count == 0) return error.Closed;
        self.tx_pos += count;
        if (self.tx_pos == self.tx_end) {
            self.tx_pos = 0;
            self.tx_end = 0;
        }
    }

    pub fn relay(self: *Session, message: frame.Message) Error!void {
        if (self.busy()) return error.WouldBlock;
        const encoded = try frame.encode(message, .v2, self.tx[ws.max_header_length..]);
        self.pending_payload = encoded.len;
    }

    pub fn control(self: *Session, io: std.Io, role: ws.Role, opcode: ws.Opcode, bytes: []const u8) Error!void {
        if (self.busy()) return error.WouldBlock;
        var mask: ws.MaskKey = .{0} ** 4;
        if (role == .client) io.randomSecure(&mask) catch return error.RandomUnavailable;
        const encoded = try ws.encode(&self.tx, role, .{ .fin = true, .opcode = opcode, .key = mask }, bytes);
        self.tx_pos = 0;
        self.tx_end = encoded.len;
    }

    /// Processes at most eight frames. Control frames do not perturb fragment state.
    pub fn next(self: *Session, io: std.Io, role: ws.Role) Error!?[]const u8 {
        if (self.complete) {
            self.message_len = 0;
            self.complete = false;
        }
        for (0..8) |_| {
            if (self.rx_len == 0) {
                if (self.eof) return error.Closed;
                return null;
            }
            const decoded = ws.decode(self.rx[0..self.rx_len], role) catch |err| switch (err) {
                error.UnexpectedEnd => {
                    if (self.eof) return error.UnexpectedEnd;
                    const header = ws.readHeader(self.rx[0..self.rx_len]) catch |header_err| switch (header_err) {
                        error.UnexpectedEnd => return null,
                        else => return header_err,
                    };
                    if (header.payload_length > capacity) return error.FrameTooLarge;
                    return null;
                },
                else => return err,
            };
            const header = decoded.frame;
            if (header.payload_length > capacity) return error.FrameTooLarge;
            const end = header.header_length + decoded.payload.len;
            const payload = self.rx[header.header_length..end];
            // A queued pong must be sent before consuming another ping.
            if (header.opcode == .ping and self.busy()) return null;
            if (header.masked) ws.mask(header.mask_key, payload);
            switch (header.opcode) {
                .close => {
                    try validateClose(payload);
                    return error.Closed;
                },
                .ping => {
                    try self.control(io, role, .pong, payload);
                    self.consume(end);
                    return null;
                },
                .pong => {},
                .text, .binary, .continuation => {
                    if (header.opcode != .continuation and self.fragmented) return error.UnexpectedMessage;
                    if (header.opcode == .continuation and !self.fragmented) return error.UnexpectedMessage;
                    if (header.opcode != .continuation) self.text_message = header.opcode == .text;
                    if (payload.len > self.message.len - self.message_len) return error.FrameTooLarge;
                    @memcpy(self.message[self.message_len..][0..payload.len], payload);
                    self.message_len += payload.len;
                    self.fragmented = !header.fin;
                    self.consume(end);
                    if (header.fin) {
                        if (self.text_message) {
                            if (!std.unicode.utf8ValidateSlice(self.message[0..self.message_len]))
                                return error.InvalidUtf8;
                            self.message_len = 0;
                            continue;
                        }
                        self.complete = true;
                        return self.message[0..self.message_len];
                    }
                    continue;
                },
            }
            self.consume(end);
        }
        return null;
    }
};

fn validateClose(payload: []const u8) Error!void {
    if (payload.len == 0) return;
    if (payload.len == 1) return error.InvalidCloseFrame;
    const code = std.mem.readInt(u16, payload[0..2], .big);
    const protocol_code = code >= 1000 and code <= 1014 and
        code != 1004 and code != 1005 and code != 1006;
    const application_code = code >= 3000 and code <= 4999;
    if (!protocol_code and !application_code) return error.InvalidCloseFrame;
    if (!std.unicode.utf8ValidateSlice(payload[2..])) return error.InvalidCloseFrame;
}

test "partial coalesced fragments preserve binary message across interleaved ping" {
    var connection: Session = .{ .stream = undefined };
    const mask: ws.MaskKey = .{ 1, 2, 3, 4 };
    const first = try ws.encode(&connection.rx, .client,
        .{ .fin = false, .opcode = .binary, .key = mask }, "first");
    connection.rx_len = first.len;
    try std.testing.expectEqual(@as(?[]const u8, null),
        try connection.next(std.testing.io, .server));
    const ping = try ws.encode(&connection.rx, .client,
        .{ .fin = true, .opcode = .ping, .key = mask }, "probe");
    const last = try ws.encode(connection.rx[ping.len..], .client,
        .{ .fin = true, .opcode = .continuation, .key = mask }, "last");
    connection.rx_len = ping.len + last.len - 1;
    try std.testing.expectEqual(@as(?[]const u8, null),
        try connection.next(std.testing.io, .server));
    const pong = try ws.decode(connection.tx[0..connection.tx_end], .client);
    try std.testing.expectEqual(ws.Opcode.pong, pong.frame.opcode);
    try std.testing.expectEqualSlices(u8, "probe", pong.payload);
    connection.tx_end = 0;
    try std.testing.expectEqual(@as(?[]const u8, null),
        try connection.next(std.testing.io, .server));
    // Restore the final wire byte lost in the simulated short TCP read.
    connection.rx[connection.rx_len] = 't' ^ mask[3];
    connection.rx_len += 1;
    const message = (try connection.next(std.testing.io, .server)).?;
    try std.testing.expectEqualSlices(u8, "firstlast", message);
}

test "untrusted oversized declaration rejected before payload arrives" {
    var connection: Session = .{ .stream = undefined };
    const length = capacity + 1;
    connection.rx_len = try ws.writeHeader(&connection.rx, .{
        .fin = true, .opcode = .binary, .masked = true,
        .payload_length = length, .mask_key = .{ 1, 2, 3, 4 },
        .header_length = ws.headerLen(length, true),
    });
    try std.testing.expectError(error.FrameTooLarge, connection.next(std.testing.io, .server));
}

test "orphan continuation and wrong masking are protocol errors" {
    var connection: Session = .{ .stream = undefined };
    const orphan = try ws.encode(&connection.rx, .client,
        .{ .fin = true, .opcode = .continuation, .key = .{ 1, 2, 3, 4 } }, "x");
    connection.rx_len = orphan.len;
    try std.testing.expectError(error.UnexpectedMessage, connection.next(std.testing.io, .server));
    const unmasked = try ws.encode(&connection.rx, .server,
        .{ .fin = true, .opcode = .binary, .key = .{ 0, 0, 0, 0 } }, "x");
    connection.rx_len = unmasked.len;
    try std.testing.expectError(error.UnmaskedClientFrame, connection.next(std.testing.io, .server));
}

test "close payload rejects truncated status forbidden codes and invalid UTF8 reasons" {
    const malformed = [_][]const u8{
        &.{ 0x03 }, &.{ 0x03, 0xec }, &.{ 0x03, 0xed }, &.{ 0x03, 0xee },
        &.{ 0x03, 0xf7 }, &.{ 0x00, 0x01 }, &.{ 0x13, 0x88 },
        &.{ 0x03, 0xe8, 0xff },
    };
    for (malformed) |payload| {
        // A close error terminates this connection; each payload needs its own session.
        var connection: Session = .{ .stream = undefined };
        const encoded = try ws.encode(&connection.rx, .client,
            .{ .fin = true, .opcode = .close, .key = .{ 1, 2, 3, 4 } }, payload);
        connection.rx_len = encoded.len;
        try std.testing.expectError(error.InvalidCloseFrame,
            connection.next(std.testing.io, .server));
    }
}

test "close permits empty payload and valid protocol and application statuses" {
    const valid = [_][]const u8{
        // Status 1007 reports invalid data, but is itself a valid close status.
        "", &.{ 0x03, 0xe8 }, &.{ 0x03, 0xef }, &.{ 0x0b, 0xb8, 'o', 'k' },
    };
    for (valid) |payload| {
        var connection: Session = .{ .stream = undefined };
        const encoded = try ws.encode(&connection.rx, .client,
            .{ .fin = true, .opcode = .close, .key = .{ 1, 2, 3, 4 } }, payload);
        connection.rx_len = encoded.len;
        try std.testing.expectError(error.Closed, connection.next(std.testing.io, .server));
    }
}

test "ignored text does not reset following binary fragments at next poll" {
    var connection: Session = .{ .stream = undefined };
    const text = try ws.encode(&connection.rx, .server,
        .{ .fin = true, .opcode = .text, .key = .{0} ** 4 }, "ignored");
    const first = try ws.encode(connection.rx[text.len..], .server,
        .{ .fin = false, .opcode = .binary, .key = .{0} ** 4 }, "first");
    connection.rx_len = text.len + first.len;
    try std.testing.expectEqual(@as(?[]const u8, null),
        try connection.next(std.testing.io, .client));
    const last = try ws.encode(&connection.rx, .server,
        .{ .fin = true, .opcode = .continuation, .key = .{0} ** 4 }, "last");
    connection.rx_len = last.len;
    try std.testing.expectEqualStrings("firstlast",
        (try connection.next(std.testing.io, .client)).?);
}

test "EOF drains every complete buffered binary message before Closed" {
    var connection: Session = .{ .stream = undefined, .eof = true };
    const first = try ws.encode(&connection.rx, .server,
        .{ .fin = true, .opcode = .binary, .key = .{0} ** 4 }, "first");
    const second = try ws.encode(connection.rx[first.len..], .server,
        .{ .fin = true, .opcode = .binary, .key = .{0} ** 4 }, "second");
    connection.rx_len = first.len + second.len;
    try connection.read(std.testing.io);
    try std.testing.expectEqualStrings("first", (try connection.next(std.testing.io, .client)).?);
    try connection.read(std.testing.io);
    try std.testing.expectEqualStrings("second", (try connection.next(std.testing.io, .client)).?);
    try std.testing.expectError(error.Closed, connection.next(std.testing.io, .client));
}
