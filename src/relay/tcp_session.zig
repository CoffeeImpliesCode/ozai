const std = @import("std");
const tcp = @import("../transport/tcp.zig");
const frame = @import("frame.zig");
const ws = @import("ws_frame.zig");
const upgrade = @import("http_upgrade.zig");
const websocket = @import("ws_processor.zig");
const tcp_error = @import("../transport/tcp_error.zig");

pub const Error = tcp.OpenError || tcp.ConnectError || tcp.ReadError || tcp.WriteError ||
    tcp_error.ListenError || tcp_error.AcceptError || frame.Error || ws.Error || upgrade.Error ||
    error{
        InvalidHost,
        InvalidUpgrade,
        UnexpectedMessage,
        Closed,
        RandomUnavailable,
        SignatureInvalid,
        InvalidCloseFrame,
    };
pub const capacity = frame.max_packet_size + 1;

/// Descriptor-independent transport execution. The context remains borrowed until close.
/// Production sessions use Tcp directly; deterministic adapters supply all three operations.
/// Callbacks run on the calling thread and must not reenter their session.
/// Read/write borrow `io` and their byte slice only for the duration of the call.
pub const Transport = struct {
    context: *anyopaque,
    read: *const fn (std.Io, *anyopaque, []u8) Error!usize,
    write: *const fn (std.Io, *anyopaque, []const u8) Error!usize,
    close: *const fn (*anyopaque) void,
};

pub const Session = struct {
    stream: tcp.Tcp,
    transport: ?Transport = null,
    closed: bool = false,
    rx: [capacity + ws.max_header_length]u8 = undefined,
    rx_len: usize = 0,
    eof: bool = false,
    tx: [capacity + ws.max_header_length]u8 = undefined,
    tx_pos: usize = 0,
    tx_end: usize = 0,
    pending_payload: ?usize = null,
    pending_opcode: ws.Opcode = .binary,
    message: [capacity]u8 = undefined,
    websocket: websocket.State = .{},

    pub fn close(self: *Session) void {
        if (self.closed) return;
        self.closed = true;
        if (self.transport) |transport| {
            transport.close(transport.context);
        } else {
            self.stream.close();
        }
    }

    fn readTransport(self: *Session, io: std.Io, bytes: []u8) Error!usize {
        if (self.transport) |transport| return transport.read(io, transport.context, bytes);
        return self.stream.read(io, bytes, 0);
    }

    fn writeTransport(self: *Session, io: std.Io, bytes: []const u8) Error!usize {
        if (self.transport) |transport| return transport.write(io, transport.context, bytes);
        return self.stream.write(io, bytes, 0);
    }

    pub fn busy(self: *const Session) bool {
        return self.tx_pos != self.tx_end or self.pending_payload != null;
    }

    pub fn consume(self: *Session, count: usize) void {
        @memmove(self.rx[0 .. self.rx_len - count], self.rx[count..self.rx_len]);
        self.rx_len -= count;
    }

    pub fn read(self: *Session, io: std.Io) Error!void {
        if (self.eof) return;
        if (self.rx_len == self.rx.len) return;
        const count = self.readTransport(io, self.rx[self.rx_len..]) catch |err| switch (err) {
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
                .fin = true,
                .opcode = self.pending_opcode,
                .masked = role == .client,
                .payload_length = length,
                .mask_key = mask,
                .header_length = header_len,
            });
            std.debug.assert(written == header_len);
            if (role == .client) ws.mask(mask, self.tx[ws.max_header_length..][0..length]);
            self.tx_pos = start;
            self.tx_end = ws.max_header_length + length;
            self.pending_payload = null;
        }
        if (self.tx_pos == self.tx_end) return;
        const count = self.writeTransport(
            io,
            self.tx[self.tx_pos..self.tx_end],
        ) catch |err| switch (err) {
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
        self.pending_opcode = .binary;
    }

    pub fn control(self: *Session, opcode: ws.Opcode, bytes: []const u8) Error!void {
        if (self.busy()) return error.WouldBlock;
        if (bytes.len > 125) return error.FrameTooLarge;
        @memcpy(self.tx[ws.max_header_length..][0..bytes.len], bytes);
        self.pending_payload = bytes.len;
        self.pending_opcode = opcode;
    }

    /// Processes at most eight frames. Control frames do not perturb fragment state.
    pub fn next(self: *Session, role: ws.Role) Error!?[]const u8 {
        if (self.websocket.complete) {
            self.websocket.message_len = 0;
            self.websocket.complete = false;
        }
        for (0..8) |_| {
            if (self.rx_len == 0) {
                if (self.eof) return error.Closed;
                return null;
            }
            const decoded = ws.decode(self.rx[0..self.rx_len], role) catch |err| switch (err) {
                error.UnexpectedEnd => {
                    if (self.eof) return error.UnexpectedEnd;
                    const header = ws.readHeader(
                        self.rx[0..self.rx_len],
                    ) catch |header_err| switch (header_err) {
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
            const result = try websocket.process(self.websocket, .{
                .opcode = header.opcode,
                .fin = header.fin,
                .payload = payload,
                .capacity = self.message.len,
                .output_ready = !self.busy(),
            });
            var offset = self.websocket.message_len;
            self.websocket = result.state;
            for (result.actions[0..result.count]) |action| {
                switch (action) {
                    .append => |bytes| {
                        @memcpy(self.message[offset..][0..bytes.len], bytes);
                        offset += bytes.len;
                    },
                    .consume => self.consume(end),
                    .pong => |bytes| try self.control(.pong, bytes),
                    .deliver => return self.message[0..self.websocket.message_len],
                    .reset => {},
                    .close => return error.Closed,
                }
            }
            if (header.opcode == .ping) return null;
        }
        return null;
    }
};

test "partial coalesced fragments preserve binary message across interleaved ping" {
    var connection: Session = .{ .stream = undefined };
    const mask: ws.MaskKey = .{ 1, 2, 3, 4 };
    const first = try ws.encode(
        &connection.rx,
        .client,
        .{ .fin = false, .opcode = .binary, .key = mask },
        "first",
    );
    connection.rx_len = first.len;
    try std.testing.expectEqual(
        @as(?[]const u8, null),
        try connection.next(.server),
    );
    const ping = try ws.encode(
        &connection.rx,
        .client,
        .{ .fin = true, .opcode = .ping, .key = mask },
        "probe",
    );
    const last = try ws.encode(
        connection.rx[ping.len..],
        .client,
        .{ .fin = true, .opcode = .continuation, .key = mask },
        "last",
    );
    connection.rx_len = ping.len + last.len - 1;
    try std.testing.expectEqual(
        @as(?[]const u8, null),
        try connection.next(.server),
    );
    try std.testing.expectEqual(ws.Opcode.pong, connection.pending_opcode);
    const pong_length = connection.pending_payload orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, "probe", connection.tx[ws.max_header_length..][0..pong_length]);
    connection.pending_payload = null;
    try std.testing.expectEqual(
        @as(?[]const u8, null),
        try connection.next(.server),
    );
    // Restore the final wire byte lost in the simulated short TCP read.
    connection.rx[connection.rx_len] = 't' ^ mask[3];
    connection.rx_len += 1;
    // Restoring the final byte completes the continuation of the buffered binary message.
    const message = (try connection.next(.server)) orelse
        @panic("complete binary continuation must produce a message");
    try std.testing.expectEqualSlices(u8, "firstlast", message);
}

test "client next consumes server ping without entropy and preserves binary fragments" {
    // Decoded input must advance even when output masking entropy is unavailable.
    const Entropy = struct {
        fn draw(userdata: ?*anyopaque, _: []u8) std.Io.RandomSecureError!void {
            const calls: *usize = @ptrCast(@alignCast(userdata.?));
            calls.* += 1;
            return error.EntropyUnavailable;
        }
    };
    var entropy_calls: usize = 0;
    var vtable = std.Io.failing.vtable.*;
    vtable.randomSecure = Entropy.draw;
    const io: std.Io = .{ .userdata = &entropy_calls, .vtable = &vtable };
    var connection: Session = .{ .stream = undefined };
    const first = try ws.encode(
        &connection.rx,
        .server,
        .{ .fin = false, .opcode = .binary, .key = .{0} ** 4 },
        "first",
    );
    connection.rx_len = first.len;
    try std.testing.expectEqual(
        @as(?[]const u8, null),
        try connection.next(.client),
    );
    try std.testing.expectEqual(@as(usize, 0), connection.rx_len);
    try std.testing.expect(connection.websocket.fragmented);
    try std.testing.expect(!connection.websocket.text_message);
    try std.testing.expect(!connection.websocket.complete);
    try std.testing.expectEqual(@as(usize, 5), connection.websocket.message_len);
    try std.testing.expectEqualSlices(u8, "first", connection.message[0..connection.websocket.message_len]);
    try std.testing.expect(!connection.busy());
    try std.testing.expectEqual(@as(usize, 0), entropy_calls);

    const ping = try ws.encode(
        &connection.rx,
        .server,
        .{ .fin = true, .opcode = .ping, .key = .{0} ** 4 },
        "probe",
    );
    connection.rx_len = ping.len;
    try std.testing.expectEqual(
        @as(?[]const u8, null),
        try connection.next(.client),
    );
    try std.testing.expectEqual(@as(usize, 0), connection.rx_len);
    try std.testing.expect(connection.websocket.fragmented);
    try std.testing.expect(!connection.websocket.text_message);
    try std.testing.expect(!connection.websocket.complete);
    try std.testing.expectEqual(@as(usize, 5), connection.websocket.message_len);
    try std.testing.expectEqualSlices(u8, "first", connection.message[0..connection.websocket.message_len]);
    try std.testing.expect(connection.busy());
    try std.testing.expectEqual(@as(usize, 0), entropy_calls);
    try std.testing.expectError(error.RandomUnavailable, connection.flush(io, .client));
    try std.testing.expectEqual(@as(usize, 1), entropy_calls);
    try std.testing.expect(connection.busy());
}

test "untrusted oversized declaration rejected before payload arrives" {
    var connection: Session = .{ .stream = undefined };
    const length = capacity + 1;
    connection.rx_len = try ws.writeHeader(&connection.rx, .{
        .fin = true,
        .opcode = .binary,
        .masked = true,
        .payload_length = length,
        .mask_key = .{ 1, 2, 3, 4 },
        .header_length = ws.headerLen(length, true),
    });
    try std.testing.expectError(error.FrameTooLarge, connection.next(.server));
}

test "orphan continuation and wrong masking are protocol errors" {
    var connection: Session = .{ .stream = undefined };
    const orphan = try ws.encode(
        &connection.rx,
        .client,
        .{ .fin = true, .opcode = .continuation, .key = .{ 1, 2, 3, 4 } },
        "x",
    );
    connection.rx_len = orphan.len;
    try std.testing.expectError(error.UnexpectedMessage, connection.next(.server));
    const unmasked = try ws.encode(
        &connection.rx,
        .server,
        .{ .fin = true, .opcode = .binary, .key = .{ 0, 0, 0, 0 } },
        "x",
    );
    connection.rx_len = unmasked.len;
    try std.testing.expectError(
        error.UnmaskedClientFrame,
        connection.next(.server),
    );
}

test "close payload rejects truncated status forbidden codes and invalid UTF8 reasons" {
    const malformed = [_][]const u8{
        &.{0x03},         &.{ 0x03, 0xec }, &.{ 0x03, 0xed }, &.{ 0x03, 0xee },
        &.{ 0x03, 0xf7 }, &.{ 0x00, 0x01 }, &.{ 0x13, 0x88 }, &.{ 0x03, 0xe8, 0xff },
    };
    for (malformed) |payload| {
        // A close error terminates this connection; each payload needs its own session.
        var connection: Session = .{ .stream = undefined };
        const encoded = try ws.encode(
            &connection.rx,
            .client,
            .{ .fin = true, .opcode = .close, .key = .{ 1, 2, 3, 4 } },
            payload,
        );
        connection.rx_len = encoded.len;
        try std.testing.expectError(
            error.InvalidCloseFrame,
            connection.next(.server),
        );
    }
}

test "close permits empty payload and valid protocol and application statuses" {
    const valid = [_][]const u8{
        // Status 1007 reports invalid data, but is itself a valid close status.
        "", &.{ 0x03, 0xe8 }, &.{ 0x03, 0xef }, &.{ 0x0b, 0xb8, 'o', 'k' },
    };
    for (valid) |payload| {
        var connection: Session = .{ .stream = undefined };
        const encoded = try ws.encode(
            &connection.rx,
            .client,
            .{ .fin = true, .opcode = .close, .key = .{ 1, 2, 3, 4 } },
            payload,
        );
        connection.rx_len = encoded.len;
        try std.testing.expectError(error.Closed, connection.next(.server));
    }
}

test "ignored text does not reset following binary fragments at next poll" {
    var connection: Session = .{ .stream = undefined };
    const text = try ws.encode(
        &connection.rx,
        .server,
        .{ .fin = true, .opcode = .text, .key = .{0} ** 4 },
        "ignored",
    );
    const first = try ws.encode(
        connection.rx[text.len..],
        .server,
        .{ .fin = false, .opcode = .binary, .key = .{0} ** 4 },
        "first",
    );
    connection.rx_len = text.len + first.len;
    try std.testing.expectEqual(
        @as(?[]const u8, null),
        try connection.next(.client),
    );
    const last = try ws.encode(
        &connection.rx,
        .server,
        .{ .fin = true, .opcode = .continuation, .key = .{0} ** 4 },
        "last",
    );
    connection.rx_len = last.len;
    try std.testing.expectEqualStrings(
        "firstlast",
        (try connection.next(.client)).?,
    );
}

test "EOF drains every complete buffered binary message before Closed" {
    var connection: Session = .{ .stream = undefined, .eof = true };
    const first = try ws.encode(
        &connection.rx,
        .server,
        .{ .fin = true, .opcode = .binary, .key = .{0} ** 4 },
        "first",
    );
    const second = try ws.encode(
        connection.rx[first.len..],
        .server,
        .{ .fin = true, .opcode = .binary, .key = .{0} ** 4 },
        "second",
    );
    connection.rx_len = first.len + second.len;
    try connection.read(std.testing.io);
    try std.testing.expectEqualStrings("first", (try connection.next(.client)).?);
    try connection.read(std.testing.io);
    try std.testing.expectEqualStrings("second", (try connection.next(.client)).?);
    try std.testing.expectError(error.Closed, connection.next(.client));
}

test "queued pong leaves a second masked ping untouched until output drains" {
    var connection: Session = .{ .stream = undefined };
    const key: ws.MaskKey = .{ 1, 2, 3, 4 };
    const first = try ws.encode(&connection.rx, .client, .{
        .fin = true,
        .opcode = .ping,
        .key = key,
    }, "first");
    const second = try ws.encode(connection.rx[first.len..], .client, .{
        .fin = true,
        .opcode = .ping,
        .key = key,
    }, "second");
    connection.rx_len = first.len + second.len;
    try std.testing.expectEqual(@as(?[]const u8, null), try connection.next(.server));
    try std.testing.expectEqual(second.len, connection.rx_len);
    var retained: [32]u8 = undefined;
    @memcpy(retained[0..second.len], connection.rx[0..second.len]);
    try std.testing.expectEqual(@as(?[]const u8, null), try connection.next(.server));
    try std.testing.expectEqualSlices(u8, retained[0..second.len], connection.rx[0..second.len]);
    connection.pending_payload = null;
    try std.testing.expectEqual(@as(?[]const u8, null), try connection.next(.server));
    try std.testing.expectEqual(@as(usize, 0), connection.rx_len);
    try std.testing.expectEqualStrings(
        "second",
        connection.tx[ws.max_header_length..][0..connection.pending_payload.?],
    );
}
