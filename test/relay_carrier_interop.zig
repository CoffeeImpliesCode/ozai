//! Exercise the production TCP/WebSocket relay through real kernel streams.
const std = @import("std");
const ozai = @import("ozai");
const carrier = ozai.relay_tcp_carrier;
const tcp = ozai.transport_tcp;
const frame = ozai.relay_frame;
const websocket = ozai.relay_ws_frame;
const t = std.testing;
const loopback: ozai.SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 0 };
const rounds_max = 10_000;

const Raw = struct {
    socket: tcp.Tcp,
    buffer: [8192]u8 = undefined,
    length: usize = 0,
    upgraded: bool = false,

    fn init(server: *carrier.Server) !Raw {
        var socket = try tcp.Tcp.create(server.address);
        errdefer socket.close();
        try socket.connect(t.io, 1000);
        return .{ .socket = socket };
    }

    fn send(self: *Raw, bytes: []const u8) !void {
        var offset: usize = 0;
        for (0..rounds_max) |_| {
            offset += self.socket.write(t.io, bytes[offset..], 1) catch |err| switch (err) {
                error.WouldBlock => continue,
                else => return err,
            };
            if (offset == bytes.len) return;
        }
        return error.WriteTimeout;
    }

    fn message(self: *Raw, server: *carrier.Server) !frame.Message {
        for (0..rounds_max) |_| {
            try server.poll(t.io);
            if (!self.upgraded) {
                if (std.mem.indexOf(u8, self.buffer[0..self.length], "\r\n\r\n")) |end| {
                    try t.expect(std.mem.startsWith(u8, self.buffer[0..self.length],
                        "HTTP/1.1 101"));
                    self.consume(end + 4);
                    self.upgraded = true;
                }
            }
            if (self.upgraded and self.length > 0) {
                const decoded: ?websocket.Decoded =
                    websocket.decode(self.buffer[0..self.length], .client) catch |err|
                    switch (err) {
                        error.UnexpectedEnd => null,
                        else => return err,
                    };
                if (decoded) |value| {
                    try t.expectEqual(websocket.Opcode.binary, value.frame.opcode);
                    // Challenge/auth-confirm payloads own no borrowed slices.
                    const result = try frame.decode(value.payload, .v2);
                    self.consume(value.frame.header_length + @as(usize,
                        @intCast(value.frame.payload_length)));
                    return result;
                }
            }
            const read = self.socket.read(t.io, self.buffer[self.length..], 1) catch |err|
                switch (err) {
                    error.WouldBlock => continue,
                    else => return err,
                };
            if (read == 0) return error.UnexpectedPeerClose;
            self.length += read;
            if (self.length == self.buffer.len) return error.BufferFull;
        }
        return error.ReadTimeout;
    }

    fn consume(self: *Raw, count: usize) void {
        std.mem.copyForwards(u8, self.buffer[0 .. self.length - count],
            self.buffer[count..self.length]);
        self.length -= count;
    }

    fn upgrade(self: *Raw, server: *carrier.Server) !frame.ServerChallenge {
        try self.send("GET /relay HTTP/1.1\r\nHost: localhost\r\n" ++
            "Upgrade: websocket\r\nConnection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
            "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: iroh-relay-v2\r\n\r\n");
        return switch (try self.message(server)) {
            .server_challenge => |challenge| challenge,
            else => error.ExpectedChallenge,
        };
    }

    fn sendFrame(self: *Raw, payload: []const u8, opcode: websocket.Opcode) !void {
        var bytes: [2048]u8 = undefined;
        try self.send(try websocket.encode(&bytes, .client,
            .{ .fin = true, .opcode = opcode, .key = websocket.fixedMaskKey() }, payload));
    }

    fn authenticate(self: *Raw, server: *carrier.Server, secret: *const ozai.SecretKey) !void {
        const challenge = try self.upgrade(server);
        var bytes: [256]u8 = undefined;
        try self.sendFrame(try frame.encode(.{
            .client_auth = ozai.relay_client.signChallenge(secret, challenge),
        }, .v2, &bytes), .binary);
        switch (try self.message(server)) {
            .server_confirms_auth => {},
            else => return error.ExpectedAuthConfirmation,
        }
    }

    fn expectClosed(self: *Raw, server: *carrier.Server) !void {
        var bytes: [2048]u8 = undefined;
        for (0..rounds_max) |_| {
            try server.poll(t.io);
            const read = self.socket.read(t.io, &bytes, 1) catch |err| switch (err) {
                error.WouldBlock => continue,
                error.ConnectionReset => return,
                else => return err,
            };
            if (read == 0) return;
        }
        return error.SessionNotClosed;
    }
};

test "production carrier rejects authentication signed for a different challenge" {
    var server = try carrier.Server.init(loopback);
    defer server.deinit();
    var raw = try Raw.init(&server);
    defer raw.socket.close();
    var secret = try ozai.SecretKey.fromSeed(@splat(0x51));
    defer secret.deinit();
    var challenge = try raw.upgrade(&server);
    challenge.challenge[0] ^= 1;
    var bytes: [256]u8 = undefined;
    try raw.sendFrame(try frame.encode(.{
        .client_auth = ozai.relay_client.signChallenge(&secret, challenge),
    }, .v2, &bytes), .binary);
    try raw.expectClosed(&server);
}

test "production carrier rejects malformed relay payload after signed registration" {
    var server = try carrier.Server.init(loopback);
    defer server.deinit();
    var raw = try Raw.init(&server);
    defer raw.socket.close();
    var secret = try ozai.SecretKey.fromSeed(@splat(0x52));
    defer secret.deinit();
    try raw.authenticate(&server, &secret);
    try raw.sendFrame(&.{0x7f}, .binary);
    try raw.expectClosed(&server);
}

test "production carrier rejects unmasked client frames and closes a registered session" {
    var server = try carrier.Server.init(loopback);
    defer server.deinit();
    var raw = try Raw.init(&server);
    defer raw.socket.close();
    var secret = try ozai.SecretKey.fromSeed(@splat(0x53));
    defer secret.deinit();
    try raw.authenticate(&server, &secret);
    try raw.send(&.{ 0x82, 0x01, 0x7f });
    try raw.expectClosed(&server);
}

test "production carrier closes a WebSocket close session without forwarding payload" {
    var server = try carrier.Server.init(loopback);
    defer server.deinit();
    var raw = try Raw.init(&server);
    defer raw.socket.close();
    var secret = try ozai.SecretKey.fromSeed(@splat(0x54));
    defer secret.deinit();
    try raw.authenticate(&server, &secret);
    // A one-byte close payload cannot contain an RFC 6455 status code.
    try raw.sendFrame(&.{0x03}, .close);
    try raw.expectClosed(&server);
}

test "two production carrier clients deliver exact datagrams with signed source identities" {
    var server = try carrier.Server.init(loopback);
    defer server.deinit();
    var alice_secret = try ozai.SecretKey.fromSeed(@splat(0x5a));
    defer alice_secret.deinit();
    var bob_secret = try ozai.SecretKey.fromSeed(@splat(0x6c));
    defer bob_secret.deinit();
    var alice = try carrier.Client.init(.{
        .address = server.address, .host = "localhost", .secret = alice_secret,
    });
    defer alice.deinit();
    var bob = try carrier.Client.init(.{
        .address = server.address, .host = "localhost", .secret = bob_secret,
    });
    defer bob.deinit();
    for (0..rounds_max) |_| {
        try server.poll(t.io);
        try alice.poll(t.io);
        try bob.poll(t.io);
        if (alice.isReady() and bob.isReady()) break;
        try std.Io.sleep(t.io, .fromMilliseconds(1), .awake);
    }
    try t.expect(alice.isReady());
    try t.expect(bob.isReady());
    const request = "alice carrier exact datagram";
    const response = "bob carrier exact datagram";
    try alice.send(bob_secret.nodeId(), request);
    try bob.send(alice_secret.nodeId(), response);
    var alice_received = false;
    var bob_received = false;
    for (0..rounds_max) |_| {
        try server.poll(t.io);
        try alice.poll(t.io);
        try bob.poll(t.io);
        if (try alice.receive()) |packet| {
            try t.expectEqual(bob_secret.nodeId(), packet.source);
            try t.expectEqualSlices(u8, response, packet.datagrams.contents);
            alice_received = true;
        }
        if (try bob.receive()) |packet| {
            try t.expectEqual(alice_secret.nodeId(), packet.source);
            try t.expectEqualSlices(u8, request, packet.datagrams.contents);
            bob_received = true;
        }
        if (alice_received and bob_received) break;
        try std.Io.sleep(t.io, .fromMilliseconds(1), .awake);
    }
    try t.expect(alice_received);
    try t.expect(bob_received);
}

test "production client distinguishes malformed server close from orderly close" {
    for ([_][]const u8{
        &.{0x03}, &.{ 0x03, 0xed }, &.{ 0x03, 0xe8, 0xff }, &.{},
    }, 0..) |payload, case| {
        var server = try carrier.Server.init(loopback);
        defer server.deinit();
        var secret = try ozai.SecretKey.fromSeed(@splat(0x55));
        defer secret.deinit();
        var client = try carrier.Client.init(.{
            .address = server.address, .host = "localhost", .secret = secret,
        });
        defer client.deinit();
        for (0..rounds_max) |_| {
            try server.poll(t.io);
            try client.poll(t.io);
            if (client.isReady()) break;
            try std.Io.sleep(t.io, .fromMilliseconds(1), .awake);
        }
        try t.expect(client.isReady());
        var bytes: [32]u8 = undefined;
        const encoded = try websocket.encode(&bytes, .server,
            .{ .fin = true, .opcode = .close, .key = websocket.fixedMaskKey() }, payload);
        const registered = &server.peers[0].?;
        try t.expectEqual(secret.nodeId(), registered.identity.?);
        try t.expectEqual(encoded.len, try registered.connection.stream.write(t.io, encoded, 1000));
        var rejected = false;
        for (0..rounds_max) |_| {
            client.poll(t.io) catch |err| {
                if (case < 3) {
                    try t.expectEqual(error.InvalidCloseFrame, err);
                } else {
                    try t.expectEqual(error.Closed, err);
                }
                rejected = true;
                break;
            };
            try std.Io.sleep(t.io, .fromMilliseconds(1), .awake);
        }
        try t.expect(rejected);
    }
}
