const std = @import("std");
const key = @import("../base/key.zig");
const frame = @import("frame.zig");
const tcp = @import("../transport/tcp.zig");
const SocketAddr = @import("../base/addr.zig").SocketAddr;
const upgrade = @import("http_upgrade.zig");
const session = @import("tcp_session.zig");
const Session = session.Session;
pub const Error = session.Error;
const CarrierError = Error;
pub const NodeId = key.NodeId;
pub const SecretKey = key.SecretKey;

pub const Config = struct {
    address: SocketAddr,
    host: []const u8,
    secret: SecretKey,
};

pub const Packet = struct {
    source: NodeId,
    datagrams: frame.Datagrams,
};

pub const Client = struct {
    connection: Session,
    secret: SecretKey,
    host: [256]u8 = undefined,
    host_len: usize,
    state: enum { connecting, request, upgrade, challenge, confirm, ready, closed },
    accept: [upgrade.accept_length]u8 = undefined,
    packet: ?Packet = null,

    pub fn init(config: Config) CarrierError!Client {
        if (config.host.len == 0 or config.host.len > 256) return error.InvalidHost;
        for (config.host) |byte| {
            if (byte <= 32 or byte >= 127) return error.InvalidHost;
        }
        var stream = try tcp.Tcp.create(config.address);
        errdefer stream.close();
        const connected = try stream.startConnect();
        var result: Client = .{
            .connection = .{ .stream = stream },
            .secret = config.secret,
            .host_len = config.host.len,
            .state = if (connected) .request else .connecting,
        };
        @memcpy(result.host[0..config.host.len], config.host);
        return result;
    }

    pub fn deinit(self: *Client) void {
        self.connection.stream.close();
        self.secret.deinit();
        self.state = .closed;
    }

    pub fn isReady(self: *const Client) bool {
        return self.state == .ready;
    }

    pub fn send(self: *Client, target: NodeId, datagram: []const u8) CarrierError!void {
        if (!self.isReady()) return error.WouldBlock;
        try self.connection.relay(.{ .client_to_relay_datagram = .{
            .node_id = target,
            .datagrams = .{ .ecn = null, .segment_size = null, .contents = datagram },
        } });
    }

    /// Packet storage is invalidated by the next poll, not by receive.
    pub fn receive(self: *Client) CarrierError!?Packet {
        const packet = self.packet;
        self.packet = null;
        return packet;
    }

    pub fn poll(self: *Client, io: std.Io) CarrierError!void {
        self.packet = null;
        self.pollInner(io) catch |err| {
            self.state = .closed;
            return err;
        };
    }

    fn pollInner(self: *Client, io: std.Io) CarrierError!void {
        if (self.state == .closed) return error.Closed;
        if (self.state == .connecting) {
            if (!try self.connection.stream.finishConnect(io)) return;
            self.state = .request;
        }
        if (self.state == .request) {
            var nonce: [16]u8 = undefined;
            io.randomSecure(&nonce) catch return error.RandomUnavailable;
            var key_text: [24]u8 = undefined;
            const encoded_key = std.base64.standard.Encoder.encode(&key_text, &nonce);
            self.accept = upgrade.accept(encoded_key);
            const request = std.fmt.bufPrint(&self.connection.tx,
                "GET /relay HTTP/1.1\r\nHost: {s}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++
                "Sec-WebSocket-Key: {s}\r\nSec-WebSocket-Version: 13\r\n" ++
                "Sec-WebSocket-Protocol: iroh-relay-v2\r\n\r\n",
                .{ self.host[0..self.host_len], encoded_key }) catch return error.BufferFull;
            self.connection.tx_end = request.len;
            self.state = .upgrade;
        }
        try self.connection.flush(io, .client);
        try self.connection.read(io);
        if (self.state == .upgrade) {
            const end = headerEnd(self.connection.rx[0..self.connection.rx_len]) orelse {
                if (self.connection.rx_len >= upgrade.max_header_length) return error.InvalidUpgrade;
                if (self.connection.eof) return error.UnexpectedEnd;
                return;
            };
            try verifyResponse(self.connection.rx[0..end], &self.accept);
            self.connection.consume(end);
            self.state = .challenge;
        }
        for (0..8) |_| {
            if (self.connection.busy()) return;
            const bytes = try self.connection.next(io, .client) orelse return;
            const message = try frame.decode(bytes, .v2);
            switch (self.state) {
                .challenge => switch (message) {
                    .server_challenge => |challenge| {
                        try self.connection.relay(.{ .client_auth = @import("client.zig").signChallenge(&self.secret, challenge) });
                        self.state = .confirm;
                    },
                    else => return error.UnexpectedMessage,
                },
                .confirm => switch (message) {
                    .server_confirms_auth => self.state = .ready,
                    else => return error.UnexpectedMessage,
                },
                .ready => switch (message) {
                    .relay_to_client_datagram, .relay_to_client_datagram_batch => |datagram| {
                        self.packet = .{ .source = datagram.node_id, .datagrams = datagram.datagrams };
                        return;
                    },
                    .ping => |ping| try self.connection.relay(.{ .pong = ping }),
                    .pong, .endpoint_gone, .restarting => {},
                    .status => |status| switch (status) {
                        .same_endpoint_id_connected => return error.Closed,
                        else => {},
                    },
                    else => return error.UnexpectedMessage,
                },
                else => return error.UnexpectedMessage,
            }
        }
    }
};

const Peer = struct {
    connection: Session,
    state: enum { upgrade, response, auth, confirming, ready } = .upgrade,
    challenge: frame.ServerChallenge = undefined,
    identity: ?NodeId = null,
    pending: ?frame.DatagramFrame = null,
};

pub const Server = struct {
    listener: tcp.Listener,
    address: SocketAddr,
    peers: [16]?Peer = .{null} ** 16,

    pub fn init(bind: SocketAddr) Error!Server {
        const listener = try tcp.Listener.init(bind);
        return .{ .listener = listener, .address = listener.local };
    }

    pub fn deinit(self: *Server) void {
        for (&self.peers) |*peer| {
            if (peer.*) |*active| active.connection.stream.close();
            peer.* = null;
        }
        self.listener.close();
    }

    pub fn poll(self: *Server, io: std.Io) Error!void {
        // Admission and servicing each have a fixed budget independent of peers' traffic.
        for (0..16) |_| {
            var stream = try self.listener.accept() orelse break;
            var admitted = false;
            for (&self.peers) |*peer| {
                if (peer.* == null) {
                    peer.* = .{ .connection = .{ .stream = stream } };
                    admitted = true;
                    break;
                }
            }
            if (!admitted) stream.close();
        }
        for (0..self.peers.len) |index| {
            if (self.peers[index] == null) continue;
            self.pollPeer(io, index) catch {
                self.peers[index].?.connection.stream.close();
                self.peers[index] = null;
            };
        }
    }

    fn pollPeer(self: *Server, io: std.Io, index: usize) Error!void {
        const peer = &self.peers[index].?;
        try peer.connection.flush(io, .server);
        if (peer.state == .confirming and !peer.connection.busy()) peer.state = .ready;
        if (peer.state == .response and !peer.connection.busy()) {
            io.randomSecure(&peer.challenge.challenge) catch return error.RandomUnavailable;
            try peer.connection.relay(.{ .server_challenge = peer.challenge });
            peer.state = .auth;
        }
        try peer.connection.read(io);
        if (peer.state == .upgrade) {
            const end = headerEnd(peer.connection.rx[0..peer.connection.rx_len]) orelse {
                if (peer.connection.rx_len >= upgrade.max_header_length) return error.InvalidUpgrade;
                if (peer.connection.eof) return error.UnexpectedEnd;
                return;
            };
            const request = try upgrade.parse(peer.connection.rx[0..end]);
            if (request.version != .v2) return error.InvalidUpgrade;
            const response = try upgrade.build(&peer.connection.tx, .v2, request.key_text);
            peer.connection.tx_end = response.len;
            peer.connection.consume(end);
            peer.state = .response;
            return;
        }
        if (peer.pending) |datagram| {
            if (!try self.forward(peer.identity.?, datagram)) return;
            peer.pending = null;
        }
        for (0..8) |_| {
            if (peer.connection.busy()) return;
            const bytes = try peer.connection.next(io, .server) orelse return;
            const message = try frame.decode(bytes, .v2);
            switch (peer.state) {
                .auth => switch (message) {
                    .client_auth => |auth| {
                        try @import("client.zig").verifyClientAuth(auth, peer.challenge);
                        // A new authenticated connection supersedes the old route.
                        for (&self.peers, 0..) |*other, other_index| {
                            if (other_index == index) continue;
                            if (other.*) |*active| {
                                if (active.identity) |identity| {
                                    if (std.meta.eql(identity, auth.node_id)) {
                                        active.connection.stream.close();
                                        other.* = null;
                                    }
                                }
                            }
                        }
                        peer.identity = auth.node_id;
                        try peer.connection.relay(.{ .server_confirms_auth = {} });
                        peer.state = .confirming;
                    },
                    else => return error.UnexpectedMessage,
                },
                .ready => switch (message) {
                    .client_to_relay_datagram, .client_to_relay_datagram_batch => |datagram| {
                        if (!try self.forward(peer.identity.?, datagram)) {
                            // Retain the message borrow; do not decode again until destination frees tx.
                            peer.pending = datagram;
                            return;
                        }
                    },
                    .ping => |ping| try peer.connection.relay(.{ .pong = ping }),
                    .pong => {},
                    else => return error.UnexpectedMessage,
                },
                else => return error.UnexpectedMessage,
            }
        }
    }

    fn forward(self: *Server, source: NodeId, datagram: frame.DatagramFrame) Error!bool {
        for (&self.peers) |*destination| {
            if (destination.*) |*active| {
                if (active.state != .ready) continue;
                if (!std.meta.eql(active.identity.?, datagram.node_id)) continue;
                if (active.connection.busy()) return false;
                const forwarded: frame.DatagramFrame = .{
                    .node_id = source, .datagrams = datagram.datagrams,
                };
                try active.connection.relay(if (datagram.datagrams.isBatch())
                    .{ .relay_to_client_datagram_batch = forwarded }
                else
                    .{ .relay_to_client_datagram = forwarded });
                return true;
            }
        }
        // No registered destination is available; report the actual missing route.
        for (&self.peers) |*candidate| {
            if (candidate.*) |*active| {
                if (active.state != .ready or !std.meta.eql(active.identity.?, source)) continue;
                if (active.connection.busy()) return false;
                try active.connection.relay(.{ .endpoint_gone = datagram.node_id });
                return true;
            }
        }
        return true;
    }
};

fn headerEnd(bytes: []const u8) ?usize {
    const end = std.mem.find(u8, bytes, "\r\n\r\n") orelse return null;
    return end + 4;
}

fn verifyResponse(bytes: []const u8, expected_accept: []const u8) Error!void {
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
        if (count > upgrade.max_fields or line.len > upgrade.max_field_length) return error.InvalidUpgrade;
        const colon = std.mem.findScalar(u8, line, ':') orelse return error.InvalidUpgrade;
        const name = line[0..colon];
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(name, "Sec-WebSocket-Accept")) {
            if (accepted or !std.mem.eql(u8, value, expected_accept)) return error.InvalidUpgrade;
            accepted = true;
        } else if (std.ascii.eqlIgnoreCase(name, "Upgrade")) {
            if (upgraded or !std.ascii.eqlIgnoreCase(value, "websocket")) return error.InvalidUpgrade;
            upgraded = true;
        } else if (std.ascii.eqlIgnoreCase(name, "Connection")) {
            if (connected) return error.InvalidUpgrade;
            var tokens = std.mem.splitScalar(u8, value, ',');
            while (tokens.next()) |token| {
                if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, token, " \t"), "upgrade")) connected = true;
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

test "authenticated websocket relay forwards copied datagrams with authenticated source" {
    const io = std.testing.io;
    var server = try Server.init(.{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 0 });
    defer server.deinit();
    const first_secret = try key.SecretKey.fromSeed(.{1} ** 32);
    const second_secret = try key.SecretKey.fromSeed(.{2} ** 32);
    var first = try Client.init(.{ .address = server.address, .host = "localhost", .secret = first_secret });
    defer first.deinit();
    var second = try Client.init(.{ .address = server.address, .host = "localhost", .secret = second_secret });
    defer second.deinit();
    for (0..10000) |_| {
        try server.poll(io);
        try first.poll(io);
        try second.poll(io);
        if (first.isReady() and second.isReady()) break;
    }
    try std.testing.expect(first.isReady());
    try std.testing.expect(second.isReady());
    var payload = [_]u8{ 1, 2, 3, 4 };
    try first.send(second_secret.nodeId(), &payload);
    payload[0] = 9;
    try std.testing.expectError(error.WouldBlock, first.send(second_secret.nodeId(), "occupied"));
    for (0..10000) |_| {
        try first.poll(io);
        try server.poll(io);
        try second.poll(io);
        if (try second.receive()) |packet| {
            try std.testing.expectEqual(first_secret.nodeId(), packet.source);
            try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, packet.datagrams.contents);
            return;
        }
    }
    return error.TestUnexpectedResult;
}

test "client refuses header injection before opening TCP" {
    try std.testing.expectError(error.InvalidHost, Client.init(.{
        .address = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 1 },
        .host = "relay\r\nInjected: value",
        .secret = try key.SecretKey.fromSeed(.{3} ** 32),
    }));
}

test "server disconnects invalid authentication without failing listener" {
    const io = std.testing.io;
    var server = try Server.init(.{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 0 });
    defer server.deinit();
    var stream = try tcp.Tcp.create(server.address);
    defer stream.close();
    var connected = try stream.startConnect();
    for (0..10000) |_| {
        if (connected) break;
        connected = try stream.finishConnect(io);
    }
    try std.testing.expect(connected);
    var raw: Session = .{ .stream = stream };
    const request = "GET /relay HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n" ++
        "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: iroh-relay-v2\r\n\r\n";
    @memcpy(raw.tx[0..request.len], request);
    raw.tx_end = request.len;
    for (0..1000) |_| {
        try raw.flush(io, .client);
        try server.poll(io);
    }
    var secret = try SecretKey.fromSeed(.{ 4 } ** 32);
    defer secret.deinit();
    try raw.relay(.{ .client_auth = .{
        .node_id = secret.nodeId(), .signature = key.Signature.fromBytes(.{0} ** 64),
    } });
    for (0..1000) |_| {
        if (raw.busy()) try raw.flush(io, .client);
        try server.poll(io);
    }
    for (server.peers) |peer| try std.testing.expect(peer == null);
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

test "destination backpressure retains authenticated pending datagram without overwriting tx" {
    var source_secret = try SecretKey.fromSeed(.{ 5 } ** 32);
    defer source_secret.deinit();
    var target_secret = try SecretKey.fromSeed(.{ 6 } ** 32);
    defer target_secret.deinit();
    var server: Server = .{
        .listener = undefined,
        .address = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 0 },
    };
    server.peers[0] = .{
        .connection = .{ .stream = undefined },
        .state = .ready, .identity = source_secret.nodeId(),
    };
    server.peers[1] = .{
        .connection = .{ .stream = undefined, .tx_end = 1 },
        .state = .ready, .identity = target_secret.nodeId(),
    };
    const datagram: frame.DatagramFrame = .{
        .node_id = target_secret.nodeId(),
        .datagrams = .{ .ecn = null, .segment_size = null, .contents = "pending" },
    };
    try std.testing.expect(!try server.forward(source_secret.nodeId(), datagram));
    try std.testing.expectEqual(@as(usize, 1), server.peers[1].?.connection.tx_end);
    server.peers[0].?.pending = datagram;
    server.peers[1].?.connection.tx_end = 0;
    try std.testing.expect(try server.forward(source_secret.nodeId(), server.peers[0].?.pending.?));
    const destination = &server.peers[1].?.connection;
    const received = try frame.decode(destination.tx[@import("ws_frame.zig").max_header_length..]
        [0..destination.pending_payload.?], .v2);
    try std.testing.expectEqual(source_secret.nodeId(), received.relay_to_client_datagram.node_id);
    try std.testing.expectEqualStrings("pending", received.relay_to_client_datagram.datagrams.contents);
}

test "server retries authenticated pending datagram after source EOF" {
    var source_secret = try SecretKey.fromSeed(.{ 7 } ** 32);
    defer source_secret.deinit();
    var target_secret = try SecretKey.fromSeed(.{ 8 } ** 32);
    defer target_secret.deinit();
    var server: Server = .{
        .listener = undefined,
        .address = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 0 },
    };
    server.peers[0] = .{
        .connection = .{ .stream = undefined, .eof = true },
        .state = .ready, .identity = source_secret.nodeId(),
        .pending = .{
            .node_id = target_secret.nodeId(),
            .datagrams = .{ .ecn = null, .segment_size = null, .contents = "after-eof" },
        },
    };
    server.peers[1] = .{
        .connection = .{ .stream = undefined, .tx_end = 1 },
        .state = .ready, .identity = target_secret.nodeId(),
    };
    try server.pollPeer(std.testing.io, 0);
    try std.testing.expect(server.peers[0].?.pending != null);
    server.peers[1].?.connection.tx_end = 0;
    try std.testing.expectError(error.Closed, server.pollPeer(std.testing.io, 0));
    const destination = &server.peers[1].?.connection;
    const received = try frame.decode(destination.tx[@import("ws_frame.zig").max_header_length..]
        [0..destination.pending_payload.?], .v2);
    try std.testing.expectEqualStrings("after-eof",
        received.relay_to_client_datagram.datagrams.contents);
}

test "Client delivers coalesced datagrams at EOF one receive per poll" {
    const ws = @import("ws_frame.zig");
    var client: Client = .{
        .connection = .{ .stream = undefined, .eof = true },
        .secret = try SecretKey.fromSeed(.{ 9 } ** 32),
        .host_len = 0,
        .state = .ready,
    };
    defer client.secret.deinit();
    var payload: [256]u8 = undefined;
    const first = try frame.encode(.{ .relay_to_client_datagram = .{
        .node_id = client.secret.nodeId(),
        .datagrams = .{ .ecn = null, .segment_size = null, .contents = "first" },
    } }, .v2, &payload);
    const first_wire = try ws.encode(&client.connection.rx, .server,
        .{ .fin = true, .opcode = .binary, .key = .{0} ** 4 }, first);
    const second = try frame.encode(.{ .relay_to_client_datagram = .{
        .node_id = client.secret.nodeId(),
        .datagrams = .{ .ecn = null, .segment_size = null, .contents = "second" },
    } }, .v2, &payload);
    const second_wire = try ws.encode(client.connection.rx[first_wire.len..], .server,
        .{ .fin = true, .opcode = .binary, .key = .{0} ** 4 }, second);
    client.connection.rx_len = first_wire.len + second_wire.len;
    try client.poll(std.testing.io);
    const first_packet = (try client.receive()).?;
    try std.testing.expectEqualStrings("first", first_packet.datagrams.contents);
    try std.testing.expectEqual(@as(?Packet, null), try client.receive());
    try client.poll(std.testing.io);
    const second_packet = (try client.receive()).?;
    try std.testing.expectEqualStrings("second", second_packet.datagrams.contents);
    try std.testing.expectError(error.Closed, client.poll(std.testing.io));
}

test "incomplete HTTP upgrade at EOF fails rather than holding a session forever" {
    var client: Client = .{
        .connection = .{ .stream = undefined, .eof = true },
        .secret = try SecretKey.fromSeed(.{ 10 } ** 32),
        .host_len = 0, .state = .upgrade,
    };
    defer client.secret.deinit();
    try std.testing.expectError(error.UnexpectedEnd, client.poll(std.testing.io));
    var server: Server = .{
        .listener = undefined,
        .address = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 0 },
    };
    server.peers[0] = .{ .connection = .{ .stream = undefined, .eof = true } };
    try std.testing.expectError(error.UnexpectedEnd, server.pollPeer(std.testing.io, 0));
}
