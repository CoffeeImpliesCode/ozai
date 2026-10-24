//! Owns relay listener admission and bounded peer servicing.
//! The injected execution context must outlive the server and every accepted connection.
const std = @import("std");
const key = @import("../base/key.zig");
const frame = @import("frame.zig");
const tcp = @import("../transport/tcp.zig");
const listener = @import("../transport/tcp_listener.zig");
const Execution = @import("../transport/tcp_execution.zig").Execution;
const SocketAddr = @import("../base/addr.zig").SocketAddr;
const upgrade = @import("http_upgrade.zig");
const session = @import("tcp_session.zig");
const processor = @import("tcp_processor.zig");
const ws = @import("ws_frame.zig");
const relay_client = @import("client.zig");
const Session = session.Session;
pub const Error = session.Error;
pub const NodeId = key.NodeId;
pub const SecretKey = key.SecretKey;
const http = @import("tcp_http.zig");
const forwarding = @import("tcp_forward.zig");
const Peer = forwarding.Peer;
const Client = @import("tcp_client.zig").Client;
const Packet = @import("tcp_client.zig").Packet;
pub const Server = struct {
    listener: listener.Listener,
    address: SocketAddr,
    peers: [16]?Peer = @splat(null),

    pub fn init(io: std.Io, bind: SocketAddr, execution: Execution) Error!Server {
        const bound = try listener.Listener.init(io, bind, execution);
        return .{ .listener = bound, .address = bound.local };
    }

    pub fn deinit(self: *Server) void {
        for (&self.peers) |*peer| {
            if (peer.*) |*active| active.connection.close();
            peer.* = null;
        }
        self.listener.close();
        self.* = undefined;
    }

    pub fn poll(self: *Server, io: std.Io) Error!void {
        // Admission and servicing each have a fixed budget independent of peers' traffic.
        for (0..16) |_| {
            var stream = try self.listener.accept(io) orelse break;
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
        for (0..self.peers.len) |index| self.servicePeer(io, index);
    }

    fn servicePeer(self: *Server, io: std.Io, index: usize) void {
        if (self.peers[index]) |*peer| {
            self.pollPeer(io, index) catch {
                // Replacement removes only other slots; this borrow still owns its descriptor.
                peer.connection.close();
                self.peers[index] = null;
            };
        }
    }

    fn pollPeer(self: *Server, io: std.Io, index: usize) Error!void {
        // Admission owns slot removal; servicing cannot remove its own peer.
        const peer = if (self.peers[index]) |*active|
            active
        else
            @panic("pollPeer requires an admitted peer");
        try peer.connection.flush(io, .server);
        if (!peer.connection.busy()) {
            if (peer.state == .response)
                io.randomSecure(&peer.challenge.challenge) catch return error.RandomUnavailable;
            const result = try processor.server(peer.state, .drained, peer.challenge);
            for (result.actions[0..result.count]) |action| {
                switch (action) {
                    .relay => |outgoing| try peer.connection.relay(outgoing),
                    else => unreachable,
                }
            }
            peer.state = result.state;
        }
        try peer.connection.read(io);
        if (peer.state == .upgrade) {
            const end = http.headerEnd(peer.connection.rx[0..peer.connection.rx_len]) orelse {
                if (peer.connection.rx_len >=
                    upgrade.max_header_length) return error.InvalidUpgrade;
                if (peer.connection.eof) return error.UnexpectedEnd;
                return;
            };
            const request = try upgrade.parse(peer.connection.rx[0..end]);
            const result = try processor.server(peer.state, .{
                .upgrade = request.version == .v2,
            }, peer.challenge);
            for (result.actions[0..result.count]) |action| {
                switch (action) {
                    .response => {
                        const response = try upgrade.build(
                            &peer.connection.tx,
                            .v2,
                            request.key_text,
                        );
                        peer.connection.tx_end = response.len;
                    },
                    else => unreachable,
                }
            }
            peer.connection.consume(end);
            peer.state = result.state;
            return;
        }
        if (peer.pending) |datagram| {
            // Pending datagrams are retained only after authentication reaches ready.
            const identity = peer.identity orelse
                @panic("pending datagram requires an authenticated identity");
            if (!try forwarding.forward(&self.peers, identity, datagram)) return;
            peer.pending = null;
        }
        for (0..8) |_| {
            if (peer.connection.busy()) return;
            const bytes = try peer.connection.next(.server) orelse return;
            const message = try frame.decode(bytes, .v2);
            const result = try processor.server(
                peer.state,
                .{ .message = message },
                peer.challenge,
            );
            for (result.actions[0..result.count]) |action| {
                switch (action) {
                    .register => |identity| forwarding.register(&self.peers, index, peer, identity),
                    .relay => |outgoing| try peer.connection.relay(outgoing),
                    .forward => |datagram| {
                        const identity = peer.identity orelse
                            @panic("ready peer requires an authenticated identity");
                        if (!try forwarding.forward(&self.peers, identity, datagram)) {
                            // Preserve the decode borrow until forwarding succeeds.
                            peer.pending = datagram;
                            return;
                        }
                    },
                    else => unreachable,
                }
            }
            peer.state = result.state;
        }
    }
};

test "authenticated websocket relay forwards copied datagrams with authenticated source" {
    const io = std.testing.io;
    var server = try Server.init(io, .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 0 }, Execution.native);
    defer server.deinit();
    const first_secret = try key.SecretKey.fromSeed(@splat(1));
    const second_secret = try key.SecretKey.fromSeed(@splat(2));
    var first = try Client.init(io, .{
        .address = server.address,
        .execution = Execution.native,
        .host = "localhost",
        .secret = first_secret,
    });
    defer first.deinit();
    var second = try Client.init(io, .{
        .address = server.address,
        .execution = Execution.native,
        .host = "localhost",
        .secret = second_secret,
    });
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
    try std.testing.expectError(error.InvalidHost, Client.init(std.testing.io, .{
        .execution = Execution.native,
        .address = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 1 },
        .host = "relay\r\nInjected: value",
        .secret = try key.SecretKey.fromSeed(@splat(3)),
    }));
}

test "server disconnects invalid authentication without failing listener" {
    const io = std.testing.io;
    var server = try Server.init(io, .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 0 }, Execution.native);
    defer server.deinit();
    var stream = try tcp.Tcp.create(io, server.address, Execution.native);
    defer stream.close();
    var connected = try stream.startConnect(io);
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
    var secret = try SecretKey.fromSeed(@splat(4));
    defer secret.deinit();
    try raw.relay(.{ .client_auth = .{
        .node_id = secret.nodeId(),
        .signature = key.Signature.fromBytes(@splat(0)),
    } });
    for (0..1000) |_| {
        if (raw.busy()) try raw.flush(io, .client);
        try server.poll(io);
    }
    for (server.peers) |peer| try std.testing.expect(peer == null);
}

test "destination backpressure retains authenticated pending datagram without overwriting tx" {
    var source_secret = try SecretKey.fromSeed(@splat(5));
    defer source_secret.deinit();
    var target_secret = try SecretKey.fromSeed(@splat(6));
    defer target_secret.deinit();
    var server: Server = .{
        .listener = undefined,
        .address = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 0 },
    };
    server.peers[0] = .{
        .connection = .{ .stream = undefined },
        .state = .ready,
        .identity = source_secret.nodeId(),
    };
    server.peers[1] = .{
        .connection = .{ .stream = undefined, .tx_end = 1 },
        .state = .ready,
        .identity = target_secret.nodeId(),
    };
    const datagram: frame.DatagramFrame = .{
        .node_id = target_secret.nodeId(),
        .datagrams = .{ .ecn = null, .segment_size = null, .contents = "pending" },
    };
    try std.testing.expect(!try forwarding.forward(&server.peers, source_secret.nodeId(), datagram));
    const source = if (server.peers[0]) |*peer| peer else return error.TestUnexpectedResult;
    const target = if (server.peers[1]) |*peer| peer else return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 1), target.connection.tx_end);
    source.pending = datagram;
    target.connection.tx_end = 0;
    const pending = source.pending orelse return error.TestUnexpectedResult;
    try std.testing.expect(try forwarding.forward(&server.peers, source_secret.nodeId(), pending));
    const destination = &target.connection;
    const payload_length = destination.pending_payload orelse return error.TestUnexpectedResult;
    const received = try frame.decode(
        destination.tx[ws.max_header_length..][0..payload_length],
        .v2,
    );
    try std.testing.expectEqual(source_secret.nodeId(), received.relay_to_client_datagram.node_id);
    try std.testing.expectEqualStrings(
        "pending",
        received.relay_to_client_datagram.datagrams.contents,
    );
}

test "server retries authenticated pending datagram after source EOF" {
    var source_secret = try SecretKey.fromSeed(@splat(7));
    defer source_secret.deinit();
    var target_secret = try SecretKey.fromSeed(@splat(8));
    defer target_secret.deinit();
    var server: Server = .{
        .listener = undefined,
        .address = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 0 },
    };
    server.peers[0] = .{
        .connection = .{ .stream = undefined, .eof = true },
        .state = .ready,
        .identity = source_secret.nodeId(),
        .pending = .{
            .node_id = target_secret.nodeId(),
            .datagrams = .{ .ecn = null, .segment_size = null, .contents = "after-eof" },
        },
    };
    server.peers[1] = .{
        .connection = .{ .stream = undefined, .tx_end = 1 },
        .state = .ready,
        .identity = target_secret.nodeId(),
    };
    try server.pollPeer(std.testing.io, 0);
    const source = if (server.peers[0]) |*peer| peer else return error.TestUnexpectedResult;
    const target = if (server.peers[1]) |*peer| peer else return error.TestUnexpectedResult;
    try std.testing.expect(source.pending != null);
    target.connection.tx_end = 0;
    try std.testing.expectError(error.Closed, server.pollPeer(std.testing.io, 0));
    const destination = &target.connection;
    const payload_length = destination.pending_payload orelse return error.TestUnexpectedResult;
    const received = try frame.decode(
        destination.tx[ws.max_header_length..][0..payload_length],
        .v2,
    );
    try std.testing.expectEqualStrings(
        "after-eof",
        received.relay_to_client_datagram.datagrams.contents,
    );
}

test "Client delivers coalesced datagrams at EOF one receive per poll" {
    var injected: FailingTransport = .{};
    var client: Client = .{
        .address = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 1 },
        .connection = .{
            .stream = undefined,
            .eof = true,
            .transport = injected.transport(),
        },
        .secret = try SecretKey.fromSeed(@splat(9)),
        .host_len = 0,
        .state = .ready,
    };
    defer client.secret.deinit();
    var payload: [256]u8 = undefined;
    const first = try frame.encode(.{ .relay_to_client_datagram = .{
        .node_id = client.secret.nodeId(),
        .datagrams = .{ .ecn = null, .segment_size = null, .contents = "first" },
    } }, .v2, &payload);
    const first_wire = try ws.encode(
        &client.connection.rx,
        .server,
        .{ .fin = true, .opcode = .binary, .key = @splat(0) },
        first,
    );
    const second = try frame.encode(.{ .relay_to_client_datagram = .{
        .node_id = client.secret.nodeId(),
        .datagrams = .{ .ecn = null, .segment_size = null, .contents = "second" },
    } }, .v2, &payload);
    const second_wire = try ws.encode(
        client.connection.rx[first_wire.len..],
        .server,
        .{ .fin = true, .opcode = .binary, .key = @splat(0) },
        second,
    );
    client.connection.rx_len = first_wire.len + second_wire.len;
    try client.poll(std.testing.io);
    const first_packet = (try client.receive()) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("first", first_packet.datagrams.contents);
    try std.testing.expectEqual(@as(?Packet, null), try client.receive());
    try client.poll(std.testing.io);
    const second_packet = (try client.receive()) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("second", second_packet.datagrams.contents);
    try std.testing.expectError(error.Closed, client.poll(std.testing.io));
}

test "incomplete HTTP upgrade at EOF fails rather than holding a session forever" {
    var injected: FailingTransport = .{};
    var client: Client = .{
        .address = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 1 },
        .connection = .{
            .stream = undefined,
            .eof = true,
            .transport = injected.transport(),
        },
        .secret = try SecretKey.fromSeed(@splat(10)),
        .host_len = 0,
        .state = .upgrade,
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

const FailingTransport = struct {
    writes: usize = 0,
    closes: usize = 0,

    fn read(_: std.Io, _: *anyopaque, _: []u8) Error!usize {
        return error.WouldBlock;
    }

    fn write(_: std.Io, context: *anyopaque, _: []const u8) Error!usize {
        const self: *FailingTransport = @ptrCast(@alignCast(context));
        self.writes += 1;
        return error.Closed;
    }

    fn close(context: *anyopaque) void {
        const self: *FailingTransport = @ptrCast(@alignCast(context));
        self.closes += 1;
    }

    fn transport(self: *FailingTransport) session.Transport {
        return .{ .context = self, .read = read, .write = write, .close = close };
    }
};

test "client authentication action write failure closes session exactly once" {
    var injected: FailingTransport = .{};
    var client: Client = .{
        .address = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 1 },
        .connection = .{ .stream = undefined, .transport = injected.transport() },
        .secret = try SecretKey.fromSeed(@splat(41)),
        .host_len = 0,
        .state = .challenge,
    };
    defer client.deinit();
    var payload: [128]u8 = undefined;
    const challenge = try frame.encode(.{
        .server_challenge = .{ .challenge = @splat(43) },
    }, .v2, &payload);
    const wire = try ws.encode(&client.connection.rx, .server, .{
        .fin = true,
        .opcode = .binary,
        .key = @splat(0),
    }, challenge);
    client.connection.rx_len = wire.len;
    try client.poll(std.testing.io);
    try std.testing.expectEqual(processor.ClientState.confirm, client.state);
    try std.testing.expect(client.connection.busy());
    try std.testing.expectError(error.Closed, client.poll(std.testing.io));
    try std.testing.expectEqual(processor.ClientState.closed, client.state);
    try std.testing.expectEqual(@as(usize, 1), injected.writes);
    try std.testing.expectEqual(@as(usize, 1), injected.closes);
    try std.testing.expectError(error.Closed, client.poll(std.testing.io));
    try std.testing.expectEqual(@as(usize, 1), injected.closes);
}

test "server confirmation action write failure removes authenticated peer" {
    var injected: FailingTransport = .{};
    var server: Server = .{
        .listener = undefined,
        .address = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 0 },
    };
    var secret = try SecretKey.fromSeed(@splat(47));
    defer secret.deinit();
    const challenge: frame.ServerChallenge = .{ .challenge = @splat(53) };
    server.peers[0] = .{
        .connection = .{ .stream = undefined, .transport = injected.transport() },
        .state = .auth,
        .challenge = challenge,
    };
    const peer = if (server.peers[0]) |*active|
        active
    else
        return error.TestUnexpectedResult;
    var payload: [256]u8 = undefined;
    const auth = try frame.encode(.{
        .client_auth = relay_client.signChallenge(&secret, challenge),
    }, .v2, &payload);
    const wire = try ws.encode(&peer.connection.rx, .client, .{
        .fin = true,
        .opcode = .binary,
        .key = .{ 1, 2, 3, 4 },
    }, auth);
    peer.connection.rx_len = wire.len;
    server.servicePeer(std.testing.io, 0);
    const authenticated = if (server.peers[0]) |*active|
        active
    else
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(processor.ServerState.confirming, authenticated.state);
    const identity = authenticated.identity orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(secret.nodeId(), identity);
    server.servicePeer(std.testing.io, 0);
    try std.testing.expect(server.peers[0] == null);
    try std.testing.expectEqual(@as(usize, 1), injected.writes);
    try std.testing.expectEqual(@as(usize, 1), injected.closes);
}
