const std = @import("std");
const base_addr = @import("../base/addr.zig");
const addr_map = @import("../transport/addr_map.zig");
const ula = @import("../base/ula.zig");
const base_key = @import("../base/key.zig");
const dial_route = @import("../transport/dial_route.zig");
const carrier = @import("../relay/tcp_client.zig");
const server_carrier = @import("../relay/tcp_server.zig");
const tcp_execution = @import("../transport/tcp_execution.zig");
const frame = @import("../relay/frame.zig");
const ws = @import("../relay/ws_frame.zig");

pub const Config = struct {
    client: ?carrier.Config = null,
    serve: ?base_addr.SocketAddr = null,
    /// Borrowed execution for the serving carrier; the client carries its own.
    execution: tcp_execution.Execution = .native,
};

pub const Error = carrier.Error || server_carrier.Error || error{
    UnmappedPeer,
    UnsupportedMappedTransport,
    RelayUnavailable,
    RelayQueueFull,
    RelayTargetMismatch,
    DatagramTooLarge,
    UnreadDatagrams,
};

pub const Datagram = struct {
    source: base_key.NodeId,
    bytes: []const u8,
    ecn: ?frame.Ecn,
};

const queue_capacity = 16;
const Queued = struct {
    target: base_key.NodeId,
    length: usize,
    bytes: [frame.max_packet_size - 33]u8,
};

/// The TCP carrier's lifetime is independent of each inner QUIC connection.
pub const State = struct {
    client: ?carrier.Client = null,
    server: ?server_carrier.Server = null,
    incoming: ?carrier.Packet = null,
    queue: [queue_capacity]Queued = undefined,
    head: usize = 0,
    count: usize = 0,

    pub fn init(self: *State, io: std.Io, config: Config) Error!void {
        self.* = .{};
        errdefer self.deinit();
        if (config.serve) |address| {
            self.server = try server_carrier.Server.init(io, address, config.execution);
        }
        if (config.client) |client| self.client = try carrier.Client.init(io, client);
    }

    /// Release the carriers once; the state is invalid until init is called again.
    pub fn deinit(self: *State) void {
        if (self.client) |*client| client.deinit();
        if (self.server) |*server| server.deinit();
        self.* = undefined;
    }

    /// Drain receive() before polling again: its bytes borrow the carrier buffer.
    pub fn poll(self: *State, io: std.Io) Error!void {
        if (self.incoming != null) return error.UnreadDatagrams;
        if (self.server) |*server| try server.poll(io);
        if (self.client) |*client| {
            try client.poll(io);
            if (self.count != 0 and client.isReady()) {
                const pending = &self.queue[self.head];
                client.send(pending.target, pending.bytes[0..pending.length]) catch |err| {
                    if (err == error.WouldBlock) return;
                    return err;
                };
                self.head = (self.head + 1) % queue_capacity;
                self.count -= 1;
            }
        }
    }

    /// Flush only output before graceful shutdown. WouldBlock preserves all unsent bytes.
    /// No handshake or inbound work is performed; an unready carrier cannot drain its queue.
    pub fn flush(self: *State, io: std.Io) Error!void {
        const client = if (self.client) |*value| value else {
            if (self.count != 0) return error.RelayUnavailable;
            return;
        };
        // At most one current frame plus the fixed datagram queue can be emitted.
        for (0..queue_capacity + 1) |_| {
            const connection = &client.connection;
            var remaining = if (connection.pending_payload) |length|
                ws.headerLen(length, true) + length
            else
                connection.tx_end - connection.tx_pos;
            while (connection.busy()) {
                try connection.flush(io, .client);
                const after = connection.tx_end - connection.tx_pos;
                // Every successful pass consumes bytes, bounding work by the pending frame.
                if (after >= remaining) return error.WouldBlock;
                remaining = after;
            }
            if (self.count == 0) return;
            const pending = &self.queue[self.head];
            try client.send(pending.target, pending.bytes[0..pending.length]);
            self.head = (self.head + 1) % queue_capacity;
            self.count -= 1;
        }
        unreachable;
    }

    /// One native GRO segment, borrowed until the next poll. ECN is preserved.
    pub fn receive(self: *State) Error!?Datagram {
        for (0..queue_capacity) |_| {
            if (self.incoming) |*packet| {
                if (packet.datagrams.contents.len != 0) {
                    const segment = packet.datagrams.takeSegments(1);
                    const result: Datagram = .{
                        .source = packet.source,
                        .bytes = segment.contents,
                        .ecn = segment.ecn,
                    };
                    if (packet.datagrams.contents.len == 0) self.incoming = null;
                    return result;
                }
                self.incoming = null;
            }
            const client = if (self.client) |*value| value else return null;
            self.incoming = try client.receive() orelse return null;
        }
        return null;
    }

    /// Admit the sole supported carrier before creating any inner connection or mapping.
    pub fn admit(
        self: *const State,
        target: base_addr.TransportAddr,
    ) error{ RelayUnavailable, RelayTargetMismatch }!void {
        switch (target) {
            .ip, .custom => {},
            .relay => |relay| {
                const client = if (self.client) |*value| value else return error.RelayUnavailable;
                try admitRelay(client, &relay);
            },
        }
    }

    /// False means real IP only. Every synthetic-address error stays off UDP.
    pub fn sendMapped(
        self: *State,
        map: *const addr_map.MappedAddrs,
        peer: base_addr.SocketAddr,
        datagram: []const u8,
    ) Error!bool {
        const target = try mappedTarget(map, peer) orelse return false;
        const client = if (self.client) |*value| value else return error.RelayUnavailable;
        if (map.relayTarget(peer.ip.v6)) |relay| try admitRelay(client, relay);
        if (datagram.len > self.queue[0].bytes.len) return error.DatagramTooLarge;
        if (self.count == 0 and client.isReady()) {
            client.send(target, datagram) catch |err| {
                if (err != error.WouldBlock) return err;
                try self.enqueue(target, datagram);
                return true;
            };
            return true;
        }
        try self.enqueue(target, datagram);
        return true;
    }

    fn enqueue(self: *State, target: base_key.NodeId, datagram: []const u8) Error!void {
        if (self.count == queue_capacity) return error.RelayQueueFull;
        const entry = &self.queue[(self.head + self.count) % queue_capacity];
        entry.target = target;
        entry.length = datagram.len;
        @memcpy(entry.bytes[0..datagram.len], datagram);
        self.count += 1;
    }
};

fn admitRelay(
    client: *const carrier.Client,
    target: *const base_addr.RelayUrl,
) error{RelayTargetMismatch}!void {
    // The carrier implements plaintext HTTP upgrade only, never HTTPS/TLS.
    if (target.scheme != .http or target.port != client.address.port) {
        return error.RelayTargetMismatch;
    }
    const host = client.host[0..client.host_len];
    const target_host = target.hostSlice();
    if (!std.mem.eql(u8, host, target_host)) {
        if (host.len <= target_host.len or
            !std.mem.startsWith(u8, host, target_host) or host[target_host.len] != ':')
        {
            return error.RelayTargetMismatch;
        }
        const port = std.fmt.parseInt(u16, host[target_host.len + 1 ..], 10) catch
            return error.RelayTargetMismatch;
        if (port != client.address.port) return error.RelayTargetMismatch;
    }
    const literal = target.socketAddr() catch return;
    if (literal.ip.order(client.address.ip) != .eq) return error.RelayTargetMismatch;
}

fn hostBytes(host: []const u8) [256]u8 {
    var bytes: [256]u8 = @splat(0);
    @memcpy(bytes[0..host.len], host);
    return bytes;
}

fn mappedTarget(
    map: *const addr_map.MappedAddrs,
    peer: base_addr.SocketAddr,
) error{ UnmappedPeer, UnsupportedMappedTransport }!?base_key.NodeId {
    if (ula.classify(peer) == .ip) return null;
    return switch (dial_route.ownerOf(map, peer) orelse return error.UnmappedPeer) {
        .any_path => |node| node,
        .relay, .custom => error.UnsupportedMappedTransport,
    };
}

test "unowned virtual peer is never admitted to UDP sender" {
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(std.testing.allocator);
    const virtual = ula.socketAddrFor(.relay, @splat(7));
    try std.testing.expectError(error.UnmappedPeer, mappedTarget(&map, virtual));
}

test "only an ordinary IP can fall through to UDP sender" {
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(std.testing.allocator);
    const direct: base_addr.SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 7777 };
    try std.testing.expectEqual(null, try mappedTarget(&map, direct));
    try std.testing.expectError(
        error.UnmappedPeer,
        mappedTarget(&map, ula.socketAddrFor(.custom, @splat(9))),
    );
}

test "mapped peer without a carrier reports unavailable, never falls through UDP" {
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(std.testing.allocator);
    var generator = std.Random.DefaultPrng.init(19);
    const secret = try base_key.SecretKey.fromSeed(@splat(3));
    const peer = secret.nodeId();
    const octets = try map.get(std.testing.allocator, .{ .any_path = peer }, generator.random());
    const socket = ula.socketAddrFor(.any_path, addr_map.hostBitsOf(octets));
    var state: State = .{};
    try std.testing.expectError(error.RelayUnavailable, state.sendMapped(&map, socket, "packet"));
}

test "native GRO ingress delivers full segments and the short tail under one origin" {
    const secret = try base_key.SecretKey.fromSeed(@splat(5));
    const source = secret.nodeId();
    var state: State = .{ .incoming = .{
        .source = source,
        .datagrams = .{ .ecn = null, .segment_size = 3, .contents = "abcdefgh" },
    } };
    for ([_][]const u8{ "abc", "def", "gh" }) |expected| {
        const datagram = try state.receive() orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(source, datagram.source);
        try std.testing.expectEqualSlices(u8, expected, datagram.bytes);
    }
    try std.testing.expectEqual(null, try state.receive());
}

test "obsolete per-relay virtual key cannot select the canonical peer carrier" {
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(std.testing.allocator);
    var generator = std.Random.DefaultPrng.init(29);
    const secret = try base_key.SecretKey.fromSeed(@splat(6));
    const octets = try map.get(std.testing.allocator, .{ .relay = .{
        .relay = try base_addr.RelayUrl.parse("http://relay.example/"),
        .node = secret.nodeId(),
    } }, generator.random());
    const socket = ula.socketAddrFor(.relay, addr_map.hostBitsOf(octets));
    try std.testing.expectError(error.UnsupportedMappedTransport, mappedTarget(&map, socket));
}

const CloseTransport = struct {
    // A flush drains one current Session frame plus the entire bounded datagram queue.
    const capture_capacity = (queue_capacity + 1) *
        (@import("../relay/tcp_session.zig").capacity + ws.max_header_length);
    bytes: [capture_capacity]u8 = undefined,
    length: usize = 0,
    write_limit: usize = 3,
    blocked: bool = false,
    writes: usize = 0,
    reads: usize = 0,
    closes: usize = 0,

    fn read(_: std.Io, context: *anyopaque, _: []u8) carrier.Error!usize {
        const self: *CloseTransport = @ptrCast(@alignCast(context));
        self.reads += 1;
        return error.WouldBlock;
    }

    fn write(_: std.Io, context: *anyopaque, bytes: []const u8) carrier.Error!usize {
        const self: *CloseTransport = @ptrCast(@alignCast(context));
        std.debug.assert(self.closes == 0);
        self.writes += 1;
        if (self.blocked) return error.WouldBlock;
        const remaining = self.bytes.len - self.length;
        if (remaining == 0) return error.WouldBlock;
        const count = @min(bytes.len, self.write_limit, remaining);
        @memcpy(self.bytes[self.length..][0..count], bytes[0..count]);
        self.length += count;
        return count;
    }

    fn close(context: *anyopaque) void {
        const self: *CloseTransport = @ptrCast(@alignCast(context));
        self.closes += 1;
    }

    fn client(self: *CloseTransport) !carrier.Client {
        return .{
            .connection = .{
                .stream = undefined,
                .transport = .{
                    .context = self,
                    .read = read,
                    .write = write,
                    .close = close,
                },
            },
            .secret = try base_key.SecretKey.fromSeed(@splat(31)),
            .address = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 80 },
            .host = hostBytes("relay-a.example"),
            .host_len = "relay-a.example".len,
            .state = .ready,
        };
    }
};

test "relay target mismatch rejects egress before the configured carrier queue" {
    // The real route resolver must not dispatch relay B through the sole carrier at A.
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(std.testing.allocator);
    var generator = std.Random.DefaultPrng.init(43);
    const secret = try base_key.SecretKey.fromSeed(@splat(47));
    const route = try dial_route.resolveRoute(
        std.testing.allocator,
        &map,
        .{ .relay = try base_addr.RelayUrl.parse("http://relay-b.example/") },
        secret.nodeId(),
        generator.random(),
    );
    var transport: CloseTransport = .{};
    var state: State = .{ .client = try transport.client() };
    defer state.deinit();
    const client = &state.client.?;
    const host = "relay-a.example";
    @memcpy(client.host[0..host.len], host);
    client.host_len = host.len;
    client.state = .request;
    try std.testing.expectError(
        error.RelayTargetMismatch,
        state.sendMapped(&map, route.socket, "must not reach relay A"),
    );
    try std.testing.expectEqual(@as(usize, 0), state.count);
}

test "canonical relay ingress replies use the sole carrier without losing ordinary UDP" {
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(std.testing.allocator);
    var generator = std.Random.DefaultPrng.init(46);
    const secret = try base_key.SecretKey.fromSeed(@splat(51));
    const ingress = try map.get(
        std.testing.allocator,
        .{ .any_path = secret.nodeId() },
        generator.random(),
    );
    try std.testing.expectEqual(null, map.relayTarget(ingress));
    var transport: CloseTransport = .{};
    var state: State = .{ .client = try transport.client() };
    defer state.deinit();
    state.client.?.state = .request;
    const mapped = ula.socketAddrFor(.any_path, addr_map.hostBitsOf(ingress));
    try std.testing.expect(try state.sendMapped(&map, mapped, "reply"));
    try std.testing.expectEqual(@as(usize, 1), state.count);
    const ordinary: base_addr.SocketAddr = .{
        .ip = .{ .v4 = .{ 127, 0, 0, 1 } },
        .port = 7777,
    };
    var absent: State = .{};
    try std.testing.expect(!try absent.sendMapped(&map, ordinary, "UDP"));
    try std.testing.expectEqual(@as(usize, 0), absent.count);
}

test "matching relay target queues on the configured unready carrier" {
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(std.testing.allocator);
    var generator = std.Random.DefaultPrng.init(44);
    const secret = try base_key.SecretKey.fromSeed(@splat(48));
    const target: base_addr.TransportAddr = .{
        .relay = try base_addr.RelayUrl.parse("http://relay-a.example/"),
    };
    const route = try dial_route.resolveRoute(
        std.testing.allocator,
        &map,
        target,
        secret.nodeId(),
        generator.random(),
    );
    var transport: CloseTransport = .{};
    var state: State = .{ .client = try transport.client() };
    defer state.deinit();
    state.client.?.state = .request;
    try state.admit(target);
    try std.testing.expect(try state.sendMapped(&map, route.socket, "supported"));
    try std.testing.expectEqual(@as(usize, 1), state.count);
    try std.testing.expectEqual(secret.nodeId(), state.queue[0].target);
    try std.testing.expectEqualSlices(
        u8,
        "supported",
        state.queue[0].bytes[0..state.queue[0].length],
    );
    try std.testing.expectEqual(@as(usize, 0), transport.writes);
}

test "relay admission rejects absent carrier and mismatched host port or protocol" {
    var state: State = .{};
    const target: base_addr.TransportAddr = .{
        .relay = try base_addr.RelayUrl.parse("http://relay-a.example/"),
    };
    try std.testing.expectError(error.RelayUnavailable, state.admit(target));
    var transport: CloseTransport = .{};
    state.client = try transport.client();
    defer state.deinit();
    state.client.?.state = .request;
    for ([_][]const u8{
        "http://relay-b.example/",
        "http://relay-a.example:81/",
        "https://relay-a.example:80/",
        "http://127.0.0.2/",
    }) |url| {
        try std.testing.expectError(
            error.RelayTargetMismatch,
            state.admit(.{ .relay = try base_addr.RelayUrl.parse(url) }),
        );
    }
    state.client.?.host = hostBytes("relay-a.example:80");
    state.client.?.host_len = "relay-a.example:80".len;
    try state.admit(target);
    state.client.?.host = hostBytes("relay-a.example:81");
    state.client.?.host_len = "relay-a.example:81".len;
    try std.testing.expectError(error.RelayTargetMismatch, state.admit(target));
    state.client.?.host = hostBytes("127.0.0.1");
    state.client.?.host_len = "127.0.0.1".len;
    try state.admit(.{ .relay = try base_addr.RelayUrl.parse("http://127.0.0.1/") });
    state.client.?.host = hostBytes("127.0.0.2");
    state.client.?.host_len = "127.0.0.2".len;
    try std.testing.expectError(
        error.RelayTargetMismatch,
        state.admit(.{ .relay = try base_addr.RelayUrl.parse("http://127.0.0.2/") }),
    );
    try std.testing.expectEqual(@as(usize, 0), state.count);
    try std.testing.expectEqual(@as(usize, 0), transport.writes);
}

test "Node start rejects unsupported relay before manager map and attempt state mutation" {
    const Node = @import("node.zig").Node;
    const peer_secret = try base_key.SecretKey.fromSeed(@splat(49));
    const peers = [_]@import("node_config.zig").Peer{.{
        .id = peer_secret.nodeId(),
        .addr = .{ .relay = try base_addr.RelayUrl.parse("http://relay-b.example/") },
    }};
    const node = try Node.create(std.testing.allocator, std.testing.io, .{
        .secret = try base_key.SecretKey.fromSeed(@splat(50)),
        .peers = &peers,
    }, 45);
    defer node.deinit();
    defer node.close(std.testing.io, 1_000_000_000, node.generator()) catch |err|
        std.debug.panic("relay admission fixture close failed: {t}", .{err});
    try std.testing.expectError(error.RelayUnavailable, node.start(1_000_000_000, node.generator()));
    try expectNoDialMutation(node);
    var transport: CloseTransport = .{};
    node.relay_runtime.client = try transport.client();
    try std.testing.expectError(
        error.RelayTargetMismatch,
        node.start(1_000_000_000, node.generator()),
    );
    try expectNoDialMutation(node);
    node.relay_runtime.client.?.host = hostBytes("relay-b.example");
    node.relay_runtime.client.?.host_len = "relay-b.example".len;
    try node.start(1_000_000_000, node.generator());
    try std.testing.expectEqual(@as(usize, 1), node.bridge.manager.connectionCount());
    try std.testing.expectEqual(@as(usize, 1), node.map.by_key.count());
    try std.testing.expectEqual(@as(usize, 1), node.map.by_addr.count());
    try std.testing.expectEqual(@as(usize, 1), node.dialled.count());
    try std.testing.expectEqual(@as(usize, 1), node.stats.dials);
    try std.testing.expectEqual(
        std.math.Order.eq,
        peers[0].addr.relay.order(node.map.relayTarget(
            node.map.by_key.get(.{ .any_path = peers[0].id }).?,
        ).?.*),
    );
}

fn expectNoDialMutation(node: *@import("node.zig").Node) !void {
    try std.testing.expectEqual(@as(usize, 0), node.bridge.manager.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), node.map.by_key.count());
    try std.testing.expectEqual(@as(usize, 0), node.map.by_addr.count());
    try std.testing.expectEqual(@as(usize, 0), node.dialled.count());
    try std.testing.expectEqual(@as(usize, 0), node.relay_runtime.count);
    try std.testing.expectEqual(@as(usize, 0), node.stats.dials);
    try std.testing.expectEqual(@as(usize, 0), node.stats.dials_refused);
    try std.testing.expect(!node.joined);
}

fn expectCloseDatagram(bytes: []u8, target: base_key.NodeId, datagram: []const u8) !usize {
    const decoded = try ws.decode(bytes, .server);
    try std.testing.expectEqual(ws.Opcode.binary, decoded.frame.opcode);
    try std.testing.expect(decoded.frame.fin);
    try std.testing.expect(decoded.frame.masked);
    const end = decoded.frame.header_length + decoded.payload.len;
    const payload = bytes[decoded.frame.header_length..end];
    ws.mask(decoded.frame.mask_key, payload);
    var expected: [256]u8 = undefined;
    const encoded = try frame.encode(.{ .client_to_relay_datagram = .{
        .node_id = target,
        .datagrams = .{ .ecn = null, .segment_size = null, .contents = datagram },
    } }, .v2, &expected);
    try std.testing.expectEqualSlices(u8, encoded, payload);
    return end;
}

test "close egress flush drains pending relay frame and queued datagrams with partial writes" {
    // Drive the production output seam without reading or closing its borrowed carrier.
    var transport: CloseTransport = .{};
    var state: State = .{ .client = try transport.client() };
    const client = if (state.client) |*value| value else return error.TestUnexpectedResult;
    const target = client.secret.nodeId();
    try client.send(target, "earlier");
    try state.enqueue(target, "final close datagram");
    try state.enqueue(target, "last peer close");
    try state.flush(std.testing.io);
    try std.testing.expectEqual(@as(usize, 0), state.count);
    try std.testing.expect(!client.connection.busy());
    try std.testing.expectEqual(@as(usize, 0), transport.reads);
    try std.testing.expectEqual(@as(usize, 0), transport.closes);
    var offset: usize = 0;
    for ([_][]const u8{ "earlier", "final close datagram", "last peer close" }) |datagram| {
        offset += try expectCloseDatagram(
            transport.bytes[offset..transport.length],
            target,
            datagram,
        );
    }
    try std.testing.expectEqual(transport.length, offset);
    const writes = transport.writes;
    try state.flush(std.testing.io);
    try std.testing.expectEqual(writes, transport.writes);
    state.deinit();
    try std.testing.expectEqual(@as(usize, 1), transport.closes);
}

test "blocked close egress flush preserves partial frame and queue for resumption" {
    // A blocked output is an explicit error, never a successful close or an inbound poll.
    var transport: CloseTransport = .{};
    var state: State = .{ .client = try transport.client() };
    defer state.deinit();
    const client = if (state.client) |*value| value else return error.TestUnexpectedResult;
    const target = client.secret.nodeId();
    try client.send(target, "final close datagram");
    try state.enqueue(target, "next peer close");
    try client.connection.flush(std.testing.io, .client);
    const position = client.connection.tx_pos;
    transport.blocked = true;
    const writes = transport.writes;
    try std.testing.expectError(error.WouldBlock, state.flush(std.testing.io));
    try std.testing.expectEqual(writes + 1, transport.writes);
    try std.testing.expectEqual(position, client.connection.tx_pos);
    try std.testing.expectEqual(@as(usize, 1), state.count);
    try std.testing.expectEqual(@as(usize, 0), transport.reads);
    try std.testing.expectEqual(@as(usize, 0), transport.closes);
    transport.blocked = false;
    try state.flush(std.testing.io);
    const offset = try expectCloseDatagram(
        transport.bytes[0..transport.length],
        target,
        "final close datagram",
    );
    const last = try expectCloseDatagram(
        transport.bytes[offset..transport.length],
        target,
        "next peer close",
    );
    try std.testing.expectEqual(transport.length, offset + last);
    try std.testing.expectEqual(@as(usize, 0), transport.closes);
}

test "close egress flush reports unready carrier without polling or dropping queued datagrams" {
    var transport: CloseTransport = .{};
    var state: State = .{ .client = try transport.client() };
    defer state.deinit();
    const client = if (state.client) |*value| value else return error.TestUnexpectedResult;
    client.state = .upgrade;
    try state.enqueue(client.secret.nodeId(), "final close datagram");
    try std.testing.expectError(error.WouldBlock, state.flush(std.testing.io));
    try std.testing.expectEqual(@as(usize, 1), state.count);
    try std.testing.expectEqual(@as(usize, 0), transport.writes);
    try std.testing.expectEqual(@as(usize, 0), transport.reads);
    try std.testing.expectEqual(@as(usize, 0), transport.closes);
}

test "close egress flush drains a full wrapped queue after the current frame" {
    var transport: CloseTransport = .{ .write_limit = 1 };
    var state: State = .{ .client = try transport.client(), .head = queue_capacity - 1 };
    defer state.deinit();
    const client = if (state.client) |*value| value else return error.TestUnexpectedResult;
    const target = client.secret.nodeId();
    try client.send(target, "current");
    for (0..queue_capacity) |index| {
        try state.enqueue(target, &.{@intCast(index)});
    }
    try state.flush(std.testing.io);
    try std.testing.expectEqual(@as(usize, 0), state.count);
    try std.testing.expect(!client.connection.busy());
    var offset = try expectCloseDatagram(transport.bytes[0..transport.length], target, "current");
    for (0..queue_capacity) |index| {
        offset += try expectCloseDatagram(
            transport.bytes[offset..transport.length],
            target,
            &.{@intCast(index)},
        );
    }
    try std.testing.expectEqual(transport.length, offset);
    try std.testing.expectEqual(@as(usize, 0), transport.reads);
    try std.testing.expectEqual(@as(usize, 0), transport.closes);
}

const InitExecution = struct {
    const errors = @import("../transport/tcp_error.zig");
    fail_wake: bool,
    streams: usize = 0,
    bound: bool = false,
    listened: bool = false,
    closes: [2]usize = .{ 0, 0 },

    fn execution(self: *InitExecution) tcp_execution.Execution {
        return .{ .context = self, .vtable = &vtable };
    }

    const vtable = block: {
        var callbacks = tcp_execution.Execution.native.vtable.*;
        callbacks.createStream = createStream;
        callbacks.createWake = createWake;
        callbacks.bind = bind;
        callbacks.listen = listen;
        callbacks.boundAddress = boundAddress;
        callbacks.close = close;
        break :block callbacks;
    };

    fn state(context: ?*anyopaque) *InitExecution {
        return @ptrCast(@alignCast(context.?));
    }

    fn createStream(
        _: std.Io,
        context: ?*anyopaque,
        _: base_addr.IpAddress,
    ) errors.OpenError!std.c.fd_t {
        const self = state(context);
        self.streams += 1;
        if (self.streams == 2 and !self.fail_wake) return error.ResourcesExhausted;
        std.debug.assert(self.streams <= 2);
        return @intCast(self.streams);
    }

    fn createWake(_: std.Io, context: ?*anyopaque) errors.OpenError!std.c.fd_t {
        const self = state(context);
        std.debug.assert(self.fail_wake);
        std.debug.assert(self.streams == 2);
        return error.ResourcesExhausted;
    }

    fn bind(
        _: std.Io,
        context: ?*anyopaque,
        handle: std.c.fd_t,
        _: base_addr.SocketAddr,
    ) errors.OpenError!void {
        std.debug.assert(handle == 1);
        state(context).bound = true;
    }

    fn listen(
        _: std.Io,
        context: ?*anyopaque,
        handle: std.c.fd_t,
    ) errors.ListenError!void {
        std.debug.assert(handle == 1);
        std.debug.assert(state(context).bound);
        state(context).listened = true;
    }

    fn boundAddress(
        _: std.Io,
        context: ?*anyopaque,
        handle: std.c.fd_t,
    ) errors.OpenError!base_addr.SocketAddr {
        std.debug.assert(handle == 1);
        std.debug.assert(state(context).listened);
        return .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 8080 };
    }

    fn close(context: ?*anyopaque, handle: std.c.fd_t) void {
        std.debug.assert(handle == 1 or handle == 2);
        const self = state(context);
        const index: usize = @intCast(handle - 1);
        std.debug.assert(self.closes[index] == 0);
        self.closes[index] += 1;
    }
};

test "relay runtime initialization rolls back serving carrier and partial client exactly once" {
    for ([_]bool{ false, true }) |fail_wake| {
        var execution: InitExecution = .{ .fail_wake = fail_wake };
        var state: State = undefined;
        try std.testing.expectError(error.ResourcesExhausted, state.init(std.testing.io, .{
            .serve = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 8080 },
            .execution = execution.execution(),
            .client = .{
                .address = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 8080 },
                .host = "127.0.0.1:8080",
                .secret = try base_key.SecretKey.fromSeed(@splat(52)),
                .execution = execution.execution(),
            },
        }));
        try std.testing.expect(execution.bound);
        try std.testing.expect(execution.listened);
        try std.testing.expectEqual(@as(usize, 2), execution.streams);
        try std.testing.expectEqual(@as(usize, 1), execution.closes[0]);
        try std.testing.expectEqual(@as(usize, if (fail_wake) 1 else 0), execution.closes[1]);
    }
}
