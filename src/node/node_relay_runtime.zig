const std = @import("std");
const base_addr = @import("../base/addr.zig");
const addr_map = @import("../transport/addr_map.zig");
const ula = @import("../base/ula.zig");
const base_key = @import("../base/key.zig");
const dial_route = @import("../transport/dial_route.zig");
const carrier = @import("../relay/tcp_carrier.zig");
const frame = @import("../relay/frame.zig");

pub const Config = struct {
    client: ?carrier.Config = null,
    serve: ?base_addr.SocketAddr = null,
};

pub const Error = carrier.Error || error{
    UnmappedPeer,
    UnsupportedMappedTransport,
    RelayUnavailable,
    RelayQueueFull,
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
    server: ?carrier.Server = null,
    incoming: ?carrier.Packet = null,
    queue: [queue_capacity]Queued = undefined,
    head: usize = 0,
    count: usize = 0,

    pub fn init(self: *State, config: Config) Error!void {
        self.* = .{};
        errdefer self.deinit();
        if (config.serve) |address| self.server = try carrier.Server.init(address);
        if (config.client) |client| self.client = try carrier.Client.init(client);
    }

    pub fn deinit(self: *State) void {
        if (self.client) |*client| client.deinit();
        if (self.server) |*server| server.deinit();
        self.client = null;
        self.server = null;
        self.incoming = null;
        self.count = 0;
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

    /// False means real IP only. Every synthetic-address error stays off UDP.
    pub fn sendMapped(
        self: *State,
        map: *const addr_map.MappedAddrs,
        peer: base_addr.SocketAddr,
        datagram: []const u8,
    ) Error!bool {
        const target = try mappedTarget(map, peer) orelse return false;
        const client = if (self.client) |*value| value else return error.RelayUnavailable;
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
    try std.testing.expectError(error.UnmappedPeer, mappedTarget(&map,
        ula.socketAddrFor(.custom, @splat(9))));
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
        const datagram = (try state.receive()).?;
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
