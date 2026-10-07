const std = @import("std");
const node = @import("node.zig");
const key = @import("../base/key.zig");
const addr = @import("../base/addr.zig");
const socket = @import("../transport/socket.zig");
const batch = @import("../transport/batch.zig");
const bridge = @import("../transport/quic_bridge.zig");
const dns_live = @import("../discovery/dns_live.zig");
const wire = @import("../discovery/lookup_wire.zig");
const t = std.testing;
const loopback: addr.SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 0 };

const Server = struct {
    handle: *socket.Socket,
    target: addr.SocketAddr,
    failure: ?anyerror = null,
    foreign: bool = false,

    fn run(self: *Server) void {
        self.answer() catch |err| { self.failure = err; };
    }

    fn answer(self: *Server) !void {
        var question: [1232]u8 = undefined;
        var control: socket.ControlBuffer = undefined;
        const got = try self.handle.receive(t.io, &question, &control, 2000);
        var end: usize = 12;
        while (question[end] != 0) end += 1 + question[end];
        end += 5;
        var response: [1232]u8 = @splat(0);
        @memcpy(response[0..end], question[0..end]);
        if (self.foreign) wire.put16(&response, 0, wire.be16(&question, 0) +% 1);
        wire.put16(&response, 2, 0x8180);
        wire.put16(&response, 6, 1);
        wire.put16(&response, 10, 0);
        var record: [128]u8 = undefined;
        const value = try std.fmt.bufPrint(&record, "addr={f}", .{self.target});
        response[end] = 0xc0;
        response[end + 1] = 12;
        wire.put16(&response, end + 2, 16);
        wire.put16(&response, end + 4, 1);
        wire.put32(&response, end + 6, 60);
        wire.put16(&response, end + 10, @intCast(value.len + 1));
        response[end + 12] = @intCast(value.len);
        @memcpy(response[end + 13 ..][0..value.len], value);
        _ = try self.handle.send(t.io, got.from, batch.Send.single(response[0 .. end + 13 + value.len], null));
    }
};

fn release(value: *node.Node) void {
    value.close(t.io, 1_000_000_000, value.generator()) catch unreachable;
    value.deinit();
}

test "identity-only discovery resolves through local DNS and carries authenticated application bytes" {
    const listener = try node.Node.create(t.allocator, t.io, .{
        .secret = try key.SecretKey.fromSeed(@splat(0x51)),
        .listen = loopback,
        .alpn = "ozai-discovery-fixture/1",
    }, 0x1111);
    defer release(listener);
    var nameserver = try socket.Socket.create(loopback, .{});
    defer nameserver.close();
    var resolver = try dns_live.Resolver.open(loopback, nameserver.address, .{});
    defer resolver.close();
    const ids = [_]key.NodeId{listener.nodeId()};
    const client = try node.Node.create(t.allocator, t.io, .{
        .secret = try key.SecretKey.fromSeed(@splat(0xc1)),
        .listen = loopback,
        .alpn = "ozai-discovery-fixture/1",
        .discovery = .{ .peer_ids = &ids, .lookup = .{ .datagram = resolver.seam(), .server = nameserver.address } },
    }, 0x2222);
    defer release(client);
    var server: Server = .{ .handle = &nameserver, .target = listener.address() };
    const thread = try std.Thread.spawn(.{}, Server.run, .{&server});
    var joined = false;
    defer if (!joined) thread.join();
    var at: i64 = 1_000_000_000;
    try client.start(at, client.generator());
    try t.expectEqual(@as(usize, 0), client.config.peers.len);
    for (0..512) |_| {
        at += 1_000_000;
        _ = try client.step(t.io, at, client.generator());
        _ = try listener.step(t.io, at, listener.generator());
    }
    thread.join();
    joined = true;
    if (server.failure) |err| return err;
    try t.expectEqual(@as(usize, 1), client.establishedCount());
    try t.expectEqual(@as(usize, 1), listener.establishedCount());
    const conn = client.bridge.connectionAt(0).?;
    try t.expectEqualSlices(u8, &listener.nodeId().toBytes(), &conn.entry.conn.tls13_hs.?.peerNodeId().?);
    try t.expectEqual(@as(u64, 1), client.stats.discovery_lookups);
    try t.expectEqual(@as(u64, 1), client.stats.dials);
    var stream = try bridge.Stream.open(conn);
    const payload = "identity-only DNS lookup application bytes";
    try stream.write(payload);
    stream.close();
    var received: std.ArrayList(u8) = .empty;
    defer received.deinit(t.allocator);
    for (0..128) |_| {
        at += 1_000_000;
        _ = try client.step(t.io, at, client.generator());
        _ = try listener.step(t.io, at, listener.generator());
        const accepted = listener.bridge.connectionAt(0).?;
        if (accepted.entry.conn.streams.streams.get(stream.id())) |entry| {
            var inbound: bridge.Stream = .{ .entry = entry };
            _ = try inbound.drain(t.allocator, &received);
        }
    }
    try t.expectEqualStrings(payload, received.items);
}

test "failed discovery neither dials nor reports records and is not retried on later ticks" {
    var nameserver = try socket.Socket.create(loopback, .{});
    defer nameserver.close();
    var resolver = try dns_live.Resolver.open(loopback, nameserver.address, .{});
    defer resolver.close();
    const ids = [_]key.NodeId{(try key.SecretKey.fromSeed(@splat(0x51))).nodeId()};
    const client = try node.Node.create(t.allocator, t.io, .{
        .secret = try key.SecretKey.fromSeed(@splat(0xc1)),
        .listen = loopback,
        .discovery = .{ .peer_ids = &ids, .lookup = .{ .datagram = resolver.seam(), .server = nameserver.address } },
    }, 0x2222);
    defer release(client);
    var server: Server = .{ .handle = &nameserver, .target = nameserver.address, .foreign = true };
    const thread = try std.Thread.spawn(.{}, Server.run, .{&server});
    var joined = false;
    defer if (!joined) thread.join();
    var at: i64 = 1_000_000_000;
    try client.start(at, client.generator());
    _ = try client.step(t.io, at, client.generator());
    thread.join();
    joined = true;
    if (server.failure) |err| return err;
    try t.expectEqual(@as(u64, 1), client.discovery.refused.foreign);
    for (0..3) |_| {
        at += 60 * std.time.ns_per_s;
        _ = try client.step(t.io, at, client.generator());
    }
    try t.expectEqual(@as(u64, 1), client.stats.discovery_lookups);
    try t.expectEqual(@as(u64, 0), client.stats.discovery_answers);
    try t.expectEqual(@as(u64, 0), client.stats.discovery_items);
    try t.expectEqual(@as(u64, 0), client.stats.dials);
    try t.expectEqual(@as(usize, 0), client.establishedCount());
}

test "an already attempted static peer is not looked up or dialled twice" {
    const listener = try node.Node.create(t.allocator, t.io, .{
        .secret = try key.SecretKey.fromSeed(@splat(0x51)),
        .listen = loopback,
    }, 0x1111);
    defer release(listener);
    var nameserver = try socket.Socket.create(loopback, .{});
    defer nameserver.close();
    var resolver = try dns_live.Resolver.open(loopback, nameserver.address, .{});
    defer resolver.close();
    const ids = [_]key.NodeId{listener.nodeId()};
    const peers = [_]node.Peer{.{ .id = listener.nodeId(), .addr = .{ .ip = listener.address() } }};
    const client = try node.Node.create(t.allocator, t.io, .{
        .secret = try key.SecretKey.fromSeed(@splat(0xc1)),
        .listen = loopback,
        .peers = &peers,
        .discovery = .{
            .peer_ids = &ids,
            .lookup = .{ .datagram = resolver.seam(), .server = nameserver.address },
            .deadline_ms = 1,
        },
    }, 0x2222);
    defer release(client);
    var at: i64 = 1_000_000_000;
    try client.start(at, client.generator());
    for (0..512) |_| {
        at += 1_000_000;
        _ = try client.step(t.io, at, client.generator());
        _ = try listener.step(t.io, at, listener.generator());
    }
    try t.expectEqual(@as(usize, 1), client.establishedCount());
    try t.expectEqual(@as(u64, 1), client.stats.dials);
    try t.expectEqual(@as(u64, 0), client.stats.discovery_lookups);
    try t.expectEqual(@as(u64, 0), client.discovery.refused.timed_out);
}
