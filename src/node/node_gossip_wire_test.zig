//! Authenticated connection lifecycle consumers preserve stream ownership and alternate routes.
const std = @import("std");
const tree = @import("../gossip/plumtree.zig");
const swarm = @import("../gossip/hyparview.zig");
const codec = @import("../gossip/codec.zig");
const node_mod = @import("node.zig");
const gossip_wire = @import("node_gossip_wire.zig");
const bridge_peer = @import("../transport/bridge_peer.zig");
const key = @import("../base/key.zig");
const socket_mod = @import("../transport/socket.zig");
const SocketAddr = @import("../base/addr.zig").SocketAddr;
const test_peer = @import("node_gossip_test_peer.zig");
const t = std.testing;

test "same peer scans preserve both consumed partial stream assemblies" {
    const topics = [_]swarm.TopicId{swarm.TopicId.fromBytes(@splat(0x71))};
    var deliveries: test_peer.Deliveries = .{};
    var server_secret = try key.SecretKey.fromSeed(bridge_peer.server_seed);
    defer server_secret.deinit();
    var client_secret = try key.SecretKey.fromSeed(bridge_peer.client_seed);
    defer client_secret.deinit();
    const loopback: SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 0 };
    var first_socket = try socket_mod.Socket.create(loopback, .{});
    defer first_socket.close();
    var second_socket = try socket_mod.Socket.create(loopback, .{});
    defer second_socket.close();
    const node = try node_mod.Node.create(t.allocator, t.io, .{
        .secret = server_secret,
        .gossip_topics = &topics,
        .on_gossip = test_peer.Deliveries.receive,
        .on_gossip_context = &deliveries,
    }, 917);
    defer test_peer.closeNode(node);
    var clients: [2]bridge_peer.Client = undefined;
    try test_peer.gossipClient(&clients[0], client_secret, node.nodeId(), 918, .{
        .server = node.address(),
        .client = first_socket.address,
    });
    defer clients[0].deinit();
    try test_peer.exchangeDirect(&clients[0], node, first_socket.address);
    try test_peer.gossipClient(&clients[1], client_secret, node.nodeId(), 919, .{
        .server = node.address(),
        .client = second_socket.address,
    });
    defer clients[1].deinit();
    try test_peer.exchangeDirect(&clients[1], node, second_socket.address);
    try t.expectEqual(@as(usize, 2), node.establishedCount());
    const first = node.bridge.connectionAt(0).?;
    const second = node.bridge.connectionAt(1).?;
    try t.expect(first.established());
    try t.expect(second.established());
    try t.expectEqual(client_secret.nodeId(), gossip_wire.peerOf(first).?);
    try t.expectEqual(client_secret.nodeId(), gossip_wire.peerOf(second).?);

    var bytes: [2][128]u8 = undefined;
    var lengths: [2]usize = undefined;
    const payloads = [_][]const u8{ "first", "second" };
    for (payloads, 0..) |payload, index| {
        const header = try codec.encodeStreamHeader(.init(topics[0]), bytes[index][0..36]);
        try t.expectEqual(@as(usize, 36), header.len);
        const frame = try codec.encode(.{ .gossip = .{ .gossip = .{
            .id = tree.MessageId.fromContent(payload),
            .content = payload,
            .scope = .neighbors,
        } } }, bytes[index][36..]);
        lengths[index] = 36 + frame.len;
    }
    const first_stream = try first.entry.conn.streams.getOrCreateRecvStream(2);
    const second_stream = try second.entry.conn.streams.getOrCreateRecvStream(2);
    // One connection pauses inside the topic header; the other inside a message body.
    const cuts = [_]usize{ 11, 43 };
    try first_stream.handleStreamFrame(0, bytes[0][0..cuts[0]], false);
    try second_stream.handleStreamFrame(0, bytes[1][0..cuts[1]], false);
    gossip_wire.learn(node);
    try t.expect(try gossip_wire.receive(node, 0));
    try t.expectEqual(@as(u64, cuts[0]), first_stream.consumed());
    try t.expectEqual(@as(u64, cuts[1]), second_stream.consumed());
    const route = node.gossip.conns.connFor(client_secret.nodeId()).?;
    for (0..3) |_| gossip_wire.learn(node);
    try first_stream.handleStreamFrame(cuts[0], bytes[0][cuts[0]..lengths[0]], true);
    try second_stream.handleStreamFrame(cuts[1], bytes[1][cuts[1]..lengths[1]], true);
    try t.expect(try gossip_wire.receive(node, 0));
    try t.expect(deliveries.first);
    try t.expect(deliveries.second);
    try t.expectEqual(@as(u64, 2), node.gossip.received);
    try t.expectEqual(@as(u64, 0), node.gossip.rejected);
    try t.expectEqual(route, node.gossip.conns.connFor(client_secret.nodeId()).?);
    try t.expectEqual(@as(usize, 0), node.gossip.incoming.len);
}

test "peerGone after selected connection expiry preserves authenticated alternate" {
    const node_gossip = @import("node_gossip.zig");
    const topics = [_]swarm.TopicId{swarm.TopicId.fromBytes(@splat(0x79))};
    var deliveries: test_peer.Deliveries = .{};
    var server_secret = try key.SecretKey.fromSeed(bridge_peer.server_seed);
    defer server_secret.deinit();
    var client_secret = try key.SecretKey.fromSeed(bridge_peer.client_seed);
    defer client_secret.deinit();
    const same_peer = client_secret.nodeId();
    const loopback: SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 0 };
    var first_socket = try socket_mod.Socket.create(loopback, .{});
    defer first_socket.close();
    var second_socket = try socket_mod.Socket.create(loopback, .{});
    defer second_socket.close();
    const node = try node_mod.Node.create(t.allocator, t.io, .{
        .secret = server_secret,
        .gossip_topics = &topics,
        .on_gossip = test_peer.Deliveries.receive,
        .on_gossip_context = &deliveries,
    }, 936);
    defer test_peer.closeNode(node);
    var clients: [2]bridge_peer.Client = undefined;
    try test_peer.gossipClient(&clients[0], client_secret, node.nodeId(), 937, .{
        .server = node.address(),
        .client = first_socket.address,
    });
    defer clients[0].deinit();
    try test_peer.exchangeDirect(&clients[0], node, first_socket.address);
    try test_peer.gossipClient(&clients[1], client_secret, node.nodeId(), 938, .{
        .server = node.address(),
        .client = second_socket.address,
    });
    defer clients[1].deinit();
    try test_peer.exchangeDirect(&clients[1], node, second_socket.address);
    try t.expectEqual(@as(usize, 2), node.establishedCount());
    const first = node.bridge.connectionAt(0).?;
    const second = node.bridge.connectionAt(1).?;
    try t.expect(first.established());
    try t.expect(second.established());
    try t.expectEqual(same_peer, gossip_wire.peerOf(first).?);
    try t.expectEqual(same_peer, gossip_wire.peerOf(second).?);
    gossip_wire.learn(node);
    try t.expectEqual(first.id(), node.gossip.conns.connFor(same_peer).?);
    try node_gossip.feedGossip(node, 0, .{ .recv_message = .{
        .from = same_peer,
        .message = .{ .swarm = .{ .join = null } },
    } }, try node_gossip.gossipNow(bridge_peer.start));
    try t.expect(node.gossip_topics[0].swarm.active_view.contains(same_peer));
    const neighbor_down_before = node.stats.neighbor_down;

    var bytes: [2][128]u8 = undefined;
    var lengths: [2]usize = undefined;
    const payloads = [_][]const u8{ "first", "second" };
    for (payloads, 0..) |payload, index| {
        const header = try codec.encodeStreamHeader(.init(topics[0]), bytes[index][0..36]);
        try t.expectEqual(@as(usize, 36), header.len);
        const frame = try codec.encode(.{ .gossip = .{ .gossip = .{
            .id = tree.MessageId.fromContent(payload),
            .content = payload,
            .scope = .neighbors,
        } } }, bytes[index][36..]);
        lengths[index] = 36 + frame.len;
    }
    const first_stream = try first.entry.conn.streams.getOrCreateRecvStream(2);
    const second_stream = try second.entry.conn.streams.getOrCreateRecvStream(2);
    const cuts = [_]usize{ 11, 43 };
    try first_stream.handleStreamFrame(0, bytes[0][0..cuts[0]], false);
    try second_stream.handleStreamFrame(0, bytes[1][0..cuts[1]], false);
    try t.expect(try gossip_wire.receive(node, 0));
    try t.expectEqual(@as(u64, cuts[0]), first_stream.consumed());
    try t.expectEqual(@as(u64, cuts[1]), second_stream.consumed());
    try t.expectEqual(@as(usize, 2), node.gossip.incoming.len);
    try t.expect(!deliveries.first);
    try t.expect(!deliveries.second);

    // Retire only the selected connection through transport's real timer API.
    first.entry.conn.close(0, "", bridge_peer.start);
    const close_deadline = first.entry.conn.nextTimeoutNs(bridge_peer.start).?;
    try t.expect(close_deadline > bridge_peer.start);
    try t.expectEqual(
        @import("../transport/quic_bridge.zig").Tick.finished,
        node.bridge.tick(first, close_deadline + 1, node.generator()),
    );
    try t.expect(first.closed());
    try t.expectEqual(@as(usize, 1), node.establishedCount());
    try t.expect(second.established());
    try t.expect(!second.closed());
    try t.expectEqual(second.id(), node.bridge.connectionAt(0).?.id());

    // Select the authenticated survivor; direct addresses need no fabricated relay ownership.
    gossip_wire.learn(node);
    try t.expectEqual(second.id(), node.gossip.conns.connFor(same_peer).?);
    try t.expectEqual(@as(usize, 1), node.gossip.incoming.len);
    const before = &node.gossip.incoming.entries[0];
    try t.expectEqual(second.id(), before.conn);
    try t.expectEqual(@as(u64, 2), before.stream_id);
    try t.expectEqual(@as(?usize, 0), before.topic_index);
    try t.expectEqual(cuts[1] - 36, before.assembly.used);
    try t.expectEqual(lengths[1] - 36, before.assembly.target);
    try t.expect(!before.assembly.complete);
    try t.expectEqualSlices(
        u8,
        bytes[1][36..cuts[1]],
        before.assembly.bytes[0..before.assembly.used],
    );

    try node_gossip.peerGone(node, same_peer, bridge_peer.start);
    try t.expect(node.gossip.conns.connFor(same_peer) != null);
    try t.expectEqual(second.id(), node.gossip.conns.connFor(same_peer).?);
    try t.expect(node.gossip_topics[0].swarm.active_view.contains(same_peer));
    try t.expectEqual(neighbor_down_before, node.stats.neighbor_down);
    try t.expectEqual(@as(usize, 1), node.gossip.incoming.len);
    const after = &node.gossip.incoming.entries[0];
    try t.expectEqual(second.id(), after.conn);
    try t.expectEqual(@as(u64, 2), after.stream_id);
    try t.expectEqual(@as(?usize, 0), after.topic_index);
    try t.expectEqual(cuts[1] - 36, after.assembly.used);
    try t.expectEqual(lengths[1] - 36, after.assembly.target);
    try t.expect(!after.assembly.complete);
    try t.expectEqualSlices(
        u8,
        bytes[1][36..cuts[1]],
        after.assembly.bytes[0..after.assembly.used],
    );
    try t.expectEqual(@as(u64, cuts[1]), second_stream.consumed());

    try second_stream.handleStreamFrame(cuts[1], bytes[1][cuts[1]..lengths[1]], true);
    try t.expect(try gossip_wire.receive(node, 0));
    try t.expect(!deliveries.first);
    try t.expect(deliveries.second);
    try t.expectEqual(@as(u64, 1), node.gossip.received);
    try t.expectEqual(@as(u64, 0), node.gossip.rejected);
    try t.expectEqual(@as(usize, 0), node.gossip.incoming.len);
    try t.expectEqual(second.id(), node.gossip.conns.connFor(same_peer).?);
    try t.expect(node.gossip_topics[0].swarm.active_view.contains(same_peer));
    try t.expectEqual(neighbor_down_before, node.stats.neighbor_down);
}
