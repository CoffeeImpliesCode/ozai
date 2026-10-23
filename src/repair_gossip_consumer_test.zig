//! Standalone consumer regressions; intentionally not registered in default test roots.
const std = @import("std");
const tree = @import("gossip/plumtree.zig");
const swarm = @import("gossip/hyparview.zig");
const codec = @import("gossip/codec.zig");
const NodeId = @import("base/key.zig").NodeId;
const t = std.testing;

fn peer(value: u8) NodeId {
    return @import("gossip/plumtree/test_node_id.zig").testNodeId(value) catch
        @panic("invalid fixed test identity seed");
}

fn rejectedBroadcast(length: usize) !void {
    var content: [4059]u8 = @splat(0x5a);
    const payload = content[0..length];
    var state: tree.State = .init(peer(1), .{});
    try state.addEager(peer(2));
    var out: tree.Actions(tree.OutEvent) = .init(t.allocator);
    defer out.deinit();
    const candidate: codec.Message = .{ .gossip = .{ .gossip = .{
        .id = tree.MessageId.fromContent(payload),
        .content = payload,
        .scope = .{ .swarm = .zero },
    } } };
    try t.expectEqual(length + 38, codec.encodedLen(candidate));
    var frame: [4101]u8 = undefined;
    try t.expectError(error.FrameTooLarge, codec.encode(candidate, &frame));
    const result = state.broadcast(payload, .swarm, 0, &out);
    try t.expectEqual(@as(usize, 0), state.cache.count());
    try t.expectEqual(@as(usize, 0), state.received_messages.count());
    try t.expectEqual(@as(usize, 0), out.count());
    try t.expectError(error.MessageTooLarge, result);
}

test "repair gossip broadcast 4058 refuses before cache mutation" {
    try rejectedBroadcast(4058);
}

test "repair gossip broadcast 4059 refuses before cache mutation" {
    try rejectedBroadcast(4059);
}

test "repair gossip broadcast last writable payload remains deliverable" {
    const content: [4057]u8 = @splat(0x59);
    var state: tree.State = .init(peer(1), .{});
    try state.addEager(peer(2));
    var out: tree.Actions(tree.OutEvent) = .init(t.allocator);
    defer out.deinit();
    try state.broadcast(&content, .swarm, 0, &out);
    try t.expectEqual(@as(usize, 1), state.cache.count());
    var sent: usize = 0;
    var frame: [4100]u8 = undefined;
    for (0..out.count()) |index| {
        const action = out.at(index);
        if (action == .send_message) {
            const message: codec.Message = .{ .gossip = action.send_message.message };
            try t.expectEqual(@as(usize, 4095), codec.encodedLen(message));
            const encoded = try codec.encode(message, &frame);
            const decoded = try codec.decode(encoded);
            try t.expectEqualSlices(u8, &content, decoded.gossip.gossip.content);
            sent += 1;
        }
    }
    try t.expectEqual(@as(usize, 1), sent);
}

test "repair gossip valid Join cannot commit an unwritable ForwardJoin" {
    const contact: [4090]u8 = @splat(0x67);
    const join: codec.Message = .{ .swarm = .{ .join = &contact } };
    var frame: [4132]u8 = undefined;
    try t.expectEqual(@as(usize, 4095), codec.encodedLen(join));
    const encoded = try codec.encode(join, &frame);
    const decoded = try codec.decode(encoded);
    try t.expectEqualSlices(u8, &contact, decoded.swarm.join.?);
    var state = try swarm.State.init(peer(1), null, .{}, .init(42));
    var out: swarm.Actions(swarm.SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    try state.handle(.{ .recv_message = .{
        .from = peer(2),
        .message = .{ .join = null },
    } }, &out);
    out.clear();
    const forward: codec.Message = .{ .swarm = .{ .forward_join = .{
        .peer = .{ .id = peer(3), .data = decoded.swarm.join },
        .ttl = state.config.active_random_walk_length,
    } } };
    try t.expectEqual(@as(usize, 4128), codec.encodedLen(forward));
    try t.expectError(error.FrameTooLarge, codec.encode(forward, &frame));
    const result = state.handle(.{ .recv_message = .{
        .from = peer(3),
        .message = decoded.swarm,
    } }, &out);
    try t.expect(!state.active_view.contains(peer(3)));
    try t.expect(state.peer_data.get(peer(3)) == null);
    try t.expectEqual(@as(usize, 1), state.activeView().len);
    try t.expectEqual(@as(usize, 0), out.count());
    try t.expectError(error.MessageTooLarge, result);
}

const node_mod = @import("node/node.zig");
const gossip_wire = @import("node/node_gossip_wire.zig");
const bridge_peer = @import("transport/bridge_peer.zig");
const bridge_address = @import("transport/bridge_address.zig");
const key = @import("base/key.zig");
const quic = @import("quic");
const socket_mod = @import("transport/socket.zig");
const SocketAddr = @import("base/addr.zig").SocketAddr;

fn gossipClient(
    client: *bridge_peer.Client,
    secret: key.SecretKey,
    server: NodeId,
    seed: u64,
    addresses: struct { server: SocketAddr, client: SocketAddr },
) !void {
    client.* = .{
        .conn = undefined,
        .engine = bridge_peer.Prng.init(seed),
        .spki = quic.tls13.ed25519Spki(&secret.nodeId().toBytes()),
        .cert_chain = undefined,
        .alpn_list = .{node_mod.gossip_alpn},
        .seed = secret.toBytes()[0..key.SecretKey.seed_length].*,
    };
    client.cert_chain = .{&client.spki};
    client.conn = try t.allocator.create(quic.connection.Connection);
    errdefer t.allocator.destroy(client.conn);
    try quic.connection.connectInto(client.conn, t.allocator, bridge_peer.server_name, .{}, .{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &client.alpn_list,
        .server_name = bridge_peer.server_name,
        .expect_peer_node_id = server.toBytes(),
        .client_certificate = .{
            .cert_chain_der = &client.cert_chain,
            .private_key_bytes = &client.seed,
            .private_key_algorithm = .ed25519,
        },
    }, null, bridge_peer.start, client.random());
    client.conn.paths[0].peer_addr = bridge_address.toCoreAddress(addresses.server);
    client.conn.paths[0].local_addr = bridge_address.toCoreAddress(addresses.client);
}

fn receiveDirect(
    client: *bridge_peer.Client,
    bytes: []const u8,
    addresses: struct { server: SocketAddr, client: SocketAddr },
) void {
    std.debug.assert(bytes.len <= client.inbound.len);
    @memcpy(client.inbound[0..bytes.len], bytes);
    client.conn.handleDatagram(client.inbound[0..bytes.len], .{
        .to = bridge_address.toCoreAddress(addresses.client),
        .from = bridge_address.toCoreAddress(addresses.server),
        .datagram_size = bytes.len,
    }, bridge_peer.start, client.random());
}

fn exchangeDirect(client: *bridge_peer.Client, node: *node_mod.Node, from: SocketAddr) !void {
    var scratch: [2 * bridge_peer.max_datagram]u8 = undefined;
    var egress: [bridge_peer.max_egress]@import("transport/quic_bridge.zig").Egress = undefined;
    var out: [bridge_peer.max_egress * bridge_peer.max_datagram]u8 = undefined;
    for (0..bridge_peer.max_rounds) |_| {
        var moved = false;
        for (0..64) |_| {
            const length = try client.conn.sendAt(
                &client.buffer,
                bridge_peer.start,
                client.random(),
            );
            if (length == 0) break;
            const ingress = try node.bridge.recv(&node.map, .{
                .bytes = client.buffer[0..length],
                .from = from,
                .local = node.address(),
                .ecn = null,
            }, &scratch, bridge_peer.start, client.random());
            switch (ingress.outcome) {
                .processed => |conn| {
                    const sends = try conn.drain(
                        &egress,
                        &out,
                        bridge_peer.start,
                        client.random(),
                    );
                    for (sends) |send| {
                        var runs = try @import("transport/batch.zig").Runs.init(send.send, .none);
                        while (runs.next()) |run| {
                            receiveDirect(client, run.contents, .{
                                .server = node.address(),
                                .client = from,
                            });
                        }
                    }
                    moved = sends.len != 0 or moved;
                },
                .reply => |reply| {
                    receiveDirect(client, reply.contents, .{
                        .server = node.address(),
                        .client = from,
                    });
                    moved = true;
                },
                .dropped, .foreign => {},
            }
        }
        if (!moved) break;
    }
    node.bridge.sweep();
}

const Deliveries = struct {
    first: bool = false,
    second: bool = false,

    fn receive(context: ?*anyopaque, _: swarm.TopicId, _: NodeId, content: []const u8) void {
        const self: *Deliveries = @ptrCast(@alignCast(context.?));
        if (std.mem.eql(u8, content, "first")) self.first = true;
        if (std.mem.eql(u8, content, "second")) self.second = true;
    }
};

fn closeNode(node: *node_mod.Node) void {
    defer node.deinit();
    node.close(t.io, bridge_peer.start, node.generator()) catch
        @panic("failed to close standalone regression node");
}

test "repair gossip same peer scans preserve both consumed partial stream assemblies" {
    const topics = [_]swarm.TopicId{swarm.TopicId.fromBytes(@splat(0x71))};
    var deliveries: Deliveries = .{};
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
        .on_gossip = Deliveries.receive,
        .on_gossip_context = &deliveries,
    }, 917);
    defer closeNode(node);
    var clients: [2]bridge_peer.Client = undefined;
    try gossipClient(&clients[0], client_secret, node.nodeId(), 918, .{
        .server = node.address(),
        .client = first_socket.address,
    });
    defer clients[0].deinit();
    try exchangeDirect(&clients[0], node, first_socket.address);
    try gossipClient(&clients[1], client_secret, node.nodeId(), 919, .{
        .server = node.address(),
        .client = second_socket.address,
    });
    defer clients[1].deinit();
    try exchangeDirect(&clients[1], node, second_socket.address);
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

test "repair gossip final Node broadcast first refusal preserves timer initialization" {
    const topics = [_]swarm.TopicId{swarm.TopicId.fromBytes(@splat(0x72))};
    var secret = try key.SecretKey.fromSeed(bridge_peer.server_seed);
    defer secret.deinit();
    const node = try node_mod.Node.create(t.allocator, t.io, .{
        .secret = secret,
        .gossip_topics = &topics,
    }, 920);
    defer closeNode(node);
    try node.gossip_topics[0].gossip.addEager(peer(2));
    const content: [4059]u8 = @splat(0x5a);
    for ([_]usize{ 4058, 4059 }) |length| {
        const result = node.broadcast(topics[0], content[0..length], bridge_peer.start);
        try t.expectEqual(@as(usize, 0), node.gossip_topics[0].gossip.cache.count());
        try t.expectEqual(@as(usize, 0), node.gossip_topics[0].gossip.received_messages.count());
        try t.expect(!node.gossip_topics[0].gossip.started);
        try t.expect(!node.gossip_topics[0].gossip.dispatch_timer_scheduled);
        try t.expectEqual(@as(usize, 0), node.timers.items.len);
        try t.expectEqual(@as(u64, 0), node.gossip.queued);
        try t.expectEqual(@as(u64, 0), node.gossip.sent);
        try t.expectEqual(@as(u64, 0), node.gossip.refused.frame_too_large);
        try t.expectError(error.MessageTooLarge, result);
    }
    try node.broadcast(topics[0], "accepted after refusal", bridge_peer.start);
    try t.expect(node.gossip_topics[0].gossip.started);
    try t.expectEqual(@as(usize, 1), node.gossip_topics[0].gossip.cache.count());
    try t.expectEqual(@as(usize, 1), node.gossip_topics[0].gossip.received_messages.count());
    try t.expect(node.gossip_topics[0].gossip.dispatch_timer_scheduled);
    var cache_timers: usize = 0;
    var dispatch_timers: usize = 0;
    var cache_due: swarm.Nanos = 0;
    // Membership timers are independent of the two promised gossip timers.
    for (node.timers.items) |pending| {
        if (pending.topic_index != 0) continue;
        switch (pending.timer) {
            .gossip => |timer| switch (timer) {
                .evict_cache => {
                    cache_timers += 1;
                    cache_due = pending.due;
                    try t.expect(pending.due > 0);
                },
                .dispatch_lazy_push => {
                    dispatch_timers += 1;
                    try t.expect(pending.due > 0);
                },
                else => {},
            },
            else => {},
        }
    }
    try t.expectEqual(@as(usize, 1), cache_timers);
    try t.expectEqual(@as(usize, 1), dispatch_timers);

    const cache_expires = @as(swarm.Nanos, @intCast(bridge_peer.start)) +
        node.gossip_topics[0].gossip.config.message_cache_retention;
    const stepped_time = @max(cache_due, cache_expires);
    const bridge = @import("transport/quic_bridge.zig");
    const stepped_at: bridge.Instant = @intCast(stepped_time);
    try t.expect(try node.step(t.io, stepped_at, node.generator()));
    try t.expectEqual(@as(usize, 0), node.gossip_topics[0].gossip.cache.count());
    try t.expect(node.gossip_topics[0].gossip.started);
    try t.expect(!node.gossip_topics[0].gossip.dispatch_timer_scheduled);
    cache_timers = 0;
    dispatch_timers = 0;
    for (node.timers.items) |pending| {
        if (pending.topic_index != 0) continue;
        switch (pending.timer) {
            .gossip => |timer| switch (timer) {
                .evict_cache => {
                    cache_timers += 1;
                    try t.expect(pending.due > stepped_time);
                },
                .dispatch_lazy_push => dispatch_timers += 1,
                else => {},
            },
            else => {},
        }
    }
    try t.expectEqual(@as(usize, 1), cache_timers);
    try t.expectEqual(@as(usize, 0), dispatch_timers);
}

test "repair gossip last writable ForwardJoin keeps complete contact data" {
    const contact: [4057]u8 = @splat(0x68);
    var state = try swarm.State.init(peer(1), null, .{}, .init(42));
    var out: swarm.Actions(swarm.SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    try state.handle(.{ .recv_message = .{
        .from = peer(2),
        .message = .{ .join = null },
    } }, &out);
    out.clear();
    try state.handle(.{ .recv_message = .{
        .from = peer(3),
        .message = .{ .join = &contact },
    } }, &out);
    try t.expect(state.active_view.contains(peer(3)));
    try t.expectEqualSlices(u8, &contact, state.peer_data.get(peer(3)).?.slice());
    var forwarded: usize = 0;
    var frame: [4100]u8 = undefined;
    for (out.slice()) |action| {
        if (action == .send_message) {
            const message: codec.Message = .{ .swarm = action.send_message.message };
            const encoded = try codec.encode(message, &frame);
            if (message.swarm == .forward_join) {
                try t.expectEqual(@as(usize, 4095), codec.encodedLen(message));
                const decoded = try codec.decode(encoded);
                try t.expectEqualSlices(u8, &contact, decoded.swarm.forward_join.peer.data.?);
                forwarded += 1;
            }
        }
    }
    try t.expectEqual(@as(usize, 1), forwarded);
}

test "repair gossip receive capacity still admits Join without a forwarding recipient" {
    const contact: [4090]u8 = @splat(0x69);
    var state = try swarm.State.init(peer(1), null, .{}, .init(42));
    var out: swarm.Actions(swarm.SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    try state.handle(.{ .recv_message = .{
        .from = peer(2),
        .message = .{ .join = &contact },
    } }, &out);
    try t.expect(state.active_view.contains(peer(2)));
    try t.expectEqualSlices(u8, &contact, state.peer_data.get(peer(2)).?.slice());
    var frame: [4100]u8 = undefined;
    for (out.slice()) |action| {
        if (action == .send_message) {
            const message: codec.Message = .{ .swarm = action.send_message.message };
            try t.expect(message.swarm != .forward_join);
            const encoded = try codec.encode(message, &frame);
            try t.expectEqual(codec.encodedLen(message) + 4, encoded.len);
        }
    }
}

fn receivedRoundGrowth(length: usize, round: u16) !void {
    const content: [4057]u8 = @splat(0x6a);
    const payload = content[0..length];
    const id = tree.MessageId.fromContent(payload);
    var state: tree.State = .init(peer(1), .{});
    try state.addEager(peer(3));
    try state.addLazy(peer(4));
    var out: tree.Actions(tree.OutEvent) = .init(t.allocator);
    defer out.deinit();
    try state.handle(.{ .recv_message = .{
        .from = peer(4),
        .message = .{ .i_have = try tree.IHaves.init(&.{.{
            .id = id,
            .round = .zero,
        }}) },
    } }, 0, &out);
    try t.expectEqual(@as(usize, 1), state.missing_messages_len);
    out.clear();
    const incoming: codec.Message = .{ .gossip = .{ .gossip = .{
        .id = id,
        .content = payload,
        .scope = .{ .swarm = .{ .value = round } },
    } } };
    var input: [4100]u8 = undefined;
    try t.expectEqual(@as(usize, 4095), codec.encodedLen(incoming));
    const encoded = try codec.encode(incoming, &input);
    const decoded = try codec.decode(encoded);
    try state.handle(.{ .recv_message = .{
        .from = peer(2),
        .message = decoded.gossip,
    } }, 0, &out);
    var output: [4100]u8 = undefined;
    var delivered = false;
    var grafted = false;
    var pruned = false;
    for (out.slice()) |action| switch (action) {
        .send_message => |send| {
            try t.expect(send.message != .i_have);
            switch (send.message) {
                .graft => |graft| {
                    try t.expect(graft.id == null);
                    try t.expectEqualSlices(u8, &peer(4).toBytes(), &send.to.toBytes());
                    grafted = true;
                },
                .prune => {
                    try t.expectEqualSlices(u8, &peer(2).toBytes(), &send.to.toBytes());
                    pruned = true;
                },
                else => {},
            }
            const outgoing: codec.Message = .{ .gossip = send.message };
            try t.expect(codec.encodedLen(outgoing) < codec.max_message_size);
            const written = try codec.encode(outgoing, &output);
            try t.expectEqual(codec.encodedLen(outgoing) + 4, written.len);
        },
        .emit_event => |event| {
            try t.expectEqualSlices(u8, payload, event.content);
            delivered = true;
        },
        else => {},
    };
    try t.expect(delivered);
    try t.expect(grafted);
    try t.expect(pruned);
    try t.expectEqual(@as(usize, 0), state.missing_messages_len);
    try t.expect(state.received_messages.contains(id));
    try t.expectEqual(@as(usize, 0), state.cache.count());
    try t.expectEqual(@as(usize, 0), state.lazy_push_queue_len);
}

test "repair gossip envelope received round127 growth refuses unwritable eager lazy cache" {
    try receivedRoundGrowth(4057, 127);
}

test "repair gossip envelope received round16383 growth refuses unwritable eager lazy cache" {
    try receivedRoundGrowth(4056, 16383);
}

test "repair gossip Graft cannot resend an unwritable receive-capacity cache entry" {
    const content: [4057]u8 = @splat(0x6b);
    const id = tree.MessageId.fromContent(&content);
    var state: tree.State = .init(peer(1), .{});
    var out: tree.Actions(tree.OutEvent) = .init(t.allocator);
    defer out.deinit();
    try state.handle(.{ .recv_message = .{
        .from = peer(2),
        .message = .{ .gossip = .{
            .id = id,
            .content = &content,
            .scope = .{ .swarm = .{ .value = 127 } },
        } },
    } }, 0, &out);
    out.clear();
    const result = state.handle(.{ .recv_message = .{
        .from = peer(3),
        .message = .{ .graft = .{ .id = id, .round = .{ .value = 128 } } },
    } }, 0, &out);
    var frame: [4100]u8 = undefined;
    for (out.slice()) |action| {
        if (action == .send_message) {
            const message: codec.Message = .{ .gossip = action.send_message.message };
            try t.expect(codec.encodedLen(message) < codec.max_message_size);
            const encoded = try codec.encode(message, &frame);
            try t.expectEqual(codec.encodedLen(message) + 4, encoded.len);
        }
    }
    try result;
}

fn membershipIncoming(message: codec.Message, buffer: []u8) !codec.Message {
    // Receive permits the inclusive boundary that the strict sender cannot write.
    const length = codec.encodedLen(message);
    try t.expect(length <= codec.max_message_size);
    std.mem.writeInt(u32, buffer[0..4], @intCast(length), .big);
    var writer = @import("wire/postcard.zig").Writer.init(buffer[4..]);
    try codec.encodeBody(message, &writer);
    try t.expectEqual(length, writer.finish().len);
    return codec.decode(buffer[0 .. 4 + length]);
}

fn membershipSeed(
    state: *swarm.State,
    id: NodeId,
    data: ?[]const u8,
    out: *swarm.Actions(swarm.SwarmOutEvent),
) !void {
    try state.handle(.{ .recv_message = .{
        .from = id,
        .message = .{ .neighbor = .{ .priority = .high, .data = data } },
    } }, out);
    try t.expect(state.active_view.contains(id));
    out.clear();
}

test "repair gossip envelope local Join4096 rejects before output" {
    const data: [4091]u8 = @splat(0x81);
    var state = try swarm.State.init(peer(1), try swarm.PeerData.fromBytes(&data), .{}, .init(42));
    var out: swarm.Actions(swarm.SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    const candidate: codec.Message = .{ .swarm = .{ .join = state.myData() } };
    var output: [4100]u8 = undefined;
    try t.expectEqual(@as(usize, 4096), codec.encodedLen(candidate));
    try t.expectError(error.FrameTooLarge, codec.encode(candidate, &output));
    const result = state.handle(.{ .request_join = peer(2) }, &out);
    try t.expectEqual(@as(usize, 0), out.count());
    try t.expectEqual(@as(usize, 0), state.activeView().len);
    try t.expectEqualSlices(u8, &data, state.myData().?);
    try t.expectError(error.MessageTooLarge, result);
}

test "repair gossip envelope local Join4095 preserves full contact data" {
    const data: [4090]u8 = @splat(0x82);
    var state = try swarm.State.init(peer(1), try swarm.PeerData.fromBytes(&data), .{}, .init(42));
    var out: swarm.Actions(swarm.SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    try state.handle(.{ .request_join = peer(2) }, &out);
    var output: [4100]u8 = undefined;
    var sends: usize = 0;
    for (out.slice()) |action| {
        if (action == .send_message) {
            const message: codec.Message = .{ .swarm = action.send_message.message };
            try t.expectEqual(@as(usize, 4095), codec.encodedLen(message));
            const decoded = try codec.decode(try codec.encode(message, &output));
            try t.expectEqualSlices(u8, &data, decoded.swarm.join.?);
            sends += 1;
        }
    }
    try t.expectEqual(@as(usize, 1), sends);
}

test "repair gossip envelope Neighbor4096 rejects Join before membership commit" {
    const own: [4090]u8 = @splat(0x83);
    const contact = [_]u8{0x84};
    var state = try swarm.State.init(peer(1), try swarm.PeerData.fromBytes(&own), .{}, .init(42));
    var out: swarm.Actions(swarm.SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    var input: [4100]u8 = undefined;
    const decoded = try membershipIncoming(.{ .swarm = .{ .join = &contact } }, &input);
    const candidate: codec.Message = .{ .swarm = .{ .neighbor = .{
        .priority = .high,
        .data = state.myData(),
    } } };
    var output: [4100]u8 = undefined;
    try t.expectEqual(@as(usize, 4096), codec.encodedLen(candidate));
    try t.expectError(error.FrameTooLarge, codec.encode(candidate, &output));
    const result = state.handle(.{ .recv_message = .{
        .from = peer(2),
        .message = decoded.swarm,
    } }, &out);
    try t.expectEqual(@as(usize, 0), state.activeView().len);
    try t.expectEqual(@as(usize, 0), state.passiveView().len);
    try t.expectEqual(@as(usize, 0), state.peer_data.count());
    try t.expectEqual(@as(usize, 0), state.pending_neighbor_requests.count());
    try t.expectEqual(@as(usize, 0), out.count());
    try t.expectEqualSlices(u8, &own, state.myData().?);
    try t.expectError(error.MessageTooLarge, result);
}

fn membershipJoinTtl(ttl: u16, reject: bool) !void {
    const contact: [4057]u8 = @splat(0x85);
    var state = try swarm.State.init(peer(1), null, .{
        .active_random_walk_length = .{ .value = ttl },
    }, .init(42));
    var out: swarm.Actions(swarm.SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    try membershipSeed(&state, peer(2), null, &out);
    var input: [4100]u8 = undefined;
    const decoded = try membershipIncoming(.{ .swarm = .{ .join = &contact } }, &input);
    const candidate: codec.Message = .{ .swarm = .{ .forward_join = .{
        .peer = .{ .id = peer(3), .data = decoded.swarm.join },
        .ttl = .{ .value = ttl },
    } } };
    var output: [4100]u8 = undefined;
    try t.expectEqual(@as(usize, if (reject) 4096 else 4095), codec.encodedLen(candidate));
    if (reject) try t.expectError(error.FrameTooLarge, codec.encode(candidate, &output));
    const result = state.handle(.{ .recv_message = .{
        .from = peer(3),
        .message = decoded.swarm,
    } }, &out);
    if (reject) {
        try t.expectEqual(@as(usize, 1), state.activeView().len);
        try t.expect(!state.active_view.contains(peer(3)));
        try t.expect(state.peer_data.get(peer(3)) == null);
        try t.expect(!state.pending_neighbor_requests.contains(peer(3)));
        try t.expectEqual(@as(usize, 0), out.count());
        try t.expectError(error.MessageTooLarge, result);
    } else {
        try result;
        try t.expectEqualSlices(u8, &contact, state.peer_data.get(peer(3)).?.slice());
        var forwards: usize = 0;
        for (out.slice()) |action| {
            if (action == .send_message) {
                const message: codec.Message = .{ .swarm = action.send_message.message };
                const received = try codec.decode(try codec.encode(message, &output));
                if (received.swarm == .forward_join) {
                    try t.expectEqual(@as(usize, 4095), codec.encodedLen(message));
                    try t.expectEqual(ttl, received.swarm.forward_join.ttl.value);
                    try t.expectEqualSlices(u8, &contact, received.swarm.forward_join.peer.data.?);
                    forwards += 1;
                }
            }
        }
        try t.expectEqual(@as(usize, 1), forwards);
    }
}

test "repair gossip envelope Join4057 TTL128 rejects ForwardJoin4096 before commit" {
    try membershipJoinTtl(128, true);
}

test "repair gossip envelope Join4057 TTL127 emits complete ForwardJoin4095" {
    try membershipJoinTtl(127, false);
}

fn membershipForwardInclusive(length: usize, ttl: u16, reject: bool) !void {
    const bytes: [4058]u8 = @splat(0x86);
    const contact = bytes[0..length];
    var state = try swarm.State.init(peer(1), null, .{
        .passive_random_walk_length = .{ .value = ttl },
    }, .init(42));
    var out: swarm.Actions(swarm.SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    try membershipSeed(&state, peer(2), null, &out);
    try membershipSeed(&state, peer(3), null, &out);
    var input: [4100]u8 = undefined;
    const incoming: codec.Message = .{ .swarm = .{ .forward_join = .{
        .peer = .{ .id = peer(4), .data = contact },
        .ttl = .{ .value = ttl },
    } } };
    try t.expectEqual(@as(usize, 4096), codec.encodedLen(incoming));
    const decoded = try membershipIncoming(incoming, &input);
    try t.expectEqualSlices(u8, contact, decoded.swarm.forward_join.peer.data.?);
    var output: [4100]u8 = undefined;
    const proposed: codec.Message = .{ .swarm = .{ .forward_join = .{
        .peer = decoded.swarm.forward_join.peer,
        .ttl = .{ .value = ttl - 1 },
    } } };
    try t.expectEqual(@as(usize, if (reject) 4096 else 4095), codec.encodedLen(proposed));
    if (reject) try t.expectError(error.FrameTooLarge, codec.encode(proposed, &output));
    const rng_before = state.rng;
    const result = state.handle(.{ .recv_message = .{
        .from = peer(2),
        .message = decoded.swarm,
    } }, &out);
    if (reject) {
        try t.expectEqual(@as(usize, 0), state.passiveView().len);
        try t.expect(state.peer_data.get(peer(4)) == null);
        try t.expectEqualDeep(rng_before, state.rng);
        try t.expectEqual(@as(usize, 2), state.activeView().len);
        try t.expect(!state.pending_neighbor_requests.contains(peer(4)));
        try t.expectEqual(@as(usize, 0), out.count());
        try t.expectError(error.MessageTooLarge, result);
    } else {
        try result;
        try t.expect(state.passive_view.contains(peer(4)));
        try t.expectEqualSlices(u8, contact, state.peer_data.get(peer(4)).?.slice());
        var forwards: usize = 0;
        for (out.slice()) |action| {
            if (action == .send_message) {
                try t.expectEqualSlices(
                    u8,
                    &peer(3).toBytes(),
                    &action.send_message.to.toBytes(),
                );
                const message: codec.Message = .{ .swarm = action.send_message.message };
                try t.expectEqual(@as(usize, 4095), codec.encodedLen(message));
                const received = try codec.decode(try codec.encode(message, &output));
                try t.expectEqual(ttl - 1, received.swarm.forward_join.ttl.value);
                try t.expectEqualSlices(u8, contact, received.swarm.forward_join.peer.data.?);
                forwards += 1;
            }
        }
        try t.expectEqual(@as(usize, 1), forwards);
    }
}

test "repair gossip envelope inclusive ForwardJoin4058 TTL127 rejects before passive RNG output" {
    try membershipForwardInclusive(4058, 127, true);
}

test "repair gossip envelope inclusive ForwardJoin4057 TTL128 reforward127 preserves data" {
    try membershipForwardInclusive(4057, 128, false);
}

fn membershipLocalShuffle(length: usize, reject: bool) !void {
    const bytes: [4025]u8 = @splat(0x87);
    const contact = bytes[0..length];
    var state = try swarm.State.init(peer(1), null, .{
        .shuffle_active_view_count = 1,
        .shuffle_passive_view_count = 0,
    }, .init(42));
    var out: swarm.Actions(swarm.SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    try membershipSeed(&state, peer(2), null, &out);
    try state.handle(.{ .update_peer_data = try swarm.PeerData.fromBytes(contact) }, &out);
    out.clear();
    const candidate: codec.Message = .{ .swarm = .{ .shuffle = .{
        .origin = peer(1),
        .nodes = try swarm.PeerInfos.init(&.{.{ .id = peer(1), .data = state.myData() }}),
        .ttl = state.config.shuffle_random_walk_length,
    } } };
    var output: [4100]u8 = undefined;
    try t.expectEqual(@as(usize, if (reject) 4096 else 4095), codec.encodedLen(candidate));
    if (reject) try t.expectError(error.FrameTooLarge, codec.encode(candidate, &output));
    const result = state.handle(.{ .timer_expired = .do_shuffle }, &out);
    try t.expectEqualSlices(u8, contact, state.myData().?);
    if (reject) {
        try t.expectEqual(@as(usize, 0), out.count());
        try t.expectError(error.MessageTooLarge, result);
    } else {
        try result;
        var sends: usize = 0;
        for (out.slice()) |action| {
            if (action == .send_message) {
                const message: codec.Message = .{ .swarm = action.send_message.message };
                try t.expectEqual(@as(usize, 4095), codec.encodedLen(message));
                const decoded = try codec.decode(try codec.encode(message, &output));
                try t.expectEqual(@as(u8, 1), decoded.swarm.shuffle.nodes.count);
                try t.expectEqualSlices(u8, contact, decoded.swarm.shuffle.nodes.slice()[0].data.?);
                sends += 1;
            }
        }
        try t.expectEqual(@as(usize, 1), sends);
    }
}

test "repair gossip envelope local self Shuffle4025 refuses unwritable4096 action" {
    try membershipLocalShuffle(4025, true);
}

test "repair gossip envelope local self Shuffle4024 emits complete4095 action" {
    try membershipLocalShuffle(4024, false);
}

fn membershipStoredReply(length: usize, reject: bool) !void {
    const bytes: [4058]u8 = @splat(0x88);
    const contact = bytes[0..length];
    var state = try swarm.State.init(peer(1), null, .{
        .passive_view_capacity = 0,
    }, .init(42));
    var out: swarm.Actions(swarm.SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    var input: [4100]u8 = undefined;
    const join = try membershipIncoming(.{ .swarm = .{ .join = contact } }, &input);
    try state.handle(.{ .recv_message = .{
        .from = peer(2),
        .message = join.swarm,
    } }, &out);
    try t.expectEqualSlices(u8, contact, state.peer_data.get(peer(2)).?.slice());
    out.clear();
    const reply: codec.Message = .{ .swarm = .{ .shuffle_reply = .{
        .nodes = try swarm.PeerInfos.init(&.{.{ .id = peer(2), .data = contact }}),
    } } };
    var output: [4100]u8 = undefined;
    try t.expectEqual(@as(usize, if (reject) 4096 else 4095), codec.encodedLen(reply));
    if (reject) try t.expectError(error.FrameTooLarge, codec.encode(reply, &output));
    const shuffle = try membershipIncoming(.{ .swarm = .{ .shuffle = .{
        .origin = peer(3),
        .nodes = try swarm.PeerInfos.init(&.{.{ .id = peer(3), .data = null }}),
        .ttl = .{ .value = 0 },
    } } }, &input);
    const result = state.handle(.{ .recv_message = .{
        .from = peer(2),
        .message = shuffle.swarm,
    } }, &out);
    try t.expectEqualSlices(u8, contact, state.peer_data.get(peer(2)).?.slice());
    try t.expectEqual(@as(usize, 1), state.activeView().len);
    if (reject) {
        try t.expectEqual(@as(usize, 0), out.count());
        try t.expectError(error.MessageTooLarge, result);
    } else {
        try result;
        var sends: usize = 0;
        for (out.slice()) |action| {
            if (action == .send_message) {
                const message: codec.Message = .{ .swarm = action.send_message.message };
                try t.expectEqual(@as(usize, 4095), codec.encodedLen(message));
                const decoded = try codec.decode(try codec.encode(message, &output));
                try t.expectEqual(@as(u8, 1), decoded.swarm.shuffle_reply.nodes.count);
                try t.expectEqualSlices(u8, contact, decoded.swarm.shuffle_reply.nodes.slice()[0].data.?);
                sends += 1;
            }
        }
        try t.expectEqual(@as(usize, 1), sends);
    }
}

test "repair gossip envelope stored4058 expired Shuffle refuses ShuffleReply4096 action" {
    try membershipStoredReply(4058, true);
}

test "repair gossip envelope stored4057 expired Shuffle emits complete ShuffleReply4095" {
    try membershipStoredReply(4057, false);
}

test "repair gossip envelope inclusive Join4091 remains receivable without forward recipient" {
    const contact: [4091]u8 = @splat(0x89);
    const own = [_]u8{0x8a};
    var state = try swarm.State.init(peer(1), try swarm.PeerData.fromBytes(&own), .{}, .init(42));
    var out: swarm.Actions(swarm.SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    var input: [4100]u8 = undefined;
    const incoming: codec.Message = .{ .swarm = .{ .join = &contact } };
    try t.expectEqual(@as(usize, 4096), codec.encodedLen(incoming));
    const decoded = try membershipIncoming(incoming, &input);
    try state.handle(.{ .recv_message = .{
        .from = peer(2),
        .message = decoded.swarm,
    } }, &out);
    try t.expect(state.active_view.contains(peer(2)));
    try t.expectEqualSlices(u8, &contact, state.peer_data.get(peer(2)).?.slice());
    var output: [4100]u8 = undefined;
    var neighbors: usize = 0;
    for (out.slice()) |action| {
        if (action == .send_message) {
            const message: codec.Message = .{ .swarm = action.send_message.message };
            try t.expect(message.swarm == .neighbor);
            const received = try codec.decode(try codec.encode(message, &output));
            try t.expectEqualSlices(u8, &own, received.swarm.neighbor.data.?);
            neighbors += 1;
        }
    }
    try t.expectEqual(@as(usize, 1), neighbors);
}

test "repair gossip envelope stored round128 Graft rejects before requester eager mutation" {
    const content: [4057]u8 = @splat(0x8b);
    const id = tree.MessageId.fromContent(&content);
    var state: tree.State = .init(peer(1), .{});
    try state.addLazy(peer(3));
    const cached: tree.Gossip = .{
        .id = id,
        .content = &content,
        .scope = .{ .swarm = .{ .value = 128 } },
    };
    try state.cache.put(cached, 1_000_000);
    try t.expectEqual(@as(usize, 1), state.cache.count());
    try t.expectEqualSlices(u8, &content, state.cache.get(id).?.content);
    try t.expectEqual(@as(u16, 128), state.cache.get(id).?.scope.swarm.value);
    var output: [4100]u8 = undefined;
    const candidate: codec.Message = .{ .gossip = .{ .gossip = cached } };
    try t.expectEqual(@as(usize, 4096), codec.encodedLen(candidate));
    try t.expectError(error.FrameTooLarge, codec.encode(candidate, &output));
    var out: tree.Actions(tree.OutEvent) = .init(t.allocator);
    defer out.deinit();
    const result = state.handle(.{ .recv_message = .{
        .from = peer(3),
        .message = .{ .graft = .{ .id = id, .round = .{ .value = 128 } } },
    } }, 0, &out);
    for (out.slice()) |action| {
        if (action == .send_message) {
            try t.expect(action.send_message.message != .gossip);
            const message: codec.Message = .{ .gossip = action.send_message.message };
            const written = try codec.encode(message, &output);
            try t.expectEqual(codec.encodedLen(message) + 4, written.len);
        }
    }
    try t.expect(!state.eager_push_peers.contains(peer(3)));
    try t.expect(state.lazy_push_peers.contains(peer(3)));
    try t.expectEqual(@as(usize, 1), state.cache.count());
    try t.expectEqualSlices(u8, &content, state.cache.get(id).?.content);
    try t.expectError(error.MessageTooLarge, result);
}

test "repair gossip envelope Neighbor4095 accepts tiny Join with full own4089 data" {
    const own: [4089]u8 = @splat(0x8c);
    const contact = [_]u8{0x8d};
    var state = try swarm.State.init(peer(1), try swarm.PeerData.fromBytes(&own), .{}, .init(42));
    var out: swarm.Actions(swarm.SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    var input: [4100]u8 = undefined;
    const decoded = try membershipIncoming(.{ .swarm = .{ .join = &contact } }, &input);
    try state.handle(.{ .recv_message = .{
        .from = peer(2),
        .message = decoded.swarm,
    } }, &out);
    try t.expect(state.active_view.contains(peer(2)));
    try t.expect(state.pending_neighbor_requests.contains(peer(2)));
    try t.expectEqualSlices(u8, &contact, state.peer_data.get(peer(2)).?.slice());
    var output: [4100]u8 = undefined;
    var neighbors: usize = 0;
    for (out.slice()) |action| {
        if (action == .send_message) {
            const message: codec.Message = .{ .swarm = action.send_message.message };
            try t.expect(message.swarm == .neighbor);
            try t.expectEqual(@as(usize, 4095), codec.encodedLen(message));
            const received = try codec.decode(try codec.encode(message, &output));
            try t.expectEqualSlices(u8, &own, received.swarm.neighbor.data.?);
            neighbors += 1;
        }
    }
    try t.expectEqual(@as(usize, 1), neighbors);
}

test "repair gossip envelope peerGone after selected connection expiry preserves authenticated alternate" {
    const node_gossip = @import("node/node_gossip.zig");
    const topics = [_]swarm.TopicId{swarm.TopicId.fromBytes(@splat(0x79))};
    var deliveries: Deliveries = .{};
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
        .on_gossip = Deliveries.receive,
        .on_gossip_context = &deliveries,
    }, 936);
    defer closeNode(node);
    var clients: [2]bridge_peer.Client = undefined;
    try gossipClient(&clients[0], client_secret, node.nodeId(), 937, .{
        .server = node.address(),
        .client = first_socket.address,
    });
    defer clients[0].deinit();
    try exchangeDirect(&clients[0], node, first_socket.address);
    try gossipClient(&clients[1], client_secret, node.nodeId(), 938, .{
        .server = node.address(),
        .client = second_socket.address,
    });
    defer clients[1].deinit();
    try exchangeDirect(&clients[1], node, second_socket.address);
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
        @import("transport/quic_bridge.zig").Tick.finished,
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

fn remainingReceive(length: usize, scope: tree.DeliveryScope, reject: bool) !void {
    const bytes: [4060]u8 = @splat(0x91);
    const content = bytes[0..length];
    const id = tree.MessageId.fromContent(content);
    const incoming: codec.Message = .{ .gossip = .{ .gossip = .{
        .id = id,
        .content = content,
        .scope = scope,
    } } };
    try t.expectEqual(@as(usize, if (reject) 4097 else 4096), codec.encodedLen(incoming));
    var state: tree.State = .init(peer(1), .{});
    try state.addEager(peer(2));
    try state.addEager(peer(3));
    try state.addLazy(peer(4));
    var out: tree.Actions(tree.OutEvent) = .init(t.allocator);
    defer out.deinit();
    var input: [4101]u8 = undefined;
    if (reject) {
        std.mem.writeInt(u32, input[0..4], 4097, .big);
        var writer = @import("wire/postcard.zig").Writer.init(input[4..]);
        try codec.encodeBody(incoming, &writer);
        try t.expectEqual(@as(usize, 4097), writer.finish().len);
    }
    // Over-budget bodies cannot decode, but the public state API must reject them too.
    const message = if (reject) incoming else try membershipIncoming(incoming, &input);
    const result = state.handle(.{ .recv_message = .{
        .from = peer(2),
        .message = message.gossip,
    } }, 0, &out);
    try t.expectEqual(@as(usize, 0), state.cache.count());
    try t.expectEqual(@as(usize, 0), state.lazy_push_queue_len);
    try t.expect(!state.dispatch_timer_scheduled);
    try t.expect(state.eager_push_peers.contains(peer(2)));
    try t.expect(state.eager_push_peers.contains(peer(3)));
    try t.expect(state.lazy_push_peers.contains(peer(4)));
    if (reject) {
        try t.expectEqual(@as(usize, 0), state.received_messages.count());
        try t.expectEqual(@as(usize, 0), out.count());
        try t.expectError(error.MessageTooLarge, result);
    } else {
        try result;
        try t.expectEqual(@as(usize, if (scope == .swarm) 1 else 0), state.received_messages.count());
        if (scope == .swarm) try t.expect(state.received_messages.contains(id));
        var delivered: usize = 0;
        var output: [4100]u8 = undefined;
        for (out.slice()) |action| {
            switch (action) {
                .emit_event => |event| {
                    try t.expectEqualSlices(u8, content, event.content);
                    try t.expectEqual(peer(2), event.delivered_from);
                    try t.expectEqualDeep(scope, event.scope);
                    delivered += 1;
                },
                .send_message => |send| {
                    const candidate: codec.Message = .{ .gossip = send.message };
                    try t.expect(codec.encodedLen(candidate) < codec.max_message_size);
                    _ = try codec.encode(candidate, &output);
                    try t.expect(send.message != .gossip);
                    try t.expect(send.message != .i_have);
                },
                .schedule_timer => |timer| {
                    try t.expect(timer.timer != .dispatch_lazy_push);
                },
            }
        }
        try t.expectEqual(@as(usize, 1), delivered);
    }
}

test "repair gossip remaining inclusive neighbors4059 delivers without derived state" {
    try remainingReceive(4059, .neighbors, false);
}

test "repair gossip remaining inclusive swarm4057 round128 delivers and records ID" {
    try remainingReceive(4057, .{ .swarm = .{ .value = 128 } }, false);
}

test "repair gossip remaining direct swarm4059 round0 body4097 rejects before mutation" {
    try remainingReceive(4059, .{ .swarm = .zero }, true);
}

test "repair gossip remaining direct neighbors4060 body4097 rejects before mutation" {
    try remainingReceive(4060, .neighbors, true);
}

fn remainingContacts() !swarm.PeerInfos {
    return swarm.PeerInfos.init(&.{
        .{ .id = peer(3), .data = "three" },
        .{ .id = peer(4), .data = "four" },
        .{ .id = peer(5), .data = "five" },
    });
}

fn remainingAcceptContacts(
    state: *swarm.State,
    out: *swarm.Actions(swarm.SwarmOutEvent),
) !void {
    var input: [4100]u8 = undefined;
    const decoded = try membershipIncoming(.{ .swarm = .{ .shuffle_reply = .{
        .nodes = try remainingContacts(),
    } } }, &input);
    try state.handle(.{ .recv_message = .{
        .from = peer(6),
        .message = decoded.swarm,
    } }, out);
}

fn remainingExpectContacts(state: *const swarm.State, excluded: ?NodeId) !void {
    const contacts = try remainingContacts();
    var retained: usize = 0;
    for (contacts.slice()) |contact| {
        const removed = if (excluded) |id|
            std.mem.eql(u8, &contact.id.toBytes(), &id.toBytes())
        else
            false;
        try t.expectEqual(!removed, state.passive_view.contains(contact.id));
        // Timeout removes eligibility, not the contact record.
        try t.expectEqualSlices(u8, contact.data.?, state.peer_data.get(contact.id).?.slice());
        if (!removed) retained += 1;
    }
    try t.expectEqual(retained, state.passiveView().len);
}

fn remainingExpectNoRefill(out: *const swarm.Actions(swarm.SwarmOutEvent)) !void {
    for (out.slice()) |action| {
        switch (action) {
            .send_message => try t.expect(false),
            .schedule_timer => |timer| try t.expect(timer.timer == .do_shuffle),
            else => {},
        }
    }
}

fn remainingPendingTimer(
    state: *const swarm.State,
    out: *const swarm.Actions(swarm.SwarmOutEvent),
) !swarm.SwarmTimer {
    try t.expectEqual(@as(usize, 1), state.pending_neighbor_requests.count());
    const pending = state.pending_neighbor_requests.slice()[0];
    try t.expect(state.passive_view.contains(pending));
    var timer: ?swarm.SwarmTimer = null;
    var neighbors: usize = 0;
    for (out.slice()) |action| {
        if (action == .schedule_timer and
            action.schedule_timer.timer == .pending_neighbor_request)
        {
            try t.expect(timer == null);
            timer = action.schedule_timer.timer;
            try t.expectEqual(pending, timer.?.pending_neighbor_request);
        }
        if (action == .send_message and action.send_message.message == .neighbor) {
            try t.expectEqual(pending, action.send_message.to);
            neighbors += 1;
        }
    }
    try t.expectEqual(@as(usize, 1), neighbors);
    try t.expect(timer != null);
    return timer.?;
}

test "repair gossip remaining ShuffleReply retains three contacts when own Neighbor4096 cannot fit" {
    const own: [4090]u8 = @splat(0x92);
    var state = try swarm.State.init(peer(1), try swarm.PeerData.fromBytes(&own), .{}, .init(42));
    var out: swarm.Actions(swarm.SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    var rng_before = state.rng;
    const result = remainingAcceptContacts(&state, &out);
    try remainingExpectContacts(&state, null);
    try t.expectEqual(@as(usize, 3), state.peer_data.count());
    try t.expectEqual(@as(usize, 0), state.activeView().len);
    try t.expectEqual(@as(usize, 0), state.pending_neighbor_requests.count());
    try remainingExpectNoRefill(&out);
    var rng_after = state.rng;
    for (0..4) |_| try t.expectEqual(rng_before.next(), rng_after.next());
    try result;
}

test "repair gossip remaining pending timeout removes failed target without unwritable replacement" {
    var state = try swarm.State.init(peer(1), null, .{}, .init(42));
    var out: swarm.Actions(swarm.SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    try remainingAcceptContacts(&state, &out);
    const timer = try remainingPendingTimer(&state, &out);
    try remainingExpectContacts(&state, null);
    const own: [4090]u8 = @splat(0x93);
    try state.handle(.{ .update_peer_data = try swarm.PeerData.fromBytes(&own) }, &out);
    out.clear();
    var rng_before = state.rng;
    const result = state.handle(.{ .timer_expired = timer }, &out);
    try t.expectEqual(@as(usize, 0), state.pending_neighbor_requests.count());
    try t.expectEqual(@as(usize, 0), state.activeView().len);
    try remainingExpectContacts(&state, timer.pending_neighbor_request);
    try remainingExpectNoRefill(&out);
    try t.expectEqual(@as(usize, 0), out.count());
    var rng_after = state.rng;
    for (0..4) |_| try t.expectEqual(rng_before.next(), rng_after.next());
    try result;
}

test "repair gossip remaining departure preserves pending contacts and required down actions" {
    var state = try swarm.State.init(peer(1), null, .{}, .init(42));
    var out: swarm.Actions(swarm.SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    try membershipSeed(&state, peer(2), "two", &out);
    // Complete the real Neighbor exchange so peer2 is not an outstanding request.
    try state.handle(.{ .recv_message = .{
        .from = peer(2),
        .message = .{ .neighbor = .{ .priority = .high, .data = "two" } },
    } }, &out);
    out.clear();
    try t.expectEqual(@as(usize, 0), state.pending_neighbor_requests.count());
    try remainingAcceptContacts(&state, &out);
    const timer = try remainingPendingTimer(&state, &out);
    try remainingExpectContacts(&state, null);
    const own: [4090]u8 = @splat(0x94);
    try state.handle(.{ .update_peer_data = try swarm.PeerData.fromBytes(&own) }, &out);
    out.clear();
    var rng_before = state.rng;
    const result = state.handle(.{ .peer_disconnected = peer(2) }, &out);
    try t.expect(!state.active_view.contains(peer(2)));
    try t.expectEqual(@as(usize, 0), state.activeView().len);
    try t.expectEqual(@as(usize, 1), state.pending_neighbor_requests.count());
    try t.expect(state.pending_neighbor_requests.contains(timer.pending_neighbor_request));
    try remainingExpectContacts(&state, null);
    try remainingExpectNoRefill(&out);
    var down: usize = 0;
    var disconnects: usize = 0;
    for (out.slice()) |action| {
        if (action == .emit_event) {
            try t.expect(action.emit_event == .neighbor_down);
            try t.expectEqual(peer(2), action.emit_event.neighbor_down);
            down += 1;
        }
        if (action == .disconnect_peer) {
            try t.expectEqual(peer(2), action.disconnect_peer);
            disconnects += 1;
        }
    }
    try t.expectEqual(@as(usize, 1), down);
    try t.expectEqual(@as(usize, 1), disconnects);
    try t.expectEqual(@as(usize, 2), out.count());
    var rng_after = state.rng;
    for (0..4) |_| try t.expectEqual(rng_before.next(), rng_after.next());
    try result;
}

test "repair gossip remaining inclusive swarm4056 round65535 wraps into writable4094 forward" {
    const content: [4056]u8 = @splat(0x95);
    const id = tree.MessageId.fromContent(&content);
    const incoming: codec.Message = .{ .gossip = .{ .gossip = .{
        .id = id,
        .content = &content,
        .scope = .{ .swarm = .{ .value = 65535 } },
    } } };
    try t.expectEqual(@as(usize, 4096), codec.encodedLen(incoming));
    var input: [4100]u8 = undefined;
    const decoded = try membershipIncoming(incoming, &input);
    var state: tree.State = .init(peer(1), .{});
    try state.addEager(peer(2));
    try state.addEager(peer(3));
    var out: tree.Actions(tree.OutEvent) = .init(t.allocator);
    defer out.deinit();
    try state.handle(.{ .recv_message = .{
        .from = peer(2),
        .message = decoded.gossip,
    } }, 0, &out);
    try t.expectEqual(@as(usize, 1), state.received_messages.count());
    try t.expect(state.received_messages.contains(id));
    try t.expectEqual(@as(usize, 1), state.cache.count());
    const cached = state.cache.get(id).?;
    try t.expectEqualSlices(u8, &content, cached.content);
    try t.expectEqual(@as(u16, 0), cached.scope.swarm.value);
    try t.expectEqual(@as(usize, 4094), codec.encodedLen(.{ .gossip = .{ .gossip = cached } }));
    var delivered: usize = 0;
    var forwards: usize = 0;
    var output: [4100]u8 = undefined;
    for (out.slice()) |action| {
        if (action == .emit_event) {
            try t.expectEqualSlices(u8, &content, action.emit_event.content);
            try t.expectEqual(peer(2), action.emit_event.delivered_from);
            try t.expectEqual(@as(u16, 65535), action.emit_event.scope.swarm.value);
            delivered += 1;
        }
        if (action == .send_message) {
            try t.expectEqual(peer(3), action.send_message.to);
            const message: codec.Message = .{ .gossip = action.send_message.message };
            try t.expectEqual(@as(usize, 4094), codec.encodedLen(message));
            const received = try codec.decode(try codec.encode(message, &output));
            try t.expectEqualSlices(u8, &content, received.gossip.gossip.content);
            try t.expectEqual(@as(u16, 0), received.gossip.gossip.scope.swarm.value);
            forwards += 1;
        }
    }
    try t.expectEqual(@as(usize, 1), delivered);
    try t.expectEqual(@as(usize, 1), forwards);
}

fn remainingNeighborsBroadcast(length: usize, reject: bool) !void {
    const bytes: [4059]u8 = @splat(0x96);
    const content = bytes[0..length];
    const message: codec.Message = .{ .gossip = .{ .gossip = .{
        .id = tree.MessageId.fromContent(content),
        .content = content,
        .scope = .neighbors,
    } } };
    try t.expectEqual(@as(usize, if (reject) 4096 else 4095), codec.encodedLen(message));
    var state: tree.State = .init(peer(1), .{});
    try state.addEager(peer(2));
    try state.addLazy(peer(3));
    var out: tree.Actions(tree.OutEvent) = .init(t.allocator);
    defer out.deinit();
    const result = state.broadcast(content, .neighbors, 0, &out);
    try t.expectEqual(@as(usize, 0), state.cache.count());
    try t.expectEqual(@as(usize, 0), state.received_messages.count());
    try t.expectEqual(@as(usize, 0), state.lazy_push_queue_len);
    try t.expect(!state.dispatch_timer_scheduled);
    if (reject) {
        try t.expectEqual(@as(usize, 0), out.count());
        try t.expectError(error.MessageTooLarge, result);
    } else {
        try result;
        try t.expectEqual(@as(usize, 1), out.count());
        const action = out.at(0);
        try t.expect(action == .send_message);
        try t.expectEqual(peer(2), action.send_message.to);
        var output: [4100]u8 = undefined;
        const candidate: codec.Message = .{ .gossip = action.send_message.message };
        try t.expectEqual(@as(usize, 4095), codec.encodedLen(candidate));
        const decoded = try codec.decode(try codec.encode(candidate, &output));
        try t.expect(decoded.gossip.gossip.scope == .neighbors);
        try t.expectEqualSlices(u8, content, decoded.gossip.gossip.content);
    }
}

test "repair gossip remaining local neighbors4058 writes full body4095 without tree state" {
    try remainingNeighborsBroadcast(4058, false);
}

test "repair gossip remaining local neighbors4059 refuses before eager output or cache" {
    try remainingNeighborsBroadcast(4059, true);
}

fn finalLocalBroadcastAdmission(scope: tree.Scope, length: usize) !void {
    // Admission must precede the first-event timer, not just the payload cache.
    const bytes: [4059]u8 = @splat(0xa1);
    var state: tree.State = .init(peer(1), .{
        .message_cache_retention = 10,
        .message_id_retention = 20,
        .cache_evict_interval = 25,
    });
    try state.addEager(peer(2));
    try state.addLazy(peer(3));
    var out: tree.Actions(tree.OutEvent) = .init(t.allocator);
    defer out.deinit();
    const rejected = bytes[0..length];
    try t.expectError(error.MessageTooLarge, state.handle(.{ .broadcast = .{
        .content = rejected,
        .scope = scope,
    } }, 100, &out));
    try t.expectEqual(@as(usize, 0), out.count());
    try t.expect(!state.started);
    try t.expectEqual(@as(usize, 0), state.cache.count());
    try t.expectEqual(@as(usize, 0), state.received_messages.count());
    try t.expectEqual(@as(usize, 0), state.lazy_push_queue_len);
    try t.expect(!state.dispatch_timer_scheduled);

    const content = "accepted after first local refusal";
    try state.handle(.{ .broadcast = .{
        .content = content,
        .scope = scope,
    } }, 100, &out);
    try t.expect(state.started);
    var evictions: usize = 0;
    var dispatches: usize = 0;
    var payloads: usize = 0;
    for (out.slice()) |action| {
        switch (action) {
            .schedule_timer => |schedule| switch (schedule.timer) {
                .evict_cache => {
                    try t.expectEqual(@as(u64, 25), schedule.after);
                    evictions += 1;
                },
                .dispatch_lazy_push => {
                    try t.expect(scope == .swarm);
                    dispatches += 1;
                },
                .send_graft => return error.UnexpectedGraftTimer,
            },
            .send_message => |send| {
                try t.expectEqual(peer(2), send.to);
                try t.expect(send.message == .gossip);
                const gossip = send.message.gossip;
                try t.expectEqual(tree.MessageId.fromContent(content), gossip.id);
                try t.expectEqualSlices(u8, content, gossip.content);
                switch (scope) {
                    .swarm => {
                        try t.expect(gossip.scope == .swarm);
                        try t.expectEqual(@as(u16, 0), gossip.scope.swarm.value);
                    },
                    .neighbors => try t.expect(gossip.scope == .neighbors),
                }
                payloads += 1;
            },
            .emit_event => return error.UnexpectedLocalDelivery,
        }
    }
    try t.expectEqual(@as(usize, 1), evictions);
    try t.expectEqual(@as(usize, 1), payloads);
    try t.expectEqual(@as(usize, if (scope == .swarm) 1 else 0), dispatches);
    try t.expectEqual(@as(usize, if (scope == .swarm) 3 else 2), out.count());
    try t.expectEqual(@as(usize, if (scope == .swarm) 1 else 0), state.cache.count());
    try t.expectEqual(
        @as(usize, if (scope == .swarm) 1 else 0),
        state.received_messages.count(),
    );

    // Fire the published sweep: a real timer maintains and rearms both caches.
    out.clear();
    try state.handle(.{ .timer_expired = .evict_cache }, 125, &out);
    try t.expectEqual(@as(usize, 0), state.cache.count());
    try t.expectEqual(@as(usize, 0), state.received_messages.count());
    try t.expectEqual(@as(usize, 1), out.count());
    const maintenance = out.at(0);
    try t.expect(maintenance == .schedule_timer);
    try t.expect(maintenance.schedule_timer.timer == .evict_cache);
    try t.expectEqual(@as(u64, 25), maintenance.schedule_timer.after);
}

test "repair gossip final first handle broadcast swarm4058 refuses before initialization" {
    try finalLocalBroadcastAdmission(.swarm, 4058);
}

test "repair gossip final first handle broadcast neighbors4059 refuses before initialization" {
    try finalLocalBroadcastAdmission(.neighbors, 4059);
}
