//! Authenticated direct-path fixtures for private Node gossip consumers.
const std = @import("std");
const node_mod = @import("node.zig");
const bridge_peer = @import("../transport/bridge_peer.zig");
const bridge_address = @import("../transport/bridge_address.zig");
const key = @import("../base/key.zig");
const NodeId = key.NodeId;
const quic = @import("quic");
const swarm = @import("../gossip/hyparview.zig");
const SocketAddr = @import("../base/addr.zig").SocketAddr;
const t = std.testing;

pub fn gossipClient(
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

pub fn exchangeDirect(client: *bridge_peer.Client, node: *node_mod.Node, from: SocketAddr) !void {
    var scratch: [2 * bridge_peer.max_datagram]u8 = undefined;
    var egress: [bridge_peer.max_egress]@import("../transport/quic_bridge.zig").Egress = undefined;
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
                        var runs = try @import("../transport/batch.zig").Runs.init(send.send, .none);
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

pub const Deliveries = struct {
    first: bool = false,
    second: bool = false,

    pub fn receive(context: ?*anyopaque, _: swarm.TopicId, _: NodeId, content: []const u8) void {
        const self: *Deliveries = @ptrCast(@alignCast(context.?));
        if (std.mem.eql(u8, content, "first")) self.first = true;
        if (std.mem.eql(u8, content, "second")) self.second = true;
    }
};

pub fn closeNode(node: *node_mod.Node) void {
    defer node.deinit();
    node.close(t.io, bridge_peer.start, node.generator()) catch
        @panic("failed to close gossip test node");
}
