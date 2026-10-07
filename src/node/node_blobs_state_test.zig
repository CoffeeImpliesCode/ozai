const std = @import("std");
const blobs = @import("node_blobs.zig");
const bridge_mod = @import("../transport/quic_bridge.zig");
const peer = @import("../transport/bridge_peer.zig");
const key = @import("../base/key.zig");
const addr_map = @import("../transport/addr_map.zig");
const protocol = @import("../blobs/protocol.zig");
const store = @import("../blobs/store.zig");
const bao = @import("../blobs/bao_outboard.zig");
const provider_mod = @import("../blobs/provider.zig");
const quic = @import("quic");
const bridge_address = @import("../transport/bridge_address.zig");
const t = std.testing;

const Fixture = struct {
    bridge: *bridge_mod.Bridge,
    client: peer.Client,
    map: addr_map.MappedAddrs,

    fn init(self: *Fixture) !void {
        var server_secret = try key.SecretKey.fromSeed(peer.server_seed);
        defer server_secret.deinit();
        var client_secret = try key.SecretKey.fromSeed(peer.client_seed);
        defer client_secret.deinit();
        var engine = peer.Prng.init(917);
        self.bridge = try bridge_mod.Bridge.create(t.allocator, t.io, .{
            .secret = server_secret,
            .alpn = protocol.alpn,
        }, engine.random());
        errdefer self.bridge.destroy();
        self.map = addr_map.MappedAddrs.init();
        errdefer self.map.deinit(t.allocator);
        self.client = .{
            .conn = undefined,
            .engine = peer.Prng.init(918),
            .spki = quic.tls13.ed25519Spki(&client_secret.nodeId().toBytes()),
            .cert_chain = undefined,
            .alpn_list = .{protocol.alpn},
            .seed = client_secret.toBytes()[0..key.SecretKey.seed_length].*,
        };
        self.client.cert_chain = .{&self.client.spki};
        self.client.conn = try t.allocator.create(quic.connection.Connection);
        errdefer t.allocator.destroy(self.client.conn);
        try quic.connection.connectInto(
            self.client.conn,
            t.allocator,
            peer.server_name,
            .{},
            .{
                .cert_chain_der = &.{},
                .private_key_bytes = &.{},
                .alpn = &self.client.alpn_list,
                .server_name = peer.server_name,
                .expect_peer_node_id = server_secret.nodeId().toBytes(),
                .client_certificate = .{
                    .cert_chain_der = &self.client.cert_chain,
                    .private_key_bytes = &self.client.seed,
                    .private_key_algorithm = .ed25519,
                },
            },
            null,
            peer.start,
            self.client.random(),
        );
        errdefer self.client.conn.deinit();
        self.client.conn.paths[0].peer_addr = bridge_address.toCoreAddress(peer.server_addr);
        self.client.conn.paths[0].local_addr = bridge_address.toCoreAddress(peer.client_addr);
        try peer.exchange(&self.client, self.bridge, &self.map, peer.start);
        try t.expect(self.bridge.connectionAt(0).?.established());
    }

    fn deinit(self: *Fixture) void {
        self.client.deinit();
        self.map.deinit(t.allocator);
        self.bridge.destroy();
    }
};

// A real Bao answer with trailing bytes must not be decoded until all receive runs are consumed.
test "blob state defers trailing byte rejection until the finished response is drained" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const data = try t.allocator.alloc(u8, 49189);
    defer t.allocator.free(data);
    for (data, 0..) |*byte, i| byte.* = @intCast(i % 251);
    const tree = bao.BaoTree.init(data.len);
    const hash = try tree.rootHash(data);
    const outboard = try t.allocator.alloc(u8, @intCast(bao.bytes(tree)));
    defer t.allocator.free(outboard);
    const written = try bao.encode(tree, data, outboard);
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var names: store.NameStorage = undefined;
    const paths = store.names(&names, hash);
    {
        const partial = try store.createPartial(t.io, tmp.dir, paths);
        defer partial.close(t.io);
        try partial.data.writeStreamingAll(t.io, data);
        try partial.outboard.writeStreamingAll(t.io, outboard[0..written]);
    }
    try store.commit(t.io, tmp.dir, paths);
    var scratch: [16384]u8 = undefined;
    const provider = try provider_mod.Provider.init(tmp.dir, &names, hash, &scratch);
    var response: std.Io.Writer.Allocating = .init(t.allocator);
    defer response.deinit();
    try t.expectEqual(.answered, try provider.answer(
        t.io, &response.writer, protocol.GetRequest.blob(hash),
    ));
    const trailing = try t.allocator.alloc(u8, 65 * 65536);
    defer t.allocator.free(trailing);
    @memset(trailing, 0xa5);
    try response.writer.writeAll(trailing);
    var state: blobs.State = .init(.{ .getter = .{ .hash = hash, .size = data.len } });
    defer state.deinit(t.allocator);
    try t.expect(try state.drive(t.allocator, t.io, fixture.bridge));
    const conn = fixture.bridge.connectionAt(0).?;
    const core = conn.entry.conn.streams.streams.get(1).?;
    const wire = response.written();
    core.recv.receive_window = wire.len;
    var offset: usize = 0;
    while (offset < wire.len) {
        const end = @min(offset + 65536, wire.len);
        try core.recv.handleStreamFrame(offset, wire[offset..end], end == wire.len);
        offset = end;
    }
    try t.expect(core.recv.allReceived());
    try t.expect(core.recv.sorter.chunks.items.len > 64);
    try t.expect(try state.drive(t.allocator, t.io, fixture.bridge));
    try t.expectEqual(@as(u64, 0), state.completed);
    try t.expect(state.payload(conn.id()) == null);
    try t.expect(core.recv.peekLen() != null);
    try t.expect(try state.drive(t.allocator, t.io, fixture.bridge));
    try t.expectEqual(@as(u64, 0), state.completed);
    try t.expectError(error.TrailingBytes, state.drive(t.allocator, t.io, fixture.bridge));
    try t.expectEqual(@as(u64, 0), state.completed);
    try t.expect(state.payload(conn.id()) == null);
}

// The provider must reject excess request bytes even when the peer never sends FIN.
test "blob provider rejects oversized accumulation before FIN" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var state: blobs.State = .init(.{ .provider = .{ .dir = tmp.dir, .hash = @splat(0) } });
    defer state.deinit(t.allocator);
    const conn = fixture.bridge.connectionAt(0).?;
    const core = try conn.entry.conn.streams.getOrCreateStream(0);
    const bytes = try t.allocator.alloc(u8, protocol.max_message_size + 2);
    defer t.allocator.free(bytes);
    @memset(bytes, 0);
    core.recv.receive_window = bytes.len;
    try core.recv.handleStreamFrame(0, bytes, false);
    try t.expect(!core.recv.allReceived());
    try t.expectError(error.MessageTooLarge, state.drive(t.allocator, t.io, fixture.bridge));
    try t.expectEqual(@as(u64, 0), state.completed);
    try t.expectEqual(@as(u64, 0), state.sent_bytes);
}

// Answered stream IDs stay remembered without borrowed handles, then disappear with the connection.
test "blob provider handles more than sixteen streams and prunes disconnected state" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var state: blobs.State = .init(.{ .provider = .{ .dir = tmp.dir, .hash = @splat(0) } });
    defer state.deinit(t.allocator);
    const conn = fixture.bridge.connectionAt(0).?;
    var request_buffer: [128]u8 = undefined;
    const request = try blobs.encodeRequest(.{ .hash = @splat(0) }, &request_buffer);
    for (0..20) |index| {
        const core = try conn.entry.conn.streams.getOrCreateStream(index * 4);
        try core.recv.handleStreamFrame(0, request, true);
    }
    try t.expect(try state.drive(t.allocator, t.io, fixture.bridge));
    try t.expect(try state.drive(t.allocator, t.io, fixture.bridge));
    try t.expectEqual(@as(usize, 20), state.transfers.items.len);
    for (state.transfers.items) |transfer| {
        try t.expect(transfer.done);
        try t.expect(transfer.stream == null);
        try t.expectEqual(@as(usize, 0), transfer.bytes.items.len);
    }
    const received = state.received_bytes;
    try t.expect(!try state.drive(t.allocator, t.io, fixture.bridge));
    try t.expectEqual(received, state.received_bytes);
    try t.expectEqual(@as(u64, 0), state.completed);
    fixture.bridge.manager.removeConnection(conn.entry);
    fixture.bridge.sweep();
    try t.expect(!try state.drive(t.allocator, t.io, fixture.bridge));
    try t.expectEqual(@as(usize, 0), state.transfers.items.len);
}
