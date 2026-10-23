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
const test_scratch = @import("test_scratch");
const t = std.testing;

const Fixture = struct {
    bridge: *bridge_mod.Bridge,
    client: peer.Client,
    map: addr_map.MappedAddrs,

    fn init(self: *Fixture) !void {
        try self.initAllocator(t.allocator);
    }

    fn initAllocator(self: *Fixture, gpa: std.mem.Allocator) !void {
        var server_secret = try key.SecretKey.fromSeed(peer.server_seed);
        defer server_secret.deinit();
        var engine = peer.Prng.init(917);
        self.bridge = try bridge_mod.Bridge.create(gpa, t.io, .{
            .secret = server_secret,
            .alpn = protocol.alpn,
        }, engine.random());
        errdefer self.bridge.destroy();
        try self.connectClient(918);
    }

    fn connectClient(self: *Fixture, seed: u64) !void {
        var server_secret = try key.SecretKey.fromSeed(peer.server_seed);
        defer server_secret.deinit();
        var client_secret = try key.SecretKey.fromSeed(peer.client_seed);
        defer client_secret.deinit();
        self.map = addr_map.MappedAddrs.init();
        errdefer self.map.deinit(t.allocator);
        self.client = .{
            .conn = undefined,
            .engine = peer.Prng.init(seed),
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
        const conn = self.bridge.connectionAt(0) orelse return error.TestUnexpectedResult;
        try t.expect(conn.established());
    }

    fn deinit(self: *Fixture) void {
        self.client.deinit();
        self.map.deinit(t.allocator);
        self.bridge.destroy();
        self.* = undefined;
    }
};

// An exact Bao response can wait for FIN, but appended bytes cannot grow transfer storage.
test "blob state rejects bytes beyond complete proof before provider FIN" {
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
    var tmp = try test_scratch.tmpDir(.{});
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
        t.io,
        &response.writer,
        protocol.GetRequest.blob(hash),
    ));
    var state: blobs.State = .init(.{ .getter = .{ .hash = hash, .size = data.len } });
    defer state.deinit(t.allocator);
    try t.expect(try state.drive(t.allocator, t.io, fixture.bridge));
    const conn = fixture.bridge.connectionAt(0) orelse return error.TestUnexpectedResult;
    const core = conn.entry.conn.streams.streams.get(1) orelse return error.TestUnexpectedResult;
    const wire = response.written();
    core.recv.receive_window = wire.len + 1;
    try core.recv.handleStreamFrame(0, wire, false);
    try t.expect(try state.drive(t.allocator, t.io, fixture.bridge));
    try t.expectEqual(@as(u64, 0), state.completed);
    try t.expectEqualSlices(u8, wire, state.transfers.items[0].bytes.items);
    try core.recv.handleStreamFrame(wire.len, "x", false);
    try t.expectError(error.MessageTooLarge, state.drive(t.allocator, t.io, fixture.bridge));
    try t.expectEqual(@as(u64, 0), state.completed);
    try t.expectEqual(@as(?usize, 1), core.recv.peekLen());
    try t.expectEqual(wire.len, state.transfers.items[0].bytes.items.len);
    try t.expectEqual(@as(usize, 0), state.transfers.items[0].verified.items.len);
    try t.expect(state.payload(conn.id()) == null);
}

// The provider must reject excess request bytes even when the peer never sends FIN.
test "blob provider rejects oversized accumulation before FIN" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    var tmp = try test_scratch.tmpDir(.{});
    defer tmp.cleanup();
    var state: blobs.State = .init(.{ .provider = .{ .dir = tmp.dir, .hash = @splat(0) } });
    defer state.deinit(t.allocator);
    const conn = fixture.bridge.connectionAt(0) orelse return error.TestUnexpectedResult;
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

// Closing a gap must not let a queued run allocate past the remaining request budget.
test "blob provider rejects gap-closing oversized run before allocation" {
    var failing = t.FailingAllocator.init(t.allocator, .{});
    const gpa = failing.allocator();
    var fixture: Fixture = undefined;
    try fixture.initAllocator(gpa);
    defer fixture.deinit();
    var tmp = try test_scratch.tmpDir(.{});
    defer tmp.cleanup();
    var state: blobs.State = .init(.{ .provider = .{ .dir = tmp.dir, .hash = @splat(0) } });
    defer state.deinit(gpa);
    const conn = fixture.bridge.connectionAt(0) orelse return error.TestUnexpectedResult;
    const core = try conn.entry.conn.streams.getOrCreateStream(0);
    try core.recv.handleStreamFrame(0, "x", false);
    try t.expect(try state.drive(gpa, t.io, fixture.bridge));
    try state.transfers.items[0].bytes.ensureTotalCapacity(gpa, 2);
    const bytes = try t.allocator.alloc(u8, 6 * 1024 * 1024);
    defer t.allocator.free(bytes);
    @memset(bytes, 0xa5);
    core.recv.receive_window = bytes.len + 2;
    try core.recv.handleStreamFrame(2, bytes, true);
    try t.expect(core.recv.peekLen() == null);
    try core.recv.handleStreamFrame(1, "y", false);
    try t.expect(core.recv.allReceived());
    const allocated_before = failing.allocated_bytes;
    failing.fail_index = failing.alloc_index;
    try t.expectError(error.MessageTooLarge, state.drive(gpa, t.io, fixture.bridge));
    try t.expectEqual(allocated_before, failing.allocated_bytes);
    try t.expect(!failing.has_induced_failure);
    try t.expectEqualStrings("xy", state.transfers.items[0].bytes.items);
    try t.expectEqual(@as(u64, 2), state.received_bytes);
    try t.expectEqual(@as(?usize, bytes.len), core.recv.peekLen());
    try t.expectEqual(@as(u64, 2), core.recv.bytes_read);
    try t.expectEqual(@as(u64, 0), state.sent_bytes);
    try t.expectError(error.MessageTooLarge, state.drive(gpa, t.io, fixture.bridge));
    try t.expectEqual(@as(?usize, bytes.len), core.recv.peekLen());
}

// The framing byte belongs to the request allowance; neither valid boundary needs FIN.
test "blob provider accepts small and maximum request accumulation without FIN" {
    for ([_]usize{ 32, protocol.max_message_size + 1 }) |size| {
        var fixture: Fixture = undefined;
        try fixture.init();
        defer fixture.deinit();
        var tmp = try test_scratch.tmpDir(.{});
        defer tmp.cleanup();
        var state: blobs.State = .init(.{ .provider = .{ .dir = tmp.dir, .hash = @splat(0) } });
        defer state.deinit(t.allocator);
        const conn = fixture.bridge.connectionAt(0) orelse return error.TestUnexpectedResult;
        const core = try conn.entry.conn.streams.getOrCreateStream(0);
        const bytes = try t.allocator.alloc(u8, size);
        defer t.allocator.free(bytes);
        @memset(bytes, 0xa5);
        core.recv.receive_window = size + 1;
        try core.recv.handleStreamFrame(0, bytes, false);
        try t.expect(try state.drive(t.allocator, t.io, fixture.bridge));
        try t.expectEqualSlices(u8, bytes, state.transfers.items[0].bytes.items);
        try t.expect(state.transfers.items[0].bytes.capacity <= protocol.max_message_size + 1);
        try t.expectEqual(size, state.received_bytes);
        try t.expect(core.recv.peekLen() == null);
        try t.expect(!try state.drive(t.allocator, t.io, fixture.bridge));
        if (size == protocol.max_message_size + 1) {
            try core.recv.handleStreamFrame(size, "x", false);
            try t.expectError(
                error.MessageTooLarge,
                state.drive(t.allocator, t.io, fixture.bridge),
            );
        }
    }
}

// Answered stream IDs stay remembered without borrowed handles, then disappear with the connection.
test "blob provider handles more than sixteen streams and prunes disconnected state" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    var tmp = try test_scratch.tmpDir(.{});
    defer tmp.cleanup();
    var state: blobs.State = .init(.{ .provider = .{ .dir = tmp.dir, .hash = @splat(0) } });
    defer state.deinit(t.allocator);
    const conn = fixture.bridge.connectionAt(0) orelse return error.TestUnexpectedResult;
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
        try t.expect(transfer.machine.done);
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

test "blob getter propagates allocation failure until verified completion" {
    for (0..64) |fail_index| {
        var failing = t.FailingAllocator.init(t.allocator, .{});
        getterAllocationBoundary(&failing, fail_index) catch |err| {
            try t.expectEqual(error.OutOfMemory, err);
            try t.expect(failing.has_induced_failure);
            try t.expectEqual(failing.allocated_bytes, failing.freed_bytes);
            continue;
        };
        try t.expect(!failing.has_induced_failure);
        try t.expectEqual(failing.allocated_bytes, failing.freed_bytes);
        return;
    }
    return error.TestUnexpectedResult;
}

fn getterAllocationBoundary(failing: *t.FailingAllocator, fail_index: usize) !void {
    const gpa = failing.allocator();
    var fixture: Fixture = undefined;
    try fixture.initAllocator(gpa);
    defer fixture.deinit();
    const data = try t.allocator.alloc(u8, 49189);
    defer t.allocator.free(data);
    for (data, 0..) |*byte, i| byte.* = @intCast(i % 251);
    const tree = bao.BaoTree.init(data.len);
    const hash = try tree.rootHash(data);
    const outboard = try t.allocator.alloc(u8, @intCast(bao.bytes(tree)));
    defer t.allocator.free(outboard);
    const written = try bao.encode(tree, data, outboard);
    var tmp = try test_scratch.tmpDir(.{});
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
        t.io,
        &response.writer,
        protocol.GetRequest.blob(hash),
    ));
    var state: blobs.State = .init(.{ .getter = .{ .hash = hash, .size = data.len } });
    defer state.deinit(gpa);
    try t.expect(try state.drive(gpa, t.io, fixture.bridge));
    const conn = fixture.bridge.connectionAt(0) orelse return error.TestUnexpectedResult;
    const stream = conn.stream(state.transfers.items[0].stream_id) orelse
        return error.TestUnexpectedResult;
    try stream.pin();
    defer stream.unpin();
    const core = conn.entry.conn.streams.streams.get(stream.id()) orelse
        return error.TestUnexpectedResult;
    const wire = response.written();
    core.recv.receive_window = wire.len;
    try core.recv.handleStreamFrame(0, wire, true);
    // Arm only after the real response is queued; transport setup is not the boundary.
    failing.fail_index = failing.alloc_index + fail_index;
    for (0..4) |_| {
        _ = state.drive(gpa, t.io, fixture.bridge) catch |err| {
            try t.expectEqual(error.OutOfMemory, err);
            try t.expectEqual(@as(u64, 0), state.completed);
            try t.expect(state.payload(conn.id()) == null);
            try t.expectEqual(state.transfers.items[0].bytes.items.len, state.received_bytes);
            if (state.transfers.items[0].bytes.items.len == 0) {
                try t.expect(core.recv.peekLen() != null);
                try t.expectEqual(@as(u64, 0), core.recv.bytes_read);
            }
            return err;
        };
        if (state.completed != 0) break;
    }
    try t.expectEqual(@as(u64, 1), state.completed);
    try t.expectEqual(wire.len, state.received_bytes);
    const payload = state.payload(conn.id()) orelse return error.TestUnexpectedResult;
    try t.expectEqualSlices(u8, data, payload);
    try t.expect(!try state.drive(gpa, t.io, fixture.bridge));
}

// An interrupted getter owns no export, so removing its connection must release accumulation.
test "blob getter prunes incomplete bytes when its real connection is reaped" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    var state: blobs.State = .init(.{ .getter = .{ .hash = @splat(0) } });
    defer state.deinit(t.allocator);
    try t.expect(try state.drive(t.allocator, t.io, fixture.bridge));
    const conn = fixture.bridge.connectionAt(0) orelse return error.TestUnexpectedResult;
    const connection_id = conn.id();
    const core = conn.entry.conn.streams.streams.get(1) orelse return error.TestUnexpectedResult;
    var size: [8]u8 = undefined;
    std.mem.writeInt(u64, &size, 49189, .little);
    try core.recv.handleStreamFrame(0, &size, false);
    try t.expect(try state.drive(t.allocator, t.io, fixture.bridge));
    try t.expectEqual(@as(usize, 8), state.transfers.items[0].bytes.items.len);
    fixture.bridge.manager.removeConnection(conn.entry);
    fixture.bridge.sweep();
    try t.expect(!try state.drive(t.allocator, t.io, fixture.bridge));
    try t.expectEqual(@as(usize, 0), state.transfers.items.len);
    try t.expect(state.payload(connection_id) == null);
    try t.expectEqual(@as(u64, 0), state.completed);
}

// A known-size response has a Bao-derived allowance even if the provider withholds FIN.
test "blob getter rejects oversized open response before allocation and preserves unread run" {
    var failing = t.FailingAllocator.init(t.allocator, .{});
    const gpa = failing.allocator();
    var fixture: Fixture = undefined;
    try fixture.initAllocator(gpa);
    defer fixture.deinit();
    var state: blobs.State = .init(.{ .getter = .{ .hash = @splat(0), .size = 1 } });
    defer state.deinit(gpa);
    try t.expect(try state.drive(gpa, t.io, fixture.bridge));
    const conn = fixture.bridge.connectionAt(0) orelse return error.TestUnexpectedResult;
    const stream_id = state.transfers.items[0].stream_id;
    const core = conn.entry.conn.streams.streams.get(stream_id) orelse
        return error.TestUnexpectedResult;
    var header: [8]u8 = undefined;
    std.mem.writeInt(u64, &header, 1, .little);
    try core.recv.handleStreamFrame(0, &header, false);
    try t.expect(try state.drive(gpa, t.io, fixture.bridge));
    const excess: [4096]u8 = @splat(0xa5);
    try core.recv.handleStreamFrame(8, &excess, false);
    try t.expect(!core.recv.allReceived());
    const allocated_before = failing.allocated_bytes;
    failing.fail_index = failing.alloc_index;
    failing.resize_fail_index = failing.resize_index;
    try t.expectError(error.MessageTooLarge, state.drive(gpa, t.io, fixture.bridge));
    try t.expectEqual(allocated_before, failing.allocated_bytes);
    try t.expect(!failing.has_induced_failure);
    try t.expectEqualSlices(u8, &header, state.transfers.items[0].bytes.items);
    try t.expectEqual(@as(?usize, excess.len), core.recv.peekLen());
    try t.expectEqual(@as(u64, 8), core.recv.bytes_read);
    try t.expectEqual(@as(u64, 0), state.completed);
    try t.expectEqual(@as(usize, 0), state.transfers.items[0].verified.items.len);
}

// An authenticated prefix does not authenticate a skipped terminal chunk's byte length.
test "blob getter does not publish forged prefix size as verified metadata" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const encode = @import("../blobs/bao_proof_encode.zig");
    const plan = @import("../blobs/bao_plan.zig");
    var data: [2049]u8 = undefined;
    for (&data, 0..) |*byte, index| byte.* = @intCast(index % 251);
    const tree = bao.BaoTree.init(data.len);
    try t.expectEqual(@as(u64, 3), tree.chunks());
    try t.expectEqual(tree.chunks(), bao.BaoTree.init(2050).chunks());
    const hash = try tree.rootHash(&data);
    var wire: [2049 + 256]u8 = undefined;
    const proof_len = try encode.encode(
        plan.planOf(tree, .{ .start = 0, .end = 1 }),
        tree,
        &data,
        wire[8..],
    );
    std.mem.writeInt(u64, wire[0..8], 2050, .little);
    const options: blobs.Getter = .{ .hash = hash, .range = .{ .start = 0, .end = 1 } };
    var output: [1024]u8 = undefined;
    const decoded = try blobs.decodeResponse(options, wire[0 .. proof_len + 8], &output);
    try t.expectEqual(@as(u64, 2050), decoded.claimed_size);
    try t.expectEqual(@as(?u64, null), decoded.verified_size);
    try t.expectEqual(@as(usize, 1024), decoded.written);
    try t.expectEqualSlices(u8, data[0..1024], &output);
    var state: blobs.State = .init(.{ .getter = options });
    defer state.deinit(t.allocator);
    try t.expect(try state.drive(t.allocator, t.io, fixture.bridge));
    const conn = fixture.bridge.connectionAt(0) orelse return error.TestUnexpectedResult;
    const core = conn.entry.conn.streams.streams.get(state.transfers.items[0].stream_id) orelse
        return error.TestUnexpectedResult;
    try core.recv.handleStreamFrame(0, wire[0 .. proof_len + 8], true);
    try t.expect(try state.drive(t.allocator, t.io, fixture.bridge));
    try t.expect(try state.drive(t.allocator, t.io, fixture.bridge));
    try t.expectEqual(@as(u64, 1), state.completed);
    try t.expectEqualSlices(u8, data[0..1024], state.payload(conn.id()).?);
    try t.expectEqual(@as(?u64, null), state.last_size);
    try t.expectEqual(@as(?u64, 2050), state.last_claimed_size);
}

// Store validation failures refuse one stream; an unrelated connection still answers requests.
test "blob provider confines corrupt and short outboard refusal to response stream" {
    for ([_]bool{ false, true }) |truncate| {
        var fixture: Fixture = undefined;
        try fixture.init();
        defer fixture.deinit();
        var unrelated: Fixture = undefined;
        unrelated.bridge = fixture.bridge;
        try unrelated.connectClient(919);
        defer unrelated.client.deinit();
        defer unrelated.map.deinit(t.allocator);
        const other = fixture.bridge.connectionAt(1) orelse return error.TestUnexpectedResult;
        try t.expect(other.established());
        var tmp = try test_scratch.tmpDir(.{});
        defer tmp.cleanup();
        var data: [49189]u8 = undefined;
        for (&data, 0..) |*byte, index| byte.* = @intCast(index % 251);
        const tree = bao.BaoTree.init(data.len);
        const hash = try tree.rootHash(&data);
        const outboard = try t.allocator.alloc(u8, @intCast(bao.bytes(tree)));
        defer t.allocator.free(outboard);
        const written = try bao.encode(tree, &data, outboard);
        outboard[0] ^= 1;
        var names: store.NameStorage = undefined;
        const paths = store.names(&names, hash);
        {
            const partial = try store.createPartial(t.io, tmp.dir, paths);
            defer partial.close(t.io);
            try partial.data.writeStreamingAll(t.io, &data);
            try partial.outboard.writeStreamingAll(
                t.io,
                outboard[0..if (truncate) 1 else written],
            );
        }
        try store.commit(t.io, tmp.dir, paths);
        var state: blobs.State = .init(.{ .provider = .{ .dir = tmp.dir, .hash = hash } });
        defer state.deinit(t.allocator);
        const conn = fixture.bridge.connectionAt(0) orelse return error.TestUnexpectedResult;
        const corrupt_stream = try conn.entry.conn.streams.getOrCreateStream(0);
        var request_buffer: [128]u8 = undefined;
        const request = try blobs.encodeRequest(.{ .hash = hash }, &request_buffer);
        try corrupt_stream.recv.handleStreamFrame(0, request, true);
        try t.expect(try state.drive(t.allocator, t.io, fixture.bridge));
        try t.expect(try state.drive(t.allocator, t.io, fixture.bridge));
        try t.expect(state.transfers.items[0].machine.done);
        try t.expect(conn.established());
        try t.expect(!conn.closed());
        try t.expect(other.established());
        try t.expect(!other.closed());
        var absent_hash = hash;
        absent_hash[0] ^= 1;
        const next = try other.entry.conn.streams.getOrCreateStream(0);
        const absent_request = try blobs.encodeRequest(.{ .hash = absent_hash }, &request_buffer);
        try next.recv.handleStreamFrame(0, absent_request, true);
        try t.expect(try state.drive(t.allocator, t.io, fixture.bridge));
        try t.expect(try state.drive(t.allocator, t.io, fixture.bridge));
        try t.expectEqual(@as(usize, 2), state.transfers.items.len);
        try t.expect(state.transfers.items[1].machine.done);
        try t.expect(!conn.closed());
        try t.expect(other.established());
        try t.expect(!other.closed());
    }
}

// Unknown size still cannot exceed the decoder's finite proof-plan capacity.
test "blob getter rejects oversized unknown-size open response before allocation" {
    var failing = t.FailingAllocator.init(t.allocator, .{});
    const gpa = failing.allocator();
    var fixture: Fixture = undefined;
    try fixture.initAllocator(gpa);
    defer fixture.deinit();
    var state: blobs.State = .init(.{ .getter = .{ .hash = @splat(0) } });
    defer state.deinit(gpa);
    try t.expect(try state.drive(gpa, t.io, fixture.bridge));
    const conn = fixture.bridge.connectionAt(0) orelse return error.TestUnexpectedResult;
    const core = conn.entry.conn.streams.streams.get(state.transfers.items[0].stream_id) orelse
        return error.TestUnexpectedResult;
    const excess = try t.allocator.alloc(u8, 6 * 1024 * 1024);
    defer t.allocator.free(excess);
    @memset(excess, 0xa5);
    std.mem.writeInt(u64, excess[0..8], std.math.maxInt(u64), .little);
    core.recv.receive_window = excess.len;
    try core.recv.handleStreamFrame(0, excess, false);
    const allocated_before = failing.allocated_bytes;
    failing.fail_index = failing.alloc_index;
    failing.resize_fail_index = failing.resize_index;
    try t.expectError(error.MessageTooLarge, state.drive(gpa, t.io, fixture.bridge));
    try t.expectEqual(allocated_before, failing.allocated_bytes);
    try t.expect(!failing.has_induced_failure);
    try t.expectEqual(@as(?usize, excess.len), core.recv.peekLen());
    try t.expectEqual(@as(u64, 0), core.recv.bytes_read);
    try t.expectEqual(@as(usize, 0), state.transfers.items[0].bytes.items.len);
}
