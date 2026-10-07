//! Mixed Rust/Node gossip consumers on real sockets, with application ACKs.
const std = @import("std");
const ozai = @import("ozai");
const rust_peer = @import("rust_interop_child.zig");
const t = std.testing;
const Node = ozai.node.Node;
const NodeId = ozai.NodeId;
const TopicId = ozai.gossip_hyparview.TopicId;

const topic = TopicId.fromBytes(.{
    0x91, 0x27, 0x43, 0x05, 0xa6, 0xb8, 0xc9, 0xda,
    0xeb, 0xfc, 0x1d, 0x2e, 0x3f, 0x40, 0x51, 0x62,
    0x73, 0x84, 0x95, 0xa6, 0xb7, 0xc8, 0xd9, 0xea,
    0xfb, 0x0c, 0x1d, 0x2e, 0x3f, 0x50, 0x61, 0x72,
});
const topics = [_]TopicId{topic};
const message = "ozai-node-gossip-mixed-role-exact-927";
const ack_prefix = "ozai-gossip-ack:";
const acknowledgement = ack_prefix ++ message;
const zig_seed: [ozai.SecretKey.seed_length]u8 = @splat(0x5a);
const rust_seed: [ozai.SecretKey.seed_length]u8 = @splat(0x6c);
const wrong_seed: [ozai.SecretKey.seed_length]u8 = @splat(0x39);
const rust_seed_hex = "6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c";
const max_passes = 20_000;
const poll_ns = std.time.ns_per_ms;

const Role = enum { server, client };

const Consumer = struct {
    expected_peer: NodeId,
    message_received: bool = false,
    acknowledgement_received: bool = false,
    acknowledgement_pending: bool = false,
    acknowledgement_sent: bool = false,
    unexpected: bool = false,
    acknowledgement_bytes: [acknowledgement.len]u8 = undefined,

    fn onGossip(
        context: ?*anyopaque,
        received_topic: TopicId,
        delivered_from: NodeId,
        content: []const u8,
    ) void {
        const self: *Consumer = @ptrCast(@alignCast(context.?));
        if (!std.mem.eql(u8, &topic, &received_topic) or
            !std.mem.eql(u8, &self.expected_peer.toBytes(), &delivered_from.toBytes()))
        {
            self.unexpected = true;
            return;
        }
        if (std.mem.eql(u8, message, content)) {
            self.message_received = true;
            if (!self.acknowledgement_sent) {
                @memcpy(self.acknowledgement_bytes[0..ack_prefix.len], ack_prefix);
                @memcpy(self.acknowledgement_bytes[ack_prefix.len..], content);
                self.acknowledgement_pending = true;
            }
        } else if (std.mem.eql(u8, acknowledgement, content)) {
            self.acknowledgement_received = true;
        } else {
            self.unexpected = true;
        }
    }
};

comptime {
    std.debug.assert(ack_prefix.len == 16);
    std.debug.assert(topic.len == 32);
}

test "actual Node gossip consumer exchanges exact topic and ACK with Rust server" {
    try exchange(.server, false);
}

test "actual Node gossip consumer exchanges exact topic and ACK with Rust client" {
    try exchange(.client, false);
}

test "Rust gossip server rejects mismatched authenticated Node pin before delivery" {
    try exchange(.server, true);
}

test "Rust gossip client rejects mismatched authenticated Node pin before delivery" {
    try exchange(.client, true);
}

fn exchange(role: Role, wrong_pin: bool) !void {
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    var zig_secret = try ozai.SecretKey.fromSeed(zig_seed);
    defer zig_secret.deinit();
    var rust_secret = try ozai.SecretKey.fromSeed(rust_seed);
    defer rust_secret.deinit();
    var wrong_secret = try ozai.SecretKey.fromSeed(wrong_seed);
    defer wrong_secret.deinit();
    const zig_id = zig_secret.nodeId();
    const rust_id = rust_secret.nodeId();
    const expected_hex = rust_peer.hexId(if (wrong_pin) wrong_secret.nodeId() else zig_id);
    const topic_hex = std.fmt.bytesToHex(topic, .lower);
    const topics_hex = [_][]const u8{&topic_hex};
    var consumer: Consumer = .{ .expected_peer = rust_id };
    var peers: [1]ozai.node.Peer = undefined;
    var node: ?*Node = null;
    defer if (node) |live| {
        live.close(t.io, nowNs(), live.generator()) catch |err| {
            std.debug.panic("gossip interop Node shutdown failed: {t}", .{err});
        };
        live.deinit();
    };
    if (role == .client) {
        node = try createNode(zig_secret, &consumer, &.{});
    }
    const child = try rust_peer.Process.start(t.allocator, arena.allocator(), t.io,
        @tagName(role), .{
            .tls = "iroh",
            .protocol = "gossip",
            .role = @tagName(role),
            .seed_hex = rust_seed_hex,
            .expect_peer_hex = &expected_hex,
            .topics_hex = &topics_hex,
            .message = message,
            .connect_address = if (node) |live| live.address() else null,
            .run_ms = rust_peer.budget_ms,
        });
    defer child.deinit(t.io);
    const address = try awaitBanner(child, rust_id);
    if (role == .server) {
        peers[0] = .{ .id = rust_id, .addr = .{ .ip = address } };
        node = try createNode(zig_secret, &consumer, &peers);
    }
    const live = node.?;
    try live.start(nowNs(), live.generator());
    const started_ms = nowMs();
    for (0..max_passes) |_| {
        const at = nowNs();
        _ = try live.step(t.io, at, live.generator());
        // Callback data is borrowed; this buffer is owned and broadcasting cannot reenter step.
        if (consumer.acknowledgement_pending) {
            try live.broadcastNeighbors(topic, &consumer.acknowledgement_bytes, at);
            consumer.acknowledgement_pending = false;
            consumer.acknowledgement_sent = true;
        }
        try child.pump(t.io);
        if (child.finished()) {
            if (wrong_pin) break;
            if (consumer.message_received and consumer.acknowledgement_received and
                consumer.acknowledgement_sent) break;
        }
        if (nowMs() - started_ms >= rust_peer.budget_ms) {
            child.gaveUp("gossip exchange exceeded its deadline", .{});
        }
        try std.Io.sleep(t.io, .{ .nanoseconds = poll_ns }, .awake);
    }
    if (!child.finished()) child.gaveUp("gossip exchange exhausted bounded passes", .{});
    const failed = try child.reportFailure(t.io);
    if (wrong_pin) {
        try assertPinRejected(child, &consumer, failed);
    } else {
        if (failed) child.gaveUp("gossip actor exited unsuccessfully", .{});
        try t.expect(!consumer.unexpected);
        try t.expect(consumer.message_received);
        try t.expect(consumer.acknowledgement_received);
        try t.expect(consumer.acknowledgement_sent);
        try assertProof(arena.allocator(), child, zig_id, "gossip-proof:", message);
        try assertProof(arena.allocator(), child, zig_id, "gossip-ack-proof:", acknowledgement);
    }
}

fn createNode(secret: ozai.SecretKey, consumer: *Consumer, peers: []const ozai.node.Peer) !*Node {
    return Node.create(t.allocator, t.io, .{
        .secret = secret,
        .peers = peers,
        .expect_peer = consumer.expected_peer,
        .alpn = ozai.node.gossip_alpn,
        .gossip_topics = &topics,
        .gossip_message = message,
        .on_gossip = Consumer.onGossip,
        .on_gossip_context = consumer,
    }, 0x927a5);
}

fn awaitBanner(child: *rust_peer.Process, expected_peer: NodeId) !ozai.SocketAddr {
    const started_ms = nowMs();
    for (0..max_passes) |_| {
        try child.pump(t.io);
        if (try child.address()) |address| {
            if (child.value("node")) |printed| {
                try t.expectEqualStrings(&rust_peer.hexId(expected_peer), printed);
                return address;
            }
        }
        if (child.finished()) child.gaveUp("exited before its gossip banner", .{});
        if (nowMs() - started_ms >= rust_peer.budget_ms) {
            child.gaveUp("did not publish its gossip banner before the deadline", .{});
        }
        try std.Io.sleep(t.io, .{ .nanoseconds = poll_ns }, .awake);
    }
    child.gaveUp("did not publish its gossip banner in bounded passes", .{});
}

fn assertProof(
    arena: std.mem.Allocator,
    child: *rust_peer.Process,
    expected_sender: NodeId,
    prefix: []const u8,
    payload: []const u8,
) !void {
    const expected = try std.fmt.allocPrint(arena,
        "{s} scope neighbors, topic {s}, sender {s}, payload {x}, received {d}, broadcast {d}",
        .{ prefix, &std.fmt.bytesToHex(topic, .lower), &rust_peer.hexId(expected_sender),
            payload, payload.len, payload.len });
    const observed = child.line(prefix) orelse child.gaveUp("missing {s}", .{prefix});
    try t.expectEqualStrings(expected, observed);
}

fn assertPinRejected(child: *rust_peer.Process, consumer: *const Consumer, failed: bool) !void {
    try t.expect(failed);
    try t.expect(child.line("gossip-proof:") == null);
    try t.expect(child.line("gossip-ack-proof:") == null);
    try t.expect(!consumer.message_received);
    try t.expect(!consumer.acknowledgement_received);
    try t.expect(!consumer.acknowledgement_sent);
    try t.expect(!consumer.unexpected);
}

fn nowMs() i64 {
    return std.Io.Clock.awake.now(t.io).toMilliseconds();
}

fn nowNs() i64 {
    return nowMs() * std.time.ns_per_ms;
}
