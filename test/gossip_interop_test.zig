//! Mixed Rust/Node gossip consumers on real sockets, with application ACKs.
const std = @import("std");
const ozai = @import("ozai");
const rust_peer = @import("rust_interop_child.zig");
const child_cleanup = @import("child_cleanup.zig");
const child_exit_probe = @import("child_exit_probe.zig");
const child_constructor_safety = @import("child_constructor_safety.zig");
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
const repeated_topics = [_]TopicId{ topic, TopicId.fromBytes(@splat(0x75)) };
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

const TopicState = struct {
    message_received: bool = false,
    acknowledgement_received: bool = false,
    acknowledgement_pending: bool = false,
    acknowledgement_sent: bool = false,
};

const Consumer = struct {
    expected_peer: NodeId,
    configured_topics: []const TopicId = &topics,
    state: [repeated_topics.len]TopicState = @splat(.{}),
    message_received: bool = false,
    acknowledgement_received: bool = false,
    acknowledgement_sent: bool = false,
    unexpected: bool = false,

    fn updateCompletion(self: *Consumer) void {
        self.message_received = true;
        self.acknowledgement_received = true;
        self.acknowledgement_sent = true;
        for (self.state[0..self.configured_topics.len]) |state| {
            self.message_received = self.message_received and state.message_received;
            self.acknowledgement_received =
                self.acknowledgement_received and state.acknowledgement_received;
            self.acknowledgement_sent = self.acknowledgement_sent and state.acknowledgement_sent;
        }
    }

    fn onGossip(
        context: ?*anyopaque,
        received_topic: TopicId,
        delivered_from: NodeId,
        content: []const u8,
    ) void {
        const supplied = context orelse @panic("gossip callback requires a Consumer");
        const self: *Consumer = @ptrCast(@alignCast(supplied));
        if (!std.mem.eql(u8, &self.expected_peer.toBytes(), &delivered_from.toBytes())) {
            self.unexpected = true;
            return;
        }
        for (self.configured_topics, 0..) |configured, index| {
            if (!configured.eql(received_topic)) continue;
            const state = &self.state[index];
            if (std.mem.eql(u8, message, content)) {
                state.message_received = true;
                if (!state.acknowledgement_sent) state.acknowledgement_pending = true;
            } else if (std.mem.eql(u8, acknowledgement, content)) {
                state.acknowledgement_received = true;
            } else {
                self.unexpected = true;
            }
            self.updateCompletion();
            return;
        }
        self.unexpected = true;
    }
};

comptime {
    std.debug.assert(ack_prefix.len == 16);
}

test "actual Node gossip consumer exchanges exact topic and ACK with Rust server" {
    try exchange(.server, false, &topics);
}

test "actual Node gossip consumer exchanges exact topic and ACK with Rust client" {
    try exchange(.client, false, &topics);
}

test "Rust gossip server rejects mismatched authenticated Node pin before delivery" {
    try exchange(.server, true, &topics);
}

test "Rust gossip client rejects mismatched authenticated Node pin before delivery" {
    try exchange(.client, true, &topics);
}

test "repeated topic memberships receive exact payload and ACK with Rust server" {
    try exchange(.server, false, &repeated_topics);
}

test "repeated topic memberships receive exact payload and ACK with Rust client" {
    try exchange(.client, false, &repeated_topics);
}

fn exchange(role: Role, wrong_pin: bool, selected_topics: []const TopicId) !void {
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
    std.debug.assert(selected_topics.len > 0);
    std.debug.assert(selected_topics.len <= repeated_topics.len);
    var topic_hex: [repeated_topics.len][64]u8 = undefined;
    var topics_hex: [repeated_topics.len][]const u8 = undefined;
    for (selected_topics, 0..) |selected, index| {
        topic_hex[index] = std.fmt.bytesToHex(selected.toBytes(), .lower);
        topics_hex[index] = &topic_hex[index];
    }
    var consumer: Consumer = .{ .expected_peer = rust_id, .configured_topics = selected_topics };
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
    const argv = try rust_peer.flags(arena.allocator(), .{
        .tls = "iroh",
        .protocol = "gossip",
        .role = @tagName(role),
        .seed_hex = rust_seed_hex,
        .expect_peer_hex = &expected_hex,
        .topics_hex = topics_hex[0..selected_topics.len],
        .message = message,
        .connect_address = if (node) |live| live.address() else null,
        .run_ms = rust_peer.budget_ms,
    });
    const started = try rust_peer.Process.start(t.allocator, t.io, .{
        .name = @tagName(role),
        .argv = argv,
        .final_argv = argv,
        .run_ms = rust_peer.budget_ms,
    });
    const child = switch (started) {
        .ready => |process| process,
        .failed => |failure| {
            failure.process.deinit(t.io);
            return failure.cause;
        },
    };
    defer child.deinit(t.io);
    const address = try awaitBanner(child, rust_id);
    if (role == .server) {
        peers[0] = .{ .id = rust_id, .addr = .{ .ip = address } };
        node = try createNode(zig_secret, &consumer, &peers);
    }
    const live = node orelse return error.TestUnexpectedResult;
    try live.start(nowNs(), live.generator());
    const started_ms = nowMs();
    var consumer_closed = false;
    for (0..max_passes) |_| {
        const at = nowNs();
        if (!consumer_closed) {
            _ = try live.step(t.io, at, live.generator());
            // Each topic owns its ACK state; the callback's input is borrowed.
            for (selected_topics, 0..) |selected, index| {
                const state = &consumer.state[index];
                if (state.acknowledgement_pending) {
                    try live.broadcastNeighbors(selected, acknowledgement, at);
                    state.acknowledgement_pending = false;
                    state.acknowledgement_sent = true;
                }
            }
            consumer.updateCompletion();
            if (!wrong_pin and consumer.message_received and
                consumer.acknowledgement_received and consumer.acknowledgement_sent)
            {
                // Receipt of Rust's final ACK is the barrier, not child exit.
                // Closing here lets Rust keep its actor alive until this proof.
                try live.close(t.io, at, live.generator());
                consumer_closed = true;
            }
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
        try t.expect(consumer_closed);
        for (selected_topics) |selected| {
            try assertProof(arena.allocator(), child, selected, zig_id, "gossip-proof:", message);
            try assertProof(
                arena.allocator(),
                child,
                selected,
                zig_id,
                "gossip-ack-proof:",
                acknowledgement,
            );
        }
    }
}

fn createNode(secret: ozai.SecretKey, consumer: *Consumer, peers: []const ozai.node.Peer) !*Node {
    return Node.create(t.allocator, t.io, .{
        .secret = secret,
        .peers = peers,
        .expect_peer = consumer.expected_peer,
        .alpn = ozai.node.gossip_alpn,
        .gossip_topics = consumer.configured_topics,
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
    expected_topic: TopicId,
    expected_sender: NodeId,
    prefix: []const u8,
    payload: []const u8,
) !void {
    const expected = try std.fmt.allocPrint(
        arena,
        "{s} scope neighbors, topic {s}, sender {s}, payload {x}, received {d}, broadcast {d}",
        .{
            prefix,
            &std.fmt.bytesToHex(expected_topic.toBytes(), .lower),
            &rust_peer.hexId(expected_sender),
            payload,
            payload.len,
            payload.len,
        },
    );
    defer arena.free(expected);
    const observed = try child.lines(arena, prefix);
    defer arena.free(observed);
    for (observed) |line| {
        if (std.mem.eql(u8, expected, line)) return;
    }
    child.gaveUp("missing exact topic proof {s}", .{expected});
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

test {
    t.refAllDecls(child_cleanup);
    t.refAllDecls(child_exit_probe);
    t.refAllDecls(child_constructor_safety);
}
