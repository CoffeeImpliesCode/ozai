//! A bounded consumer of the production Node carrier and pinned inner QUIC connection.
const std = @import("std");
const ozai = @import("ozai");
const node_cli = @import("node_cli");
const bridge = ozai.transport_quic_bridge;
const Node = ozai.node.Node;
const alpn = "ozai-relay-endpoint/1";
pub const std_options: std.Options = .{ .log_level = .warn };

pub fn main(init: std.process.Init) !void {
    const options = try Options.parse(init.minimal.args);
    if (options.carrier_only) return @import("relay_carrier_peer.zig").run(init, .{
        .client = options.client, .seed_hex = options.seed_hex, .expect_peer = options.expect_peer,
        .bind = options.bind, .relay_url = options.relay_url,
        .message = options.message, .run_ms = options.run_ms,
    });
    var seed: [32]u8 = undefined;
    const secret_bytes = try std.fmt.hexToBytes(&seed, options.seed_hex);
    if (secret_bytes.len != 32) return error.InvalidSeed;
    var secret = try ozai.SecretKey.fromSeed(seed);
    defer secret.deinit();
    const expected = try ozai.NodeId.parseHex(options.expect_peer);
    const url = try ozai.RelayUrl.parse(options.relay_url);
    const peer: [1]ozai.node.Peer = .{.{ .id = expected, .addr = .{ .relay = url } }};
    var config: ozai.node.Config = .{
        .secret = secret,
        .listen = try node_cli.parseSocket(options.bind),
        .alpn = alpn,
        .peers = if (options.client) &peer else &.{},
        .relay = .{ .client = .{
            .address = try url.socketAddr(), .host = url.hostSlice(), .secret = secret,
        } },
    };
    var candidates: [1]ozai.SocketAddr = undefined;
    if (!options.relay_only) {
        candidates[0] = try node_cli.parseSocket(
            options.local_candidate orelse return error.MissingConfiguredCandidate,
        );
        config.traversal = .{ .local_candidates = &candidates, .initiate = options.client };
        config.initial_max_path_id = 1;
        config.max_remote_nat_traversal_addresses = 2;
    }
    const node = try Node.create(init.gpa, init.io, config, 0x72656c6179);
    defer node.deinit();
    var engine = std.Random.DefaultPrng.init(0x70696e6e6564);
    const random = engine.random();
    const start = std.Io.Clock.awake.now(init.io);
    const start_ns = start.nanoseconds;
    try node.start(@intCast(start_ns), random);
    var output_buffer: [2048]u8 = undefined;
    var output = std.Io.File.stdout().writerStreaming(init.io, &output_buffer);
    try output.interface.print("relay-endpoint-ready: remote_id {f}\n", .{expected});
    try output.flush();
    var stream_id: ?u64 = null;
    var received: std.ArrayList(u8) = .empty;
    defer received.deinit(init.gpa);
    var replied = false;
    var finished = false;
    var phase: u8 = 1;
    var previous_stream: ?u64 = null;
    var stable_id: ?u64 = null;
    defer releaseStream(node, stable_id, stream_id);
    for (0..options.run_ms * 100) |_| {
        const now_ns = std.Io.Clock.awake.now(init.io).nanoseconds;
        if (now_ns - start_ns >= @as(i128, options.run_ms) * std.time.ns_per_ms)
            return error.DeadlineExceeded;
        const now: bridge.Instant = @intCast(now_ns);
        const moved = try node.step(init.io, now, random);
        var connection: ?bridge.Conn = null;
        const count = node.bridge.manager.connectionCount();
        for (0..count) |index| {
            const candidate = node.bridge.connectionAt(index) orelse continue;
            if (!candidate.established()) continue;
            if (!std.mem.eql(u8, candidate.entry.conn.negotiatedAlpn(), alpn)) continue;
            try verifyPeer(candidate, expected);
            if (connection != null) return error.SecondInnerConnection;
            if (stable_id) |id| {
                if (candidate.id() != id) return error.InnerConnectionChanged;
            } else stable_id = candidate.id();
            connection = candidate;
        }
        if (finished) {
            if (connection == null or connection.?.closed()) return;
            if (!moved) try std.Io.sleep(init.io, .fromMilliseconds(1), .awake);
            continue;
        }
        if (stable_id != null and connection == null) return error.InnerConnectionClosed;
        if (connection) |conn| {
            if (conn.closed()) return error.InnerConnectionClosed;
            if (conn.id() != stable_id.?) return error.InnerConnectionChanged;
            try verifyPeer(conn, expected);
            const route = try selectedRoute(node, conn);
            if (route != null and route.? == (phase == 1)) {
                if (stream_id == null) {
                    if (options.client) {
                        var opened = try bridge.Stream.open(conn);
                        try opened.pin();
                        try opened.write(options.message);
                        opened.close();
                        stream_id = opened.id();
                    } else {
                        for (0..64) |index| {
                            var inbound = conn.incomingStream(index) orelse break;
                            if (previous_stream) |previous| {
                                if (inbound.id() <= previous) continue;
                            }
                            try inbound.pin();
                            stream_id = inbound.id();
                            break;
                        }
                    }
                }
                if (stream_id) |id| {
                    var active = conn.stream(id) orelse return error.StreamDisappeared;
                    _ = try active.drain(init.gpa, &received);
                    if (received.items.len > options.message.len) return error.UnexpectedApplicationBytes;
                    if (active.finished()) {
                        if (!std.mem.eql(u8, received.items, options.message))
                            return error.UnexpectedApplicationBytes;
                        if (!options.client and !replied) {
                            try active.write(options.message);
                            active.close();
                            replied = true;
                        }
                        if (active.sentFinished()) {
                            var payload: [8192]u8 = undefined;
                            const digits = "0123456789abcdef";
                            for (received.items, 0..) |byte, index| {
                                payload[2 * index] = digits[byte >> 4];
                                payload[2 * index + 1] = digits[byte & 15];
                            }
                            try output.interface.print(
                                "relay-phase{d}: stable_id {d} remote_id {f} selected {s} " ++
                                    "bytes {d} payload_hex {s}\n",
                                .{ phase, conn.id(), expected, if (route.?) "relay" else "direct",
                                    received.items.len, payload[0 .. received.items.len * 2] },
                            );
                            try output.flush();
                            previous_stream = active.id();
                            active.unpin();
                            stream_id = null;
                            if (phase == 2 or options.relay_only) {
                                try reportCounts(node, options.client, &output.interface);
                                try output.flush();
                                finished = true;
                            }
                            received.clearRetainingCapacity();
                            replied = false;
                            phase = 2;
                        }
                    }
                }
            }
        }
        if (!moved) try std.Io.sleep(init.io, .fromMilliseconds(1), .awake);
    }
    return error.DeadlineExceeded;
}

fn releaseStream(node: *Node, connection_id: ?u64, stream_id: ?u64) void {
    const expected = connection_id orelse return;
    const id = stream_id orelse return;
    for (0..node.bridge.manager.connectionCount()) |index| {
        const conn = node.bridge.connectionAt(index) orelse continue;
        if (conn.id() != expected) continue;
        var stream = conn.stream(id) orelse return;
        stream.unpin();
        return;
    }
}

fn verifyPeer(conn: bridge.Conn, expected: ozai.NodeId) !void {
    if (!conn.entry.conn.is_server) {
        if (conn.entry.conn.tls13_hs) |handshake| {
            const authenticated = handshake.peerNodeId() orelse return error.MissingPeerIdentity;
            if (!std.mem.eql(u8, &authenticated, &expected.toBytes()))
                return error.PeerIdentityMismatch;
            return;
        }
        return error.MissingPeerIdentity;
    }
    const certificate = conn.entry.conn.peerCertificate() orelse return error.MissingPeerCertificate;
    const prefix = [_]u8{ 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00 };
    if (certificate.len != 44) return error.InvalidPeerCertificate;
    if (!std.mem.eql(u8, certificate[0..12], &prefix)) return error.InvalidPeerCertificate;
    if (!std.mem.eql(u8, certificate[12..], &expected.toBytes())) return error.PeerIdentityMismatch;
}

fn reportCounts(node: *Node, client: bool, output: *std.Io.Writer) !void {
    if (node.stats.dials != @as(u64, @intFromBool(client))) return error.UnexpectedDialCount;
    if (node.stats.handler_connections != @as(u64, @intFromBool(!client)))
        return error.UnexpectedAcceptCount;
    try output.print("relay-counts: dials {d} accepts {d}\n",
        .{ node.stats.dials, node.stats.handler_connections });
}

fn selectedRoute(node: *Node, conn: bridge.Conn) !?bool {
    for (0..2) |index| {
        const path = conn.pathSnapshot(@intCast(index)) orelse continue;
        if (!path.selected or !path.validated) continue;
        const peer = path.peer orelse return error.MissingPathPeer;
        return switch (peer.ip) {
            .v4 => false,
            .v6 => |bytes| if (node.map.lookup(bytes) != null) true else false,
        };
    }
    return null;
}

const Options = struct {
    client: bool = false,
    carrier_only: bool = false,
    seed_hex: []const u8 = "",
    expect_peer: []const u8 = "",
    relay_url: []const u8 = "",
    bind: []const u8 = "127.0.0.1:0",
    message: []const u8 = "ozai-relay-exact-application-bytes",
    run_ms: usize = 60_000,
    relay_only: bool = false,
    local_candidate: ?[]const u8 = null,

    fn parse(args: std.process.Args) !Options {
        var result: Options = .{};
        var iterator = std.process.Args.iterate(args);
        defer iterator.deinit();
        _ = iterator.skip();
        while (iterator.next()) |flag| {
            if (std.mem.eql(u8, flag, "--relay-only")) {
                result.relay_only = true;
                continue;
            }
            const value = iterator.next() orelse return error.MissingFlagValue;
            if (std.mem.eql(u8, flag, "--protocol")) {
                if (!std.mem.eql(u8, value, "relay-endpoint") and !std.mem.eql(u8, value, "relay"))
                    return error.InvalidProtocol;
                result.carrier_only = std.mem.eql(u8, value, "relay");
            } else if (std.mem.eql(u8, flag, "--tls")) {
                if (!std.mem.eql(u8, value, "iroh")) return error.InvalidTls;
            } else if (std.mem.eql(u8, flag, "--role")) {
                if (!std.mem.eql(u8, value, "client") and !std.mem.eql(u8, value, "server"))
                    return error.InvalidRole;
                result.client = std.mem.eql(u8, value, "client");
            } else if (std.mem.eql(u8, flag, "--seed-hex")) {
                result.seed_hex = value;
            } else if (std.mem.eql(u8, flag, "--expect-peer")) {
                result.expect_peer = value;
            } else if (std.mem.eql(u8, flag, "--relay-url")) {
                result.relay_url = value;
            } else if (std.mem.eql(u8, flag, "--bind")) {
                result.bind = value;
            } else if (std.mem.eql(u8, flag, "--message")) {
                result.message = value;
            } else if (std.mem.eql(u8, flag, "--for")) {
                result.run_ms = try std.fmt.parseInt(usize, value, 10);
                if (result.run_ms == 0 or result.run_ms > 300_000) return error.InvalidDeadline;
            } else if (std.mem.eql(u8, flag, "--local-candidate")) {
                result.local_candidate = value;
            } else return error.UnknownFlag;
        }
        if (result.seed_hex.len != 64 or result.expect_peer.len != 64) return error.MissingIdentity;
        if (result.relay_url.len == 0 and (!result.carrier_only or result.client))
            return error.MissingRelay;
        if (result.message.len == 0 or result.message.len > 4096) return error.InvalidMessageSize;
        return result;
    }
};
