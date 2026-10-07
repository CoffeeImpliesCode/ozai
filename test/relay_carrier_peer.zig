//! CLI consumer of the same production HTTP/WebSocket carrier used by Node.
const std = @import("std");
const ozai = @import("ozai");
const node_cli = @import("node_cli");
const carrier = ozai.relay_tcp_carrier;

pub const Options = struct {
    client: bool,
    seed_hex: []const u8,
    expect_peer: []const u8,
    bind: []const u8,
    relay_url: []const u8,
    message: []const u8,
    run_ms: usize,
};

pub fn run(init: std.process.Init, options: Options) !void {
    var seed: [32]u8 = undefined;
    const bytes = try std.fmt.hexToBytes(&seed, options.seed_hex);
    if (bytes.len != seed.len) return error.InvalidSeed;
    var secret = try ozai.SecretKey.fromSeed(seed);
    defer secret.deinit();
    const expected = try ozai.NodeId.parseHex(options.expect_peer);
    var service: ?carrier.Server = null;
    defer if (service) |*server| server.deinit();
    var address: ozai.SocketAddr = undefined;
    var host: []const u8 = undefined;
    var url: ozai.RelayUrl = undefined;
    if (options.client) {
        url = try ozai.RelayUrl.parse(options.relay_url);
        address = try url.socketAddr();
        host = url.hostSlice();
    } else {
        service = try carrier.Server.init(try node_cli.parseSocket(options.bind));
        address = service.?.address;
        if (address.ip == .v4 and std.mem.eql(u8, &address.ip.v4, &.{ 0, 0, 0, 0 }))
            address.ip.v4 = .{ 127, 0, 0, 1 };
        host = "localhost";
    }
    var client = try carrier.Client.init(.{ .address = address, .host = host, .secret = secret });
    defer client.deinit();
    var output_buffer: [2048]u8 = undefined;
    var output = std.Io.File.stdout().writerStreaming(init.io, &output_buffer);
    if (service) |*server| {
        try output.interface.print("relay-ready: url http://{f}/ qad disabled\n", .{server.address});
        try output.flush();
    }
    const start_ns = std.Io.Clock.awake.now(init.io).nanoseconds;
    var registered = false;
    var sent = false;
    var echoed = false;
    var received = false;
    for (0..options.run_ms * 100) |_| {
        if (std.Io.Clock.awake.now(init.io).nanoseconds - start_ns >=
            @as(i128, options.run_ms) * std.time.ns_per_ms) return error.DeadlineExceeded;
        if (service) |*server| try server.poll(init.io);
        try client.poll(init.io);
        if (client.isReady() and !registered) {
            registered = true;
            try output.interface.writeAll("relay-client-ready: registered\n");
            try output.flush();
        }
        if (options.client and registered and !sent) {
            try client.send(expected, options.message);
            sent = true;
        }
        if (try client.receive()) |packet| {
            if (packet.source.order(expected) != .eq) return error.CarrierIdentityMismatch;
            if (packet.datagrams.segment_size != null) return error.UnexpectedBatch;
            if (!std.mem.eql(u8, packet.datagrams.contents, options.message))
                return error.UnexpectedApplicationBytes;
            received = true;
            if (!options.client) {
                try client.send(expected, options.message);
                echoed = true;
            }
        }
        // Keep the service alive until its receiving peer has closed after the echo.
        if (received and (options.client or (echoed and !hasPeer(&service.?, expected)))) {
            var payload: [8192]u8 = undefined;
            const digits = "0123456789abcdef";
            for (options.message, 0..) |byte, index| {
                payload[2 * index] = digits[byte >> 4];
                payload[2 * index + 1] = digits[byte & 15];
            }
            try output.interface.print("relay-carrier: remote_id {f} payload_hex {s}\n",
                .{ expected, payload[0 .. options.message.len * 2] });
            try output.flush();
            return;
        }
        try std.Io.sleep(init.io, .fromMilliseconds(1), .awake);
    }
    return error.DeadlineExceeded;
}

fn hasPeer(server: *const carrier.Server, expected: ozai.NodeId) bool {
    for (&server.peers) |*slot| {
        if (slot.*) |*peer| {
            const identity = peer.identity orelse continue;
            if (identity.order(expected) == .eq) return true;
        }
    }
    return false;
}
