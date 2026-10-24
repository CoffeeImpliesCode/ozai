//! Command-line options for authenticated application protocols and carriers.

const std = @import("std");

const ozai = @import("ozai");
const cli_values = @import("cli_values.zig");

const node_mod = ozai.node;
const Allocator = std.mem.Allocator;
const Peer = node_mod.Peer;
const SocketAddr = ozai.SocketAddr;
const SecretKey = ozai.SecretKey;
const CliError = cli_values.CliError;

/// How long a run lasts when `--for` does not say. A binary that ran until a
/// signal forever could not be smoke-tested from a script, and a script that
/// cannot run it is a binary nobody runs.
const default_run_ms: i64 = 500;

/// What the command line asked for.
pub const Options = struct {
    /// Where to bind. Port zero lets the kernel choose, which is what lets two
    /// nodes on one machine both listen.
    listen: SocketAddr = .{
        .ip = .{ .v4 = .{ 127, 0, 0, 1 } },
        .port = 0,
    },
    /// Who to dial, in the order the flags named them.
    peers: std.ArrayList(Peer) = .empty,
    /// Identities to resolve; static `--peer` addresses never enter this list.
    lookup_peers: std.ArrayList(ozai.NodeId) = .empty,
    /// Explicit resolver destination. No external server is selected by default.
    dns_server: ?SocketAddr = null,
    dns_origin: []const u8 = (node_mod.Discovery{}).origin,
    lookup_deadline_ms: i32 = (node_mod.Discovery{}).deadline_ms,
    lookup_interval_ms: u64 = (node_mod.Discovery{}).interval_ms,
    /// This node's identity, drawn when the caller does not supply one.
    secret: ?SecretKey = null,
    expect_peer: ?ozai.NodeId = null,
    /// Inner application ALPN; carrier selection never changes it.
    alpn: ?[]const u8 = null,
    relay_listen: ?SocketAddr = null,
    relay_server: ?SocketAddr = null,
    relay_host: ?[]const u8 = null,
    gossip_topics: std.ArrayList(ozai.gossip_hyparview.TopicId) = .empty,
    message: ?[]const u8 = null,
    blob_role: ?BlobRole = null,
    blob_dir: ?[]const u8 = null,
    blob_hash: ?cli_values.BlobHash = null,
    blob_size: ?u64 = null,
    blob_range: ?ozai.blobs_protocol.ChunkRange = null,
    blob_range_explicit: bool = false,
    blob_output: ?[]const u8 = null,
    traversal_addresses: std.ArrayList(SocketAddr) = .empty,
    traversal_initiate: bool = false,

    /// The generator's seed. Fixed by default, so two runs of the same command
    /// line present the same connection ids and a failure reproduces.
    seed: u64 = 0x6f7a_69,
    /// When to stop on our own.
    run_ms: i64 = default_run_ms,
    /// Emit live state changes so supervisors can wait on state rather than time.
    progress: bool = false,

    /// What the usage text says, and nothing it does not.
    const usage =
        \\usage: ozai-node [options]
        \\
        \\  --listen <ip:port>     where to bind. Port 0 lets the kernel choose.
        \\  --peer <nodeid@ip:port>
        \\                          dial this peer. May be repeated.
        \\  --lookup-peer <nodeid> resolve and dial this identity. May be repeated.
        \\  --expect-peer <nodeid> pin incoming authenticated connections.
        \\  --dns-server <ip:port> explicit DNS server; requires --lookup-peer.
        \\  --dns-origin <origin> DNS suffix. Default: the production iroh origin.
        \\  --lookup-deadline <ms> positive query budget, at most 2147483647.
        \\  --lookup-interval <ms> positive refresh interval, at most 9223372036854.
        \\  --key-seed <base32>    this node's ed25519 seed, z-base-32. Drawn
        \\                          when absent; the node id is printed either
        \\                          way.
        \\  --alpn <bytes>         inner application protocol, independent of relay.
        \\  --relay-listen <ip:port> serve the relay carrier (port 0 permitted).
        \\  --relay-server <ip:port> connect to this relay carrier.
        \\  --relay-host <host>    HTTP Host for --relay-server.
        \\  --peer-relay <nodeid@relay-url> pinned inner peer. May be repeated.
        \\  --topic-hex <64hex>    gossip topic. May be repeated, at most four.
        \\  --message <bytes>     initial gossip message; requires a topic.
        \\  --blob-role provider|getter selects /iroh-bytes/4.
        \\  --blob-dir <directory> provider's content-addressed store.
        \\  --blob-hash <64hex>    blob to serve or retrieve.
        \\  --blob-size <u64>      expected getter size.
        \\  --blob-range all|start:end end-exclusive 1024-byte chunk indexes.
        \\  --blob-output <file>   write verified getter bytes.
        \\  --traversal-address <ip:port> configured native candidate; at most two.
        \\  --traversal-initiate   initiate native traversal; requires a candidate.
        \\
        \\  --seed <u64>           the generator seed. Default: fixed, so a run
        \\                          reproduces.
        \\  --for <ms>             stop after this long, gracefully. Default: 500.
        \\  --progress             flush live counter changes while running.
        \\  --help                 print this.
        \\
        \\A node id is z-base-32, as `ozai-node-id` prints it.
        \\
    ;

    /// Read the command line.
    ///
    /// Three answers rather than a `?Options`, because three are true: a run,
    /// `--help`, and a rejection. The last is a different answer from the
    /// middle one and a caller can tell them apart, which is why the exit code
    /// can be 1 for one and 0 for the other.
    ///
    /// `pub` because `main.zig` calls it from outside this file. This module
    /// is a split out of `main.zig`, and `main.zig` is the only caller: it
    /// owns the arena and the writer that are parsed into.
    pub fn parse(
        arena: Allocator,
        args: std.process.Args,
        out: *std.Io.Writer,
    ) !Parse {
        var options: Options = .{};
        var it = std.process.Args.iterate(args);
        defer it.deinit();
        _ = it.skip();
        while (it.next()) |flag| {
            if (std.mem.eql(u8, flag, "--help")) {
                try out.writeAll(usage);
                return .help;
            }
            if (std.mem.eql(u8, flag, "--progress")) {
                options.progress = true;
                continue;
            }
            if (std.mem.eql(u8, flag, "--traversal-initiate")) {
                options.traversal_initiate = true;
                continue;
            }
            if (std.mem.eql(u8, flag, "--relay") or
                std.mem.eql(u8, flag, "--relay-peer") or
                std.mem.eql(u8, flag, "--send"))
            {
                try out.print("ozai-node: {s} is not an option\n", .{flag});
                return .{ .rejected = error.NotAnOption };
            }

            const value = it.next() orelse {
                try out.print("ozai-node: {s} wants a value\n", .{flag});
                return .{ .rejected = error.FlagWithoutValue };
            };
            if (try options.parseValue(arena, flag, value, out)) |refusal| return refusal;
        }
        if (try contradictions(out, options)) |refusal| return .{ .rejected = refusal };
        if (options.blob_role != null) options.alpn = ozai.blobs_protocol.alpn;
        if (options.gossip_topics.items.len != 0) options.alpn = node_mod.gossip_alpn;

        return .{ .run = options };
    }

    fn parseValue(
        options: *Options,
        arena: Allocator,
        flag: []const u8,
        value: []const u8,
        out: *std.Io.Writer,
    ) !?Parse {
        if (std.mem.eql(u8, flag, "--listen")) {
            options.listen = cli_values.parseSocket(value) catch |err| {
                try cli_values.reject(out, flag, value, err);
                return .{ .rejected = err };
            };
        } else if (std.mem.eql(u8, flag, "--peer")) {
            const peer = cli_values.parsePeer(value) catch |err| {
                try cli_values.reject(out, flag, value, err);
                return .{ .rejected = err };
            };
            // The arena is the process's and does not grow on its own, so
            // this can only fail if the process is out of memory — which
            // is propagated rather than dressed up as a bad argument.
            try options.peers.append(arena, peer);
        } else if (std.mem.eql(u8, flag, "--lookup-peer")) {
            const id = ozai.NodeId.parseZ32(value) catch |err| {
                try cli_values.reject(out, flag, value, err);
                return .{ .rejected = err };
            };
            try options.lookup_peers.append(arena, id);
        } else if (std.mem.eql(u8, flag, "--dns-server")) {
            const server = cli_values.parseSocket(value) catch |err| {
                try cli_values.reject(out, flag, value, err);
                return .{ .rejected = err };
            };
            if (server.port == 0) {
                try cli_values.reject(out, flag, value, error.AddressNotReachable);
                return .{ .rejected = error.AddressNotReachable };
            }
            options.dns_server = server;
        } else if (std.mem.eql(u8, flag, "--dns-origin")) {
            options.dns_origin = cli_values.parseDnsOrigin(value) catch |err| {
                try cli_values.reject(out, flag, value, err);
                return .{ .rejected = err };
            };
            // Wire DNS names must be absolute; accept the usual suffix
            // spelling without silently relying on a host search domain.
            if (!std.mem.endsWith(u8, options.dns_origin, "."))
                options.dns_origin = try std.fmt.allocPrint(arena, "{s}.", .{options.dns_origin});
        } else if (std.mem.eql(u8, flag, "--lookup-deadline")) {
            options.lookup_deadline_ms = cli_values.parseLookupMilliseconds(
                i32,
                value,
                std.math.maxInt(i32),
            ) catch |err| {
                try cli_values.reject(out, flag, value, err);
                return .{ .rejected = err };
            };
        } else if (std.mem.eql(u8, flag, "--lookup-interval")) {
            options.lookup_interval_ms = cli_values.parseLookupMilliseconds(
                u64,
                value,
                cli_values.max_lookup_interval_ms,
            ) catch |err| {
                try cli_values.reject(out, flag, value, err);
                return .{ .rejected = err };
            };
        } else if (std.mem.eql(u8, flag, "--expect-peer")) {
            options.expect_peer = ozai.NodeId.parseZ32(value) catch |err| {
                try cli_values.reject(out, flag, value, err);
                return .{ .rejected = err };
            };
        } else if (std.mem.eql(u8, flag, "--key-seed")) {
            const seed = ozai.base32.decode(
                ozai.base32.z32,
                SecretKey.seed_length,
                value,
            ) catch |err| {
                try cli_values.reject(out, flag, value, err);
                return .{ .rejected = err };
            };
            options.secret = SecretKey.fromSeed(seed) catch |err| {
                try cli_values.reject(out, flag, value, err);
                return .{ .rejected = err };
            };
        } else {
            return options.parseCarrierValue(arena, flag, value, out);
        }
        return null;
    }

    fn parseCarrierValue(
        options: *Options,
        arena: Allocator,
        flag: []const u8,
        value: []const u8,
        out: *std.Io.Writer,
    ) !?Parse {
        if (std.mem.eql(u8, flag, "--alpn")) {
            options.alpn = value;
        } else if (std.mem.eql(u8, flag, "--peer-relay")) {
            const peer = cli_values.parseRelayPeer(value) catch |err| {
                try cli_values.reject(out, flag, value, err);
                return .{ .rejected = err };
            };
            try options.peers.append(arena, peer);
        } else if (std.mem.eql(u8, flag, "--relay-listen") or
            std.mem.eql(u8, flag, "--relay-server") or
            std.mem.eql(u8, flag, "--traversal-address"))
        {
            const address = cli_values.parseSocket(value) catch |err| {
                try cli_values.reject(out, flag, value, err);
                return .{ .rejected = err };
            };
            if (std.mem.eql(u8, flag, "--relay-listen")) {
                options.relay_listen = address;
            } else {
                if (address.port == 0) {
                    try cli_values.reject(out, flag, value, error.AddressNotReachable);
                    return .{ .rejected = error.AddressNotReachable };
                }
                if (std.mem.eql(u8, flag, "--relay-server")) {
                    options.relay_server = address;
                } else {
                    if (options.traversal_addresses.items.len == 2) {
                        try cli_values.reject(out, flag, value, error.TooManyTraversalAddresses);
                        return .{ .rejected = error.TooManyTraversalAddresses };
                    }
                    try options.traversal_addresses.append(arena, address);
                }
            }
        } else if (std.mem.eql(u8, flag, "--relay-host")) {
            if (value.len == 0 or std.mem.indexOfAny(u8, value, "\r\n") != null) {
                try cli_values.reject(out, flag, value, error.InvalidRelayHost);
                return .{ .rejected = error.InvalidRelayHost };
            }
            options.relay_host = value;
        } else if (std.mem.eql(u8, flag, "--topic-hex")) {
            if (options.gossip_topics.items.len == 4) {
                try cli_values.reject(out, flag, value, error.TooManyTopics);
                return .{ .rejected = error.TooManyTopics };
            }
            const topic = cli_values.parseTopic(value) catch |err| {
                try cli_values.reject(out, flag, value, err);
                return .{ .rejected = err };
            };
            try options.gossip_topics.append(arena, topic);
        } else {
            return options.parseApplicationValue(flag, value, out);
        }
        return null;
    }

    fn parseApplicationValue(
        options: *Options,
        flag: []const u8,
        value: []const u8,
        out: *std.Io.Writer,
    ) !?Parse {
        if (std.mem.eql(u8, flag, "--message")) {
            options.message = value;
        } else if (std.mem.eql(u8, flag, "--blob-role")) {
            options.blob_role = std.meta.stringToEnum(BlobRole, value) orelse {
                try cli_values.reject(out, flag, value, error.InvalidBlobRole);
                return .{ .rejected = error.InvalidBlobRole };
            };
        } else if (std.mem.eql(u8, flag, "--blob-hash")) {
            options.blob_hash = cli_values.parseBlobHash(value) catch |err| {
                try cli_values.reject(out, flag, value, err);
                return .{ .rejected = err };
            };
        } else if (std.mem.eql(u8, flag, "--blob-size")) {
            options.blob_size = std.fmt.parseInt(u64, value, 10) catch {
                try cli_values.reject(out, flag, value, error.InvalidBlobSize);
                return .{ .rejected = error.InvalidBlobSize };
            };
        } else if (std.mem.eql(u8, flag, "--blob-range")) {
            options.blob_range = cli_values.parseBlobRange(value) catch |err| {
                try cli_values.reject(out, flag, value, err);
                return .{ .rejected = err };
            };
            options.blob_range_explicit = true;
        } else if (std.mem.eql(u8, flag, "--blob-dir") or
            std.mem.eql(u8, flag, "--blob-output"))
        {
            if (value.len == 0) {
                try cli_values.reject(out, flag, value, error.EmptyPath);
                return .{ .rejected = error.EmptyPath };
            }
            if (std.mem.eql(u8, flag, "--blob-dir")) {
                options.blob_dir = value;
            } else {
                options.blob_output = value;
            }
        } else {
            return options.parseRunValue(flag, value, out);
        }
        return null;
    }

    fn parseRunValue(
        options: *Options,
        flag: []const u8,
        value: []const u8,
        out: *std.Io.Writer,
    ) !?Parse {
        if (std.mem.eql(u8, flag, "--seed")) {
            options.seed = std.fmt.parseInt(u64, value, 10) catch {
                try cli_values.reject(out, flag, value, error.NotASeed);
                return .{ .rejected = error.NotASeed };
            };
        } else if (std.mem.eql(u8, flag, "--for")) {
            options.run_ms = std.fmt.parseInt(i64, value, 10) catch {
                try cli_values.reject(out, flag, value, error.NotMilliseconds);
                return .{ .rejected = error.NotMilliseconds };
            };
        } else {
            try out.print("ozai-node: {s} is not an option\n", .{flag});
            try out.writeAll(usage);
            return .{ .rejected = error.NotAnOption };
        }
        return null;
    }

    /// Refusals are values; writer failures are program errors.
    fn contradictions(
        out: *std.Io.Writer,
        options: Options,
    ) std.Io.Writer.Error!?CliError {
        if (options.lookup_peers.items.len != 0 and options.dns_server == null) {
            try out.writeAll("ozai-node: --lookup-peer requires --dns-server\n");
            return @as(?CliError, error.LookupNeedsServer);
        }
        if (options.dns_server != null and options.lookup_peers.items.len == 0) {
            try out.writeAll("ozai-node: --dns-server requires --lookup-peer\n");
            return @as(?CliError, error.LookupNeedsPeer);
        }
        const refusal: ?CliError = if (options.relay_listen != null and
            options.relay_server != null)
            error.TwoRelayRoles
        else if (options.relay_server != null and options.relay_host == null)
            error.RelayNeedsHost
        else if (options.relay_host != null and options.relay_server == null)
            error.RelayNeedsServer
        else if (options.traversal_initiate and options.traversal_addresses.items.len == 0)
            error.TraversalNeedsAddress
        else if (options.message != null and options.gossip_topics.items.len == 0)
            error.MessageNeedsTopic
        else if (options.gossip_topics.items.len != 0 and options.blob_role != null)
            error.ConflictingProtocols
        else if (options.gossip_topics.items.len != 0 and options.alpn != null and
            !std.mem.eql(u8, options.alpn.?, node_mod.gossip_alpn))
            error.TopicAlpnMismatch
        else if (options.blob_role == null and (options.blob_dir != null or
            options.blob_hash != null or options.blob_size != null or
            options.blob_range_explicit or options.blob_output != null))
            error.BlobNeedsRole
        else if (options.blob_role != null and options.blob_hash == null)
            error.BlobNeedsHash
        else if (options.blob_role == .provider and options.blob_dir == null)
            error.BlobNeedsDirectory
        else if (options.blob_role == .provider and (options.blob_size != null or
            options.blob_range_explicit or options.blob_output != null))
            error.BlobProviderGetterOptions
        else if (options.blob_role == .getter and options.blob_dir != null)
            error.BlobGetterDirectory
        else if (options.blob_role != null and options.alpn != null and
            !std.mem.eql(u8, options.alpn.?, ozai.blobs_protocol.alpn))
            error.BlobAlpnMismatch
        else
            null;
        if (refusal) |err| {
            try out.print("ozai-node: incompatible options: {t}\n", .{err});
            return @as(?CliError, err);
        }
        return null;
    }
};

pub const BlobRole = enum { provider, getter };

/// What the command line turned out to mean.
pub const Parse = union(enum) {
    run: Options,
    /// `--help`. Exit 0: the program was asked a question and answered it.
    help: void,
    /// Something it will not do. Exit 1: a caller scripting this wants a
    /// failure and not a node that quietly ran with defaults.
    rejected: CliError,
};

test "explicit lookup peers retain static peers and DNS settings" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var secret = try ozai.SecretKey.fromSeed(@splat(7));
    defer secret.deinit();
    var id_buffer: [ozai.NodeId.z32_length + 1]u8 = undefined;
    const id = try std.fmt.bufPrintSentinel(&id_buffer, "{s}", .{secret.nodeId().toZ32()}, 0);
    var peer_buffer: [100]u8 = undefined;
    const peer = try std.fmt.bufPrintSentinel(&peer_buffer, "{s}@127.0.0.1:9000", .{id}, 0);
    const args = [_][*:0]const u8{
        "ozai-node",     "--peer",            peer,
        "--lookup-peer", id,                  "--lookup-peer",
        id,              "--dns-server",      "[::1]:5353",
        "--dns-origin",  "test.invalid",      "--lookup-deadline",
        "25",            "--lookup-interval", "100",
    };
    var out: std.Io.Writer.Allocating = .init(arena.allocator());
    const parsed = try Options.parse(arena.allocator(), .{ .vector = &args }, &out.writer);
    try std.testing.expect(parsed == .run);
    const options = parsed.run;
    try std.testing.expectEqual(@as(usize, 1), options.peers.items.len);
    try std.testing.expectEqual(@as(u16, 9000), options.peers.items[0].addr.ip.port);
    try std.testing.expectEqual(@as(usize, 2), options.lookup_peers.items.len);
    try std.testing.expectEqual(@as(u16, 5353), options.dns_server.?.port);
    try std.testing.expectEqualStrings("test.invalid.", options.dns_origin);
    try std.testing.expectEqual(@as(i32, 25), options.lookup_deadline_ms);
    try std.testing.expectEqual(@as(u64, 100), options.lookup_interval_ms);
}

test "lookup requires explicit peers and source and bounded positive timing" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var secret = try ozai.SecretKey.fromSeed(@splat(7));
    defer secret.deinit();
    var id_buffer: [ozai.NodeId.z32_length + 1]u8 = undefined;
    const id = try std.fmt.bufPrintSentinel(&id_buffer, "{s}", .{secret.nodeId().toZ32()}, 0);
    const Case = struct { args: []const [*:0]const u8, refusal: CliError };
    const cases = [_]Case{
        .{ .args = &.{ "ozai-node", "--lookup-peer", id }, .refusal = error.LookupNeedsServer },
        .{
            .args = &.{ "ozai-node", "--dns-server", "127.0.0.1:53" },
            .refusal = error.LookupNeedsPeer,
        },
        .{
            .args = &.{ "ozai-node", "--lookup-deadline", "0" },
            .refusal = error.LookupTimingOutOfRange,
        },
        .{
            .args = &.{ "ozai-node", "--lookup-deadline", "2147483648" },
            .refusal = error.LookupTimingOutOfRange,
        },
        .{
            .args = &.{ "ozai-node", "--lookup-interval", "-1" },
            .refusal = error.LookupTimingOutOfRange,
        },
        .{
            .args = &.{ "ozai-node", "--lookup-interval", "9223372036855" },
            .refusal = error.LookupTimingOutOfRange,
        },
        .{
            .args = &.{ "ozai-node", "--dns-server", "127.0.0.1:0" },
            .refusal = error.AddressNotReachable,
        },
        .{ .args = &.{ "ozai-node", "--dns-origin", "" }, .refusal = error.InvalidDnsOrigin },
    };
    for (cases) |case| {
        var out: std.Io.Writer.Allocating = .init(arena.allocator());
        const parsed = try Options.parse(arena.allocator(), .{ .vector = case.args }, &out.writer);
        try std.testing.expect(parsed == .rejected);
        try std.testing.expectEqual(case.refusal, parsed.rejected);
    }
}

test "static peer does not enable external DNS" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var secret = try ozai.SecretKey.fromSeed(@splat(7));
    defer secret.deinit();
    const id = secret.nodeId().toZ32();
    var peer_buffer: [100]u8 = undefined;
    const peer = try std.fmt.bufPrintSentinel(&peer_buffer, "{s}@127.0.0.1:9000", .{id}, 0);
    const args = [_][*:0]const u8{ "ozai-node", "--peer", peer };
    var out: std.Io.Writer.Allocating = .init(arena.allocator());
    const parsed = try Options.parse(arena.allocator(), .{ .vector = &args }, &out.writer);
    try std.testing.expect(parsed == .run);
    try std.testing.expectEqual(@as(usize, 0), parsed.run.lookup_peers.items.len);
    try std.testing.expect(parsed.run.dns_server == null);
}

test "carrier and pinned relay peers leave inner application independent" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var secret = try ozai.SecretKey.fromSeed(@splat(7));
    defer secret.deinit();
    var peer_buffer: [160]u8 = undefined;
    const peer = try std.fmt.bufPrintSentinel(
        &peer_buffer,
        "{s}@http://relay.invalid:8080",
        .{secret.nodeId().toZ32()},
        0,
    );
    const args = [_][*:0]const u8{
        "ozai-node",
        "--relay-server",
        "127.0.0.1:8080",
        "--relay-host",
        "relay.invalid",
        "--peer-relay",
        peer,
        "--alpn",
        "app",
        "--traversal-address",
        "127.0.0.1:9000",
        "--traversal-address",
        "[::1]:9001",
        "--traversal-initiate",
    };
    var out: std.Io.Writer.Allocating = .init(arena.allocator());
    const parsed = try Options.parse(arena.allocator(), .{ .vector = &args }, &out.writer);
    try std.testing.expect(parsed == .run);
    try std.testing.expectEqualStrings("app", parsed.run.alpn.?);
    try std.testing.expectEqualStrings("relay.invalid", parsed.run.relay_host.?);
    try std.testing.expect(parsed.run.peers.items[0].addr == .relay);
    try std.testing.expectEqualStrings(
        "relay.invalid",
        parsed.run.peers.items[0].addr.relay.hostSlice(),
    );
    try std.testing.expectEqual(@as(usize, 2), parsed.run.traversal_addresses.items.len);
    try std.testing.expect(parsed.run.traversal_initiate);
}

test "gossip topics and getter options use protocol values" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const args = [_][*:0]const u8{
        "ozai-node", "--topic-hex", "abababababababababababababababababababababababababababababababab", "--topic-hex", "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        "--message", "hello",       "--relay-listen",                                                   "127.0.0.1:0",
    };
    var out: std.Io.Writer.Allocating = .init(arena.allocator());
    const gossip = try Options.parse(arena.allocator(), .{ .vector = &args }, &out.writer);
    try std.testing.expect(gossip == .run);
    try std.testing.expectEqual(@as(usize, 2), gossip.run.gossip_topics.items.len);
    try std.testing.expectEqual(@as(u8, 0xab), gossip.run.gossip_topics.items[0].bytes[0]);
    try std.testing.expectEqualStrings("hello", gossip.run.message.?);
    const blob_args = [_][*:0]const u8{
        "ozai-node",    "--blob-role", "getter",       "--blob-hash", "abababababababababababababababababababababababababababababababab",
        "--blob-size",  "40000",       "--blob-range", "15:33",       "--blob-output",
        "verified.bin",
    };
    const blob = try Options.parse(arena.allocator(), .{ .vector = &blob_args }, &out.writer);
    try std.testing.expect(blob == .run);
    try std.testing.expectEqualStrings(ozai.blobs_protocol.alpn, blob.run.alpn.?);
    try std.testing.expectEqual(@as(u64, 15), blob.run.blob_range.?.start);
    try std.testing.expectEqual(@as(u64, 33), blob.run.blob_range.?.end);
    try std.testing.expectEqual(@as(u8, 0xab), blob.run.blob_hash.?[0]);
}

test "protocol contradictions invalid values and removed flags are rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const Case = struct { args: []const [*:0]const u8, refusal: CliError };
    const cases = [_]Case{
        .{ .args = &.{ "node", "--relay" }, .refusal = error.NotAnOption },
        .{ .args = &.{ "node", "--relay-peer", "x" }, .refusal = error.NotAnOption },
        .{ .args = &.{ "node", "--send", "x" }, .refusal = error.NotAnOption },
        .{
            .args = &.{ "node", "--relay-server", "127.0.0.1:80" },
            .refusal = error.RelayNeedsHost,
        },
        .{ .args = &.{ "node", "--relay-host", "local" }, .refusal = error.RelayNeedsServer },
        .{
            .args = &.{
                "node",           "--relay-listen", "127.0.0.1:0",
                "--relay-server", "127.0.0.1:80",   "--relay-host",
                "local",
            },
            .refusal = error.TwoRelayRoles,
        },
        .{
            .args = &.{
                "node", "--blob-role", "getter", "--blob-hash", "abababababababababababababababababababababababababababababababab", "--alpn", "other",
            },
            .refusal = error.BlobAlpnMismatch,
        },
        .{
            .args = &.{ "node", "--blob-role", "provider", "--blob-hash", "abababababababababababababababababababababababababababababababab" },
            .refusal = error.BlobNeedsDirectory,
        },
        .{ .args = &.{ "node", "--blob-role", "getter" }, .refusal = error.BlobNeedsHash },
        .{ .args = &.{ "node", "--blob-hash", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz" }, .refusal = error.InvalidBlobHash },
        .{ .args = &.{ "node", "--blob-hash", "ab" }, .refusal = error.InvalidBlobHash },
        .{ .args = &.{ "node", "--blob-range", "1:1" }, .refusal = error.InvalidBlobRange },
        .{ .args = &.{ "node", "--blob-range", "2:1" }, .refusal = error.InvalidBlobRange },
        .{ .args = &.{ "node", "--blob-range", "1:2:3" }, .refusal = error.InvalidBlobRange },
        .{ .args = &.{ "node", "--blob-size", "-1" }, .refusal = error.InvalidBlobSize },
        .{ .args = &.{ "node", "--topic-hex", "ab" }, .refusal = error.InvalidTopic },
        .{
            .args = &.{
                "node",                                                             "--topic-hex",                                                      "abababababababababababababababababababababababababababababababab", "--topic-hex",                                                      "abababababababababababababababababababababababababababababababab",
                "--topic-hex",                                                      "abababababababababababababababababababababababababababababababab", "--topic-hex",                                                      "abababababababababababababababababababababababababababababababab", "--topic-hex",
                "abababababababababababababababababababababababababababababababab",
            },
            .refusal = error.TooManyTopics,
        },
    };
    for (cases) |case| {
        var out: std.Io.Writer.Allocating = .init(arena.allocator());
        const parsed = try Options.parse(arena.allocator(), .{ .vector = case.args }, &out.writer);
        try std.testing.expect(parsed == .rejected);
        try std.testing.expectEqual(case.refusal, parsed.rejected);
    }
}

test "expected peer identity is explicit and curve validated" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var secret = try ozai.SecretKey.fromSeed(@splat(9));
    defer secret.deinit();
    var buffer: [ozai.NodeId.z32_length + 1]u8 = undefined;
    const id = try std.fmt.bufPrintSentinel(&buffer, "{s}", .{secret.nodeId().toZ32()}, 0);
    const args = [_][*:0]const u8{ "node", "--expect-peer", id };
    var out: std.Io.Writer.Allocating = .init(arena.allocator());
    const parsed = try Options.parse(arena.allocator(), .{ .vector = &args }, &out.writer);
    try std.testing.expect(parsed == .run);
    try std.testing.expectEqualStrings(id, &parsed.run.expect_peer.?.toZ32());
    const invalid_args = [_][*:0]const u8{ "node", "--expect-peer", "invalid" };
    const invalid = try Options.parse(arena.allocator(), .{ .vector = &invalid_args }, &out.writer);
    try std.testing.expect(invalid == .rejected);
}

test "provider directory and all chunk getter range are accepted" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var out: std.Io.Writer.Allocating = .init(arena.allocator());
    const provider_args = [_][*:0]const u8{
        "node",        "--blob-role",                                                      "provider", "--blob-dir",    "store",
        "--blob-hash", "abababababababababababababababababababababababababababababababab", "--alpn",   "/iroh-bytes/4",
    };
    const provider = try Options.parse(
        arena.allocator(),
        .{ .vector = &provider_args },
        &out.writer,
    );
    try std.testing.expect(provider == .run);
    try std.testing.expect(provider.run.blob_role == .provider);
    try std.testing.expectEqualStrings("store", provider.run.blob_dir.?);
    const getter_args = [_][*:0]const u8{
        "node",         "--blob-role", "getter",      "--blob-hash", "abababababababababababababababababababababababababababababababab",
        "--blob-range", "all",         "--blob-size", "0",
    };
    const getter = try Options.parse(arena.allocator(), .{ .vector = &getter_args }, &out.writer);
    try std.testing.expect(getter == .run);
    try std.testing.expect(getter.run.blob_range == null);
    try std.testing.expectEqual(@as(u64, 0), getter.run.blob_size.?);
}

test "role dependent options do not disappear into defaults" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const Case = struct { args: []const [*:0]const u8, refusal: CliError };
    const cases = [_]Case{
        .{ .args = &.{ "node", "--blob-role", "unknown" }, .refusal = error.InvalidBlobRole },
        .{ .args = &.{ "node", "--blob-range", "all" }, .refusal = error.BlobNeedsRole },
        .{ .args = &.{ "node", "--blob-range", "-1:2" }, .refusal = error.InvalidBlobRange },
        .{
            .args = &.{ "node", "--blob-range", "0:18446744073709551616" },
            .refusal = error.InvalidBlobRange,
        },
        .{ .args = &.{ "node", "--blob-range", "all:2" }, .refusal = error.InvalidBlobRange },
        .{
            .args = &.{ "node", "--blob-size", "18446744073709551616" },
            .refusal = error.InvalidBlobSize,
        },
        .{
            .args = &.{
                "node",        "--blob-role",                                                      "provider",     "--blob-dir", "store",
                "--blob-hash", "abababababababababababababababababababababababababababababababab", "--blob-range", "all",
            },
            .refusal = error.BlobProviderGetterOptions,
        },
        .{
            .args = &.{
                "node", "--blob-role", "getter", "--blob-hash", "abababababababababababababababababababababababababababababababab", "--blob-dir", "store",
            },
            .refusal = error.BlobGetterDirectory,
        },
        .{ .args = &.{ "node", "--message", "hello" }, .refusal = error.MessageNeedsTopic },
        .{ .args = &.{ "node", "--relay-host", "" }, .refusal = error.InvalidRelayHost },
        .{
            .args = &.{ "node", "--relay-server", "127.0.0.1:0" },
            .refusal = error.AddressNotReachable,
        },
        .{
            .args = &.{ "node", "--traversal-address", "127.0.0.1:0" },
            .refusal = error.AddressNotReachable,
        },
        .{ .args = &.{ "node", "--blob-output", "" }, .refusal = error.EmptyPath },
    };
    for (cases) |case| {
        var out: std.Io.Writer.Allocating = .init(arena.allocator());
        const parsed = try Options.parse(arena.allocator(), .{ .vector = case.args }, &out.writer);
        try std.testing.expect(parsed == .rejected);
        try std.testing.expectEqual(case.refusal, parsed.rejected);
    }
}

test "explicit gossip topics select gossip and reject competing application protocols" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var out: std.Io.Writer.Allocating = .init(arena.allocator());
    const args = [_][*:0]const u8{ "node", "--topic-hex", "abababababababababababababababababababababababababababababababab" };
    const parsed = try Options.parse(arena.allocator(), .{ .vector = &args }, &out.writer);
    try std.testing.expect(parsed == .run);
    try std.testing.expectEqualStrings(node_mod.gossip_alpn, parsed.run.alpn.?);
    const Case = struct { args: []const [*:0]const u8, refusal: CliError };
    const cases = [_]Case{
        .{
            .args = &.{ "node", "--topic-hex", "abababababababababababababababababababababababababababababababab", "--alpn", "other" },
            .refusal = error.TopicAlpnMismatch,
        },
        .{
            .args = &.{
                "node",                                                             "--topic-hex", "abababababababababababababababababababababababababababababababab", "--blob-role", "getter", "--blob-hash",
                "abababababababababababababababababababababababababababababababab",
            },
            .refusal = error.ConflictingProtocols,
        },
    };
    for (cases) |case| {
        const rejected = try Options.parse(
            arena.allocator(),
            .{ .vector = case.args },
            &out.writer,
        );
        try std.testing.expect(rejected == .rejected);
        try std.testing.expectEqual(case.refusal, rejected.rejected);
    }
}

test "native traversal requires candidates and bounds configured candidates" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const Case = struct { args: []const [*:0]const u8, refusal: CliError };
    const cases = [_]Case{
        .{ .args = &.{ "node", "--traversal-initiate" }, .refusal = error.TraversalNeedsAddress },
        .{
            .args = &.{
                "node",                "--traversal-address", "127.0.0.1:1",
                "--traversal-address", "127.0.0.1:2",         "--traversal-address",
                "127.0.0.1:3",
            },
            .refusal = error.TooManyTraversalAddresses,
        },
    };
    for (cases) |case| {
        var out: std.Io.Writer.Allocating = .init(arena.allocator());
        const parsed = try Options.parse(arena.allocator(), .{ .vector = case.args }, &out.writer);
        try std.testing.expect(parsed == .rejected);
        try std.testing.expectEqual(case.refusal, parsed.rejected);
    }
}
