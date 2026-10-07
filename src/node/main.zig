//! CLI for pinned inner QUIC peers, gossip topics, and Bao-verified blobs.
//! Relay TCP is a carrier, independent of the inner application ALPN.
const std = @import("std");
const builtin = @import("builtin");
const ozai = @import("ozai");
const coverage_abi = @import("coverage_abi");
const cli_options = @import("cli_options.zig");
const cli_loop = @import("cli_loop.zig");
const cli_report = @import("cli_report.zig");
const node_mod = ozai.node;
const Node = node_mod.Node;

comptime {
    if (builtin.fuzz) _ = coverage_abi;
}

pub const std_options: std.Options = .{ .log_level = .warn };

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var out_buffer: [512]u8 = undefined;
    var out = std.Io.File.stdout().writerStreaming(io, &out_buffer);
    const text = &out.interface;
    const options = switch (try cli_options.Options.parse(
        init.arena.allocator(),
        init.minimal.args,
        text,
    )) {
        .run => |run| run,
        .help => {
            try out.flush();
            return;
        },
        .rejected => {
            try out.flush();
            std.process.exit(1);
        },
    };
    const alpn = options.alpn orelse if (options.blob_role != null)
        ozai.blobs_protocol.alpn
    else
        node_mod.gossip_alpn;
    var secret = options.secret orelse ozai.SecretKey.generate(io);
    defer secret.deinit();

    // Borrowed handles and callback context outlive Node.deinit.
    var blob_dir: ?std.Io.Dir = null;
    defer if (blob_dir) |dir| dir.close(io);
    if (options.blob_role == .provider) {
        const path = options.blob_dir orelse @panic("blob provider requires a directory");
        blob_dir = try std.Io.Dir.cwd().openDir(io, path, .{});
    }
    var evidence: cli_report.GossipEvidence = .{ .writer = text };
    var dns_socket: ?ozai.transport_socket.Socket = null;
    defer if (dns_socket) |*handle| handle.close();
    var dns_datagram: ozai.discovery_lookup_live.Datagram = undefined;
    var discovery: node_mod.Discovery = .{
        .peer_ids = options.lookup_peers.items,
        .origin = options.dns_origin,
        .deadline_ms = options.lookup_deadline_ms,
        .interval_ms = options.lookup_interval_ms,
    };
    if (options.dns_server) |server| {
        const bind: ozai.SocketAddr = .{
            .ip = switch (server.ip) {
                .v4 => .{ .v4 = .{ 0, 0, 0, 0 } },
                .v6 => .{ .v6 = .{0} ** 16 },
            },
            .port = 0,
        };
        dns_socket = try ozai.transport_socket.Socket.create(bind, .{});
        if (dns_socket) |*socket| {
            dns_datagram = .init(socket);
        } else {
            @panic("DNS socket creation did not retain its handle");
        }
        discovery.lookup = .{
            .datagram = dns_datagram.seam(),
            .server = server,
            .resolver_stopped = &dns_datagram.stopped,
            .stream_execution = .native,
        };
    }
    const has_traversal_addresses = options.traversal_addresses.items.len != 0;
    const node = try Node.create(init.gpa, io, .{
        .secret = secret,
        .listen = options.listen,
        .peers = options.peers.items,
        .expect_peer = options.expect_peer,
        .alpn = alpn,
        .gossip_topics = options.gossip_topics.items,
        .gossip_message = options.message,
        .on_gossip = cli_report.GossipEvidence.receive,
        .on_gossip_context = &evidence,
        .blobs = if (options.blob_role) |role| switch (role) {
            .provider => .{ .provider = .{
                .dir = blob_dir orelse @panic("blob provider directory was not opened"),
                .hash = options.blob_hash orelse @panic("blob provider requires a hash"),
            } },
            .getter => .{ .getter = .{
                .hash = options.blob_hash orelse @panic("blob getter requires a hash"),
                .size = options.blob_size,
                .range = options.blob_range,
            } },
        } else .disabled,
        .relay = .{
            .serve = options.relay_listen,
            .client = if (options.relay_server) |server| .{
                .address = server,
                .host = options.relay_host orelse @panic("relay client requires a host"),
                .secret = secret,
                .execution = .native,
            } else null,
        },
        .max_remote_nat_traversal_addresses = if (has_traversal_addresses) 2 else null,
        .initial_max_path_id = if (has_traversal_addresses) 1 else null,
        .traversal = .{
            .local_candidates = options.traversal_addresses.items,
            .initiate = options.traversal_initiate,
        },
        .discovery = discovery,
    }, options.seed);
    defer node.deinit();
    cli_loop.watchForStop();
    try text.print(
        "node       {f}\nz-base-32  {s}\nlistening  {f}\nalpn       {s}\n",
        .{ node.nodeId(), node.nodeId().toZ32(), node.address(), alpn },
    );
    if (node.relay_runtime.server) |*server|
        try text.print("relay TCP  serving {f}\n", .{server.address});
    if (options.relay_server) |address| {
        const host = options.relay_host orelse @panic("relay client requires a host");
        try text.print("relay TCP  {f} host {s}\n", .{ address, host });
    }
    for (options.peers.items) |peer| try text.print(
        "peer       {f} at {f}\n",
        .{ peer.id, peer.addr },
    );
    for (options.lookup_peers.items) |peer| {
        const server = options.dns_server orelse @panic("lookup peers require a DNS server");
        try text.print(
            "lookup     {f} through {f}, origin {s}\n",
            .{ peer, server, options.dns_origin },
        );
    }
    for (options.traversal_addresses.items) |address|
        try text.print("traversal  configured candidate {f}\n", .{address});
    try text.print("running    {d} ms, then a graceful close\n", .{options.run_ms});
    try out.flush();

    const started = try cli_loop.nowNs(io);
    cli_loop.stopped.expireAt(started + options.run_ms * std.time.ns_per_ms);
    cli_loop.drive(
        io,
        node,
        options.blob_output,
        &evidence,
        if (options.progress) text else null,
    ) catch |err| {
        _ = try cli_loop.shut(io, node, node.establishedCount());
        return err;
    };
    const holding: cli_report.Holding = .{ .connections = node.establishedCount() };
    const close = try cli_loop.shut(io, node, holding.connections);
    try cli_report.report(text, node, holding, close);
    try out.flush();
}
