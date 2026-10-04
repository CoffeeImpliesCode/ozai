//! Stable node construction, protocol registration and exactly-once disposal.

const std = @import("std");
const node_mod = @import("node.zig");
const node_config = @import("node_config.zig");
const node_protocol = @import("node_protocol.zig");
const node_lane = @import("node_lane.zig");
const node_dispatch = @import("node_dispatch.zig");
const node_framing = @import("node_framing.zig");
const addr_map = @import("../transport/addr_map.zig");
const bridge_mod = @import("../transport/quic_bridge.zig");
const quic_conn = @import("../transport/quic_conn.zig");
const dial_mod = @import("../transport/dial.zig");
const socket_mod = @import("../transport/socket.zig");
const router = @import("../router/router.zig");
const lifetime_mod = @import("../router/lifetime.zig");
const endpoint = @import("../endpoint/endpoint.zig");
const hyparview = @import("../gossip/hyparview.zig");
const relay_state = @import("relay_state.zig");
const SocketAddr = @import("../base/addr.zig").SocketAddr;
const Error = @import("node_error.zig").Error;
const Config = node_config.Config;
const Node = node_mod.Node;
const Csprng = std.Random.DefaultCsprng;

/// Allocates one heap-stable owner; protocol validation precedes all allocations.
/// `config.secret` is copied, so the caller must still wipe its own copy.
/// Registration reads the protocol slice once. Its ALPN bytes and custom handler
/// state, the peer slice and custom-address payloads must outlive the node.
/// The three secure entropy draws propagate `error.EntropyUnavailable` or
/// `error.Canceled`; every error releases acquired resources and every exit wipes
/// the temporary seed. `io` is not retained; keep `gpa` alive until `deinit`.
/// Lanes, registry storage and leases borrow this allocation: never copy the node.
/// Close it before calling `deinit` exactly once.
pub fn create(gpa: std.mem.Allocator, io: std.Io, config: Config) Error!*Node {
    try node_protocol.validateProtocols(config.protocols);
    var secret_seed: [Csprng.secret_seed_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &secret_seed);
    io.randomSecure(&secret_seed) catch |err| switch (err) {
        error.EntropyUnavailable => return error.EntropyUnavailable,
        error.Canceled => return error.Canceled,
    };
    const self = try gpa.create(Node);
    errdefer gpa.destroy(self);
    self.* = .{
        .gpa = gpa,
        .config = config,
        .socket = undefined,
        .bridge = undefined,
        .dialer = undefined,
        .map = addr_map.MappedAddrs.init(),
        .socket_open = true,
        .endpoint_closed = false,
        .entries = undefined,
        .table = undefined,
        .lanes = undefined,
        .lane_lifetimes = undefined,
        .lane_lanes = undefined,
        .offer_list = undefined,
        .tasks = undefined,
        .accept = undefined,
        .lease = undefined,
        .topics = .{},
        .connections = .{},
        .engine = Csprng.init(secret_seed),
        .egress = &.{},
        .out = &.{},
        .scratch = &.{},
        .buf = &.{},
        .control = undefined,
        .held = null,
        .offered = .empty,
        .dialled = .empty,
        .joined = false,
        .relay_state = undefined,
        .stats = .{},
    };
    errdefer self.map.deinit(gpa);
    errdefer self.offered.deinit(gpa);
    errdefer self.dialled.deinit(gpa);
    register(self);
    const offers = self.offer_list[0..self.table.offers(&self.offer_list)];
    self.socket = try socket_mod.Socket.create(config.listen, .{});
    errdefer node_dispatch.shutdownSocket(self);
    self.bridge = try bridge_mod.Bridge.create(gpa, io, .{
        .expect_peer = null,
        .secret = config.secret,
        .alpns = offers,
    }, node_mod.generator(self));
    errdefer self.bridge.destroy();
    self.dialer = try dial_mod.Dialer.create(gpa, self.bridge, .{
        .secret = config.secret,
        .alpns = offers,
    });
    errdefer {
        std.debug.assert(self.bridge.manager.entries.items.len == 0);
        self.dialer.destroy() catch |err| switch (err) {
            error.DialedConnectionsLive => std.debug.panic(
                "a dialled connection is live while building a node: {t}",
                .{err},
            ),
        };
    }
    self.egress = try gpa.alloc(quic_conn.Egress, node_config.max_egress);
    errdefer gpa.free(self.egress);
    self.out = try gpa.alloc(u8, node_config.send_room);
    errdefer gpa.free(self.out);
    self.scratch = try gpa.alloc(u8, node_config.scratch_room);
    errdefer gpa.free(self.scratch);
    self.buf = try gpa.alloc(u8, node_config.receive_room);
    errdefer gpa.free(self.buf);
    const relay_sizing: ?relay_state.Sizing = switch (config.relay.role) {
        .serve => |role| relay_state.Sizing{
            .clients = role.clients,
            .queue_depth = role.queue_depth,
            .datagram = node_config.max_datagram,
        },
        else => null,
    };
    if (relay_sizing) |size| {
        if (size.clients > node_config.max_relay_clients) return error.TooManyRelayClients;
        if (size.queue_depth == 0) return error.RelayQueueDepthZero;
    }
    try self.relay_state.init(
        gpa,
        node_config.relay_frame_room + node_framing.varint_max,
        node_config.relay_frame_room,
        relay_sizing,
    );
    errdefer self.relay_state.deinit(gpa);
    var addr_text: [SocketAddr.max_text_length]u8 = undefined;
    const advertised = std.fmt.bufPrint(&addr_text, "{f}", .{
        self.socket.address,
    }) catch |err| switch (err) {
        error.NoSpaceLeft => std.debug.panic(
            "address text needs more than {d} bytes: max_text_length is wrong",
            .{SocketAddr.max_text_length},
        ),
    };
    // The one swarm this node is in, named by the configuration rather than
    // derived from anything: a stream it opens names this id, and a peer hears
    // this node only if both ends were built with the same one.
    const joined = self.topics.add(
        config.topic_id,
        self.bridge.nodeId(),
        try hyparview.PeerData.fromBytes(advertised),
        config.topic,
        hyparview.Rng.init(self.engine.random().int(u64)),
    ) catch |err| switch (err) {
        // An empty table cannot be full: this is its first topic and
        // `max_topics` is eight, so there is no caller that could make it true.
        // Claimed rather than handled, and not silently ignored.
        error.TopicTableFull => unreachable,
        else => |rest| return rest,
    };
    // Read back, because every `feedGossip` reaches this topic by position
    // rather than by id and nothing else would say the two disagree.
    std.debug.assert(joined == self.topics.at(0));
    errdefer self.topics.deinit(gpa);
    // The admission filter, registered once and asked from two places: the
    // core's pre-accept hook below, where a `retry` verdict is still a token
    // the peer can answer, and the loop's `Action.offer`, where it is the
    // endpoint's own recorded answer. Both read this one registration, so the
    // two cannot disagree about what a node admits.
    //
    // **The extra round trip is per new flow, not per datagram.** The hook is
    // consulted only inside `route`'s "no connection for this DCID yet" branch
    // (`vendor/quic/src/quic/connection_manager.zig`), so the second and every
    // later datagram of a flow are routed to the entry the first one opened and
    // are never offered again. What the first datagram of each new flow costs is
    // exactly what buys address validation for that connection: the flow comes
    // back carrying the token, and that attempt is the one the core answers
    // `isPathValidated` for (`vendor/quic/src/quic/connection_manager.zig`, "an
    // admission verdict reaches the peer" — the echoed token is accepted with
    // the path proved). A validated address then bypasses Retry rather than
    // earning another one.
    //
    // **A flow that is already proved is accepted, and a Retry asked for on one
    // is refused rather than sent.** That is the filter's own rule
    // (`node_dispatch.proveAddress`: proved answers accept, only unvalidated is
    // asked back) and the core's backstop under it — a `retry` verdict on a
    // validated flow becomes CONNECTION_REFUSED, because QUIC permits one Retry
    // per flow and there is no second token to send. Both are covered by "a
    // Retry asked for on a flow that already proved its address is refused, not
    // sent twice" in the same file.
    self.bridge.manager.admission = .{
        .ptr = self,
        .decide = node_dispatch.admission,
    };
    self.accept = endpoint.Loop.init(&self.table, node_dispatch.filterer(self), &self.tasks);
    self.lease = self.accept.acquire();
    return self;
}

/// Installs the validated configuration once at the node's final address.
/// The table borrows its lanes and ALPN bytes for the node's lifetime.
fn register(self: *node_mod.Node) void {
    var builder = router.Builder.init(&self.entries);
    for (self.config.protocols, 0..) |registration, index| {
        self.lanes[index] = .{
            .owner = self,
            .alpn = registration.alpn,
            .standard = switch (registration.handler) {
                .standard => node_protocol.standardOf(registration.alpn).?,
                .custom => null,
            },
            .caller = switch (registration.handler) {
                .custom => |handler| handler,
                .standard => null,
            },
        };
        const registered = builder.accept(registration.alpn, .{
            .ptr = @ptrCast(&self.lanes[index]),
            .on_accepting = null,
            .accept = node_lane.laneAccept,
            .shutdown = node_lane.laneShutdown,
        }) catch @panic("validateProtocols and Builder.accept disagree about a protocol list");
        std.debug.assert(registered == .fresh);
    }
    self.table = builder.build();
    self.lane_lanes = lifetime_mod.Lanes.init(&self.lane_lifetimes, &self.table);
}

/// Releases connections, owned storage and the stable allocation, wiping secrets.
/// Requires a closed node with no driver or callback still running; single-threaded.
/// An abandoned lease is reported at error level, not closed gracefully here.
/// Connections leave before their dialer seed and transport owners are released.
/// The pointer and owned views are invalid afterward; calling this again is invalid.
/// The caller's allocator and borrowed custom-address payloads are not released.
pub fn deinit(self: *node_mod.Node) void {
    switch (self.lease.deinit()) {
        .closed => {},
        .abandoned => |phase| std.log.err(
            "node {f} was dropped in phase {t} without close()",
            .{ self.bridge.nodeId(), phase },
        ),
        .already_gone => {},
    }
    // Swap-removal requires a backwards walk, and handshakes borrow the dialer's seed.
    var index = self.bridge.manager.entries.items.len;
    while (index > 0) {
        index -= 1;
        const entry = self.bridge.manager.entries.items[index];
        if (!entry.conn.is_server) self.bridge.manager.removeConnection(entry);
    }
    self.bridge.sweep();
    self.relay_state.deinit(self.gpa);
    for (self.bridge.manager.entries.items) |entry| {
        std.debug.assert(entry.conn.is_server);
    }
    self.dialer.destroy() catch |err| switch (err) {
        error.DialedConnectionsLive => std.debug.panic(
            "a dialled connection is live at teardown: {t}",
            .{err},
        ),
    };
    self.bridge.destroy();
    self.gpa.free(self.egress);
    self.gpa.free(self.out);
    self.gpa.free(self.scratch);
    self.gpa.free(self.buf);
    self.map.deinit(self.gpa);
    self.offered.deinit(self.gpa);
    self.dialled.deinit(self.gpa);
    self.topics.deinit(self.gpa);
    node_dispatch.shutdownSocket(self);
    self.config.secret.deinit();
    std.crypto.secureZero(u8, std.mem.asBytes(&self.engine));
    self.gpa.destroy(self);
}
