//! Construction, explicit subscription startup, and reverse-order teardown.

const std = @import("std");

const node_mod = @import("node.zig");
const node_config = @import("node_config.zig");
const node_accept = @import("node_accept.zig");
const node_blobs = @import("node_blobs.zig");
const node_transport = @import("node_transport.zig");
const node_gossip = @import("node_gossip.zig");
const node_holepunch = @import("node_holepunch.zig");

const base_key = @import("../base/key.zig");
const base_addr = @import("../base/addr.zig");
const addr_map = @import("../transport/addr_map.zig");
const node_discovery_record = @import("node_discovery_record.zig");
const bridge_mod = @import("../transport/quic_bridge.zig");
const dial_mod = @import("../transport/dial.zig");
const socket_mod = @import("../transport/socket.zig");
const router = @import("../router/router.zig");
const endpoint = @import("../endpoint/endpoint.zig");
const hyparview = @import("../gossip/hyparview.zig");

const Self = node_mod.Node;
const Config = node_config.Config;
const Error = node_config.Error;
const NodeId = base_key.NodeId;
const named_ring = node_gossip.named_ring;
const SocketAddr = base_addr.SocketAddr;
const Bridge = bridge_mod.Bridge;
const Instant = bridge_mod.Instant;
const Egress = bridge_mod.Egress;
const Dialer = dial_mod.Dialer;
const Socket = socket_mod.Socket;
const Prng = std.Random.DefaultPrng;
const max_egress = node_transport.max_egress;
const send_room = node_transport.send_room;
const scratch_room = node_transport.scratch_room;
const receive_room = node_transport.receive_room;

/// All allocation uses `gpa`, which outlives the node. Configuration is copied,
/// but application topic IDs, peer addresses, callback context, directory handles
/// and TLS/discovery storage are borrowed for the node's lifetime.
/// Carrier resources are independent of inner QUIC application connections.
pub fn create(gpa: std.mem.Allocator, io: std.Io, config: Config, seed: u64) Error!*Self {
    try node_config.validate(config);
    if (config.discovery.deadline_ms <= 0 or config.discovery.interval_ms == 0 or
        config.discovery.interval_ms > @as(u64, @intCast(std.math.maxInt(i64))) /
            std.time.ns_per_ms or
        (config.discovery.peer_ids.len != 0 and config.discovery.lookup == null and
            !config.discovery.resolve_pkarr) or
        (config.discovery.resolve_pkarr and config.discovery.relay == null))
    {
        return error.InvalidDiscoveryConfig;
    }
    const self = try gpa.create(Self);
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
        .tasks = undefined,
        .accept = undefined,
        .lease = undefined,
        .gossip_topics = &.{},
        .timers = .empty,
        .named = @as([named_ring]NodeId, @splat(undefined)),
        .named_len = 0,
        .engine = Prng.init(seed),
        .egress = &.{},
        .out = &.{},
        .scratch = &.{},
        .buf = &.{},
        .control = undefined,
        .held = null,
        .offered = .empty,
        .dialled = .empty,
        .joined = false,
        .blobs = node_blobs.State.init(config.blobs),
        .relay_runtime = undefined,
        .stats = .{},
        .discovery = .{},
        .holepunch = undefined,
    };
    errdefer wipeConfigSecrets(&self.config);
    errdefer self.map.deinit(gpa);
    errdefer self.offered.deinit(gpa);
    errdefer self.dialled.deinit(gpa);
    errdefer self.timers.deinit(gpa);
    try self.relay_runtime.init(io, config.relay);
    errdefer self.relay_runtime.deinit();
    errdefer self.blobs.deinit(gpa);

    self.socket = try Socket.create(config.listen, .{});
    errdefer node_transport.shutdownSocket(self);
    self.bridge = try Bridge.create(gpa, io, .{
        .expect_peer = config.expect_peer,
        .secret = config.secret,
        .alpn = config.alpn,
        .initial_policy = config.initial_policy,
        .address_discovery_role = config.address_discovery_role,
        .max_remote_nat_traversal_addresses = config.max_remote_nat_traversal_addresses,
        .initial_max_path_id = config.initial_max_path_id,
        .ipv6_supported = self.socket.address.ip == .v6,
    }, self.generator());
    errdefer self.bridge.destroy();
    self.holepunch = try node_holepunch.State.init(gpa, self.bridge.manager.max_connections);
    errdefer self.holepunch.deinit(gpa);
    self.dialer = try Dialer.create(gpa, self.bridge, .{
        .secret = config.secret,
        .alpn = config.alpn,
        .address_discovery_role = config.address_discovery_role,
        .max_remote_nat_traversal_addresses = config.max_remote_nat_traversal_addresses,
        .initial_max_path_id = config.initial_max_path_id,
        .ipv6_supported = self.socket.address.ip == .v6,
    });
    // `destroy` refuses only while a dialled connection is live, and this
    // errdefer cannot meet one: the bridge above was created with an empty
    // table, and every call between there and a failure here allocates,
    // prints an address or builds a table — none of them dials. Asserted
    // rather than assumed, and the arm below says so out loud instead of
    // returning with the dialer's seed un-zeroed.
    errdefer {
        std.debug.assert(self.bridge.manager.entries.items.len == 0);
        self.dialer.destroy() catch |err| switch (err) {
            error.DialedConnectionsLive => std.debug.panic(
                "a dialled connection is live while building a node: {t}",
                .{err},
            ),
        };
    }
    self.egress = try gpa.alloc(Egress, max_egress);
    errdefer gpa.free(self.egress);
    self.out = try gpa.alloc(u8, send_room);
    errdefer gpa.free(self.out);
    self.scratch = try gpa.alloc(u8, scratch_room);
    errdefer gpa.free(self.scratch);
    self.buf = try gpa.alloc(u8, receive_room);
    errdefer gpa.free(self.buf);

    // What this node advertises as its own contact data: the address it
    // is reachable at. Upstream carries opaque bytes and this is the one
    // that is true of every node in it.
    //
    // The buffer is `SocketAddr.max_text_length` and not a byte more, so
    // the only way `bufPrint` refuses is a bound that is wrong; the arm
    // below is the statement that it is, made loud rather than silent.
    var addr_text: [SocketAddr.max_text_length]u8 = undefined;
    const advertised = std.fmt.bufPrint(&addr_text, "{f}", .{
        self.socket.address,
    }) catch |err| switch (err) {
        error.NoSpaceLeft => std.debug.panic(
            "address text needs more than {d} bytes: max_text_length is wrong",
            .{SocketAddr.max_text_length},
        ),
    };
    self.gossip_topics = try gpa.alloc(hyparview.TopicState, config.gossip_topics.len);
    errdefer gpa.free(self.gossip_topics);
    for (self.gossip_topics) |*topic| {
        topic.* = try hyparview.TopicState.init(
            self.bridge.nodeId(),
            try hyparview.PeerData.fromBytes(advertised),
            config.topic,
            hyparview.Rng.init(seed),
        );
    }

    // Last, because the two values below read through this struct and a
    // failure after this point would have to unwind a lease that nothing
    // else holds.
    var builder = router.Builder.init(&self.entries);
    const registered = try builder.accept(config.alpn, node_accept.handler(self));
    // `.fresh` is the only answer here: the table was built a line ago and
    // holds no ALPN, so a `.replaced` would be a second registration for
    // the one protocol this node speaks, which `max_alpns` rules out.
    std.debug.assert(registered == .fresh);
    self.table = builder.build();
    self.accept = endpoint.Loop.init(&self.table, null, &self.tasks);
    self.lease = self.accept.acquire();
    // The node's own record, armed once and republished by the discovery pass
    // on its timer. Not a failure: a node configured with no relay has nothing
    // to publish, and that is `discovery/preset.zig`'s own default rather than
    // a refusal of the node — `arm` counts it by name and leaves the timer
    // unarmed, so the pass never comes due.
    node_discovery_record.arm(self);
    return self;
}

/// Dial every peer the configuration names, once, and tell the gossip layer to
/// join them.
///
/// Not part of `create`: a dial needs an instant and a generator, and
/// `create` has a seed rather than either. Upstream dials from
/// `Endpoint::connect`, after the endpoint exists; this draws the line
/// where the instant is available, which is the same line.
///
/// Idempotent, so `run` may call it every pass: a peer already attempted
/// is skipped, whether the dial worked or not, and the join command is fed
/// once.
///
/// **A `start` that failed has not joined, and the next one tries again.**
/// The latch is set once the command has been fed, so a refusal — the
/// length check, a clock this node cannot use, or an allocator that gave
/// out inside `node_gossip.feedGossip` — leaves a node willing rather than
/// latched into a success that joined nothing. Re-arming says the caller
/// *may* try, not that a retry is safe: what a failed `feedGossip` left in
/// the gossip layer is not promised to be replayable (`Node.step`'s own
/// rule), and `run` and the binary's own loop both answer a failed `start`
/// by leaving the loop rather than by calling it again. A caller driving
/// `start` itself owns that choice — try once more, or close the node and
/// throw it away.
pub fn start(self: *Self, at: Instant, random: std.Random) Error!void {
    for (self.config.peers) |peer| {
        if (self.dialled.contains(peer.id)) continue;
        try self.relay_runtime.admit(peer.addr);
        try self.dialled.put(self.gpa, peer.id, {});
        const reached = self.dialer.dial(
            peer.addr,
            peer.id,
            self.socket.address,
            &self.map,
            at,
            random,
        ) catch |err| {
            // A peer that cannot be reached is a fact about the network and
            // not a refusal to start: the node keeps running with the peers
            // it did reach, and the count is what a caller reads. The dial
            // is recorded as attempted either way, which is why this node
            // does not retry it — see `Config.peers`.
            self.stats.dials_refused += 1;
            std.log.warn("node: {f} was not reached: {t}", .{ peer.id, err });
            continue;
        };
        // On a direct dial the address the core was told is the target's
        // own, and a relay or a custom target resolves to a synthetic RFC
        // 4193 address — which is the whole of what `resolveRoute` does
        // (`dial.zig`'s module doc), and a node that remembered the
        // target's own address here would be remembering a fact nothing
        // downstream holds.
        switch (peer.addr) {
            .ip => |target| std.debug.assert(reached.route.socket.order(target) == .eq),
            .relay, .custom => {},
        }
        self.stats.dials += 1;
    }
    if (self.joined) return;
    if (self.gossip_topics.len == 0) {
        self.joined = true;
        return;
    }
    // Checked before the list is built rather than left to `Peers.init`,
    // which would refuse the same length one line later with the list
    // already half filled.
    if (self.config.peers.len + self.config.discovery.peer_ids.len > hyparview.max_bootstrap) {
        return error.BootstrapListTooLong;
    }
    // The command is fed even when no peer was named: an empty list means
    // "be ready to be asked", which is how upstream's bootstrap node starts
    // (`hyparview.Command`'s own doc).
    var ids: [hyparview.max_bootstrap]NodeId = undefined;
    var count: usize = 0;
    for (self.config.peers) |peer| {
        ids[count] = peer.id;
        count += 1;
    }
    for (self.config.discovery.peer_ids) |peer| {
        var duplicate = false;
        for (ids[0..count]) |known| {
            if (known.order(peer) == .eq) duplicate = true;
        }
        if (!duplicate) {
            ids[count] = peer;
            count += 1;
        }
    }
    try node_gossip.start(self, ids[0..count], try node_gossip.gossipNow(at));
    self.joined = true;
}

/// Free everything the node owns.
///
/// The endpoint lease is given up first, and what it reports is this
/// node's misuse or not: upstream logs an error from `EndpointInner`'s
/// `Drop` when `close()` was never called — "Endpoint dropped without
/// calling `Endpoint::close`. Aborting ungracefully"
/// (`iroh/src/socket.rs:220-230`) — so dropping a node whose accept loop
/// is still serving is a misuse and not a cleanup. The report is at error
/// level on purpose: it is a finding, and `zig build test`'s runner fails an
/// artifact that logged one.
///
/// All node-owned transfers and carrier resources end here. Borrowed configuration
/// storage remains the caller's property.
/// The caller destroys the node allocation after releasing these resources.
///
/// **It may not run under a `run` or a `step` that is still on the
/// stack.** `run` closes the node on its way out precisely so that the
/// caller reaches this call with the shutdown already run out; a caller
/// that destroys a node whose loop is still passing it frees the buffers
/// the pass is writing into. Single-threaded, like everything else here.
///
/// Client connections leave before their dialer's secret storage and the bridge.
/// Protocol states release their resources before the remaining node storage.
pub fn release(self: *Self) void {
    switch (self.lease.deinit()) {
        .closed => {},
        .abandoned => |phase| std.log.err(
            "node {f} was dropped in phase {t} without close()",
            .{ self.bridge.nodeId(), phase },
        ),
        .already_gone => {},
    }
    // `Dialer.destroy`'s order, and for its reason: a dialled connection's
    // handshake points at the dialer's own seed, so every connection this
    // dialer opened has to leave the manager before the dialer goes, and
    // the manager has to outlive both. Backwards, because
    // `removeConnection` swap-removes and a forward walk would skip an
    // entry.
    var index = self.bridge.manager.entries.items.len;
    while (index > 0) {
        index -= 1;
        const entry = self.bridge.manager.entries.items[index];
        if (!entry.conn.is_server) self.bridge.manager.removeConnection(entry);
    }
    self.bridge.sweep();
    self.blobs.deinit(self.gpa);
    self.relay_runtime.deinit();
    // The walk above already applied `destroy`'s own test — every entry
    // with `!entry.conn.is_server` — to every entry there was, and
    // `removeConnection` swap-removes the entry it is handed
    // (`vendor/quic/src/quic/connection_manager.zig:447`), so there is
    // nothing left for `destroy` to refuse on. Checked rather than
    // assumed: an entry that survived the walk would have the bridge
    // freed and the seed zeroed under a live handshake.
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
    // ZBC cannot infer that `egress` is terminally owned and `self` is destroyed afterward.
    // zbc-disable-next-line: free-without-null-then-check
    self.gpa.free(self.egress);
    // ZBC cannot infer that `out` is terminally owned and `self` is destroyed afterward.
    // zbc-disable-next-line: free-without-null-then-check
    self.gpa.free(self.out);
    // ZBC cannot infer that `scratch` is terminally owned and `self` is destroyed afterward.
    // zbc-disable-next-line: free-without-null-then-check
    self.gpa.free(self.scratch);
    // ZBC cannot infer that `buf` is terminally owned and `self` is destroyed afterward.
    // zbc-disable-next-line: free-without-null-then-check
    self.gpa.free(self.buf);
    self.map.deinit(self.gpa);
    self.offered.deinit(self.gpa);
    self.dialled.deinit(self.gpa);
    self.timers.deinit(self.gpa);
    // ZBC cannot see later cleanup ignore this terminal slice before `Node.deinit` destroys `self`.
    // zbc-disable-next-line: free-without-null-then-check
    self.gpa.free(self.gossip_topics);
    self.discovery.release();
    self.holepunch.deinit(self.gpa);
    node_transport.shutdownSocket(self);
    wipeConfigSecrets(&self.config);
}

fn wipeConfigSecrets(config: *Config) void {
    config.secret.deinit();
    if (config.relay.client) |*client| client.secret.deinit();
}

// Inspect the copied key at owned-free time, before the backing allocator poisons memory.
test "node construction rollback wipes copied secret before freeing owner" {
    var secret = try base_key.SecretKey.fromSeed(@splat(0x5b));
    defer secret.deinit();
    var observer: RollbackSecretAllocator = .{};
    try std.testing.expectError(
        error.OutOfMemory,
        create(observer.allocator(), std.testing.io, .{ .secret = secret }, 991),
    );
    try std.testing.expect(observer.refused);
    try std.testing.expect(observer.freed);
    try std.testing.expect(observer.secret_zero_at_free);
    try std.testing.expectEqual(@as(u8, 0x5b), secret.toBytes()[0]);
}

const RollbackSecretAllocator = struct {
    owner: ?[*]u8 = null,
    refused: bool = false,
    freed: bool = false,
    secret_zero_at_free: bool = false,

    fn allocator(self: *RollbackSecretAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = allocate,
            .resize = std.mem.Allocator.noResize,
            .remap = std.mem.Allocator.noRemap,
            .free = freeOwner,
        } };
    }

    fn allocate(
        context: *anyopaque,
        length: usize,
        alignment: std.mem.Alignment,
        return_address: usize,
    ) ?[*]u8 {
        const self: *RollbackSecretAllocator = @ptrCast(@alignCast(context));
        if (self.owner != null) {
            self.refused = true;
            return null;
        }
        std.debug.assert(length == @sizeOf(Self));
        const owner = std.testing.allocator.rawAlloc(length, alignment, return_address) orelse
            return null;
        self.owner = owner;
        return owner;
    }

    fn freeOwner(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        return_address: usize,
    ) void {
        const self: *RollbackSecretAllocator = @ptrCast(@alignCast(context));
        std.debug.assert(memory.ptr == self.owner.?);
        std.debug.assert(memory.len == @sizeOf(Self));
        const owner: *Self = @ptrCast(@alignCast(memory.ptr));
        const bytes = owner.config.secret.toBytes();
        self.secret_zero_at_free = std.mem.allEqual(u8, &bytes, 0);
        self.freed = true;
        std.testing.allocator.rawFree(memory, alignment, return_address);
    }
};

test "node deinit wipes primary and retained relay config secrets before freeing owner" {
    // Observe the real owner before DebugAllocator can poison either copied key.
    var secret = try base_key.SecretKey.fromSeed(@splat(0x61));
    defer secret.deinit();
    var relay_secret = try base_key.SecretKey.fromSeed(@splat(0x61));
    defer relay_secret.deinit();
    const primary_bytes = secret.toBytes();
    const relay_bytes = relay_secret.toBytes();
    try std.testing.expect(&secret != &relay_secret);
    var listener = try @import("../transport/tcp_listener.zig").Listener.init(
        std.testing.io,
        .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 0 },
        .native,
    );
    defer listener.close();
    var observer: ConfigSecretAllocator = .{};
    const node = try Self.create(observer.allocator(), std.testing.io, .{
        .secret = secret,
        .relay = .{ .client = .{
            .address = listener.local,
            .host = "127.0.0.1",
            .secret = relay_secret,
            .execution = .native,
        } },
    }, 992);
    var node_live = true;
    errdefer if (node_live) node.deinit();
    try std.testing.expectEqual(@intFromPtr(node), @intFromPtr(observer.owner.?));
    try std.testing.expectEqualSlices(u8, &primary_bytes, &node.config.secret.toBytes());
    try std.testing.expectEqualSlices(u8, &relay_bytes, &node.config.relay.client.?.secret.toBytes());
    try node.close(std.testing.io, 1_000 * std.time.ns_per_s, node.generator());
    node.deinit();
    node_live = false;
    try std.testing.expect(observer.freed);
    try std.testing.expect(std.mem.allEqual(u8, &observer.primary_at_free, 0));
    try std.testing.expect(std.mem.allEqual(u8, &observer.relay_at_free, 0));
    try std.testing.expectEqualSlices(u8, &primary_bytes, &secret.toBytes());
    try std.testing.expectEqualSlices(u8, &relay_bytes, &relay_secret.toBytes());
}

test "node constructor fail-N wipes primary and retained relay config secrets before freeing owner" {
    // Sweep every allocation refusal, including failures after carrier acquisition.
    var secret = try base_key.SecretKey.fromSeed(@splat(0x63));
    defer secret.deinit();
    var relay_secret = try base_key.SecretKey.fromSeed(@splat(0x63));
    defer relay_secret.deinit();
    const primary_bytes = secret.toBytes();
    const relay_bytes = relay_secret.toBytes();
    try std.testing.expect(&secret != &relay_secret);
    var succeeded = false;
    var owned_rollbacks: usize = 0;
    var primary_wiped = true;
    var relay_wiped = true;
    for (0..128) |fail_index| {
        var listener = try @import("../transport/tcp_listener.zig").Listener.init(
            std.testing.io,
            .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 0 },
            .native,
        );
        defer listener.close();
        var observer: ConfigSecretAllocator = .{ .fail_index = fail_index };
        const node = Self.create(observer.allocator(), std.testing.io, .{
            .secret = secret,
            .relay = .{ .client = .{
                .address = listener.local,
                .host = "127.0.0.1",
                .secret = relay_secret,
                .execution = .native,
            } },
        }, 993) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expect(observer.refused);
            if (fail_index == 0) {
                try std.testing.expect(observer.owner == null);
                try std.testing.expect(!observer.freed);
            } else {
                try std.testing.expect(observer.freed);
                owned_rollbacks += 1;
                primary_wiped = primary_wiped and
                    std.mem.allEqual(u8, &observer.primary_at_free, 0);
                relay_wiped = relay_wiped and std.mem.allEqual(u8, &observer.relay_at_free, 0);
            }
            try std.testing.expectEqualSlices(u8, &primary_bytes, &secret.toBytes());
            try std.testing.expectEqualSlices(u8, &relay_bytes, &relay_secret.toBytes());
            continue;
        };
        var node_live = true;
        errdefer if (node_live) node.deinit();
        try std.testing.expect(!observer.refused);
        try std.testing.expectEqual(@intFromPtr(node), @intFromPtr(observer.owner.?));
        try node.close(std.testing.io, 1_000 * std.time.ns_per_s, node.generator());
        node.deinit();
        node_live = false;
        try std.testing.expect(observer.freed);
        try std.testing.expectEqualSlices(u8, &primary_bytes, &secret.toBytes());
        try std.testing.expectEqualSlices(u8, &relay_bytes, &relay_secret.toBytes());
        succeeded = true;
        break;
    }
    try std.testing.expect(succeeded);
    try std.testing.expect(owned_rollbacks > 1);
    try std.testing.expect(primary_wiped);
    try std.testing.expect(relay_wiped);
}

const ConfigSecretAllocator = struct {
    owner: ?[*]u8 = null,
    fail_index: usize = std.math.maxInt(usize),
    allocation_index: usize = 0,
    refused: bool = false,
    freed: bool = false,
    primary_at_free: [base_key.SecretKey.byte_length]u8 = undefined,
    relay_at_free: [base_key.SecretKey.byte_length]u8 = undefined,

    fn allocator(self: *ConfigSecretAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = allocate,
            .resize = std.mem.Allocator.noResize,
            .remap = std.mem.Allocator.noRemap,
            .free = free,
        } };
    }

    fn allocate(
        context: *anyopaque,
        length: usize,
        alignment: std.mem.Alignment,
        return_address: usize,
    ) ?[*]u8 {
        const self: *ConfigSecretAllocator = @ptrCast(@alignCast(context));
        const index = self.allocation_index;
        self.allocation_index += 1;
        if (index == self.fail_index) {
            self.refused = true;
            return null;
        }
        const memory = std.testing.allocator.rawAlloc(length, alignment, return_address) orelse
            return null;
        if (index == 0) {
            std.debug.assert(length == @sizeOf(Self));
            self.owner = memory;
        }
        return memory;
    }

    fn free(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        return_address: usize,
    ) void {
        const self: *ConfigSecretAllocator = @ptrCast(@alignCast(context));
        if (memory.ptr == self.owner) {
            std.debug.assert(memory.len == @sizeOf(Self));
            std.debug.assert(!self.freed);
            const owner: *Self = @ptrCast(@alignCast(memory.ptr));
            self.primary_at_free = owner.config.secret.toBytes();
            self.relay_at_free = owner.config.relay.client.?.secret.toBytes();
            self.freed = true;
        }
        std.testing.allocator.rawFree(memory, alignment, return_address);
    }
};
