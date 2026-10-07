//! One identity, a `ConnectionManager` it dials through, and the four steps
//! that register a client connection with it.
//!
//! Split out of `transport/dial.zig`, which is now the facade over this and
//! three other named modules. The boundary is drawn at the registration: the
//! accept loop in `quic_bridge` is what drives a connection once it exists, and
//! everything this file does is decide that one exists and hand back the same
//! borrowed handle an accepted connection arrives as. The refusal in `destroy`
//! is security-relevant and is stated there, where it is implemented.

const std = @import("std");
const quic = @import("quic");
const base_key = @import("../base/key.zig");
const base_addr = @import("../base/addr.zig");
const addr_map = @import("addr_map.zig");
const quic_bridge = @import("quic_bridge.zig");
const dial_config = @import("dial_config.zig");
const dial_route = @import("dial_route.zig");
const native_candidate_policy = @import("native_candidate_policy.zig");

const NodeId = base_key.NodeId;
const SecretKey = base_key.SecretKey;
const SocketAddr = base_addr.SocketAddr;
const TransportAddr = base_addr.TransportAddr;

const Bridge = quic_bridge.Bridge;
const Conn = quic_bridge.Conn;

const Entry = quic.connection_manager.ConnEntry;
const CidKey = quic.connection_manager.CidKey;
const Connection = quic.connection.Connection;
const ConnectionConfig = quic.connection.ConnectionConfig;
const State = quic.connection.State;
const tls13 = quic.tls13;

const Config = dial_config.Config;
const DestroyError = dial_config.DestroyError;
const Error = dial_config.Error;
const Instant = dial_config.Instant;
const default_server_name = dial_config.default_server_name;
const seed_length = dial_config.seed_length;
const spki_length = dial_config.spki_length;

const resolveRoute = dial_route.resolveRoute;
const ownerOf = dial_route.ownerOf;
const Dial = dial_route.Dial;

/// One identity, a `ConnectionManager` it dials through, and the strings its
/// configurations point at.
///
/// It owns no `std.Io`, no clock and no generator: `Instant` and `std.Random`
/// are parameters of `dial`, which is what lets the same dialer be driven
/// twice at two different instants and get two different answers. It does keep
/// the allocator, because the core's connections are freed through the
/// manager, which was created with the caller's.
///
/// Heap-allocated rather than returned by value because the TLS configuration
/// a dial hands the core points at this struct's own `spki` and `alpn_list`, and
/// a returned struct is moved into the caller's frame.
///
/// Keep the heap address stable and release it exactly once with `destroy`.
/// Copies share resources and are not independent owners. Serialize operations
/// with this dialer and its bridge. The bridge and allocator must outlive it.
/// `gpa` must be the bridge's allocator because the bridge frees dialled entries.
pub const Dialer = struct {
    gpa: std.mem.Allocator,
    /// The bridge whose manager will own the dialled connection. Borrowed: the
    /// connection is freed by `Bridge.sweep` or `Bridge.destroy`, never here.
    bridge: *Bridge,
    /// Options copied by value, including a secret-key copy erased by `destroy`.
    /// ALPN and SNI bytes must outlive this dialer and its connections. The
    /// token bytes must stay unchanged until `destroy`.
    config: Config,
    node_id: NodeId,
    /// The 32 bytes of seed the presented certificate is built from.
    seed: [seed_length]u8,
    /// The certificate: an SPKI over `node_id`, and nothing behind it.
    spki: [spki_length]u8,
    /// The one-element chain the core's config points at. It points into
    /// `spki`, which is why this struct lives on the heap.
    cert_chain: [1][]const u8,
    /// The one-element ALPN list, for the same reason.
    alpn_list: [1][]const u8,

    /// A dialer presenting `config.secret`'s node, dialling through `bridge`.
    ///
    /// No `std.Io` and no generator, and the module doc says why there is
    /// nothing for either to do. `config.alpn` and `config.server_name` are
    /// borrowed: the core's configuration holds the slices for as long as the
    /// connection lives, so they must outlive every connection this dialer
    /// opens.
    ///
    /// `config.initial_token` is also borrowed, until `destroy`. On error no
    /// dialer is returned and the bridge is unchanged.
    pub fn create(
        gpa: std.mem.Allocator,
        bridge: *Bridge,
        config: Config,
    ) Error!*Dialer {
        const self = try gpa.create(Dialer);
        errdefer gpa.destroy(self);
        self.* = .{
            .gpa = gpa,
            .bridge = bridge,
            .config = config,
            .node_id = config.secret.nodeId(),
            .seed = config.secret.toBytes()[0..seed_length].*,
            .spki = undefined,
            .cert_chain = undefined,
            .alpn_list = undefined,
        };
        self.spki = tls13.ed25519Spki(&self.node_id.toBytes());
        self.cert_chain = .{self.spki[0..]};
        self.alpn_list = .{config.alpn};
        return self;
    }

    /// Free the dialer, refusing while any client entry remains in the bridge.
    ///
    /// Both retained key copies are erased first: `config.secret` and `seed`.
    /// Handshakes borrow the seed, so a live client entry prevents erasure.
    ///
    /// A refusal leaves the dialer usable. Finish and sweep client connections
    /// before retrying, while the bridge is still alive. A successful call
    /// invalidates this pointer and every borrowed TLS configuration.
    pub fn destroy(self: *Dialer) DestroyError!void {
        // TLS configurations borrow dialer storage. Without an owner index,
        // refusing every client entry prevents release while one may borrow it.
        for (self.bridge.manager.entries.items) |entry| {
            if (!entry.conn.is_server) return error.DialedConnectionsLive;
        }
        std.crypto.secureZero(u8, self.seed[0..]);
        self.config.secret.deinit();
        self.gpa.destroy(self);
    }

    /// The node id this dialer presents as a bare `SubjectPublicKeyInfo`.
    pub fn nodeId(self: *const Dialer) NodeId {
        return self.node_id;
    }

    /// The TLS configuration a dial pinning `expect_peer` hands the core.
    ///
    /// Exposed because it is the translation, and a translation nobody can
    /// read is a translation nobody can check. It is a function of the pin
    /// rather than a value because `connectInto` copies it into the handshake
    /// and the handshake keeps that copy: one value per dialer could not say
    /// what a given dial used.
    ///
    /// The result borrows this dialer's identity and configuration storage.
    /// It is valid only while the dialer and its borrowed inputs remain alive.
    /// Import the registered `quic` module to name the result type.
    pub fn tlsConfigFor(self: *const Dialer, expect_peer: ?NodeId) quic.tls13.TlsConfig {
        return .{
            // Two required fields the core's struct has no default for, and
            // both server-only. A client presents nothing here; the identity it
            // offers is `client_certificate` below. They are read on the
            // server's path only, so an empty pair is what "not a server" is.
            .cert_chain_der = &.{},
            .private_key_bytes = &.{},
            .private_key_algorithm = .ed25519,
            .alpn = &self.alpn_list,
            // Read and then overwritten: `connectInto` copies this config and
            // assigns `server_name` from its own argument (`connection.zig:4667`).
            // Set anyway, so the value a caller reads back here is the value the
            // caller asked for rather than a null beside it.
            .server_name = self.config.server_name,
            .client_certificate = .{
                .cert_chain_der = &self.cert_chain,
                .private_key_bytes = self.seed[0..],
                .private_key_algorithm = .ed25519,
            },
            // The pin, and the only field a client handshake reads
            // (`tls13.zig:1465`). Null accepts any key, and then the peer has
            // proved possession of the id it presented rather than being the
            // node the caller asked for.
            .expect_peer_node_id = if (expect_peer) |peer| peer.toBytes() else null,
            // Server only, and left null for the same reason `quic_bridge.zig`
            // leaves `expect_peer_node_id` null on the accept side: setting the
            // field that looks like a second pin and enforces nothing is worse
            // than not having it. See that file's finding 4.
            .client_auth = null,
        };
    }

    /// Open a connection to `expect_peer` over `transport`.
    ///
    /// `expect_peer` is both the pin and the key the address is allocated
    /// under, which is not a coincidence: on a dial the node you are dialling
    /// and the node whose key you must present are the same fact. `local` is
    /// the address the caller's socket is bound to and the peer will see; only
    /// the caller knows it, which is one of the reasons the socket is the
    /// caller's.
    ///
    /// `at` and `random` are the caller's, for the module doc's reason. The
    /// returned `Dial` carries a connection the bridge drives, and the caller
    /// has to have a socket open for `dial.route.socket` before draining it.
    ///
    /// On error no new connection remains registered. A resolved synthetic
    /// mapping and manager capacity may remain, and random draws are consumed.
    /// The returned handle borrows the bridge and is invalid after its sweep
    /// frees the connection. No caller teardown is required for the handle.
    pub fn dial(
        self: *Dialer,
        transport: TransportAddr,
        expect_peer: ?NodeId,
        local: SocketAddr,
        map: *addr_map.MappedAddrs,
        at: Instant,
        random: std.Random,
    ) Error!Dial {
        // Before the map is touched, so a refused dial leaves no trace: no
        // host bits drawn, no entry allocated, nothing in the manager.
        if (expect_peer == null and self.config.require_peer_pin) return error.NoPeerPin;
        const route = try resolveRoute(self.gpa, map, transport, expect_peer, random);
        const conn = try self.open(route.socket, local, self.tlsConfigFor(expect_peer), at, random);
        return .{ .conn = conn, .route = route };
    }

    /// Build a client connection and register it with the manager, and hand back
    /// a `Conn` — the same handle an accepted connection arrives as.
    ///
    /// The four steps are `acceptConnection`'s, in the same order, with
    /// `connectInto` in place of `acceptInto`.
    fn open(
        self: *Dialer,
        peer_addr: SocketAddr,
        local: SocketAddr,
        tls: quic.tls13.TlsConfig,
        at: Instant,
        random: std.Random,
    ) Error!Conn {
        const manager = &self.bridge.manager;
        if (manager.entries.items.len >= manager.max_connections) {
            return error.TooManyConnections;
        }
        // The same two reservations `acceptConnection` makes, for the same
        // reason: the `appendAssumeCapacity` below and the `dead_entries`
        // append in `removeConnection` both have to be unable to fail, or a
        // connection taken out of the table mid-cycle would have to be freed
        // early — while a caller still holds a handle to it.
        try manager.entries.ensureUnusedCapacity(self.gpa, 1);
        try manager.dead_entries.ensureTotalCapacity(
            self.gpa,
            manager.entries.items.len + manager.dead_entries.items.len + 1,
        );

        const conn = try self.gpa.create(Connection);
        // A failed `connectInto` leaves nothing to release: the core's own
        // `acceptConnection` destroys the raw connection on the same failure
        // and only `deinit`s it once construction has returned. Mirroring that
        // is deliberate — a half-built connection's teardown is the core's
        // business, not ours.
        errdefer self.gpa.destroy(conn);
        quic.connection.connectInto(
            conn,
            self.gpa,
            self.config.server_name,
            connectionConfig(self.config),
            tls,
            self.config.initial_token,
            at,
            random,
        ) catch |err| {
            // The core carries no named set here, so the one arm this project
            // can act on is named and the rest is logged before it is refused,
            // exactly as `Conn.drain` does for a packet it cannot build.
            if (err == error.OutOfMemory) return error.OutOfMemory;
            std.log.warn("dial: the core refused to open a connection: {t}", .{err});
            return error.CoreRefused;
        };
        errdefer conn.deinit();

        // What the first flight is sent to, and nothing more: the core builds
        // its path from the first datagram it receives (`connection.zig:1533`),
        // so these are read once by `Conn.drain` and then rewritten. They are
        // written at all because a `NetworkPath` starts `unset`, and `drain`
        // would refuse the first datagram it was ever asked for.
        conn.paths[0].peer_addr = toCoreAddress(peer_addr);
        conn.paths[0].local_addr = toCoreAddress(local);

        const entry = try self.gpa.create(Entry);
        errdefer self.gpa.destroy(entry);
        entry.* = .{ .conn = conn, .id = manager.next_entry_id };
        manager.next_entry_id += 1;

        // One CID, not two — see the module doc. It goes in before the append,
        // so the only fallible steps left are the two the table itself owns.
        const scid = CidKey.fromSlice(conn.scid[0..conn.scid_len]);
        try manager.cid_map.put(scid, entry);
        errdefer _ = manager.cid_map.remove(scid);
        try noteCid(entry, scid);

        manager.entries.appendAssumeCapacity(entry);
        return .{ .entry = entry };
    }
};

/// The core's connection configuration for a dial.
///
/// One field differs from `quic_bridge.zig`'s and it is the whole of it:
/// `token_key` is the secret NEW_TOKENs are signed with, it is read on the
/// server only, and a dial has no NEW_TOKEN to sign. The token a dial
/// *presents* is `Config.initial_token`, and `connectInto` copies it into the
/// connection's own buffer, so the caller's slice is not retained.
fn connectionConfig(config: Config) ConnectionConfig {
    return .{
        .max_idle_timeout = config.idle_timeout_ms,
        .address_discovery_role = config.address_discovery_role,
        .max_remote_nat_traversal_addresses = config.max_remote_nat_traversal_addresses,
        .initial_max_path_id = config.initial_max_path_id,
        .candidateAdmission = native_candidate_policy.admit,
        .supportedIPv6 = config.ipv6_supported,
    };
}

/// Record `key` on `entry` so `removeConnection` takes it back out of the
/// routing map.
///
/// `ConnEntry.addRegisteredCid` (`connection_manager.zig:101`) is these two
/// lines and is not `pub`. Writing them out is not a style point:
/// `removeConnection` unregisters only the keys in this array
/// (`connection_manager.zig:441`), so a key put into `cid_map` and not recorded
/// here outlives the entry and routes later datagrams to freed memory. Later
/// CIDs the core issues are recorded by the core's own `syncCids`, which
/// `route` calls after every datagram.
fn noteCid(entry: *Entry, key: CidKey) Error!void {
    if (entry.registered_cid_count == entry.registered_cids.len) return error.CidPoolFull;
    entry.registered_cids[entry.registered_cid_count] = key;
    entry.registered_cid_count += 1;
}

/// This project's address as the core's own.
///
/// `quic_bridge.zig` has the same conversion for both directions and does not
/// export it, so this is a second copy of one `switch` — the smallest
/// duplication in the file, and it is here because a dial writes a path
/// directly and the bridge's copy is not part of its own surface.
fn toCoreAddress(socket: SocketAddr) quic.address.Address {
    return switch (socket.ip) {
        .v4 => |octets| quic.address.Address.initIpv4(octets, socket.port),
        // The scope is zero because `SocketAddr` carries none; see
        // `quic_bridge.toCoreAddress` for why that is the only honest value.
        .v6 => |octets| quic.address.Address.initIpv6(octets, socket.port, 0),
    };
}

const t = std.testing;

// The pair of ends a dial is closed against, named here so the tests below
// stand as they were written.
const base_ula = @import("../base/ula.zig");
const Egress = quic_bridge.Egress;

const pair_mod = @import("dial_pair.zig");
const client_seed = pair_mod.client_seed;
const server_seed = pair_mod.server_seed;
const client_addr = pair_mod.client_addr;
const direct_addr = pair_mod.direct_addr;
const stranger_seed = pair_mod.stranger_seed;
const alpn = pair_mod.alpn;
const start = pair_mod.start;
const Prng = pair_mod.Prng;
const max_datagram = pair_mod.max_datagram;
const max_egress = pair_mod.max_egress;
const relayTarget = pair_mod.relayTarget;
const Pair = pair_mod.Pair;
const StateLog = pair_mod.StateLog;
const exchange = pair_mod.exchange;

test "dial factory enables pure native candidate policy by default" {
    var secret = try SecretKey.fromSeed(@splat(42));
    defer secret.deinit();
    const core = connectionConfig(.{ .secret = secret, .alpn = alpn });
    try t.expect(core.supportedIPv6);
    const admit = core.candidateAdmission orelse return error.TestUnexpectedResult;
    try t.expect(admit(quic.address.Address.initIpv4(.{ 192, 0, 2, 1 }, 443)));
    try t.expect(!admit(toCoreAddress(base_ula.socketAddrFor(.any_path, @splat(1)))));
}

test "native transport options reach peers through the bridge and dial handshake" {
    // Peer parameters are decoded from TLS flights, not copied from either config.
    // Cover absence, mutual negotiation, and a peer that declines the extensions.
    for ([_]struct { server: bool, client: bool, ipv6: bool = false }{
        .{ .server = false, .client = false },
        .{ .server = true, .client = true },
        .{ .server = true, .client = true, .ipv6 = true },
        .{ .server = true, .client = false },
        .{ .server = false, .client = true },
    }) |enabled| {
        var pair: Pair = undefined;
        {
            const secret = try SecretKey.fromSeed(client_seed);
            errdefer {
                var failed_secret = secret;
                failed_secret.deinit();
            }
            pair = .{
                .dialer_secret = secret,
                .server_secret = try SecretKey.fromSeed(server_seed),
                .dialer_bridge = undefined,
                .server_bridge = undefined,
                .dialer = undefined,
                .map = addr_map.MappedAddrs.init(),
                .engine = Prng.init(891),
            };
            errdefer pair.server_secret.deinit();
            errdefer pair.map.deinit(t.allocator);
            pair.dialer_bridge = try Bridge.create(t.allocator, t.io, .{
                .secret = pair.dialer_secret,
                .alpn = alpn,
            }, pair.engine.random());
            errdefer pair.dialer_bridge.destroy();
            var server_config: quic_bridge.Config = .{
                .secret = pair.server_secret,
                .expect_peer = pair.dialer_secret.nodeId(),
                .alpn = alpn,
                .ipv6_supported = enabled.ipv6,
            };
            if (enabled.server) {
                server_config.address_discovery_role = .send_only;
                server_config.max_remote_nat_traversal_addresses = 32;
                server_config.initial_max_path_id = 1;
            }
            pair.server_bridge = try Bridge.create(
                t.allocator, t.io, server_config, pair.engine.random(),
            );
            errdefer pair.server_bridge.destroy();
            var client_config: Config = .{
                .secret = pair.dialer_secret,
                .alpn = alpn,
                .ipv6_supported = enabled.ipv6,
            };
            if (enabled.client) {
                client_config.address_discovery_role = .receive_only;
                client_config.max_remote_nat_traversal_addresses = 7;
                client_config.initial_max_path_id = 1;
            }
            pair.dialer = try Dialer.create(t.allocator, pair.dialer_bridge, client_config);
        }
        defer pair.deinit();
        const dial = try pair.dialer.dial(
            if (enabled.server and enabled.client) try relayTarget() else .{ .ip = direct_addr },
            pair.server_secret.nodeId(),
            client_addr,
            &pair.map,
            start,
            pair.engine.random(),
        );
        var log: StateLog = .{};
        try exchange(
            pair.dialer, dial.conn, pair.server_bridge, &pair.map,
            &log, start, pair.engine.random(),
        );
        const accepted = pair.server_bridge.connectionAt(0) orelse
            return error.TestUnexpectedResult;
        const client = dial.conn.entry.conn;
        const server = accepted.entry.conn;
        try t.expectEqual(State.connected, client.state);
        try t.expectEqual(State.connected, server.state);
        try t.expectEqual(enabled.ipv6, client.supportedIPv6);
        try t.expectEqual(enabled.ipv6, server.supportedIPv6);
        const client_peer = client.peer_params orelse return error.TestUnexpectedResult;
        const server_peer = server.peer_params orelse return error.TestUnexpectedResult;
        try t.expectEqual(
            @as(quic.observed_address.Role, if (enabled.server) .send_only else .disabled),
            client_peer.address_discovery_role,
        );
        try t.expectEqual(
            @as(quic.observed_address.Role, if (enabled.client) .receive_only else .disabled),
            server_peer.address_discovery_role,
        );
        try t.expectEqual(
            @as(?u8, if (enabled.server) 32 else null),
            client_peer.max_remote_nat_traversal_addresses,
        );
        try t.expectEqual(
            @as(?u8, if (enabled.client) 7 else null),
            server_peer.max_remote_nat_traversal_addresses,
        );
        try t.expectEqual(
            @as(?u32, if (enabled.server) 1 else null),
            client_peer.initial_max_path_id,
        );
        try t.expectEqual(
            @as(?u32, if (enabled.client) 1 else null),
            server_peer.initial_max_path_id,
        );
        try t.expectEqual(enabled.server and enabled.client, client.multipathNegotiated());
        try t.expectEqual(enabled.server and enabled.client, server.multipathNegotiated());
        try t.expectEqual(enabled.server and enabled.client, client.nat_state != null);
        try t.expectEqual(enabled.server and enabled.client, server.nat_state != null);
        if (enabled.server and enabled.client) {
            // A virtual path0 still completes TLS. Only NAT candidates are filtered.
            try t.expect(base_ula.classify(dial.conn.peer().?) != .ip);
            var candidates: [32]quic.address.Address = undefined;
            var packet_bytes: [max_datagram]u8 = undefined;
            for ([_]base_ula.Path{ .any_path, .relay, .custom }) |path| {
                const virtual = toCoreAddress(base_ula.socketAddrFor(path, @splat(9)));
                const reach: quic.frame.Frame = .{
                    .reach_address = .{ .round = 1, .address = virtual },
                };
                const add: quic.frame.Frame = .{
                    .add_address = .{ .sequence = 0, .address = virtual },
                };
                try server.processFrame(&reach, .application, start, pair.engine.random());
                try client.processFrame(&add, .application, start, pair.engine.random());
                try server.addNatTraversalAddress(virtual);
                try client.addNatTraversalAddress(virtual);
                try t.expectEqual(@as(u8, 0), server.nat_state.?.local_count);
                try t.expectEqual(@as(u8, 0), client.nat_state.?.local_count);
                try t.expectEqual(@as(usize, 0), server.remoteTraversalCandidates(&candidates).len);
                try t.expectEqual(@as(usize, 0), client.remoteTraversalCandidates(&candidates).len);
                const pn = server.pkt_handler.next_pn[2];
                try t.expectEqual(@as(usize, 0), try server.sendAt(
                    &packet_bytes, start, pair.engine.random(),
                ));
                try t.expectEqual(pn, server.pkt_handler.next_pn[2]);
                const client_pn = client.pkt_handler.next_pn[2];
                try t.expectEqual(@as(usize, 0), try client.sendAt(
                    &packet_bytes, start, pair.engine.random(),
                ));
                try t.expectEqual(client_pn, client.pkt_handler.next_pn[2]);
            }
            const physical_v6 = quic.address.Address.initIpv6(
                .{ 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
                4040, 0,
            );
            const v6_reach: quic.frame.Frame = .{
                .reach_address = .{ .round = 1, .address = physical_v6 },
            };
            try server.processFrame(&v6_reach, .application, start, pair.engine.random());
            const v6_add: quic.frame.Frame = .{
                .add_address = .{ .sequence = 0, .address = physical_v6 },
            };
            try client.processFrame(&v6_add, .application, start, pair.engine.random());
            try t.expectEqual(
                @as(usize, if (enabled.ipv6) 1 else 0),
                client.remoteTraversalCandidates(&candidates).len,
            );
            const pn = server.pkt_handler.next_pn[2];
            const v6_sent = try server.sendAt(&packet_bytes, start, pair.engine.random());
            if (enabled.ipv6) {
                try t.expect(v6_sent > 0);
                try t.expect(server.last_send_peer.eql(physical_v6));
                try t.expect(server.pkt_handler.next_pn[2] > pn);
            } else {
                try t.expectEqual(@as(usize, 0), v6_sent);
                try t.expectEqual(pn, server.pkt_handler.next_pn[2]);
                try t.expectEqual(@as(usize, 0), server.remoteTraversalCandidates(&candidates).len);
            }
            const physical = quic.address.Address.initIpv4(.{ 192, 0, 2, 11 }, 4040);
            const reach: quic.frame.Frame = .{
                .reach_address = .{ .round = 1, .address = physical },
            };
            try server.processFrame(&reach, .application, start, pair.engine.random());
            try t.expect((try server.sendAt(&packet_bytes, start, pair.engine.random())) > 0);
            try t.expect(server.last_send_peer.eql(physical));
            try t.expect(server.peerAddress().eql(toCoreAddress(client_addr)));
            const add: quic.frame.Frame = .{
                .add_address = .{ .sequence = 1, .address = physical },
            };
            try client.processFrame(&add, .application, start, pair.engine.random());
            try client.addNatTraversalAddress(
                quic.address.Address.initIpv4(.{ 192, 0, 2, 12 }, 5050),
            );
            try client.initiateNatTraversalRound(start, pair.engine.random());
            try t.expect((try client.sendAt(&packet_bytes, start, pair.engine.random())) > 0);
            try t.expect(client.last_send_peer.eql(if (enabled.ipv6) physical_v6 else physical));
            try t.expect(client.peerAddress().eql(toCoreAddress(dial.route.socket)));
        }
    }
}

test "the configuration the core is handed is this node's SPKI and the peer's pin" {
    var pair: Pair = undefined;
    try pair.init(client_seed, server_seed, null, 9, true);
    defer pair.deinit();
    const peer = pair.server_secret.nodeId();
    const tls = pair.dialer.tlsConfigFor(peer);

    // Server-only fields the core's struct has no default for. A client
    // presents nothing in either, and the whole of this node's identity is
    // below in `client_certificate`.
    try t.expectEqual(@as(usize, 0), tls.cert_chain_der.len);
    try t.expectEqual(@as(usize, 0), tls.private_key_bytes.len);
    // No `certs`, so no server ever calls `selectCertificateFor` and no SNI
    // selects anything on this stack. See the module doc on `server_name`.
    try t.expectEqual(@as(usize, 0), tls.certs.len);
    try t.expectEqual(@as(?*const tls13.ClientAuth, null), tls.client_auth);
    try t.expectEqualStrings(default_server_name, tls.server_name.?);
    try t.expectEqual(@as(usize, 1), tls.alpn.len);
    try t.expectEqualStrings(alpn, tls.alpn[0]);

    // The certificate, presented, is a bare SPKI over our own id — and it is
    // the same 44 bytes the server side builds, read back from the other end
    // of the handshake below.
    try t.expectEqual(@as(usize, 1), tls.client_certificate.?.cert_chain_der.len);
    try t.expectEqual(spki_length, tls.client_certificate.?.cert_chain_der[0].len);
    try t.expectEqualSlices(
        u8,
        &tls13.ed25519Spki(&pair.dialer_secret.nodeId().toBytes()),
        tls.client_certificate.?.cert_chain_der[0],
    );
    try t.expectEqual(
        tls13.PrivateKeyAlgorithm.ed25519,
        tls.client_certificate.?.private_key_algorithm,
    );
    const seed = pair.dialer_secret.toBytes();
    try t.expectEqualSlices(
        u8,
        seed[0..seed_length],
        tls.client_certificate.?.private_key_bytes,
    );

    // The pin: byte for byte, and the mirror image of what the bridge sets on
    // the server side.
    try t.expectEqual(peer.toBytes(), tls.expect_peer_node_id.?);
}

test "the SNI the core was actually given is the caller's name, not the config's" {
    var pair: Pair = undefined;
    try pair.init(client_seed, server_seed, null, 11, true);
    defer pair.deinit();
    var engine = Prng.init(12);
    const dial = try pair.dialer.dial(
        try relayTarget(),
        pair.server_secret.nodeId(),
        client_addr,
        &pair.map,
        start,
        engine.random(),
    );

    // `connectInto` copies the config it is handed and assigns `server_name`
    // from its own argument, so the value inside the handshake is the one the
    // caller passed positionally. The field in `tlsConfigFor` is a readable
    // mirror of it and nothing more, and this is the test that says so.
    const handshake = dial.conn.entry.conn.tls13_hs orelse return error.TestUnexpectedResult;
    const given = handshake.config;
    try t.expectEqualStrings(default_server_name, given.server_name.?);
    try t.expectEqual(
        pair.server_secret.nodeId().toBytes(),
        given.expect_peer_node_id.?,
    );
}

test "a dial with no pin is refused, and refuses before it allocates anything" {
    var pair: Pair = undefined;
    try pair.init(client_seed, server_seed, null, 13, true);
    defer pair.deinit();
    var engine = Prng.init(14);

    try t.expectError(
        error.NoPeerPin,
        pair.dialer.dial(
            try relayTarget(),
            null,
            client_addr,
            &pair.map,
            start,
            engine.random(),
        ),
    );
    // Nothing drawn, nothing allocated, nothing in the table: the refusal is
    // the first thing `dial` does, and this is the proof it stayed there.
    try t.expectEqual(@as(usize, 0), pair.map.by_key.count());
    try t.expectEqual(@as(usize, 0), pair.dialer_bridge.manager.connectionCount());
}

test "an unpinned dial is reachable only by naming it, and only on a direct path" {
    var pair: Pair = undefined;
    try pair.init(client_seed, server_seed, null, 15, false);
    defer pair.deinit();
    var engine = Prng.init(16);

    // The pin is clearable, and the answer is a value the caller can read
    // back: no connection can be built that nobody can see is unpinned.
    try t.expectEqual(
        @as(?[32]u8, null),
        pair.dialer.tlsConfigFor(null).expect_peer_node_id,
    );
    // A synthetic subnet is keyed on the peer's id, so there is no key to
    // allocate an address from and the shape refuses before anything else can.
    try t.expectError(
        error.NoPeerId,
        pair.dialer.dial(try relayTarget(), null, client_addr, &pair.map, start, engine.random()),
    );

    // A direct path needs no key, so this is the one target an unpinned dial
    // can name — and it opened, with the pin visibly absent.
    const dial = try pair.dialer.dial(
        .{ .ip = direct_addr },
        null,
        client_addr,
        &pair.map,
        start,
        engine.random(),
    );
    try t.expectEqual(direct_addr, dial.route.socket);
    try t.expectEqual(
        @as(?[32]u8, null),
        dial.conn.entry.conn.tls13_hs.?.config.expect_peer_node_id,
    );
    try t.expectEqual(@as(usize, 1), pair.dialer_bridge.manager.connectionCount());
}

test "a dial runs initiated to connected as a function of datagrams and nothing else" {
    var pair: Pair = undefined;
    try pair.init(client_seed, server_seed, null, 17, true);
    defer pair.deinit();
    var engine = Prng.init(18);

    const dial = try pair.dialer.dial(
        try relayTarget(),
        pair.server_secret.nodeId(),
        client_addr,
        &pair.map,
        start,
        engine.random(),
    );

    // Before any event: initiated, and the address it was opened at is the one
    // `resolveRoute` produced.
    try t.expectEqual(State.first_flight, dial.conn.entry.conn.state);
    try t.expect(!dial.conn.established());
    try t.expectEqual(dial.route.socket, dial.conn.peer().?);
    try t.expectEqual(client_addr, dial.conn.local().?);

    // The core keeps two paths and indexes one as active. One target, one
    // address, one path — the ceiling the module doc names.
    try t.expectEqual(@as(usize, 2), dial.conn.entry.conn.paths.len);
    try t.expectEqual(@as(u8, 0), dial.conn.entry.conn.active_path_idx);

    var log: StateLog = .{};
    try exchange(
        pair.dialer,
        dial.conn,
        pair.server_bridge,
        &pair.map,
        &log,
        start,
        engine.random(),
    );

    // The state machine, as a function of the datagrams that arrived: the
    // first server Initial moves it off `first_flight`, and the handshake
    // finishes it. Both transitions happened without a socket and without any
    // call reading a clock.
    // The trace is the assertion. It is `first_flight` and then `connected`,
    // and *nothing in between at a datagram boundary*: the core sets
    // `.handshake` on the first Initial (`connection.zig:1561`) and clears it
    // to `.connected` on the same datagram's later packets
    // (`connection.zig:2559`), coalesced into one `recv`. A dialler therefore
    // watches a connection go from initiated to connected with no observable
    // middle, which is the answer to what a caller has to drive: two states,
    // and `tick` in between.
    try t.expect(log.count > 0);
    try t.expectEqual(State.first_flight, log.states[0]);
    try t.expect(log.saw(.connected));
    for (log.states[0..log.count]) |seen| {
        try t.expect(seen == .first_flight or seen == .connected);
    }
    try t.expect(dial.conn.established());

    // The same manager, the same entry table, the same drain. The dialled
    // connection is found by the bridge's own index walk — there is no second
    // table for it to be in.
    try t.expectEqual(@as(usize, 1), pair.dialer_bridge.manager.connectionCount());
    const found = pair.dialer_bridge.connectionAt(0) orelse return error.TestUnexpectedResult;
    try t.expectEqual(dial.conn.id(), found.id());

    // What the core was told, and what it learned. The synthetic address
    // survived the trip into the core's own representation and `classify`
    // still names the peer's any-path subnet: the core does not validate a peer's
    // address, and a client is not even subject to the anti-amplification
    // limit.
    try t.expectEqual(dial.route.socket, dial.conn.peer().?);
    try t.expectEqual(
        base_ula.Classification{ .any_path = dial.route.socket.ip.v6 },
        base_ula.classify(dial.conn.peer().?),
    );
    try t.expectEqual(dial.route.key.?, ownerOf(&pair.map, dial.conn.peer().?).?);

    // The peer's identity, and the shape it has on a dial. `clientProcessCertificate`
    // lifts the 32 bytes out of the peer's `SubjectPublicKeyInfo`, compares
    // them with the pin and keeps only the key (`tls13.zig:1463`) — the server
    // arm of the same function is the one that keeps a copy
    // (`tls13.zig:2091`). So a dialler's connection names its peer by node id
    // and cannot hand the raw certificate back, which is worth knowing before
    // anything asks it to.
    try t.expectEqual(
        pair.server_secret.nodeId().toBytes(),
        dial.conn.entry.conn.tls13_hs.?.peerNodeId().?,
    );
    try t.expectEqual(
        @as(?[]const u8, null),
        dial.conn.entry.conn.peerCertificate(),
    );
    try t.expectEqualStrings(alpn, dial.conn.entry.conn.negotiatedAlpn());

    // And the server saw the same SPKI we presented, as the mirror image of
    // the pin it enforces: two bridges, one handshake, no second loop. A
    // server does keep the copy, so the whole 44 bytes are readable here.
    const accepted = pair.server_bridge.connectionAt(0) orelse return error.TestUnexpectedResult;
    try t.expect(accepted.established());
    try t.expectEqualSlices(
        u8,
        &tls13.ed25519Spki(&pair.dialer_secret.nodeId().toBytes()),
        accepted.entry.conn.peerCertificate().?,
    );
    try t.expectEqual(
        pair.dialer_secret.nodeId().toBytes(),
        accepted.entry.conn.clientAuth().?.expect_node_id.?,
    );
    try t.expectEqual(@as(usize, 1), pair.server_bridge.manager.connectionCount());
}

test "the pin is a comparison against the peer's own id, and it is per dial" {
    var pair: Pair = undefined;
    try pair.init(client_seed, server_seed, null, 19, true);
    defer pair.deinit();
    const peer = pair.server_secret.nodeId();
    var engine = Prng.init(20);

    // The two sides of the comparison, read back off a connection that used
    // it: the pin the core was handed and the id it lifted out of the peer's
    // `SubjectPublicKeyInfo` (`tls13.zig:1465` compares exactly these two).
    const dial = try pair.dialer.dial(
        try relayTarget(),
        peer,
        client_addr,
        &pair.map,
        start,
        engine.random(),
    );
    try t.expectEqual(
        peer.toBytes(),
        dial.conn.entry.conn.tls13_hs.?.config.expect_peer_node_id.?,
    );
    var log: StateLog = .{};
    try exchange(
        pair.dialer,
        dial.conn,
        pair.server_bridge,
        &pair.map,
        &log,
        start,
        engine.random(),
    );
    try t.expectEqual(peer.toBytes(), dial.conn.entry.conn.tls13_hs.?.peerNodeId().?);

    // The pin belongs to the dial, not to the dialer: a second dial from the
    // same identity names a different peer and carries a different pin, and a
    // config-wide pin would be whichever peer was named last.
    var stranger = try SecretKey.fromSeed(stranger_seed);
    defer stranger.deinit();
    const other = try pair.dialer.dial(
        .{ .ip = direct_addr },
        stranger.nodeId(),
        client_addr,
        &pair.map,
        start,
        engine.random(),
    );
    try t.expectEqual(
        stranger.nodeId().toBytes(),
        other.conn.entry.conn.tls13_hs.?.config.expect_peer_node_id.?,
    );
    try t.expect(other.conn.entry.conn.tls13_hs.?.peerNodeId() == null);
    // Neither dial changed the other's pin, and the first connection still
    // holds the one it was opened with.
    try t.expectEqual(
        peer.toBytes(),
        dial.conn.entry.conn.tls13_hs.?.config.expect_peer_node_id.?,
    );
}

test "two targets to one peer are two connections, because the core has one path" {
    var pair: Pair = undefined;
    try pair.init(client_seed, server_seed, null, 21, true);
    defer pair.deinit();
    const peer = pair.server_secret.nodeId();
    var engine = Prng.init(22);

    const over_relay = try pair.dialer.dial(
        try relayTarget(),
        peer,
        client_addr,
        &pair.map,
        start,
        engine.random(),
    );
    const over_ip = try pair.dialer.dial(
        .{ .ip = direct_addr },
        peer,
        client_addr,
        &pair.map,
        start,
        engine.random(),
    );

    // The multipath cost `DECISIONS/0001` records, as the core sees it: a
    // datagram from the second address on one connection would be a migration
    // challenge (`connection.zig:1541`), not a second path, so a peer with
    // two addresses is two connections and the caller owns the policy that
    // says which one to use.
    try t.expectEqual(@as(usize, 2), pair.dialer_bridge.manager.connectionCount());
    try t.expect(over_relay.conn.id() != over_ip.conn.id());
    try t.expectEqual(over_relay.route.socket, over_relay.conn.peer().?);
    try t.expectEqual(over_ip.route.socket, over_ip.conn.peer().?);
    // One address each, and both are what the core was told: the relay one in
    // the peer's any-path subnet, the direct one untouched.
    try t.expectEqual(base_ula.Path.any_path, over_relay.route.subnet.?);
    try t.expectEqual(@as(?base_ula.Path, null), over_ip.route.subnet);
    try t.expectEqual(
        base_ula.Classification{ .ip = direct_addr },
        base_ula.classify(over_ip.conn.peer().?),
    );
    // Two entries, and each carries exactly the one CID it is addressed by.
    try t.expectEqual(
        @as(u8, 1),
        pair.dialer_bridge.manager.entries.items[0].registered_cid_count,
    );
    try t.expectEqual(
        @as(u8, 1),
        pair.dialer_bridge.manager.entries.items[1].registered_cid_count,
    );
    // The dialler refuses to go while either is live, because their handshakes
    // point at its seed.
    try t.expectError(error.DialedConnectionsLive, pair.dialer.destroy());
}

test "the caller's instant reaches the core, and nothing is stored" {
    var pair: Pair = undefined;
    try pair.init(client_seed, server_seed, null, 23, true);
    defer pair.deinit();
    const peer = pair.server_secret.nodeId();
    var first_engine = Prng.init(24);
    var second_engine = Prng.init(25);

    // Two dials from one dialer at two instants and two generators. Nothing
    // here reads a clock or draws entropy: the answers differ because the
    // arguments did, which is the only way a test can tell a threaded instant
    // from a stored one.
    const later: Instant = start + 30 * std.time.ns_per_s;
    const first = try pair.dialer.dial(
        try relayTarget(),
        peer,
        client_addr,
        &pair.map,
        start,
        first_engine.random(),
    );
    const second = try pair.dialer.dial(
        try relayTarget(),
        peer,
        client_addr,
        &pair.map,
        later,
        second_engine.random(),
    );

    try t.expectEqual(start, first.conn.entry.conn.creation_time);
    try t.expectEqual(later, second.conn.entry.conn.creation_time);
    // Same relay target, so the same address: the map is a value the caller
    // owns and it is the only state the dialler keeps.
    try t.expectEqual(first.route.socket, second.route.socket);
    // Different generators, so different connection ids: the caller kept the
    // engines, and a dialler that had stored one would have produced the same
    // CID twice.
    try t.expect(!std.mem.eql(
        u8,
        first.conn.entry.conn.scid[0..first.conn.entry.conn.scid_len],
        second.conn.entry.conn.scid[0..second.conn.entry.conn.scid_len],
    ));
}

test "a dial with a NEW_TOKEN presents it in the first Initial" {
    var pair: Pair = undefined;
    try pair.init(client_seed, server_seed, null, 27, true);
    defer pair.deinit();
    var engine = Prng.init(28);

    const token: [16]u8 = @splat(0x5a);
    pair.dialer.config.initial_token = token[0..];
    const dial = try pair.dialer.dial(
        try relayTarget(),
        pair.server_secret.nodeId(),
        client_addr,
        &pair.map,
        start,
        engine.random(),
    );

    // `connectInto` copies the token into the connection's own buffer, so the
    // caller's slice is not retained: the connection owns the bytes from here.
    try t.expectEqual(token.len, dial.conn.entry.conn.retry_token_len);
    try t.expectEqualSlices(
        u8,
        &token,
        dial.conn.entry.conn.retry_token_buf[0..dial.conn.entry.conn.retry_token_len],
    );
    // And the core put it in the first flight, which is the only place a
    // NEW_TOKEN is ever carried.
    var egress: [max_egress]Egress = undefined;
    var out: [max_egress * max_datagram]u8 = undefined;
    try t.expect((try dial.conn.drain(egress[0..], out[0..], start, engine.random())).len > 0);
}

test "destroy wipes every retained secret copy before releasing its storage" {
    const alignment = @max(@alignOf(Bridge), @alignOf(Dialer));
    var backing: [@sizeOf(Bridge) + @sizeOf(Dialer) + alignment]u8 align(alignment) = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&backing);
    const alloc = fixed.allocator();
    var secret = try SecretKey.fromSeed(client_seed);
    defer secret.deinit();
    var engine = Prng.init(81);
    const bridge = try Bridge.create(alloc, t.io, .{
        .secret = secret,
        .alpn = alpn,
        .retry_token_key = @splat(0x12),
        .static_reset_key = @splat(0x34),
    }, engine.random());
    defer bridge.destroy();
    const dialer = try Dialer.create(alloc, bridge, .{ .secret = secret, .alpn = alpn });
    const secret_start = @intFromPtr(&dialer.config.secret) - @intFromPtr(&backing);
    const seed_start = @intFromPtr(&dialer.seed) - @intFromPtr(&backing);
    try dialer.destroy();

    // The allocator releases objects, not the caller-owned backing array.
    const erased_secret: [@sizeOf(SecretKey)]u8 = @splat(0);
    const erased_seed: [seed_length]u8 = @splat(0);
    try t.expectEqualSlices(u8, &erased_secret, backing[secret_start..][0..erased_secret.len]);
    try t.expectEqualSlices(u8, &erased_seed, backing[seed_start..][0..erased_seed.len]);
}
