//! One vendored `ConnectionManager` and the identity it presents: the accept
//! side's whole turn surface — create, recv, tick, sweep, destroy — and the two
//! behaviours that are security rather than style, both of which live in
//! `create` and `destroy` where they are implemented.
//!
//! Split out of `transport/quic_bridge.zig`, which is now the facade over it
//! and five other named modules. The boundary is drawn at the thing that owns
//! the core: every module below this one answers one call, and everything this
//! file returns is a value the caller holds. The two copies of the Retry-token
//! key are one `drawKey` call each, and `destroy` releases the connections
//! before it erases the seed they were holding — neither is a cross-module
//! decision, so neither can be reordered by the split.

const std = @import("std");
const quic = @import("quic");
const base_key = @import("../base/key.zig");
const base_addr = @import("../base/addr.zig");
const base_ula = @import("../base/ula.zig");
const addr_map = @import("addr_map.zig");
const bridge_address = @import("bridge_address.zig");
const bridge_config = @import("bridge_config.zig");
const bridge_conn = @import("bridge_conn.zig");
const bridge_ingress = @import("bridge_ingress.zig");

const NodeId = base_key.NodeId;

const Manager = quic.connection_manager.ConnectionManager;
const tls13 = quic.tls13;
const ClientAuth = tls13.ClientAuth;

const Config = bridge_config.Config;
const CreateError = bridge_config.CreateError;
const Error = bridge_config.Error;
const Instant = bridge_config.Instant;
const demandsPeerCertificate = bridge_config.demandsPeerCertificate;
const drawKey = bridge_config.drawKey;
const seed_length = bridge_config.seed_length;
const spki_length = bridge_config.spki_length;

const toCoreAddress = bridge_address.toCoreAddress;

const Datagram = bridge_ingress.Datagram;
const Ingress = bridge_ingress.Ingress;
const Tick = bridge_ingress.Tick;
const ecnBits = bridge_ingress.ecnBits;

const Conn = bridge_conn.Conn;
const group = bridge_conn.group;
const min_datagram = bridge_conn.min_datagram;

/// One vendored `ConnectionManager` and the identity it presents.
///
/// It owns no `std.Io`, no clock and no generator: `Instant` and `std.Random`
/// are parameters of every call below, which is what lets the same bridge be
/// driven twice at two different instants and get two different answers. It
/// does keep the allocator it was created with, because the core's
/// connections are freed through it and a caller that has to be asked for an
/// allocator on `destroy` has to be trusted to answer.
///
/// Heap-allocated by `create`, not returned by value: the core's
/// `TlsConfig` points at this struct's own `spki` and `alpn_list`, and a
/// returned struct is moved into the caller's frame.
///
/// Keep the allocated address stable and call `destroy` exactly once.
/// Copies share resources and cannot be separately released. Serialize access,
/// including access through connection and stream handles. `gpa` and
/// `config.alpn` must stay alive until `destroy`.
pub const Bridge = struct {
    gpa: std.mem.Allocator,
    /// The core. Public because a caller reads connection state off it, not
    /// because poking it is safe.
    manager: Manager,
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
    /// The peer pin a server actually enforces. It points into this struct
    /// for the same reason.
    client_auth: ClientAuth,

    /// A bridge presenting `config.secret`'s node, with a `ConnectionManager`
    /// built from it.
    ///
    /// `random` seeds the core's SipHash key and draws the connection ids it
    /// hands out; `io` is used only where `config` left a transport key
    /// null, and for that it is `std.Io.randomSecure` rather than a process
    /// CSPRNG — a global RNG is what `AGENTS.md` §2 forbids, and an `std.Io`
    /// the caller was handed is not a global.
    ///
    /// The returned pointer is owned by `gpa` and freed by `destroy`.
    /// `config.alpn` is borrowed and must remain alive and unchanged.
    /// On error no bridge or owned allocation remains. Entropy and random
    /// draws already made are not restored. `error.Canceled` is forwarded.
    pub fn create(
        gpa: std.mem.Allocator,
        io: std.Io,
        config: Config,
        random: std.Random,
    ) CreateError!*Bridge {
        const self = try gpa.create(Bridge);
        errdefer gpa.destroy(self);
        const retry_key = try drawKey(io, config.retry_token_key);
        const reset_key = try drawKey(io, config.static_reset_key);
        self.* = .{
            .gpa = gpa,
            .manager = undefined,
            .node_id = config.secret.nodeId(),
            .seed = config.secret.toBytes()[0..seed_length].*,
            .spki = undefined,
            .cert_chain = undefined,
            .alpn_list = undefined,
            .client_auth = .{
                .expect_node_id = if (config.expect_peer) |peer| peer.toBytes() else null,
                // A pin implies a certificate, so the two fields are read
                // through one decision rather than two: see
                // `demandsPeerCertificate`.
                .mode = if (demandsPeerCertificate(config)) .required else .optional,
            },
        };
        self.manager = Manager.init(
            gpa,
            self.buildTlsConfig(config),
            connectionConfig(config, retry_key),
            retry_key,
            reset_key,
            random,
        );
        return self;
    }

    /// Free every connection the core holds and then the bridge.
    ///
    /// The secret seed is zeroed after the connections are released.
    /// This invalidates every connection, stream and TLS view from the bridge.
    /// Do not call through this pointer again or destroy an owner copy.
    pub fn destroy(self: *Bridge) void {
        self.manager.deinit();
        std.crypto.secureZero(u8, self.seed[0..]);
        self.gpa.destroy(self);
    }

    /// The node id this bridge presents as a bare `SubjectPublicKeyInfo`.
    pub fn nodeId(self: *const Bridge) NodeId {
        return self.node_id;
    }

    /// The TLS configuration the core is running.
    ///
    /// Exposed because it is the translation, and a translation nobody can
    /// read is a translation nobody can check.
    ///
    /// The result borrows this bridge's identity and ALPN storage.
    /// Keep the bridge and its borrowed ALPN alive while using the result.
    /// Import the registered `quic` module to name the result type.
    pub fn tlsConfig(self: *const Bridge) quic.tls13.TlsConfig {
        return self.manager.tls_config;
    }

    /// The core's TLS configuration for this identity.
    ///
    /// The two vocabularies differ because the core was written for a TLS
    /// stack that had an X.509 chain and a host name to check, and a node
    /// has neither: it is 32 bytes of ed25519 public key presented as a
    /// `SubjectPublicKeyInfo`, and the peer is named by the key rather than
    /// by a name in a certificate. So the translation is one-way and total —
    /// a node id in, an SPKI and a pin out — and it happens here once, rather
    /// than at each of the call sites that would otherwise have to know both
    /// spellings.
    ///
    /// `expect_peer_node_id` is deliberately left null. It is read only by
    /// `clientProcessCertificate` and a `ConnectionManager` never runs a
    /// client handshake, so setting it would read as a second pin and enforce
    /// nothing; the pin a server enforces is `client_auth.expect_node_id`,
    /// set above.
    ///
    /// The block is handed over whenever a peer is pinned, not only when a
    /// certificate is demanded: it is where the pin lives, so withholding it
    /// withholds the pin — see `demandsPeerCertificate`, which is also what
    /// `Config.require_peer_certificate` no longer decides on its own.
    fn buildTlsConfig(self: *Bridge, config: Config) quic.tls13.TlsConfig {
        self.spki = tls13.ed25519Spki(&self.node_id.toBytes());
        self.cert_chain = .{self.spki[0..]};
        self.alpn_list = .{config.alpn};
        return .{
            .cert_chain_der = &self.cert_chain,
            .private_key_bytes = self.seed[0..],
            .private_key_algorithm = .ed25519,
            .alpn = &self.alpn_list,
            .client_auth = if (demandsPeerCertificate(config)) &self.client_auth else null,
        };
    }

    /// One datagram through the core.
    ///
    /// `map` is the caller's address map and is borrowed for this call only.
    /// It answers who owns the address a datagram arrived from, which is the
    /// question a departing path is asked.
    ///
    /// `scratch` is the core's buffer: the datagram is copied into its front
    /// and any stateless reply is written behind it, so one buffer serves both
    /// and the reply borrows it until the next call. The core takes its input
    /// as `[]u8` because it decrypts in place; the copy is the price of that,
    /// and it is paid once per datagram rather than once per packet.
    ///
    /// `at` is the caller's instant and `random` the caller's generator, for
    /// the reason the module doc gives.
    ///
    /// `scratch` must not overlap `datagram.bytes`. Replies borrow `scratch`
    /// until it is reused or released. The source key is an independent copy.
    /// `error.NoRoom` before processing leaves connection state unchanged.
    /// `error.OutOfMemory` may follow committed packet processing, but preserves
    /// routing keys. Do not replay the input; synchronize live entries through
    /// `manager.syncCids` before draining newly issued CIDs, or close the owner.
    pub fn recv(
        self: *Bridge,
        map: *const addr_map.MappedAddrs,
        datagram: Datagram,
        scratch: []u8,
        at: Instant,
        random: std.Random,
    ) Error!Ingress {
        if (datagram.bytes.len > scratch.len) return error.NoRoom;
        @memcpy(scratch[0..datagram.bytes.len], datagram.bytes);
        const action = try self.manager.recvDatagram(
            scratch[0..datagram.bytes.len],
            toCoreAddress(datagram.from),
            toCoreAddress(datagram.local),
            ecnBits(datagram.ecn),
            scratch[datagram.bytes.len..],
            at,
            random,
        );
        const classification = base_ula.classify(datagram.from);
        const owner: ?addr_map.Key = switch (classification) {
            // Only a synthetic address can be owned; a direct path needs no
            // map and keeps its real port, which is why `classify` carries it
            // through whole rather than reducing it to a `Ula`.
            .any_path, .relay, .custom => |octets| map.lookup(octets),
            .ip => null,
        };
        return .{
            .source = .{
                .socket = datagram.from,
                .classification = classification,
                .owner = owner,
            },
            .outcome = switch (action) {
                .processed => |entry| .{ .processed = .{ .entry = entry } },
                .send_response => |bytes| .{ .reply = try group(bytes, bytes.len, null) },
                .dropped => .dropped,
                .foreign => |server_id| .{ .foreign = server_id },
            },
        };
    }

    /// One pass of the core's timers for `conn`, at the caller's instant.
    ///
    /// A finished connection leaves the core's table here and its memory
    /// stands until `sweep`, which is what lets a caller drain the close it
    /// just produced before the memory goes.
    pub fn tick(
        self: *Bridge,
        conn: Conn,
        at: Instant,
        random: std.Random,
    ) Tick {
        if (self.manager.tickEntry(conn.entry, at, random)) return .live;
        return .finished;
    }

    /// The i-th connection the core holds, or null when there is no i-th.
    ///
    /// A borrowed handle, and no more than `tick` says a connection is live:
    /// after `sweep` it points at freed bytes. Walking this by index rather
    /// than taking a slice keeps the conversion allocation-free, which is the
    /// only reason it is not a slice of `Conn`.
    pub fn connectionAt(self: *const Bridge, index: usize) ?Conn {
        if (index >= self.manager.entries.items.len) return null;
        return .{ .entry = self.manager.entries.items[index] };
    }

    /// Free the connections `tick` took out of the table.
    ///
    /// After all processing for the cycle, and never in the middle of it: a
    /// caller still holding a handle must read a closed connection rather
    /// than freed memory.
    pub fn sweep(self: *Bridge) void {
        self.manager.freeDeadEntries();
    }
};

/// The core's connection configuration for a node's config.
///
/// One field is not a rename and is the reason this function exists at all:
/// `token_key` is the same secret as the manager's `retry_token_key` and
/// nothing sets it for you: a connection with no token key issues no NEW_TOKEN
/// at all, which is why this one is always supplied. Two fields in the core,
/// one value in this project's vocabulary.
fn connectionConfig(config: Config, retry_token_key: [16]u8) quic.connection.ConnectionConfig {
    return .{
        .max_idle_timeout = config.idle_timeout_ms,
        .token_key = retry_token_key,
    };
}

const t = std.testing;

// The peer's half of a handshake and the virtual clock, named here so the tests
// below stand as they were written.
const peer_mod = @import("bridge_peer.zig");
const SecretKey = base_key.SecretKey;
const SocketAddr = base_addr.SocketAddr;
const Egress = bridge_conn.Egress;
const server_seed = peer_mod.server_seed;
const client_seed = peer_mod.client_seed;
const alpn = peer_mod.alpn;
const start = peer_mod.start;
const Prng = peer_mod.Prng;
const client_addr = peer_mod.client_addr;
const server_addr = peer_mod.server_addr;
const client_host = peer_mod.client_host;
const max_datagram = peer_mod.max_datagram;
const max_egress = peer_mod.max_egress;
const max_rounds = peer_mod.max_rounds;
const Client = peer_mod.Client;
const exchange = peer_mod.exchange;
const unsupportedVersionProbe = peer_mod.unsupportedVersionProbe;

test "a node's identity reaches the core as a bare SPKI and the handshake finishes" {
    var server_secret = try SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();
    var client_secret = try SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();

    var engine = Prng.init(1);
    const bridge = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .expect_peer = client_secret.nodeId(),
        .alpn = alpn,
    }, engine.random());
    defer bridge.destroy();

    // The translation, read back rather than assumed. One certificate, 44
    // bytes, wrapping this node's own id, the peer pinned in the one field
    // a server actually enforces, and nothing set in the field that only a
    // client reads.
    const tls = bridge.tlsConfig();
    try t.expectEqual(@as(usize, 1), tls.cert_chain_der.len);
    try t.expectEqual(@as(usize, spki_length), tls.cert_chain_der[0].len);
    try t.expectEqualSlices(
        u8,
        &tls13.ed25519Spki(&server_secret.nodeId().toBytes()),
        tls.cert_chain_der[0],
    );
    try t.expectEqual(tls13.PrivateKeyAlgorithm.ed25519, tls.private_key_algorithm);
    try t.expectEqual(@as(usize, 1), tls.alpn.len);
    try t.expectEqualStrings(alpn, tls.alpn[0]);
    try t.expectEqual(@as(?[32]u8, null), tls.expect_peer_node_id);
    try t.expectEqual(client_secret.nodeId().toBytes(), tls.client_auth.?.expect_node_id.?);
    try t.expectEqual(tls13.ClientAuth.Mode.required, tls.client_auth.?.mode);

    // The consequence of the translation above: a handshake completes, and
    // it completes over two synthetic addresses with no socket anywhere.
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    var client: Client = undefined;
    try client.init(client_secret, server_secret.nodeId(), 2, start);
    defer client.deinit();
    try exchange(&client, bridge, &map, start);

    try t.expectEqual(@as(usize, 1), bridge.manager.connectionCount());
    const conn = bridge.connectionAt(0) orelse return error.TestUnexpectedResult;
    try t.expect(conn.established());

    // The answer to the question `docs/PLAN.md`'s mapping raises: the core
    // does not validate a peer's address, so an RFC 4193 ULA is a peer
    // address like any other. It round-trips through the core's own address
    // type unchanged, and `classify` still recognises it.
    try t.expectEqual(client_addr, conn.peer().?);
    try t.expectEqual(server_addr, conn.local().?);
    try t.expectEqual(
        base_ula.Classification{ .any_path = base_ula.ulaFor(.any_path, client_host) },
        base_ula.classify(conn.peer().?),
    );

    // The peer identity this connection runs on came out of the certificate
    // the client presented and from nothing else. The whole certificate is
    // that client's 44 bytes, the policy that accepted it is the one this
    // bridge built, and the ALPN both ends settled on is the one string the
    // caller named — three fields of the translation, read back off a
    // connection that used them.
    try t.expectEqualSlices(
        u8,
        &tls13.ed25519Spki(&client_secret.nodeId().toBytes()),
        conn.entry.conn.peerCertificate().?,
    );
    try t.expectEqual(
        client_secret.nodeId().toBytes(),
        conn.entry.conn.clientAuth().?.expect_node_id.?,
    );
    try t.expectEqualStrings(alpn, conn.entry.conn.negotiatedAlpn());
}

test "a bridge that pins no node still learns which node it is talking to" {
    var server_secret = try SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();
    var client_secret = try SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();

    // One field changed from the test above and nothing else: no expected
    // peer. The certificate request is still made, so the connection is
    // still identified — the peer has proved possession of the id it
    // presented rather than being the node the caller asked for.
    var engine = Prng.init(3);
    const bridge = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .alpn = alpn,
    }, engine.random());
    defer bridge.destroy();
    try t.expectEqual(@as(?[32]u8, null), bridge.tlsConfig().client_auth.?.expect_node_id);

    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    var client: Client = undefined;
    try client.init(client_secret, server_secret.nodeId(), 4, start);
    defer client.deinit();
    try exchange(&client, bridge, &map, start);

    const conn = bridge.connectionAt(0) orelse return error.TestUnexpectedResult;
    try t.expect(conn.established());
    try t.expectEqualSlices(
        u8,
        &tls13.ed25519Spki(&client_secret.nodeId().toBytes()),
        conn.entry.conn.peerCertificate().?,
    );
    try t.expectEqual(@as(?[32]u8, null), conn.entry.conn.clientAuth().?.expect_node_id);
}

test "a caller's instant reaches the core byte for byte" {
    var server_secret = try SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();

    var engine = Prng.init(7);
    const bridge = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .alpn = alpn,
    }, engine.random());
    defer bridge.destroy();
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);

    const probe = unsupportedVersionProbe();
    // An instant nothing on this host would produce: a monotonic clock that
    // started at an odd offset and has a sub-millisecond remainder on it.
    const at: Instant = 7 * std.time.ns_per_s + 123_456_789;
    var scratch: [2 * max_datagram]u8 = undefined;
    const ingress = try bridge.recv(&map, .{
        .bytes = probe[0..],
        .from = client_addr,
        .local = server_addr,
        .ecn = null,
    }, scratch[0..], at, engine.random());

    // Version Negotiation is the one reply the core writes without a
    // connection, and reaching it costs the reply limiter a refill whose only
    // input is the instant.
    try t.expect(ingress.outcome == .reply);
    try t.expect(ingress.outcome.reply.contents.len > 0);
    try t.expectEqual(at, bridge.manager.reply_limits.version_negotiation.last_refill_ns);
}

test "the same call at two instants gives two answers" {
    var server_secret = try SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();
    var client_secret = try SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();

    var engine = Prng.init(11);
    const bridge = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .expect_peer = client_secret.nodeId(),
        .alpn = alpn,
    }, engine.random());
    defer bridge.destroy();
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    var client: Client = undefined;
    try client.init(client_secret, server_secret.nodeId(), 12, start);
    defer client.deinit();
    try exchange(&client, bridge, &map, start);

    const conn = bridge.connectionAt(0) orelse return error.TestUnexpectedResult;
    try t.expect(conn.established());
    const stream = try conn.entry.conn.openStream();
    try stream.send.writeData("a datagram to send");
    stream.send.close();

    var egress: [max_egress]Egress = undefined;
    var out: [max_egress * max_datagram]u8 = undefined;

    // At the instant the connection was accepted, the same two calls say
    // there is a flight to send and the connection is alive.
    const before = try conn.drain(egress[0..], out[0..], start, client.random());
    try t.expect(before.len > 0);
    try t.expectEqual(Tick.live, bridge.tick(conn, start, client.random()));

    // At an instant past the idle timeout, the same two calls say the
    // connection is over and there is nothing left to send. Nothing in this
    // file read a clock to get there: the answers differ because the
    // arguments did, which is the property `docs/DECISIONS/0002` is about and
    // the only way a test can tell a threaded clock from a stored one.
    const later = start + 60 * std.time.ns_per_s;
    try t.expectEqual(Tick.finished, bridge.tick(conn, later, client.random()));
    try t.expectEqual(
        @as(usize, 0),
        (try conn.drain(egress[0..], out[0..], later, client.random())).len,
    );

    bridge.sweep();
}

test "an address that arrived off the wire is the path it stands for" {
    var server_secret = try SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();

    var engine = Prng.init(13);
    const bridge = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .alpn = alpn,
    }, engine.random());
    defer bridge.destroy();

    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    var map_engine = Prng.init(14);
    const relay = try base_addr.RelayUrl.parse("https://relay.example.com");
    const owned: addr_map.Key = .{ .relay = .{ .relay = relay, .node = server_secret.nodeId() } };
    const allocated = try map.get(t.allocator, owned, map_engine.random());

    const probe = unsupportedVersionProbe();
    var scratch: [2 * max_datagram]u8 = undefined;
    const from_relay: SocketAddr = .{ .ip = .{ .v6 = allocated }, .port = base_ula.mapped_port };
    const ingress = try bridge.recv(&map, .{
        .bytes = probe[0..],
        .from = from_relay,
        .local = server_addr,
        .ecn = null,
    }, scratch[0..], start, engine.random());

    // `classify` says which path the address stands for; the map says whose
    // it is. A datagram on a relay path names the relay and the peer, and the
    // two answers are separate lookups on purpose.
    try t.expectEqual(
        base_ula.Classification{ .relay = allocated },
        ingress.source.classification,
    );
    try t.expectEqual(from_relay, ingress.source.socket);
    try t.expectEqual(owned, ingress.source.owner.?);

    // An address this node's map never handed out has no owner, and says so
    // rather than guessing. `client_addr` is in the `any_path` subnet and was
    // never allocated here.
    const unallocated = try bridge.recv(&map, .{
        .bytes = probe[0..],
        .from = client_addr,
        .local = server_addr,
        .ecn = null,
    }, scratch[0..], start, engine.random());
    try t.expectEqual(
        base_ula.Classification{ .any_path = base_ula.ulaFor(.any_path, client_host) },
        unallocated.source.classification,
    );
    try t.expectEqual(@as(?addr_map.Key, null), unallocated.source.owner);
}

test "no egress room leaves the flight unsent, and the retry after it emits the flight" {
    var server_secret = try SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();
    var client_secret = try SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();

    var engine = Prng.init(19);
    const bridge = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .alpn = alpn,
    }, engine.random());
    defer bridge.destroy();
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    var client: Client = undefined;
    try client.init(client_secret, server_secret.nodeId(), 20, start);
    defer client.deinit();

    // The client's first Initial, accepted. The connection therefore holds a
    // whole flight that nothing has sent yet.
    var scratch: [2 * max_datagram]u8 = undefined;
    const len = try client.conn.sendAt(&client.buffer, start, client.random());
    const ingress = try bridge.recv(&map, .{
        .bytes = client.buffer[0..len],
        .from = client_addr,
        .local = server_addr,
        .ecn = null,
    }, scratch[0..], start, client.random());
    const conn = switch (ingress.outcome) {
        .processed => |handled| handled,
        else => return error.TestUnexpectedResult,
    };

    var egress: [max_egress]Egress = undefined;
    var out: [max_egress * max_datagram]u8 = undefined;
    var no_slot: [0]Egress = undefined;
    var too_short: [min_datagram - 1]u8 = undefined;

    // Both refusals come before the core is asked for anything.
    try t.expectError(error.NoRoom, conn.drain(no_slot[0..], out[0..], start, client.random()));
    try t.expectError(error.NoRoom, conn.drain(egress[0..], too_short[0..], start, client.random()));

    // And the flight is still there: the datagram both refusals declined to
    // produce is the one this call gets.
    const sends = try conn.drain(egress[0..], out[0..], start, client.random());
    try t.expect(sends.len > 0);
    try t.expect(sends[0].send.contents.len > 0);
}

test "an egress array that fills up is a short answer, and asking again finishes the flight" {
    var server_secret = try SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();
    var client_secret = try SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();

    var engine = Prng.init(21);
    const bridge = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .alpn = alpn,
    }, engine.random());
    defer bridge.destroy();
    var map = addr_map.MappedAddrs.init();
    defer map.deinit(t.allocator);
    var client: Client = undefined;
    try client.init(client_secret, server_secret.nodeId(), 22, start);
    defer client.deinit();

    var scratch: [2 * max_datagram]u8 = undefined;
    const len = try client.conn.sendAt(&client.buffer, start, client.random());
    const ingress = try bridge.recv(&map, .{
        .bytes = client.buffer[0..len],
        .from = client_addr,
        .local = server_addr,
        .ecn = null,
    }, scratch[0..], start, client.random());
    const conn = switch (ingress.outcome) {
        .processed => |handled| handled,
        else => return error.TestUnexpectedResult,
    };

    // One slot at a time, as a caller with a small array would. Every call
    // answers with what it could carry, the first is not empty because there
    // is a flight waiting, and the calls end rather than repeating a
    // refusal: nothing the core produced was dropped on the way.
    var one: [1]Egress = undefined;
    var out: [max_datagram]u8 = undefined;
    var passes: usize = 0;
    while (passes < max_rounds) : (passes += 1) {
        const sends = try conn.drain(one[0..], out[0..], start, client.random());
        if (sends.len == 0) break;
        try t.expectEqual(one.len, sends.len);
        try t.expect(sends[0].send.contents.len > 0);
    }
    try t.expect(passes < max_rounds);
    try t.expectEqual(
        @as(usize, 0),
        (try conn.drain(one[0..], out[0..], start, client.random())).len,
    );
}

test "a peer pin is enforced whatever the caller said about certificates" {
    var server_secret = try SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();
    var client_secret = try SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();
    var engine = Prng.init(25);

    // The pin, with the certificate requirement explicitly cleared. The core
    // reads the pin out of the block that requirement decides on, so this is
    // the configuration in which an unenforced pin was possible.
    const pinned = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .expect_peer = client_secret.nodeId(),
        .require_peer_certificate = false,
        .alpn = alpn,
    }, engine.random());
    defer pinned.destroy();
    const tls = pinned.tlsConfig();
    try t.expect(tls.client_auth != null);
    try t.expectEqual(
        client_secret.nodeId().toBytes(),
        tls.client_auth.?.expect_node_id.?,
    );
    try t.expectEqual(tls13.ClientAuth.Mode.required, tls.client_auth.?.mode);

    // Naming no peer and asking for no certificate is the one configuration
    // that accepts an anonymous peer, and it still asks for one by default.
    const anonymous = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .require_peer_certificate = false,
        .alpn = alpn,
    }, engine.random());
    defer anonymous.destroy();
    try t.expectEqual(@as(?*const ClientAuth, null), anonymous.tlsConfig().client_auth);

    const defaulted = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .alpn = alpn,
    }, engine.random());
    defer defaulted.destroy();
    const default_tls = defaulted.tlsConfig();
    try t.expect(default_tls.client_auth != null);
    try t.expectEqual(tls13.ClientAuth.Mode.required, default_tls.client_auth.?.mode);
    try t.expectEqual(@as(?[32]u8, null), default_tls.client_auth.?.expect_node_id);
}

test "one egress slot at a time sends as much as the whole array sends" {
    var server_secret = try SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();
    var client_secret = try SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();

    // Two bridges and two clients over one identity and one seed, so both
    // sides hold the same flight and either drain is free to produce it. One
    // is drained into the whole array, the other one slot at a time; the bytes
    // that come out have to be the same, or a caller with a small array loses
    // what a caller with a big one sends — which is the whole cost of a
    // commit boundary that is checked one datagram too late.
    var wide_engine = Prng.init(31);
    const wide = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .alpn = alpn,
    }, wide_engine.random());
    defer wide.destroy();
    var narrow_engine = Prng.init(31);
    const narrow = try Bridge.create(t.allocator, t.io, .{
        .secret = server_secret,
        .alpn = alpn,
    }, narrow_engine.random());
    defer narrow.destroy();
    var map: addr_map.MappedAddrs = .init();
    defer map.deinit(t.allocator);
    // A second mapping table, so the address the first accept allocated is not
    // still in the one the second accept reads: both sides then hold the same
    // state and any difference in the bytes is the drain's.
    var narrow_map: addr_map.MappedAddrs = .init();
    defer narrow_map.deinit(t.allocator);
    var scratch: [2 * max_datagram]u8 = undefined;

    var wide_client: Client = undefined;
    try wide_client.init(client_secret, server_secret.nodeId(), 32, start);
    defer wide_client.deinit();
    const wide_len = try wide_client.conn.sendAt(&wide_client.buffer, start, wide_client.random());
    const wide_ingress = try wide.recv(&map, .{
        .bytes = wide_client.buffer[0..wide_len],
        .from = client_addr,
        .local = server_addr,
        .ecn = null,
    }, scratch[0..], start, wide_client.random());
    const wide_conn = switch (wide_ingress.outcome) {
        .processed => |handled| handled,
        else => return error.TestUnexpectedResult,
    };

    var narrow_client: Client = undefined;
    try narrow_client.init(client_secret, server_secret.nodeId(), 32, start);
    defer narrow_client.deinit();
    const narrow_len = try narrow_client.conn.sendAt(&narrow_client.buffer, start, narrow_client.random());
    const narrow_ingress = try narrow.recv(&narrow_map, .{
        .bytes = narrow_client.buffer[0..narrow_len],
        .from = client_addr,
        .local = server_addr,
        .ecn = null,
    }, scratch[0..], start, narrow_client.random());
    const narrow_conn = switch (narrow_ingress.outcome) {
        .processed => |handled| handled,
        else => return error.TestUnexpectedResult,
    };

    var egress: [max_egress]Egress = undefined;
    var out: [max_egress * max_datagram]u8 = undefined;
    var wide_bytes: std.ArrayList(u8) = .empty;
    defer wide_bytes.deinit(t.allocator);
    for (try wide_conn.drain(egress[0..], out[0..], start, wide_client.random())) |send| {
        try wide_bytes.appendSlice(t.allocator, send.send.contents);
    }

    var one: [1]Egress = undefined;
    var narrow_out: [max_datagram]u8 = undefined;
    var narrow_bytes: std.ArrayList(u8) = .empty;
    defer narrow_bytes.deinit(t.allocator);
    var passes: usize = 0;
    while (passes < max_rounds) : (passes += 1) {
        const sends = try narrow_conn.drain(one[0..], narrow_out[0..], start, narrow_client.random());
        if (sends.len == 0) break;
        for (sends) |send| try narrow_bytes.appendSlice(t.allocator, send.send.contents);
    }

    // The consumer-visible claim is that a caller with a one-slot array loses
    // nothing, so the totals must match. The bytes of two separately built
    // connections are not the same bytes — connection ids and the transcript
    // that covers them differ — and nothing in the core's contract says they
    // should be, so asserting that would assert a property this test's own
    // premise cannot deliver.
    try t.expect(wide_bytes.items.len > 0);
    try t.expectEqual(wide_bytes.items.len, narrow_bytes.items.len);
    try t.expect(passes > 0);
}
