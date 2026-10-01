//! Originating a QUIC connection: the other direction of `quic_bridge.zig`.
//!
//! `transport/quic_bridge.zig` owns a `ConnectionManager` that only ever runs
//! a server. Until this file existed nothing under `src/` could open one, and a
//! P2P stack that cannot dial is a server. Everything here exists to make the
//! client half a first-class member of the *same* machinery, so a dialler and a
//! listener differ in who starts the connection and in where the first address
//! comes from, and in nothing else.
//!
//! # The loop is the bridge's, not a second copy
//!
//! `ConnectionManager` has one client arm and it is this one.
//! `ConnectionManager.acceptConnection` (`connection_manager.zig:348`) is the
//! whole of what it does to admit a connection: build a `Connection`, wrap it
//! in a `ConnEntry`, register the connection's own CID in `cid_map`, append the
//! entry. `Dialer.open` does the same four steps with `Connection.connectInto`
//! in place of `Connection.acceptInto`, and from there the two are
//! indistinguishable. `Bridge.recv` routes a reply to it by DCID, `Conn.drain`
//! serialises it into `batch.Send` values, `Bridge.tick` runs its timers,
//! `Bridge.sweep` frees it, `Bridge.connectionAt` finds it. There is no second
//! `recv`, no second `drain` and no second timer pass in this file, and a
//! dialled connection is driven by exactly the calls an accepted one is. That
//! is the finding, and it is the reason this file is short.
//!
//! One asymmetry in the registration is real and was read rather than assumed.
//! An accepted entry registers *two* CIDs: its own SCID, and the DCID the
//! client chose, so retransmitted Initials still route (`connection_manager.zig:394`).
//! A dialled entry registers *one*, its SCID, because a peer never sends with
//! the DCID we chose — it answers with the CID from our ClientHello. Version
//! negotiation needs none of this: `route` answers a VN at
//! `connection_manager.zig:549`, before it looks anything up.
//!
//! What a caller drives, then, is two states and a timer. The core sets
//! `.handshake` on the first Initial (`connection.zig:1561`) and clears it to
//! `.connected` on the same datagram's later packets (`connection.zig:2559`),
//! coalesced into one `recv` — so `.handshake` is not observable from outside
//! the core, and a dialled connection is seen going straight from
//! `first_flight` to `connected`. The test "a dial runs initiated to connected
//! as a function of datagrams and nothing else" pins that trace rather than
//! the state machine it was expected to have.
//!
//! # `io`, the instant and the generator
//!
//! `Instant` and `std.Random` are parameters of every call that moves the core
//! forward, and nothing in this file reads a clock or draws entropy, for the
//! reason `quic_bridge.zig`'s module doc gives. `std.Io` is stronger here than
//! threaded: **there is no `std.Io` on this path at all.** `Bridge.create` takes
//! one because it draws the two transport secrets a caller may leave null; a
//! dial draws nothing — a client signs no Retry token and issues no NEW_TOKEN,
//! and the one secret a client has is its own seed, which the caller already
//! holds in `Config.secret`. A parameter with no work is a parameter a caller
//! has to thread for a fiction, so there is not one, and this is the same
//! property `docs/DECISIONS/0002` buys from the other side: a dialler driven
//! twice at two instants with two generators is two dialler's worth of answers.
//!
//! # The address, and what the core is told
//!
//! A dial starts from a target: a direct `SocketAddr`, a `RelayUrl`, or a
//! `CustomAddr`. `base/ula.zig` maps the two non-IP arms onto synthetic RFC
//! 4193 addresses and `transport/addr_map.zig` memoises them, and both are used
//! here — `resolveRoute` is the one place a target becomes an address, and the
//! core is told the *socket address* while the caller is handed the *key* it
//! stands for. That split is the point: the core gets an address it can put in
//! a `sockaddr.storage` and compare, and the caller gets back the peer and relay
//! or the custom bytes it has to open a socket for. `Conn.drain` gives the
//! caller an `Egress` carrying only the address, so the address is all the
//! socket layer ever sees and `ownerOf` is how it turns one back into a key.
//!
//! **One target, one address, one connection.** The core holds two
//! `NetworkPath`s and indexes one as active (`connection.zig:626`), and a 1-RTT
//! packet carrying at least one non-probing frame, from any other address,
//! becomes a migration rather than a second path (`connection.zig:1540`). So
//! the multipath cost `DECISIONS/0001` records is observable here as a hard one:
//! a peer reachable over a relay and a direct path is **two dials**, and the
//! caller owns the policy that says which. Nothing in this file can widen it,
//! and pretending otherwise would be a second core.
//!
//! The migration adds no path and queues none either: `handleMigration` writes
//! the alternate slot (`connection.zig:3442`) and promotes it (`:3452`), so the
//! address that was active is written over rather than kept. The moment the peer
//! answers on the second address the first stops being used at all — measured,
//! the client sent nothing further to the address it left — which makes a
//! second address a hazard on a live connection rather than spare capacity on it.
//! Only non-probing frames do this: padding, PATH_CHALLENGE, PATH_RESPONSE and
//! NEW_CONNECTION_ID from an address the connection has never heard of are
//! answered and otherwise ignored, so an address that has not spoken is never
//! discovered and the candidate slot is never filled for one. Nothing in a
//! resolved address distinguishes those two kinds, which is why the choice
//! belongs to the dial and not to the connection.
//!
//! Two further things the core does with an address, both found by reading it:
//!
//! 1. **A dialled connection's first inbound datagram rewrites its path.**
//!    `connectInto` leaves `path_initialized` false and `paths` zeroed, and
//!    `recv` builds the path from the first datagram it sees
//!    (`connection.zig:1533`). So the two addresses `open` writes are what the
//!    first flight is sent to and nothing more, and they are written only
//!    because `Conn.drain` reads the destination off the active path before any
//!    packet has arrived. For a relay that is the right answer — the reply
//!    arrives from the relay's real address and the core should keep sending
//!    there — and it means the caller's job after the first exchange is to hold
//!    a socket for whatever address the core now holds.
//! 2. **The synthetic address is never validated.** The core's only
//!    address-sensitive policy is `NetworkPath.canSend`
//!    (`connection.zig:127`), the server-side anti-amplification limit, and it
//!    is guarded by `is_server` at both uses (`connection.zig:3270`, `:3381`).
//!    An RFC 4193 ULA is a peer address like any other to a client, which is
//!    the answer `DECISIONS/0001` asks for and it is a different answer than
//!    the server side's.
//!
//! # The pin, and the shape that keeps it set
//!
//! Verification on a dial is `TlsConfig.expect_peer_node_id`, a byte comparison
//! of the 32 bytes lifted out of the peer's `SubjectPublicKeyInfo`
//! (`tls13.zig:1465`). The mirror of what `Bridge` does with
//! `ClientAuth.expect_node_id`. `expect_peer_node_id` is `?` in the core, and
//! null is a connection that proves nothing about who is on the other end, so
//! two things here are built to make the null case reachable only by naming it:
//!
//! - The pin is a **parameter of the dial**, not a field of the dialer, because
//!   one dialer dials many peers and a config-wide pin would be a pin for
//!   whichever peer was named last.
//! - `Config.require_peer_pin` defaults to true and `dial` returns
//!   `error.NoPeerPin` before it touches the map, so a refused dial allocates
//!   nothing at all.
//!
//! And then the shape removes the remaining case. Both synthetic subnets are
//! keyed on the peer's id — `addr_map.Key.relay` is a `(relay, node)` pair and
//! `Key.custom` belongs to one node — so **a dial with no id has no key to
//! allocate an address from**, and `resolveRoute` returns `error.NoPeerId`. The
//! only target an unpinned dial can name is a direct `SocketAddr`, and reaching
//! that takes `require_peer_pin = false` written out by the caller.
//!
//! One more asymmetry, and the one a caller is most likely to trip on. The pin
//! is enforced, but the bytes it was compared against are not kept on this
//! side: `clientProcessCertificate` lifts the key out of the peer's
//! `SubjectPublicKeyInfo`, compares it and drops the certificate
//! (`tls13.zig:1463`), where the server arm of the same handshake is the one
//! that copies it (`tls13.zig:2091`). So a dialled connection names its peer
//! by node id — `tls13_hs.?.peerNodeId()` — and
//! `Connection.peerCertificate()` is null on it even after a handshake that
//! verified. The bridge's own test reads the certificate off the *accepted*
//! connection, where it is there, and nothing about a dial can read it back.
//!
//! # What `server_name` means on a dial
//!
//! It is not a host being verified, and after the M8 certificate patch it could
//! not be: the peer certificate is a bare 44-byte SPKI with no name in it, and
//! the pin is a 32-byte comparison. Nothing in ozai populates
//! `TlsConfig.certs`, so no server here ever calls `selectCertificateFor` and no
//! name selects anything. What the field *is* on a dial is the SNI extension
//! the client sends, and this project sends `default_server_name` — one
//! constant, `"ozai.invalid"`, RFC 2606 reserved so it can never resolve, on
//! every dial. It names the protocol, discloses nothing, and is the same bytes
//! to every observer.
//!
//! It is deliberately **not** `NodeId.toLocalTlsName()`. That helper exists and
//! is documented in `base/key.zig` as never sent: iroh stopped transmitting it
//! in 1.0.3 because it discloses the peer id, and the core's signature takes
//! `server_name: []const u8` with no null to opt out with
//! (`connection.zig:4540`), so the only lever left is what the bytes are. A
//! caller that wants the peer-id label — a future multi-identity bridge
//! selecting by SNI, say — sets `Config.server_name` itself, and the field is
//! there for that reason rather than as decoration.
//!
//! # Who owns the socket
//!
//! Nobody here, and that is a position rather than an omission. `dial` takes
//! the caller's `local` address and returns the address to send to; opening the
//! socket, waking on a read, and sleeping until the next deadline are the
//! caller's. A dial that opened a socket would have to hold it, and a held
//! socket is held state with a file descriptor and a lifetime — the same
//! objection `endpoint/endpoint.zig` records for `std.Io`, and for the same
//! reason. It is also what makes every decision in this file testable without
//! one.

const std = @import("std");
const quic = @import("quic");

// Named for the layer, not the file: `key`, `addr` and `ula` are this
// module's own vocabulary as declarations and a parameter may not shadow one.
const base_key = @import("../base/key.zig");
const base_addr = @import("../base/addr.zig");
const base_ula = @import("../base/ula.zig");
const addr_map = @import("addr_map.zig");
const batch = @import("batch.zig");
const quic_bridge = @import("quic_bridge.zig");

const posix = std.posix;

const NodeId = base_key.NodeId;
const SecretKey = base_key.SecretKey;
const SocketAddr = base_addr.SocketAddr;
const TransportAddr = base_addr.TransportAddr;
const CustomAddr = base_addr.CustomAddr;

const Bridge = quic_bridge.Bridge;
const Conn = quic_bridge.Conn;
const Egress = quic_bridge.Egress;
const Entry = quic.connection_manager.ConnEntry;
const CidKey = quic.connection_manager.CidKey;
const Connection = quic.connection.Connection;
const ConnectionConfig = quic.connection.ConnectionConfig;
const State = quic.connection.State;
const tls13 = quic.tls13;

/// The instant the core is driven at. Re-exported so a caller threading a dial
/// names one module for its identity and its clock.
pub const Instant = quic_bridge.Instant;

/// The size of a peer certificate: a DER `SubjectPublicKeyInfo` wrapping 32
/// bytes of ed25519 public key and nothing else.
pub const spki_length = quic_bridge.spki_length;

/// The 32 bytes of a secret key that are the actual entropy source; what the
/// core wants as `private_key_bytes` for `.ed25519`.
const seed_length = SecretKey.seed_length;

/// The SNI every dial sends unless the caller names another one. See the
/// module doc: this is a constant, not a host, and it is never verified.
pub const default_server_name = "ozai.invalid";

/// What this path refuses.
///
/// Three other vocabularies are included whole rather than restated. One set
/// covers a dialled and an accepted connection, and a second copy of
/// `quic_bridge.Error` is a list that goes stale when that file grows an arm.
/// A target can reach every arm of `base_addr.CustomAddrParseError` and of
/// `addr_map.GetError`, and a caller should not have to import two more
/// modules to handle a refused dial. Of those, `DataTooLong` is the one worth
/// a word: a key that silently cut a custom address off would send the peer
/// somewhere that is not here.
pub const Error = quic_bridge.Error || base_addr.CustomAddrParseError ||
    addr_map.GetError || error{
    /// The caller's allocator refused the dial.
    OutOfMemory,
    /// The caller required a pin and named no peer to pin. Nothing was
    /// allocated: the refusal is the first thing `dial` does.
    NoPeerPin,
    /// A non-IP target and no peer's id, so there is no map key to allocate
    /// an address from. See the module doc.
    NoPeerId,
    /// The manager's connection table is full. A dial takes the same slot an
    /// accepted connection would, and a node that is refusing new connections
    /// is refusing both.
    TooManyConnections,
    /// The connection had more live CIDs than `ConnEntry` can record, so one
    /// could not be taken back out of the routing map. Unreachable for a
    /// connection the manager just built; named because a silent drop here
    /// would leave a routing entry pointing at freed memory.
    CidPoolFull,
};

/// What `Dialer.destroy` refuses.
pub const DestroyError = error{
    /// A connection this dialer opened is still in the manager's table. Its
    /// TLS handshake points at this dialer's seed, `cert_chain` and `alpn_list`,
    /// so freeing those now leaves the core reading freed bytes.
    DialedConnectionsLive,
};

/// The configuration a caller supplies, in this project's vocabulary.
///
/// Nothing here is named after a field in the vendored tree, for
/// `quic_bridge.zig`'s reason, and there is deliberately no pin: the pin
/// belongs to a dial, not to a dialer, because one dialer dials many peers.
pub const Config = struct {
    /// This node's identity: the seed the presented certificate is built from,
    /// and the node id a peer compares the certificate against.
    secret: SecretKey,
    /// The one ALPN this build speaks. The core takes a list because it is a
    /// general TLS stack; a node speaks one.
    alpn: []const u8,
    /// The SNI to send. A constant for every dial this project originates; see
    /// the module doc for what the field is and is not.
    server_name: []const u8 = default_server_name,
    /// How long a connection may sit idle before the core gives it up, in
    /// milliseconds. The core's unit is milliseconds and so is this one.
    idle_timeout_ms: u64 = 30_000,
    /// A NEW_TOKEN from an earlier connection to this peer, to be presented in
    /// the first Initial. `connectInto` copies it into the connection's own
    /// buffer, so this slice is not retained. Null sends no token.
    initial_token: ?[]const u8 = null,
    /// Whether a dial that names no peer is refused.
    ///
    /// True by default, and the answer to the question the core's nullable
    /// pin raises: a connection with no pin verifies nothing, so a caller that
    /// wants one has to write `false` here and say so in the same breath.
    /// Whatever it is, the pin the core was handed is readable back off
    /// `tlsConfigFor`, so no connection can be built that nobody can see is
    /// unpinned.
    require_peer_pin: bool = true,
};

/// One target and the node behind it: a dial's whole reason to exist.
///
/// A `NodeAddr` is a list of these, and one of them is one connection — see the
/// module doc on paths.
pub const Dial = struct {
    /// The connection, borrowed out of the manager. Drive it with the bridge's
    /// `recv`, `tick` and `sweep` exactly as an accepted one, and it is freed
    /// by `sweep` or by `Bridge.destroy`, never by the dialer.
    conn: Conn,
    /// The address the core was told, and what it stands for.
    route: Route,
};

/// The address a target is reached at, and the key behind it.
pub const Route = struct {
    /// The address the core is told. A synthetic RFC 4193 address for a relay
    /// or a custom target, and the target's own address for a direct one.
    socket: SocketAddr,
    /// The key that owns `socket`, or null on a direct path: upstream never
    /// puts an IP in the map, and this one does not either.
    key: ?addr_map.Key,
    /// Which synthetic subnet `socket` sits in, or null on a direct path, which
    /// has none. This and `key` are both null exactly when `socket` is one of
    /// the caller's own.
    subnet: ?base_ula.Path,
};

/// What a target becomes: one address the core is told, and one key the caller
/// keeps.
///
/// A direct target comes back whole and is never allocated in the map, for
/// `base/ula.zig`'s reason. The other two are the arms that need dressing up,
/// and each is keyed on the peer's id: `Key.relay` is a `(relay, node)` pair
/// and `Key.custom` belongs to one node. That is why `peer` may be null only
/// for a direct path, and why the answer to a null id on the others is
/// `error.NoPeerId` rather than an address nobody could resolve back to a peer.
pub fn resolveRoute(
    gpa: std.mem.Allocator,
    map: *addr_map.MappedAddrs,
    transport: TransportAddr,
    peer: ?NodeId,
    random: std.Random,
) Error!Route {
    switch (transport) {
        .ip => |socket| return .{ .socket = socket, .key = null, .subnet = null },
        .relay => |url| return routeThrough(
            gpa,
            map,
            .{ .relay = .{ .relay = url, .node = peer orelse return error.NoPeerId } },
            .relay,
            random,
        ),
        .custom => |custom| return routeThrough(
            gpa,
            map,
            // `from` copies the data into the key. An entry outlives the frame
            // that produced the address, so a key pointing into it would be
            // read back over bytes already reused.
            .{ .custom = try addr_map.CustomKey.from(custom) },
            .custom,
            random,
        ),
    }
}

/// The address a synthetic key is reached at, on the subnet its arm names.
fn routeThrough(
    gpa: std.mem.Allocator,
    map: *addr_map.MappedAddrs,
    key: addr_map.Key,
    subnet: base_ula.Path,
    random: std.Random,
) Error!Route {
    return .{
        .socket = base_ula.socketAddrFor(
            subnet,
            addr_map.hostBitsOf(try map.get(gpa, key, random)),
        ),
        .key = key,
        .subnet = subnet,
    };
}

/// The key that owns `socket` on this node's map, or null.
///
/// The egress-side twin of what `Bridge.recv` computes on the way in
/// (`quic_bridge.zig:574`). A sender has to answer the same two questions a
/// receiver does — which subnet the address is in, and whose key stands behind
/// it — to know which socket to put the datagram on, and `Conn.drain` hands
/// over the address alone. It is the same `classify`-then-`lookup` the bridge
/// makes; there is no seam to call there, so it is written out, and the two
/// must agree about the three subnets or a dialled connection is sent on a
/// socket it did not open.
pub fn ownerOf(map: *const addr_map.MappedAddrs, socket: SocketAddr) ?addr_map.Key {
    return switch (base_ula.classify(socket)) {
        .ip => null,
        .any_path, .relay, .custom => |octets| map.lookup(octets),
    };
}

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
pub const Dialer = struct {
    gpa: std.mem.Allocator,
    /// The bridge whose manager will own the dialled connection. Borrowed: the
    /// connection is freed by `Bridge.sweep` or `Bridge.destroy`, never here.
    bridge: *Bridge,
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

    /// Free the dialer, refusing while a connection it opened is still live.
    ///
    /// The seed is zeroed first, for `Bridge.destroy`'s reason: it is a copy of
    /// a key the caller also holds, and the core's handshakes on this dialer's
    /// connections point at it, which is why a live connection refuses this.
    pub fn destroy(self: *Dialer) DestroyError!void {
        // A bridge only ever accepts a server connection — `acceptConnection`
        // passes `is_server = true` as a `comptime` argument — so a client
        // connection in this table is one this dialer opened, with no
        // bookkeeping of its own to keep.
        for (self.bridge.manager.entries.items) |entry| {
            if (!entry.conn.is_server) return error.DialedConnectionsLive;
        }
        std.crypto.secureZero(u8, self.seed[0..]);
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
    /// The type is the core's own and is spelled in full: an alias for it here
    /// would be private, and a public signature may not name a private type.
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
        // written at all because an all-zero `sockaddr.storage` is an address
        // family this project does not model, and `drain` would refuse the
        // first datagram it was ever asked for.
        conn.paths[0].peer_addr = toSockaddr(peer_addr);
        conn.paths[0].local_addr = toSockaddr(local);

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
    return .{ .max_idle_timeout = config.idle_timeout_ms };
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

/// This project's address as the core's `sockaddr.storage`.
///
/// The core's own address vocabulary is `vendor/quic/src/sockaddr.zig`, which
/// stands in for the `std.net.Address` Zig 0.16 removed, and it carries both
/// conversions; this is its way in, for the same reason the bridge has a
/// `fromSockaddr` as well as a `toSockaddr`. `quic_bridge.zig` has the same
/// conversion for its two directions and does not export it, so this is a
/// second copy of one `switch` — the smallest duplication in the file, and
/// unavoidable without changing a file this ticket was told not to change.
fn toSockaddr(socket: SocketAddr) posix.sockaddr.storage {
    var addr: quic.sockaddr.Address = switch (socket.ip) {
        .v4 => |octets| quic.sockaddr.Address.initIp4(octets, socket.port),
        .v6 => |octets| .{
            .in6 = .{
                .sa = .{
                    .port = std.mem.nativeToBig(u16, socket.port),
                    .flowinfo = 0,
                    .addr = octets,
                    // Zero because `SocketAddr` carries no scope. A link-local
                    // address would need one and this project has no name for it; the
                    // synthetic ULAs are not link-local, which is why the core's
                    // `scope_id` comparison can never disagree with `ula` for them.
                    .scope_id = 0,
                },
            },
        },
    };
    return quic.connection.sockaddrToStorage(&addr.any);
}

const t = std.testing;

/// Fixed seeds, so a run draws the same connection ids and the same nonces
/// every time. `generateDeterministic` fails only on a degenerate seed, which
/// a constant byte pattern is not.
const server_seed: [SecretKey.seed_length]u8 = @splat(0x53);
const client_seed: [SecretKey.seed_length]u8 = @splat(0xc1);
/// A third node, for the pin the peer does not carry.
const stranger_seed: [SecretKey.seed_length]u8 = @splat(0x3c);

/// The one ALPN both ends speak.
const alpn = "ozai";

/// Where virtual time starts: a second past zero, so nothing has timed out
/// before the first packet and every deadline below is a plain offset.
const start: Instant = 1_000 * std.time.ns_per_s;

/// A seeded generator's engine. `std.Random` is an interface over a pointer to
/// an engine, so the engine has to outlive every value handed out from it.
const Prng = std.Random.DefaultPrng;

/// The largest datagram a socket read is expected to hold — the same bound
/// `quic_bridge.zig` and `vendor/quic/src/quic/lossy_link_test.zig` use.
const max_datagram = 1500;

/// How many socket writes one drain may hand back before the room is called
/// too small.
const max_egress = 32;

/// How many passes `exchange` makes before it decides the two ends have
/// nothing left for each other.
const max_rounds = 8;

/// This node's own synthetic address, in the subnet a peer is reached on
/// before a path is chosen.
const client_host: base_ula.HostBits = .{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };

/// The address the dialler's socket is bound to, so the address the server
/// sees it come from. The peer is not named here: the relay subnets allocate
/// their host bits from the caller's generator, so the address a test dials
/// *at* is whatever `resolveRoute` drew and every test reads it back off the
/// route rather than naming it in advance.
const client_addr: SocketAddr = base_ula.socketAddrFor(.any_path, client_host);

/// A direct address standing in for a second path to the same peer.
const direct_addr: SocketAddr = .{ .ip = .{ .v4 = .{ 192, 0, 2, 7 } }, .port = 7842 };

/// The target most of these tests dial: a relay, because that is the arm the
/// synthetic subnets exist for.
///
/// Parsed rather than written out. `RelayUrl.host` is a 253-byte array with a
/// length beside it, and a hand-built one is a second way to spell a URL.
fn relayTarget() !TransportAddr {
    return .{ .relay = try base_addr.RelayUrl.parse("https://relay.example.com") };
}

/// Hand every datagram `conn` produced to `into`, and say whether it produced
/// any.
///
/// Both directions of a handshake go through this one function, which is the
/// point of the file: a dialled connection is drained, routed and re-drained
/// by the same calls an accepted one is. The sender's address is read off its
/// own active path and the receiver's off each `Egress.to`, which is what a
/// socket would have learned from `recvmsg`.
fn forward(
    conn: Conn,
    into: *Bridge,
    watch: Conn,
    log: *StateLog,
    map: *const addr_map.MappedAddrs,
    at: Instant,
    random: std.Random,
    scratch: []u8,
    egress: []Egress,
    out: []u8,
) Error!bool {
    const from = conn.local() orelse return error.UnknownAddressFamily;
    const sends = try conn.drain(egress, out, at, random);
    for (sends) |send| {
        // Through `batch.Runs` on the way, at a capability that cannot
        // segment: what is being proven here is that a dialled connection's
        // egress is something the send seam can consume at all, and
        // `batch.zig` has tests of its own for the segmentation.
        var runs = try batch.Runs.init(send.send, batch.Capability.none);
        while (runs.next()) |run| {
            const ingress = try into.recv(map, .{
                .bytes = run.contents,
                .from = from,
                .local = send.to,
                .ecn = run.ecn,
            }, scratch, at, random);
            // One reading per datagram, not per pass: the core moves a
            // connection between states inside a single `recv`, so a reading
            // taken once a half-round would step over the transition entirely.
            log.add(watch.entry.conn.state);
            switch (ingress.outcome) {
                // The receiver's own egress is picked up on the next pass, so
                // this pass has done everything it can.
                .processed, .reply, .dropped, .foreign => {},
            }
        }
    }
    return sends.len != 0;
}

/// The state a dialled connection was in after each half-round of `exchange`.
///
/// The log is the assertion: a dial is a state machine over events, and this
/// is what the events did to it, with no socket and no clock in the file.
const StateLog = struct {
    /// Sized for a handshake's worth of half-rounds, so a test that runs away
    /// stops recording rather than growing the stack.
    states: [2 * max_rounds + 4]State = undefined,
    count: usize = 0,

    fn add(self: *StateLog, state: State) void {
        if (self.count == self.states.len) return;
        self.states[self.count] = state;
        self.count += 1;
    }

    /// Whether `state` was reached at some point in the log.
    fn saw(self: *const StateLog, state: State) bool {
        for (self.states[0..self.count]) |seen| {
            if (seen == state) return true;
        }
        return false;
    }
};

/// Move datagrams between a dialled connection and the server until neither
/// has more, and record the dialled connection's state as it goes.
///
/// Time never advances here: `at` is the instant every single call is made at.
/// A handshake driven entirely in one instant is a handshake a test fully
/// controls, and the only way to get one is that nothing underneath reads a
/// clock.
fn exchange(
    dialer: *Dialer,
    conn: Conn,
    server: *Bridge,
    map: *const addr_map.MappedAddrs,
    log: *StateLog,
    at: Instant,
    random: std.Random,
) !void {
    var scratch: [2 * max_datagram]u8 = undefined;
    var egress: [max_egress]Egress = undefined;
    var out: [max_egress * max_datagram]u8 = undefined;
    var rounds: usize = 0;
    while (rounds < max_rounds) : (rounds += 1) {
        var moved = false;
        if (try forward(
            conn,
            server,
            conn,
            log,
            map,
            at,
            random,
            scratch[0..],
            egress[0..],
            out[0..],
        )) {
            moved = true;
        }
        var index: usize = 0;
        while (server.connectionAt(index)) |accepted| : (index += 1) {
            const sent = try forward(
                accepted,
                dialer.bridge,
                conn,
                log,
                map,
                at,
                random,
                scratch[0..],
                egress[0..],
                out[0..],
            );
            if (sent) moved = true;
        }
        if (!moved) break;
    }
    server.sweep();
    dialer.bridge.sweep();
}

/// A bridge and a dialer over one identity pair, plus the map they share.
///
/// A dialler and a server are two `Bridge`s, because a bridge presents one
/// identity and one manager, and the two ends of a handshake are two of
/// them. The map is the third value: a synthetic address is only a key into
/// it, and the tests that dial a relay path would be asserting nothing if the
/// same map did not stand behind both.
const Pair = struct {
    dialer_secret: SecretKey,
    server_secret: SecretKey,
    dialer_bridge: *Bridge,
    server_bridge: *Bridge,
    dialer: *Dialer,
    map: addr_map.MappedAddrs,
    engine: Prng,

    fn init(
        self: *Pair,
        dialer_seed: [SecretKey.seed_length]u8,
        server_seed_: [SecretKey.seed_length]u8,
        expect_peer: ?NodeId,
        engine_seed: u64,
        require_peer_pin: bool,
    ) !void {
        self.* = .{
            .dialer_secret = try SecretKey.fromSeed(dialer_seed),
            .server_secret = try SecretKey.fromSeed(server_seed_),
            .dialer_bridge = undefined,
            .server_bridge = undefined,
            .dialer = undefined,
            .map = addr_map.MappedAddrs.init(),
            .engine = Prng.init(engine_seed),
        };
        errdefer self.dialer_secret.deinit();
        errdefer self.server_secret.deinit();
        errdefer self.map.deinit(t.allocator);
        self.dialer_bridge = try Bridge.create(t.allocator, t.io, .{
            .secret = self.dialer_secret,
            .expect_peer = expect_peer,
            .alpn = alpn,
        }, self.engine.random());
        errdefer self.dialer_bridge.destroy();
        self.server_bridge = try Bridge.create(t.allocator, t.io, .{
            .secret = self.server_secret,
            .expect_peer = self.dialer_secret.nodeId(),
            .alpn = alpn,
        }, self.engine.random());
        errdefer self.server_bridge.destroy();
        self.dialer = try Dialer.create(t.allocator, self.dialer_bridge, .{
            .secret = self.dialer_secret,
            .alpn = alpn,
            .require_peer_pin = require_peer_pin,
        });
    }

    /// Take every dialled connection out of the table and free it, then the
    /// dialer, then the bridges.
    ///
    /// The order is the one `Dialer.destroy` refuses to invert: a live
    /// connection's handshake points at the dialer's seed, and the bridges
    /// are what free connections. A test that wants to observe
    /// `error.DialedConnectionsLive` asks for it before this runs.
    fn deinit(self: *Pair) void {
        // Backwards: `removeConnection` swap-removes from the list being walked,
        // so a forward walk skips an entry and a freed one stays behind.
        var index = self.dialer_bridge.manager.entries.items.len;
        while (index > 0) {
            index -= 1;
            const entry = self.dialer_bridge.manager.entries.items[index];
            if (!entry.conn.is_server) self.dialer_bridge.manager.removeConnection(entry);
        }
        self.dialer_bridge.sweep();
        // Every client entry was taken out and swept above, so there is
        // nothing left for `destroy` to refuse. What it refuses on is an
        // entry it opened, and the walk above swap-removes every one it
        // finds, backwards, so an entry it moves down is never one it has
        // already passed. A client entry here means the walk is wrong, which
        // is a bug to name rather than a state to unwind.
        self.dialer.destroy() catch @panic(
            "a client connection outlived the walk in Pair.deinit",
        );
        self.dialer_bridge.destroy();
        self.server_bridge.destroy();
        self.map.deinit(t.allocator);
        self.dialer_secret.deinit();
        self.server_secret.deinit();

        // Nothing here is live: the dialer and both bridges are freed and both
        // seeds are zeroed, so every field left standing is a dangling pointer
        // or a key that is no longer this node's. Left as it was, a second
        // `deinit` or any read after the `defer` would be reading freed memory
        // and would still look like a value.
        self.* = undefined;
    }
};

test "a relay target becomes one address the core is told, and the map says whose" {
    var pair: Pair = undefined;
    try pair.init(client_seed, server_seed, null, 1, true);
    defer pair.deinit();
    const peer = pair.server_secret.nodeId();

    var route_engine = Prng.init(2);
    const route = try resolveRoute(
        t.allocator,
        &pair.map,
        try relayTarget(),
        peer,
        route_engine.random(),
    );

    // Three separate answers, and the dial needs all three: the core is told
    // the address, the caller is handed the key, and `ula.classify` is what a
    // receiver on the other side will use to get the key back.
    try t.expectEqual(base_ula.Path.relay, route.subnet.?);
    try t.expectEqual(
        base_ula.Classification{ .relay = route.socket.ip.v6 },
        base_ula.classify(route.socket),
    );
    // The /64 is the relay subnet's and the host bits are this map's
    // allocation, so the address is the prefix and nothing else that is fixed.
    try t.expectEqualSlices(u8, &base_ula.prefixFor(.relay), route.socket.ip.v6[0..8]);
    try t.expectEqual(base_ula.mapped_port, route.socket.port);
    const expected_key: addr_map.Key = .{ .relay = .{
        .relay = (try relayTarget()).relay,
        .node = peer,
    } };
    try t.expectEqual(expected_key, route.key.?);
    // And the map agrees, which is what lets a sender turn an `Egress` back
    // into a peer and a relay.
    try t.expectEqual(route.key.?, ownerOf(&pair.map, route.socket).?);

    // Memoised: the same target answers with the same address for the life of
    // the map, so a second call draws no host bits and a second generator
    // cannot change the answer.
    var again_engine = Prng.init(999);
    const again = try resolveRoute(
        t.allocator,
        &pair.map,
        try relayTarget(),
        peer,
        again_engine.random(),
    );
    try t.expectEqual(route.socket, again.socket);
    try t.expectEqual(@as(usize, 1), pair.map.by_key.count());
}

test "a custom target is its own subnet, and the key owns the bytes" {
    var pair: Pair = undefined;
    try pair.init(client_seed, server_seed, null, 3, true);
    defer pair.deinit();

    var payload: [4]u8 = .{ 0xde, 0xad, 0xbe, 0xef };
    const custom: CustomAddr = .{ .id = 7, .data = payload[0..] };
    var route_engine = Prng.init(4);
    const route = try resolveRoute(
        t.allocator,
        &pair.map,
        .{ .custom = custom },
        pair.server_secret.nodeId(),
        route_engine.random(),
    );

    try t.expectEqual(base_ula.Path.custom, route.subnet.?);
    // The address is the custom /64 plus host bits, and `classify` names that
    // same subnet back out of the bytes it was handed.
    try t.expectEqualSlices(u8, &base_ula.prefixFor(.custom), route.socket.ip.v6[0..8]);
    try t.expectEqual(
        base_ula.Classification{ .custom = route.socket.ip.v6 },
        base_ula.classify(route.socket),
    );

    // The key copied the data, and the copy still reads correctly after the
    // buffer it came from has been overwritten. A key pointing into a popped
    // frame would send the peer somewhere that is not here.
    @memset(payload[0..], 0xa5);
    try t.expectEqual(@as(u8, 7), route.key.?.custom.id);
    try t.expectEqualSlices(u8, &[_]u8{ 0xde, 0xad, 0xbe, 0xef }, route.key.?.custom.dataSlice());
}

test "a direct target keeps its own address and never enters the map" {
    var pair: Pair = undefined;
    try pair.init(client_seed, server_seed, null, 5, true);
    defer pair.deinit();

    var route_engine = Prng.init(6);
    const route = try resolveRoute(
        t.allocator,
        &pair.map,
        .{ .ip = direct_addr },
        null,
        route_engine.random(),
    );

    try t.expectEqual(direct_addr, route.socket);
    try t.expectEqual(@as(?addr_map.Key, null), route.key);
    try t.expectEqual(@as(?base_ula.Path, null), route.subnet);
    try t.expectEqual(
        base_ula.Classification{ .ip = direct_addr },
        base_ula.classify(route.socket),
    );
    try t.expectEqual(@as(?addr_map.Key, null), ownerOf(&pair.map, route.socket));
    // Nothing was allocated, in either direction of the map.
    try t.expectEqual(@as(usize, 0), pair.map.by_key.count());
    try t.expectEqual(@as(usize, 0), pair.map.by_addr.count());
}

test "a custom address too long for a key is refused, not truncated" {
    var pair: Pair = undefined;
    try pair.init(client_seed, server_seed, null, 7, true);
    defer pair.deinit();

    const oversize = [_]u8{0x01} ** (base_addr.max_inline_length + 1);
    var route_engine = Prng.init(8);
    try t.expectError(
        error.DataTooLong,
        resolveRoute(
            t.allocator,
            &pair.map,
            .{ .custom = .{ .id = 1, .data = oversize[0..] } },
            pair.server_secret.nodeId(),
            route_engine.random(),
        ),
    );
    try t.expectEqual(@as(usize, 0), pair.map.by_key.count());
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
    // survived the `sockaddr.storage` round trip and `classify` still names the
    // relay subnet: the core does not validate a peer's address, and a client
    // is not even subject to the anti-amplification limit.
    try t.expectEqual(dial.route.socket, dial.conn.peer().?);
    try t.expectEqual(
        base_ula.Classification{ .relay = dial.route.socket.ip.v6 },
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
    // the relay subnet, the direct one untouched.
    try t.expectEqual(base_ula.Path.relay, over_relay.route.subnet.?);
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
