//! The loopback transport harness: two ozai endpoints, each with its own
//! `Bridge` and its own socket, meeting for the first time on 127.0.0.1.
//!
//! Everything above the socket in this project has been tested against itself.
//! `transport/quic_bridge.zig` drives a handshake with a hand-built client
//! standing in for the peer; `transport/dial.zig` drives a dialled connection
//! against a bridge that never opens a descriptor. Neither has ever put a
//! datagram through the kernel, so nothing above `transport/socket.zig` has
//! been asked whether its half of the stack fits the other half's.
//!
//! # What is in this file and what is not
//!
//! What is here is the transport: an identity, a socket on an ephemeral port,
//! the bridge that runs that side's connections, the buffers both seams need,
//! and the flight loop that moves datagrams between two of them. What is *not*
//! here is any assertion about what those datagrams mean.
//!
//! That split is the reason this file exists at all. Two roots need a real
//! socket — `loopback_test.zig`, which asks who answered and which protocol
//! was negotiated, and `protocol_loopback_test.zig`, which asks whether gossip
//! converges — and before this file each kept its own copy of the transport.
//! Two copies of a flight loop is one copy too many: a stall report that names
//! the wrong counters is a diagnosis that points somewhere else.
//!
//! # Time is virtual and moves only when a caller says so
//!
//! There are no sleeps and no fixed ports here. `Instant` is a parameter of
//! every call into the core, so a caller that needs retransmission to fire says
//! so by advancing the instant it passes; a caller that does not pass one at
//! all gets a run in which nothing can time out. Nothing reads a clock.
//!
//! # Loss is injected, not waited for
//!
//! A loopback does not drop packets, so `Link.drop` throws a named number of
//! egress datagrams away before the socket sees them. That is the only way this
//! harness can ask the core to recover from a lossy path, and it is why the
//! loss test advances its clock instead of asserting on a link that happened to
//! be quiet.

const std = @import("std");
const ozai = @import("ozai");

const batch = ozai.transport_batch;
const addr_map = ozai.addr_map;
const bridge = ozai.transport_quic_bridge;
const quic_conn = ozai.transport_quic_conn;
const quic_config = ozai.transport_quic_config;
const dial = ozai.transport_dial;
const socket_mod = ozai.transport_socket;

pub const Bridge = bridge.Bridge;
pub const Conn = quic_conn.Conn;
pub const Egress = quic_conn.Egress;
pub const Instant = quic_conn.Instant;
pub const Dialer = dial.Dialer;
pub const Socket = socket_mod.Socket;
pub const ControlBuffer = socket_mod.ControlBuffer;

pub const NodeId = ozai.NodeId;
pub const SecretKey = ozai.SecretKey;
pub const SocketAddr = ozai.SocketAddr;

/// A seeded generator's engine, kept beside every value handed out from it:
/// `std.Random` is an interface over a pointer to the engine, so the engine
/// has to outlive the connection it seeds.
pub const Prng = std.Random.DefaultPrng;

/// The one ALPN both ends speak unless a caller says otherwise. A test that
/// wants two protocols on one wire names them itself: the point of this
/// constant is that the ordinary case does not have to.
pub const alpn = "ozai";

/// Where both sockets bind, with port zero: the kernel picks, so two runs at
/// once and a socket left over from the last one cannot collide, and nothing
/// in a test needs to be reconfigured when one of them does.
pub const loopback: SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 0 };

/// Where virtual time starts. It does not have to stay there — see the module
/// doc — but no call may be made before it.
pub const start: Instant = 1_000 * std.time.ns_per_s;

/// The largest datagram a path is expected to carry, the same bound
/// `quic_bridge.zig` and the vendored lossy-link test use.
pub const max_datagram = 1500;

/// How many socket writes one drain may hand back before the room is too
/// small. A whole flight fits; a caller that wants less learns it from
/// `error.NoRoom`.
pub const max_egress = 8;

/// Room for every datagram one drain may produce.
pub const send_room: usize = max_egress * max_datagram;

/// The core's own buffer: the datagram is copied into its front and a
/// stateless reply is written behind it, which is `Bridge.recv`'s contract and
/// the reason it is twice a datagram.
pub const scratch_room: usize = 2 * max_datagram;

/// Room for the largest list the kernel may coalesce into one read.
/// `batch.max_gro_segments_linux` is the count a socket installs when it
/// accepts `UDP_GRO`, and its own doc says a receive buffer too small for the
/// largest list truncates a coalesced read — which arrives at this seam as
/// `error.MessageTooLarge` rather than as a short datagram.
pub const receive_room: usize = @as(usize, max_datagram) * batch.max_gro_segments_linux;

/// The one protocol an ordinary link speaks, as the list `Config.alpns` takes.
/// A test that wants a server offering several passes its own.
pub const default_alpns: []const []const u8 = &.{alpn};

/// The DER `SubjectPublicKeyInfo` an ed25519 key is presented as: a fixed
/// twelve-byte header and then the 32 bytes of public key.
///
/// The header is the encoding itself — a 42-byte SEQUENCE, a 5-byte
/// `AlgorithmIdentifier` naming OID 1.3.101.112, and a BIT STRING of 33 bytes
/// with no unused bits — written out here rather than read off the dialer's
/// own certificate. A test that compares a value against the thing that
/// produced it proves nothing: this is the same 44 bytes `tls13.ed25519Spki`
/// builds, built a second time so the comparison has two sides.
pub fn spkiOf(node: NodeId) [quic_config.spki_length]u8 {
    const header = [_]u8{
        0x30, 0x2a, // SEQUENCE, 42 bytes
        0x30, 0x05, //   SEQUENCE, 5 bytes
        0x06, 0x03, 0x2b, 0x65, 0x70, //   OID 1.3.101.112, id-Ed25519
        0x03, 0x21, 0x00, //   BIT STRING, 33 bytes, no padding
    };
    var out: [quic_config.spki_length]u8 = undefined;
    @memcpy(out[0..header.len], &header);
    @memcpy(out[header.len..], &node.toBytes());
    return out;
}

/// The codepoint's own name, or `none` for a datagram that carried no
/// control message. `Ecn` has no not-ECT tag, so "zero" is an absence here.
pub fn ecnName(ecn: ?batch.Ecn) []const u8 {
    const set = ecn orelse return "none";
    return @tagName(set);
}

/// Whether `side` holds a connection the core says is established.
pub fn established(side: *Side) bool {
    var index: usize = 0;
    while (side.bridge.connectionAt(index)) |conn| : (index += 1) {
        if (conn.established()) return true;
    }
    return false;
}

/// The handshake phase's goal: both ends agree the connection is up, neither
/// because it was told so and neither before the other.
pub fn bothUp(client: *Side, server: *Side) bool {
    return established(client) and established(server);
}

/// What one side is built with beyond its identity.
///
/// The defaults are the ordinary case, so a test that only cares about a
/// handshake names four fields and says nothing else. The remaining fields
/// exist because the transport's optional features are all off by default in
/// `quic_config.Config` — DATAGRAM needs a frame size on *both* ends or the
/// core leaves the extension disabled for the whole connection — and a caller
/// that has to know that to turn a feature on should not also have to know it
/// to leave it off.
pub const SideConfig = struct {
    name: []const u8,
    secret: SecretKey,
    /// The peer this side insists on, when it knows one before the handshake.
    expect_peer: ?NodeId = null,
    /// The protocols this side offers, in preference order: the server picks the
    /// first of these the peer also named. See `Config.alpns`.
    alpns: []const []const u8 = default_alpns,
    engine_seed: u64,
    /// The DATAGRAM transport parameter. Null leaves RFC 9221 unadvertised.
    max_datagram_frame_size: ?u64 = null,
    /// The unidirectional stream limit this side advertises. Null is the
    /// core's own default.
    initial_max_streams_uni: ?u64 = null,
    /// The send window this side grants on each unidirectional stream the peer
    /// opens. Null is the core's own 1 MiB; set it to make a `NoSendCredit`
    /// boundary reachable without a megabyte allocation.
    initial_max_stream_data_uni: ?u64 = null,
    /// Whether this side answers an Initial with a Retry rather than with a
    /// connection. Off by default; nothing else in the transport asks for it.
    require_retry: bool = false,
    /// How many validated addresses accumulate before this side starts
    /// answering with a Retry. Null means it never does on its own.
    retry_threshold: ?usize = null,
};

/// One endpoint: an identity, a socket on an ephemeral loopback port, the
/// bridge that runs its connections, and the buffers the send and receive
/// seams need.
///
/// The buffers are on the heap because the receive one is 96 KB. A test that
/// overflows the stack fails for a reason that has nothing to do with QUIC,
/// and every buffer here is the caller's by the seam's own contract.
pub const Side = struct {
    name: []const u8,
    socket: Socket,
    bridge: *Bridge,
    map: addr_map.MappedAddrs,
    engine: Prng,
    egress: []Egress,
    out: []u8,
    scratch: []u8,
    buf: []u8,
    control: ControlBuffer,

    pub fn init(self: *Side, config: SideConfig) !void {
        self.* = .{
            .name = config.name,
            .socket = undefined,
            .bridge = undefined,
            .map = addr_map.MappedAddrs.init(),
            .engine = Prng.init(config.engine_seed),
            .egress = &.{},
            .out = &.{},
            .scratch = &.{},
            .buf = &.{},
            .control = undefined,
        };
        errdefer self.map.deinit(std.testing.allocator);
        // The bind happens inside `create`, so the address this side is
        // reachable at is only known once the socket exists. That is why the
        // dialling side is dialled at this side's address rather than at one
        // the test made up.
        self.socket = try Socket.create(loopback, .{});
        errdefer self.socket.close();
        // Both transport keys are supplied rather than drawn from `t.io`: a
        // test whose Retry key differs on every run has failures that move.
        self.bridge = try Bridge.create(std.testing.allocator, std.testing.io, .{
            .secret = config.secret,
            .expect_peer = config.expect_peer,
            .alpns = config.alpns,
            .retry_token_key = @splat(0x11),
            .static_reset_key = @splat(0x22),
            .max_datagram_frame_size = config.max_datagram_frame_size,
            .initial_max_streams_uni = config.initial_max_streams_uni,
            .initial_max_stream_data_uni = config.initial_max_stream_data_uni,
            .require_retry = config.require_retry,
            .retry_threshold = config.retry_threshold,
        }, self.random());
        errdefer self.bridge.destroy();
        self.egress = try std.testing.allocator.alloc(Egress, max_egress);
        errdefer std.testing.allocator.free(self.egress);
        self.out = try std.testing.allocator.alloc(u8, send_room);
        errdefer std.testing.allocator.free(self.out);
        // The core's own buffer: the datagram is copied into its front and a
        // stateless reply is written behind it, which is `Bridge.recv`'s
        // contract and the reason it is twice a datagram.
        self.scratch = try std.testing.allocator.alloc(u8, scratch_room);
        errdefer std.testing.allocator.free(self.scratch);
        self.buf = try std.testing.allocator.alloc(u8, receive_room);
        errdefer std.testing.allocator.free(self.buf);
    }

    pub fn deinit(self: *Side) void {
        self.bridge.destroy();
        std.testing.allocator.free(self.egress);
        std.testing.allocator.free(self.out);
        std.testing.allocator.free(self.scratch);
        std.testing.allocator.free(self.buf);
        self.map.deinit(std.testing.allocator);
        self.socket.close();
        self.* = undefined;
    }

    /// A generator over this side's own engine, good until the next call.
    pub fn random(self: *Side) std.Random {
        return self.engine.random();
    }

    /// The connection this side holds that the core says is established, or
    /// null when it holds none.
    ///
    /// Found by index rather than by a handle the caller was handed, because an
    /// accepted connection has no other way in and the dialled one has to be
    /// found the same way or the dial path becomes a second implementation.
    pub fn live(self: *const Side) ?Conn {
        var index: usize = 0;
        while (self.bridge.connectionAt(index)) |conn| : (index += 1) {
            if (conn.established()) return conn;
        }
        return null;
    }

    /// Copy whatever a stream the peer opened has delivered into `out`, and
    /// say how many bytes came.
    ///
    /// Two things about the read, both of them the application's problem
    /// rather than the core's. There is no accept-side accessor — a stream
    /// arrives by being written to on the wire, and the connection's own
    /// stream map is then the only place it is readable, so `getStream` is
    /// that map's accessor. And `recv.read` hands the caller ownership of a
    /// whole allocation (`FrameSorter.pop` pops one chunk and the application
    /// frees it), which is why the copy is made here and the core's bytes are
    /// released before this returns.
    pub fn takeStream(self: *Side, stream_id: u64, out: []u8) usize {
        const conn = self.bridge.connectionAt(0) orelse return 0;
        const opened = conn.entry.conn.streams.getStream(stream_id) orelse return 0;
        const chunk = opened.recv.read() orelse return 0;
        defer std.testing.allocator.free(chunk);
        const taken = @min(chunk.len, out.len);
        @memcpy(out[0..taken], chunk[0..taken]);
        return taken;
    }
};

/// How the two sides of a `Link` differ from the ordinary case.
///
/// Split in two rather than taking two whole `SideConfig`s because the fields
/// that must agree between the ends — the pins, the seeds, the transport keys —
/// are the ones `Link.init` already derives from the two secrets it is given.
/// What a test varies is per side and per dial, and nothing else.
pub const LinkOptions = struct {
    /// What the client offers. Empty is the ordinary one-protocol default.
    client_alpns: []const []const u8 = &.{},
    /// What the server offers, in preference order. Empty is the default.
    server_alpns: []const []const u8 = &.{},
    /// What the dialer offers, which is not always what the client's bridge
    /// offers: a dial is the only place a peer chooses its own list. Empty is
    /// the client's own, and then that is the default.
    dial_alpns: []const []const u8 = &.{},
    /// The SNI this dial sends, when a test needs one other than the dialer's
    /// own default. Null leaves that default in place rather than restating it
    /// here, which is also why the field is nullable: nothing in the harness
    /// owns the ordinary name.
    ///
    /// It is the only ClientHello field a caller controls that has no
    /// ceiling — RFC 6066 sets none and the core writes whatever the name's
    /// length field encodes (`vendor/quic/src/quic/tls13.zig:4320-4336`) — so
    /// a test that needs a ClientHello longer than one datagram, and cannot
    /// say so with protocol names (a name past what a selection holds is not
    /// an offer at all, and `Dialer.create` refuses one), says so here.
    dial_server_name: ?[]const u8 = null,
    /// Set on both bridges or on neither: DATAGRAM comes up only when both
    /// ends advertise a frame size.
    max_datagram_frame_size: ?u64 = null,
    /// Set on both bridges or on neither, and only to a number small enough to
    /// drive a refusal.
    initial_max_streams_uni: ?u64 = null,
    /// Set on both bridges or on neither. This is the window the *peer* grants,
    /// so it is what a `NoSendCredit` boundary is measured against.
    initial_max_stream_data_uni: ?u64 = null,
    /// Applied to the accepting side alone: a Retry is something a server
    /// answers with.
    server_require_retry: bool = false,
    server_retry_threshold: ?usize = null,
};

/// `want` when a test named some protocols, the default otherwise.
///
/// An empty option is "the ordinary case" rather than "offer nothing": a side
/// that offers no protocol at all is a real thing — it is what
/// `Router.offers` returns for an unconfigured endpoint — but it is not what a
/// harness option should mean, because the caller wrote the field to vary
/// something and leaving it unset is not that.
fn offered(want: []const []const u8, fallback: []const []const u8) []const []const u8 {
    return if (want.len == 0) fallback else want;
}

/// The two endpoints and the bookkeeping that makes a stall readable.
///
/// Index 0 is the dialling side and index 1 the accepting one, everywhere in
/// this struct.
pub const Link = struct {
    client: Side,
    server: Side,
    dialer: *Dialer,
    /// The connection `Dialer.dial` handed back, kept only to prove that the
    /// bridge finds the same one by index. It is a borrowed handle: `deinit`
    /// frees it, and nothing may read it afterwards.
    dialled: Conn,
    /// Datagrams each side wrote to its socket and read off it.
    ///
    /// **Datagrams, not socket writes**, and the difference is one this
    /// harness was built to hide: `Conn.drain` hands back *runs*, not
    /// datagrams, and a run is several datagrams of one size in one
    /// segmented `sendmsg` (`quic_conn.zig:122-128`, `socket.zig:296-301`).
    /// Two Initial packets carrying one ClientHello are both padded to the
    /// 1200-byte floor of RFC 9000 §14.1 and therefore *the same size*, so
    /// they are one run — a counter that counted runs would report a
    /// ClientHello split across two datagrams as one datagram, and every
    /// comparison below a datagram count would be quietly off. `received`
    /// was always `Recv.datagramCount`; `sent` is now the same unit, and
    /// `report` prints the two beside each other as datagrams.
    ///
    /// The one place that is not a conversion is `take`'s stateless reply,
    /// which stays at one: a Retry, a Version Negotiation and a stateless
    /// reset are each a whole datagram by construction (`Ingress.reply` is
    /// built with `batch.Send.single`), so there is nothing there to measure.
    sent: [2]usize = .{ 0, 0 },
    received: [2]usize = .{ 0, 0 },
    /// Connections the core declared finished, which leaves the table but
    /// keeps its memory until `sweep`.
    finished: [2]usize = .{ 0, 0 },
    /// Egress runs still to be discarded, per side. See the module doc.
    /// A run rather than a datagram count, because a loss test drops a whole
    /// thing the core built: dropping half a segmented run would be a
    /// truncation, not the loss a packet number and a PTO stand for.
    drop: [2]usize = .{ 0, 0 },
    /// Datagrams that were discarded, per side — the datagram count of the
    /// runs `drop` retired. A stall report prints it, because a side that
    /// dropped four of them and says only "no traffic" is a diagnosis that
    /// hides its own cause.
    dropped: [2]usize = .{ 0, 0 },
    ecn: [2]Cods = .{ .{}, .{} },

    /// What each side marked on the wire and what each side read off the
    /// wire.
    ///
    /// Counts rather than a single remembered value, because a handshake is
    /// sent not-ECT — which is `Ecn`'s null, not a fourth codepoint — and the
    /// core only starts marking once the handshake confirms. The counts are
    /// what say the marking ever happened.
    pub const Cods = struct {
        marked: usize = 0,
        saw: usize = 0,
        lost: usize = 0,
        last_sent: ?batch.Ecn = null,
        last_seen: ?batch.Ecn = null,
    };

    pub fn init(
        self: *Link,
        client_secret: SecretKey,
        server_secret: SecretKey,
        pinned: NodeId,
        engine_seed: u64,
        options: LinkOptions,
    ) !void {
        self.* = .{
            .client = undefined,
            .server = undefined,
            .dialer = undefined,
            .dialled = undefined,
        };
        // Unwound in the one order `Dialer.destroy` refuses to invert: a
        // dialled connection's handshake points at the dialer's own seed, so
        // the dialer goes before the bridges. Errdefers run in reverse of
        // declaration, so the dialer is named last.
        // Both paths go through `closeDialed`, so the teardown an unwinding
        // `init` performs is the teardown a finished test performs and the two
        // cannot drift apart.
        var client_live = false;
        var server_live = false;
        var dialer_live = false;
        errdefer if (client_live) self.client.deinit();
        errdefer if (server_live) self.server.deinit();
        errdefer if (dialer_live) self.closeDialed();

        // The client first: the dial below is handed the address this socket
        // came back bound to, and it cannot be dialled without one.
        try self.client.init(.{
            .name = "client",
            .secret = client_secret,
            .alpns = offered(options.client_alpns, default_alpns),
            .engine_seed = engine_seed,
            .max_datagram_frame_size = options.max_datagram_frame_size,
            .initial_max_streams_uni = options.initial_max_streams_uni,
            .initial_max_stream_data_uni = options.initial_max_stream_data_uni,
        });
        client_live = true;
        try self.server.init(.{
            .name = "server",
            .secret = server_secret,
            .expect_peer = client_secret.nodeId(),
            .alpns = offered(options.server_alpns, default_alpns),
            .engine_seed = engine_seed + 1,
            .max_datagram_frame_size = options.max_datagram_frame_size,
            .initial_max_streams_uni = options.initial_max_streams_uni,
            .initial_max_stream_data_uni = options.initial_max_stream_data_uni,
            .require_retry = options.server_require_retry,
            .retry_threshold = options.server_retry_threshold,
        });
        server_live = true;
        var dialer_config: dial.Config = .{
            .secret = client_secret,
            .alpns = offered(options.dial_alpns, offered(options.client_alpns, default_alpns)),
            .max_datagram_frame_size = options.max_datagram_frame_size,
            .initial_max_streams_uni = options.initial_max_streams_uni,
            .initial_max_stream_data_uni = options.initial_max_stream_data_uni,
        };
        // After the literal, so the ordinary case names no SNI at all and the
        // dialer's own default is what the core is handed.
        if (options.dial_server_name) |name| dialer_config.server_name = name;
        self.dialer = try Dialer.create(std.testing.allocator, self.client.bridge, dialer_config);
        dialer_live = true;
        // A direct target, so the address the core is told is the server's
        // real one and no synthetic subnet is involved: this harness is about
        // the socket, and a relay path would test the map instead.
        self.dialled = (try self.dialer.dial(
            .{ .ip = self.server.socket.address },
            pinned,
            self.client.socket.address,
            &self.client.map,
            start,
            self.client.random(),
        )).conn;
    }

    pub fn deinit(self: *Link) void {
        self.closeDialed();
        self.client.deinit();
        self.server.deinit();
        self.* = undefined;
    }

    /// Take the dialled connections out of the client's bridge, then free the
    /// dialer that opened them.
    ///
    /// `Dialer.destroy` refuses while one is still in the table, so the
    /// removal is what makes the call that follows it possible. It walks
    /// backwards because `removeConnection` swap-removes and a forward walk
    /// would skip an entry and leave a freed one behind, and `sweep` frees
    /// what the core declared finished.
    ///
    /// A refusal is not returned, because neither caller can return one: the
    /// normal teardown is a `defer` and the unwinding one an `errdefer`, and
    /// neither may `return`. So it is reported the way a stall is reported —
    /// the counts and both ends' connection states are exactly what says
    /// whether a connection outlived the dialer or arrived after this walk —
    /// and then logged at error level, which is the one thing an artifact
    /// wearing `test/expected_log_runner.zig` turns into a failed run beyond
    /// the message `build.zig` names. `destroy` returns before it frees, so a
    /// refusal has left the dialer allocated and the leak checker says so in
    /// this run; the log is what stops the step passing with the teardown
    /// named only in a leak trace.
    pub fn closeDialed(self: *Link) void {
        var index = self.client.bridge.manager.entries.items.len;
        while (index > 0) {
            index -= 1;
            const entry = self.client.bridge.manager.entries.items[index];
            if (!entry.conn.is_server) self.client.bridge.manager.removeConnection(entry);
        }
        self.client.bridge.sweep();
        self.dialer.destroy() catch |err| {
            self.report("teardown", "a dialled connection outlived its dialer");
            std.log.err("loopback teardown: the dialer was not freed: {t}", .{err});
        };
    }

    /// The side at `which`: 0 is the dialling end, 1 the accepting one.
    pub fn of(self: *Link, which: usize) *Side {
        return if (which == 0) &self.client else &self.server;
    }

    /// Drain everything on one side's connections and write each datagram to
    /// the peer's real socket, then take whatever is waiting on the other.
    ///
    /// Both directions go through `Socket.send` and `Socket.tryReceive`, so a
    /// datagram is a `sendmsg` and a `recvmsg` here exactly as it would be in
    /// production — including the traffic-class and segment control messages
    /// `batch.zig` models, which is the only reason the codepoint assertions
    /// mean anything.
    ///
    /// A datagram this side is set to drop never reaches the socket and is not
    /// counted as moved: the run really did lose it, and a caller reading
    /// `sent` is reading what the wire saw.
    pub fn step(self: *Link, from: usize, into: usize, at: Instant) !bool {
        const sender = self.of(from);
        var moved = false;
        var index: usize = 0;
        // Found by index, never by a handle the caller was handed: an accepted
        // connection has no other way in, and the dialled one has to be found
        // the same way or the dial path is a second implementation.
        while (sender.bridge.connectionAt(index)) |conn| : (index += 1) {
            for (try conn.drain(sender.egress, sender.out, at, sender.random())) |egress| {
                // How many datagrams this one egress carries, which is not
                // one. A run is every datagram of one size the core produced
                // back to back, and `Socket.send` puts the whole run in one
                // segmented `sendmsg` — so the datagrams that reached the
                // wire are `datagramCount`, and counting the run instead is
                // a counter that reads a two-datagram flight as one.
                const datagrams = egress.send.datagramCount();
                if (self.drop[from] != 0) {
                    self.drop[from] -= 1;
                    self.dropped[from] += datagrams;
                    continue;
                }
                const went = try sender.socket.send(std.testing.io, egress.to, egress.send);
                if (!went.ecnSurvived()) self.ecn[from].lost += 1;
                if (went.carried) |set| {
                    self.ecn[from].marked += 1;
                    self.ecn[from].last_sent = set;
                }
                self.sent[from] += datagrams;
                moved = true;
            }
        }
        // Timers after the sends, so a connection that owes a retransmission
        // gets the chance to produce one in this round rather than the next.
        // `tick` may take a finished connection out of the table, which shifts
        // what the index walk sees; every round walks it again and the count
        // is in the stall report, so a skipped tick costs a round and not a
        // correctness answer.
        var scan: usize = 0;
        while (sender.bridge.connectionAt(scan)) |conn| : (scan += 1) {
            if (sender.bridge.tick(conn, at, sender.random()) == .finished) {
                self.finished[from] += 1;
            }
        }
        return if (try self.take(into, at)) true else moved;
    }

    /// Take everything queued on one side's socket and hand it to that side's
    /// bridge.
    ///
    /// A read is not one datagram: `UDP_GRO` may have coalesced a burst into
    /// one buffer, so the stride is what says how many packets there are and
    /// the bridge is handed them one at a time — which is what `Datagram`
    /// documents, since two packets sharing one buffer would leave the core
    /// with two replies pointing at the same bytes.
    pub fn take(self: *Link, which: usize, at: Instant) !bool {
        const side = self.of(which);
        var moved = false;
        while (true) {
            const sock = &side.socket;
            const got = sock.tryReceive(
                std.testing.io,
                side.buf,
                &side.control,
            ) catch |err| switch (err) {
                // The socket is non-blocking from the moment it was created,
                // and an empty queue is a fact the loop acts on rather than a
                // failure.
                error.WouldBlock => break,
                else => return err,
            };
            const recv = try got.toRecv();
            self.received[which] += recv.datagramCount();
            if (recv.ecn) |set| {
                self.ecn[which].saw += recv.datagramCount();
                self.ecn[which].last_seen = set;
            }
            var position: usize = 0;
            while (position < recv.datagramCount()) : (position += 1) {
                const ingress = try side.bridge.recv(&side.map, .{
                    // The loop's bound is `recv.datagramCount()`, and
                    // `Recv.datagram` answers null only past that count.
                    // zwanzig-disable-next-line: optional-unwrap
                    .bytes = recv.datagram(position).?,
                    .from = got.from,
                    .local = side.socket.address,
                    .ecn = recv.ecn,
                }, side.scratch, at, side.random());
                moved = true;
                switch (ingress.outcome) {
                    // Nothing to do here: the connection this datagram belongs
                    // to is drained by the next `step`, which finds it by
                    // index.
                    .processed => {},
                    // A stateless reply is a send, so it goes back out of the
                    // same socket to the address the datagram came from.
                    .reply => |reply| {
                        self.sent[which] += 1;
                        _ = try side.socket.send(std.testing.io, ingress.source.socket, reply);
                    },
                    .dropped, .foreign => {},
                }
            }
        }
        return moved;
    }

    /// One pass of the whole link: everything the client has, then everything
    /// the server has. A round is one flight in each direction.
    pub fn exchange(self: *Link, at: Instant) !bool {
        const moved = try self.step(0, 1, at);
        return (try self.step(1, 0, at)) or moved;
    }

    /// Move datagrams both ways until `goal` holds, or until the bound is
    /// reached.
    ///
    /// There is no timer in here. `at` is one instant for the whole run, so
    /// nothing but the state machines or the bound can end this loop — which
    /// is the property the pure layers were built for, and also the reason a
    /// stall here is a finding about the stack rather than a flake about a
    /// loaded machine. A caller that injected loss has to drive the loop
    /// itself, because a run with a fixed instant can never retransmit what it
    /// dropped.
    pub fn drive(self: *Link, at: Instant, max_rounds: usize, goal: fn (*Side, *Side) bool) !void {
        var round: usize = 0;
        while (round < max_rounds) : (round += 1) {
            if (goal(&self.client, &self.server)) return;
            if (!try self.exchange(at)) {
                self.report("stalled", "a whole round moved no datagram in either direction");
                return error.Stalled;
            }
        }
        if (goal(&self.client, &self.server)) return;
        self.report("stalled", "the round bound was reached before both ends were there");
        return error.Stalled;
    }

    /// Print what a failure looks like from the inside: what kind of failure
    /// it is, the datagrams each side moved, the codepoints it marked and
    /// read, and the state of every connection on it.
    ///
    /// "Handshake failed" on a pair that never exchanged a datagram is not a
    /// diagnosis. This is: a side that sent two datagrams and received none
    /// is a different finding from one that moved traffic both ways and never
    /// settled, and only the counts say which.
    pub fn report(self: *Link, what: []const u8, reason: []const u8) void {
        std.debug.print("\nloopback {s}: {s}\n", .{ what, reason });
        for (0..2) |which| {
            const side = self.of(which);
            std.debug.print(
                "  {s} at {f}: {d} sent, {d} received, {d} dropped, ecn {d} marked, {d} seen, {d} lost\n",
                .{
                    side.name,
                    side.socket.address,
                    self.sent[which],
                    self.received[which],
                    self.dropped[which],
                    self.ecn[which].marked,
                    self.ecn[which].saw,
                    self.ecn[which].lost,
                },
            );
            std.debug.print("    last codepoint: {s} out, {s} in\n", .{
                ecnName(self.ecn[which].last_sent),
                ecnName(self.ecn[which].last_seen),
            });
            var index: usize = 0;
            while (side.bridge.connectionAt(index)) |conn| : (index += 1) {
                std.debug.print(
                    "    conn {d}: state {t}, established {}, closed {}, peer {f}\n",
                    .{
                        conn.id(),
                        conn.entry.conn.state,
                        conn.established(),
                        conn.closed(),
                        conn.peer() orelse side.socket.address,
                    },
                );
            }
            const held = side.bridge.manager.connectionCount();
            std.debug.print("    connections held: {d}\n", .{held});
        }
        const out_total = self.sent[0] + self.sent[1];
        const in_total = self.received[0] + self.received[1];
        std.debug.print(
            "  the exchange stopped at datagram {d}: {d} written, {d} read back\n",
            .{ out_total, out_total, in_total },
        );
        std.debug.print(
            "  connections the core declared finished: {d}\n",
            .{self.finished[0] + self.finished[1]},
        );
    }
};
