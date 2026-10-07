//! The peer's half of a handshake, and the constants a bridge test drives it
//! with: the client connection standing in for the other end, the two synthetic
//! addresses, the fixed seeds, the instant that never moves, and the two
//! functions that move datagrams between the two ends.
//!
//! Split out of `transport/quic_bridge.zig`, which is now the facade over it
//! and five other named modules. It is named for what it stands in for rather
//! than for being test-only: `ConnectionManager` only ever runs a server, so
//! the other half of a handshake has to be built by hand exactly as
//! `vendor/quic/src/quic/lossy_link_test.zig` builds it, and every test that
//! proves a handshake finishes needs the same one. Nothing here is production
//! code, and the module doc of the facade says so where a reader starts.

const std = @import("std");
const quic = @import("quic");
const base_key = @import("../base/key.zig");
const base_addr = @import("../base/addr.zig");
const base_ula = @import("../base/ula.zig");
const addr_map = @import("addr_map.zig");
const batch = @import("batch.zig");
const bridge_address = @import("bridge_address.zig");
const bridge_config = @import("bridge_config.zig");
const bridge_conn = @import("bridge_conn.zig");
const bridge_manager = @import("bridge_manager.zig");

const NodeId = base_key.NodeId;
const SecretKey = base_key.SecretKey;
const SocketAddr = base_addr.SocketAddr;

const tls13 = quic.tls13;

const Instant = bridge_config.Instant;
const seed_length = bridge_config.seed_length;
const spki_length = bridge_config.spki_length;

const toCoreAddress = bridge_address.toCoreAddress;

const Conn = bridge_conn.Conn;
const Egress = bridge_conn.Egress;
const min_datagram = bridge_conn.min_datagram;

const Bridge = bridge_manager.Bridge;

const t = std.testing;

/// A client's own synthetic address, in the subnet a node is reached on
/// before a path is chosen.
pub const client_host: base_ula.HostBits = .{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
/// The server's, in the relay subnet — a relay path is the case
/// `docs/PLAN.md`'s mapping exists for, so it is the one these tests drive.
pub const server_host: base_ula.HostBits = .{ 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };

/// How the client and the server each see the other, as this project
/// addresses it. Both are synthetic: the core never sees a real IP here.
pub const client_addr: SocketAddr = base_ula.socketAddrFor(.any_path, client_host);
pub const server_addr: SocketAddr = base_ula.socketAddrFor(.relay, server_host);

/// Fixed seeds, so a run draws the same connection ids and the same nonces
/// every time. `generateDeterministic` fails only on a degenerate seed,
/// which a constant byte pattern is not.
pub const server_seed: [SecretKey.seed_length]u8 = @splat(0x53);
pub const client_seed: [SecretKey.seed_length]u8 = @splat(0xc1);

/// The one ALPN both ends speak.
pub const alpn = "ozai";

/// The name the client asks for. Nothing resolves it and nothing checks it:
/// there is no certificate to match a name against, only a key to compare.
pub const server_name = "ozai.invalid";

/// Where virtual time starts: a second past zero, so nothing has timed out
/// before the first packet and every deadline below is a plain offset.
pub const start: Instant = 1_000 * std.time.ns_per_s;

/// Seeded engine kept stable while calls use its `std.Random` interface.
pub const Prng = std.Random.DefaultPrng;

/// Fixture datagram capacity, matching the core packer's 1500-byte ceiling.
pub const max_datagram = 1500;

/// The core's floor for a datagram, re-exported rather than written down: a
/// test that pads to its own idea of 1200 would keep passing if the core's
/// floor moved. The same value `Conn.drain` refuses a short buffer against.
pub const min_initial = min_datagram;

/// How many socket writes one `drain` hands back. A connection's whole flight
/// fits; a caller that wants fewer gets a short answer rather than a refusal
/// — see `Conn.drain` — and asks again for the rest.
pub const max_egress = 32;

/// How many datagrams `exchange` moves before it decides the two ends have
/// nothing left for each other.
pub const max_rounds = 8;

/// A long header for a version the core does not speak, padded to the size
/// RFC 9000 §14.1 requires before a server will spend anything on it.
///
/// This is the cheapest thing the core consults a timer for: it reaches its
/// Version Negotiation reply limiter and nothing else, and no connection is
/// created, so a test can drive `recv` without a handshake.
pub fn unsupportedVersionProbe() [min_initial]u8 {
    var bytes = [_]u8{0} ** min_initial;
    // Long header (0x80), fixed bit (0x40), packet type 0b00.
    bytes[0] = 0xc0;
    std.mem.writeInt(u32, bytes[1..5], 0x0a0a0a0a, .big);
    bytes[5] = 8; // destination connection id length
    @memset(bytes[6..14], 0x5a);
    bytes[14] = 8; // source connection id length
    @memset(bytes[15..23], 0x3c);
    // A zero token length and a zero payload length. The rest stays zero, so
    // the next byte the routing loop looks at has the fixed bit clear and it
    // stops there — one packet in the datagram, which is what it claims to be.
    return bytes;
}

/// A client connection, standing in for the peer's half of a relay path.
///
/// `quic.ConnectionManager` only ever runs a server — there is no client arm
/// of it — so the other half of a handshake is built the way
/// `vendor/quic/src/quic/lossy_link_test.zig` builds it: a `Connection` and a
/// `TlsConfig` the caller's node id is pinned into. That is not a gap in this
/// file, it is the core's shape.
///
/// Built in place rather than returned by value because its config points at
/// its own `spki`: a returned struct is moved into the caller's frame and the
/// pointer would dangle.
pub const Client = struct {
    conn: *quic.connection.Connection,
    engine: Prng,
    /// The certificate this client presents, and the seed behind it, kept
    /// here for as long as the config points at them.
    spki: [spki_length]u8,
    cert_chain: [1][]const u8,
    alpn_list: [1][]const u8,
    seed: [seed_length]u8,
    /// The send-side scratch, and the core's mutable read buffer beside it so
    /// a datagram going each way never shares bytes.
    buffer: [max_datagram]u8 = undefined,
    inbound: [max_datagram]u8 = undefined,

    pub fn init(
        self: *Client,
        secret: SecretKey,
        expect: ?NodeId,
        engine_seed: u64,
        at: Instant,
    ) !void {
        self.* = .{
            .conn = undefined,
            .engine = Prng.init(engine_seed),
            .spki = undefined,
            .cert_chain = undefined,
            .alpn_list = undefined,
            .seed = secret.toBytes()[0..seed_length].*,
        };
        self.spki = tls13.ed25519Spki(&secret.nodeId().toBytes());
        self.cert_chain = .{self.spki[0..]};
        self.alpn_list = .{alpn};
        self.conn = try t.allocator.create(quic.connection.Connection);
        errdefer t.allocator.destroy(self.conn);
        try quic.connection.connectInto(
            self.conn,
            t.allocator,
            server_name,
            .{},
            .{
                .cert_chain_der = &.{},
                .private_key_bytes = &.{},
                .alpn = &self.alpn_list,
                .server_name = server_name,
                // The client's own pin on the server — the one field of the
                // core's config a client actually reads. The bridge sets the
                // mirror image of it on the server side; see `buildTlsConfig`.
                .expect_peer_node_id = if (expect) |peer| peer.toBytes() else null,
                .client_certificate = .{
                    .cert_chain_der = &self.cert_chain,
                    .private_key_bytes = self.seed[0..],
                    .private_key_algorithm = .ed25519,
                },
            },
            null,
            at,
            self.random(),
        );
        self.conn.paths[0].peer_addr = toCoreAddress(server_addr);
        self.conn.paths[0].local_addr = toCoreAddress(client_addr);
    }

    pub fn deinit(self: *Client) void {
        self.conn.deinit();
        t.allocator.destroy(self.conn);

        // The connection is freed, and nothing else in here outlives it: the
        // handshake's config points at `spki` and `alpn_list`, which is why
        // this struct was built in place rather than returned. Left standing,
        // a second `deinit` or a read after the `defer` would walk a connection
        // that is already back in the testing allocator.
        self.* = undefined;
    }

    pub fn random(self: *Client) std.Random {
        return self.engine.random();
    }

    /// Hand one datagram to the client, as a socket would. Everything the
    /// client ever receives comes from the server, so there is one address.
    ///
    /// The core takes its input as `[]u8` because it decrypts in place, so
    /// the datagram is copied in from the send seam's slice. It is the same
    /// copy `Bridge.recv` makes and for the same reason: the read buffer
    /// belongs to whoever owns it, and the core does not get to keep a
    /// pointer into somebody else's.
    pub fn receive(self: *Client, bytes: []const u8, at: Instant) void {
        std.debug.assert(bytes.len <= self.inbound.len);
        @memcpy(self.inbound[0..bytes.len], bytes);
        self.conn.handleDatagram(self.inbound[0..bytes.len], .{
            .to = toCoreAddress(client_addr),
            .from = toCoreAddress(server_addr),
            .datagram_size = bytes.len,
        }, at, self.random());
    }
};

/// Drain a connection and hand every datagram it produced to the client.
///
/// The runs go through `batch.Runs` on the way, at a capability that cannot
/// segment: a test that wanted to prove the batching would pass
/// `Capability.linux_full` and count the runs, and `batch.zig` has tests of
/// its own for that. What this proves is that what the bridge hands over is
/// something the send seam can consume at all.
pub fn deliver(
    conn: Conn,
    client: *Client,
    egress: []Egress,
    out: []u8,
    at: Instant,
) !bool {
    const sends = try conn.drain(egress, out, at, client.random());
    for (sends) |send| {
        var runs = try batch.Runs.init(send.send, batch.Capability.none);
        while (runs.next()) |run| client.receive(run.contents, at);
    }
    return sends.len != 0;
}

/// Move datagrams between the client and the bridge until neither has more.
///
/// Time never advances here: `at` is the instant every single call is made
/// at. That is the point of the whole design — a handshake driven entirely in
/// one instant is a handshake a test fully controls, and the only way to get
/// one is that nothing underneath reads a clock.
pub fn exchange(
    client: *Client,
    bridge: *Bridge,
    map: *const addr_map.MappedAddrs,
    at: Instant,
) !void {
    var scratch: [2 * max_datagram]u8 = undefined;
    var egress: [max_egress]Egress = undefined;
    var out: [max_egress * max_datagram]u8 = undefined;
    var rounds: usize = 0;
    while (rounds < max_rounds) : (rounds += 1) {
        var moved = false;
        while (true) {
            const len = client.conn.sendAt(&client.buffer, at, client.random()) catch break;
            if (len == 0) break;
            const ingress = try bridge.recv(map, .{
                .bytes = client.buffer[0..len],
                .from = client_addr,
                .local = server_addr,
                .ecn = null,
            }, scratch[0..], at, client.random());
            switch (ingress.outcome) {
                .processed => |conn| {
                    if (try deliver(conn, client, egress[0..], out[0..], at)) moved = true;
                },
                .reply => |reply| {
                    client.receive(reply.contents, at);
                    moved = true;
                },
                // Nothing to move and nothing to answer.
                .dropped, .foreign => {},
            }
        }
        if (!moved) break;
    }
    bridge.sweep();
}
