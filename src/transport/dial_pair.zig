//! Two bridges and a dialer over one identity pair, plus the map they share:
//! the fixture every dial test is closed against.
//!
//! Split out of `transport/dial.zig`, which is now the facade over it and three
//! other named modules. It is named for what it stands in for rather than for
//! being test-only: a dialled connection and an accepted one are two of
//! everything, and a test that asserted anything about a dial against one
//! bridge would be asserting against a handshake with itself. Nothing here is
//! production code, and the module doc of the facade says so where a reader
//! starts.

const std = @import("std");
const quic = @import("quic");
const base_key = @import("../base/key.zig");
const base_addr = @import("../base/addr.zig");
const base_ula = @import("../base/ula.zig");
const addr_map = @import("addr_map.zig");
const batch = @import("batch.zig");
const quic_bridge = @import("quic_bridge.zig");
const dial_client = @import("dial_client.zig");
const dial_config = @import("dial_config.zig");

const NodeId = base_key.NodeId;
const SecretKey = base_key.SecretKey;
const SocketAddr = base_addr.SocketAddr;
const TransportAddr = base_addr.TransportAddr;

pub const State = quic.connection.State;

const Bridge = quic_bridge.Bridge;
const Conn = quic_bridge.Conn;
const Egress = quic_bridge.Egress;

const Dialer = dial_client.Dialer;
const Error = dial_config.Error;
const Instant = dial_config.Instant;

const t = std.testing;

/// Fixed seeds, so a run draws the same connection ids and the same nonces
/// every time. `generateDeterministic` fails only on a degenerate seed, which
/// a constant byte pattern is not.
pub const server_seed: [SecretKey.seed_length]u8 = @splat(0x53);
pub const client_seed: [SecretKey.seed_length]u8 = @splat(0xc1);
/// A third node, for the pin the peer does not carry.
pub const stranger_seed: [SecretKey.seed_length]u8 = @splat(0x3c);

/// The one ALPN both ends speak.
pub const alpn = "ozai";

/// Where virtual time starts: a second past zero, so nothing has timed out
/// before the first packet and every deadline below is a plain offset.
pub const start: Instant = 1_000 * std.time.ns_per_s;

/// A seeded generator's engine. `std.Random` is an interface over a pointer to
/// an engine, so the engine has to outlive every value handed out from it.
pub const Prng = std.Random.DefaultPrng;

/// The largest datagram a socket read is expected to hold — the same bound
/// `quic_bridge.zig` and `vendor/quic/src/quic/lossy_link_test.zig` use.
pub const max_datagram = 1500;

/// How many socket writes one drain may hand back before the room is called
/// too small.
pub const max_egress = 32;

/// How many passes `exchange` makes before it decides the two ends have
/// nothing left for each other.
pub const max_rounds = 8;

/// This node's own synthetic address, in the subnet a peer is reached on
/// before a path is chosen.
pub const client_host: base_ula.HostBits = .{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };

/// The address the dialler's socket is bound to, so the address the server
/// sees it come from. The peer is not named here: the relay subnets allocate
/// their host bits from the caller's generator, so the address a test dials
/// *at* is whatever `resolveRoute` drew and every test reads it back off the
/// route rather than naming it in advance.
pub const client_addr: SocketAddr = base_ula.socketAddrFor(.any_path, client_host);

/// A direct address standing in for a second path to the same peer.
pub const direct_addr: SocketAddr = .{ .ip = .{ .v4 = .{ 192, 0, 2, 7 } }, .port = 7842 };

/// The target most of these tests dial: a relay, because that is the arm the
/// synthetic subnets exist for.
///
/// Parsed rather than written out. `RelayUrl.host` is a 253-byte array with a
/// length beside it, and a hand-built one is a second way to spell a URL.
pub fn relayTarget() !TransportAddr {
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
    const from = conn.local() orelse return error.NoPathAddress;
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
pub const StateLog = struct {
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
    pub fn saw(self: *const StateLog, state: State) bool {
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
pub fn exchange(
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
pub const Pair = struct {
    dialer_secret: SecretKey,
    server_secret: SecretKey,
    dialer_bridge: *Bridge,
    server_bridge: *Bridge,
    dialer: *Dialer,
    map: addr_map.MappedAddrs,
    engine: Prng,

    pub fn init(
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
    pub fn deinit(self: *Pair) void {
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
