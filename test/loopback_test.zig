//! Loopback integration: two ozai endpoints, each with its own `Bridge` and
//! its own socket, meeting for the first time on 127.0.0.1.
//!
//! Everything above the socket in this project has been tested against itself.
//! `transport/quic_bridge.zig` drives a handshake with a hand-built client
//! standing in for the peer; `transport/dial.zig` drives a dialled connection
//! against a bridge that never opens a descriptor. Neither has ever put a
//! datagram through the kernel, so nothing above `transport/socket.zig` has
//! been asked whether its half of the stack fits the other half's.
//!
//! # What is asserted
//!
//! Three things, and each one is the whole of a claim the project has not yet
//! made good on:
//!
//! 1. A handshake completes between two `ConnectionManager`s over a real
//!    socket, with the dialling side finding its connection by `connectionAt`
//!    — the same index walk an accepted connection is found by, which is what
//!    makes the dial path the same machinery rather than a parallel one.
//! 2. The peer is the node that was named, and it is established by comparing
//!    the certificate against an SPKI built here from the DER encoding rather
//!    than off the configuration that produced it. The second test exists to
//!    show that assertion has teeth: the same handshake with one byte of the
//!    pin changed does not finish.
//! 3. Bytes written to a stream arrive at the other end, in both directions.
//!
//! The codepoint the core marks rides out with every datagram and is compared
//! at both ends. `batch.zig`'s entire model is that a codepoint is something
//! the socket carries in a control message rather than something the layer
//! above invents, and only the kernel can confirm it.
//!
//! # What is reported
//!
//! When one of those does not hold, the run prints the datagram each side
//! moved, the state every connection on it was in, and both codepoints, and
//! then fails. It does not relax the assertion: a red loopback test with an
//! accurate diagnosis is worth more here than a green one that stopped asking.
//!
//! # The artifact's exit code
//!
//! The second test makes the core refuse a certificate, and the core logs the
//! refusal at error level (`vendor/quic/src/quic/connection.zig:2458`). A test
//! runner that fails any binary which logged at error level cannot host that
//! test, so this artifact names its own runner through
//! `std.Build.Step.Compile.test_runner`: `test/expected_log_runner.zig`,
//! which accounts for that one message and nothing else. The core still logs
//! the refusal at error level, the message is still printed, and the assertion
//! below still has to hold on its own — the runner changes which log is also
//! a failure, not whether it is a log.
//!
//! The tolerated message is named whole, so anything this file logs at error
//! level is counted and fails the run. It logs exactly one thing, in one
//! place: a teardown that could not free the dialer. `Link.deinit` is a
//! `defer` and `Link.init` unwinds through an `errdefer`, and neither may
//! `return` an error, so that failure is reported the way a stall is
//! reported and then logged rather than swallowed. Nothing else here logs at
//! error level, and a run in which every teardown succeeded writes no such
//! line at all.
//!
//! Two things a reader will otherwise try first, both checked against the
//! 0.16.0 sources rather than assumed:
//!
//! * A `std_options` in *this* file would do it, and would not be read.
//!   `zig test` compiles `lib/compiler/test_runner.zig` as the root, and
//!   `lib/std/std.zig` resolves `std.options` off the root — so the runner's
//!   `std_options` is the one that counts and this file's is not compiled into
//!   the decision at all. `--test-runner` is what moves the root.
//! * `std.testing.log_level` exists and is the obvious lever, and is dead.
//!   Nothing in 0.16.0 reads it, and it could not work even if something did:
//!   the generated runner counts with
//!   `if (@intFromEnum(message_level) <= @intFromEnum(std.log.Level.err))`,
//!   and `Level` has nothing below `.err` for a threshold to move.
//!
//! There are no sleeps and no fixed ports anywhere in this file. Time does not
//! move at all — every call below is made at one instant — so the loops end on
//! what the state machines report or on a round bound, and never on a delay.

const std = @import("std");
const ozai = @import("ozai");

const t = std.testing;

const batch = ozai.transport_batch;
const addr_map = ozai.addr_map;
const bridge = ozai.transport_quic_bridge;
const dial = ozai.transport_dial;
const socket_mod = ozai.transport_socket;

const Bridge = bridge.Bridge;
const Conn = bridge.Conn;
const Egress = bridge.Egress;
const Instant = bridge.Instant;
const Dialer = dial.Dialer;
const Socket = socket_mod.Socket;
const ControlBuffer = socket_mod.ControlBuffer;

const NodeId = ozai.NodeId;
const SecretKey = ozai.SecretKey;
const SocketAddr = ozai.SocketAddr;

/// A seeded generator's engine, kept beside every value handed out from it:
/// `std.Random` is an interface over a pointer to the engine, so the engine
/// has to outlive the connection it seeds.
const Prng = std.Random.DefaultPrng;

/// The one ALPN both ends speak, and the only thing they agree on besides the
/// handshake itself.
const alpn = "ozai";

/// Fixed seeds, so both endpoints present the same certificate on every run
/// and a failure can be reproduced rather than re-diagnosed.
const client_seed: [SecretKey.seed_length]u8 = @splat(0xc1);
const server_seed: [SecretKey.seed_length]u8 = @splat(0x53);
/// A third identity that is on neither socket, for the pin that must not be
/// satisfied.
const stranger_seed: [SecretKey.seed_length]u8 = @splat(0x3c);

/// Where both sockets bind, with port zero: the kernel picks, so two runs at
/// once and a socket left over from the last one cannot collide, and nothing
/// in the test needs to be reconfigured when one of them does.
const loopback: SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 0 };

/// Where virtual time starts. It never moves: see the module doc.
const start: Instant = 1_000 * std.time.ns_per_s;

/// The largest datagram a path is expected to carry, the same bound
/// `quic_bridge.zig` and the vendored lossy-link test use.
const max_datagram = 1500;

/// How many socket writes one drain may hand back before the room is too
/// small. A whole flight fits; a caller that wants less learns it from
/// `error.NoRoom`.
const max_egress = 8;

/// Room for every datagram one drain may produce.
const send_room: usize = max_egress * max_datagram;

/// Room for the largest list the kernel may coalesce into one read.
/// `batch.max_gro_segments_linux` is the count a socket installs when it
/// accepts `UDP_GRO`, and its own doc says a receive buffer too small for the
/// largest list truncates a coalesced read — which arrives at this seam as
/// `error.MessageTooLarge` rather than as a short datagram.
const receive_room: usize = @as(usize, max_datagram) * batch.max_gro_segments_linux;

/// How many flights each direction a phase may take before it is called
/// stalled. Generous, because a round is a few syscalls and nothing here can
/// block: the bound is a backstop against a run that never converges, not a
/// timer.
const max_rounds = 32;

/// The DER `SubjectPublicKeyInfo` an ed25519 key is presented as: a fixed
/// twelve-byte header and then the 32 bytes of public key.
///
/// The header is the encoding itself — a 42-byte SEQUENCE, a 5-byte
/// `AlgorithmIdentifier` naming OID 1.3.101.112, and a BIT STRING of 33 bytes
/// with no unused bits — written out here rather than read off the dialer's
/// own certificate. A test that compares a value against the thing that
/// produced it proves nothing: this is the same 44 bytes `tls13.ed25519Spki`
/// builds, built a second time so the comparison has two sides.
fn spkiOf(node: NodeId) [bridge.spki_length]u8 {
    const header = [_]u8{
        0x30, 0x2a, // SEQUENCE, 42 bytes
        0x30, 0x05, //   SEQUENCE, 5 bytes
        0x06, 0x03, 0x2b, 0x65, 0x70, //   OID 1.3.101.112, id-Ed25519
        0x03, 0x21, 0x00, //   BIT STRING, 33 bytes, no padding
    };
    var out: [bridge.spki_length]u8 = undefined;
    @memcpy(out[0..header.len], &header);
    @memcpy(out[header.len..], &node.toBytes());
    return out;
}

/// The codepoint's own name, or `none` for a datagram that carried no
/// control message. `Ecn` has no not-ECT tag, so "zero" is an absence here.
fn ecnName(ecn: ?batch.Ecn) []const u8 {
    const set = ecn orelse return "none";
    return @tagName(set);
}

/// Whether `side` holds a connection the core says is established.
fn established(side: *Side) bool {
    var index: usize = 0;
    while (side.bridge.connectionAt(index)) |conn| : (index += 1) {
        if (conn.established()) return true;
    }
    return false;
}

/// The handshake phase's goal: both ends agree the connection is up, neither
/// because it was told so and neither before the other.
fn bothUp(client: *Side, server: *Side) bool {
    return established(client) and established(server);
}

/// One endpoint: an identity, a socket on an ephemeral loopback port, the
/// bridge that runs its connections, and the buffers the send and receive
/// seams need.
///
/// The buffers are on the heap because the receive one is 96 KB. A test that
/// overflows the stack fails for a reason that has nothing to do with QUIC,
/// and every buffer here is the caller's by the seam's own contract.
const Side = struct {
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

    fn init(
        self: *Side,
        name: []const u8,
        secret: SecretKey,
        expect: ?NodeId,
        engine_seed: u64,
    ) !void {
        self.* = .{
            .name = name,
            .socket = undefined,
            .bridge = undefined,
            .map = addr_map.MappedAddrs.init(),
            .engine = Prng.init(engine_seed),
            .egress = &.{},
            .out = &.{},
            .scratch = &.{},
            .buf = &.{},
            .control = undefined,
        };
        errdefer self.map.deinit(t.allocator);
        // The bind happens inside `create`, so the address this side is
        // reachable at is only known once the socket exists. That is why the
        // dialling side is dialled at this side's address rather than at one
        // the test made up.
        self.socket = try Socket.create(loopback, .{});
        errdefer self.socket.close();
        // Both transport keys are supplied rather than drawn from `t.io`: a
        // test whose Retry key differs on every run has failures that move.
        self.bridge = try Bridge.create(t.io, t.allocator, .{
            .secret = secret,
            .expect_peer = expect,
            .alpn = alpn,
            .retry_token_key = @splat(0x11),
            .static_reset_key = @splat(0x22),
        }, self.random());
        errdefer self.bridge.destroy();
        self.egress = try t.allocator.alloc(Egress, max_egress);
        errdefer t.allocator.free(self.egress);
        self.out = try t.allocator.alloc(u8, send_room);
        errdefer t.allocator.free(self.out);
        // The core's own buffer: the datagram is copied into its front and a
        // stateless reply is written behind it, which is `Bridge.recv`'s
        // contract and the reason it is twice a datagram.
        self.scratch = try t.allocator.alloc(u8, 2 * max_datagram);
        errdefer t.allocator.free(self.scratch);
        self.buf = try t.allocator.alloc(u8, receive_room);
        errdefer t.allocator.free(self.buf);
    }

    fn deinit(self: *Side) void {
        self.bridge.destroy();
        t.allocator.free(self.egress);
        t.allocator.free(self.out);
        t.allocator.free(self.scratch);
        t.allocator.free(self.buf);
        self.map.deinit(t.allocator);
        self.socket.close();
    }

    /// A generator over this side's own engine, good until the next call.
    fn random(self: *Side) std.Random {
        return self.engine.random();
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
    fn takeStream(self: *Side, stream_id: u64, out: []u8) usize {
        const conn = self.bridge.connectionAt(0) orelse return 0;
        const opened = conn.entry.conn.streams.getStream(stream_id) orelse return 0;
        const chunk = opened.recv.read() orelse return 0;
        defer t.allocator.free(chunk);
        const taken = @min(chunk.len, out.len);
        @memcpy(out[0..taken], chunk[0..taken]);
        return taken;
    }
};

/// The two endpoints and the bookkeeping that makes a stall readable.
///
/// Index 0 is the dialling side and index 1 the accepting one, everywhere in
/// this struct.
const Link = struct {
    client: Side,
    server: Side,
    dialer: *Dialer,
    /// The connection `Dialer.dial` handed back, kept only to prove that the
    /// bridge finds the same one by index. It is a borrowed handle: `deinit`
    /// frees it, and nothing may read it afterwards.
    dialled: Conn,
    sent: [2]usize = .{ 0, 0 },
    received: [2]usize = .{ 0, 0 },
    /// Connections the core declared finished, which leaves the table but
    /// keeps its memory until `sweep`.
    finished: [2]usize = .{ 0, 0 },
    ecn: [2]Cods = .{ .{}, .{} },

    /// What each side marked on the wire and what each side read off the
    /// wire.
    ///
    /// Counts rather than a single remembered value, because a handshake is
    /// sent not-ECT — which is `Ecn`'s null, not a fourth codepoint — and the
    /// core only starts marking once the handshake confirms. The counts are
    /// what say the marking ever happened.
    const Cods = struct {
        marked: usize = 0,
        saw: usize = 0,
        lost: usize = 0,
        last_sent: ?batch.Ecn = null,
        last_seen: ?batch.Ecn = null,
    };

    fn init(
        self: *Link,
        client_secret: SecretKey,
        server_secret: SecretKey,
        pinned: NodeId,
        engine_seed: u64,
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
        try self.client.init("client", client_secret, null, engine_seed);
        client_live = true;
        try self.server.init("server", server_secret, client_secret.nodeId(), engine_seed + 1);
        server_live = true;
        self.dialer = try Dialer.create(t.allocator, self.client.bridge, .{
            .secret = client_secret,
            .alpn = alpn,
        });
        dialer_live = true;
        // A direct target, so the address the core is told is the server's
        // real one and no synthetic subnet is involved: this file is about the
        // socket, and a relay path would test the map instead.
        self.dialled = (try self.dialer.dial(
            .{ .ip = self.server.socket.address },
            pinned,
            self.client.socket.address,
            &self.client.map,
            start,
            self.client.random(),
        )).conn;
    }

    fn deinit(self: *Link) void {
        self.closeDialed();
        self.client.deinit();
        self.server.deinit();
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
    /// and then logged at error level, which is the one thing this artifact's
    /// runner turns into a failed run beyond the message `build.zig` names.
    /// `destroy` returns before it frees, so a refusal has left the dialer
    /// allocated and the leak checker says so in this run; the log is what
    /// stops the step passing with the teardown named only in a leak trace.
    fn closeDialed(self: *Link) void {
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
    fn of(self: *Link, which: usize) *Side {
        return if (which == 0) &self.client else &self.server;
    }

    /// Drain everything on one side's connections and write each datagram to
    /// the peer's real socket, then take whatever is waiting on the other.
    ///
    /// Both directions go through `Socket.send` and `Socket.tryReceive`, so a
    /// datagram is a `sendmsg` and a `recvmsg` here exactly as it would be in
    /// production — including the traffic-class and segment control messages
    /// `batch.zig` models, which is the only reason the codepoint assertions
    /// below mean anything.
    fn step(self: *Link, from: usize, into: usize, at: Instant) !bool {
        const sender = self.of(from);
        var moved = false;
        var index: usize = 0;
        // Found by index, never by a handle the caller was handed: an accepted
        // connection has no other way in, and the dialled one has to be found
        // the same way or the dial path is a second implementation.
        while (sender.bridge.connectionAt(index)) |conn| : (index += 1) {
            for (try conn.drain(sender.egress, sender.out, at, sender.random())) |egress| {
                const went = try sender.socket.send(t.io, egress.to, egress.send);
                if (!went.ecnSurvived()) self.ecn[from].lost += 1;
                if (went.carried) |set| {
                    self.ecn[from].marked += 1;
                    self.ecn[from].last_sent = set;
                }
                self.sent[from] += 1;
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
    fn take(self: *Link, which: usize, at: Instant) !bool {
        const side = self.of(which);
        var moved = false;
        while (true) {
            const sock = &side.socket;
            const got = sock.tryReceive(t.io, side.buf, &side.control) catch |err| switch (err) {
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
                        _ = try side.socket.send(t.io, ingress.source.socket, reply);
                    },
                    .dropped, .foreign => {},
                }
            }
        }
        return moved;
    }

    /// One pass of the whole link: everything the client has, then everything
    /// the server has. A round is one flight in each direction.
    fn exchange(self: *Link, at: Instant) !bool {
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
    /// loaded machine.
    fn drive(self: *Link, at: Instant, goal: fn (*Side, *Side) bool) !void {
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
    fn report(self: *Link, what: []const u8, reason: []const u8) void {
        std.debug.print("\nloopback {s}: {s}\n", .{ what, reason });
        for (0..2) |which| {
            const side = self.of(which);
            std.debug.print(
                "  {s} at {f}: {d} sent, {d} received, ecn {d} marked, {d} seen, {d} lost\n",
                .{
                    side.name,
                    side.socket.address,
                    self.sent[which],
                    self.received[which],
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

/// What the client wrote, and what came back. One short line: the point is
/// that the bytes crossed the socket and were read at the far end, not that a
/// particular payload survived.
const question = "who is on the other end of this socket?";
const answer = "ozai, over loopback, on a real descriptor";

test "two endpoints meet on a loopback socket, and the dialled peer is the one that answered" {
    var client_secret = try SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();
    var server_secret = try SecretKey.fromSeed(server_seed);

    var link: Link = undefined;
    try link.init(client_secret, server_secret, server_secret.nodeId(), 1);
    defer link.deinit();

    // The sockets are the kernel's, not the test's: both ports were zero, so
    // what is below is two ephemeral ports the test never chose.
    try t.expect(link.server.socket.address.port != 0);
    try t.expect(link.client.socket.address.port != 0);
    try t.expect(link.server.socket.address.port != link.client.socket.address.port);

    // Before anything moves, the dialled connection is what `dial.zig` says a
    // dial is: initiated, one connection in the manager, and not yet up.
    try t.expectEqual(@as(usize, 1), link.client.bridge.manager.connectionCount());
    try t.expect(!link.dialled.established());
    try t.expectEqual(@as(usize, 0), link.server.bridge.manager.connectionCount());

    try link.drive(start, bothUp);

    try t.expectEqual(@as(usize, 1), link.client.bridge.manager.connectionCount());
    try t.expectEqual(@as(usize, 1), link.server.bridge.manager.connectionCount());

    // Both ends found their connection by index, and the dialled one is the
    // connection the dialer was handed. `Dialer.dial` returns a `Conn` and
    // nothing else; if the bridge could not find the same connection by
    // walking its own table, the dial path would be a second one.
    const dialled = link.client.bridge.connectionAt(0).?;
    try t.expectEqual(link.dialled.id(), dialled.id());
    try t.expect(dialled.established());
    const accepted = link.server.bridge.connectionAt(0).?;
    try t.expect(accepted.established());

    // The addresses on both ends are the loopback ones the sockets came back
    // bound to, in both directions, which is what says the datagrams really
    // went through the kernel: nothing here could have produced these from a
    // synthetic subnet.
    try t.expectEqual(link.server.socket.address, dialled.peer().?);
    try t.expectEqual(link.client.socket.address, dialled.local().?);
    try t.expectEqual(link.client.socket.address, accepted.peer().?);
    try t.expectEqual(link.server.socket.address, accepted.local().?);

    // ── identity ──
    //
    // The server read the client's certificate and it is compared here against
    // an SPKI built from the DER encoding in `spkiOf`, not against the
    // certificate the dialer was configured with. A test that pinned its
    // expectation to the configuration would pass against any peer that
    // happens to be the one dialled.
    const client_id = client_secret.nodeId().toBytes();
    const server_id = server_secret.nodeId().toBytes();
    try t.expectEqualSlices(
        u8,
        &spkiOf(client_secret.nodeId()),
        accepted.entry.conn.peerCertificate().?,
    );

    // The client lifted the server's key out of the same encoding, compared
    // those 32 bytes against the pin the dial carried, and dropped the
    // certificate (`tls13.zig:1463`) — so a dialled connection names its peer
    // by node id and holds no copy of what it verified. Both halves of that
    // are asserted, because the second is why the first cannot be faked.
    try t.expectEqual(server_id, dialled.entry.conn.tls13_hs.?.peerNodeId().?);
    try t.expectEqual(@as(?[]const u8, null), dialled.entry.conn.peerCertificate());
    try t.expectEqual(server_id, dialled.entry.conn.tls13_hs.?.config.expect_peer_node_id.?);
    // The server enforced its own mirror of that pin against what the client
    // presented, and the policy it enforced is the one this bridge was built
    // with.
    try t.expectEqual(client_id, accepted.entry.conn.clientAuth().?.expect_node_id.?);
    try t.expectEqualStrings(alpn, dialled.entry.conn.negotiatedAlpn());
    try t.expectEqualStrings(alpn, accepted.entry.conn.negotiatedAlpn());

    // ── data ──
    //
    // The client writes once, before the loop starts: a driver that wrote on
    // every round would be testing its own timing rather than the path. What
    // the loop moves is datagrams, and what the server reads is the far end
    // of a socket.
    const stream = try dialled.entry.conn.openStream();
    try stream.send.writeData(question);
    stream.send.close();

    var heard: [question.len]u8 = undefined;
    var heard_len: usize = 0;
    var round: usize = 0;
    while (round < max_rounds) : (round += 1) {
        _ = try link.exchange(start);
        heard_len += link.server.takeStream(stream.stream_id, heard[heard_len..]);
        if (heard_len == heard.len) break;
    }
    if (heard_len != heard.len) {
        link.report("stalled", "the stream the client opened never arrived at the server");
        return error.StreamStalled;
    }
    try t.expectEqualStrings(question, heard[0..heard_len]);

    // And back the other way, on the same stream: a handshake that completes
    // and then goes silent is a handshake that works and a stack that does
    // not.
    const server_stream = accepted.entry.conn.streams.getStream(stream.stream_id).?;
    try server_stream.send.writeData(answer);
    server_stream.send.close();

    var reply: [answer.len]u8 = undefined;
    var reply_len: usize = 0;
    round = 0;
    while (round < max_rounds) : (round += 1) {
        _ = try link.exchange(start);
        reply_len += link.client.takeStream(stream.stream_id, reply[reply_len..]);
        if (reply_len == reply.len) break;
    }
    if (reply_len != reply.len) {
        link.report("stalled", "the stream the server answered on never arrived at the client");
        return error.StreamStalled;
    }
    try t.expectEqualStrings(answer, reply[0..reply_len]);

    // ── ECN ──
    //
    // The core marks ECT(0) once the handshake confirms and not before, so a
    // mark on the wire at all is the core's answer, and the same value coming
    // back off the peer's socket is the kernel's. Both ends are checked: a
    // codepoint that survives one hop is a codepoint the control message
    // carried, and one that survives the round trip is a codepoint `batch.zig`
    // modelled correctly.
    // Every side both marked and saw a codepoint. Anything less and there is
    // nothing to compare, which is a finding rather than a pass.
    const counts = [_][2]usize{
        .{ link.ecn[0].marked, link.ecn[0].saw },
        .{ link.ecn[1].marked, link.ecn[1].saw },
    };
    for (counts) |pair| {
        if (pair[0] == 0 or pair[1] == 0) {
            link.report(
                "codepoint",
                "a datagram went out or came in with no codepoint to compare",
            );
            return error.NoEcnObserved;
        }
    }
    try t.expectEqual(batch.Ecn.ect0, link.ecn[0].last_sent.?);
    try t.expectEqual(batch.Ecn.ect0, link.ecn[1].last_seen.?);
    try t.expectEqual(batch.Ecn.ect0, link.ecn[1].last_sent.?);
    try t.expectEqual(batch.Ecn.ect0, link.ecn[0].last_seen.?);
}

test "a dial that names a peer nobody is fails, and it fails at the certificate" {
    var client_secret = try SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();
    var server_secret = try SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();
    // The third identity exists only to be named. It is on no socket and
    // holds no certificate, so the only way this handshake can succeed is if
    // the pin is not enforced at all.
    var stranger = try SecretKey.fromSeed(stranger_seed);
    defer stranger.deinit();

    var link: Link = undefined;
    try link.init(client_secret, server_secret, stranger.nodeId(), 2);
    defer link.deinit();

    // One byte of the pin differs from the first test's and nothing else does:
    // same seeds, same sockets, same loop.
    //
    // Driven to the bound rather than through `drive`, which reports a round
    // that moves nothing as a stall — and this exchange moves nothing on
    // purpose. Were the pin not enforced, both ends would be up inside
    // `max_rounds` and the assertion below would catch it with both states to
    // show.
    //
    // The refusal is loud, and the loudness is not this stack's: the core logs
    // a certificate it will not accept at error level
    // (`connection.zig:2458`), and the runner `zig test` generates fails any
    // binary that logged one. So this artifact runs under
    // `test/expected_log_runner.zig`, which accounts for that one message and
    // lets every other error log through as a failure. The message below is
    // still printed, and nothing in the first test was weakened to earn the
    // green run this one ends in.
    var round: usize = 0;
    while (round < max_rounds) : (round += 1) {
        _ = try link.exchange(start);
        if (bothUp(&link.client, &link.server)) break;
    }

    const held = link.client.bridge.connectionAt(0);
    if (held == null) {
        // The core dropped the connection outright rather than refusing it.
        // That is still a refusal, but there is nothing left to read the pin
        // off, and an assertion with nothing to look at is not one.
        link.report("pin check", "the wrong pin dropped the connection rather than refusing it");
        return error.PinFailureNotInspectable;
    }
    const dialled = held.?;

    // The client's end is the one that refuses: its pin names a node id that
    // is not the one the server's certificate carries, and
    // `clientProcessCertificate` compares those 32 bytes with a constant-time
    // equality and returns `error.BadCertificate` when they differ.
    if (dialled.established()) {
        link.report("pin check", "a dial with the wrong pin finished the handshake anyway");
        return error.PinNotEnforced;
    }
    // And it refused *at* the certificate: the core never kept a peer id,
    // because it never accepted the certificate the id would have come out
    // of. A peer that was accepted and then found wanting would leave the id
    // behind instead.
    const carried = dialled.entry.conn.tls13_hs.?;
    try t.expectEqual(@as(?[32]u8, null), carried.peerNodeId());
    try t.expectEqual(stranger.nodeId().toBytes(), carried.config.expect_peer_node_id.?);

    // The pin is a comparison and not an assertion: it was carried, it was
    // checked, and the comparison is against bytes the peer had to prove
    // possession of. The first test is only worth anything because this one
    // fails.
    const stranger_id = stranger.nodeId().toBytes();
    const server_id = server_secret.nodeId().toBytes();
    try t.expect(!std.mem.eql(u8, &stranger_id, &server_id));
    try t.expect(!std.mem.eql(u8, &spkiOf(stranger.nodeId()), &spkiOf(server_secret.nodeId())));
}
