//! The Rust partner and a Zig endpoint, meeting on a real socket.
//!
//! `test/two_process_test.zig` puts two `ozai-node` processes on a wire. This
//! puts **two independent implementations** on one: the Zig endpoint in this
//! repository and `interop/iroh-peer`, a Rust process running iroh's QUIC core
//! (`noq` 1.3.0, the exact version `iroh` 1.3.0 pins). Nothing else in the tree
//! drives a second implementation, so this is where a claim about iroh
//! interoperability either has a process on the other end of it or does not
//! have one.
//!
//! # What is asserted, and where each half of it was earned
//!
//! 1. **Stock transport offers only `ozai`.** The peer's live `offer` lines
//!    are compared against the loopback transport ALPN. Actual gossip, blobs
//!    and relay interoperability belongs to their dedicated protocol drivers.
//! 2. **The peer's identity is compared with its expected id.** In the
//!    direct `rpk` server mode, rustls pins the Zig client's raw key during TLS.
//!    Stock iroh keeps its verifier unchanged; the harness reads the accepted
//!    raw certificate from `peer_identity()` and checks the pin before bytes
//!    are exchanged. The reciprocal Rust-client test checks both pins too.
//! 3. **Application bytes cross on a real bidirectional stream**, with the
//!    Rust receive oracle and Zig response oracle comparing exact byte strings
//!    and the peer's counters agreeing.
//!
//! # The modes and the contract they exercise
//!
//! Both Rust TLS paths require RFC 7250 raw public keys. One uses the direct
//! `noq` 1.3.0 configuration in `rpk.rs`; the other uses stock
//! `iroh::Endpoint` 1.3.0 without changing its verifier. Each successful case
//! checks the expected identity and ALPN, then exchanges a request and response.
//! `contract.rs` records the certificate-type negotiation both sides require.
//!
//! `test/two_process_*` starts `ozai-node` because it is testing the program.
//! This is testing the wire, so the Zig half is the transport this repository
//! exposes — `loopback_side.Side` and `transport_dial.Dialer` — driven by the
//! same round loop `test/loopback_link.zig` uses, with the far end being a
//! foreign process rather than a second `Side`. The bridge and dialer use the
//! transport ALPN `ozai`; dedicated protocol drivers exercise actual gossip,
//! Bao blobs and the HTTP relay carrier instead of generic byte echoes.
//!
//! # Time
//!
//! Each exchange owns a virtual clock seeded at `start`; each datagram round
//! advances it by `clock_step` before driving the bridge. This lets transport
//! timers run without coupling protocol progress to host scheduling. The host
//! clock only bounds startup waits and never decides success.

const std = @import("std");

const ozai = @import("ozai");

const t = std.testing;

const loopback_side = @import("loopback_side.zig");
const rust_peer = @import("rust_interop_child.zig");

const Side = loopback_side.Side;
const Process = rust_peer.Process;

const bridge_mod = ozai.transport_quic_bridge;
const dial_mod = ozai.transport_dial;

const Conn = bridge_mod.Conn;
const Instant = bridge_mod.Instant;
const Dialer = dial_mod.Dialer;
const NodeId = ozai.NodeId;
const SecretKey = ozai.SecretKey;
const SocketAddr = ozai.SocketAddr;

/// These are transport exchanges, not fake gossip application messages.
const alpn: []const u8 = loopback_side.alpn;

/// Seed for each exchange's virtual clock.
const start: Instant = loopback_side.start;

/// How far each datagram round advances its caller-owned virtual clock.
const clock_step: Instant = std.time.ns_per_ms;

/// A run's caller-owned virtual time. Its value is never shared between tests.
const Clock = struct {
    now: Instant,

    fn advance(self: *Clock) void {
        self.now += clock_step;
    }
};

/// The bytes the Zig half writes, and the bytes it expects back. Named once
/// each: a payload written at one call site and compared at another is two
/// places for a typo to hide in.
const question = "ozai-to-iroh-peer";
const answer = "iroh-peer-to-ozai";

/// DER prefix for Ed25519 SubjectPublicKeyInfo, as used by the core.
const ed25519_spki_prefix: [12]u8 = .{
    0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00,
};

/// The Zig half's identity, fixed so a failure reproduces and so the id can be
/// handed to the peer on its command line before the peer is running.
const zig_seed: [SecretKey.seed_length]u8 = @splat(0x5A);

/// The peer's identity, fixed for the same reason, and different from the Zig
/// half's so a run cannot have the two hearing the same certificate twice.
const peer_seed_hex = "6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c";

/// A generator seed for the Zig side's core. Distinct from anything else in the
/// tree, so neither half can hand the core a connection id the other has used.
const engine_seed: u64 = 0x1a2b;

/// How long a parent wait for one observed state may take, in milliseconds. A
/// watchdog, not a success condition.
const budget_ms = rust_peer.budget_ms;

/// How many datagram rounds this driver may spend.
///
/// Each round advances virtual time by `clock_step`. The bound remains a
/// backstop against a run that will never converge, not a wall-clock timer.
const max_rounds = 4_000;

/// How many non-blocking socket reads one round may consume before yielding
/// the remaining queue to the next round.
const max_receive_batches = 64;

/// The Zig half of a run: its identity, its socket and bridge, the dialer, and
/// the connection the dial handed back.
const Zig = struct {
    secret: SecretKey,
    node_id: NodeId,
    side: Side,
    dialer: *Dialer,
    /// The connection `Dialer.dial` handed back.
    dialled: Conn,
    /// Whether `side.init` has run, so `deinit` does not release a bridge that
    /// was never created.
    side_live: bool = false,
    /// Whether `Dialer.create` has run.
    dialer_live: bool = false,

    fn deinit(self: *Zig) void {
        if (self.dialer_live) {
            self.closeDialled();
            self.dialer.destroy() catch |err| {
                std.log.err("rust_interop teardown: the dialer was not freed: {t}", .{err});
            };
        }
        if (self.side_live) self.side.deinit();
        self.secret.deinit();
        self.* = undefined;
    }

    /// Take the dialled connections out of the bridge, then sweep.
    ///
    /// `Dialer.destroy` refuses while one is still in the table, so the removal
    /// is what makes the call after it possible. It walks backwards because
    /// `removeConnection` swap-removes and a forward walk would skip an entry and
    /// leave a freed one behind; `sweep` frees what the core declared finished.
    /// Both are `loopback_link.zig:161-186`'s.
    fn closeDialled(self: *Zig) void {
        var index = self.side.bridge.manager.entries.items.len;
        while (index > 0) {
            index -= 1;
            const entry = self.side.bridge.manager.entries.items[index];
            if (!entry.conn.is_server) self.side.bridge.manager.removeConnection(entry);
        }
        self.side.bridge.sweep();
    }
};

// ---------------------------------------------------------------------------
// The peer's offer, and the reservation it must not contain
// ---------------------------------------------------------------------------

test "stock iroh transport offers only ozai and never the reserved QAD ALPN" {
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    var secret = try SecretKey.fromSeed(zig_seed);
    defer secret.deinit();

    var peer = try startPeer(arena.allocator(), secret.nodeId(), "contract", "iroh");
    defer peer.deinit(t.io);
    try awaitBanner(t.io, peer);

    // Stock transport must not advertise fake gossip, blobs or relay handlers.
    const offered = try peer.lines("offer ", arena.allocator());
    try t.expectEqual(@as(usize, 1), offered.len);
    try t.expectEqualStrings(alpn, offered[0]);

    // The reservation, from the Zig side's own constant. An iroh peer may offer
    // `/iroh-qad/0` because iroh owns that protocol, and this tree refuses the
    // registration (`src/router/alpn_table.zig:173`, `:208`), so a peer that
    // offered it would be offering something no node here can answer.
    for (offered) |name| {
        try t.expect(!std.mem.eql(u8, name, ozai.router.qad_alpn));
    }

    // And the identity model, read off the peer: 32 bytes of hex, which is what
    // `--expect-peer` took and what `NodeId.parseHex` reads on this side. The
    // length check is not the assertion; the difference from this half's own id
    // is, because a peer that printed its seed back would satisfy the length.
    const printed = peer.value("node") orelse
        return peer.gaveUp("printed a banner with no node id in it", .{});
    try t.expectEqual(@as(usize, 64), printed.len);
    const peer_id = try NodeId.parseHex(printed);
    try t.expect(!std.mem.eql(u8, &peer_id.toBytes(), &secret.nodeId().toBytes()));

    try peer.stop();
}

// ---------------------------------------------------------------------------
// The exchange
// ---------------------------------------------------------------------------

test "a Zig endpoint and a Rust noq peer authenticate each other and pass bytes" {
    try authenticatedByteExchange("rpk");
}

test "a Zig endpoint and stock iroh 1.3.0 authenticate each other and pass bytes" {
    try authenticatedByteExchange("iroh");
}

fn authenticatedByteExchange(tls: []const u8) !void {
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    var secret = try SecretKey.fromSeed(zig_seed);
    defer secret.deinit();

    var peer = try startPeer(arena.allocator(), secret.nodeId(), "peer", tls);
    defer peer.deinit(t.io);

    var clock: Clock = .{ .now = start };
    var zig = try startZig(secret);
    defer zig.deinit();

    const peer_addr = try peerAddress(t.io, peer);
    const peer_id = try NodeId.parseHex(peer.value("node") orelse
        return peer.gaveUp("printed a banner with no node id in it", .{}));

    // The Zig half dials the peer, pinning the node id the peer printed. The
    // dial is one call; everything after it is rounds, and a round only moves
    // datagrams.
    zig.dialled = (try zig.dialer.dial(
        // A direct route, so the address the core is told is the peer's real
        // one and no synthetic subnet is involved (`loopback_link.zig:133-141`).
        .{ .ip = peer_addr },
        peer_id,
        zig.side.socket.address,
        &zig.side.map,
        clock.now,
        zig.side.random(),
    )).conn;

    // The handshake, as rounds. Nothing here waits for a duration: a round that
    // moved nothing and a round that moved something are the same loop, and the
    // loop ends on a state.
    try driveUntil(t.io, peer, &zig, &clock, struct {
        fn holds(state: *const Zig) bool {
            return state.dialled.established();
        }
    }.holds, "a connection the Zig core says is established");

    // The Zig side's own account of who it is talking to, read off the
    // connection rather than off the pin. `clientProcessCertificate` lifts the
    // key, compares it and drops the certificate (`tls13.zig:1463`), so this is
    // the id and there is no certificate to read back on this side at all
    // (`loopback_test.zig:197-204`).
    const handshake = zig.dialled.entry.conn.tls13_hs orelse return error.NoPeerIdentity;
    const lifted = handshake.peerNodeId() orelse return error.NoPeerIdentity;
    try t.expectEqualSlices(u8, &peer_id.toBytes(), &lifted);
    try t.expectEqual(@as(?[]const u8, null), zig.dialled.entry.conn.peerCertificate());
    try t.expectEqualStrings(alpn, zig.dialled.entry.conn.negotiatedAlpn());

    // One real bidirectional stream: the Zig side sends the request and the
    // Rust side replies on that same stream after checking the exact request.
    var stream = try bridge_mod.Stream.open(zig.dialled);
    try stream.write(question);
    stream.close();

    var reply: std.ArrayList(u8) = .empty;
    defer reply.deinit(t.allocator);
    var round: usize = 0;
    while (round < max_rounds) : (round += 1) {
        try pump(t.io, peer, &zig, &clock);
        _ = try stream.drain(t.allocator, &reply);
        if (stream.finished()) break;
    }
    if (!stream.finished() or !std.mem.eql(u8, reply.items, answer)) {
        printPeer(t.io, peer);
        return error.NoAnswer;
    }

    // The peer agrees, from its own counters, that it read the request and
    // wrote the response. The Rust handler independently checks request bytes.
    try drivePeerUntil(t.io, peer, &zig.side, &clock, struct {
        fn holds(child: *const Process) bool {
            return child.line("stopped:") != null;
        }
    }.holds, "peer's final report");
    const report = peer.value("stopped:") orelse
        return peer.gaveUp("exited without a final report", .{});
    try t.expect(std.mem.indexOf(u8, report, &rust_peer.hexId(secret.nodeId())) != null);
    try t.expectEqualStrings(alpn, valueAfter(report, "alpn "));
    try t.expectEqual(@as(u64, question.len), try std.fmt.parseInt(
        u64, valueAfter(report, "received "), 10,
    ));
    try t.expectEqual(@as(u64, answer.len), try std.fmt.parseInt(
        u64, valueAfter(report, "sent "), 10,
    ));
    try drivePeerUntil(t.io, peer, &zig.side, &clock, struct {
        fn holds(child: *const Process) bool {
            return child.finished();
        }
    }.holds, "peer process termination");
    try t.expect(!(try peer.reportFailure(t.io)));
}

test "a strict direct noq client and a Zig server authenticate and pass bytes" {
    try reciprocalClientExchange("rpk");
}

test "a stock iroh 1.3.0 client and a Zig server authenticate and pass bytes" {
    try reciprocalClientExchange("iroh");
}

fn reciprocalClientExchange(tls: []const u8) !void {
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    var zig_secret = try SecretKey.fromSeed(zig_seed);
    defer zig_secret.deinit();
    var rust_secret = try SecretKey.fromSeed(@splat(0x6c));
    defer rust_secret.deinit();

    var side: Side = undefined;
    try side.init("zig-server", zig_secret, rust_secret.nodeId(), engine_seed);
    defer side.deinit();
    side.bridge.alpn_list[0] = alpn;
    side.bridge.manager.tls_config.alpn = side.bridge.alpn_list[0..];

    var clock: Clock = .{ .now = start };
    const zig_id_hex = rust_peer.hexId(zig_secret.nodeId());
    var peer = try Process.start(t.allocator, arena.allocator(), t.io, "rust-client", .{
        .tls = tls,
        .seed_hex = peer_seed_hex,
        .expect_peer_hex = &zig_id_hex,
        .run_ms = budget_ms,
        .connect_address = side.socket.address,
    });
    defer peer.deinit(t.io);

    try awaitNode(t.io, peer);
    const printed = peer.value("node") orelse
        return peer.gaveUp("printed no node identity", .{});
    const printed_id = try NodeId.parseHex(printed);
    const rust_node_id_bytes = rust_secret.nodeId().toBytes();
    try t.expectEqualSlices(u8, &rust_node_id_bytes, &printed_id.toBytes());

    try driveServerUntil(t.io, peer, &side, &clock, struct {
        fn holds(server: *Side) bool {
            const accepted = server.bridge.connectionAt(0) orelse return false;
            return accepted.established() and accepted.peerStream() != null;
        }
    }.holds, "an established Rust client connection with its request stream");

    const accepted = side.bridge.connectionAt(0) orelse return error.NoConnection;
    const client_certificate = accepted.entry.conn.peerCertificate() orelse
        return error.NoPeerCertificate;
    try t.expectEqual(@as(usize, 44), client_certificate.len);
    try t.expectEqualSlices(u8, &ed25519_spki_prefix, client_certificate[0..12]);
    try t.expectEqualSlices(u8, &rust_node_id_bytes, client_certificate[12..]);
    try t.expectEqualStrings(alpn, accepted.entry.conn.negotiatedAlpn());

    var inbound = accepted.peerStream() orelse return error.NoPeerStream;
    var request: std.ArrayList(u8) = .empty;
    defer request.deinit(t.allocator);
    var round: usize = 0;
    while (round < max_rounds) : (round += 1) {
        try pumpSide(t.io, peer, &side, &clock);
        _ = try inbound.drain(t.allocator, &request);
        if (inbound.finished()) break;
    }
    if (!inbound.finished() or !std.mem.eql(u8, request.items, question)) {
        printPeer(t.io, peer);
        return error.UnexpectedRequest;
    }

    try inbound.write(answer);
    inbound.close();

    try drivePeerUntil(t.io, peer, &side, &clock, struct {
        fn holds(child: *const Process) bool {
            return child.line("stopped:") != null;
        }
    }.holds, "peer's final report");
    const report = peer.value("stopped:") orelse
        return peer.gaveUp("exited without a final report", .{});
    try t.expect(std.mem.indexOf(u8, report, &rust_peer.hexId(zig_secret.nodeId())) != null);
    try t.expectEqualStrings(alpn, valueAfter(report, "alpn "));
    try t.expectEqual(@as(u64, question.len), try std.fmt.parseInt(
        u64, valueAfter(report, "sent "), 10,
    ));
    try t.expectEqual(@as(u64, answer.len), try std.fmt.parseInt(
        u64, valueAfter(report, "received "), 10,
    ));
    try drivePeerUntil(t.io, peer, &side, &clock, struct {
        fn holds(child: *const Process) bool {
            return child.finished();
        }
    }.holds, "peer process termination");
    try t.expect(!(try peer.reportFailure(t.io)));
}

// ---------------------------------------------------------------------------
// The pieces
// ---------------------------------------------------------------------------

/// The Zig half: an identity, a socket, a bridge, and a dialer over it.
fn startZig(secret: SecretKey) !Zig {
    var zig: Zig = .{
        .secret = secret,
        .node_id = secret.nodeId(),
        .side = undefined,
        .dialer = undefined,
        .dialled = undefined,
    };
    errdefer zig.secret.deinit();
    try zig.side.init("zig", secret, null, engine_seed);
    zig.side_live = true;

    // Both TLS lists must select transport `ozai`, matching the stock Rust
    // transport handler. Dedicated protocol drivers own their application ALPNs.
    zig.side.bridge.alpn_list[0] = alpn;
    zig.side.bridge.manager.tls_config.alpn = zig.side.bridge.alpn_list[0..];
    zig.dialer = try Dialer.create(t.allocator, zig.side.bridge, .{
        .secret = secret,
        .alpn = alpn,
    });
    zig.dialer_live = true;
    zig.dialer.alpn_list[0] = alpn;
    return zig;
}

/// Start the peer and read its banner, so the caller has both identities.
///
/// `tls` selects the peer's independently configured TLS implementation. The
/// two callers exercise strict direct `noq` and stock iroh configurations.
fn startPeer(
    arena: std.mem.Allocator,
    zig_node_id: NodeId,
    name: []const u8,
    tls: []const u8,
) !*Process {
    return Process.start(t.allocator, arena, t.io, name, .{
        .tls = tls,
        .seed_hex = peer_seed_hex,
        .expect_peer_hex = &rust_peer.hexId(zig_node_id),
        .run_ms = budget_ms,
    });
}

/// One round: everything the Zig side has, then everything the peer has said.
///
/// One pass of `loopback_link.zig`'s `step`/`take` with the far end being a
/// foreign process. Everything the Zig side owns is the same; what changed is
/// that the datagrams land on the peer's socket rather than a second `Side`'s.
fn pump(io: std.Io, peer: *Process, zig: *Zig, clock: *Clock) !void {
    try pumpSide(io, peer, &zig.side, clock);
}

/// One round over any Zig endpoint, including one accepting the Rust dial.
/// Advances the caller's virtual clock once, then uses that instant throughout.
fn pumpSide(io: std.Io, peer: *Process, side: *Side, clock: *Clock) !void {
    clock.advance();
    var index: usize = 0;
    while (side.bridge.connectionAt(index)) |conn| : (index += 1) {
        for (try conn.drain(side.egress, side.out, clock.now, side.random())) |egress| {
            _ = try side.socket.send(io, egress.to, egress.send);
        }
    }
    var scan: usize = 0;
    // Timers follow the sends, so a connection that owes a retransmission can
    // produce it in this round rather than the next.
    while (side.bridge.connectionAt(scan)) |conn| : (scan += 1) {
        _ = side.bridge.tick(conn, clock.now, side.random());
    }
    try take(io, side, clock);
    try peer.pump(io);
    // The foreign runtime uses host time, not the virtual QUIC clock.
    try std.Io.sleep(io, .{ .nanoseconds = std.time.ns_per_ms }, .awake);
}

/// Take a bounded number of socket reads and hand each datagram to the bridge.
///
/// A read is not one datagram: `UDP_GRO` may have coalesced a burst into one
/// buffer, so the stride is what says how many packets there are and the bridge
/// is handed them one at a time — which is what `Datagram` documents, since two
/// packets sharing one buffer would leave the core with two replies pointing at
/// the same bytes. If the read bound is reached, queued packets remain for the
/// next round.
fn take(io: std.Io, side: *Side, clock: *Clock) !void {
    var batch_index: usize = 0;
    while (batch_index < max_receive_batches) : (batch_index += 1) {
        const got = side.socket.tryReceive(
            io,
            side.buf,
            &side.control,
        ) catch |err| switch (err) {
            // The socket is non-blocking from the moment it was created, and an
            // empty queue is a fact the loop acts on rather than a failure.
            error.WouldBlock => break,
            else => return err,
        };
        const recv = try got.toRecv();
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
            }, side.scratch, clock.now, side.random());
            switch (ingress.outcome) {
                // Nothing to do here: the connection this datagram belongs to is
                // drained by the next round, which finds it by index.
                .processed => {},
                // A stateless reply is a send, so it goes back out of the same
                // socket to the address the datagram came from.
                .reply => |reply| {
                    _ = try side.socket.send(io, ingress.source.socket, reply);
                },
                .dropped, .foreign => {},
            }
        }
    }
}

/// Round until `holds` is true of the Zig half, or `max_rounds` is spent.
///
/// Each round advances the caller-owned virtual clock. A gate that never held
/// prints the peer, because the question is about a process this file cannot
/// see into.
fn driveUntil(
    io: std.Io,
    peer: *Process,
    zig: *Zig,
    clock: *Clock,
    comptime gate: anytype,
    comptime what: []const u8,
) !void {
    if (try rounds(io, peer, zig, clock, gate)) return;
    printPeer(io, peer);
    std.debug.print("rust_interop: the run never reached {s} in {d} rounds\n", .{
        what, max_rounds,
    });
    return error.RoundsExhausted;
}

/// Round until `holds` is true of an accepting Zig endpoint, or the bound is
/// spent.
fn driveServerUntil(
    io: std.Io,
    peer: *Process,
    side: *Side,
    clock: *Clock,
    comptime holds: anytype,
    comptime what: []const u8,
) !void {
    var round: usize = 0;
    while (round < max_rounds) : (round += 1) {
        try pumpSide(io, peer, side, clock);
        if (holds(side)) return;
        if (peer.finished()) break;
    }
    printPeer(io, peer);
    std.debug.print("rust_interop: the run never reached {s} in {d} rounds\n", .{
        what, max_rounds,
    });
    return error.RoundsExhausted;
}

/// Keep the endpoint and peer pipes moving until a peer state is observed.
fn drivePeerUntil(
    io: std.Io,
    peer: *Process,
    side: *Side,
    clock: *Clock,
    comptime holds: anytype,
    comptime what: []const u8,
) !void {
    var round: usize = 0;
    while (round < max_rounds) : (round += 1) {
        try pumpSide(io, peer, side, clock);
        if (holds(peer)) return;
        if (peer.finished()) break;
    }
    printPeer(io, peer);
    std.debug.print("rust_interop: the peer never reached {s} in {d} rounds\n", .{
        what, max_rounds,
    });
    return error.RoundsExhausted;
}

/// Wait for the peer's identity banner, as both client and server peers emit it.
fn awaitNode(io: std.Io, peer: *Process) !void {
    try awaitState(io, peer, struct {
        fn holds(child: *const Process) bool {
            return child.line("node") != null;
        }
    }.holds);
}

/// Round until `holds` is true of the Zig half or the bound is spent, and say
/// whether it held.
fn rounds(
    io: std.Io,
    peer: *Process,
    zig: *Zig,
    clock: *Clock,
    comptime holds: anytype,
) !bool {
    var round: usize = 0;
    while (round < max_rounds) : (round += 1) {
        try pump(io, peer, zig, clock);
        if (holds(zig)) return true;
        if (peer.finished()) return holds(zig);
    }
    return false;
}

/// Wait for a peer-only startup state before a Zig transport is active.
///
/// Once an exchange is active, callers use `drivePeerUntil` to keep sockets
/// moving while they observe peer progress.
fn awaitState(io: std.Io, peer: *Process, comptime holds: anytype) !void {
    const deadline = try nowMs() + budget_ms;
    while (try nowMs() < deadline) {
        try peer.pump(io);
        if (holds(peer)) return;
        if (peer.finished()) break;
        try std.Io.sleep(t.io, .{ .nanoseconds = 2 * std.time.ns_per_ms }, .awake);
    }
    try peer.pump(io);
    if (holds(peer)) return;
    printPeer(io, peer);
    return error.PeerStateTimeout;
}

/// The first progress line follows the complete ALPN offer list.
fn awaitBanner(io: std.Io, peer: *Process) !void {
    try awaitState(io, peer, struct {
        fn holds(child: *const Process) bool {
            return child.line("listening") != null and
                child.line("node") != null and child.progress() != null;
        }
    }.holds);
}

/// The address the peer printed, with the port the kernel gave it.
///
/// The address is parsed here rather than handed to the peer as a fixed port,
/// so two runs at once and a socket left over from the last one cannot collide.
fn peerAddress(io: std.Io, peer: *Process) !SocketAddr {
    try awaitBanner(io, peer);
    return (try peer.address()) orelse
        peer.gaveUp("said it was listening without saying where", .{});
}

/// The host clock in milliseconds. Only ever a bound on a wait.
fn nowMs() !i64 {
    return std.Io.Clock.awake.now(t.io).toMilliseconds();
}

/// What a line said after `label`, with the spaces between them gone.
fn valueAfter(line: []const u8, label: []const u8) []const u8 {
    const at = std.mem.indexOf(u8, line, label) orelse return "";
    const rest = line[at + label.len ..];
    const end = std.mem.indexOfScalar(u8, rest, ',') orelse rest.len;
    return std.mem.trim(u8, rest[0..end], " ");
}

/// Print both of the peer's pipes, and its last progress line.
fn printPeer(io: std.Io, peer: *Process) void {
    peer.pump(io) catch |err| {
        std.debug.print("rust_interop: diagnostic read failed: {s}\n", .{@errorName(err)});
    };
    std.debug.print("rust_interop: the peer {s} wrote\n", .{peer.name});
    std.debug.print("  stdout:\n{s}\n", .{peer.out.items});
    std.debug.print("  stderr:\n{s}\n", .{peer.err_out.items});
    if (peer.progressLine()) |line| {
        std.debug.print("  its last progress line said:\n  {s}\n", .{line});
    }
}
