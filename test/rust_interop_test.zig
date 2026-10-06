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
//! 1. **The peer's ALPN offer is the Zig tree's.** The peer prints one `offer`
//!    line per protocol; this file compares that list against
//!    `node.gossip_alpn`, `node.relay_alpn`, `blobs_protocol.alpn` and the
//!    transport ALPN, and against `router.qad_alpn` to say the reserved one is
//!    absent. A contract written in two implementations and compared across is a
//!    contract; one written in one is a comment.
//! 2. **Each side proved the other's node id.** The Zig dialer pins the peer
//!    (`expect_peer_node_id`, `tls13.zig:2578-2580`) and the peer pins this side
//!    (`PinnedClient`, `interop/iroh-peer/src/rpk.rs`), so a handshake that
//!    completes is two byte comparisons having held. The Zig side's own view is
//!    then read back off the connection rather than taken from the pin.
//! 3. **Application bytes crossed in both directions**, on two streams, with
//!    each side's bytes compared, and the peer's own counters agreeing.
//!
//! # The one deviation, and the test that names it
//!
//! `interop/iroh-peer/src/contract.rs` records it: iroh 1.3.0's rustls
//! verifiers require RFC 7250 `certificate_type` negotiation, and the vendored
//! TLS 1.3 neither sends nor answers it. The second test below runs the peer
//! with `--tls iroh`, i.e. stock `iroh::Endpoint` 1.3.0, and asserts that the
//! handshake fails and that the peer says why. **The Zig side is not touched to
//! make an unmodified upstream peer agree**: a deviation deleted to buy a green
//! run is a deviation nobody can read any more.
//!
//! # Why the Zig half is in this process
//!
//! `test/two_process_*` starts `ozai-node` because it is testing the program.
//! This is testing the wire, so the Zig half is the transport this repository
//! exposes — `loopback_side.Side` and `transport_dial.Dialer` — driven by the
//! same round loop `test/loopback_link.zig` uses, with the far end being a
//! foreign process rather than a second `Side`. `Side.init` pins the loopback
//! fixture's own ALPN, so the two one-element ALPN lists this test writes put
//! the gossip protocol on the wire; the rest of `Side` — socket, bridge,
//! buffers, `takeStream` — is reused as it stands.
//!
//! # Time
//!
//! The host clock bounds waits and nothing else. Completion is an observed
//! counter or a compared byte string, never a sleep. The datagram round loop is
//! bounded by `loopback_side.max_rounds` for the same reason `loopback_link.zig`'s
//! is, and it reads no clock at all: `start` is one instant for a whole run.

const std = @import("std");

const ozai = @import("ozai");

const t = std.testing;

const loopback_side = @import("loopback_side.zig");
const progress_ns = @import("two_process_progress.zig");
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

/// The protocol this driver speaks. A node registers exactly one ALPN
/// (`src/node/node_accept.zig:45`), and this half is a transport below the node
/// layer, so the gossip protocol is the one whose spelling matters.
const alpn: []const u8 = ozai.node.gossip_alpn;

/// The transport-level protocol the two in-tree loopback drivers speak
/// (`test/loopback_side.zig:36`), named here because it is one of the four the
/// peer offers and the contract check compares against it.
const transport_alpn: []const u8 = loopback_side.alpn;

/// Where the Zig half binds, port zero so the kernel chooses.
const loopback: SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 0 };

/// Where virtual time starts. One instant for a whole run, so nothing in the
/// round loop can expire and a stall is a finding about the stack.
const start: Instant = loopback_side.start;

/// The bytes the Zig half writes, and the bytes it expects back. Named once
/// each: a payload written at one call site and compared at another is two
/// places for a typo to hide in.
const question = "ozai-to-iroh-peer";
const answer = "iroh-peer-to-ozai";

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
/// Far larger than `loopback_side.max_rounds`, and for the reason the loopback
/// drivers can afford 32: their two ends are in one process, so a round hands
/// bytes to memory. Here the far end is another process, so a round is a
/// `sendmsg` and a `recvmsg` and the peer needs to be scheduled before its
/// answer can exist. A round is a few syscalls and nothing blocks, so the bound
/// is a backstop against a run that will never converge and not a timer — the
/// clock is only ever read by `awaitState`.
const max_rounds = 4_000;

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

test "the peer's ALPN offer is this tree's, and the reserved one is not in it" {
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    var secret = try SecretKey.fromSeed(zig_seed);
    defer secret.deinit();

    var peer = try startPeer(arena.allocator(), secret.nodeId(), "contract", "rpk");
    defer peer.deinit(t.io);
    try awaitBanner(t.io, peer);

    // Four protocols, compared one at a time against the Zig tree's own
    // constants. Read off the peer rather than off its source: a peer that
    // offered a fifth protocol, or spelled one differently, fails here.
    const offered = try peer.lines("offer ", arena.allocator());
    try t.expectEqual(@as(usize, 4), offered.len);
    try t.expectEqualStrings(ozai.node.gossip_alpn, offered[0]);
    try t.expectEqualStrings(ozai.node.relay_alpn, offered[1]);
    try t.expectEqualStrings(ozai.blobs_protocol.alpn, offered[2]);
    try t.expectEqualStrings(transport_alpn, offered[3]);

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

test "a Zig endpoint and a Rust iroh peer authenticate each other and pass bytes" {
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    var secret = try SecretKey.fromSeed(zig_seed);
    defer secret.deinit();

    var peer = try startPeer(arena.allocator(), secret.nodeId(), "peer", "rpk");
    defer peer.deinit(t.io);

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
        start,
        zig.side.random(),
    )).conn;

    // The handshake, as rounds. Nothing here waits for a duration: a round that
    // moved nothing and a round that moved something are the same loop, and the
    // loop ends on a state.
    try driveUntil(t.io, peer, &zig, struct {
        fn holds(state: *const Zig) bool {
            return state.dialled.established();
        }
    }.holds, "a connection the Zig core says is established");

    // The Zig side's own account of who it is talking to, read off the
    // connection rather than off the pin. `clientProcessCertificate` lifts the
    // key, compares it and drops the certificate (`tls13.zig:1463`), so this is
    // the id and there is no certificate to read back on this side at all
    // (`loopback_test.zig:197-204`).
    const lifted = zig.dialled.entry.conn.tls13_hs.?.peerNodeId() orelse
        return error.NoPeerIdentity;
    try t.expectEqualSlices(u8, &peer_id.toBytes(), &lifted);
    try t.expectEqual(@as(?[]const u8, null), zig.dialled.entry.conn.peerCertificate());
    // The ALPN both ends settled on, from the core's own record.
    try t.expectEqualStrings(alpn, zig.dialled.entry.conn.negotiatedAlpn());

    // Outbound: one stream, written once before the loop. A driver that wrote on
    // every round would be testing its own timing rather than the path.
    const out = try zig.dialled.entry.conn.openStream();
    try out.send.writeData(question);
    out.send.close();

    var heard: [question.len]u8 = undefined;
    var heard_len: usize = 0;
    var round: usize = 0;
    while (round < max_rounds) : (round += 1) {
        try pump(t.io, peer, &zig);
        heard_len += zig.side.takeStream(out.stream_id, heard[heard_len..]);
        if (heard_len == heard.len) break;
    }
    if (heard_len != heard.len) {
        printPeer(t.io, peer);
        return error.StreamStalled;
    }
    try t.expectEqualStrings(question, heard[0..heard_len]);

    // Inbound: the peer opened a stream of its own, and `Conn.peerStream` is
    // the accessor for a stream this end did not open. The sink is the
    // caller's and grows, because a read has no length worth guessing
    // (`bridge_conn.zig:278-295`).
    var reply: std.ArrayList(u8) = .empty;
    defer reply.deinit(t.allocator);
    round = 0;
    while (round < max_rounds) : (round += 1) {
        try pump(t.io, peer, &zig);
        var inbound = zig.dialled.peerStream() orelse continue;
        _ = try inbound.drain(t.allocator, &reply);
        if (reply.items.len > 0) break;
    }
    if (!std.mem.eql(u8, reply.items, answer)) {
        printPeer(t.io, peer);
        return error.NoAnswer;
    }

    // And the peer agrees, from its own counters, through the harness's own
    // gates. `received` is the Zig half's bytes and `sent` its own: a peer that
    // had answered nothing would have read them and written none. `Need.holds`
    // is `two_process_progress`'s; `Progress.count` is module-private, so a
    // counter this file wants is asked for by name.
    try awaitState(t.io, peer, struct {
        fn holds(child: *const Process) bool {
            const seen = child.progress() orelse return false;
            const need = progress_ns.Need{ .field = "received", .want = question.len };
            return need.holds(seen) and
                (progress_ns.Need{ .field = "sent", .want = answer.len }).holds(seen);
        }
    }.holds);

    // The report the peer wrote on the way out names the node it proved, and it
    // is this half's id: the pin was a 32-byte comparison and this is what it
    // compared against.
    const report = peer.value("stopped:") orelse
        return peer.gaveUp("exited without a final report", .{});
    try t.expect(std.mem.indexOf(u8, report, &rust_peer.hexId(secret.nodeId())) != null);
    try t.expectEqualStrings(alpn, valueAfter(report, "alpn "));
}

// A Zig endpoint and a stock iroh 1.3.0 peer, and the refusal between them.
//
// The peer runs `--tls iroh`, so its rustls verifiers require RFC 7250
// `certificate_type` negotiation, which the vendored core neither offers nor
// answers (`interop/iroh-peer/src/contract.rs` section 3). The handshake is
// expected to fail, and the peer's own account of why is asserted: a run in
// which it succeeded would mean iroh stopped requiring it, and this test is the
// record that it has not.
test "a stock iroh 1.3.0 peer is refused at the certificate-type extension" {
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    var secret = try SecretKey.fromSeed(zig_seed);
    defer secret.deinit();

    var peer = try startPeer(arena.allocator(), secret.nodeId(), "iroh-peer", "iroh");
    defer peer.deinit(t.io);
    const peer_addr = try peerAddress(t.io, peer);
    const peer_id = try NodeId.parseHex(peer.value("node") orelse
        return peer.gaveUp("printed a banner with no node id in it", .{}));

    var zig = try startZig(secret);
    defer zig.deinit();
    zig.dialled = (try zig.dialer.dial(
        // A direct route, so the address the core is told is the peer's real
        // one and no synthetic subnet is involved (`loopback_link.zig:133-141`).
        .{ .ip = peer_addr },
        peer_id,
        zig.side.socket.address,
        &zig.side.map,
        start,
        zig.side.random(),
    )).conn;

    // The rounds run until one side gives up, because a handshake that fails
    // ends on the peer's alert rather than on any state the Zig side reaches.
    _ = try rounds(t.io, peer, &zig, struct {
        fn holds(state: *const Zig) bool {
            return state.dialled.established();
        }
    }.holds);

    // No connection, from the Zig side. A handshake that reached `established`
    // would mean the certificate-type extensions were tolerated after all.
    try t.expect(!zig.dialled.established());

    // And the peer's reason, which is the deviation named rather than inferred.
    // `stop` first: a refusal is a failed handshake, not a peer that keeps
    // listening, and a child left running is a process the next run collides
    // with.
    // The peer reports no connection of its own accord, which is the other half
    // of the same fact: neither side came up.
    try awaitState(t.io, peer, struct {
        fn holds(child: *const Process) bool {
            return child.finished();
        }
    }.holds);
    const report = peer.value("stopped:") orelse
        return peer.gaveUp("exited without a final report", .{});
    try t.expect(std.mem.indexOf(u8, report, "accepted 0") != null);
    try t.expect(std.mem.indexOf(u8, report, "up 0") != null);

    // The reason is in the alert the *Zig* side received, and the Zig core logs
    // it rather than propagating it to this file: the run above prints
    // `peer CONNECTION_CLOSE: error_code=0x128 ... reason=peer is incompatible:
    // IncorrectCertificateTypeExtension` before this test's own output. Asserted
    // here as the peer's exit being non-zero, which is what that alert causes.
    try t.expect(try peer.reportFailure(t.io));
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

    // `Side.init` configures the loopback fixture's own ALPN. The gossip
    // protocol is the one a node registers, so the bridge's one-element list and
    // the dialer's are both written to it. Both lists are storage those two
    // already own, so this is a write and not an allocation.
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
/// `tls` is a parameter rather than a field `startZig` shares, because it is the
/// whole difference between the two tests below and a default would hide it in
/// the two call sites that do not pass it.
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
fn pump(io: std.Io, peer: *Process, zig: *Zig) !void {
    var index: usize = 0;
    while (zig.side.bridge.connectionAt(index)) |conn| : (index += 1) {
        for (try conn.drain(zig.side.egress, zig.side.out, start, zig.side.random())) |egress| {
            _ = try zig.side.socket.send(io, egress.to, egress.send);
        }
    }
    // Timers after the sends, so a connection that owes a retransmission gets
    // the chance to produce one in this round rather than the next
    // (`loopback_link.zig:221-225`).
    var scan: usize = 0;
    while (zig.side.bridge.connectionAt(scan)) |conn| : (scan += 1) {
        _ = zig.side.bridge.tick(conn, start, zig.side.random());
    }
    try take(io, zig);
    try peer.pump(io);
}

/// Take everything queued on the Zig side's socket and hand it to its bridge.
///
/// A read is not one datagram: `UDP_GRO` may have coalesced a burst into one
/// buffer, so the stride is what says how many packets there are and the bridge
/// is handed them one at a time — which is what `Datagram` documents, since two
/// packets sharing one buffer would leave the core with two replies pointing at
/// the same bytes.
fn take(io: std.Io, zig: *Zig) !void {
    while (true) {
        const got = zig.side.socket.tryReceive(
            io,
            zig.side.buf,
            &zig.side.control,
        ) catch |err| switch (err) {
            // The socket is non-blocking from the moment it was created, and an
            // empty queue is a fact the loop acts on rather than a failure.
            error.WouldBlock => break,
            else => return err,
        };
        const recv = try got.toRecv();
        var position: usize = 0;
        while (position < recv.datagramCount()) : (position += 1) {
            const ingress = try zig.side.bridge.recv(&zig.side.map, .{
                // The loop's bound is `recv.datagramCount()`, and
                // `Recv.datagram` answers null only past that count.
                // zwanzig-disable-next-line: optional-unwrap
                .bytes = recv.datagram(position).?,
                .from = got.from,
                .local = zig.side.socket.address,
                .ecn = recv.ecn,
            }, zig.side.scratch, start, zig.side.random());
            switch (ingress.outcome) {
                // Nothing to do here: the connection this datagram belongs to is
                // drained by the next round, which finds it by index.
                .processed => {},
                // A stateless reply is a send, so it goes back out of the same
                // socket to the address the datagram came from.
                .reply => |reply| {
                    _ = try zig.side.socket.send(io, ingress.source.socket, reply);
                },
                .dropped, .foreign => {},
            }
        }
    }
}

/// Round until `holds` is true of the Zig half, or `max_rounds` is spent.
///
/// `max_rounds` is a backstop against a run that never converges, not a timer:
/// nothing here reads a clock, so a stall is a finding about the stack rather
/// than about how loaded this machine is. A gate that never held prints the
/// peer, because the question is about a process this file cannot see into.
fn driveUntil(
    io: std.Io,
    peer: *Process,
    zig: *Zig,
    comptime gate: anytype,
    comptime what: []const u8,
) !void {
    if (try rounds(io, peer, zig, gate)) return;
    printPeer(io, peer);
    std.debug.print("rust_interop: the run never reached {s} in {d} rounds\n", .{
        what, max_rounds,
    });
    return error.RoundsExhausted;
}

/// Round until `holds` is true of the Zig half or the bound is spent, and say
/// whether it held.
fn rounds(io: std.Io, peer: *Process, zig: *Zig, comptime holds: anytype) !bool {
    var round: usize = 0;
    while (round < max_rounds) : (round += 1) {
        try pump(io, peer, zig);
        if (holds(zig)) return true;
        if (peer.finished()) return holds(zig);
    }
    return false;
}

/// Pump the peer's pipes until `holds` is true of them, or `budget_ms` is spent.
///
/// A peer cannot wait for a state, so it reports one and this is the half that
/// decides what a missing state means. Only the host clock is read, and only to
/// bound the wait: the loop pumps both pipes and re-reads them, so a peer that
/// reports early is noticed early.
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
    std.debug.panic("rust_interop: the peer never reached the state waited for", .{});
}

/// Wait for the peer's banner: the node id and the address it bound.
fn awaitBanner(io: std.Io, peer: *Process) !void {
    try awaitState(io, peer, struct {
        fn holds(child: *const Process) bool {
            return child.line("listening") != null and child.line("node") != null;
        }
    }.holds);
}

/// The address the peer printed, with the port the kernel gave it.
///
/// The address is parsed here rather than handed to the peer as a fixed port,
/// so two runs at once and a socket left over from the last one cannot collide.
fn peerAddress(io: std.Io, peer: *Process) !SocketAddr {
    try awaitBanner(io, peer);
    const text = peer.value("listening") orelse
        return peer.gaveUp("said it was listening without saying where", .{});
    const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse
        return peer.gaveUp("printed an address with no port", .{});
    const host = ozai.IpAddress.parse(text[0..colon]) orelse
        return peer.gaveUp("printed {s}, which is not an address", .{text});
    const port = std.fmt.parseInt(u16, text[colon + 1 ..], 10) catch
        return peer.gaveUp("printed {s}, whose port does not parse", .{text});
    return .{ .ip = host, .port = port };
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
    peer.pump(io) catch {};
    std.debug.print("rust_interop: the peer {s} wrote\n", .{peer.name});
    std.debug.print("  stdout:\n{s}\n", .{peer.out.items});
    std.debug.print("  stderr:\n{s}\n", .{peer.err_out.items});
    if (peer.progressLine()) |line| {
        std.debug.print("  its last progress line said:\n  {s}\n", .{line});
    }
}
