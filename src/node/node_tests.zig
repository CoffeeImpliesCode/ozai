const std = @import("std");
const node_mod = @import("node.zig");
const lifecycle = @import("node_lifecycle.zig");
const runtime = @import("node_runtime.zig");
const closing = @import("node_close.zig");
const client_pass = @import("node_relay_client.zig");
const protocol = @import("node_protocol.zig");
const config = @import("node_config.zig");
const node_error = @import("node_error.zig");
const framing = @import("node_framing.zig");
const base_key = @import("../base/key.zig");
const shutdown_mod = @import("../router/shutdown.zig");
const hyparview = @import("../gossip/hyparview.zig");
const relay_frame = @import("../relay/frame_types.zig");
const relay_state = @import("relay_state.zig");
const SecretKey = base_key.SecretKey;
const SocketAddr = @import("../base/addr.zig").SocketAddr;
const Socket = @import("../transport/socket.zig").Socket;
const Conn = @import("../transport/quic_conn.zig").Conn;
const Instant = @import("../transport/quic_conn.zig").Instant;
const RecvUni = @import("../transport/quic_stream.zig").RecvUni;
const relay_storage = relay_state.State(config.relay_table_slots, config.relay_displaced);

const t = std.testing;

/// Where a test node binds, with port zero: the kernel picks, so two nodes in
/// one process both bind and a socket left over from the last run cannot
/// collide with this one.
const loopback: SocketAddr = .{
    .ip = .{ .v4 = .{ 127, 0, 0, 1 } },
    .port = 0,
};

/// Where virtual time starts. It moves only because this test says so — see
/// `test/protocol_loopback_test.zig`'s module doc, which is the discipline
/// this file borrows.
const start_ns: Instant = 1_000 * std.time.ns_per_s;

/// How far the clock moves per pass. A pass is a handful of syscalls, so this
/// is a clock and not a delay: nothing in this file waits for it to elapse, and
/// the total stays far below the core's 30 s idle timeout so a connection is
/// never reaped by the clock.
const time_quantum: Instant = hyparview.nanos_per_milli;

/// How many passes the loop runs. Generous, because a pass is a few syscalls
/// and nothing here can block: the bound is a backstop against a run that
/// never converges, not a timer. It is also the claim the milestone is
/// about — a node does not stop here, and this number is only a backstop.
const max_passes = 256;

/// A fixed identity per test node, so both ends present the same certificate
/// on every run and a failure reproduces rather than has to be
/// re-diagnosed.
fn identityOf(tag: u8) base_key.KeyError!SecretKey {
    return SecretKey.fromSeed(@splat(tag));
}

/// Membership and broadcast with the paper's defaults and short clocks, so
/// the `shuffle` and `pending_neighbor_request` paths are on the wire inside
/// the pass bound rather than sitting on a timer the run never reaches. The
/// capacities and the walk lengths are left alone: this test is about the
/// loop and not about the paper.
fn briskTopic() hyparview.TopicConfig {
    return .{ .membership = .{
        .shuffle_interval = 4 * hyparview.nanos_per_milli,
        .neighbor_request_timeout = 2 * hyparview.nanos_per_milli,
    } };
}

/// Close before release even when a test assertion fails.
fn closedOnExit(node: *node_mod.Node) void {
    defer lifecycle.deinit(node);
    closing.close(t.io, node, start_ns, node_mod.generator(node)) catch |err|
        std.debug.panic("node close failed during test teardown: {t}", .{err});
}

/// The X25519 and P-256 public keys one connection offered in its
/// `ClientHello`, read off the handshake the core built.
///
/// **Off the core's own handshake, not off a second draw.** `tls13_hs` is
/// where `Tls13Handshake.initClientInto` put the scalars it drew, and
/// `x25519_public`/`p256_public` are the public values it derived from them,
/// so this is the key that went on the wire rather than a re-derivation that
/// could agree with the first one by accident. False when no dialled
/// connection of this node holds a handshake yet, which is a different answer
/// from a zero key.
fn readEphemeral(node: *node_mod.Node, x25519: *[32]u8, p256: *[65]u8) bool {
    var index: usize = 0;
    while (node.bridge.connectionAt(index)) |conn| : (index += 1) {
        // A dialled connection, not an accepted one: this is the half that
        // offers a key share. An accepted connection answers with the group
        // the client chose and holds no key pair of its own.
        if (conn.entry.conn.is_server) continue;
        const handshake = conn.entry.conn.tls13_hs orelse continue;
        x25519.* = handshake.x25519_public;
        p256.* = handshake.p256_public;
        return true;
    }
    return false;
}
test "a node dials a peer, both ends finish a handshake, and every action is performed" {
    // The listener first: its ephemeral port is only known once the socket
    // exists, and the dialer is given that address rather than one made up.
    const listener = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0x51),
        .listen = loopback,
        .topic = briskTopic(),
    });
    defer lifecycle.deinit(listener);

    const peers = [_]config.Peer{.{
        .id = node_mod.nodeId(listener),
        .addr = .{ .ip = node_mod.address(listener) },
    }};
    const dialer = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0xc1),
        .listen = loopback,
        .peers = &peers,
        .topic = briskTopic(),
    });
    defer lifecycle.deinit(dialer);

    // Two different identities: a node that dialled itself would be told its
    // own certificate, which proves nothing about a pin.
    try t.expect(node_mod.nodeId(dialer).order(node_mod.nodeId(listener)) != .eq);

    var at: Instant = start_ns;
    try runtime.start(dialer, at, node_mod.generator(dialer));

    // One round loop over both nodes, which is `Mesh.round` in
    // `test/protocol_loopback_test.zig` with two nodes in it instead of four.
    var passes: usize = 0;
    var moved: usize = 0;
    while (passes < max_passes) : (passes += 1) {
        at += time_quantum;
        if (try runtime.step(t.io, dialer, at, node_mod.generator(dialer))) moved += 1;
        if (try runtime.step(t.io, listener, at, node_mod.generator(listener))) moved += 1;
    }

    // More than one pass ran, and the loop kept going rather than stopping at
    // convergence: the pass count is the whole claim, and the bound above it
    // never fired.
    try t.expect(passes > 1);
    try t.expect(passes == max_passes);
    try t.expectEqual(@as(u64, max_passes), dialer.stats.steps);
    try t.expectEqual(@as(u64, max_passes), listener.stats.steps);
    try t.expect(moved > 0);

    // The handshake completed on both sides, over real sockets, with the
    // dialling side's pin enforced.
    try t.expectEqual(@as(usize, 1), node_mod.establishedCount(dialer));
    try t.expectEqual(@as(usize, 1), node_mod.establishedCount(listener));
    try t.expectEqual(@as(u64, 1), dialer.stats.dials);
    try t.expectEqual(@as(u64, 0), dialer.stats.dials_refused);
    try t.expect(dialer.stats.datagrams_out > 0);
    try t.expect(listener.stats.datagrams_in > 0);

    // The listening node performed every action the endpoint owed: the
    // arrival was offered to the filter, the filter accepted it, the loop
    // spawned a task, the task ran the handler's `accept`, and the task was
    // reaped when the handler finished.
    try t.expectEqual(@as(u64, 1), listener.stats.attempts);
    try t.expectEqual(@as(u64, 1), listener.stats.spawned);
    try t.expectEqual(@as(u64, 1), listener.stats.handler_connections);
    // And the handshake named a configured protocol, so the task carried one
    // while it was held: this is the claim behind `Task.protocol`, and the only
    // observable left once `drive` has reaped the task in the same pass.
    try t.expectEqual(@as(u64, 1), listener.stats.tasks_routed);
    // The dialling node is not an accept: it asked for the connection and
    // already knew who the peer was, which is what `Endpoint::accept` never
    // returns.
    try t.expectEqual(@as(u64, 0), dialer.stats.attempts);

    // The gossip loop is a loop. It was fed the join, it scheduled a timer,
    // the timer fired, and the state machine asked to be told something — and
    // nothing was sent, which is the module doc's named gap and is asserted
    // here as the positive fact it is rather than left to be inferred from the
    // silence that follows it.
    try t.expect(dialer.stats.gossip_events > 0);
    try t.expect(dialer.stats.gossip_timers_scheduled > 0);
    try t.expect(dialer.stats.gossip_timers_fired > 0);
    try t.expect(dialer.stats.gossip_membership_asked > 0);
    // Every peer the state machine named is the peer this node dialled, and
    // there is at least one: a counter that grew with an empty ring would say
    // the two halves disagree about what happened.
    try t.expect(node_mod.namedPeers(dialer).len > 0);
    for (node_mod.namedPeers(dialer)) |named| {
        try t.expectEqual(node_mod.nodeId(listener), named);
    }

    // The shutdown, in the order `shutdown_mod.Shutdown` enforces: the handlers, then
    // the cancel, then the close.
    try t.expectEqual(shutdown_mod.Shutdown.Phase.serving, dialer.accept.shutdown.phase);
    try closing.close(t.io, dialer, at, node_mod.generator(dialer));
    try closing.close(t.io, listener, at, node_mod.generator(listener));
    for ([_]*node_mod.Node{ dialer, listener }) |node| {
        try t.expectEqual(shutdown_mod.Shutdown.Phase.closed, node.accept.shutdown.phase);
        try t.expectEqual(@as(u64, 1), node.stats.handler_shutdowns);
        try t.expectEqual(@as(usize, 0), node.accept.live);
        try t.expect(!node.socket_open);
    }
    // `deinit` is a `defer` above and it gave up a lease the loop had driven
    // to `closed`; an abandoned one is logged at error level, which fails the
    // artifact, so reaching here is itself part of what is asserted.
}

test "a node configured with two protocols offers both and serves the one negotiated" {
    // The listener offers both protocols and the client offers only the second,
    // so a listener that had quietly served only its first would fail the
    // handshake outright rather than pass this by accident.
    const listener = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0x91),
        .listen = loopback,
        .protocols = &.{ .{ .alpn = protocol.gossip_alpn }, .{ .alpn = protocol.relay_alpn } },
        .topic = briskTopic(),
    });
    defer lifecycle.deinit(listener);

    const peers = [_]config.Peer{.{
        .id = node_mod.nodeId(listener),
        .addr = .{ .ip = node_mod.address(listener) },
    }};
    const client = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0xd1),
        .listen = loopback,
        .peers = &peers,
        .protocols = &.{.{ .alpn = protocol.relay_alpn }},
        .topic = briskTopic(),
    });
    defer lifecycle.deinit(client);

    // The table, the offer list and the wire are one configuration read three
    // ways: the same two ALPNs in the same order, or this is three answers to
    // one question.
    try t.expectEqual(@as(usize, 2), listener.table.configured());
    try t.expectEqual(@as(usize, 2), listener.table.protocolCount());
    var offered: [protocol.max_alpns][]const u8 = undefined;
    try t.expectEqual(@as(usize, 2), listener.table.offers(&offered));
    try t.expectEqualStrings(protocol.gossip_alpn, offered[0]);
    try t.expectEqualStrings(protocol.relay_alpn, offered[1]);
    const wire = listener.bridge.tlsConfig().alpn;
    try t.expectEqual(@as(usize, 2), wire.len);
    try t.expectEqualStrings(protocol.gossip_alpn, wire[0]);
    try t.expectEqualStrings(protocol.relay_alpn, wire[1]);
    // The close is owed two handler reports before anything is asked of it, so
    // the count a node is built with is the count it will wait for. This is
    // `endpoint.handlerCount` reading the same table the walk above read.
    try t.expectEqual(@as(usize, 2), listener.accept.shutdown.handlers);
    try t.expectEqual(@as(usize, 1), client.accept.shutdown.handlers);

    var at: Instant = start_ns;
    try runtime.start(client, at, node_mod.generator(client));

    // The same round loop the single-protocol test above runs, over real
    // sockets, to the same bound.
    var passes: usize = 0;
    while (passes < max_passes) : (passes += 1) {
        at += time_quantum;
        _ = try runtime.step(t.io, client, at, node_mod.generator(client));
        _ = try runtime.step(t.io, listener, at, node_mod.generator(listener));
    }

    // The connection landed on the relay protocol because that is the only one
    // this client offered — the server prefers gossip, and a peer offering one
    // protocol of two gets that one (RFC 7301 §3.2: the server chooses from
    // what the client advertised, not the other way round).
    try t.expectEqual(@as(usize, 1), node_mod.establishedCount(listener));
    try t.expectEqual(@as(u64, 1), listener.stats.tasks_routed);
    try t.expectEqual(@as(u64, 1), listener.stats.handler_connections);
    var index: usize = 0;
    var served: usize = 0;
    while (listener.bridge.connectionAt(index)) |conn| : (index += 1) {
        if (!conn.entry.conn.is_server) continue;
        try t.expectEqualStrings(protocol.relay_alpn, conn.entry.conn.negotiatedAlpn());
        served += 1;
    }
    try t.expectEqual(@as(usize, 1), served);

    // Two protocols registered, two `shutdown` calls owed and two made: the
    // unit is the ALPN, and the machine's count and the walk that performed
    // them agree on it rather than one of them being adjusted to the other.
    try closing.close(t.io, client, at, node_mod.generator(client));
    try closing.close(t.io, listener, at, node_mod.generator(listener));
    try t.expectEqual(shutdown_mod.Shutdown.Phase.closed, client.accept.shutdown.phase);
    try t.expectEqual(@as(u64, 1), client.stats.handler_shutdowns);
    try t.expectEqual(shutdown_mod.Shutdown.Phase.closed, listener.accept.shutdown.phase);
    try t.expectEqual(@as(u64, 2), listener.stats.handler_shutdowns);
}

test "a protocol list past the bound is refused by name, and builds nothing" {
    const too_many = [_]protocol.Protocol{
        .{ .alpn = protocol.gossip_alpn },
        .{ .alpn = protocol.relay_alpn },
        .{ .alpn = "/iroh-bytes/4" },
    };
    try t.expect(protocol.max_alpns < too_many.len);
    // The bound is this file's and the refusal is this file's: the transport's
    // own bound is looser, so a list this long is refused here rather than
    // being offered on the wire with nothing to dispatch it to.
    try t.expectError(error.TooManyProtocols, lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0x13),
        .listen = loopback,
        .protocols = &too_many,
    }));
}

test "two nodes built the same way offer two different TLS ephemeral keys" {
    // The property an observer of a captured handshake needs, stated as a
    // production invariant rather than as an inspection of the generator.
    //
    // **Two nodes configured identically must not share an ephemeral key.**
    // The audited defect was that `create` seeded `std.Random.DefaultPrng` from
    // a caller-supplied `u64`, so two nodes built from the same seed walked the
    // same stream and `Tls13Handshake.initClientInto` drew the same X25519 and
    // P-256 scalars for both. The scalars are the ECDHE secret: whoever holds
    // them and a capture of either ClientHello reads the session's forward
    // secrecy away. Equal ephemeral keys are therefore not a weak draw, they
    // are the same key, and this is the boundary the fix has to move.
    //
    // **The key is read off the handshake the core built**, through
    // `readEphemeral`, so a generator that stopped feeding this seam would fail
    // here rather than pass by leaving the field unset. Both ends are driven
    // over real sockets to a real handshake: `dialer.start` is the call that
    // reaches `Dialer.open` and `Tls13Handshake.initClientInto`, and the
    // connection is the one this project will put on a wire.
    const listener = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0x51),
        .listen = loopback,
        .topic = briskTopic(),
    });
    defer closedOnExit(listener);

    // The same peer for both, and no `--seed`-shaped difference between them:
    // these two are configured identically in every field a caller controls,
    // which is exactly the claim.
    const peers = [_]config.Peer{.{
        .id = node_mod.nodeId(listener),
        .addr = .{ .ip = node_mod.address(listener) },
    }};
    const first = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0xc1),
        .listen = loopback,
        .peers = &peers,
        .topic = briskTopic(),
    });
    defer closedOnExit(first);
    const second = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0xc1),
        .listen = loopback,
        .peers = &peers,
        .topic = briskTopic(),
    });
    defer closedOnExit(second);

    var at: Instant = start_ns;
    try runtime.start(first, at, node_mod.generator(first));
    try runtime.start(second, at, node_mod.generator(second));

    var first_x25519: [32]u8 = undefined;
    var first_p256: [65]u8 = undefined;
    var second_x25519: [32]u8 = undefined;
    var second_p256: [65]u8 = undefined;
    // The handshake has to exist before the comparison means anything: a node
    // that never drew a key would satisfy "the two differ" for the wrong
    // reason, and `undefined` bytes would compare unequal by accident.
    var passes: usize = 0;
    while (passes < max_passes) : (passes += 1) {
        at += time_quantum;
        _ = try runtime.step(t.io, first, at, node_mod.generator(first));
        _ = try runtime.step(t.io, second, at, node_mod.generator(second));
        _ = try runtime.step(t.io, listener, at, node_mod.generator(listener));
        if (readEphemeral(first, &first_x25519, &first_p256) and
            readEphemeral(second, &second_x25519, &second_p256)) break;
    }
    try t.expect(readEphemeral(first, &first_x25519, &first_p256));
    try t.expect(readEphemeral(second, &second_x25519, &second_p256));
    try t.expectEqual(@as(u64, 1), first.stats.dials);
    try t.expectEqual(@as(u64, 1), second.stats.dials);

    // The claim. Both groups, because the ClientHello offers both and either
    // one repeating is the same defect.
    try t.expect(!std.mem.eql(u8, &first_x25519, &second_x25519));
    try t.expect(!std.mem.eql(u8, &first_p256, &second_p256));
}

test "a node that dials two peers reaches both of them" {
    // The shape one node dialling one peer cannot see. Two dials out of one
    // process are two connections with connection ids minted from one
    // generator, two peers on one socket, and two accepts that each owe the
    // endpoint an arrival — so this is the only shape in which a datagram can
    // be written for one peer and go to the other.
    const gate = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0x33),
        .listen = loopback,
        .topic = briskTopic(),
    });
    defer lifecycle.deinit(gate);
    const listener = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0x51),
        .listen = loopback,
        .topic = briskTopic(),
    });
    defer lifecycle.deinit(listener);

    const peers = [_]config.Peer{
        .{ .id = node_mod.nodeId(gate), .addr = .{ .ip = node_mod.address(gate) } },
        .{ .id = node_mod.nodeId(listener), .addr = .{ .ip = node_mod.address(listener) } },
    };
    const dialer = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0xc1),
        .listen = loopback,
        .peers = &peers,
        .topic = briskTopic(),
    });
    defer lifecycle.deinit(dialer);

    var at: Instant = start_ns;
    try runtime.start(dialer, at, node_mod.generator(dialer));

    var passes: usize = 0;
    while (passes < max_passes) : (passes += 1) {
        at += time_quantum;
        _ = try runtime.step(t.io, dialer, at, node_mod.generator(dialer));
        _ = try runtime.step(t.io, gate, at, node_mod.generator(gate));
        _ = try runtime.step(t.io, listener, at, node_mod.generator(listener));
    }

    // Both dials went out and neither was refused, which is a count of what
    // `start` did rather than of what the wire did.
    try t.expectEqual(@as(u64, 2), dialer.stats.dials);
    try t.expectEqual(@as(u64, 0), dialer.stats.dials_refused);

    // And the wire: both handshakes completed, and each peer admitted exactly
    // one arrival. A peer that saw no byte has no attempt and no handler
    // connection, which is the whole of what "the dial found nobody" is.
    try t.expectEqual(@as(usize, 2), node_mod.establishedCount(dialer));
    try t.expectEqual(@as(usize, 1), node_mod.establishedCount(gate));
    try t.expectEqual(@as(usize, 1), node_mod.establishedCount(listener));
    try t.expectEqual(@as(u64, 1), gate.stats.attempts);
    try t.expectEqual(@as(u64, 1), gate.stats.handler_connections);
    try t.expectEqual(@as(u64, 1), listener.stats.attempts);
    try t.expectEqual(@as(u64, 1), listener.stats.handler_connections);
    // Closed rather than abandoned: an abandoned node is logged at error level
    // by `deinit`, which fails the artifact on its own.
    try closing.close(t.io, dialer, at, node_mod.generator(dialer));
    try closing.close(t.io, gate, at, node_mod.generator(gate));
    try closing.close(t.io, listener, at, node_mod.generator(listener));
}
test "a node that dialled two peers notices both of them close" {
    // The shape one peer cannot show. Two dials out of one process are two
    // connections on one socket, and this is the claim that has to hold for
    // both: a peer that shuts down says so with a CONNECTION_CLOSE, and a node
    // still running has to finish that connection rather than sit on it until
    // the core's idle timeout — thirty seconds, six times the window
    // `test/two_process_test.zig` gives a survivor.
    const gate = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0x33),
        .listen = loopback,
        .topic = briskTopic(),
    });
    defer lifecycle.deinit(gate);
    const listener = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0x51),
        .listen = loopback,
        .topic = briskTopic(),
    });
    defer lifecycle.deinit(listener);
    const peers = [_]config.Peer{
        .{ .id = node_mod.nodeId(gate), .addr = .{ .ip = node_mod.address(gate) } },
        .{ .id = node_mod.nodeId(listener), .addr = .{ .ip = node_mod.address(listener) } },
    };
    const dialer = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0xc1),
        .listen = loopback,
        .peers = &peers,
        .topic = briskTopic(),
    });
    defer lifecycle.deinit(dialer);

    var at: Instant = start_ns;
    try runtime.start(dialer, at, node_mod.generator(dialer));
    var passes: usize = 0;
    while (passes < max_passes) : (passes += 1) {
        at += time_quantum;
        _ = try runtime.step(t.io, dialer, at, node_mod.generator(dialer));
        _ = try runtime.step(t.io, gate, at, node_mod.generator(gate));
        _ = try runtime.step(t.io, listener, at, node_mod.generator(listener));
    }
    // Both dials reached a peer before either peer is taken away: a run that
    // never got here would be asserting about a handshake that did not happen.
    try t.expectEqual(@as(usize, 2), node_mod.establishedCount(dialer));

    // Both peers close, as a process whose `--for` expired does.
    try closing.close(t.io, gate, at, node_mod.generator(gate));
    try closing.close(t.io, listener, at, node_mod.generator(listener));

    // The dialer keeps running. Two passes is the floor — the close arrives in
    // one pass and the core needs a later instant to leave the draining period
    // — and the bound is generous because the claim is that the connections
    // finish at all, not how many passes that took.
    passes = 0;
    while (passes < max_passes and dialer.stats.connections_finished < 2) : (passes += 1) {
        at += time_quantum;
        _ = try runtime.step(t.io, dialer, at, node_mod.generator(dialer));
    }
    try t.expectEqual(@as(u64, 2), dialer.stats.connections_finished);
    try t.expectEqual(@as(usize, 0), node_mod.establishedCount(dialer));

    try closing.close(t.io, dialer, at, node_mod.generator(dialer));
}

test "a reaped connection leaves no accepted id behind" {
    // The lifetime defect, as an invariant a caller can observe rather than as
    // a reading of a private map.
    //
    // `admit` records every offered connection id in `Node.offered` and the only
    // removal in the file was on the shutdown cancellation path, so a
    // connection that ended the ordinary way — the core finished with it, `drive`
    // reaped its task, `expire` counted it — left its id in the set for the life
    // of the node. Sequential accept/disconnect cycles therefore grow that set
    // without bound on a long-lived listener.
    //
    // **What is claimed is that the set holds nothing for a connection that is
    // gone.** The churn is driven through the real path — a handshake completes
    // on a real socket, the peer closes, this node notices and reaps — and the
    // assertion is made after the reap, which is the boundary the removal
    // belongs at. A removal at process teardown would pass a test that checked
    // the set before `close` and fail this one.
    const listener = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0x51),
        .listen = loopback,
        .topic = briskTopic(),
    });
    defer closedOnExit(listener);
    const peers = [_]config.Peer{.{
        .id = node_mod.nodeId(listener),
        .addr = .{ .ip = node_mod.address(listener) },
    }};

    // Two cycles rather than one. A single cycle cannot distinguish "removed at
    // reap" from "removed when the second id arrived", and the second is exactly
    // the shape that hid this: churn is what accumulates.
    //
    // One clock for the whole test, never restarted: the listener is the node
    // whose timers these cycles advance, and a clock that went backwards
    // between them would be a second thing under test that this one is not.
    var at: Instant = start_ns;
    for (0..2) |cycle| {
        // Scoped, so the dialer is released on every exit including an
        // assertion failure — which is the run this test is expected to have
        // before the repair, and a leak there would report as a second,
        // unrelated failure.
        {
            const dialer = try lifecycle.create(t.allocator, t.io, .{
                .secret = try identityOf(@intCast(0xc1 + cycle)),
                .listen = loopback,
                .peers = &peers,
                .topic = briskTopic(),
            });
            defer lifecycle.deinit(dialer);

            try runtime.start(dialer, at, node_mod.generator(dialer));

            // **Both ends established, not just the listener's.** The listener
            // completes its half one round trip before the dialling side
            // completes its own, so a loop that stops on the listener's count
            // alone closes a connection the client is still handshaking — and a
            // close at that point is not the event under test here. This is
            // what the earlier version of this fixture got wrong: it drove on
            // `listener.establishedCount()` alone, the listener finished the
            // connection for that reason rather than because a peer said so,
            // and the run failed on its own precondition
            // (`connections_finished` read 0) before reaching the assertion
            // about the retained id.
            var passes: usize = 0;
            while (passes < max_passes and
                (node_mod.establishedCount(listener) == 0 or node_mod.establishedCount(dialer) == 0)) : (passes += 1)
            {
                at += time_quantum;
                _ = try runtime.step(t.io, dialer, at, node_mod.generator(dialer));
                _ = try runtime.step(t.io, listener, at, node_mod.generator(listener));
            }
            // The handshake happened on both sides, so the id really was
            // offered: an assertion about a set that never grew would pass on a
            // node that admitted nothing at all.
            try t.expectEqual(@as(usize, 1), node_mod.establishedCount(listener));
            try t.expectEqual(@as(usize, 1), node_mod.establishedCount(dialer));
            try t.expectEqual(@as(usize, cycle + 1), listener.stats.attempts);

            for (0..4) |_| {
                at += time_quantum;
                _ = try runtime.step(t.io, dialer, at, node_mod.generator(dialer));
                _ = try runtime.step(t.io, listener, at, node_mod.generator(listener));
            }
            // The peer goes away the way a stopped process goes away, and this
            // node keeps running: the close is on the wire and the core finishes
            // the connection on a later pass.
            try closing.close(t.io, dialer, at, node_mod.generator(dialer));
        }

        var passes: usize = 0;
        while (passes < max_passes and
            listener.stats.connections_finished < @as(u64, @intCast(cycle + 1))) : (passes += 1)
        {
            at += 10 * time_quantum;
            _ = try runtime.step(t.io, listener, at, node_mod.generator(listener));
        }
        try t.expectEqual(@as(u64, @intCast(cycle + 1)), listener.stats.connections_finished);
        try t.expectEqual(@as(usize, 0), node_mod.establishedCount(listener));

        // The claim: the connection is over and nothing is still tracking it.
        try t.expectEqual(@as(usize, 0), listener.offered.count());
    }
}

/// The listening node is holding an accept task.
///
/// `live` is 0 until the flow comes back carrying the token the filter's retry
/// verdict bought it, and 1 from the pass that spawns the task until the task
/// is reaped — so this is the earliest pass at which an accept is running,
/// and the pass a close still has something to cancel.
fn listenerHoldsAccept(nodes: []const *node_mod.Node) bool {
    return nodes[1].accept.live == 1;
}

test "a close cancels an accept that is still running before it closes the endpoint" {
    // The branch the ordering exists for. `router.zig:642-650` says why: a
    // handler's `shutdown` closes connections its own `accept` is still using,
    // so cancelling the accepts first cuts a graceful close in half, and
    // closing the endpoint first does the same damage a step later. A test
    // that only ever closes an idle node cannot tell the three steps apart, so
    // this one closes a node that still holds an accept.
    const listener = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0x51),
        .listen = loopback,
    });
    // Released through `closedOnExit` as well as closed on the way out: an
    // assertion that fails before the close below must not leave a node the
    // teardown then reports as abandoned, which would name a leak this test
    // does not have and bury the failure that did happen.
    defer closedOnExit(listener);

    const peers = [_]config.Peer{.{
        .id = node_mod.nodeId(listener),
        .addr = .{ .ip = node_mod.address(listener) },
    }};
    const dialer = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0xc1),
        .listen = loopback,
        .peers = &peers,
    });
    defer closedOnExit(dialer);

    // **The fixture pays the round trip the admission filter costs.** This node
    // registers one (`node_lifecycle.create`), and the core asks it inside
    // `route`'s "no connection for this DCID yet" branch
    // (`vendor/quic/src/quic/connection_manager.zig`), where a `retry` verdict
    // writes a Retry packet and returns without accepting: nothing is committed
    // for that flow — no connection, no entry, no routing map entry. So the
    // listener's first pass holds no accept at all, it has sent a Retry, and
    // the flow is only accepted on the datagram carrying the token back. The
    // dialer acts on that Retry inside `recv`
    // (`vendor/quic/src/quic/connection.zig`, `handleRetryPacket`), so the token
    // flight leaves from the pass that read the Retry, so the flow costs two
    // listener passes with a dialling pass between them.
    //
    // The pair is driven in lockstep until the listener holds an accept rather
    // than to a pass count, because what this test needs is the state a cancel
    // has to account for and how many passes buy it is the core's arithmetic,
    // not a number this fixture should be guessing at. `live` is 0 until the
    // flow comes back proved and 1 from that pass until the task is reaped, so
    // the drive stops at the first pass holding one and the close below still
    // races an accept that is running. Whether it arrived is the next
    // assertion, which names what is missing when it did not.
    var at: Instant = start_ns;
    try runtime.start(dialer, at, node_mod.generator(dialer));
    const nodes = [_]*node_mod.Node{ dialer, listener };
    _ = try driveUntil(&nodes, &at, listenerHoldsAccept);

    // The precondition, stated positively: an accept task is live, the handler
    // has not run, and the handshake is not through. A connection that had
    // finished would have been reaped by `drive` in the same pass.
    try t.expectEqual(@as(usize, 1), listener.accept.live);
    try t.expectEqual(@as(u64, 0), listener.stats.handler_connections);
    // And nothing has been routed: a task still waiting on its handshake has
    // no protocol, which is the state `hold` writes it in and the only state
    // `Task.protocol` is null for. A counter that had already grown here would
    // say this node routed a connection it has not finished accepting.
    try t.expectEqual(@as(u64, 0), listener.stats.tasks_routed);
    try t.expectEqual(@as(usize, 0), node_mod.establishedCount(listener));

    try closing.close(t.io, listener, at, node_mod.generator(listener));

    // The cancel ran, on the task that was live, and the close came after it.
    try t.expectEqual(@as(u64, 1), listener.stats.accepts_cancelled);
    try t.expectEqual(@as(u64, 1), listener.stats.handler_shutdowns);
    try t.expectEqual(@as(u64, 0), listener.stats.handler_connections);
    try t.expectEqual(@as(usize, 0), listener.accept.live);
    try t.expectEqual(shutdown_mod.Shutdown.Phase.closed, listener.accept.shutdown.phase);
    try t.expect(!listener.socket_open);

    // The dialling side closes too: a release that only deinited it would find
    // a lease still in `serving` and report the abandoned endpoint at error
    // level, which fails the artifact. That is the point of the report and not
    // a reason to leave a node open.
    try closing.close(t.io, dialer, at, node_mod.generator(dialer));
    try t.expectEqual(shutdown_mod.Shutdown.Phase.closed, dialer.accept.shutdown.phase);
}

test "a stop asked for before the loop is entered ends it and closes the node" {
    const node = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0x7a),
        .listen = loopback,
        .topic = briskTopic(),
    });
    defer lifecycle.deinit(node);

    var stop = node_mod.Stop.init();
    try t.expect(!stop.requested());
    try t.expect(!stop.expired(start_ns));
    try t.expectEqual(shutdown_mod.Shutdown.Phase.serving, node.accept.shutdown.phase);

    // Raised before `run` is entered, which is what a signal handler reaching
    // the loop between two passes looks like.
    stop.request();
    try t.expect(stop.requested());
    try t.expect(stop.expired(start_ns));
    try runtime.run(t.io, node, &stop);

    // No pass ran, and the node closed anyway: the exit is not a consequence of
    // the work, and neither is the dial `run` would have done on its first.
    try t.expectEqual(@as(u64, 0), node.stats.steps);
    try t.expectEqual(shutdown_mod.Shutdown.Phase.closed, node.accept.shutdown.phase);
    try t.expectEqual(@as(u64, 1), node.stats.handler_shutdowns);
    try t.expectEqual(@as(usize, 0), node.accept.live);
    try t.expect(!node.socket_open);

    // A second `run` on a closed node is the no-op it looks like: the close
    // only runs out of `serving`, so nothing is shut down twice.
    try runtime.run(t.io, node, &stop);
    try t.expectEqual(@as(u64, 1), node.stats.handler_shutdowns);
    try t.expectEqual(@as(u64, 0), node.stats.steps);
}

/// A runtime that is cancelled the way a real backend is: it answers
/// `checkCancel` with `error.Canceled` until the task blocks cancellation, and
/// it honours `swapCancelProtection` to know when that is.
///
/// Two vtable fields and one double, so every other answer stays the live
/// backend's and the close these tests watch afterwards is a real write rather
/// than a stub. A `checkCancel` that always answered `error.Canceled` would
/// describe a runtime no backend is: the protection `run` relies on to write
/// its CONNECTION_CLOSEs is exactly what such a double ignores.
/// Kept on the thread that asked for it: the vtable slot receives only the
/// backend's own userdata, so a per-test struct could not reach it without
/// taking every other slot's userdata with it and breaking the live backend.
threadlocal var cancel_protection: std.Io.CancelProtection = .unblocked;

/// The two slots of an otherwise untouched vtable, and the whole of the double.
fn cancelledCheck(userdata: ?*anyopaque) std.Io.Cancelable!void {
    _ = userdata;
    if (cancel_protection == .blocked) return;
    return error.Canceled;
}

fn cancelledSwap(userdata: ?*anyopaque, new: std.Io.CancelProtection) std.Io.CancelProtection {
    _ = userdata;
    const previous = cancel_protection;
    cancel_protection = new;

    return previous;
}

/// An `std.Io` that is `io` in every slot except its entropy source, which
/// answers `refused`.
///
/// **A copy of the live vtable with `io`'s own userdata, never a foreign
/// backend's.** Every other slot keeps the real backend's answer, so every
/// cancellation point around this node is a live one and only the entropy draw
/// is the double. That is the whole of what `create` uses `io` for — the two
/// transport secrets `Bridge.create` draws and this node's own CSPRNG seed —
/// so nothing else about the runtime is being described here, and pairing this
/// vtable with a different `userdata` would be exactly the mistake that pairs
/// `Io.Threaded`'s slots with something that is not its backend.
///
/// `vtable` is the caller's own storage and so outlives every `Io` built from
/// it here, which is the same discipline `quic_bridge.zig`'s own double
/// follows for its `cancelled_vtable`.
fn refusingEntropy(
    comptime refused: std.Io.RandomSecureError,
    io: std.Io,
    vtable: *std.Io.VTable,
) std.Io {
    vtable.* = io.vtable.*;
    vtable.randomSecure = struct {
        fn draw(_: ?*anyopaque, _: []u8) std.Io.RandomSecureError!void {
            return refused;
        }
    }.draw;
    return .{ .userdata = io.userdata, .vtable = vtable };
}

test "a cancelled Io ends the loop, and the node is closed with its closes written" {
    // Two nodes, because the half of the promise that can fail is the one with
    // something to release: `close` writes a CONNECTION_CLOSE per connection
    // before it shuts the descriptor, and that write is the only work the
    // shutdown asks of a runtime at all.
    const listener = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0x61),
        .listen = loopback,
        .topic = briskTopic(),
    });
    defer lifecycle.deinit(listener);

    const peers = [_]config.Peer{.{
        .id = node_mod.nodeId(listener),
        .addr = .{ .ip = node_mod.address(listener) },
    }};
    const dialer = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0xa1),
        .listen = loopback,
        .peers = &peers,
        .topic = briskTopic(),
    });
    defer lifecycle.deinit(dialer);

    // A live connection, established over real sockets exactly as the test
    // above establishes one.
    var at: Instant = start_ns;
    try runtime.start(dialer, at, node_mod.generator(dialer));
    var pass: usize = 0;
    while (pass < max_passes) : (pass += 1) {
        at += time_quantum;
        _ = try runtime.step(t.io, dialer, at, node_mod.generator(dialer));
        _ = try runtime.step(t.io, listener, at, node_mod.generator(listener));
    }
    try t.expectEqual(@as(usize, 1), node_mod.establishedCount(dialer));
    try t.expectEqual(@as(usize, 1), node_mod.establishedCount(listener));

    // A runtime that refuses. Every other answer stays the live backend's, so
    // the close this test watches afterwards is a real write and not a stub.
    cancel_protection = .unblocked;
    var vtable = t.io.vtable.*;
    vtable.checkCancel = cancelledCheck;
    vtable.swapCancelProtection = cancelledSwap;
    const cancelled: std.Io = .{ .userdata = t.io.userdata, .vtable = &vtable };
    defer cancel_protection = .unblocked;

    var stop = node_mod.Stop.init();
    const steps_before = dialer.stats.steps;
    const written_before = dialer.stats.datagrams_out;
    try t.expectError(error.Canceled, runtime.run(cancelled, dialer, &stop));

    // The exit is the cancellation and not the work: one pass ran and stopped at
    // the socket's first question.
    try t.expectEqual(steps_before + 1, dialer.stats.steps);

    // The node is closed. This is the promise, and it is a promise about the
    // exits the loop did not choose: whatever ended `run`, a caller left
    // holding this node holds a closed one — the shutdown out of `serving`, the
    // accepts reaped, the descriptor gone.
    try t.expectEqual(shutdown_mod.Shutdown.Phase.closed, dialer.accept.shutdown.phase);
    try t.expectEqual(@as(u64, 1), dialer.stats.handler_shutdowns);
    try t.expectEqual(@as(usize, 0), dialer.accept.live);
    try t.expect(!dialer.socket_open);

    // And the peer was told rather than left to time out, which is the half
    // that needs cancellation protection: `run` answers the cancellation it was
    // given, not the one the close would have hit on the same `Io`.
    try t.expect(dialer.stats.datagrams_out > written_before);

    // The listener closes too, or its `defer deinit` reports an endpoint
    // dropped without a close and the error-level log fails the artifact.
    try closing.close(t.io, listener, at, node_mod.generator(listener));
}

/// A clock whose answer `Instant` — a signed 64-bit nanosecond count — cannot
/// hold, which is what `error.InstantOutOfRange` is for. One field of an
/// otherwise untouched vtable again, and this time the refusal is the clock
/// rather than the runtime.
fn unusableClock(_: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
    return .{ .nanoseconds = std.math.maxInt(i96) };
}

test "a clock this node cannot use still closes the node" {
    // The exit before the loop body, and the reason the cleanup is registered
    // before the first clock read rather than after it: `create` has already
    // opened the descriptor, so a caller that gets this error back and then
    // calls `deinit` must not be left holding an endpoint that was never shut.
    const node = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0x7c),
        .listen = loopback,
        .topic = briskTopic(),
    });
    defer lifecycle.deinit(node);

    var vtable = t.io.vtable.*;
    vtable.now = unusableClock;
    const broken: std.Io = .{ .userdata = t.io.userdata, .vtable = &vtable };

    var stop = node_mod.Stop.init();
    try t.expectError(error.InstantOutOfRange, runtime.run(broken, node, &stop));

    // Nothing ran, and the node is closed anyway. With no instant to stamp a
    // connection close with there is nothing graceful left to do, so this is the
    // disposal path: the handler released, the descriptor shut, the machine at
    // `closed`.
    try t.expectEqual(@as(u64, 0), node.stats.steps);
    try t.expectEqual(shutdown_mod.Shutdown.Phase.closed, node.accept.shutdown.phase);
    try t.expectEqual(@as(u64, 1), node.stats.handler_shutdowns);
    try t.expectEqual(@as(usize, 0), node.accept.live);
    try t.expect(!node.socket_open);
}

test "a close that cannot write is finished by the close after it" {
    // The residue a failed send leaves, and what has to be able to clear it.
    // `close_endpoint` is the only step that touches a runtime, so a socket that
    // refuses its sends stops the machine in `closing_endpoint` with the
    // descriptor open — and a close that refuses to resume there would leave a
    // node nothing can ever finish.
    const listener = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0x62),
        .listen = loopback,
        .topic = briskTopic(),
    });
    defer lifecycle.deinit(listener);

    const peers = [_]config.Peer{.{
        .id = node_mod.nodeId(listener),
        .addr = .{ .ip = node_mod.address(listener) },
    }};
    const dialer = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0xa2),
        .listen = loopback,
        .peers = &peers,
        .topic = briskTopic(),
    });
    defer lifecycle.deinit(dialer);

    var at: Instant = start_ns;
    try runtime.start(dialer, at, node_mod.generator(dialer));
    var pass: usize = 0;
    while (pass < max_passes) : (pass += 1) {
        at += time_quantum;
        _ = try runtime.step(t.io, dialer, at, node_mod.generator(dialer));
        _ = try runtime.step(t.io, listener, at, node_mod.generator(listener));
    }
    try t.expectEqual(@as(usize, 1), node_mod.establishedCount(dialer));

    // A runtime that refuses, and a close that therefore stops on the first
    // send it cannot make.
    cancel_protection = .unblocked;
    var vtable = t.io.vtable.*;
    vtable.checkCancel = cancelledCheck;
    vtable.swapCancelProtection = cancelledSwap;
    const cancelled: std.Io = .{ .userdata = t.io.userdata, .vtable = &vtable };
    defer cancel_protection = .unblocked;
    try t.expectError(error.Canceled, closing.close(cancelled, dialer, at, node_mod.generator(dialer)));

    // Mid-shutdown, with the descriptor still open: the state this test is for.
    try t.expectEqual(shutdown_mod.Shutdown.Phase.closing_endpoint, dialer.accept.shutdown.phase);
    try t.expect(dialer.socket_open);

    // And the next close finishes it rather than refusing, which means
    // re-performing the step that failed and then reporting it — the machine
    // will not emit `close_endpoint` twice on its own.
    try closing.close(t.io, dialer, at, node_mod.generator(dialer));
    try t.expectEqual(shutdown_mod.Shutdown.Phase.closed, dialer.accept.shutdown.phase);
    try t.expect(!dialer.socket_open);

    try closing.close(t.io, listener, at, node_mod.generator(listener));
}

test "a stop becomes due at the instant it was given and not before" {
    var stop = node_mod.Stop.init();
    try t.expect(!stop.expired(start_ns));
    stop.expireAt(start_ns + time_quantum);
    // One nanosecond short of the deadline is not the deadline.
    try t.expect(!stop.expired(start_ns + time_quantum - 1));
    try t.expect(stop.expired(start_ns + time_quantum));
}

// ---------------------------------------------------------------------------
// The relay
// ---------------------------------------------------------------------------

/// Drive `nodes` in lockstep until `want` says the state has arrived.
///
/// Virtual time moves one quantum a pass and nothing here sleeps, so the bound
/// is on passes and not on a clock — the same discipline the rest of this
/// section runs on.
fn driveUntil(
    nodes: []const *node_mod.Node,
    at: *Instant,
    want: fn (nodes: []const *node_mod.Node) bool,
) node_error.Error!bool {
    var pass: usize = 0;
    while (pass < max_passes) : (pass += 1) {
        at.* += time_quantum;
        for (nodes) |node| _ = try runtime.step(t.io, node, at.*, node_mod.generator(node));
        if (want(nodes)) return true;
    }
    return false;
}

/// Both clients are established and the relay holds two node ids.
fn bothAdmitted(nodes: []const *node_mod.Node) bool {
    return client_pass.clientCount(nodes[0]) == 2 and
        nodes[1].stats.relay_established == 1 and
        // The third node, and this predicate's only caller is the relay test,
        // whose array is `{ relay, a, b }`. The engine holds `driveUntil`'s
        // callback parameter at the two-node `listenerHoldsAccept` length.
        // zwanzig-disable-next-line: slice-bounds-engine
        nodes[2].stats.relay_established == 1;
}

/// The challenge this relay is holding out to one of its clients, if it is
/// holding one right now.
///
/// **Read from the slot the handshake actually wrote, not from a copy the test
/// made.** `serveAdmit` draws sixteen bytes into a local and hands them to
/// `relay_server.step`, which copies them into a client slot; this reads
/// that copy, so it is the challenge that went on the wire and is still
/// outstanding. Null once the client has answered, because `.challenged` is a
/// state and the handshake has moved past it — which is why this has to be read
/// before the answer rather than after the admission.
fn outstandingChallenge(relay: *const node_mod.Node) ?[relay_frame.ServerChallenge.challenge_length]u8 {
    for (relay.relay_state.clients) |slot| {
        if (!slot.live) continue;
        switch (slot.handshake) {
            .challenged => |challenged| return challenged.challenge.challenge,
            else => {},
        }
    }
    return null;
}

/// The first client has been told that a peer is not at the relay.
fn toldPeerGone(nodes: []const *node_mod.Node) bool {
    return nodes[1].stats.relay_peer_gone == 1;
}

/// The second client has been handed both of the datagrams queued for it.
fn twoDelivered(nodes: []const *node_mod.Node) bool {
    // The third node again, for the reason `bothAdmitted` gives: this
    // predicate's only caller is the relay test, and its array is three long.
    // zwanzig-disable-next-line: slice-bounds-engine
    return client_pass.delivered(nodes[2]).len >= 2;
}

/// The first client has been handed one datagram.
fn oneDelivered(nodes: []const *node_mod.Node) bool {
    return client_pass.delivered(nodes[1]).len >= 1;
}

test "a relay admits two clients, forwards both ways, and reports each once" {
    // Two datagrams of queue and one message written per pass. Those three
    // numbers are the whole reason the two queues can be told apart below: a
    // flood of three fills the data queue and the message that goes with it
    // still leaves before the datagrams do.
    const relay = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0x5e),
        .listen = loopback,
        .protocols = &.{.{ .alpn = protocol.relay_alpn }},
        .relay = .{ .role = .{ .serve = .{
            .clients = 2,
            .queue_depth = 2,
            .drain_room = 1,
        } } },
    });
    defer lifecycle.deinit(relay);

    const relay_peer = [_]config.Peer{.{
        .id = node_mod.nodeId(relay),
        .addr = .{ .ip = node_mod.address(relay) },
    }};
    const a = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0xa1),
        .listen = loopback,
        .protocols = &.{.{ .alpn = protocol.relay_alpn }},
        .relay = .{ .role = .{ .client = relay_peer[0] } },
    });
    defer lifecycle.deinit(a);
    const b = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0xb2),
        .listen = loopback,
        .protocols = &.{.{ .alpn = protocol.relay_alpn }},
        .relay = .{ .role = .{ .client = relay_peer[0] } },
    });
    defer lifecycle.deinit(b);

    // Three different identities, so no end of this can be the other: the
    // relay proves a client owns its node id, and a client that presented the
    // relay's own certificate would prove nothing.
    try t.expect(node_mod.nodeId(a).order(node_mod.nodeId(b)) != .eq);
    try t.expect(node_mod.nodeId(a).order(node_mod.nodeId(relay)) != .eq);

    const nodes = [_]*node_mod.Node{ relay, a, b };
    var at: Instant = start_ns;

    // ── the handshake, twice ──
    const admitted = try driveUntil(&nodes, &at, bothAdmitted);
    if (!admitted) std.debug.print(
        "\nrelay stalled at pass {d}: clients {d} admitted {d} attempts {d} handler {d}\n" ++
            "  a: dials {d} refused {d} auth {d} est {d} established {d}\n" ++
            "  b: dials {d} refused {d} auth {d} est {d} established {d}\n" ++
            "  relay refused {d} oversize {d} unknown {d}\n",
        .{
            at,
            client_pass.clientCount(relay),
            relay.stats.relay_admitted,
            relay.stats.attempts,
            relay.stats.handler_connections,
            a.stats.relay_dials,
            a.stats.relay_dials_refused,
            a.stats.relay_auth_sent,
            a.stats.relay_established,
            node_mod.establishedCount(a),
            b.stats.relay_dials,
            b.stats.relay_dials_refused,
            b.stats.relay_auth_sent,
            b.stats.relay_established,
            node_mod.establishedCount(b),
            relay.stats.relay_refused,
            relay.stats.relay_oversized,
            relay.stats.relay_unknown_target,
        },
    );
    try t.expect(admitted);
    try t.expectEqual(@as(usize, 2), client_pass.clientCount(relay));
    try t.expectEqual(@as(u64, 2), relay.stats.attempts);
    try t.expectEqual(@as(u64, 2), relay.stats.handler_connections);
    try t.expectEqual(@as(u64, 2), relay.stats.relay_admitted);
    // One challenge signed by each, and one confirmation each: the path taken
    // is the challenge, because this transport has no key material to offer.
    try t.expectEqual(@as(u64, 1), a.stats.relay_auth_sent);
    try t.expectEqual(@as(u64, 1), b.stats.relay_auth_sent);
    try t.expectEqual(@as(u64, 1), a.stats.relay_established);
    try t.expectEqual(@as(u64, 1), b.stats.relay_established);

    // ── two queues, observed rather than assumed ──
    //
    // Three datagrams into a queue of two, and one to a peer nobody holds,
    // all written before the relay next looks. The third datagram cannot be
    // queued and the message about the missing peer goes on the *control*
    // queue, which has all the room there is.
    const stranger = (try identityOf(0x77)).nodeId();
    try client_pass.sendThrough(a, node_mod.nodeId(b), "one");
    try client_pass.sendThrough(a, node_mod.nodeId(b), "two");
    try client_pass.sendThrough(a, node_mod.nodeId(b), "three");
    try client_pass.sendThrough(a, stranger, "nowhere");

    try t.expect(try driveUntil(&nodes, &at, toldPeerGone));
    // The message did not wait behind the datagrams: when the first client was
    // told, fewer of the queued datagrams had gone out than the relay had
    // taken. Merged into one queue both of them would have gone first and this
    // would be two — which is invariant 9, observed rather than cited.
    try t.expect(client_pass.delivered(b).len < relay.stats.relay_forwarded);
    try t.expectEqual(@as(u64, 2), relay.stats.relay_forwarded);
    try t.expectEqual(@as(u64, 1), relay.stats.relay_queue_full);
    try t.expectEqual(@as(u64, 1), relay.stats.relay_unknown_target);

    // ── the datagrams themselves, in order ──
    try t.expect(try driveUntil(&nodes, &at, twoDelivered));
    try t.expectEqual(@as(usize, 2), client_pass.delivered(b).len);
    try t.expectEqual(node_mod.nodeId(a), client_pass.delivered(b)[0].src);
    try t.expectEqualStrings("one", client_pass.delivered(b)[0].data);
    try t.expectEqual(node_mod.nodeId(a), client_pass.delivered(b)[1].src);
    try t.expectEqualStrings("two", client_pass.delivered(b)[1].data);

    // ── and the other direction, which is the same relay and no new path ──
    try client_pass.sendThrough(b, node_mod.nodeId(a), "back");
    try t.expect(try driveUntil(&nodes, &at, oneDelivered));
    try t.expectEqual(@as(usize, 1), client_pass.delivered(a).len);
    try t.expectEqual(node_mod.nodeId(b), client_pass.delivered(a)[0].src);
    try t.expectEqualStrings("back", client_pass.delivered(a)[0].data);

    // ── admission is once, however many passes follow ──
    var quiet: usize = 0;
    while (quiet < 16) : (quiet += 1) {
        at += time_quantum;
        for (nodes) |node| _ = try runtime.step(t.io, node, at, node_mod.generator(node));
    }
    try t.expectEqual(@as(u64, 2), relay.stats.relay_admitted);
    try t.expectEqual(@as(usize, 2), client_pass.clientCount(relay));
    try t.expectEqual(@as(u64, 0), relay.stats.relay_double_reports);

    // ── the shutdown, in the order `shutdown_mod.Shutdown` enforces ──
    //
    // The relay's clients are given up in `shutdown_handlers`, which is the
    // first of the three phases, so every disconnect is reported before the
    // endpoint close writes anything at all.
    for (nodes) |node| try closing.close(t.io, node, at, node_mod.generator(node));
    for (nodes) |node| {
        try t.expectEqual(shutdown_mod.Shutdown.Phase.closed, node.accept.shutdown.phase);
        try t.expectEqual(@as(usize, 0), node.accept.live);
        try t.expect(!node.socket_open);
    }
    try t.expectEqual(@as(usize, 0), client_pass.clientCount(relay));
    try t.expectEqual(@as(u64, 2), relay.stats.relay_disconnects);
    // The other two arms stay at zero, and that is the half that matters. A
    // `.disconnected` that is suppressed is the invariant working; a *first*
    // one that is swallowed is a connection the registry has let go of while
    // the relay still believes it has it, and the two look the same from
    // `relay_disconnects` alone. So the arms that would absorb a report —
    // `.duplicate`, which ends a connection a later one had already displaced,
    // and `.promoted`, which ends one and promotes another — are asserted at
    // zero rather than left to the sum.
    try t.expectEqual(@as(u64, 0), relay.stats.relay_duplicates);
    try t.expectEqual(@as(u64, 0), relay.stats.relay_promoted);
    try t.expectEqual(@as(u64, 0), relay.stats.relay_double_reports);
    try t.expectEqual(@as(u64, 1), relay.stats.handler_shutdowns);

    // A second close is the no-op it looks like: the close runs only out of
    // `serving`, so nothing is given up twice and nothing is reported twice.
    for (nodes) |node| try closing.close(t.io, node, at, node_mod.generator(node));
    try t.expectEqual(@as(u64, 2), relay.stats.relay_disconnects);
    try t.expectEqual(@as(u64, 0), relay.stats.relay_duplicates);
    try t.expectEqual(@as(u64, 0), relay.stats.relay_promoted);
    try t.expectEqual(@as(u64, 0), relay.stats.relay_double_reports);
    try t.expectEqual(@as(u64, 1), relay.stats.handler_shutdowns);
}

test "two relays built the same way challenge their clients differently" {
    // The relay half of the entropy claim, which is a different consumer from
    // the TLS scalars and has to be claimed separately.
    //
    // **`serveAdmit` drew the admission challenge from the loop's `random`
    // parameter**, which in production is the node's own generator — the same
    // `std.Random.DefaultPrng` seeded from a caller-supplied `u64` that `create`
    // builds. So a relay built the same way as another relay issued the same
    // sixteen bytes to its first client, and a challenge is exactly the value a
    // captured signed reply is replayed against.
    //
    // **What is not being claimed, and why.** A relay cannot forge ed25519 from a
    // known challenge: `relay_server.step` verifies the client's signature under
    // the node id it claimed, and `relay_server.zig`'s own tests already cover a
    // challenge answered with a wrong key, one answered under another node id,
    // and a captured reply presented against a different challenge. What a
    // repeated challenge adds is replay of a reply that was valid once, so the
    // invariant under test here is repetition and nothing else. Those denial
    // cases are reused rather than restated, and nothing here weakens them.
    //
    // Two relays and two clients over real sockets. The challenge is read off
    // the handshake the relay is actually holding (`outstandingChallenge`)
    // before the client answers it, which is why the drive stops the moment the
    // challenge exists: once the client has answered, `.challenged` is a state
    // this node has moved past and the bytes are gone.
    const first_relay = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0x71),
        .listen = loopback,
        .protocols = &.{.{ .alpn = protocol.relay_alpn }},
        .relay = .{ .role = .{ .serve = .{
            .clients = 1,
            .queue_depth = 4,
            .drain_room = 4,
        } } },
    });
    defer closedOnExit(first_relay);
    const second_relay = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0x72),
        .listen = loopback,
        .protocols = &.{.{ .alpn = protocol.relay_alpn }},
        .relay = .{ .role = .{ .serve = .{
            .clients = 1,
            .queue_depth = 4,
            .drain_room = 4,
        } } },
    });
    defer closedOnExit(second_relay);

    // Each client is given its relay and nothing else, as a peer holding a
    // relay's node id and address is.
    const first_peer = [_]config.Peer{.{
        .id = node_mod.nodeId(first_relay),
        .addr = .{ .ip = node_mod.address(first_relay) },
    }};
    const second_peer = [_]config.Peer{.{
        .id = node_mod.nodeId(second_relay),
        .addr = .{ .ip = node_mod.address(second_relay) },
    }};
    const first_client = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0x81),
        .listen = loopback,
        .protocols = &.{.{ .alpn = protocol.relay_alpn }},
        .relay = .{ .role = .{ .client = first_peer[0] } },
    });
    defer closedOnExit(first_client);
    const second_client = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0x82),
        .listen = loopback,
        .protocols = &.{.{ .alpn = protocol.relay_alpn }},
        .relay = .{ .role = .{ .client = second_peer[0] } },
    });
    defer closedOnExit(second_client);

    // Both relays are built from the same generator seed and are otherwise
    // identical, which is the whole claim: two relays an operator would run
    // with the same command line. Four different identities, so no end of this
    // can be the other.
    var at: Instant = start_ns;
    try runtime.start(first_client, at, node_mod.generator(first_client));
    try runtime.start(second_client, at, node_mod.generator(second_client));

    // Senders first and relays last, so a frame written on one pass is on the
    // wire before that relay is asked to read it.
    const nodes = [_]*node_mod.Node{ first_client, second_client, first_relay, second_relay };
    var first_challenge: ?[relay_frame.ServerChallenge.challenge_length]u8 = null;
    var second_challenge: ?[relay_frame.ServerChallenge.challenge_length]u8 = null;
    var pass: usize = 0;
    while (pass < max_passes and (first_challenge == null or second_challenge == null)) : (pass += 1) {
        try passOnce(&nodes, &at);
        if (first_challenge == null) first_challenge = outstandingChallenge(first_relay);
        if (second_challenge == null) second_challenge = outstandingChallenge(second_relay);
    }
    const one = first_challenge orelse return error.NoChallengeWasIssued;
    const two = second_challenge orelse return error.NoChallengeWasIssued;

    // Each relay really did serve an arrival over a real handshake: the slot
    // was taken and the challenge is only ever issued to one that got that far.
    try t.expectEqual(@as(u64, 1), first_relay.stats.attempts);
    try t.expectEqual(@as(u64, 1), second_relay.stats.attempts);

    // The claim. Sixteen bytes is the whole of `challenge_length`, and a relay
    // answering two clients from one stream would repeat every one of them.
    try t.expect(!std.mem.eql(u8, &one, &two));
}

/// One pass over every node, virtual time one quantum further on.
fn passOnce(nodes: []const *node_mod.Node, at: *Instant) node_error.Error!void {
    at.* += time_quantum;
    for (nodes) |node| _ = try runtime.step(t.io, node, at.*, node_mod.generator(node));
}

test "a relay with no room spends no stream, and admits again once a slot frees" {
    // **One client slot and three clients.** That is the shape that leaves two
    // connections established and unserved on every pass, and it is where an
    // open before a slot would spend the peer's whole grant on connections that
    // never become clients. `a` is the one the relay takes: the table is walked
    // in the order the clients dialled, and they are stepped in that order.
    const relay = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0x5f),
        .listen = loopback,
        .protocols = &.{.{ .alpn = protocol.relay_alpn }},
        .relay = .{ .role = .{ .serve = .{
            .clients = 1,
            .queue_depth = 4,
            .drain_room = 4,
        } } },
    });
    defer lifecycle.deinit(relay);

    const relay_peer = [_]config.Peer{.{
        .id = node_mod.nodeId(relay),
        .addr = .{ .ip = node_mod.address(relay) },
    }};
    const a = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0xa1),
        .listen = loopback,
        .protocols = &.{.{ .alpn = protocol.relay_alpn }},
        .relay = .{ .role = .{ .client = relay_peer[0] } },
    });
    defer lifecycle.deinit(a);
    const b = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0xb2),
        .listen = loopback,
        .protocols = &.{.{ .alpn = protocol.relay_alpn }},
        .relay = .{ .role = .{ .client = relay_peer[0] } },
    });
    defer lifecycle.deinit(b);
    const c = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0xc3),
        .listen = loopback,
        .protocols = &.{.{ .alpn = protocol.relay_alpn }},
        .relay = .{ .role = .{ .client = relay_peer[0] } },
    });
    defer lifecycle.deinit(c);
    const nodes = [_]*node_mod.Node{ a, b, c, relay };

    var at: Instant = start_ns;
    var pass: usize = 0;

    // ── one admitted, the other two refused for want of a slot ──
    while (pass < max_passes) : (pass += 1) {
        try passOnce(&nodes, &at);
        if (a.stats.relay_established == 1 and relay.stats.relay_refused > 1) break;
    }
    try t.expectEqual(@as(u64, 1), a.stats.relay_established);
    try t.expectEqual(@as(usize, 1), client_pass.clientCount(relay));
    try t.expectEqual(@as(u64, 1), relay.stats.relay_admitted);
    try t.expectEqual(@as(usize, 3), node_mod.establishedCount(relay));

    // ── and the refusals spent nothing ──
    //
    // A peer grants a hundred bidi streams (`connection.zig:539`) and the core
    // counts every stream this end opens against that grant for the life of the
    // connection, so a hundred and twenty-eight passes is more than either
    // refused connection could afford if this relay opened before it asked.
    //
    // The two counters say which of those happened: the refusal counter moves
    // every pass and the deferral counter does not move at all, because a relay
    // with no room never reaches the open. That is `serveAdmit`'s order, and it
    // is the whole difference between a client turned away and a connection
    // spent.
    const refused_before = relay.stats.relay_refused;
    pass = 0;
    while (pass < max_passes / 2) : (pass += 1) try passOnce(&nodes, &at);
    try t.expect(relay.stats.relay_refused > refused_before);
    try t.expectEqual(@as(u64, 0), relay.stats.relay_stream_deferred);
    try t.expectEqual(@as(u64, 1), relay.stats.relay_admitted);
    try t.expectEqual(@as(usize, 3), node_mod.establishedCount(relay));

    // ── and a freed slot still finds a client ──
    //
    // The client this relay admitted goes away, which is the only thing that
    // frees a slot, and the connections refused on every pass since are still
    // admissible. Under an open before the slot they spent their grants in the
    // passes above and neither could be served at all — which is a relay that
    // refuses forever and says nothing but a counter.
    try closing.close(t.io, a, at, node_mod.generator(a));
    const rest = [_]*node_mod.Node{ b, c, relay };
    pass = 0;
    while (pass < max_passes and relay.stats.relay_admitted < 2) : (pass += 1) {
        try passOnce(&rest, &at);
    }
    try t.expectEqual(@as(u64, 2), relay.stats.relay_admitted);
    try t.expectEqual(@as(usize, 1), client_pass.clientCount(relay));
    try t.expectEqual(@as(u64, 0), relay.stats.relay_stream_deferred);

    // Every node is wound down through the router's shutdown rather than
    // dropped on the floor: a node deinit while still serving logs an error, and
    // four of those would fail this test for a reason that has nothing to do
    // with the passes above.
    for (nodes) |node| try closing.close(t.io, node, at, node_mod.generator(node));
}

test "a refused stream costs a connection and not the pass, a fault the pass" {
    // Built from an allocator this test can break at a chosen pass, because the
    // fault arm below has to fail *inside* a pass rather than before one: a
    // relay built on an allocator that is already refusing cannot be built at
    // all, and a fault that arrives at construction says nothing about whether
    // the accept path swallows one.
    var failing = t.FailingAllocator.init(t.allocator, .{});
    // **Two client slots and three clients.** That is the shape that leaves a
    // connection established and unserved *while a slot is free*, and it is the
    // only shape in which `serveAdmit` reaches `Stream.open` at all: the slot is
    // asked for first, so a connection refused for want of one is never asked
    // for a stream. Three rather than two because the refusal arm needs a
    // client left over to make the pass worth spending.
    const relay = try lifecycle.create(failing.allocator(), t.io, .{
        .secret = try identityOf(0x5e),
        .listen = loopback,
        .protocols = &.{.{ .alpn = protocol.relay_alpn }},
        .relay = .{ .role = .{ .serve = .{
            .clients = 2,
            .queue_depth = 4,
            .drain_room = 4,
        } } },
    });
    defer lifecycle.deinit(relay);

    const relay_peer = [_]config.Peer{.{
        .id = node_mod.nodeId(relay),
        .addr = .{ .ip = node_mod.address(relay) },
    }};
    const a = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0xa1),
        .listen = loopback,
        .protocols = &.{.{ .alpn = protocol.relay_alpn }},
        .relay = .{ .role = .{ .client = relay_peer[0] } },
    });
    defer lifecycle.deinit(a);
    const b = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0xb2),
        .listen = loopback,
        .protocols = &.{.{ .alpn = protocol.relay_alpn }},
        .relay = .{ .role = .{ .client = relay_peer[0] } },
    });
    defer lifecycle.deinit(b);
    const c = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0xc3),
        .listen = loopback,
        .protocols = &.{.{ .alpn = protocol.relay_alpn }},
        .relay = .{ .role = .{ .client = relay_peer[0] } },
    });
    defer lifecycle.deinit(c);
    const nodes = [_]*node_mod.Node{ a, b, c, relay };

    var at: Instant = start_ns;
    var pass: usize = 0;

    // ── two admitted, the third established and unserved ──
    while (pass < max_passes) : (pass += 1) {
        try passOnce(&nodes, &at);
        if (relay.stats.relay_admitted == 2 and node_mod.establishedCount(relay) == 3) break;
    }
    try t.expectEqual(@as(u64, 2), relay.stats.relay_admitted);
    try t.expectEqual(@as(usize, 2), client_pass.clientCount(relay));
    try t.expectEqual(@as(usize, 3), node_mod.establishedCount(relay));

    // The connection this relay is not serving, named by that rather than by the
    // slot the core keeps it in: which slot a connection occupies is the core's
    // ordering, not this test's to assume.
    var idle: ?Conn = null;
    var index: usize = 0;
    while (relay.bridge.connectionAt(index)) |conn| : (index += 1) {
        if (!conn.entry.conn.is_server) continue;
        if (relay.relay_state.servedFor(conn.id()) != null) continue;
        idle = conn;
        break;
    }
    const held = idle orelse return error.NoUnservedConnection;

    // ── and no stream either ──
    //
    // Zeroing the core's limit turns "a slot is free" into "and the core has no
    // stream id to give", which is the refusal the bridge names and the accept
    // path has to survive.
    //
    // **It has to be now and not a pass earlier.** The core re-applies the
    // peer's transport parameters at the instant the handshake completes
    // (`connection.zig:2650`) — in the same pass, immediately before
    // `serveAdmit` runs — so a limit set before that handshake is a limit the
    // handshake overwrites before anything reads it.
    held.entry.conn.streams.setMaxStreams(0, 8);

    // ── the refusal costs that connection and nothing else ──
    //
    // Closing a served client is the only thing that frees a slot, and the pass
    // after it is the first one that asks for a stream at all. The relay keeps
    // the client it had, the connection it could not open a stream on is
    // counted as deferred rather than refused, and it is counted again on the
    // next pass — which is the whole claim, because these are phases of one
    // pass and the first of them used to end it.
    try closing.close(t.io, a, at, node_mod.generator(a));
    const rest = [_]*node_mod.Node{ b, c, relay };
    pass = 0;
    while (pass < max_passes and relay.stats.relay_stream_deferred < 2) : (pass += 1) {
        try passOnce(&rest, &at);
    }
    try t.expect(relay.stats.relay_stream_deferred >= 2);
    try t.expectEqual(@as(u64, 2), relay.stats.relay_admitted);
    try t.expectEqual(@as(usize, 1), client_pass.clientCount(relay));

    // And a pass that got past `serveAdmit` is a pass that went on to read: a
    // datagram this relay has to route to a peer it does not hold is routed on
    // one of them, and the client that sent it is told.
    const stranger = (try identityOf(0x77)).nodeId();
    try client_pass.sendThrough(b, stranger, "nowhere");
    pass = 0;
    while (pass < max_passes and b.stats.relay_peer_gone == 0) : (pass += 1) {
        try passOnce(&rest, &at);
    }
    try t.expectEqual(@as(u64, 1), relay.stats.relay_unknown_target);
    try t.expectEqual(@as(u64, 1), b.stats.relay_peer_gone);

    // ── a genuine fault, at the same call, still fails the pass ──
    //
    // The same connection, still unserved and now holding a stream of credit,
    // so `Stream.open` gets past the limit check and allocates. That allocation
    // is the whole difference between this call and the one above: a refusal the
    // protocol makes temporary, and a fault in this node. The allocator behind
    // this relay refuses the very next allocation.
    held.entry.conn.streams.setMaxStreams(1, 8);
    failing.fail_index = failing.alloc_index;
    const deferred_at_fault = relay.stats.relay_stream_deferred;
    // `CoreRefused` and not `NoStreamRoom`, on the same connection and the same
    // call: the refusal arm above cost this connection a pass and the fault
    // costs the pass, which is the difference the two arms exist to draw.
    try t.expectError(error.CoreRefused, runtime.step(t.io, relay, at, node_mod.generator(relay)));
    try t.expectEqual(deferred_at_fault, relay.stats.relay_stream_deferred);

    // Every node is wound down through the router's shutdown rather than
    // dropped on the floor: a node deinit while still serving logs an error, and
    // four of those would fail this test for a reason that has nothing to do
    // with the arms above it.
    for (nodes) |node| try closing.close(t.io, node, at, node_mod.generator(node));
}

test "a frame a peer stopped writing is counted and dropped, never read as a message" {
    const relay = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0x60),
        .listen = loopback,
        .protocols = &.{.{ .alpn = protocol.relay_alpn }},
        .relay = .{ .role = .{ .serve = .{
            .clients = 1,
            .queue_depth = 4,
            .drain_room = 4,
        } } },
    });
    defer lifecycle.deinit(relay);

    const relay_peer = [_]config.Peer{.{
        .id = node_mod.nodeId(relay),
        .addr = .{ .ip = node_mod.address(relay) },
    }};
    const a = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0xa4),
        .listen = loopback,
        .protocols = &.{.{ .alpn = protocol.relay_alpn }},
        .relay = .{ .role = .{ .client = relay_peer[0] } },
    });
    defer lifecycle.deinit(a);
    const nodes = [_]*node_mod.Node{ a, relay };

    var at: Instant = start_ns;
    var pass: usize = 0;
    while (pass < max_passes) : (pass += 1) {
        try passOnce(&nodes, &at);
        if (a.stats.relay_established == 1 and client_pass.clientCount(relay) == 1) break;
    }
    try t.expectEqual(@as(u64, 1), a.stats.relay_established);
    try t.expectEqual(@as(usize, 1), client_pass.clientCount(relay));

    // Half a frame, and then the end of the stream: a length whose bytes the
    // writer never sent. **This is what `Stream.drain` cannot report.** It
    // answers whether it appended bytes and nothing about what came before them,
    // so a stream that ended here and a stream with nothing on it read the same,
    // and `discardTail` is what tells them apart.
    const half = [_]u8{ 8, 0x51, 0x50 };
    // Both established above, so an absent spoke or stream here is a defect in
    // the path that got here and not a condition this test allows for. It is
    // returned rather than unwrapped so the runner reports which test broke
    // and the assertions below still say what was true of the wire.
    const spoke = a.relay_state.spoke orelse return error.TestUnexpectedResult;
    var out = spoke.stream orelse return error.TestUnexpectedResult;
    // The whole of it, as `writeRelay` makes every write on this path: what the
    // peer is given is one length with three of its bytes behind it, and a
    // short write is a defect in the path that got here rather than a condition
    // the assertions below read around.
    const sent = try out.write(&half);
    if (sent != half.len) return error.TestUnexpectedResult;
    out.close();

    pass = 0;
    while (pass < max_passes and relay.stats.relay_stream_truncated == 0) : (pass += 1) {
        try passOnce(&nodes, &at);
    }
    try t.expectEqual(@as(u64, 1), relay.stats.relay_stream_truncated);
    // And it was never a message: a length this relay could not read is a
    // length it refuses rather than one it decodes.
    try t.expectEqual(@as(u64, 0), relay.stats.relay_datagrams_in);

    // Counted once, not on every pass after it: the bytes are gone.
    const truncated = relay.stats.relay_stream_truncated;
    pass = 0;
    while (pass < 8) : (pass += 1) try passOnce(&nodes, &at);
    try t.expectEqual(truncated, relay.stats.relay_stream_truncated);

    for (nodes) |node| try closing.close(t.io, node, at, node_mod.generator(node));
}

/// Three bytes that are a whole relay frame and not the beginning of one: a
/// QUIC varint length of two, then the frame type of `server_confirms_auth`
/// and one payload byte behind it. `relay/frame.zig:725` reads that frame only
/// when its payload is empty and answers `error.InvalidFrame` when it is not,
/// so `peekFrame` has a complete frame to hand over and the answer comes
/// back from `decode` rather than from the length.
///
/// **This is not the half-written frame the test above covers.** There the
/// length names bytes that never arrive and the reader must wait for them;
/// here every byte the length names has arrived, so the frame is this node's
/// to decide about and the decision is made once. A reader that leaves it on
/// the inbox decides about it again on the next pass, and on every pass after
/// that, for as long as the connection lives.
const poison_frame = [_]u8{ 2, 2, 0 };

/// The one client this relay is serving, named by the slot that is live rather
/// than by which connection the core happened to give it.
fn liveSlot(relay: *node_mod.Node) ?*relay_storage.client_type {
    for (relay.relay_state.clients) |*slot| {
        if (slot.live) return slot;
    }
    return null;
}

test "a relay reads past a frame it cannot decode and does not serve one twice" {
    // **One datagram, then the poison, on one stream.** Both halves of a relay
    // read in one run of bytes and in that order, so the relay has acted on a
    // message and met a frame it cannot decode in a single pass, and whatever
    // it does with the second says what it does with the first.
    const relay = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0x61),
        .listen = loopback,
        .protocols = &.{.{ .alpn = protocol.relay_alpn }},
        .relay = .{ .role = .{ .serve = .{
            .clients = 1,
            .queue_depth = 4,
            .drain_room = 4,
        } } },
    });
    defer lifecycle.deinit(relay);

    const relay_peer = [_]config.Peer{.{
        .id = node_mod.nodeId(relay),
        .addr = .{ .ip = node_mod.address(relay) },
    }};
    const a = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0xb1),
        .listen = loopback,
        .protocols = &.{.{ .alpn = protocol.relay_alpn }},
        .relay = .{ .role = .{ .client = relay_peer[0] } },
    });
    defer lifecycle.deinit(a);
    const nodes = [_]*node_mod.Node{ a, relay };

    var at: Instant = start_ns;
    var pass: usize = 0;
    while (pass < max_passes) : (pass += 1) {
        try passOnce(&nodes, &at);
        if (a.stats.relay_established == 1 and client_pass.clientCount(relay) == 1) break;
    }
    try t.expectEqual(@as(u64, 1), a.stats.relay_established);
    try t.expectEqual(@as(usize, 1), client_pass.clientCount(relay));

    // A datagram for a node id this relay holds nobody for, and then the frame
    // that cannot be decoded. The datagram is the one the counters can be read
    // against, which is why it goes first: a frame this relay has already
    // served is told apart from one it has not by what it counted, and not by
    // the pass it counted it in.
    const stranger = (try identityOf(0x77)).nodeId();
    try client_pass.sendThrough(a, stranger, "one");
    // Established above, as in the test above: absent here is a defect in the
    // path that got here, reported rather than unwrapped.
    const spoke = a.relay_state.spoke orelse return error.TestUnexpectedResult;
    var out = spoke.stream orelse return error.TestUnexpectedResult;
    // And the whole of the poison, on the same terms: the claim below is about
    // a frame that *arrived* and could not be decoded, and a short write would
    // put a prefix of one on the wire instead of a frame to refuse.
    const sent = try out.write(&poison_frame);
    if (sent != poison_frame.len) return error.TestUnexpectedResult;

    // The relay is stepped one pass at a time and its refusals are counted
    // rather than returned, because the claim is about the passes *after* the
    // one that fails: a frame read whole and not decodable is answered once,
    // taken off the inbox, and every pass after it is a pass with nothing left
    // to do. `refused < 2` is what stops this loop on a reader that has not
    // done that — one refusal is the claim and a second is the defect.
    var refused: usize = 0;
    var clean: usize = 0;
    pass = 0;
    while (pass < max_passes and refused < 2) : (pass += 1) {
        at += time_quantum;
        _ = try runtime.step(t.io, a, at, node_mod.generator(a));
        if (runtime.step(t.io, relay, at, node_mod.generator(relay))) |_| {
            // Either the frame has not been drained yet or it is gone, and
            // only the second of those ends this loop, so only the second is
            // counted towards leaving it.
            if (refused == 1) clean += 1;
        } else |err| {
            try t.expectEqual(node_error.Error.InvalidFrame, err);
            refused += 1;
            clean = 0;
        }
        if (refused == 1 and clean == 4) break;
    }
    try t.expectEqual(@as(usize, 1), refused);

    // Acted on once: not zero, because the datagram was read whole and served
    // before the poison was met, and not once per pass, because the pass that
    // met the poison is not a pass that gave the datagram back.
    try t.expectEqual(@as(u64, 1), relay.stats.relay_datagrams_in);
    try t.expectEqual(@as(u64, 1), relay.stats.relay_unknown_target);
    // And nothing is left on the inbox, which is the state those two counters
    // are otherwise re-derived from on the next pass.
    const slot = liveSlot(relay) orelse return error.NoLiveClient;
    try t.expectEqual(@as(usize, 0), slot.inbox.items.len);

    for (nodes) |node| try closing.close(t.io, node, at, node_mod.generator(node));
}

test "a relay client reads past a frame it cannot decode and acts on one frame once" {
    // The same three bytes in the other direction, and the same claim. The
    // client half of the protocol is a second copy of the walk `serveMessages`
    // does — framing, decode, act, compact — and a defect in one is not
    // evidence about the other, so both are named here.
    const relay = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0x62),
        .listen = loopback,
        .protocols = &.{.{ .alpn = protocol.relay_alpn }},
        .relay = .{ .role = .{ .serve = .{
            .clients = 1,
            .queue_depth = 4,
            .drain_room = 4,
        } } },
    });
    defer lifecycle.deinit(relay);

    const relay_peer = [_]config.Peer{.{
        .id = node_mod.nodeId(relay),
        .addr = .{ .ip = node_mod.address(relay) },
    }};
    const a = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0xb2),
        .listen = loopback,
        .protocols = &.{.{ .alpn = protocol.relay_alpn }},
        .relay = .{ .role = .{ .client = relay_peer[0] } },
    });
    defer lifecycle.deinit(a);
    const nodes = [_]*node_mod.Node{ a, relay };

    var at: Instant = start_ns;
    var pass: usize = 0;
    while (pass < max_passes) : (pass += 1) {
        try passOnce(&nodes, &at);
        if (a.stats.relay_established == 1 and client_pass.clientCount(relay) == 1) break;
    }
    try t.expectEqual(@as(u64, 1), a.stats.relay_established);
    try t.expectEqual(@as(usize, 1), client_pass.clientCount(relay));

    // The relay writes both frames itself, on the stream it opened to this
    // client, because a client only ever learns what a relay holds from what
    // the relay sends it. `endpoint_gone` is the cheapest frame that is
    // counted when it is acted on and writes nothing back.
    const slot = liveSlot(relay) orelse return error.NoLiveClient;
    const stranger = (try identityOf(0x78)).nodeId();
    try framing.writeRelay(&slot.out, relay.relay_state.out, .{ .endpoint_gone = stranger });
    // And whole again in this direction, for the same reason: the client half
    // reads this as one frame, so a short write is a defect here and not a
    // shorter frame the client could refuse.
    const sent = try slot.out.write(&poison_frame);
    if (sent != poison_frame.len) return error.TestUnexpectedResult;

    // Counted, not returned, for the reason the test above gives: the pass
    // that fails is the one the claim is not about, and the four clean passes
    // after it are.
    var refused: usize = 0;
    var clean: usize = 0;
    pass = 0;
    while (pass < max_passes and refused < 2) : (pass += 1) {
        at += time_quantum;
        _ = try runtime.step(t.io, relay, at, node_mod.generator(relay));
        if (runtime.step(t.io, a, at, node_mod.generator(a))) |_| {
            if (refused == 1) clean += 1;
        } else |err| {
            try t.expectEqual(node_error.Error.InvalidFrame, err);
            refused += 1;
            clean = 0;
        }
        if (refused == 1 and clean == 4) break;
    }
    try t.expectEqual(@as(usize, 1), refused);

    // Told once, not once per pass: the frame in front of the poison was read
    // whole and acted on, and a pass that fails on the frame behind it does
    // not take the one in front of it back.
    try t.expectEqual(@as(u64, 1), a.stats.relay_peer_gone);
    // And the inbox holds nothing, which is the state that counter is
    // re-derived from on every pass that reads again.
    const inbox = (a.relay_state.spoke orelse return error.TestUnexpectedResult).inbox;
    try t.expectEqual(@as(usize, 0), inbox.items.len);

    for (nodes) |node| try closing.close(t.io, node, at, node_mod.generator(node));
}

test "a closing relay client dials no relay" {
    // The window `close`'s own doc opens, taken on the public route. A close
    // that stopped in `closing_endpoint` leaves the machine mid-shutdown with
    // the descriptor open, and the same doc says the next `close` resumes
    // there, so a pass in between is a call this surface permits. The relay
    // client's half of that pass is the one thing on the node that would go and
    // take new work: a connection of its own, for a relay it has never spoken
    // to, on a node that has already said it is going — and the relay dial is
    // latched, so a node driven on after an abandoned shutdown could never dial
    // that relay again.
    //
    // **Both addresses are bound sockets, and neither end ever answers**, which
    // is what makes the claim about this node's own decisions: the dialled
    // connection exists because `start` asked for it, not because anybody
    // replied. `Dialer.dial` sends nothing — it registers a core connection and
    // returns — so no `step` is needed for a connection to exist, and that is
    // what keeps the relay client itself undialed: `converse` runs only inside
    // `step`, and this fixture runs no `step` before the close.
    var peer_recipient = try Socket.create(loopback, .{});
    defer peer_recipient.close();
    var relay_recipient = try Socket.create(loopback, .{});
    defer relay_recipient.close();
    const peers = [_]config.Peer{.{
        .id = (try identityOf(0xc5)).nodeId(),
        .addr = .{ .ip = peer_recipient.address },
    }};
    const node = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0xc6),
        .listen = loopback,
        .protocols = &.{.{ .alpn = protocol.relay_alpn }},
        .peers = &peers,
        .relay = .{ .role = .{ .client = .{
            .id = (try identityOf(0xc7)).nodeId(),
            .addr = .{ .ip = relay_recipient.address },
        } } },
    });
    defer lifecycle.deinit(node);

    // The preconditions, stated positively: one dialled connection, no relay at
    // all, and a node still serving.
    var at: Instant = start_ns;
    try runtime.start(node, at, node_mod.generator(node));
    try t.expectEqual(@as(u64, 1), node.stats.dials);
    try t.expectEqual(shutdown_mod.Shutdown.Phase.serving, node.accept.shutdown.phase);
    try t.expect(!node.relay_state.dialled);
    try t.expect(node.relay_state.spoke == null);

    // A close stopped one send short of the descriptor. It needs nothing to be
    // established: the core builds its close flight from whichever seal it
    // holds, and the Initial one is always there (`connection.zig` takes
    // `app_seal orelse handshake_seal orelse initial_seal`), so a connection no
    // pass has touched still owes a CONNECTION_CLOSE.
    cancel_protection = .unblocked;
    var vtable = t.io.vtable.*;
    vtable.checkCancel = cancelledCheck;
    vtable.swapCancelProtection = cancelledSwap;
    const cancelled: std.Io = .{ .userdata = t.io.userdata, .vtable = &vtable };
    defer cancel_protection = .unblocked;
    try t.expectError(error.Canceled, closing.close(cancelled, node, at, node_mod.generator(node)));
    try t.expectEqual(shutdown_mod.Shutdown.Phase.closing_endpoint, node.accept.shutdown.phase);
    try t.expect(node.socket_open);

    // The pass the window allows. It takes no relay work: no dial, no `spoke` to
    // free, and nothing put on the wire for a relay this node will not speak to.
    at += time_quantum;
    _ = try runtime.step(t.io, node, at, node_mod.generator(node));
    try t.expect(!node.relay_state.dialled);
    try t.expect(node.relay_state.spoke == null);
    try t.expectEqual(@as(u64, 0), node.stats.relay_dials);
    try t.expectEqual(@as(u64, 0), node.stats.relay_dials_refused);
    try t.expectEqual(@as(u64, 0), node.stats.relay_auth_sent);

    // And the passes after it, because a guard on one pass and not the next is
    // a pass and not a rule.
    at += time_quantum;
    _ = try runtime.step(t.io, node, at, node_mod.generator(node));
    try t.expect(!node.relay_state.dialled);
    try t.expect(node.relay_state.spoke == null);
    try t.expectEqual(@as(u64, 0), node.stats.relay_dials);

    // The close that was owed still finishes it, which is what says the pass
    // was refused and not the shutdown.
    try closing.close(t.io, node, at, node_mod.generator(node));
    try t.expectEqual(shutdown_mod.Shutdown.Phase.closed, node.accept.shutdown.phase);
    try t.expect(!node.socket_open);
}

test "a payload the relay handed over is retained once and given back once" {
    // The ownership of one delivered datagram, in both directions: the copy is
    // the node's, and it is freed by exactly one of `clearDelivered` and
    // `deinit`. The relay does not have to be standing up for either — what is
    // under test is the pair of lines that own the payload, not the frames
    // around them.
    const node = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0x3d),
        .listen = loopback,
        .protocols = &.{.{ .alpn = protocol.relay_alpn }},
    });
    defer lifecycle.deinit(node);

    // The node's own storage, so `delivered` and `clearDelivered` are reading
    // and freeing the same list the delivery appended to, and `deinit` finds
    // whatever is left on it.
    node.relay_state.spoke = .{
        .conn = 0,
        .stream = null,
        .handshake = .{ .established = .signed_challenge },
        .inbox = .empty,
        .delivered = .empty,
    };

    const src = (try identityOf(0x4e)).nodeId();
    const frame: relay_frame.DatagramFrame = .{
        .node_id = src,
        .datagrams = .{
            .ecn = null,
            .segment_size = null,
            .contents = "from-the-relay",
        },
    };
    const spoke = if (node.relay_state.spoke) |*active| active else return error.TestUnexpectedResult;

    // **The list refuses it.** The copy is made before the list is asked to
    // hold it, so an append that cannot grow must give the copy back rather
    // than leave one payload behind for every frame refused on the way. The
    // allocator refuses the *second* allocation of the call — the first is the
    // copy — and `t.allocator` underneath it is a leak detector, so a copy
    // nobody frees fails this test even though nothing here can see it.
    {
        var failing = t.FailingAllocator.init(t.allocator, .{});
        failing.fail_index = failing.alloc_index + 1;
        failing.resize_fail_index = failing.resize_index + 1;
        const whole = node.gpa;
        node.gpa = failing.allocator();
        defer node.gpa = whole;
        try t.expectError(error.OutOfMemory, client_pass.retain(node, spoke, frame));
    }
    try t.expectEqual(@as(usize, 0), client_pass.delivered(node).len);
    try t.expectEqual(@as(u64, 0), node.stats.relay_datagrams_out);

    // Retained: one copy, the node's own allocator's, counted once, and the
    // source id carried alongside the bytes rather than borrowed from them.
    try client_pass.retain(node, spoke, frame);
    try t.expectEqual(@as(usize, 1), client_pass.delivered(node).len);
    try t.expectEqual(src, client_pass.delivered(node)[0].src);
    try t.expectEqualStrings("from-the-relay", client_pass.delivered(node)[0].data);
    try t.expectEqual(@as(u64, 1), node.stats.relay_datagrams_out);

    // And given back by exactly one call. `clearDelivered` frees the payload
    // and empties the list together, so a second call has nothing to free and
    // the `defer node.deinit()` above finds nothing either — a double free
    // here would be the other half of the same claim.
    client_pass.clearDelivered(node);
    try t.expectEqual(@as(usize, 0), client_pass.delivered(node).len);
    client_pass.clearDelivered(node);

    // The node still has to be closed rather than dropped: `deinit` reports an
    // endpoint abandoned in `serving` at error level, and an error-level log
    // fails the artifact for a reason that has nothing to do with the payload.
    try closing.close(t.io, node, start_ns, node_mod.generator(node));
}

test "a message length round-trips at every varint width" {
    // The widths a relay never reaches: a frame here is one datagram and a
    // datagram is `max_datagram` bytes, so nothing this node sends needs the
    // four- or eight-byte form. A length that crosses a width boundary and is
    // read back wrong is a frame decoded as a *different* frame, so the
    // widths are checked here rather than left to a datagram large enough to
    // need them.
    const widths = [_]u64{
        0,     63,            64,      16383,
        16384, (1 << 30) - 1, 1 << 30, (1 << 62) - 1,
    };
    var out: [framing.varint_max]u8 = undefined;
    for (widths) |value| {
        const len = try framing.writeVarint(&out, value);
        const read = framing.readVarint(out[0..len]) orelse return error.NoVarint;
        try t.expectEqual(value, read.value);
        try t.expectEqual(len, read.len);
    }
    // A buffer with no room is refused rather than truncated, and half a
    // length is not a length.
    try t.expectError(error.NoRoom, framing.writeVarint(out[0..1], 64));
    try t.expect(framing.readVarint(&.{}) == null);
    try t.expect(framing.readVarint(&.{0x40}) == null);
}

test "every relay role answers a client count, and only a serving relay holds one" {
    // Three roles and one answer each, for a node that has admitted nobody.
    // `.off` and `.client` build no registry at all — `relay_storage.init` returns
    // before the table is initialised — so a count read out of one is a read
    // of bytes nobody wrote, and the memory `create` was handed says nothing
    // about what is in it. Filling that storage with a pattern first is what
    // turns the difference into a failing assertion rather than a lucky one.
    const gossip = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0xa1),
        .listen = loopback,
        .topic = briskTopic(),
    });
    defer closedOnExit(gossip);
    const spoke = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0xa2),
        .listen = loopback,
        .topic = briskTopic(),
        .relay = .{ .role = .{ .client = .{
            .id = (try identityOf(0xa3)).nodeId(),
            .addr = .{ .ip = loopback },
        } } },
    });
    defer closedOnExit(spoke);
    const relay = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0xa4),
        .listen = loopback,
        .topic = briskTopic(),
        .relay = .{ .role = .{ .serve = .{} } },
    });
    defer closedOnExit(relay);

    gossip.relay_state.registry.len = 3;
    spoke.relay_state.registry.len = 3;

    try t.expectEqual(@as(usize, 0), client_pass.clientCount(gossip));
    try t.expectEqual(@as(usize, 0), client_pass.clientCount(spoke));
    // A serving relay has the table and is answered by it. A fresh one has
    // admitted nobody, which is the same zero the other two are owed rather
    // than a coincidence of uninitialised memory.
    try t.expectEqual(@as(usize, 0), client_pass.clientCount(relay));
}

test "a start that could not join refuses again, and a start that joined is not repeated" {
    // `max_bootstrap` and one more: the length `Peers.init` refuses, and the
    // length `start` checks first so the list is not half filled before the
    // refusal. The dials happen before that check either way — a peer that was
    // not reached is a fact about the network and is not dialled again — so
    // what this pins is the other half of idempotence: the refusal is a
    // refusal every time, and not a success that joined nothing.
    var recipient = try Socket.create(loopback, .{});
    defer recipient.close();
    var peers: [hyparview.max_bootstrap + 1]config.Peer = undefined;
    for (&peers, 0..) |*peer, index| {
        peer.* = .{
            .id = (try identityOf(@intCast(0xb0 + index))).nodeId(),
            .addr = .{ .ip = recipient.address },
        };
    }
    const node = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0xb9),
        .listen = loopback,
        .peers = &peers,
        .topic = briskTopic(),
    });
    defer closedOnExit(node);

    try t.expectError(error.BootstrapListTooLong, runtime.start(node, start_ns, node_mod.generator(node)));
    // Every peer was attempted exactly once, whichever way the dial answered.
    const attempted = node.stats.dials + node.stats.dials_refused;
    try t.expectEqual(@as(u64, hyparview.max_bootstrap + 1), attempted);

    try t.expectError(error.BootstrapListTooLong, runtime.start(node, start_ns, node_mod.generator(node)));
    try t.expectEqual(attempted, node.stats.dials + node.stats.dials_refused);
    // No join was fed and none is claimed: `gossip_events` is the count of
    // events the layer handled, so a latch set before the check would leave
    // the second call reporting success over a count of nothing.
    try t.expectEqual(@as(u64, 0), node.stats.gossip_events);
    try t.expect(!node.joined);

    // And a node whose list fits is told to join exactly once, which is what
    // `run` leans on: it calls `start` on the first pass and the call after it
    // must not feed a second join.
    const joining = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0xba),
        .listen = loopback,
        .topic = briskTopic(),
    });
    defer closedOnExit(joining);
    try runtime.start(joining, start_ns, node_mod.generator(joining));
    try t.expect(joining.joined);
    const events = joining.stats.gossip_events;
    try t.expect(events > 0);
    try runtime.start(joining, start_ns, node_mod.generator(joining));
    try t.expectEqual(events, joining.stats.gossip_events);
}

test "a join the gossip layer could not take leaves the node not joined" {
    // One peer, and the *second* allocation `start` makes through this node's
    // own allocator refused: the first is the table the dial loop records the
    // peer in, and the second is the join command's own output list. So the
    // failure lands where the latch is decided rather than beside it.
    const listener = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0xbb),
        .listen = loopback,
        .topic = briskTopic(),
    });
    defer closedOnExit(listener);
    const peers = [_]config.Peer{.{
        .id = node_mod.nodeId(listener),
        .addr = .{ .ip = node_mod.address(listener) },
    }};
    const node = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0xbc),
        .listen = loopback,
        .peers = &peers,
        .topic = briskTopic(),
    });
    defer closedOnExit(node);

    var failing = t.FailingAllocator.init(t.allocator, .{});
    failing.fail_index = 1;
    failing.resize_fail_index = 1;
    {
        const whole = node.gpa;
        node.gpa = failing.allocator();
        defer node.gpa = whole;
        try t.expectError(error.OutOfMemory, runtime.start(node, start_ns, node_mod.generator(node)));
    }

    // It did not join, and the event was not counted: the join command is what
    // was refused, so a latch set before it was fed would leave the next
    // `start` a success over nothing. What the refused command left behind is
    // deliberately not fed again here — `step` states that a consumed event is
    // not one to replay — so this claims the latch and nothing about the
    // residue. The allocator goes back at the end of the block above, which is
    // what lets the close and the free below run on the one this node was built
    // with.
    try t.expect(!node.joined);
    try t.expectEqual(@as(u64, 0), node.stats.gossip_events);
}

test "a runtime that cannot supply secure entropy builds no node" {
    // The CSPRNG seed is drawn before anything else is built, so both refusals
    // land on a runtime that has an open descriptor to give back and nothing
    // else to unwind. That is the shape this asserts: the error each kind of
    // refusal produces, and that neither leaves a node, a descriptor or an
    // allocation behind — `std.testing`'s own allocator is what reports the
    // last of those, so reaching the end of this test is itself half the claim.
    //
    // **The two errors stay two.** `error.EntropyUnavailable` is a runtime that
    // cannot key this node and never will; `error.Canceled` is the caller
    // stopping this operation and choosing to retry, which says nothing at all
    // about its entropy source. Collapsing them told a cancelling caller its
    // entropy was broken, and told one whose entropy is fine that it is not
    // retryable.
    var vtable: std.Io.VTable = undefined;
    var refused_secret = try identityOf(0xe1);
    defer refused_secret.deinit();
    inline for ([_]std.Io.RandomSecureError{ error.EntropyUnavailable, error.Canceled }) |refused| {
        const no_entropy = refusingEntropy(refused, t.io, &vtable);
        try t.expectError(refused, lifecycle.create(t.allocator, no_entropy, .{
            .secret = refused_secret,
            .listen = loopback,
            .topic = briskTopic(),
        }));
    }

    // And the same node on the real runtime, which is the control: it answers
    // neither, because `t.io` has secure entropy and is not cancelled. Without
    // this the two refusals above would also be satisfied by a `create` that
    // refused everything.
    var control_secret = try identityOf(0xe2);
    defer control_secret.deinit();
    const built = try lifecycle.create(t.allocator, t.io, .{
        .secret = control_secret,
        .listen = loopback,
        .topic = briskTopic(),
    });
    defer closedOnExit(built);
    try t.expectEqual(control_secret.nodeId(), node_mod.nodeId(built));
}

/// What the dialled connection writes, so "the session came up" is not the end
/// of the claim: a proved address that carries no data proves less than one
/// that does.
const admission_bytes = "bytes that crossed a connection this node proved first";

/// The one connection this node holds, dialled or accepted. A node with the
/// filter registered still opens exactly one connection per peer, so the index
/// is found rather than assumed.
fn oneConn(node: *node_mod.Node, accepted: bool) !Conn {
    var index: usize = 0;
    while (node.bridge.connectionAt(index)) |conn| : (index += 1) {
        if (conn.entry.conn.is_server == accepted) return conn;
    }
    return error.ConnectionMissing;
}

test "a node proves the address an inbound flow came from before it serves it" {
    // **The node half of admission, and the only part the vendored core's own
    // regression cannot reach.** `ConnectionManager.admission` proves the
    // contract at the seam — a Retry verdict becomes a Retry packet and no
    // connection, and the echoed token is accepted with the path proved — but
    // that test installs its own hook. What this one adds is that a real `Node`
    // registers one, that `node_dispatch.proveAddress` is what it holds, and
    // that an inbound flow from a real peer goes through it: refused a
    // connection it is not yet owed, answered with a Retry, and served once the
    // token comes back.
    //
    // It uses the two-Node pass loop the tests above use rather than a driver
    // of its own, so the Retry round trip is measured against the same bound and
    // the same pass the rest of this file's fixtures run on.
    const listener = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0xa1),
        .listen = loopback,
        .topic = briskTopic(),
    });
    defer lifecycle.deinit(listener);

    const peers = [_]config.Peer{.{
        .id = node_mod.nodeId(listener),
        .addr = .{ .ip = node_mod.address(listener) },
    }};
    const dialer = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0x2b),
        .listen = loopback,
        .peers = &peers,
        .topic = briskTopic(),
    });
    defer lifecycle.deinit(dialer);

    var at: Instant = start_ns;
    try runtime.start(dialer, at, node_mod.generator(dialer));
    var passes: usize = 0;
    while (passes < max_passes) : (passes += 1) {
        at += time_quantum;
        _ = try runtime.step(t.io, dialer, at, node_mod.generator(dialer));
        _ = try runtime.step(t.io, listener, at, node_mod.generator(listener));
    }

    // One connection each end, and it is up: the flow came back with the token
    // the filter's retry verdict bought it.
    try t.expectEqual(@as(usize, 1), node_mod.establishedCount(dialer));
    try t.expectEqual(@as(usize, 1), node_mod.establishedCount(listener));

    // **The verdict reached the peer.** This is read off the client, which is
    // the only side that can be wrong about it: its own core recorded the
    // Retry it was answered with. A build where the node registered no filter
    // would accept the first Initial and this is false there, which is what
    // makes the rest of the test a claim about admission rather than about a
    // connection that happened to work.
    const dialled = try oneConn(dialer, false);
    try t.expect(dialled.entry.conn.retry_received);

    // **And the address it proved is the one it serves.** The listener's own
    // answer about the flow, read from the bit the core keeps, is what a second
    // Retry could not be asked for: QUIC permits one per flow.
    const served = try oneConn(listener, true);
    try t.expect(served.isValidated());

    // And the proved connection carries data, which is what a session is: a
    // unidirectional stream written after the handshake and drained at the far
    // end, so the claim is a connection carrying bytes rather than a core that
    // reached a state.
    var uni = try dialled.openUni();
    try t.expectEqual(admission_bytes.len, try uni.write(admission_bytes));
    uni.close();

    var sink: std.ArrayList(u8) = .empty;
    defer sink.deinit(t.allocator);
    var round: usize = 0;
    var taken: ?RecvUni = null;
    while (round < max_passes and taken == null) : (round += 1) {
        at += time_quantum;
        _ = try runtime.step(t.io, dialer, at, node_mod.generator(dialer));
        _ = try runtime.step(t.io, listener, at, node_mod.generator(listener));
        taken = served.acceptUni(0);
    }
    var incoming = taken orelse return error.UniStreamMissing;
    try t.expectEqual(uni.id(), incoming.id());
    round = 0;
    while (round < max_passes) : (round += 1) {
        at += time_quantum;
        _ = try runtime.step(t.io, dialer, at, node_mod.generator(dialer));
        _ = try runtime.step(t.io, listener, at, node_mod.generator(listener));
        _ = try incoming.drain(t.allocator, &sink);
        if (incoming.finished() and sink.items.len == admission_bytes.len) break;
    }
    try t.expect(incoming.finished());
    try t.expectEqualStrings(admission_bytes, sink.items);

    // Both closed, so `deinit` above is handed a lease that was driven to
    // `closed`: an abandoned one logs at error level and fails the artifact,
    // which is why this is closed here rather than left to teardown.
    try closing.close(t.io, dialer, at, node_mod.generator(dialer));
    try closing.close(t.io, listener, at, node_mod.generator(listener));
    for ([_]*node_mod.Node{ dialer, listener }) |node| {
        try t.expectEqual(shutdown_mod.Shutdown.Phase.closed, node.accept.shutdown.phase);
    }
}
