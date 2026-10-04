//! A client that keeps talking after this relay has refused it.
//!
//! **Its own module because the claim needs the whole serving pass and the
//! fixture that drives it.** Two nodes on loopback, real sockets, virtual time
//! and the pass loop the node runtime owns, with the client's half written by
//! hand: none of that belongs beside the relay's own functions, and the
//! production modules are reached from here through the imports every other
//! caller uses rather than through anything private to them.

const std = @import("std");
const node_mod = @import("node.zig");
const config = @import("node_config.zig");
const framing = @import("node_framing.zig");
const node_protocol = @import("node_protocol.zig");
const relay_admit = @import("node_relay_serve_admit.zig");
const lifecycle = @import("node_lifecycle.zig");
const closing = @import("node_close.zig");
const runtime = @import("node_runtime.zig");
const base_key = @import("../base/key.zig");
const quic_stream = @import("../transport/quic_stream.zig");

const SocketAddr = @import("../base/addr.zig").SocketAddr;
const Instant = @import("../transport/quic_conn.zig").Instant;

const Client = relay_admit.Client;

// The driver and the identities this file's one test builds its two nodes
// with. Named here rather than beside the relay modules this test drives,
// because they are the test's dependency and not the relay's: the half that
// reads a client speaks through the connection it was handed and asks no
// driver for anything.

const t = std.testing;

/// Close before release even when an assertion fails: `deinit` on a node that
/// was never closed gives up its lease and logs at error level.
///
/// **The instant is taken by pointer**, so the close is stamped with the clock
/// as it stands when the test unwinds rather than with the one from the line
/// that registered the `defer`.
fn closeOnExit(node: *node_mod.Node, at: *const Instant) void {
    defer lifecycle.deinit(node);
    closing.close(t.io, node, at.*, node_mod.generator(node)) catch |err| std.debug.panic(
        "a node did not close during test teardown: {t}",
        .{err},
    );
}

/// This relay's refused client slot, and only while it is exactly that.
///
/// **`.denied` is the premise the claim needs, and `handshakeEnded` is
/// deliberately not the question asked.** A `client_to_relay_datagram` handed
/// to a handshake still running is `Failure.unexpected_frame`
/// (`server.zig:344`), which is terminal too, so a slot that ended on the very
/// frame this test means to keep behind the refusal would leave every counter
/// the test reads at zero with no gate having run. `live` is the other half of
/// it: a released slot is skipped whole at the top of `serveRead`
/// (`node_relay_serve_read.zig:29`), so the gate would have nothing left to
/// refuse.
fn refused(relay: *node_mod.Node) ?*Client {
    for (relay.relay_state.clients) |*slot| {
        if (!slot.live) continue;
        return switch (slot.handshake) {
            .denied => slot,
            else => null,
        };
    }
    return null;
}

test "a client whose handshake ended counts nothing sent behind its refusal" {
    // The peer here negotiates the relay ALPN and then answers the challenge
    // with a signature that verifies for nothing: the one thing a relay client
    // this stack builds never does, and the one thing a browser or a hostile
    // client can. So the two frames are written by hand, and everything else
    // is the ordinary relay fixture — two nodes on loopback, real sockets,
    // virtual time, and the pass loop the node runtime owns.
    //
    // Where a test node binds, with port zero so the kernel picks, and where
    // virtual time starts. A pass is a handful of syscalls, so the clock is a
    // quantum and not a delay: nothing here waits for it to elapse.
    const loopback: SocketAddr = .{
        .ip = .{ .v4 = .{ 127, 0, 0, 1 } },
        .port = 0,
    };
    const start_ns: Instant = 1_000 * std.time.ns_per_s;
    const time_quantum: Instant = std.time.ns_per_ms;
    const max_passes = 256;

    // Declared ahead of both nodes so that each teardown can be registered
    // against the clock every pass below advances.
    var at: Instant = start_ns;

    const relay = try lifecycle.create(t.allocator, t.io, .{
        .secret = try base_key.SecretKey.fromSeed(@splat(0x71)),
        .listen = loopback,
        .protocols = &.{.{ .alpn = node_protocol.relay_alpn }},
        .relay = .{ .role = .{ .serve = .{
            .clients = 1,
            .queue_depth = 4,
            .drain_room = 4,
        } } },
    });
    defer closeOnExit(relay, &at);

    // A peer of the relay that is not a relay client of its own: it dials,
    // negotiates the relay ALPN and then answers the challenge with bytes that
    // verify for nothing, which is what spends this relay's one slot on a client
    // it will refuse.
    const peers = [_]config.Peer{.{
        .id = node_mod.nodeId(relay),
        .addr = .{ .ip = node_mod.address(relay) },
    }};
    const peer = try lifecycle.create(t.allocator, t.io, .{
        .secret = try base_key.SecretKey.fromSeed(@splat(0x72)),
        .listen = loopback,
        .peers = &peers,
        .protocols = &.{.{ .alpn = node_protocol.relay_alpn }},
    });
    defer closeOnExit(peer, &at);

    try runtime.start(peer, at, node_mod.generator(peer));

    // Until the connection is established this end has no stream to write on,
    // and the relay spends its slot before that: `serveAdmit` runs before
    // `serveRead` on every pass, so the slot is always challenged by the time a
    // frame written here can be read.
    var pass: usize = 0;
    while (pass < max_passes and node_mod.establishedCount(peer) == 0) : (pass += 1) {
        at += time_quantum;
        _ = try runtime.step(t.io, peer, at, node_mod.generator(peer));
        _ = try runtime.step(t.io, relay, at, node_mod.generator(relay));
    }
    try t.expectEqual(@as(usize, 1), node_mod.establishedCount(peer));

    // The connection this end dialled, which is the only one it holds, and the
    // one stream the protocol runs on. Absent here is a defect in the path that
    // got here rather than a condition this test allows for, so it is reported
    // instead of unwrapped and the claim below still says what the wire said.
    var spoken: ?quic_stream.Stream = null;
    var index: usize = 0;
    while (peer.bridge.connectionAt(index)) |conn| : (index += 1) {
        if (conn.entry.conn.is_server) continue;
        spoken = quic_stream.openBidi(conn.entry.conn) catch |err| switch (err) {
            // Not yet: the relay's grant of streams has not been read.
            error.NoStreamRoom => continue,
            else => return err,
        };
        break;
    }
    var out = spoken orelse return error.TestUnexpectedResult;

    // **The refusal goes on the wire alone, and what the claim is about is not
    // on the wire yet.** Both halves of the gate are per-pass checks and one
    // pass reads a client's stream once, so the line numbers below are
    // `node_relay_serve_read.zig`'s: `serveRead` skips a slot whose handshake
    // has ended (37), fills the inbox (53), serves every whole frame in it
    // (54), and only then believes the end of the stream and discards a tail
    // (57-60). A client that put the refusal, a datagram and a half-written
    // frame in one run of bytes therefore has its tail counted on the very
    // pass that refused it, and the counter would be reporting the order of
    // the pass rather than the gate. What separates them here is time, not
    // position along one stream. The buffer is the relay's own frame room,
    // which is what every relay write is given.
    var scratch: [config.relay_frame_room + framing.varint_max]u8 = undefined;
    const claimed = node_mod.nodeId(peer);
    try framing.writeRelay(&out, scratch[0..], .{ .client_auth = .{
        .node_id = claimed,
        .signature = .{ .bytes = @splat(0) },
    } });

    // Until the relay has served the denial nothing below has a premise, so
    // this stops on the state itself and not on a pass count.
    pass = 0;
    while (pass < max_passes and refused(relay) == null) : (pass += 1) {
        at += time_quantum;
        _ = try runtime.step(t.io, peer, at, node_mod.generator(peer));
        _ = try runtime.step(t.io, relay, at, node_mod.generator(relay));
    }
    try t.expect(refused(relay) != null);

    // **The window this claim is about, read rather than assumed.** A denial is
    // a write and not a close: `relay_server.step` pairs `.denied` with
    // `.write` of `server_denies_auth` (`server.zig:452-457`) and only `fail`
    // carries `Action.close` (`server.zig:459-461`), so the core still holds
    // the connection and this is the one slot the relay still has.
    try t.expectEqual(@as(usize, 1), node_mod.establishedCount(relay));

    // **And now what the refusal is in front of.** The datagram, and then a
    // length whose bytes never arrive with the end of the stream behind it: the
    // half-written frame `discardTail` exists for, and the half of the claim
    // that is about the stream rather than about the frame. A stream this relay
    // does not read is a stream whose tail it does not count either.
    const sent_before = peer.stats.datagrams_out;
    try framing.writeRelay(&out, scratch[0..], .{ .client_to_relay_datagram = .{
        .node_id = claimed,
        .datagrams = .{ .ecn = null, .segment_size = null, .contents = "one" },
    } });
    const half = [_]u8{ 8, 0x51, 0x50 };
    // The whole of it, and the end behind it: a short write would put a prefix
    // on the wire rather than a length this relay cannot read, and that is a
    // condition the assertion below would be wrong about.
    if (try out.write(&half) != half.len) return error.TestUnexpectedResult;
    out.close();

    // Ordinary passes. The refusal is behind this slot by now and the gate is
    // at the top of the read, so none of them reaches the stream these last
    // three writes are on.
    pass = 0;
    while (pass < 8) : (pass += 1) {
        at += time_quantum;
        _ = try runtime.step(t.io, peer, at, node_mod.generator(peer));
        _ = try runtime.step(t.io, relay, at, node_mod.generator(relay));
    }

    // The claim, on the counter a caller reads: what a client sends behind a
    // handshake this relay ended is not something the relay took in.
    try t.expectEqual(@as(u64, 0), relay.stats.relay_datagrams_in);
    // **Nothing off that stream at all**, and this is the half that can only be
    // asked once the refusal is behind the gate: the tail is in the inbox, the
    // end of the stream has been believed, and a slot drained as though it were
    // live is what this counter names. A pass that refuses the client and then
    // counts its own tail moves this counter whether or not the read's gate
    // exists, which is why the denial has to be a pass of its own.
    try t.expectEqual(@as(u64, 0), relay.stats.relay_stream_truncated);
    // And the refusal was not read as an admission that arrived late.
    try t.expectEqual(@as(u64, 0), relay.stats.relay_admitted);
    // And it is still the same refused slot rather than one the relay has taken
    // back: every counter above reads zero on a released slot too.
    try t.expect(refused(relay) != null);
    // The bytes really went out, which is what says the writes above reached
    // the wire rather than having been refused by the stream.
    try t.expect(peer.stats.datagrams_out > sent_before);
}
