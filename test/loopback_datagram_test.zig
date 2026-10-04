//! The RFC 9221 DATAGRAM seam over a real socket, and what the stack does
//! about a datagram the path throws away.
//!
//! # Why this file exists
//!
//! `docs/PLAN.md` records the second half of the transport gap this wave
//! closes: the bridge "does not enable DATAGRAM". Until now the QUIC
//! *datagram* — the unreliable, unordered, per-packet payload inside a
//! connection — had never been carried by anything above
//! `transport/socket.zig`. The socket datagram is well covered; the QUIC one is
//! a different frame with a different failure mode, and a stack can pass every
//! socket-level test while this one is simply absent.
//!
//! # The one thing that has to be configured, and why it is easy to miss
//!
//! RFC 9221 comes up only when **both** peers advertise `max_datagram_frame_size`
//! in their transport parameters (`connection.zig:3382`). `quic_config.Config`
//! leaves it null, so a bridge nobody told otherwise does not advertise it,
//! `datagrams_enabled` stays false for the whole connection, and every send
//! answers `error.DatagramsNotEnabled` for as long as the connection lives —
//! there is no negotiation to retry and no later handshake to change the
//! answer. Every test here states the frame size at **both ends of the link**,
//! and the client's is stated twice over, because a bridge's `Config` covers
//! the connections it *accepts* while the dialled one is built by
//! `Dialer.create` out of the dialer's own `Config` and never reads the client
//! bridge's (`dial.zig:302`) — a dialer left at its default advertises no
//! frame size at all, which on the wire is the same as having said nothing. The
//! first assertion of the round trip is that the extension actually came up,
//! so no test in this file can pass vacuously against a link where it did not.
//!
//! # What a QUIC datagram is not
//!
//! It is **not retransmitted**. The core packs a DATAGRAM frame into whatever
//! packet is going out and never queues it for another; if that packet is lost,
//! the datagram is gone (RFC 9221 §5.2). That is what the loss test asserts, and
//! it is the opposite of what the bidirectional-stream tests show — which is why
//! the two are in different files with different clocks. A test that dropped a
//! packet and waited for the datagram to reappear would be asserting a
//! retransmission the protocol does not have.
//!
//! # Time moves here, and only here
//!
//! Every other file in this artifact drives at one instant, so nothing can time
//! out and a loop ends on the state machines. A loss test cannot work that way:
//! a dropped packet is only probed again once a timeout expires, and before any
//! RTT sample the core's PTO is `2 × 100 ms` (RFC 9002, `rtt.zig:112-116`). So
//! this file advances an instant by `time_quantum` per round, which is a clock
//! and not a delay — nothing waits for it to elapse — and the whole run stays
//! well inside the connection's 30 s idle timeout, so no connection is reaped
//! by the clock. A reaped connection here would be a finding about time rather
//! than about datagrams.

const std = @import("std");
const ozai = @import("ozai");

const t = std.testing;

const link_mod = @import("loopback_link.zig");
const batch = ozai.transport_batch;

const Link = link_mod.Link;
const Instant = link_mod.Instant;
const bothUp = link_mod.bothUp;
const link_start = link_mod.start;

const SecretKey = ozai.SecretKey;

/// Fixed seeds, as in `loopback_test.zig`.
const client_seed: [SecretKey.seed_length]u8 = @splat(0xc1);
const server_seed: [SecretKey.seed_length]u8 = @splat(0x53);

/// How many rounds a phase may take with the clock still.
const max_rounds = 32;

/// How many rounds a lossy phase may take with the clock moving.
///
/// Twenty-four rounds of `time_quantum` is 6 s of virtual time: enough for five
/// probe timeouts to expire and the connection to be asked for a retransmit it
/// does not have, and far inside the 30 s idle timeout. The bound is a backstop
/// against a run that never converges, not a budget.
const max_loss_rounds = 24;

/// How far the clock moves per round in the loss test. More than the core's
/// initial PTO of 200 ms, so a dropped packet is probed again within one round.
const time_quantum: Instant = 250 * std.time.ns_per_ms;

/// The DATAGRAM transport parameter both bridges advertise.
///
/// 65536 is the ceiling RFC 9221 §3 allows. The value that matters to these
/// tests is only that it is non-null on both ends; `maxPayload` negotiates the
/// real ceiling down from it.
const frame_size: u64 = 65536;

/// A payload small enough that the ceiling is bounded by the packet rather than
/// by this number, so the round trip tests the seam and not the frame ceiling.
const payload = "ozai datagram, carried inside a connection and not on its own";

/// The same payload with one byte changed, so "the far end saw *this* one"
/// cannot be satisfied by a queue that returned whatever it held first.
const second_payload = "ozai datagram, carried inside a connection and not on its own!";

/// What the peer sends back. One message, one answer, and no ordering guarantee
/// between them — which is why the payload itself is what is under test rather
/// than a sequence number.
const answer = "it carries whatever you hand it, once, in order or not";

/// The instant a lossy round is driven at. A clock, not a delay.
fn atRound(round: usize) Instant {
    return link_start + @as(Instant, @intCast(round)) * time_quantum;
}

test "a QUIC datagram crosses the socket, and the extension came up to let it" {
    var client_secret = try SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();
    var server_secret = try SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();

    var link: Link = undefined;
    // Both bridges, because both must advertise for the extension to come up.
    try link.init(client_secret, server_secret, server_secret.nodeId(), 21, .{
        .max_datagram_frame_size = frame_size,
    });
    defer link.deinit();
    try link.drive(link_start, max_rounds, bothUp);

    const client = link.client.live().?;
    const server = link.server.live().?;

    // The precondition, asserted on both ends and before anything is sent.
    // Without it, a link where `datagrams_enabled` was false would report the
    // refusals below as the failure when the real one is the configuration.
    try t.expect(client.datagramsEnabled());
    try t.expect(server.datagramsEnabled());

    // The ceiling is negotiated, so it is a number rather than null. This is
    // what `error.DatagramTooLarge` is measured against, and a test that used a
    // fixed payload could not tell a ceiling that moved from a payload that
    // grew.
    const ceiling = client.datagramMaxPayload().?;
    try t.expect(ceiling >= payload.len);

    try client.sendDatagram(payload, link_start);
    try t.expectEqual(@as(usize, 1), client.datagramQueued());

    // The far end takes it out of the core's queue into a buffer the caller
    // owns. `recv` copies and drops the queue entry, so this is a take rather
    // than a peek and a second read is a different datagram.
    var landed: [payload.len]u8 = undefined;
    var out: ?[]const u8 = null;
    var round: usize = 0;
    while (round < max_rounds) : (round += 1) {
        _ = try link.exchange(link_start);
        if (server.recvDatagram(&landed, link_start)) |taken| {
            out = taken;
            break;
        }
    }
    const received = out orelse {
        link.report("datagram", "the datagram never reached the peer's queue");
        return error.DatagramNotDelivered;
    };
    try t.expectEqualStrings(payload, received);

    // And back the other way, because a datagram seam that only carries in one
    // direction is half a seam. A different payload, so a queue handing back the
    // first one could not satisfy this.
    var back: [answer.len]u8 = undefined;
    try server.sendDatagram(answer, link_start);
    out = null;
    round = 0;
    while (round < max_rounds) : (round += 1) {
        _ = try link.exchange(link_start);
        if (client.recvDatagram(&back, link_start)) |taken| {
            out = taken;
            break;
        }
    }
    const replied = out orelse {
        link.report("datagram", "the answered datagram never reached the client");
        return error.DatagramNotDelivered;
    };
    try t.expectEqualStrings(answer, replied);

    // The read consumed what it copied: a datagram is taken once. A reader that
    // peeked would hand the same bytes back for ever, and this is the only
    // assertion here that would notice.
    try t.expectEqual(@as(?[]const u8, null), server.recvDatagram(&back, link_start));
}

test "a buffer with no room for a datagram leaves it queued for a wider one" {
    var client_secret = try SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();
    var server_secret = try SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();

    var link: Link = undefined;
    try link.init(client_secret, server_secret, server_secret.nodeId(), 22, .{
        .max_datagram_frame_size = frame_size,
    });
    defer link.deinit();
    try link.drive(link_start, max_rounds, bothUp);

    const client = link.client.live().?;
    const server = link.server.live().?;

    try client.sendDatagram(payload, link_start);

    // `recv` answers null both when the queue is empty and when the entry at
    // its head is wider than the buffer, and the caller owns that difference.
    // So the short read is asserted to be null on every round — which is true
    // either way — and the *wide* read that follows it in the same round is
    // what carries the claim: a datagram is taken only when it fits whole, and
    // a reader that dropped it on a short buffer would leave nothing for the
    // wide one to find.
    //
    // The two reads are in one loop on purpose. Reading the wide buffer first
    // would prove only that a datagram can be read; reading it second proves
    // the short read did not consume it.
    var tight: [payload.len - 1]u8 = undefined;
    var wide: [payload.len]u8 = undefined;
    var round: usize = 0;
    var took_it = false;
    while (round < max_rounds) : (round += 1) {
        _ = try link.exchange(link_start);
        try t.expectEqual(@as(?[]const u8, null), server.recvDatagram(&tight, link_start));
        if (server.recvDatagram(&wide, link_start)) |taken| {
            try t.expectEqualStrings(payload, taken);
            took_it = true;
            break;
        }
    }
    if (!took_it) {
        link.report("datagram", "a short buffer dropped a datagram instead of keeping it");
        return error.DatagramLostToShortBuffer;
    }
}

test "a datagram past the negotiated ceiling is refused, and one with no extension is refused sooner" {
    var client_secret = try SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();
    var server_secret = try SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();

    var link: Link = undefined;
    try link.init(client_secret, server_secret, server_secret.nodeId(), 23, .{
        .max_datagram_frame_size = frame_size,
    });
    defer link.deinit();
    try link.drive(link_start, max_rounds, bothUp);

    const client = link.client.live().?;

    // `DatagramTooLarge` is permanent and both size checks run before the core
    // is asked, so nothing is queued: a caller that caught it and shrank the
    // payload is the intended recovery, and a caller that retried the same
    // bytes would spin for ever if any had been buffered.
    const ceiling = client.datagramMaxPayload().?;
    const too_big = try t.allocator.alloc(u8, ceiling + 1);
    defer t.allocator.free(too_big);
    try t.expectError(error.DatagramTooLarge, client.sendDatagram(too_big, link_start));
    try t.expectEqual(@as(usize, 0), client.datagramQueued());

    // Exactly the ceiling is accepted, which is what says the refusal above is
    // the ceiling and not an off-by-one in the guard.
    const at_ceiling = try t.allocator.alloc(u8, ceiling);
    defer t.allocator.free(at_ceiling);
    @memset(at_ceiling, 'z');
    try client.sendDatagram(at_ceiling, link_start);
    try t.expectEqual(@as(usize, 1), client.datagramQueued());

    // A connection where neither end advertised the frame size never got the
    // extension, and there is no negotiation to retry: the refusal holds for the
    // whole life of the connection. This is the assertion the module doc is
    // about, and it is why every other test in this file configures both
    // bridges.
    var plain_client = try SecretKey.fromSeed(client_seed);
    defer plain_client.deinit();
    var plain_server = try SecretKey.fromSeed(server_seed);
    defer plain_server.deinit();
    var plain: Link = undefined;
    try plain.init(plain_client, plain_server, plain_server.nodeId(), 24, .{});
    defer plain.deinit();
    try plain.drive(link_start, max_rounds, bothUp);

    const unconfigured = plain.client.live().?;
    try t.expect(!unconfigured.datagramsEnabled());
    try t.expectEqual(@as(?usize, null), unconfigured.datagramMaxPayload());
    try t.expectError(
        error.DatagramsNotEnabled,
        unconfigured.sendDatagram(payload, link_start),
    );
}

test "a datagram the path drops is gone, and the connection keeps running without it" {
    var client_secret = try SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();
    var server_secret = try SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();

    var link: Link = undefined;
    try link.init(client_secret, server_secret, server_secret.nodeId(), 25, .{
        .max_datagram_frame_size = frame_size,
    });
    defer link.deinit();
    try link.drive(link_start, max_rounds, bothUp);

    const client = link.client.live().?;
    const server = link.server.live().?;

    // Every one of the client's next datagrams is thrown away by `Link.drop`
    // before the socket ever sees it. The drop is the harness's: a loopback does
    // not lose packets, and this is the only way to ask the core what it does
    // when one is lost.
    link.drop[0] = 8;
    try client.sendDatagram(second_payload, link_start);

    // The clock moves here and nowhere else in this artifact. A QUIC DATAGRAM
    // frame is never retransmitted (RFC 9221 §5.2), so advancing the clock is
    // what proves the negative: given every probe timeout the core could ask
    // for, the datagram still does not arrive, because there is nothing queued
    // to resend.
    var round: usize = 0;
    var arrived = false;
    var scratch: [second_payload.len]u8 = undefined;
    while (round < max_loss_rounds) : (round += 1) {
        _ = try link.exchange(atRound(round));
        if (server.recvDatagram(&scratch, atRound(round)) != null) {
            arrived = true;
            break;
        }
    }

    // The datagrams were dropped, and not merely delayed: the harness counted
    // them, so this is the harness's own arithmetic rather than an inference
    // from the peer having said nothing.
    try t.expect(link.dropped[0] > 0);
    try t.expectEqual(@as(usize, 0), link.drop[0]);

    if (arrived) {
        link.report("datagram", "a dropped datagram was delivered anyway");
        return error.DatagramRetransmitted;
    }

    // The connection survived it. A datagram is the one thing in QUIC whose loss
    // may cost the connection nothing, and this is the half of that claim an
    // "it did not arrive" assertion cannot reach: a core that tore the
    // connection down on the loss would satisfy everything above.
    try t.expect(client.established());
    try t.expect(server.established());

    // And the seam still works afterwards, with the drop budget spent. A
    // datagram lost to a transient path event is not a datagram the connection
    // has stopped carrying — which is the assertion a retransmission would
    // have made unnecessary and a drop-only reading would have missed.
    try client.sendDatagram(payload, link_start);
    var roomy: [payload.len]u8 = undefined;
    round = 0;
    var out: ?[]const u8 = null;
    while (round < max_rounds) : (round += 1) {
        _ = try link.exchange(link_start);
        if (server.recvDatagram(&roomy, link_start)) |taken| {
            out = taken;
            break;
        }
    }
    const received = out orelse {
        link.report("datagram", "the seam stopped carrying datagrams after a loss");
        return error.DatagramSeamDead;
    };
    try t.expectEqualStrings(payload, received);
}

test "a datagram rides out under the codepoint the core marked, and comes back under it" {
    var client_secret = try SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();
    var server_secret = try SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();

    var link: Link = undefined;
    try link.init(client_secret, server_secret, server_secret.nodeId(), 26, .{
        .max_datagram_frame_size = frame_size,
    });
    defer link.deinit();
    try link.drive(link_start, max_rounds, bothUp);

    const client = link.client.live().?;
    const server = link.server.live().?;
    try client.sendDatagram(payload, link_start);

    var roomy: [payload.len]u8 = undefined;
    var round: usize = 0;
    var out: ?[]const u8 = null;
    while (round < max_rounds) : (round += 1) {
        _ = try link.exchange(link_start);
        if (server.recvDatagram(&roomy, link_start)) |taken| {
            out = taken;
            break;
        }
    }
    const received = out orelse {
        link.report("datagram", "the datagram never reached the peer's queue");
        return error.DatagramNotDelivered;
    };
    try t.expectEqualStrings(payload, received);

    // The datagram rode inside a packet that carried the core's codepoint, and
    // that codepoint is what came back off the peer's socket. This is the same
    // two-sided claim the handshake test makes about a handshake, applied to
    // application data: a value that survived one hop is a value the control
    // message carried, and `batch.zig` is what says the codepoint travels that
    // way rather than being invented by the layer above.
    //
    // Both ends are checked because either alone is satisfiable by a bug on one
    // side. A side that marked nothing and saw nothing has nothing to compare,
    // which is a finding and not a pass.
    for (0..2) |which| {
        if (link.ecn[which].marked == 0 or link.ecn[which].saw == 0) {
            link.report(
                "datagram codepoint",
                "a datagram went out or came in with no codepoint to compare",
            );
            return error.NoEcnObserved;
        }
    }
    try t.expectEqual(batch.Ecn.ect0, link.ecn[0].last_sent.?);
    try t.expectEqual(batch.Ecn.ect0, link.ecn[1].last_seen.?);
}
