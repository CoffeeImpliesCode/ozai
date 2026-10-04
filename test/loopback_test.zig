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
//! # What this file is, and what it split into
//!
//! This file is the transport contract and nothing else: a handshake completes
//! between two `ConnectionManager`s over a real socket, the peer is the node
//! that was named, application bytes cross in both directions, and a peer pin
//! that names a stranger is refused *at the certificate*.
//!
//! Everything else that belongs to this artifact was split out by
//! responsibility, because one file holding four unrelated claims is four
//! claims whose failure names the wrong thing:
//!
//! * `test/loopback_link.zig` — the transport harness. An identity, a socket,
//!   the buffers, and the flight loop that moves datagrams between two of
//!   them. It has no tests; it is what the other files stand on.
//! * `test/loopback_alpn_test.zig` — which protocol was negotiated, and what
//!   happens to a peer that asks for one this node does not speak.
//! * `test/loopback_uni_stream_test.zig` — the unidirectional seam: opening,
//!   the credit a write is bounded by, and draining at the far end.
//! * `test/loopback_datagram_test.zig` — the RFC 9221 seam, and what the
//!   stack does about a datagram the path throws away.
//! * `test/loopback_retry_test.zig` — the Retry token, from the moment it is
//!   sealed to the moment a second use of it is refused.
//!
//! `test/protocol_loopback_test.zig` stands on the same harness and asks a
//! different question: not whether a socket carries bytes, but whether the
//! protocol above it converges.
//!
//! # What is asserted here
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
//! refusal at error level (`vendor/quic/src/quic/connection.zig:3178`). A test
//! runner that fails any binary which logged at error level cannot host that
//! test, so this artifact names its own runner through
//! `std.Build.Step.Compile.test_runner`: `test/expected_log_runner.zig`,
//! which accounts for that one message and nothing else. The core still logs
//! the refusal at error level, the message is still printed, and the assertion
//! below still has to hold on its own — the runner changes which log is also
//! a failure, not whether it is a log.
//!
//! **The ALPN refusal in `loopback_alpn_test.zig` logs at error level too**,
//! with the same wording and a different argument:
//! `TLS 1.3 handshake error: error.NoApplicationProtocol`. It is a second
//! message this artifact provokes on purpose, so `build.zig` has to name it as
//! a second `--expect-log` row beside the certificate one. Each row is spent
//! by the first message that matches it and by no other, which is exactly what
//! makes two refusals in one run accountable separately.
//!
//! The tolerated messages are named whole, so anything this artifact logs at
//! error level is counted and fails the run. It logs exactly one other thing,
//! in one place: a teardown that could not free the dialer. `Link.deinit` is a
//! `defer` and `Link.init` unwinds through an `errdefer`, and neither may
//! `return` an error, so that failure is reported the way a stall is
//! reported and then logged rather than swallowed. Nothing else here logs at
//! error level, and a run in which every teardown succeeded writes no such
//! line at all.
//!
//! Three things a reader will otherwise try first, all checked against the
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
//! * Adding a sibling file's tests here is not the same as adding a build
//!   step. Zig collects the test blocks of every file the root *reaches*, so
//!   the imports at the bottom of this file are what make those tests part of
//!   this artifact; without them the files would compile and never run.
//!
//! There are no sleeps and no fixed ports anywhere in this artifact. Time does
//! not move at all in this file — every call below is made at one instant — so
//! the loops end on what the state machines report or on a round bound, and
//! never on a delay. `loopback_datagram_test.zig` is the one file that moves
//! its clock, and it says why where it does it.

const std = @import("std");
const ozai = @import("ozai");

const t = std.testing;

const link_mod = @import("loopback_link.zig");

const batch = ozai.transport_batch;
const Link = link_mod.Link;
const bothUp = link_mod.bothUp;
const link_start = link_mod.start;
const link_alpn = link_mod.alpn;

const SecretKey = ozai.SecretKey;

/// Fixed seeds, so both endpoints present the same certificate on every run
/// and a failure can be reproduced rather than re-diagnosed.
const client_seed: [SecretKey.seed_length]u8 = @splat(0xc1);
const server_seed: [SecretKey.seed_length]u8 = @splat(0x53);
/// A third identity that is on neither socket, for the pin that must not be
/// satisfied.
const stranger_seed: [SecretKey.seed_length]u8 = @splat(0x3c);

/// How many rounds the handshake may take before it is called stalled.
///
/// Generous, because a round is a few syscalls and nothing here can block: the
/// bound is a backstop against a run that never converges, not a timer.
const max_rounds = 32;

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
    try link.init(client_secret, server_secret, server_secret.nodeId(), 1, .{});
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

    try link.drive(link_start, max_rounds, bothUp);

    try t.expectEqual(@as(usize, 1), link.client.bridge.manager.connectionCount());
    try t.expectEqual(@as(usize, 1), link.server.bridge.manager.connectionCount());

    // Both ends found their connection by index, and the dialled one is the
    // connection the dialer was handed. `Dialer.dial` returns a `Conn` and
    // nothing else; if the bridge could not find the same connection by
    // walking its own table, the dial path would be a second one.
    const dialled = link.client.bridge.connectionAt(0) orelse return error.NoConnection;
    try t.expectEqual(link.dialled.id(), dialled.id());
    try t.expect(dialled.established());
    const accepted = link.server.bridge.connectionAt(0) orelse return error.NoConnection;
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
        &link_mod.spkiOf(client_secret.nodeId()),
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
    try t.expectEqualStrings(link_alpn, dialled.entry.conn.negotiatedAlpn());
    try t.expectEqualStrings(link_alpn, accepted.entry.conn.negotiatedAlpn());

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
        _ = try link.exchange(link_start);
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
    const server_stream = accepted.entry.conn.streams.getStream(stream.stream_id) orelse
        return error.NoStream;
    try server_stream.send.writeData(answer);
    server_stream.send.close();

    var reply: [answer.len]u8 = undefined;
    var reply_len: usize = 0;
    round = 0;
    while (round < max_rounds) : (round += 1) {
        _ = try link.exchange(link_start);
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
    try link.init(client_secret, server_secret, stranger.nodeId(), 2, .{});
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
    // a certificate it will not accept at error level, and the runner `zig
    // test` generates fails any binary that logged one. So this artifact runs
    // under `test/expected_log_runner.zig`, which accounts for that one
    // message and lets every other error log through as a failure. The
    // message below is still printed, and nothing in the first test was
    // weakened to earn the green run this one ends in.
    var round: usize = 0;
    while (round < max_rounds) : (round += 1) {
        _ = try link.exchange(link_start);
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
    const carried = dialled.entry.conn.tls13_hs orelse {
        link.report("pin check", "the refused handshake kept no state to read the pin off");
        return error.PinFailureNotInspectable;
    };
    try t.expectEqual(@as(?[32]u8, null), carried.peerNodeId());
    try t.expectEqual(stranger.nodeId().toBytes(), carried.config.expect_peer_node_id.?);

    // The pin is a comparison and not an assertion: it was carried, it was
    // checked, and the comparison is against bytes the peer had to prove
    // possession of. The first test is only worth anything because this one
    // fails.
    const stranger_id = stranger.nodeId().toBytes();
    const server_id = server_secret.nodeId().toBytes();
    try t.expect(!std.mem.eql(u8, &stranger_id, &server_id));
    try t.expect(!std.mem.eql(u8, &link_mod.spkiOf(stranger.nodeId()), &link_mod.spkiOf(server_secret.nodeId())));
}

// The rest of this artifact. Zig collects the test blocks of every file the
// root reaches, so these four imports are what make those claims part of this
// artifact rather than four files that compile and never run — the same
// reachability rule `src/root.zig` names in its `refAllDecls` block.
test {
    _ = @import("loopback_alpn_test.zig");
    _ = @import("loopback_uni_stream_test.zig");
    _ = @import("loopback_datagram_test.zig");
    _ = @import("loopback_retry_test.zig");
}
