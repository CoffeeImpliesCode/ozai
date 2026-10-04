//! The unidirectional seam over a real socket: opening a stream the peer never
//! sends on, writing bytes the peer's window bounds, and draining at the far
//! end until the FIN arrives.
//!
//! # Why this file exists
//!
//! `docs/PLAN.md` records the gap this wave closes: "the bridge exposes
//! bidirectional streams only". A bidirectional stream has a receive half that
//! its opener also owns, so every bidirectional test in `loopback_test.zig`
//! could be written without ever asking what happens when one end has nothing
//! to send back. That is the shape a one-way protocol has — a metrics frame, a
//! gossip forward, a blob's progress — and it is the shape nothing had been
//! asked about.
//!
//! The core keeps the two halves apart, and the split is visible in this file's
//! types: `streams.send_streams` holds locally opened unidirectional streams and
//! `streams.recv_streams` holds the peer's (`stream.zig:1525-1528`). One
//! wrapper could not cover both, so `UniStream` is the send half and `RecvUni`
//! is the receive half, and neither has a bidirectional stream's convenience of
//! being both at once.
//!
//! # The bounds, and why each is its own test
//!
//! * **The stream count.** `StreamsMap.openUniStream` refuses once the peer's
//!   advertised limit is spent (`stream.zig:1763`), and the bridge names that
//!   `error.NoStreamRoom`. MAX_STREAMS is cumulative, so nothing this test does
//!   can make room again — which is why the boundary test asserts the refusal
//!   and stops, rather than trying to open "one more".
//! * **The send credit.** The core's `SendStream.writeData` is unbounded — it
//!   buffers whatever it is handed — so the refusal that protects the peer has
//!   to happen before the core is asked. `UniStream.write` checks `credit()`
//!   first. The test asserts the refusal *and* that the send buffer is still
//!   empty afterwards, because a refusal that had already copied the bytes
//!   would let a caller's retry write on top of data that was never taken.
//! * **The drain loop.** `RecvUni.drain` grows the caller's sink, so there is
//!   no refusal to assert; what there is instead is that a pass moves at most
//!   64 runs and a caller must call again. A drained stream answers `false`,
//!   and that `false` is asserted last so it cannot be a value a `drain` always
//!   returned.
//!
//! # Time does not move
//!
//! Every call is made at one instant, exactly as in `loopback_test.zig`. Nothing
//! here needs a retransmission, so no clock is advanced and the only things
//! that can end a loop are the state machines and the round bound.

const std = @import("std");
const ozai = @import("ozai");

const t = std.testing;

const link_mod = @import("loopback_link.zig");
const quic_stream = ozai.transport_quic_stream;

const Link = link_mod.Link;
const bothUp = link_mod.bothUp;
const link_start = link_mod.start;
const RecvUni = quic_stream.RecvUni;
const UniStream = quic_stream.UniStream;

const SecretKey = ozai.SecretKey;

/// Fixed seeds, as in `loopback_test.zig`, so every loopback failure in this
/// artifact reproduces from the seeds in its own file.
const client_seed: [SecretKey.seed_length]u8 = @splat(0xc1);
const server_seed: [SecretKey.seed_length]u8 = @splat(0x53);

/// How many rounds a phase may take. Generous, because a round is a few
/// syscalls and nothing here blocks.
const max_rounds = 32;

/// The unidirectional limit both bridges advertise in the bound test.
///
/// Two rather than one, so that the refusal is the *third* open: a limit of one
/// would make the second open the boundary and would not show that the counter
/// counts opens rather than live streams.
const uni_limit: u64 = 2;

/// The unidirectional send window both bridges advertise in the credit test.
/// Small enough that sitting next to the boundary costs nothing.
const uni_window: u64 = 64;

/// What the client writes on a unidirectional stream. The peer never opens a
/// send half to answer on, and never will: that is the whole point of the
/// direction, and this payload is never replied to.
const report = "a one-way report, on a stream with no other half";

test "a unidirectional stream carries bytes one way and the peer drains them to the FIN" {
    var client_secret = try SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();
    var server_secret = try SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();

    var link: Link = undefined;
    try link.init(client_secret, server_secret, server_secret.nodeId(), 11, .{});
    defer link.deinit();
    try link.drive(link_start, max_rounds, bothUp);

    const client = link.client.live().?;
    const server = link.server.live().?;

    // A client-initiated unidirectional stream is id 2, then 6, then 10 —
    // RFC 9000 §2.1 numbers them 2 + 4n. Asserted rather than read back off
    // the handle, because the id is what tells the two halves apart in the
    // core's two maps and a value taken from the opener would prove only that
    // the handle agrees with itself.

    // `var`, because the send half is written through: `UniStream.write` and
    // `close` take `*UniStream` and the handle is a value, so the binding is
    // what supplies the pointer. The datagram file's `const client` works
    // because every `Conn` call takes `self` by value — nothing here does.
    var uni = try client.openUni();
    try t.expectEqual(@as(u64, 2), uni.id());

    // The peer's credit is a real number before anything is written, and it is
    // generous: `initial_max_stream_data_uni` defaults to 1 MiB in the core
    // (`connection.zig:917`). A report is far inside it, and asserting that is
    // what says the credit this test relies on is the peer's window rather than
    // a constant the bridge invented.
    try t.expect(uni.credit() > report.len);
    try t.expectEqual(@as(usize, 0), uni.buffered());

    const written = try uni.write(report);
    try t.expectEqual(report.len, written);

    // The write is buffered, not sent: what is on the wire is whatever the next
    // `exchange` drains, and the bytes cross a real socket in that call or
    // they have not crossed anything.
    uni.close();

    // The peer finds it by id, and only once the stream exists: a `RecvUni`
    // handed out before its STREAM frame arrived would be a stream with no data
    // behind it, and the drain loop below would end on its first empty pass and
    // read that as "the peer has nothing".
    var recv: ?RecvUni = null;
    var round: usize = 0;
    while (round < max_rounds) : (round += 1) {
        _ = try link.exchange(link_start);
        if (server.acceptUni(0)) |taken| {
            recv = taken;
            break;
        }
    }
    var received = recv orelse {
        link.report("uni-stream", "the peer never saw the unidirectional stream");
        return error.UniStreamMissing;
    };
    // The id the peer found is the one the opener was given, which is what says
    // the two halves are one stream rather than two that happen to line up.
    try t.expectEqual(@as(u64, 2), received.id());

    // Draining is a loop, not a call: one pass moves at most 64 runs, so a
    // caller that stopped at the first empty pass would leave the rest of the
    // stream undelivered. The loop ends on the FIN *and* on a whole sink,
    // because either alone is not the end of the data.
    var sink: std.ArrayList(u8) = .empty;
    defer sink.deinit(t.allocator);
    round = 0;
    while (round < max_rounds) : (round += 1) {
        _ = try link.exchange(link_start);
        _ = try received.drain(t.allocator, &sink);
        if (received.finished() and sink.items.len == report.len) break;
    }

    // Every byte arrived, in order, and the FIN arrived with it. The two are
    // asserted separately because a stream that ended early would satisfy a
    // length check alone and a stream that is merely not finished yet would
    // satisfy a `finished` check alone.
    if (!received.finished()) {
        link.report("uni-stream", "the peer's unidirectional stream never finished");
        return error.UniStreamUnfinished;
    }
    try t.expectEqual(report.len, sink.items.len);
    try t.expectEqualStrings(report, sink.items);

    // A drained stream moves nothing. This is asserted last so it cannot be a
    // `false` that a `drain` always returned: every assertion above would pass
    // against one.
    try t.expect(!try received.drain(t.allocator, &sink));
    try t.expectEqual(report.len, sink.items.len);
}

test "a unidirectional write past the peer's credit is refused and buffers nothing" {
    var client_secret = try SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();
    var server_secret = try SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();

    var link: Link = undefined;
    // The window is what the *peer* grants, so this is the server advertising
    // it and the client being bounded by it. Small on purpose: the core's own
    // default is 1 MiB (`connection.zig:917`), and a boundary test that has to
    // allocate a megabyte to sit next to the line is a test that reads as if it
    // were testing allocation.
    try link.init(client_secret, server_secret, server_secret.nodeId(), 12, .{
        .initial_max_stream_data_uni = uni_window,
    });
    defer link.deinit();
    try link.drive(link_start, max_rounds, bothUp);

    const client = link.client.live().?;

    // `var` for the reason above: this is the handle `write` is called on.
    var uni = try client.openUni();

    // The credit is the window the peer granted and nothing else, so the
    // boundary below is a number this test chose rather than a default.
    try t.expectEqual(uni_window, uni.credit());

    // One byte past it. The core's own `writeData` is unbounded, so this refusal
    // is the bridge's and it happens before the core is asked at all — which is
    // the only place it can happen, because after the copy the bytes are already
    // buffered and the peer cannot unbuffer them.
    const oversized = try t.allocator.alloc(u8, uni_window + 1);
    defer t.allocator.free(oversized);
    @memset(oversized, 'x');
    try t.expectError(error.NoSendCredit, uni.write(oversized));

    // The refusal left the send buffer as it was. This is the half of the
    // contract that is easy to leave out: a caller that caught the error and
    // wrote again would be appending to bytes the core never took, and the
    // peer's window would be overrun by a write that reported failure.
    try t.expectEqual(@as(usize, 0), uni.buffered());

    // Exactly the window is taken whole, which is what says the refusal above is
    // the credit and not a cap sitting somewhere below it.
    const exact = try t.allocator.alloc(u8, uni_window);
    defer t.allocator.free(exact);
    @memset(exact, 'y');
    try t.expectEqual(@as(usize, uni_window), try uni.write(exact));
    try t.expectEqual(@as(usize, uni_window), uni.buffered());
}

test "a unidirectional open past the peer's stream limit is refused" {
    var client_secret = try SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();
    var server_secret = try SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();

    var link: Link = undefined;
    // Both bridges advertise the limit, because the limit that bounds the
    // *client's* opens is the one the *server* advertises: the core's
    // `max_uni_streams` is installed from the peer's transport parameters
    // (`connection.zig:3371`). Configuring only the client would leave the
    // default of 100 in force and the refusal below would never fire.
    try link.init(client_secret, server_secret, server_secret.nodeId(), 13, .{
        .initial_max_streams_uni = uni_limit,
    });
    defer link.deinit();
    try link.drive(link_start, max_rounds, bothUp);

    const client = link.client.live().?;

    // Two opens fit and the third is refused. Every stream is left open, so the
    // count being tested is opens and not live streams: a limit that counted
    // concurrent streams would have been satisfied by closing one, and
    // neither is closed before the refusal below.
    var opened: [uni_limit]UniStream = undefined;
    for (&opened, 0..) |*stream, index| {
        stream.* = try client.openUni();
        try t.expectEqual(@as(u64, 2 + 4 * index), stream.*.id());
    }

    // MAX_STREAMS is cumulative (RFC 9000 §2.1), so the refusal is final for
    // this connection: only a MAX_STREAMS frame raises the limit, and nothing
    // on this link grants one. Asserting the refusal a second time would
    // assert the same thing, so it is asserted once and the bound is taken as
    // final — which is also why no test in this file closes a stream to make
    // room.
    try t.expectError(error.NoStreamRoom, client.openUni());

    // The refusal left the two that did open alone: same handles, same ids,
    // and nothing written on either. That is the half of the boundary a
    // single `expectError` cannot show — an answer of `NoStreamRoom` is also
    // what a caller would get from a connection the refused open had already
    // disturbed, and these two ids are what rule that out.
    for (&opened, 0..) |*stream, index| {
        try t.expectEqual(@as(u64, 2 + 4 * index), stream.*.id());
        try t.expectEqual(@as(usize, 0), stream.*.buffered());
    }

    // Teardown, and not part of the count: both were still live when the
    // refusal fired, and the bound is cumulative, so closing them here could
    // not have made room and did not. A `UniStream` owns nothing of its own —
    // its buffer belongs to the core — so `close` is the whole of what a
    // caller owes one, and there is no `deinit` for it to balance against.
    for (&opened) |*stream| stream.close();
}
