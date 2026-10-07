//! The first *transfer* over a real connection: a blob's bytes, from a provider
//! that has them to a getter that does not.
//!
//! `test/protocol_loopback_test.zig` sent a `get` across a kernel socket and
//! proved the plan's first blob property — missing data is EOF, not an error
//! frame — with an answer of thirty-one bytes the test wrote itself. Every
//! transfer in this project so far has been a negotiation: a request went out,
//! a request came back, and no content changed hands. This file moves content.
//!
//! # What is asserted
//!
//! 1. **A whole blob, by content.** `GetRequest.blob` over a real connection,
//!    compared byte for byte against the provider's own copy. There is no
//!    length-only assertion in this file: a transfer test that checks a length
//!    has checked nothing about the data.
//! 2. **Two disjoint ranges, and nothing else.** A `RangeSpec` of two
//!    selected runs with a gap either side of each. The answer is those two
//!    runs, in order, and the byte ranges the provider derived are asserted
//!    against chunk arithmetic before the content is.
//! 3. **A byte range that is not chunk-aligned.** `bytesToChunks` rounds
//!    *outward* at both ends, so a request for bytes 5000 through 20000 is a
//!    request for chunks 4 through 20 and the answer starts at byte 4096.
//!    That rounding is the conversion the type exists for, and a whole-blob
//!    fetch never reaches it.
//! 4. **The short last chunk.** `chunksToBytes` is exact only for a whole
//!    number of chunks, so the range that ends in this blob's last chunk comes
//!    back shorter than the chunk arithmetic alone says. The provider has to
//!    clip, and the assertion is on the clipped length.
//! 5. **`ChunkRangeSet` on the wire.** An `observe` answered with the
//!    provider's own availability, decoded by the getter, which then derives
//!    from the boundaries that arrived the byte ranges the answer must cover.
//! 6. **The two framings are not interchangeable, on the wire.** A `push` and
//!    its payload share a stream, so the payload must not be readable as part
//!    of a `get` body; and a `get` frame is not a `push` frame with the byte
//!    in front changed. Both are checked against bytes off a socket.
//! 7. **A short answer is not a complete transfer.** A provider that stops
//!    part way through and closes: the getter sees a FIN, the bytes it holds
//!    are the right ones, and there are fewer of them than the request asked
//!    for. A transfer that hands the short buffer back as if it were whole is
//!    worse than one that fails, so the completion test is a content
//!    comparison and it is asserted to fail.
//! 8. **The send seam segmented the transfer.** `batch.max_segments_linux` is
//!    64 and this blob's answer is more than 64 datagrams, so the batching ran
//!    off the end of what one `sendmsg` may carry: `UDP_SEGMENT` is on the
//!    wire, and at least one batch had to be cut to go out.
//! 9. **The batch boundary, at more than one segment size.** The core's
//!    datagram size on loopback does not move, so a transfer can only ever
//!    burst at one of them. A model that cut at the segment cap alone would
//!    pass that transfer and regress at every other size, so the sizes a
//!    connection cannot be made to produce are asserted on the seam directly:
//!    the most bytes one `sendmsg` may carry is a ratio of the payload limit to
//!    the segment size and not a constant.
//!
//! # What is not asserted
//!
//! That the bytes are *valid bao data*. This project has no bao encoder, so
//! the provider's answer is the blob's own bytes and what is under test is
//! the transport, the framing and the range algebra. Whether a bao decode
//! accepts them is a question for the milestone that brings a bao encoder,
//! and `test/protocol_loopback_test.zig` says the same about the bytes it
//! wrote itself.
//!
//! # Time is virtual and moves only when the test says so
//!
//! Every call into the QUIC core takes an `Instant`. This file owns one
//! counter and advances it by one millisecond per round. No clock is ever read
//! and nothing sleeps anywhere in this file, so a loaded machine cannot make
//! this test fail by being busy: the bound is on rounds, and a run that never
//! finishes ends by naming the request it was on, the ranges it had planned
//! and how many bytes had arrived. The total virtual time stays far below the
//! core's 30 s idle timeout, so a connection is never reaped by the clock —
//! a reaped connection would be a finding about time and not about blobs.
//!
//! # The provider is this file's own
//!
//! `src/blobs/protocol.zig` is a codec: it has `BaoResponse` and no server, so
//! the half of the protocol that *answers* a request is this file's. Every
//! step of its answer is the protocol's own and none of it is invented here —
//! the sequence walk is `RangeSpecSeq.iter`, the spans are `RangeSpec.resolve`
//! against the blob's chunk count, the bytes are `chunksToBytes`, and the
//! availability an `observe` reports is a `ChunkRangeSet` boundary list. The
//! one thing this file adds is the clip at the blob's real length, because
//! `chunksToBytes` is only exact for a whole number of chunks and this blob's
//! last chunk is short.

const std = @import("std");
const ozai = @import("ozai");

const t = std.testing;

const blobs = ozai.blobs_protocol;
const postcard = ozai.postcard;
const batch = ozai.transport_batch;

const job_ns = @import("transfer_jobs.zig");
const link_ns = @import("transfer_link.zig");
const ranges_mod = @import("transfer_ranges.zig");
const wire = @import("transfer_wire.zig");

/// How much of a whole-blob answer the truncating provider stops after.
const truncated_at: usize = 1000;

/// The widths of the disjoint range spec: two chunks off, three on, four off,
/// five on. Two selected runs that do not touch, which is the shape a
/// whole-blob fetch cannot express.
const disjoint_widths = [_]u64{ 2, 3, 4, 5 };

/// The widths of a range that starts in the blob's 255th chunk. The selected
/// run runs to the end of the walk and is cut by the blob's end, which is the
/// short last chunk.
const tail_widths = [_]u64{ 254, 3 };

// -- the report ---------------------------------------------------------

/// What a stall has to say. It names the request, the range and the byte
/// count, because a stall without all three is a stall that has to be
/// reproduced before it can be read.
pub fn report(link: *link_ns.Link, reason: []const u8) void {
    std.debug.print("\nblobs transfer stalled: {s}\n", .{reason});
    for (&link.jobs) |*job| {
        if (std.mem.eql(u8, job.name, "unused")) continue;
        std.debug.print(
            "  {s}: {t} {f} on stream {d}\n",
            .{ job.name, job.kind, job.spec(), job.stream },
        );
        std.debug.print("    plan:", .{});
        for (job.plan.ranges[0..job.plan.len]) |range| {
            std.debug.print(" [{d},{d})", .{ range.start, range.end });
        }
        std.debug.print(
            " ({d} bytes), asked {}, answered {}\n",
            .{ job.plan.total(), job.asked, job.served },
        );
        const got = job_ns.received(&link.getter_bytes, job.stream);
        std.debug.print(
            "    {d} of {d} bytes arrived, fin {}\n",
            .{ got.len, job.expected.total(), link.finished(&link.getter_fin, job.stream) },
        );
    }
    for (0..2) |which| {
        const side: *wire.Wire = if (which == 0) &link.getter else &link.provider;
        std.debug.print(
            "  {s} ({f}) at {f}: {d} datagrams out, {d} in," ++
                " {d} runs in {d} sends, widest {d}, {d} segmented," ++
                " {d} finished, {d} ecn dropped\n",
            .{
                side.name,
                side.id,
                side.socket.address,
                side.stats.out,
                side.stats.in,
                side.stats.runs,
                side.stats.sends,
                side.stats.widest,
                side.stats.segmented,
                side.stats.finished,
                side.stats.dropped_ecn,
            },
        );
    }
    std.debug.print("  virtual time {d} ms; round bound {d}\n", .{
        link.now / std.time.ns_per_ms,
        wire.max_rounds,
    });
}

/// Run rounds until `goal` holds, or until the bound is reached.
pub fn drive(link: *link_ns.Link, phase: []const u8, goal: fn (*link_ns.Link) bool) !void {
    var round: usize = 0;
    while (round < wire.max_rounds) : (round += 1) {
        if (goal(link)) return;
        _ = try link.round();
    }
    if (goal(link)) return;
    report(link, phase);
    return error.Stalled;
}

pub fn handshaken(link: *link_ns.Link) bool {
    const accepted = link.provider.bridge.connectionAt(0) orelse return false;
    return link.dialled.established() and accepted.established();
}

pub fn allServed(link: *link_ns.Link) bool {
    for (&link.jobs) |*job| {
        if (std.mem.eql(u8, job.name, "unused")) continue;
        if (!job.served) return false;
    }
    return true;
}

pub fn allComplete(link: *link_ns.Link) bool {
    for (&link.jobs) |*job| {
        if (std.mem.eql(u8, job.name, "unused")) continue;
        if (!link.finished(&link.getter_fin, job.stream)) return false;
    }
    return true;
}

/// The two ends proved who they are to each other by the handshake, not by the
/// configuration.
pub fn checkIdentity(link: *link_ns.Link) !void {
    const getter_conn = link.dialled;
    const provider_conn = link.provider.bridge.connectionAt(0) orelse
        return error.NoConnection;
    if (!getter_conn.established() or !provider_conn.established()) {
        report(link, "the blobs handshake did not finish");
        return error.Stalled;
    }
    try t.expectEqual(
        link.provider.id.toBytes(),
        getter_conn.entry.conn.tls13_hs.?.peerNodeId().?,
    );
    try t.expectEqual(
        link.getter.id.toBytes(),
        provider_conn.entry.conn.clientAuth().?.expect_node_id.?,
    );
    try t.expectEqualStrings(blobs.alpn, getter_conn.entry.conn.negotiatedAlpn());
}

// ---------------------------------------------------------------------------
// What a getter does with what arrived
// ---------------------------------------------------------------------------

/// The answer on one stream, as `BaoResponse` reads it: everything that is
/// left, which is the whole of what a `get`'s answer is.
pub fn answerOf(link: *link_ns.Link, job: *job_ns.Job) blobs.BaoResponse {
    var reader = postcard.Reader.init(job_ns.received(&link.getter_bytes, job.stream));
    return blobs.BaoResponse.read(&reader);
}

/// Whether an answer is the whole of what was asked for.
///
/// A content comparison and not a length: a transfer that silently truncates
/// hands back a short buffer, and comparing what arrived against what was read
/// rather than against what was asked for would make that pass. This is the
/// predicate a caller would write, and the truncating test asserts it is false.
pub fn covers(store: ranges_mod.Store, plan: ranges_mod.Plan, answer: blobs.BaoResponse) bool {
    var at: usize = 0;
    for (plan.ranges[0..plan.len]) |range| {
        const want = store.bytes[@intCast(range.start)..@intCast(range.end)];
        if (answer.bytes.len < at + want.len) return false;
        if (!std.mem.eql(u8, want, answer.bytes[at .. at + want.len])) return false;
        at += want.len;
    }
    return at == answer.bytes.len;
}

// ---------------------------------------------------------------------------
// Test 1: a whole blob, by content, across a segmented send
// ---------------------------------------------------------------------------

test "a whole blob crosses a real socket, and the send seam segments it" {
    var link: link_ns.Link = undefined;
    try link.init();
    defer link.deinit();

    try drive(&link, "the blobs handshake", handshaken);
    try checkIdentity(&link);

    // The ephemeral ports are two distinct numbers on the loopback, which is
    // what says neither end dialled itself.
    try t.expect(link.getter.socket.address.port != link.provider.socket.address.port);
    try t.expect(link.getter.socket.address.port != 0);
    try t.expect(link.provider.socket.address.port != 0);

    const job = &link.jobs[0];
    link.put(0, .{ .name = "whole blob", .kind = .get, .whole = true });
    try job.expect(&.{.{ .start = 0, .end = link.store.bytes.len }});
    try job_ns.ask(&link, job);
    try drive(&link, "the whole-blob request never arrived whole", allServed);
    try drive(&link, "the whole blob never finished arriving", allComplete);

    // ── the request survived the socket ──
    const seen = job.seen orelse return error.NoRequestSeen;
    try t.expectEqual(blobs.RequestType.get, seen.discriminant());
    const get = switch (seen) {
        .to_eof => |request| switch (request) {
            .get => |value| value,
            else => return error.NotAGet,
        },
        .length_prefixed => return error.NotAnEofRequest,
    };
    try t.expectEqualSlices(u8, &ranges_mod.blob_hash, &get.hash);
    // The plan came from the decoded sequence rather than from the test's
    // widths, so this is the range algebra the wire carried: one selected span
    // over every chunk, cut at the blob's real length because the last chunk is
    // short.
    try t.expectEqual(@as(usize, 1), job.plan.len);
    try t.expectEqual(job.expected.ranges[0], job.plan.ranges[0]);
    try t.expectEqual(@as(u64, 0), job.plan.boundaries[0]);
    try t.expectEqual(link.store.chunkCount(), job.plan.boundaries[1]);

    // ── the bytes arrived, and they are the blob ──
    const answer = answerOf(&link, job);
    try t.expect(!answer.isEof());
    try t.expect(covers(link.store, job.expected, answer));
    // The content assertion, spelled out rather than folded into `covers`, so a
    // failure names the transfer and not only the predicate.
    try t.expectEqualSlices(u8, link.store.bytes, answer.bytes);
    // And the stream ended, with no reset behind it: `protocol.zig` has no
    // error frame, and a reset is what one would have cost this layer.
    const stream = link.dialled.entry.conn.streams.getStream(job.stream) orelse
        return error.NoStream;
    try t.expect(stream.recv.allReceived());
    try t.expectEqual(@as(?u64, null), stream.recv.reset_err);

    // ── the send seam segmented the transfer ──
    //
    // The seam's own capability, asserted rather than assumed: a socket that
    // could not segment would make every count below true in a way that says
    // nothing about segmentation.
    try t.expect(link.provider.socket.caps.supportsSegmentation());
    const sent = link.provider.stats;
    // More than one packet, and more than one GSO batch's worth of them.
    try t.expect(sent.datagrams > 1);
    try t.expect(sent.datagrams > batch.max_segments_linux);
    // `UDP_SEGMENT` went on the wire rather than merely being available.
    try t.expect(sent.segmented > 0);
    // And the batching ran off the end of what one `sendmsg` may carry, which
    // is what "crosses the batch boundary" means. The widest batch on this
    // transfer is 80 datagrams of 1200 bytes, above both `max_segments_linux`
    // and what one datagram can carry at that segment size, so `batch.Runs` had
    // to cut it: 10 sends became 12 socket writes, and 54 segments plus 26 is
    // the cut at this size.
    try t.expect(sent.widest > batch.max_segments_linux);
    try t.expect(sent.runs > sent.sends);
}

// ---------------------------------------------------------------------------
// Test 2: partial ranges
// ---------------------------------------------------------------------------

test "disjoint ranges and a whole blob return exactly the bytes asked for" {
    var link: link_ns.Link = undefined;
    try link.init();
    defer link.deinit();

    try drive(&link, "the blobs handshake", handshaken);
    try checkIdentity(&link);

    // The unaligned request, stated in bytes and derived in chunks: the two are
    // not the same question, and the conversion between them is the point. 5000
    // is inside chunk 4 and 20000 is inside chunk 19, so the outward rounding
    // asks for chunks 4 through 20 and the answer is bytes 4096 through 20480
    // — which is what the assertions below say, and not 5000.
    const unaligned: blobs.ByteRange = .{ .start = 5000, .end = 20000 };
    try t.expectEqual(blobs.ChunkRange{ .start = 4, .end = 20 }, blobs.bytesToChunks(unaligned));
    const unaligned_widths = [_]u64{ 4, 16 };

    const disjoint_expected = [_]blobs.ByteRange{
        .{ .start = 2 * 1024, .end = 5 * 1024 },
        .{ .start = 9 * 1024, .end = 14 * 1024 },
    };
    const unaligned_expected = [_]blobs.ByteRange{.{ .start = 4096, .end = 20480 }};
    const tail_expected = [_]blobs.ByteRange{
        .{ .start = 254 * 1024, .end = link.store.bytes.len },
    };
    const whole_expected = [_]blobs.ByteRange{.{ .start = 0, .end = link.store.bytes.len }};

    link.put(0, .{ .name = "two disjoint ranges", .widths = &disjoint_widths });
    link.put(1, .{ .name = "an unaligned byte range", .widths = &unaligned_widths });
    link.put(2, .{ .name = "the short last chunk", .widths = &tail_widths });
    link.put(3, .{ .name = "availability", .kind = .observe, .widths = &disjoint_widths });
    link.put(4, .{ .name = "whole blob", .whole = true });
    const jobs = 5;
    try link.jobs[0].expect(&disjoint_expected);
    try link.jobs[1].expect(&unaligned_expected);
    try link.jobs[2].expect(&tail_expected);
    try link.jobs[4].expect(&whole_expected);

    for (0..jobs) |index| try job_ns.ask(&link, &link.jobs[index]);
    try drive(&link, "a range request never arrived whole", allServed);
    try drive(&link, "a range answer never finished arriving", allComplete);

    // ── the provider planned from what it decoded ──
    //
    // Checked before the content, because a plan that is wrong and a store that
    // is wrong can produce the same bytes, and this says which of the two it
    // was. The decoded request is re-encoded into a buffer of its own and
    // compared against the getter's bytes: the two sides are the frame that
    // went out and the frame that came back, not one buffer against itself.
    for (0..jobs) |index| {
        const job = &link.jobs[index];
        const seen = job.seen orelse return error.NoRequestSeen;
        try t.expectEqual(job.kind.discriminant(), seen.discriminant());
        var check: [job_ns.request_room]u8 = undefined;
        var writer = postcard.Writer.init(&check);
        try seen.write(&writer, &link.body);
        try t.expectEqualSlices(u8, job.frame[0..job.frame_len], writer.finish());
        // The request's own ranges, read back out of the storage it was decoded
        // into. And that the decoded sequence borrows that storage, which is a
        // claim about an address and so is checked as one: a decode through a
        // `Storage` that was copied out of its own struct reads whatever is in
        // a dead frame now, and a debug build is the only reason that can look
        // like it worked.
        const get: ?blobs.GetRequest = switch (seen) {
            .to_eof => |request| switch (request) {
                .get => |value| value,
                .observe, .get_many => null,
            },
            .length_prefixed => null,
        };
        if (get) |value| {
            try t.expectEqualSlices(u8, &ranges_mod.blob_hash, &value.hash);
            try t.expectEqual(
                @intFromPtr(&job.storage.items[0]),
                @intFromPtr(value.ranges.items.ptr),
            );
        }
        const spec = try ranges_mod.requestSpec(job);
        if (job.whole) {
            // The module's own whole-blob sequence: one selected spec and the
            // terminator that stops the walk. Its spec is `RangeSpec.all`,
            // which is not the empty width list a job built from widths would
            // carry — which is why this is not a comparison against `widths`.
            try t.expect(spec.isAll());
        } else {
            try t.expectEqualSlices(u64, job.widths, spec.widths);
        }
    }

    // The disjoint spec is two selected runs with a gap either side, so the
    // answer is two runs and not one.
    try t.expectEqual(@as(usize, 2), link.jobs[0].plan.len);
    try t.expectEqual(disjoint_expected[0], link.jobs[0].plan.ranges[0]);
    try t.expectEqual(disjoint_expected[1], link.jobs[0].plan.ranges[1]);
    // The unaligned request came back on chunk boundaries, wider than the byte
    // range it was asked for at the start and narrower at the end: outward at
    // both ends, which is the conversion's whole asymmetry.
    try t.expectEqual(unaligned_expected[0], link.jobs[1].plan.ranges[0]);
    // The last chunk is short, so the range that ends in it is clipped to the
    // blob's real length rather than to 257 whole chunks: 2748 bytes where the
    // chunk arithmetic alone says 3072.
    try t.expectEqual(tail_expected[0], link.jobs[2].plan.ranges[0]);
    const tail_span = link.jobs[2].plan.ranges[0];
    try t.expectEqual(@as(usize, 2748), tail_span.end - tail_span.start);
    // The whole blob is one span, and it is clipped at the same place.
    try t.expectEqual(whole_expected[0], link.jobs[4].plan.ranges[0]);

    // ── and the bytes are exactly those ranges ──
    for (0..jobs) |index| {
        const job = &link.jobs[index];
        if (job.kind == .observe) continue;
        const answer = answerOf(&link, job);
        try t.expect(!answer.isEof());
        try t.expect(covers(link.store, job.expected, answer));
        // Spelled out, span by span, so a failure says which range is wrong.
        var at: usize = 0;
        for (job.expected.ranges[0..job.expected.len]) |range| {
            const want = link.store.bytes[@intCast(range.start)..@intCast(range.end)];
            try t.expectEqualSlices(u8, want, answer.bytes[at .. at + want.len]);
            at += want.len;
        }
        const stream = link.dialled.entry.conn.streams.getStream(job.stream) orelse
            return error.NoStream;
        try t.expect(stream.recv.allReceived());
        try t.expectEqual(@as(?u64, null), stream.recv.reset_err);
    }

    // ── `ChunkRangeSet`, over the same socket ──
    //
    // The availability the provider reported is a boundary list, and it is the
    // only description of the answer the getter gets. The byte ranges are
    // derived from it, chunks to bytes, with the clip a short last chunk needs,
    // so a getter that read the boundaries wrong gets ranges that do not match
    // the `get` above.
    {
        const job = &link.jobs[3];
        var reader = postcard.Reader.init(job_ns.received(&link.getter_bytes, job.stream));
        var run = blobs.ObserveResponse.read(&reader, &link.seen.inner);
        const item = (try run.next()) orelse return error.NoObserveItem;
        try t.expectEqual(link.store.bytes.len, item.size);
        try t.expectEqualSlices(u64, &.{ 2, 5, 9, 14 }, item.ranges.boundaries);
        // And the run ends between items, which is a `null` rather than an
        // error: an observe answer is a run to the end of its stream.
        try t.expect(try run.next() == null);
        try t.expect(link.finished(&link.getter_fin, job.stream));

        // The ranges those boundaries name, read against the size that came
        // with them — the other direction of the conversion, and the getter's.
        const derived = ranges_mod.planFromBoundaries(item.ranges.boundaries, item.size);
        try t.expectEqual(@as(usize, 2), derived.len);
        try t.expectEqual(disjoint_expected[0], derived.ranges[0]);
        try t.expectEqual(disjoint_expected[1], derived.ranges[1]);
        // And the answer to the `get` on those same ranges is what the
        // boundaries promised, which is the last of the algebra end to end.
        try t.expect(covers(link.store, derived, answerOf(&link, &link.jobs[0])));
    }
}

// ---------------------------------------------------------------------------
// Test 3: the two framings, on the wire
// ---------------------------------------------------------------------------

test "a push body cannot be read as a get body, on the wire" {
    var link: link_ns.Link = undefined;
    try link.init();
    defer link.deinit();

    try drive(&link, "the blobs handshake", handshaken);
    try checkIdentity(&link);

    // A `push` carrying a partial range request and a kilobyte of bao data
    // behind it, and a `get` for the same partial ranges, both on their own
    // streams. The two frames are the ones the confusion is about: a
    // `PushRequest` is a newtype over a `GetRequest`, so the bodies are the
    // same shape and only the byte in front and the framing behind it differ.
    link.put(0, .{ .name = "push with a payload", .kind = .push, .widths = &disjoint_widths });
    link.put(1, .{ .name = "partial get", .kind = .get, .widths = &disjoint_widths });
    const disjoint_expected = [_]blobs.ByteRange{
        .{ .start = 2 * 1024, .end = 5 * 1024 },
        .{ .start = 9 * 1024, .end = 14 * 1024 },
    };
    try link.jobs[1].expect(&disjoint_expected);

    try job_ns.ask(&link, &link.jobs[0]);
    try job_ns.ask(&link, &link.jobs[1]);
    try drive(&link, "a framed request never arrived whole", allServed);
    try drive(&link, "a framed stream never finished", allComplete);

    const push = &link.jobs[0];
    const get = &link.jobs[1];

    // ── the push arrived as a `push`, and its payload is behind it ──
    const push_seen = push.seen orelse return error.NoRequestSeen;
    try t.expectEqual(blobs.RequestType.push, push_seen.discriminant());
    const framed = switch (push_seen) {
        .length_prefixed => |value| value,
        .to_eof => return error.PushReadAsEof,
    };
    const received_push = job_ns.received(&link.provider_bytes, push.stream);
    // The payload is the kilobyte the getter wrote and not a byte of the
    // request: it starts where the decode said it starts, and the getter's
    // frame was exactly that many bytes.
    try t.expectEqual(push.frame_len, push.payload_offset);
    try t.expectEqual(received_push.len, push.frame_len + link.store.payload.len);
    {
        // Decoded again from the bytes that came off the socket, because the
        // property is about where a decode leaves its reader and not about
        // what a second call on an already-consumed one returns.
        var reader = postcard.Reader.init(received_push);
        const again = try blobs.Request.read(&reader, &push.storage.inner);
        try t.expectEqualSlices(u8, link.store.payload, again.payload(&reader));
        // The reader is left *on* the payload, not past it: the request is
        // over and the bao data has not started being consumed.
        try t.expectEqual(push.payload_offset, reader.offset);
    }
    // And the request's own ranges came through: a push is not restricted to a
    // whole blob, so the sequence is the disjoint one rather than `blob`'s.
    try t.expectEqualSlices(
        u64,
        &disjoint_widths,
        framed.request.get.ranges.items[0].spec.widths,
    );
    // A `to_eof` request has no payload at all, which the type says rather than
    // leaving the caller to know which framing it was handed.
    {
        const get_seen = get.seen orelse return error.NoRequestSeen;
        var reader = postcard.Reader.init(job_ns.received(&link.provider_bytes, get.stream));
        try t.expectEqualSlices(u8, "", get_seen.payload(&reader));
    }
    // The `get` on the same ranges got the bytes, which says the push did not
    // eat the connection and the framing is per stream.
    try t.expect(covers(link.store, get.expected, answerOf(&link, get)));

    // ── the confusion the two types exist to prevent ──
    //
    // A `push` body read as a `get` body. The discriminant says `push` and the
    // framing that carries it is length-prefixed, so the payload is not
    // swallowed into the request. Point the decoder at the other framing and it
    // is told so before it reads a byte of the body.
    {
        var reader = postcard.Reader.init(received_push[1..]);
        try t.expectError(
            error.WrongFraming,
            blobs.EofFraming.read(.push, &reader, &push.storage.inner),
        );
    }
    // The same body as a `get` frame, on its own and with the payload behind
    // it. The first is a request; the second is not one, and the `to_eof` rule
    // is what says so — the request is the whole stream, so a byte after it
    // cannot be part of it. This is the confusion in one comparison, and both
    // halves are the push's own bytes rather than a frame this file invented.
    {
        var clean_frame: [job_ns.request_room]u8 = undefined;
        var clean_writer = postcard.Writer.init(&clean_frame);
        try clean_writer.writeU8(@intFromEnum(blobs.RequestType.get));
        try framed.request.write(&clean_writer);
        const clean_bytes = clean_writer.finish();
        // `EofFraming.read` takes the *body*: the discriminant is read by
        // `Request.read`, which is the one reader that chooses between the two
        // framings. Handing it the body is the point of the type, and handing
        // it a frame is a different call.
        var clean_storage: job_ns.DecodeStorage = .{};
        clean_storage.init();
        {
            var clean_reader = postcard.Reader.init(clean_bytes[1..]);
            const clean = try blobs.EofFraming.read(.get, &clean_reader, &clean_storage.inner);
            try t.expectEqual(blobs.RequestType.get, clean.discriminant());
            try t.expectEqualSlices(u8, &ranges_mod.blob_hash, &clean.get.hash);
            try t.expectEqualSlices(
                u64,
                &disjoint_widths,
                clean.get.ranges.items[0].spec.widths,
            );
        }
        {
            var wide: [job_ns.request_room + ranges_mod.payload_length]u8 = undefined;
            @memcpy(wide[0..clean_bytes.len], clean_bytes);
            @memcpy(
                wide[clean_bytes.len..][0..link.store.payload.len],
                link.store.payload,
            );
            const all = clean_bytes.len + link.store.payload.len;
            var reader = postcard.Reader.init(wide[1..all]);
            try t.expectError(
                error.TrailingBytes,
                blobs.EofFraming.read(.get, &reader, &clean_storage.inner),
            );
        }
    }
    // And the *received* frame with its discriminant byte changed, which is
    // what a peer that ignored the byte in front would decode. The length byte
    // the `push` framing put there is now the hash's first byte, so the whole
    // body shifts and the sequence's element count is read out of hash bytes:
    // it names more pairs than any caller's storage holds, and the answer is
    // `BufferFull` — a named refusal and never a request that quietly includes
    // the payload. (`protocol.zig` reports `BadLength` from the same step on
    // its own captured hash; which named error it is depends on the bytes, and
    // that it is an error rather than a request does not.)
    {
        var swapped: [job_ns.request_room + ranges_mod.payload_length]u8 = undefined;
        @memcpy(swapped[0..received_push.len], received_push);
        swapped[0] = @intFromEnum(blobs.RequestType.get);
        var reader = postcard.Reader.init(swapped[1..]);
        try t.expectError(
            error.BufferFull,
            blobs.EofFraming.read(.get, &reader, &push.storage.inner),
        );
    }
    // And a `get` frame is not a `push` frame: with the byte in front changed,
    // the hash's first byte is the declared body length. 0x5a is a one-byte
    // varint for ninety, and the frame has thirty-seven bytes left of it.
    {
        const received_get = job_ns.received(&link.provider_bytes, get.stream);
        var swapped: [job_ns.request_room]u8 = undefined;
        @memcpy(swapped[0..received_get.len], received_get);
        swapped[0] = @intFromEnum(blobs.RequestType.push);
        var reader = postcard.Reader.init(swapped[0..received_get.len]);
        try t.expectError(
            error.UnexpectedEnd,
            blobs.Request.read(&reader, &push.storage.inner),
        );
        // And the framing that carries a `push` refuses a `get` before it
        // reads a byte, as `EofFraming` refuses a `push` above: neither is a
        // value of the other, and `Request.read` is the only reader that gets
        // to choose.
        var get_reader = postcard.Reader.init(received_get[1..]);
        try t.expectError(
            error.WrongFraming,
            blobs.LengthPrefixedFraming.read(.get, &get_reader, &push.storage.inner),
        );
    }
    // Both streams ended with a FIN and no reset, which is what a request that
    // ran to the end of its stream looks like and what a payload that stayed
    // behind the request looks like from the far end.
    try t.expect(link.finished(&link.getter_fin, push.stream));
    try t.expect(link.finished(&link.getter_fin, get.stream));
}

// ---------------------------------------------------------------------------
// Test 4: a short answer is not a complete one
// ---------------------------------------------------------------------------

test "a truncated answer is not a complete transfer, and no answer is EOF" {
    var link: link_ns.Link = undefined;
    try link.init();
    defer link.deinit();

    try drive(&link, "the blobs handshake", handshaken);
    try checkIdentity(&link);

    // A provider that stops part way through the blob and closes, and a
    // provider that has nothing at all. Both are answers the getter has to tell
    // apart from a whole one, and one of them alone proves nothing: an empty
    // answer is the success the other artifact covers, and a short one is the
    // failure this one is for.
    const whole_expected = [_]blobs.ByteRange{.{ .start = 0, .end = link.store.bytes.len }};
    const disjoint_expected = [_]blobs.ByteRange{
        .{ .start = 2 * 1024, .end = 5 * 1024 },
        .{ .start = 9 * 1024, .end = 14 * 1024 },
    };
    link.put(0, .{
        .name = "truncated after 1000 bytes",
        .whole = true,
        .truncate_to = truncated_at,
    });
    link.put(1, .{
        .name = "a provider with nothing",
        .widths = &disjoint_widths,
        .empty = true,
    });
    try link.jobs[0].expect(&whole_expected);
    try link.jobs[1].expect(&disjoint_expected);

    try job_ns.ask(&link, &link.jobs[0]);
    try job_ns.ask(&link, &link.jobs[1]);
    try drive(&link, "a truncation request never arrived whole", allServed);
    try drive(&link, "a truncated answer never finished arriving", allComplete);

    // ── the short answer ──
    const cut = &link.jobs[0];
    const wanted = cut.expected.total();
    const answer = answerOf(&link, cut);
    // It is not EOF: bytes arrived, and `protocol.zig` has no value that could
    // say "this is where the transfer stopped".
    try t.expect(!answer.isEof());
    // The stream ended anyway, and ended cleanly: a FIN and no reset, which is
    // the whole of the evidence the getter has.
    const stream = link.dialled.entry.conn.streams.getStream(cut.stream) orelse
        return error.NoStream;
    try t.expect(stream.recv.allReceived());
    try t.expectEqual(@as(?u64, null), stream.recv.reset_err);
    // The bytes that did arrive are the right ones — the transfer is not
    // corrupt, it is short.
    try t.expectEqual(truncated_at, answer.bytes.len);
    try t.expectEqualSlices(u8, link.store.bytes[0..truncated_at], answer.bytes);
    // And it is not a complete transfer. This is the assertion the file is for:
    // a caller that compared what arrived against what it had read rather than
    // against what it asked for would hand this short buffer back as a whole
    // blob, and nothing in `BaoResponse` stops it.
    try t.expect(wanted > answer.bytes.len);
    try t.expect(!covers(link.store, cut.expected, answer));

    // ── the answer that is EOF ──
    const empty = &link.jobs[1];
    const nothing = answerOf(&link, empty);
    try t.expect(nothing.isEof());
    try t.expectEqual(@as(usize, 0), nothing.bytes.len);
    // EOF is a success only where none of the data existed: the getter's
    // completion test is false for it as well, which is the point — the two
    // answers are the same bytes, and the caller has to know which it asked
    // for.
    try t.expect(!covers(link.store, empty.expected, nothing));
    const empty_stream = link.dialled.entry.conn.streams.getStream(empty.stream) orelse
        return error.NoStream;
    try t.expect(empty_stream.recv.allReceived());
    try t.expectEqual(@as(?u64, null), empty_stream.recv.reset_err);
    // The provider still planned the ranges it was asked for before it found it
    // had nothing to send, so the plan is the answer's evidence and it is a
    // real one rather than an empty stand-in.
    try t.expectEqual(@as(usize, 2), empty.plan.len);
    try t.expectEqual(disjoint_expected[0], empty.plan.ranges[0]);
    try t.expectEqual(disjoint_expected[1], empty.plan.ranges[1]);
}

// ---------------------------------------------------------------------------
// Test 5: the count a caller sees
// ---------------------------------------------------------------------------

test "a stream's received count is the count written, below and above its room" {
    var bytes: std.AutoHashMap(u64, job_ns.StreamBytes) = .init(t.allocator);
    defer {
        job_ns.freeSides(&bytes);
        bytes.deinit();
    }

    const gop = try bytes.getOrPut(1);
    if (!gop.found_existing) gop.value_ptr.* = job_ns.StreamBytes.empty;
    const short = [_]u8{ 1, 2, 3 };
    try gop.value_ptr.push(&short);

    // ── below the room ──
    //
    // Three bytes against a room of more than three whatever the allocator's
    // first stop happened to be, so the count and the room cannot coincide and
    // the line below has teeth: an accessor that handed back the room instead
    // of the count fails exactly here and nowhere else in the file.
    try t.expectEqual(@as(usize, short.len), job_ns.received(&bytes, 1).len);
    try t.expect(gop.value_ptr.room() > gop.value_ptr.slice().len);

    // ── above it ──
    //
    // A quarter of a megabyte behind a room this size, so the queue grew again
    // and again and the count is nothing like the room it started from. Both
    // halves of "well above" are measured: the count clears the room the small
    // answer left, and the room moved because of it.
    const bulk = try t.allocator.alloc(u8, 256 * 1024);
    defer t.allocator.free(bulk);
    for (bulk, 0..) |*byte, index| byte.* = @truncate(index);
    const room_before = gop.value_ptr.room();
    try gop.value_ptr.push(bulk);

    try t.expectEqual(short.len + bulk.len, job_ns.received(&bytes, 1).len);
    try t.expect(job_ns.received(&bytes, 1).len > room_before);
    try t.expect(gop.value_ptr.room() > room_before);

    // The count being right while the bytes are not is the other half of this
    // accessor, so the bytes are checked at both ends: the short answer, which
    // is where a count taken from the room would be visibly wrong, and the
    // bulk that followed it.
    const whole = job_ns.received(&bytes, 1);
    try t.expectEqualSlices(u8, &short, whole[0..short.len]);
    try t.expectEqualSlices(u8, bulk, whole[short.len..]);

    // A stream that never arrived reads as no bytes, and there is no queue to
    // read a room from — which is why `queueOf` answers `?` and `received`
    // answers a slice: the two questions are different and a caller asking for
    // the count of a stream it has never seen should not have to tell them
    // apart.
    try t.expect(job_ns.queueOf(&bytes, 2) == null);
    try t.expectEqual(@as(usize, 0), job_ns.received(&bytes, 2).len);
}

// ---------------------------------------------------------------------------
// The boundary at the segment sizes a loopback connection cannot reach
// ---------------------------------------------------------------------------

/// The most bytes one UDP datagram may carry, and the reason the batch
/// boundary is a ratio and not a count.
///
/// `batch.max_segments_linux` is `UDP_MAX_SEGMENTS`, the `1 << 6` of
/// `include/uapi/linux/udp.h`, and it is not the constraint that binds first:
/// a `sendmsg` whose payload is over what a datagram holds is refused with
/// `EMSGSIZE`, and `batch` has no field for a cap that depends on the segment
/// size. Measured on this node with a `UDP_SEGMENT` control message at
/// 1200-byte segments: 54 segments and 64800 bytes go out, 55 and 66000 are
/// refused. At 1024 it is 63 against 64, and at 1500 it is 43 against 44 —
/// three different counts for one constant, which is what "a ratio" means.
///
/// The ceiling itself is 65535 less the 20-byte IPv4 header and the 8-byte UDP
/// one; over IPv6 it is 65527. A `Runs` walk is handed no address and so no
/// family, and of two ceilings the smaller is the one legal on both, so
/// `batch.max_send_payload` is this number. It is written out here rather than
/// read from there on purpose: a test that quoted the model's own constant
/// would follow it up and not notice it move.
const max_datagram_payload: usize = 65507;

/// The datagram sizes the batcher is asked to cut, and the batch sizes around
/// the crossing.
///
/// The transfer above only ever bursts at one of them: the core's, which on
/// loopback is the base PLPMTU and does not move. A fix that holds at 1200 and
/// nowhere else would pass that transfer and regress silently at the rest, so
/// the sizes a connection cannot be made to produce are asserted here instead.
/// 576 is IPv6's minimum MTU, 1200 is what the core sends on loopback and never
/// moves from, 1024 and 1452 bracket it and 9000 is a jumbo frame. 32767 is not
/// an MTU and is here for one reason: `65535 mod 32767` is 1, so a model clamped
/// at 65535 would put two of them in one write — 65534 bytes — and pass every
/// real size in the list, while one clamped at the datagram ceiling cannot. A
/// boundary that no input can cross is not a boundary.
const segment_sizes = [_]usize{ 576, 1024, 1200, 1452, 9000, 32767 };
const batch_sizes = [_]usize{ 1, 2, 7, 54, 55, 63, 64, 65, 200 };

test "a run is within one datagram, at every segment size" {
    for (segment_sizes) |size| {
        for (batch_sizes) |count| {
            const payload = try t.allocator.alloc(u8, size * count);
            defer t.allocator.free(payload);
            @memset(payload, 0x5a);
            // A batch of one datagram carries no segment size, and the seam's
            // own rule is that it must not acquire one here.
            const send = if (count == 1)
                batch.Send.single(payload, null)
            else
                try batch.Send.batch(payload, size, null);
            var runs = try batch.Runs.init(send, batch.Capability.linux_full);
            const promised = runs.count();
            var taken: usize = 0;
            var rejoined: usize = 0;
            while (runs.next()) |run| {
                taken += 1;
                rejoined += run.contents.len;
                // The property the crossing is about: no write may ask for more
                // bytes than one datagram can carry, whatever the segment cap
                // says.
                try t.expect(run.contents.len <= max_datagram_payload);
                // No run is cut inside a datagram, so the runs put the batch
                // back together.
                try t.expectEqual(@as(usize, 0), run.contents.len % size);
                if (run.segment_size) |value| {
                    // A segmented run is the batcher's own, at this batch's own
                    // size, and it is more than one datagram.
                    try t.expectEqual(@as(usize, @intCast(size)), @as(usize, value));
                    try t.expect(run.contents.len > size);
                } else {
                    // And a run of one datagram carries no segment size, which
                    // is the fallback `DECISIONS/0002` promised.
                    try t.expectEqual(@as(usize, 1), run.datagramCount());
                }
            }
            try t.expectEqual(payload.len, rejoined);
            try t.expectEqual(promised, taken);
            // And the batch is still this many datagrams: no run dropped one
            // and none invented one.
            try t.expectEqual(send.datagramCount(), rejoined / size);
        }
    }

    // The crossing is in the table at every one of those sizes, so a model
    // that cut at the segment cap alone fails here rather than passing because
    // no case in it needed a second write.
    const largest = batch_sizes[batch_sizes.len - 1];
    try t.expect(largest > batch.max_segments_linux);
    for (segment_sizes) |size| {
        const payload = try t.allocator.alloc(u8, size * largest);
        defer t.allocator.free(payload);
        @memset(payload, 0x5a);
        var runs = try batch.Runs.init(
            try batch.Send.batch(payload, size, null),
            batch.Capability.linux_full,
        );
        try t.expect(runs.count() > 1);
    }
}
