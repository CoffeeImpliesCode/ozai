//! The UDP batch seam, and the whole surface re-exported.
//!
//! The whole surface is re-exported here, so every caller outside
//! `src/transport/` keeps importing one name and no caller changes. The
//! declarations live in two modules named for what they are responsible for,
//! and the split is by responsibility rather than by size:
//!
//! - `batch_opt.zig` — what this platform lets a socket do, and the option
//!   numbers that say so.
//! - `batch_run.zig` — what a batch is: the payload, the runs it is cut into,
//!   the buffer that comes back, and what one send carried.
//!
//! `batch_opt.zig` names nothing of `batch_run.zig`, and that is what keeps
//! the dependency one-way: the payload asks the platform how many datagrams
//! one run may hold and never the other way round.
//!
//! # The original module doc, unchanged
//!
// The UDP batch seam: a list of datagrams in, socket writes out.
//
//
// Captured from n0-computer/noq, commit
// 89ed00c31297c2127d1697a7b63983d60fd02ecb, fetched 2026-09-30:
//
// - `noq-udp/src/lib.rs` — `Transmit`, `RecvMeta`, `EcnCodepoint`, and the
//   four `effective_segment_size` vectors the test below copies.
// - `noq-udp/src/unix.rs` — the `UDP_GRO` probe, `prepare_msg`, the receive
//   side's stride default and its `UDP_GRO` control message, and the two
//   reactions to a `sendmsg` that fails.
// - `noq-udp/src/linux.rs` — `max_gso_segments` and `UDP_MAX_SEGMENTS`.
//
// Captured from n0-computer/iroh, commit
// 187f59e80afdae6bd9866002b33d3365c00b06d8 — the pin
// `relay/frame.zig` already uses — `iroh/src/socket/transports/relay/actor.rs:81`,
// `SEND_DATAGRAM_BATCH_SIZE = 20`. That is a WebSocket frame batch and not a
// GSO cap: a relay path is a TCP connection and never segments. The cap
// below is the kernel's, from `linux/udp.h`.
//
// # There is no socket here
//
// A send is a value: bytes, a segment size, and the ancillary data a socket
// would be handed. What the socket refuses comes back as a `Report` and
// nothing else. That is the whole reason the fallback is testable without an
// operating system: a caller learns which path it took by reading a value,
// not by noticing the wire got slower.
//
// # Purity
//
// No clock, no environment, no global, no allocator. The platform's
// capability is an argument, its option numbers are named once under `linux`
// and read from the Zig 0.16 std tree, and every buffer is the caller's. See
// `docs/ARCHITECTURE.md`, "Wire codecs are pure and separate from the
// transport".

const std = @import("std");
const batch_opt = @import("batch_opt.zig");
const batch_run = @import("batch_run.zig");

const std_testing = std.testing;

/// See `batch_run.Ecn`.
pub const Ecn = batch_run.Ecn;
/// See `batch_opt.Error`.
pub const Error = batch_opt.Error;
/// See `batch_opt.max_cmsg`.
pub const max_cmsg = batch_opt.max_cmsg;
/// See `batch_opt.linux`.
pub const linux = batch_opt.linux;
/// See `batch_opt.tos_width`.
pub const tos_width = batch_opt.tos_width;
/// See `batch_opt.max_segments_linux`.
pub const max_segments_linux = batch_opt.max_segments_linux;
/// See `batch_opt.max_send_payload`.
pub const max_send_payload = batch_opt.max_send_payload;
/// See `batch_opt.max_gro_segments_linux`.
pub const max_gro_segments_linux = batch_opt.max_gro_segments_linux;
/// See `batch_opt.Family`.
pub const Family = batch_opt.Family;
/// See `batch_opt.Probe`.
pub const Probe = batch_opt.Probe;
/// See `batch_opt.Capability`.
pub const Capability = batch_opt.Capability;
/// See `batch_opt.capability`.
pub const capability = batch_opt.capability;
/// See `batch_run.Send`.
pub const Send = batch_run.Send;
/// See `batch_run.Runs`.
pub const Runs = batch_run.Runs;
/// See `batch_run.Recv`.
pub const Recv = batch_run.Recv;
/// See `batch_run.Value`.
pub const Value = batch_run.Value;
/// See `batch_run.Cmsg`.
pub const Cmsg = batch_run.Cmsg;
/// See `batch_run.tosBits`.
pub const tosBits = batch_run.tosBits;
/// See `batch_run.cmsg`.
pub const cmsg = batch_run.cmsg;
/// See `batch_opt.SocketOption`.
pub const SocketOption = batch_opt.SocketOption;
/// See `batch_opt.socketOptions`.
pub const socketOptions = batch_opt.socketOptions;
/// See `batch_run.Refused`.
pub const Refused = batch_run.Refused;
/// See `batch_run.Report`.
pub const Report = batch_run.Report;
/// See `batch_run.report`.
pub const report = batch_run.report;

/// `count` datagrams of `size` bytes, each filled with its own index, so that
/// a run cut in the wrong place is visible in the bytes and not only in the
/// lengths.
fn makeBatch(gpa: std.mem.Allocator, count: usize, size: usize) ![]u8 {
    const bytes = try gpa.alloc(u8, count * size);
    for (0..count) |index| {
        @memset(bytes[index * size ..][0..size], @intCast(index % 256));
    }
    return bytes;
}

test "the option numbers are the ones the 0.16 std tree carries" {
    // `lib/std/os/linux.zig`: `UDP.SEGMENT` and `UDP.GRO` are 103 and 104,
    // `IP.TOS` is 1, `IP.RECVTOS` is 13, `IPV6.TCLASS` is 67, `SOL.IP` is 0
    // and `SOL.IPV6` is 41. `SOL.UDP` is the one this module writes down.
    try std_testing.expectEqual(@as(u32, 103), linux.segment);
    try std_testing.expectEqual(@as(u32, 104), linux.gro);
    try std_testing.expectEqual(@as(u32, 1), linux.ipv4_tos);
    try std_testing.expectEqual(@as(u32, 13), linux.ipv4_recvtos);
    try std_testing.expectEqual(@as(u32, 67), linux.ipv6_tclass);
    try std_testing.expectEqual(@as(u32, 66), linux.ipv6_recvtclass);
    try std_testing.expectEqual(@as(u32, 0), linux.ip_level);
    try std_testing.expectEqual(@as(u32, 41), linux.ipv6_level);
    try std_testing.expectEqual(@as(u32, 17), linux.udp_level);
}

test "one datagram is one run that carries no segment size" {
    const datagram = @as([100]u8, @splat(0xaa));
    const send = Send.single(&datagram, null);
    try std_testing.expectEqual(@as(usize, 1), send.datagramCount());
    try std_testing.expect(!send.isSegmented());

    var runs = try Runs.init(send, Capability.linux_full);
    try std_testing.expectEqual(@as(usize, 1), runs.count());
    const run = runs.next() orelse return error.TestUnexpectedResult;
    try std_testing.expectEqual(@as(?u16, null), run.segment_size);
    try std_testing.expectEqualSlices(u8, &datagram, run.contents);
    try std_testing.expectEqual(@as(usize, 1), run.datagramCount());
    try std_testing.expect(runs.next() == null);

    // One datagram, so one control message: there is nothing to segment.
    var out: [max_cmsg]Cmsg = undefined;
    try std_testing.expectEqual(@as(usize, 1), cmsg(send, .v4, &out).len);
}

test "N same-size datagrams are one segmented run" {
    const gpa = std_testing.allocator;
    const bytes = try makeBatch(gpa, 5, 100);
    defer gpa.free(bytes);
    const send = try Send.batch(bytes, 100, null);
    try std_testing.expectEqual(@as(usize, 5), send.datagramCount());
    try std_testing.expect(send.isSegmented());

    var runs = try Runs.init(send, Capability.linux_full);
    try std_testing.expectEqual(@as(usize, 1), runs.count());
    const run = runs.next() orelse return error.TestUnexpectedResult;
    try std_testing.expectEqual(@as(?u16, 100), run.segment_size);
    try std_testing.expectEqualSlices(u8, bytes, run.contents);
    try std_testing.expectEqual(@as(usize, 5), run.datagramCount());
    try std_testing.expect(runs.next() == null);
}

test "a batch whose last datagram is short keeps it short" {
    // Four whole datagrams and seven bytes: the size a QUIC burst's last
    // packet has, and the last datagram of a GSO batch is allowed to be.
    const bytes = @as([407]u8, @splat(0));
    const send = try Send.batch(&bytes, 100, null);
    try std_testing.expectEqual(@as(usize, 5), send.datagramCount());
    try std_testing.expectEqual(@as(usize, 7), send.lastDatagramLen());

    var runs = try Runs.init(send, Capability.linux_full);
    try std_testing.expectEqual(@as(usize, 1), runs.count());
    const run = runs.next() orelse return error.TestUnexpectedResult;
    try std_testing.expectEqual(@as(usize, 407), run.contents.len);
    try std_testing.expectEqual(@as(usize, 5), run.datagramCount());
    try std_testing.expectEqual(@as(usize, 7), run.lastDatagramLen());
}

test "an empty batch is zero datagrams, not one empty one" {
    const send = try Send.batch(&.{}, 100, null);
    try std_testing.expectEqual(@as(usize, 0), send.datagramCount());
    var runs = try Runs.init(send, Capability.linux_full);
    try std_testing.expectEqual(@as(usize, 0), runs.count());
    try std_testing.expect(runs.next() == null);
    // A single datagram of no bytes is one datagram, which is a different
    // value and is what a socket would send as a zero-length payload.
    try std_testing.expectEqual(@as(usize, 1), Send.single(&.{}, null).datagramCount());
}

test "the cap cuts runs and never a datagram" {
    const gpa = std_testing.allocator;
    const bytes = try makeBatch(gpa, 5, 10);
    defer gpa.free(bytes);
    const send = try Send.batch(bytes, 10, .ect0);
    var runs = try Runs.init(send, .{ .max_send_segments = 3, .max_recv_segments = 1 });
    try std_testing.expectEqual(@as(usize, 2), runs.count());

    var joined: [50]u8 = undefined;
    var filled: usize = 0;
    var datagrams: usize = 0;
    while (runs.next()) |run| {
        try std_testing.expectEqual(@as(?u16, 10), run.segment_size);
        @memcpy(joined[filled..][0..run.contents.len], run.contents);
        filled += run.contents.len;
        datagrams += run.datagramCount();
    }
    // The runs are the batch, cut in order and not one byte apart from it.
    try std_testing.expectEqual(bytes.len, filled);
    try std_testing.expectEqualSlices(u8, bytes, joined[0..filled]);
    try std_testing.expectEqual(@as(usize, 5), datagrams);
}

test "a run of one datagram carries no segment size, whatever the batch was" {
    const gpa = std_testing.allocator;
    const bytes = try makeBatch(gpa, 4, 10);
    defer gpa.free(bytes);
    var runs = try Runs.init(try Send.batch(bytes, 10, null), .{
        .max_send_segments = 3,
        .max_recv_segments = 1,
    });
    const first = runs.next() orelse return error.TestUnexpectedResult;
    try std_testing.expectEqual(@as(?u16, 10), first.segment_size);
    try std_testing.expectEqual(@as(usize, 3), first.datagramCount());
    const second = runs.next() orelse return error.TestUnexpectedResult;
    // The remainder is one datagram, so it is a datagram and not a batch of
    // one. This is the send-side half of rule 7.
    try std_testing.expectEqual(@as(?u16, null), second.segment_size);
    try std_testing.expect(!second.isSegmented());
    try std_testing.expectEqual(@as(usize, 1), second.datagramCount());
    try std_testing.expectEqualSlices(u8, bytes[30..40], second.contents);
    try std_testing.expect(runs.next() == null);
}

test "a socket that cannot segment gets one datagram per send" {
    const gpa = std_testing.allocator;
    const bytes = try makeBatch(gpa, 4, 10);
    defer gpa.free(bytes);
    const send = try Send.batch(bytes, 10, .ect0);
    var runs = try Runs.init(send, Capability.none);
    try std_testing.expectEqual(@as(usize, 4), runs.count());

    var seen: usize = 0;
    while (runs.next()) |run| {
        // The fallback, observable: a run of one datagram and no segment size
        // on a value that started as a batch of four.
        try std_testing.expectEqual(@as(?u16, null), run.segment_size);
        try std_testing.expect(!run.isSegmented());
        try std_testing.expectEqual(@as(usize, 1), run.datagramCount());
        try std_testing.expectEqualSlices(u8, bytes[seen * 10 ..][0..10], run.contents);
        // The codepoint is not collateral damage: the fallback is about
        // segmentation and nothing else.
        try std_testing.expectEqual(@as(?Ecn, .ect0), run.ecn);
        seen += 1;
    }
    try std_testing.expectEqual(@as(usize, 4), seen);
}

test "every run agrees with the codec on what a batch is" {
    const gpa = std_testing.allocator;
    var count: usize = 0;
    while (count <= 8) : (count += 1) {
        var cap: u16 = 1;
        while (cap <= 4) : (cap += 1) {
            const bytes = try makeBatch(gpa, count, 10);
            defer gpa.free(bytes);
            const send = try Send.batch(bytes, 10, null);
            var runs = try Runs.init(send, .{
                .max_send_segments = cap,
                .max_recv_segments = 1,
            });
            var seen: usize = 0;
            var datagrams: usize = 0;
            while (runs.next()) |run| {
                seen += 1;
                datagrams += run.datagramCount();
                // Segmented on the wire exactly when the run holds more than
                // one datagram. Never one, never neither.
                try std_testing.expectEqual(run.datagramCount() > 1, run.isSegmented());
                // A run never reaches past the payload it came from, and
                // every datagram in it is whole except the last.
                try std_testing.expect(run.contents.len <= bytes.len);
                try std_testing.expect(run.lastDatagramLen() <= 10);
            }
            try std_testing.expectEqual(runs.count(), seen);
            try std_testing.expectEqual(count, datagrams);
        }
    }
}

test "a run is bounded by both send constraints, at every segment size" {
    // 1200 is the size that made this visible: 64 segments of it are 76800
    // bytes and this node refuses that with `EMSGSIZE`, while 54 of them —
    // 64800 bytes — go out. Each row is one `maxRunDatagrams` answer.
    const rows = [_]struct { size: usize, runs: u16 }{
        .{ .size = 64, .runs = 64 },
        .{ .size = 1023, .runs = 64 },
        .{ .size = 1024, .runs = 63 },
        .{ .size = 1200, .runs = 54 },
        .{ .size = 1452, .runs = 45 },
        .{ .size = 9000, .runs = 7 },
    };
    for (rows) |row| {
        try std_testing.expectEqual(
            row.runs,
            try Capability.linux_full.maxRunDatagrams(row.size),
        );
    }
    // A socket that cannot segment is one datagram whatever the arithmetic
    // says, and the payload ceiling is not a floor it can lift.
    try std_testing.expectEqual(
        @as(u16, 1),
        try Capability.none.maxRunDatagrams(1200),
    );
}

test "the two send constraints swap which one binds at 1024 bytes" {
    // 64 segments of 1023 is 65472 bytes and the wire takes it; 64 segments of
    // 1024 is 65536 and it does not. The crossing is a segment size, and it is
    // why the answer cannot be a `u16` on `Capability`: one value below it and
    // another above it.
    const full = Capability.linux_full;
    try std_testing.expectEqual(@as(u16, 64), try full.maxRunDatagrams(1022));
    try std_testing.expectEqual(@as(u16, 64), try full.maxRunDatagrams(1023));
    try std_testing.expectEqual(@as(u16, 63), try full.maxRunDatagrams(1024));
    try std_testing.expectEqual(@as(u16, 63), try full.maxRunDatagrams(1025));
    // Below the crossing the count is the binding half and the ratio is the
    // larger answer, which is what makes the field the answer there.
    try std_testing.expectEqual(
        full.max_send_segments,
        try full.maxRunDatagrams(1023),
    );
    // Above it the count is not consulted: 1200 admits 54 and 9000 admits 7,
    // where `max_segments_linux` admits 64 for both.
    try std_testing.expect(try full.maxRunDatagrams(1200) < full.max_send_segments);
    try std_testing.expect(try full.maxRunDatagrams(9000) < full.max_send_segments);
}

test "a segment size no datagram may carry is refused, not divided by" {
    // The division is the hazard: `max_send_payload / 0` traps and
    // `max_send_payload / (max_send_payload + 1)` is zero datagrams. Both are
    // declared answers rather than either of those.
    const full = Capability.linux_full;
    try std_testing.expectError(error.ZeroSegmentSize, full.maxRunDatagrams(0));
    try std_testing.expectError(
        error.SegmentSizeTooLarge,
        full.maxRunDatagrams(max_send_payload + 1),
    );
    try std_testing.expectError(
        error.SegmentSizeTooLarge,
        full.maxRunDatagrams(std.math.maxInt(u16)),
    );
    // The widest segment size a datagram may carry admits exactly one, which
    // is where the refusal above is drawn.
    try std_testing.expectEqual(@as(u16, 1), try full.maxRunDatagrams(max_send_payload));
    // A hand-built capability of zero is one datagram, not a division by it.
    const zero: Capability = .{ .max_send_segments = 0, .max_recv_segments = 1 };
    try std_testing.expectEqual(@as(u16, 1), try zero.maxRunDatagrams(1200));

    // And the refusals reach the walk, which is where a caller meets them. A
    // size the `UDP_SEGMENT` control message carries is still a size no run
    // can be built from.
    const bytes = @as([200]u8, @splat(0));
    try std_testing.expectError(
        error.SegmentSizeTooLarge,
        Runs.init(try Send.batch(&bytes, max_send_payload + 1, null), full),
    );
}

test "no run asks a sendmsg for more than one message's worth of bytes" {
    // The invariant the crossing is about, at the sizes a connection cannot be
    // made to produce: whatever the segment count says, a run's bytes fit one
    // message, and the runs put the batch back together byte for byte.
    const gpa = std_testing.allocator;
    const sizes = [_]usize{ 1, 64, 576, 1023, 1024, 1200, 1452, 9000 };
    const counts = [_]usize{ 1, 2, 7, 54, 55, 63, 64, 65, 200 };
    for (sizes) |size| {
        for (counts) |count| {
            const bytes = try gpa.alloc(u8, size * count);
            defer gpa.free(bytes);
            @memset(bytes, 0x5a);
            // A batch of one datagram carries no segment size, and the seam's
            // own rule is that it does not acquire one here.
            const send = if (count == 1)
                Send.single(bytes, null)
            else
                try Send.batch(bytes, size, null);
            var runs = try Runs.init(send, Capability.linux_full);
            const promised = runs.count();
            var taken: usize = 0;
            var rejoined: usize = 0;
            while (runs.next()) |run| {
                taken += 1;
                rejoined += run.contents.len;
                // The property the fix is for, stated over the bytes and not
                // over the count.
                try std_testing.expect(run.contents.len <= max_send_payload);
                // No run is cut inside a datagram.
                try std_testing.expectEqual(@as(usize, 0), run.contents.len % size);
                if (run.segment_size) |value| {
                    // Segmented at this batch's own size, and at more than one
                    // datagram — the send-side half of rule 7.
                    try std_testing.expectEqual(@as(usize, @intCast(value)), size);
                    try std_testing.expect(run.contents.len > size);
                } else {
                    try std_testing.expectEqual(@as(usize, 1), run.datagramCount());
                }
            }
            try std_testing.expectEqual(promised, taken);
            try std_testing.expectEqual(bytes.len, rejoined);
            try std_testing.expectEqual(send.datagramCount(), rejoined / size);
        }
    }
}

test "capability reports unsupported, one side at a time" {
    try std_testing.expect(!Capability.none.supportsSegmentation());
    try std_testing.expect(!Capability.none.supportsCoalescing());
    try std_testing.expect(Capability.linux_full.supportsSegmentation());
    try std_testing.expect(Capability.linux_full.supportsCoalescing());
    try std_testing.expectEqual(max_segments_linux, Capability.linux_full.max_send_segments);
    try std_testing.expectEqual(max_gro_segments_linux, Capability.linux_full.max_recv_segments);

    const send_only = capability(.accepted, .unsupported);
    try std_testing.expect(send_only.supportsSegmentation());
    try std_testing.expect(!send_only.supportsCoalescing());
    const recv_only = capability(.unsupported, .accepted);
    try std_testing.expect(!recv_only.supportsSegmentation());
    try std_testing.expect(recv_only.supportsCoalescing());
    const neither = capability(.unsupported, .unsupported);
    try std_testing.expectEqual(@as(u16, 1), neither.max_send_segments);
    try std_testing.expectEqual(@as(u16, 1), neither.max_recv_segments);

    // A segmentation failure is permanent on the send side and leaves the
    // receive side alone: a driver that cannot segment can still coalesce.
    const degraded = Capability.linux_full.withoutSegmentation();
    try std_testing.expectEqual(@as(u16, 1), degraded.max_send_segments);
    try std_testing.expectEqual(max_gro_segments_linux, degraded.max_recv_segments);
    try std_testing.expect(degraded.supportsCoalescing());
    try std_testing.expect(!degraded.supportsSegmentation());
}

test "a coalesced read of one datagram is the uncoalesced read" {
    const datagram = @as([64]u8, @splat(0x5a));
    const plain = try Recv.init(&datagram, null, .ect1);
    const coalesced = try Recv.init(&datagram, datagram.len, .ect1);
    try std_testing.expectEqual(plain.stride, coalesced.stride);
    try std_testing.expectEqual(plain.datagramCount(), coalesced.datagramCount());
    try std_testing.expectEqual(@as(usize, 1), plain.datagramCount());
    try std_testing.expectEqualSlices(u8, &datagram, plain.datagram(0).?);
    try std_testing.expectEqualSlices(u8, &datagram, coalesced.datagram(0).?);
    try std_testing.expect(coalesced.datagram(1) == null);
    try std_testing.expectEqual(@as(?Ecn, .ect1), coalesced.ecn);
}

test "a coalesced read is a list of datagrams" {
    const gpa = std_testing.allocator;
    const bytes = try makeBatch(gpa, 3, 16);
    defer gpa.free(bytes);
    const recv = try Recv.init(bytes, 16, null);
    try std_testing.expectEqual(@as(usize, 3), recv.datagramCount());
    var index: usize = 0;
    while (recv.datagram(index)) |datagram| {
        try std_testing.expectEqual(@as(usize, 16), datagram.len);
        index += 1;
    }
    try std_testing.expectEqual(@as(usize, 3), index);

    // The last datagram of a coalesced list is short, not absent, and the
    // bytes past it are the end of the buffer.
    const short = try Recv.init(bytes[0..38], 16, null);
    try std_testing.expectEqual(@as(usize, 3), short.datagramCount());
    try std_testing.expectEqual(@as(usize, 6), short.datagram(2).?.len);
    try std_testing.expect(short.datagram(3) == null);
}

test "a datagram index that overflows the byte offset returns null" {
    // This index would wrap to the first datagram in unchecked builds.
    const bytes = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const recv = try Recv.init(&bytes, 4, null);
    const wrapped_index = std.math.maxInt(usize) / recv.stride + 1;
    try std_testing.expect(recv.datagram(wrapped_index) == null);
}

test "a stride that names no datagram, or one past the buffer, is refused" {
    const bytes = @as([8]u8, @splat(0));
    try std_testing.expectError(error.ZeroSegmentSize, Recv.init(&bytes, 0, null));
    try std_testing.expectError(error.ZeroSegmentSize, Recv.init(&.{}, null, null));
    try std_testing.expectError(error.StrideExceedsBuffer, Recv.init(&bytes, 9, null));
    try std_testing.expectError(error.ZeroSegmentSize, Send.batch(&bytes, 0, null));
    try std_testing.expectError(
        error.SegmentSizeTooLarge,
        Send.batch(&bytes, @as(usize, std.math.maxInt(u16)) + 1, null),
    );
    // A hand-built zero is the one shape a constructor cannot reach, and the
    // walk refuses it rather than dividing by it.
    const handbuilt: Send = .{ .ecn = null, .contents = &bytes, .segment_size = 0 };
    try std_testing.expectError(
        error.ZeroSegmentSize,
        Runs.init(handbuilt, Capability.linux_full),
    );
}

test "a codepoint survives from the value to what the seam is handed" {
    const table = [_]struct { ecn: Ecn, bits: u8 }{
        .{ .ecn = .ect1, .bits = 0b01 },
        .{ .ecn = .ect0, .bits = 0b10 },
        .{ .ecn = .ce, .bits = 0b11 },
    };
    for (table) |row| {
        const payload = @as([8]u8, @splat(0));
        const send = Send.single(&payload, row.ecn);
        // The wire carries two bits, and reading them back is the same
        // codepoint: noq's `from_bits` over the low two bits.
        try std_testing.expectEqual(row.bits, tosBits(send));
        try std_testing.expectEqual(row.ecn, Recv.ecnFromBits(tosBits(send)));

        var out: [max_cmsg]Cmsg = undefined;
        const v4 = cmsg(send, .v4, &out);
        try std_testing.expectEqual(@as(usize, 1), v4.len);
        try std_testing.expectEqual(linux.ip_level, v4[0].level);
        try std_testing.expectEqual(linux.ipv4_tos, v4[0].kind);
        try std_testing.expectEqual(row.bits, v4[0].value.bits);
        try std_testing.expectEqual(tos_width, v4[0].value.width());

        const v6 = cmsg(send, .v6, &out);
        try std_testing.expectEqual(linux.ipv6_level, v6[0].level);
        try std_testing.expectEqual(linux.ipv6_tclass, v6[0].kind);
        try std_testing.expectEqual(row.bits, v6[0].value.bits);
    }
}

test "a segmented run writes the segment size as a short" {
    const bytes = @as([200]u8, @splat(0));
    const send = try Send.batch(&bytes, 100, .ce);
    var out: [max_cmsg]Cmsg = undefined;
    const cmsgs = cmsg(send, .v6, &out);
    try std_testing.expectEqual(@as(usize, 2), cmsgs.len);
    try std_testing.expectEqual(linux.ipv6_tclass, cmsgs[0].kind);
    try std_testing.expectEqual(@as(u8, 0b11), cmsgs[0].value.bits);
    try std_testing.expectEqual(linux.udp_level, cmsgs[1].level);
    try std_testing.expectEqual(linux.segment, cmsgs[1].kind);
    try std_testing.expectEqual(@as(u16, 100), cmsgs[1].value.short);
    try std_testing.expectEqual(@as(u32, @sizeOf(u16)), cmsgs[1].value.width());
}

test "a send with no codepoint writes not-ECT rather than nothing" {
    const payload = @as([8]u8, @splat(0));
    const send = Send.single(&payload, null);
    try std_testing.expectEqual(@as(u8, 0b00), tosBits(send));
    try std_testing.expectEqual(@as(?Ecn, null), Recv.ecnFromBits(tosBits(send)));
    var out: [max_cmsg]Cmsg = undefined;
    const cmsgs = cmsg(send, .v4, &out);
    try std_testing.expectEqual(@as(usize, 1), cmsgs.len);
    try std_testing.expectEqual(@as(u8, 0b00), cmsgs[0].value.bits);
}

test "a send that loses its codepoint says so" {
    const payload = @as([8]u8, @splat(0));
    const send = Send.single(&payload, .ce);

    // Nothing refused: the codepoint is carried.
    const clean = report(send, .v4, .none);
    try std_testing.expectEqual(@as(?Ecn, .ce), clean.carried);
    try std_testing.expect(clean.ecnSurvived());
    try std_testing.expect(!clean.degraded);

    // An unknown control message is dropped on IPv4 and the datagram leaves
    // with no codepoint, which only the caller can notice. The wanted
    // codepoint stays in the report, because the peer's report of congestion
    // is about a path this send no longer describes.
    const lost = report(send, .v4, .unknown_control_message);
    try std_testing.expectEqual(@as(?Ecn, .ce), lost.wanted);
    try std_testing.expectEqual(@as(?Ecn, null), lost.carried);
    try std_testing.expect(!lost.ecnSurvived());

    // IPv6's traffic class is a core option, so the same refusal drops
    // nothing: noq leaves the IPv6 tos in place on the retry.
    const kept = report(send, .v6, .unknown_control_message);
    try std_testing.expectEqual(@as(?Ecn, .ce), kept.carried);
    try std_testing.expect(kept.ecnSurvived());

    // A send that asked for nothing has nothing to lose.
    const nothing = report(Send.single(&payload, null), .v4, .unknown_control_message);
    try std_testing.expect(nothing.ecnSurvived());
    try std_testing.expectEqual(@as(?Ecn, null), nothing.carried);
}

test "a refused segmentation degrades a batch and says so" {
    const bytes = @as([30]u8, @splat(0));
    const batch = try Send.batch(&bytes, 10, .ect0);
    const degraded = report(batch, .v4, .segmentation);
    try std_testing.expect(degraded.degraded);
    try std_testing.expectEqual(@as(?Ecn, .ect0), degraded.carried);
    try std_testing.expect(degraded.ecnSurvived());

    // One datagram is one `sendmsg` either way, so there is nothing degraded
    // about it.
    const single = report(Send.single(bytes[0..10], .ect0), .v4, .segmentation);
    try std_testing.expect(!single.degraded);
}

test "noq's own effective_segment_size vectors, captured at 89ed00c" {
    // `noq-udp/src/lib.rs:278-300`, the crate's test for the rule, values
    // copied: ten bytes of payload against a segment size that is larger
    // than, equal to, absent from, and half of the payload.
    const payload = @as([10]u8, @splat(0));
    const cases = [_]struct { segment: ?u16, segmented: bool }{
        .{ .segment = 15, .segmented = false },
        .{ .segment = 10, .segmented = false },
        .{ .segment = null, .segmented = false },
        .{ .segment = 5, .segmented = true },
    };
    for (cases) |case| {
        const send: Send = .{
            .ecn = null,
            .contents = &payload,
            .segment_size = case.segment,
        };
        try std_testing.expectEqual(case.segmented, send.isSegmented());
    }
}

test "a socket has to be asked for the codepoint on both families" {
    try std_testing.expectEqual(Family.v4, Family.of(.{ .v4 = .{ 127, 0, 0, 1 } }));
    try std_testing.expectEqual(Family.v6, Family.of(.{ .v6 = @as([16]u8, @splat(0)) }));
    const v4 = socketOptions(.v4, true);
    try std_testing.expectEqual(linux.ip_level, v4[0].level);
    try std_testing.expectEqual(linux.ipv4_recvtos, v4[0].name);
    const v6 = socketOptions(.v6, true);
    try std_testing.expectEqual(linux.ipv6_level, v6[0].level);
    try std_testing.expectEqual(linux.ipv6_recvtclass, v6[0].name);
    // Both are on: a read that was never asked reports not-ECT for a
    // datagram that may well have carried one.
    try std_testing.expect(v4[0].value);
    try std_testing.expect(v6[0].value);
    // `UDP_GRO` is asked for on both, and asking is not failing: a socket
    // that refuses it has answered, and `capability` is where that goes.
    for ([_]SocketOption{ v4[1], v6[1] }) |option| {
        try std_testing.expectEqual(linux.udp_level, option.level);
        try std_testing.expectEqual(linux.gro, option.name);
        try std_testing.expect(option.value);
    }
    // And a socket that coalesces nothing sets it off rather than omitting
    // it, the way noq sets `UDP_SEGMENT` back to zero after probing.
    try std_testing.expect(!socketOptions(.v4, false)[1].value);
}
