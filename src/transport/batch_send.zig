//! The send half of the batch seam: a payload going out, the runs one
//! `sendmsg` each can carry, the control messages that go with them, and what
//! a refused run costs.
//!
//! Five things live here and nothing else:
//!
//!   * `Send` — bytes, a segment size, and a codepoint, which is one type for
//!     one datagram and for a whole batch alike,
//!   * `Runs` — the cursor that cuts a batch at the capability of the socket
//!     it is going to,
//!   * `Cmsg`, `Value`, `cmsg` and `tosBits` — the traffic class and the
//!     segmentation size as the kernel's control messages. They are here and
//!     not in a module of their own because a control message is only
//!     meaningful beside the `Send` it goes out with,
//!   * `Refused` and `Report` — what a `sendmsg` refused and what the caller
//!     therefore lost, which is the one fact downstream cannot recover,
//!   * the send-side bounds and refusals they are enforced by.
//!
//! Nothing here touches a descriptor, a clock, an allocator or the network:
//! every buffer is the caller's and the capability is an argument.

const std = @import("std");

const batch = @import("batch.zig");

const Capability = batch.Capability;
/// The payload ceiling a run is measured against, from `batch_platform.zig`.
const max_send_payload = batch.max_send_payload;
/// The segment count a probe reports, from `batch_platform.zig`.
const max_segments_linux = batch.max_segments_linux;
const Ecn = batch.Ecn;
const Error = batch.Error;
const Family = batch.Family;
/// The option numbers, from `batch_platform.zig`. A control message is a
/// level and an option, and those are named there rather than here.
const linux = batch.linux;
const tos_width = batch.tos_width;
const divCeil = batch.divCeil;

const std_testing = std.testing;

/// The most datagrams one `sendmsg` may carry as ancillary data: the traffic
/// class and the segmentation size. Not a limit on how many datagrams a run
/// holds — that is `Capability.maxRunDatagrams`, which reads two constraints
/// rather than one.
pub const max_cmsg = 2;

/// A payload going out, and everything about it that is not in the payload.
///
/// This is one type for a whole batch and for one run of it, because that is
/// what upstream does: a `Transmit` (`noq-udp/src/lib.rs:148-160`) is one
/// call, and a caller with more datagrams than the socket will take cuts the
/// value up and calls again. The two halves are told apart by
/// `datagramCount`, never by the type.
///
/// `segment_size` is the size of one datagram and is null for exactly one
/// datagram, whatever its length. It is upstream's rule, and it is the same
/// fact as `relay/frame.zig`'s "`segment_size.is_some()` ⇔ batch frame type":
/// the two halves of rule 7 in `docs/ARCHITECTURE.md` are one fact, and a
/// value that violated it would be handed to a socket as a `UDP_SEGMENT`
/// control message naming a single datagram.
///
/// Payload bytes are borrowed. Keep them alive and unchanged through the send
/// or iterator that uses them. Copies do not copy the payload.
pub const Send = struct {
    /// The codepoint every datagram in this payload carries, or null for
    /// none.
    ecn: ?Ecn,
    /// Every datagram, back to back. When a segment size is set, all but the
    /// last are exactly that long and the last may be shorter. When it is
    /// null this is one datagram, possibly of length zero.
    contents: []const u8,
    /// The size of one datagram, or null when `contents` is one datagram.
    ///
    /// Never zero when it is set: `batch` and `Runs.init` both refuse a zero,
    /// so a `u16` of zero here can only come from a hand-built value and
    /// names no datagram.
    segment_size: ?u16,

    /// One datagram. A `Send` with no segment size is a single datagram and
    /// not a batch of one, which is the whole of rule 7 on the send side.
    pub fn single(datagram: []const u8, ecn: ?Ecn) Send {
        return .{ .ecn = ecn, .contents = datagram, .segment_size = null };
    }

    /// Several datagrams back to back.
    ///
    /// `contents.len` need not be a multiple of `segment_size`: the last
    /// datagram may be shorter, which is what the kernel does with a GSO
    /// batch and what a QUIC stack does with the last packet of a burst.
    pub fn batch(contents: []const u8, segment_size: usize, ecn: ?Ecn) Error!Send {
        if (segment_size == 0) return error.ZeroSegmentSize;
        if (segment_size > std.math.maxInt(u16)) return error.SegmentSizeTooLarge;
        return .{
            .ecn = ecn,
            .contents = contents,
            .segment_size = @intCast(segment_size),
        };
    }

    /// How many datagrams this payload holds.
    ///
    /// An unsegmented payload is one datagram, including an empty payload.
    /// A segmented payload has `ceil(contents.len / segment_size)` datagrams;
    /// a short tail counts once and an empty segmented payload counts zero.
    pub fn datagramCount(self: Send) usize {
        const size = self.segment_size orelse return 1;
        return divCeil(self.contents.len, @as(usize, size));
    }

    /// The length of the last datagram. For an empty segmented payload there
    /// is no last datagram; this reports the configured segment size.
    pub fn lastDatagramLen(self: Send) usize {
        const size = self.segment_size orelse return self.contents.len;
        const rest = self.contents.len % @as(usize, size);
        return if (rest == 0) size else rest;
    }

    /// Whether the socket is to be given a `UDP_SEGMENT` control message.
    ///
    /// Upstream `Transmit::effective_segment_size`
    /// (`noq-udp/src/lib.rs:175-180`): a segment size at or above the payload
    /// means there is effectively one segment. Some drivers reject a `sendmsg`
    /// that is told to segment a single segment, and a segment size larger
    /// than the payload is common, because a prepared batch gets split again
    /// after GSO is turned off and the last datagram of a GSO batch may be
    /// shorter than its segment size.
    ///
    /// False is the fallback, and it is a value rather than a branch inside
    /// the send: the payload is then a single datagram and goes out as one
    /// `sendmsg` with no segmentation control message.
    pub fn isSegmented(self: Send) bool {
        const size = self.segment_size orelse return false;
        return @as(usize, size) < self.contents.len;
    }
};

/// A contiguous payload and the runs a socket write each can carry.
///
/// The cursor is here, in the caller's stack frame, because upstream's is a
/// `&mut` on the value being drained (`relay/frame.zig`'s `takeSegments`,
/// noq's `max_gso_segments` loop) and a batcher that has to be driven twice
/// with different capabilities cannot keep the cursor in a global.
///
/// The cursor owns no bytes. Returned runs borrow the original payload, which
/// must remain alive and unchanged until all runs have been sent.
pub const Runs = struct {
    /// Every datagram in the batch, back to back.
    contents: []const u8,
    /// The size of one datagram, or null when the batch is one datagram.
    segment_size: ?u16,
    /// The codepoint every datagram carries.
    ecn: ?Ecn,
    /// The most datagrams one run may hold: `Capability.maxRunDatagrams` at
    /// this batch's segment size, and never below one.
    max_datagrams: u16,
    /// Datagrams already handed out.
    index: usize,
    /// Datagrams in the batch.
    total: usize,

    /// The runs for `send` on a socket that answers `caps`.
    ///
    /// The bound is decided here rather than where the segment count is read,
    /// because it is a ratio and not a number. A run of `n` datagrams is
    /// `n * segment_size` bytes on the wire, and one `sendmsg` above
    /// `max_send_payload` bytes is refused with `EMSGSIZE` — which
    /// `Socket.send` treats as fatal rather than as the `.segmentation`
    /// fallback, so a batch this seam calls legal has to be legal on the wire
    /// and not only in the count.
    ///
    /// The zero-segment-size refusal is the same one `relay/frame.zig` makes,
    /// for the same reason: this is the value on its way to the socket and a
    /// zero there names no datagram. `maxRunDatagrams` makes it too, and the
    /// check below is what catches a hand-built value naming no segment.
    pub fn init(send: Send, caps: Capability) Error!Runs {
        if (send.segment_size) |size| {
            if (size == 0) return error.ZeroSegmentSize;
        }
        const total = send.datagramCount();
        // No segment size is one datagram, and `next` hands the payload back
        // whole without consulting the bound.
        const max_datagrams = if (send.segment_size) |size|
            try caps.maxRunDatagrams(size)
        else
            1;
        return .{
            .contents = send.contents,
            .segment_size = send.segment_size,
            .ecn = send.ecn,
            .max_datagrams = max_datagrams,
            .index = 0,
            .total = total,
        };
    }

    /// The next run, or null when the batch is exhausted.
    ///
    /// A one-datagram run carries no segment size, including the fallback on
    /// a socket without segmentation. Multi-datagram runs retain the size.
    /// Runs never split a datagram and concatenate to the original payload.
    pub fn next(self: *Runs) ?Send {
        if (self.index >= self.total) return null;
        const size: usize = self.segment_size orelse 0;
        // No segment size means one datagram, and it is the whole payload.
        if (size == 0) {
            self.index = self.total;
            return .{
                .ecn = self.ecn,
                .contents = self.contents,
                .segment_size = null,
            };
        }
        const take = @min(self.max_datagrams, self.total - self.index);
        const start = self.index * size;
        const end = @min(@min(self.index + take, self.total) * size, self.contents.len);
        self.index += take;
        return .{
            .ecn = self.ecn,
            .contents = self.contents[start..end],
            .segment_size = if (take > 1) self.segment_size else null,
        };
    }

    /// How many socket writes this batch takes, without walking it.
    ///
    /// The total run count for the original batch, not the remaining count.
    /// Advancing the cursor does not change this result.
    pub fn count(self: Runs) usize {
        if (self.total == 0) return 0;
        return divCeil(self.total, self.max_datagrams);
    }
};

/// What a control message carries: a traffic class or a segment size.
///
/// A union and not one integer because the two are different ABIs, and a
/// message is a different message rather than the same one written wider:
/// `UDP_SEGMENT` copies two bytes (`udp_cmsg_send`) and `IP_TOS` reads an
/// `int` (`ip_cmsg_send`). `width` is what decides how many bytes go on the
/// wire, so it is asked of the value rather than passed beside it.
pub const Value = union(enum) {
    /// A traffic class: two bits, of which zero is not-ECT rather than no
    /// codepoint. See `tosBits`, which is where that zero comes from.
    bits: u8,
    /// A segment size, in the `u16` `UDP_SEGMENT` names it.
    short: u16,

    /// The bytes this value takes in a control message.
    pub fn width(self: Value) usize {
        return switch (self) {
            .bits => tos_width,
            .short => @sizeOf(u16),
        };
    }
};

/// One control message, as a `sendmsg` writes it.
///
/// The kernel's own header — `cmsg_level` and `cmsg_type` — and this seam's
/// idea of what the message is worth. It carries no length: that is
/// `ancillary.zig`'s to compute from `Value.width`, because it is a function
/// of the layout of the buffer rather than of what goes in it.
pub const Cmsg = struct {
    /// `cmsg_level`: the protocol this message belongs to.
    level: u32,
    /// `cmsg_type`: the option inside that protocol.
    kind: u32,
    /// What it carries.
    value: Value,
};

/// The byte a traffic-class control message carries for `ecn`.
///
/// Zero is `IP_TOS_NOT_ECT`, so "no codepoint" is a value and not an absence,
/// which is `Recv.ecnFromBits` read from the other end of the same fact. A
/// send with none writes zero rather than nothing: a socket with a codepoint
/// set on it would otherwise leak it onto datagrams this seam sent without
/// one.
pub fn tosBits(ecn: ?Ecn) u8 {
    return if (ecn) |set| set.toBits() else 0;
}

/// The control messages one `sendmsg` carrying `send` over `family` writes,
/// into the caller's `out`.
///
/// The order is fixed — the traffic class first, then the segment size — and
/// the number is one or two. The traffic class is there on every run whatever
/// the batch was cut into; the segment size only on a run that is segmented,
/// because a `sendmsg` told to segment one segment is a message some drivers
/// answer with `EINVAL`, and `Send.isSegmented` is the rule that says so.
///
/// `out` must hold `max_cmsg`; nothing here allocates and nothing is copied
/// out of `send`.
pub fn cmsg(send: Send, family: Family, out: []Cmsg) []const Cmsg {
    std.debug.assert(out.len >= max_cmsg);
    // The two arms are anonymous structs, and an inferred switch result type
    // makes them two distinct types the compiler then refuses to reconcile.
    // Naming `Cmsg` is what makes them one type.
    const class: Cmsg = switch (family) {
        .v4 => .{ .level = linux.ip_level, .kind = linux.ipv4_tos, .value = .{ .bits = 0 } },
        .v6 => .{ .level = linux.ipv6_level, .kind = linux.ipv6_tclass, .value = .{ .bits = 0 } },
    };
    out[0] = .{
        .level = class.level,
        .kind = class.kind,
        .value = .{ .bits = tosBits(send.ecn) },
    };
    if (!send.isSegmented()) return out[0..1];
    out[1] = .{
        .level = linux.udp_level,
        .kind = linux.segment,
        .value = .{ .short = send.segment_size.? },
    };
    return out[0..2];
}

/// What a `sendmsg` refused to carry.
///
/// noq's `send` (`noq-udp/src/unix.rs:419-466`) sees `EIO` or `EINVAL` and
/// reacts twice, and the two reactions are not the same kind of thing: one
/// is permanent state on the capability and the other is per-send.
pub const Refused = enum {
    /// Nothing. The send carried everything.
    none,
    /// The kernel does not know the IPv4 `IP_TOS` control message. Only that
    /// one is dropped and the send is retried, because `IPV6_TCLASS` and
    /// `UDP_SEGMENT` are core options and an unknown-control-message
    /// `EINVAL` is about the newest one — noq guards only the IPv4 tos
    /// (`unix.rs:613-618`) and leaves the other two in place.
    unknown_control_message,
    /// The socket will not segment what it was asked to segment. The run goes
    /// out one datagram per `sendmsg` and the socket's capability stops
    /// offering segmentation.
    ///
    /// Which is not only a driver that cannot segment. A socket can accept
    /// `UDP_SEGMENT` at the probe and refuse the send: measured on this node, a
    /// segment size that is a multiple of 256 is refused with `EINVAL` at
    /// every count from one to 128, through `sendmsg` and through the raw
    /// syscall alike, and 1024 is one of them. No probe reaches that, so this
    /// answer and `Capability.withoutSegmentation` are the whole of the
    /// reaction to it.
    segmentation,
};

/// What one send carried, and what it did not.
///
/// A codepoint that does not survive is the one fact here that cannot be
/// recovered downstream: the datagram leaves, it is the peer's path that will
/// report congestion, and a stack that cannot see the loss reports it to a
/// path it did not use. noq's retry drops the control message and says
/// nothing to the caller; that silence is what this value replaces.
pub const Report = struct {
    /// The codepoint the caller asked for, or null for none.
    wanted: ?Ecn,
    /// The codepoint every datagram went on the wire with, or null when at
    /// least one of them went without it. A batch is many datagrams and a
    /// caller reading this cannot tell which lost it, so one loss is reported
    /// as the loss of all — which is what `ecnSurvived` answers and what the
    /// caller acts on.
    carried: ?Ecn,
    /// Whether the run went out as more than one `sendmsg`, which is what a
    /// socket that cannot segment does with a batch.
    degraded: bool,

    /// Whether the codepoint survived the send. True for a send that asked
    /// for none, because there was nothing to lose.
    pub fn ecnSurvived(self: Report) bool {
        return self.wanted == null or self.wanted == self.carried;
    }
};

/// The report for one send.
///
/// A refused segmentation is a report about a run: a single datagram is
/// never degraded, because one datagram is one `sendmsg` either way. A
/// refused control message is a report about the codepoint and only ever on
/// IPv4, for the reason `Refused.unknown_control_message` gives.
pub fn report(send: Send, family: Family, refused: Refused) Report {
    const carried: ?Ecn = switch (refused) {
        .none, .segmentation => send.ecn,
        .unknown_control_message => if (family == .v4) null else send.ecn,
    };
    return .{
        .wanted = send.ecn,
        .carried = carried,
        .degraded = refused == .segmentation and send.datagramCount() > 1,
    };
}

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

test "one datagram is one run that carries no segment size" {
    const datagram = [_]u8{0xaa} ** 100;
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
    const bytes = [_]u8{0} ** 407;
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
    const bytes = [_]u8{0} ** 200;
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

test "a send that loses its codepoint says so" {
    const payload = [_]u8{0} ** 8;
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
    const bytes = [_]u8{0} ** 30;
    const batched = try Send.batch(&bytes, 10, .ect0);
    const degraded = report(batched, .v4, .segmentation);
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
    const payload = [_]u8{0} ** 10;
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

test "domain sweep: every Family and Refused pair answers a Report" {
    // Two families times three refusals is the whole of `report`, and each cell
    // says something different: an unknown control message drops the codepoint
    // on IPv4 and nothing on IPv6, and a refused segmentation degrades only a
    // batch. Swept over `std.enums.values` so neither enum can grow an arm
    // without this failing to compile.
    const payload = [_]u8{0x5a} ** 20;
    const shapes = [_]struct { send: Send, degraded: bool }{
        // One datagram: a refusal to segment has nothing to degrade.
        .{ .send = Send.single(&payload, .ce), .degraded = false },
        // Two: the run goes out one `sendmsg` each and the report says so.
        .{ .send = try Send.batch(&payload, 10, .ce), .degraded = true },
    };

    inline for (std.enums.values(Family)) |family| {
        for (shapes) |shape| {
            // Nothing refused: the run went out as handed over and the
            // codepoint is the one the caller asked for.
            const clean = report(shape.send, family, .none);
            try std_testing.expectEqual(shape.send.ecn, clean.carried);
            try std_testing.expect(clean.ecnSurvived());
            try std_testing.expect(!clean.degraded);

            // An unknown control message: dropped on IPv4, kept on IPv6. Only
            // the IPv4 answer loses anything, which is why `Refused`'s own
            // comment says noq guards only the IPv4 tos.
            const unknown = report(shape.send, family, .unknown_control_message);
            try std_testing.expectEqual(shape.send.ecn, unknown.wanted);
            try std_testing.expectEqual(
                if (family == .v4) @as(?Ecn, null) else shape.send.ecn,
                unknown.carried,
            );
            try std_testing.expectEqual(family == .v6, unknown.ecnSurvived());
            try std_testing.expect(!unknown.degraded);

            // A refused segmentation is a fact about the run, not about the
            // codepoint: it degrades a batch of more than one datagram and
            // leaves a single datagram alone, because one is one `sendmsg`
            // either way.
            const segmented = report(shape.send, family, .segmentation);
            try std_testing.expectEqual(shape.degraded, segmented.degraded);
            try std_testing.expectEqual(shape.send.ecn, segmented.carried);
            try std_testing.expect(segmented.ecnSurvived());

            // Every cell agrees that what the caller wanted is what the report
            // says was asked for, on every arm and both families.
            try std_testing.expectEqual(shape.send.ecn, clean.wanted);
            try std_testing.expectEqual(shape.send.ecn, segmented.wanted);
        }
    }
}

test "every segmented run's bytes fit one sendmsg, at every capability" {
    // The property both send constraints exist for, swept over the capabilities
    // a probe can produce rather than over the two named ones: whatever the
    // count says, a run's bytes are one message's worth, and the runs put the
    // batch back together byte for byte. A capability that could raise the
    // count without lowering the payload ratio would break this, and the walk
    // would hand a socket a run `EMSGSIZE`s.
    const alloc = std_testing.allocator;
    const sizes = [_]usize{ 1, 64, 576, 1023, 1024, 1200, 1452, 9000 };
    const counts = [_]usize{ 1, 2, 7, 54, 55, 63, 64, 65, 200 };
    const caps = [_]Capability{
        Capability.none,
        Capability.linux_full,
        .{ .max_send_segments = 3, .max_recv_segments = 1 },
        .{ .max_send_segments = max_segments_linux + 1, .max_recv_segments = 1 },
    };
    for (caps) |caps_value| {
        for (sizes) |size| {
            for (counts) |count| {
                const bytes = try alloc.alloc(u8, size * count);
                defer alloc.free(bytes);
                @memset(bytes, 0x5a);
                const send = if (count == 1)
                    Send.single(bytes, null)
                else
                    try Send.batch(bytes, size, null);
                var runs = try Runs.init(send, caps_value);
                const promised = runs.count();
                var taken: usize = 0;
                var rejoined: usize = 0;
                while (runs.next()) |run| {
                    taken += 1;
                    rejoined += run.contents.len;
                    try std_testing.expect(run.contents.len <= max_send_payload);
                    // No run is cut inside a datagram, and a run that carries a
                    // segment size carries more than one datagram.
                    try std_testing.expectEqual(@as(usize, 0), run.contents.len % size);
                    if (run.segment_size) |value| {
                        try std_testing.expectEqual(@as(usize, @intCast(value)), size);
                        try std_testing.expect(run.contents.len > size);
                    } else {
                        try std_testing.expectEqual(@as(usize, 1), run.datagramCount());
                    }
                }
                try std_testing.expectEqual(promised, taken);
                try std_testing.expectEqual(bytes.len, rejoined);
                // And the count the bound produced is the smaller of the two
                // constraints, which is what stops it ever being read off one.
                if (count > 1) {
                    try std_testing.expectEqual(
                        try caps_value.maxRunDatagrams(size),
                        runs.max_datagrams,
                    );
                }
            }
        }
    }
}
