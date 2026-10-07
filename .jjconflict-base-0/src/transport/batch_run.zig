//! What a batch is: the payload going out, the runs one socket write carries
//! it in, the buffer that comes back, and what a send ended up carrying.
//!
//! Split out of `transport/batch.zig`, which is now the facade over this and
//! `batch_opt.zig`. The boundary is the payload rather than the platform: every
//! value below is bytes, a stride or a codepoint, all of them borrowed from the
//! caller, and the only thing asked of the platform is the `Capability` that
//! decides how many datagrams one run may hold.

const std = @import("std");
const frame = @import("../relay/frame.zig");
const opt = @import("batch_opt.zig");

const Error = opt.Error;
const Family = opt.Family;
const Capability = opt.Capability;
const linux = opt.linux;
const max_cmsg = opt.max_cmsg;
const tos_width = opt.tos_width;

/// Explicit congestion notification, as a datagram carries it.
///
/// `noq_udp::EcnCodepoint` (`noq-udp/src/lib.rs:248`), which is
/// `noq_proto::EcnCodepoint` (`shared.rs:180`) spelled a second time. ozai
/// keeps one: the three codepoints are the same three values in both, and a
/// rule written down twice is a rule one table extension away from being
/// wrong in two places. `relay/frame.zig` owns the definition because it got
/// there first; `base` is where it belongs.
pub const Ecn = frame.Ecn;

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

/// One buffer a `recvmsg` filled: one datagram, or a list coalesced into it.
///
/// The mirror image of `Send`, and the hazard is the same one as rule 7's: a
/// buffer holding three datagrams handed to a caller expecting one is a
/// caller that reads a datagram header out of the middle of a packet. So the
/// stride is in the value rather than implied by the buffer, and every read
/// answers `datagramCount` before anything is taken from it.
pub const Recv = struct {
    /// Borrowed views into the receive buffer. Reusing or releasing that
    /// buffer invalidates this value and every returned datagram slice.
    /// The bytes the socket wrote.
    bytes: []const u8,
    /// The size of one datagram in `bytes`. Equal to `bytes.len` unless a
    /// list was coalesced; every datagram but the last is exactly this long
    /// and the last may be shorter.
    stride: usize,
    /// The codepoint the read carried, or null for none. The wire cannot tell
    /// no codepoint from any other value that reduces to zero, so `Ecn` is
    /// the two bits or nothing.
    ecn: ?Ecn,

    /// A read, given the `UDP_GRO` control message that came with it, or null
    /// when no coalescing control message arrived at all.
    ///
    /// noq initialises `RecvMeta::stride` to `len` and overwrites it only
    /// when a `UDP_GRO` control message arrives
    /// (`noq-udp/src/unix.rs:700` and `:781-784`). A null stride and a stride
    /// equal to the buffer's own length are therefore the same value, and a
    /// coalesced read of exactly one datagram is indistinguishable from an
    /// uncoalesced one. That is the property that makes the null arm safe,
    /// and it is what a test pins.
    ///
    /// A zero stride is refused, which also refuses a zero-length read: a
    /// buffer with no datagram in it is not a read this seam models.
    pub fn init(bytes: []const u8, stride: ?usize, ecn: ?Ecn) Error!Recv {
        const size = stride orelse bytes.len;
        if (size == 0) return error.ZeroSegmentSize;
        if (size > bytes.len) return error.StrideExceedsBuffer;
        return .{ .bytes = bytes, .stride = size, .ecn = ecn };
    }

    /// How many datagrams arrived in this one read.
    pub fn datagramCount(self: Recv) usize {
        return divCeil(self.bytes.len, self.stride);
    }

    /// The i-th datagram of the buffer, or null when there is no i-th.
    ///
    /// The last datagram of a coalesced list is short rather than absent, so
    /// this is a slice of the tail and not a truncated one.
    pub fn datagram(self: Recv, index: usize) ?[]const u8 {
        const start = std.math.mul(usize, index, self.stride) catch return null;
        if (start >= self.bytes.len) return null;
        return self.bytes[start..@min(start + self.stride, self.bytes.len)];
    }

    /// The codepoint a read's control message carried, or null when its bits
    /// reduce to zero.
    ///
    /// The wire carries two bits in `IP_TOS` or `IPV6_TCLASS` and zero is
    /// `IP_TOS_NOT_ECT`, so "no codepoint" is a value and not an absence:
    /// a stack that dropped the control message and a stack that read a
    /// not-ECT datagram both land here, which is why `socketOptions` exists.
    pub fn ecnFromBits(bits: u8) ?Ecn {
        return Ecn.fromBits(bits);
    }
};

/// The value a control message carries, in the width the option takes.
pub const Value = union(enum) {
    /// A traffic-class codepoint: the low two bits of `IP_TOS` for IPv4 and
    /// of `IPV6_TCLASS` for IPv6. `tos_width` is the width; the byte value is
    /// the codepoint's own two bits, or zero for not-ECT.
    bits: u8,
    /// A `u16` segment size, as `UDP_SEGMENT` takes it.
    short: u16,

    /// How many bytes the control message's value takes, which is what
    /// `CMSG_LEN` is computed from and therefore part of the message rather
    /// than a detail of it.
    pub fn width(self: Value) u32 {
        return switch (self) {
            .bits => tos_width,
            .short => @sizeOf(u16),
        };
    }
};

/// One control message, as a `sendmsg` writes it.
pub const Cmsg = struct {
    /// The socket level, `SOL_UDP` or `SOL_IP` or `SOL_IPV6`.
    level: u32,
    /// The option name within the level.
    kind: u32,
    /// What it says.
    value: Value,
};

/// The traffic class a send puts in its control message.
///
/// A send with no codepoint still writes the message, with zero. noq pushes
/// `IP_TOS` and `IPV6_TCLASS` on every send
/// (`noq-udp/src/unix.rs:608-622`) so that a codepoint set on the socket once
/// cannot leak onto a send that did not ask for one, and zero is what the
/// wire means by not-ECT. The optional codepoint and the zero it writes are
/// one thing here for the reason they are one thing there.
///
/// A caller reading this back gets the codepoint it started with, or null
/// for a send that carried none.
pub fn tosBits(send: Send) u8 {
    return (send.ecn orelse return 0).toBits();
}

/// The control messages one `sendmsg` carries, in the order a platform
/// encoder writes them, written from `out[0]` and handed back.
///
/// Traffic class first, then the segmentation size: that is noq's
/// `prepare_msg` (`noq-udp/src/unix.rs:608-630`), and the order matters to
/// a fixed-size encoder buffer. There is one message for a single datagram
/// and two for a segmented run, and the return value is the slice of `out`
/// that was used, so nothing here allocates.
///
/// Only the Linux spelling of the level and option names is implemented,
/// because that is where `std.os.linux` has them. A platform that has neither
/// option says so with `Capability.none`, and the answer there is a socket
/// that is handed the same bytes without this.
pub fn cmsg(send: Send, family: Family, out: *[max_cmsg]Cmsg) []const Cmsg {
    out[0] = .{
        .level = if (family == .v4) linux.ip_level else linux.ipv6_level,
        .kind = if (family == .v4) linux.ipv4_tos else linux.ipv6_tclass,
        .value = .{ .bits = tosBits(send) },
    };
    var len: usize = 1;
    if (send.isSegmented()) {
        out[1] = .{
            .level = linux.udp_level,
            .kind = linux.segment,
            // `isSegmented` and this read are one fact: it answers false for
            // a null `segment_size` (`Send.isSegmented` unwraps with `orelse
            // return false` first), so a true answer proves the value set.
            // zwanzig-disable-next-line: optional-unwrap
            .value = .{ .short = send.segment_size.? },
        };
        len = max_cmsg;
    }
    return out[0..len];
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

/// `a / b` rounded up, for a `b` the caller has already established is not
/// zero.
///
/// Written out rather than `std.math.divCeil` so that the precondition is at
/// the call site instead of inside a `catch`. Every `b` here is a receive
/// stride from `Recv.init` or a run bound from `Runs.init`, both of which have
/// already refused zero.
fn divCeil(a: usize, b: usize) usize {
    return a / b + @intFromBool(a % b != 0);
}
