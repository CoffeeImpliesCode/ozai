//! The UDP batch seam: a list of datagrams in, socket writes out.
//!
//! `docs/DECISIONS/0002-async-substrate.md` records the decision this module
//! implements: zio's `std.Io` bridge sends one datagram per `sendmsg`, and a
//! batch of datagrams wants `UDP_SEGMENT`, so the batcher lives here at the
//! transport seam and degrades to one-datagram sends where the platform
//! cannot segment.
//!
//! Captured from n0-computer/noq, commit
//! 89ed00c31297c2127d1697a7b63983d60fd02ecb, fetched 2026-09-30:
//!
//! - `noq-udp/src/lib.rs` — `Transmit`, `RecvMeta`, `EcnCodepoint`, and the
//!   four `effective_segment_size` vectors the test below copies.
//! - `noq-udp/src/unix.rs` — the `UDP_GRO` probe, `prepare_msg`, the receive
//!   side's stride default and its `UDP_GRO` control message, and the two
//!   reactions to a `sendmsg` that fails.
//! - `noq-udp/src/linux.rs` — `max_gso_segments` and `UDP_MAX_SEGMENTS`.
//!
//! Captured from n0-computer/iroh, commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8 — the pin
//! `relay/frame.zig` already uses — `iroh/src/socket/transports/relay/actor.rs:81`,
//! `SEND_DATAGRAM_BATCH_SIZE = 20`. That is a WebSocket frame batch and not a
//! GSO cap: a relay path is a TCP connection and never segments. The cap
//! below is the kernel's, from `linux/udp.h`.
//!
//! # There is no socket here
//!
//! A send is a value: bytes, a segment size, and the ancillary data a socket
//! would be handed. What the socket refuses comes back as a `Report` and
//! nothing else. That is the whole reason the fallback is testable without an
//! operating system: a caller learns which path it took by reading a value,
//! not by noticing the wire got slower.
//!
//! # Purity
//!
//! No clock, no environment, no global, no allocator. The platform's
//! capability is an argument, its option numbers are named once under `linux`
//! and read from the Zig 0.16 std tree, and every buffer is the caller's. See
//! `docs/ARCHITECTURE.md`, "Wire codecs are pure and separate from the
//! transport".

const std = @import("std");
const builtin = @import("builtin");
const frame = @import("../relay/frame.zig");
const addr = @import("../base/addr.zig");

const std_testing = std.testing;

/// Explicit congestion notification, as a datagram carries it.
///
/// `noq_udp::EcnCodepoint` (`noq-udp/src/lib.rs:248`), which is
/// `noq_proto::EcnCodepoint` (`shared.rs:180`) spelled a second time. ozai
/// keeps one: the three codepoints are the same three values in both, and a
/// rule written down twice is a rule one table extension away from being
/// wrong in two places. `relay/frame.zig` owns the definition because it got
/// there first; `base` is where it belongs.
pub const Ecn = frame.Ecn;

/// Every way a batch value can be refused.
///
/// The first name is `relay/frame.zig`'s, for `relay/frame.zig`'s reason: a
/// zero size names no datagram, and the codec refusing one on decode is the
/// same fact as this refusing one on the way to the socket. The second is
/// upstream's bug: noq writes the segment size with `segment_size as u16`
/// (`noq-udp/src/unix.rs:629`), so a segment larger than a `u16` is
/// truncated there and refused here.
pub const Error = error{
    /// A zero segment size or a zero receive stride. Zero names no datagram.
    ZeroSegmentSize,
    /// A segment size the `UDP_SEGMENT` control message cannot carry.
    SegmentSizeTooLarge,
    /// A receive stride larger than the buffer it describes. A datagram
    /// cannot be bigger than the bytes that hold it.
    StrideExceedsBuffer,
};

/// The most datagrams one `sendmsg` may carry as ancillary data: the traffic
/// class and the segmentation size. Not a limit on how many datagrams a run
/// holds — that is `Capability.max_send_segments`.
pub const max_cmsg = 2;

/// The Linux control-message options this seam names.
///
/// Read from the Zig 0.16 std tree rather than written down:
/// `lib/std/os/linux.zig`, `pub const UDP` at line 4192, where `SEGMENT` is
/// 103 and `GRO` is 104. `IP.TOS` and `IPV6.TCLASS` are in the same file.
///
/// No logic in this module branches on any of these numbers. They are named
/// here, once, with the source beside them, so that a search for `103` finds
/// this block and not a literal in the middle of a send. The one number the
/// std tree does not have is `SOL_UDP`: `std.os.linux.SOL` lists only the
/// levels std itself sets, and UDP is not one of them. It is
/// `include/uapi/linux/socket.h`'s `#define SOL_UDP 17`, and noq passes
/// `libc::SOL_UDP` at `noq-udp/src/unix.rs:129` and `:445`.
pub const linux = struct {
    /// `SOL_UDP`, 17. Not in the std tree; see above.
    pub const udp_level: u32 = 17;
    /// `UDP_SEGMENT`: the GSO segment size, carried per `sendmsg`.
    pub const segment: u32 = std.os.linux.UDP.SEGMENT;
    /// `UDP_GRO`: set once to ask the kernel to coalesce, and read back as a
    /// control message to learn a coalesced buffer's stride.
    pub const gro: u32 = std.os.linux.UDP.GRO;
    /// `SOL_IP`, 0.
    pub const ip_level: u32 = std.os.linux.SOL.IP;
    /// `IP_TOS`, where an IPv4 read's codepoint arrives.
    pub const ipv4_tos: u32 = std.os.linux.IP.TOS;
    /// `IP_RECVTOS`: the socket option that asks for it.
    pub const ipv4_recvtos: u32 = std.os.linux.IP.RECVTOS;
    /// `SOL_IPV6`, 41.
    pub const ipv6_level: u32 = std.os.linux.SOL.IPV6;
    /// `IPV6_TCLASS`, where an IPv6 read's codepoint arrives and where a send
    /// puts its own.
    pub const ipv6_tclass: u32 = std.os.linux.IPV6.TCLASS;
    /// `IPV6_RECVTCLASS`: the socket option that asks for it, and the reason
    /// an IPv6 read is no more self-delivering than an IPv4 one.
    pub const ipv6_recvtclass: u32 = std.os.linux.IPV6.RECVTCLASS;
};

/// The width a traffic-class control message's value takes: `c_int` on
/// everything except the two BSDs that declare it `c_uchar`, which is noq's
/// `IpTosTy` (`noq-udp/src/unix.rs:855-858`).
///
/// The width is not a detail. `CMSG_LEN` is computed from it, so a codepoint
/// written in four bytes where the option takes one is a different message,
/// not the same message padded.
pub const tos_width: u32 = switch (builtin.os.tag) {
    .freebsd, .netbsd => 1,
    else => @sizeOf(c_int),
};

/// `UDP_MAX_SEGMENTS` in `include/uapi/linux/udp.h`, `1 << 6`. noq returns
/// exactly this from `max_gso_segments` when `UDP_SEGMENT` is accepted
/// (`noq-udp/src/linux.rs:26-37`).
pub const max_segments_linux: u16 = 64;

/// `UDP_GRO_CNT_MAX` in `net/ipv4/udp_offload.c`, 64, the value noq installs
/// when `UDP_GRO` is accepted (`noq-udp/src/unix.rs:129-138`). It is not an
/// arbitrary cap: the receive buffer has to be big enough for the largest
/// list the kernel might produce, or a coalesced read is truncated.
pub const max_gro_segments_linux: u16 = 64;

/// Which IP version a datagram goes out as, or came back on.
///
/// This is the only thing about a destination this module cares about: it is
/// what decides which control message carries the codepoint. The address
/// belongs to the path, not to the batch.
pub const Family = enum {
    v4,
    v6,

    /// The family an address belongs to, so that no caller has to hand-write
    /// the tag next to an address it just read.
    pub fn of(ip: addr.IpAddress) Family {
        return switch (ip) {
            .v4 => .v4,
            .v6 => .v6,
        };
    }
};

/// What setting a socket option returned.
///
/// `setsockopt` says "no such option here" with `ENOPROTOOPT` or
/// `EOPNOTSUPP` and noq's `set_socket_option_supported` (`noq-udp/src/unix.rs:864`)
/// turns both into `false`. Everything else is an error, and the two answers
/// that matter to a capability are "it took" and "it did not".
pub const Probe = enum {
    accepted,
    unsupported,
};

/// What a socket on this platform can do, as the socket answered.
///
/// noq probes both features once per socket and remembers: `max_gso_segments`
/// is `UDP_SEGMENT` set and unset again (`noq-udp/src/linux.rs:19-46`) and
/// `gro_segments` is `UDP_GRO` set (`noq-udp/src/unix.rs:129-138`). The probe
/// needs a socket, so it is not here. This is the value the probe produces,
/// and it is an argument everywhere below it.
pub const Capability = struct {
    /// `UDP_MAX_SEGMENTS` when the socket accepted `UDP_SEGMENT`, and 1
    /// otherwise. A 1 is not a cap of one segment per send, it is the absence
    /// of the feature: noq's `max_gso_segments` means exactly that, and a
    /// batch on such a socket is sent one datagram at a time.
    max_send_segments: u16,
    /// `UDP_GRO_CNT_MAX` when the socket accepted `UDP_GRO`, and 1
    /// otherwise, for noq's `gro_segments`.
    max_recv_segments: u16,

    /// A platform that neither segments nor coalesces. Every send is one
    /// datagram and every read is one datagram.
    pub const none: Capability = .{
        .max_send_segments = 1,
        .max_recv_segments = 1,
    };

    /// What a Linux socket that accepted both options reports.
    pub const linux_full: Capability = .{
        .max_send_segments = max_segments_linux,
        .max_recv_segments = max_gro_segments_linux,
    };

    /// Whether a send may be segmented. False means every datagram goes out
    /// in its own `sendmsg`, which is a working socket and a slower one.
    pub fn supportsSegmentation(self: Capability) bool {
        return self.max_send_segments > 1;
    }

    /// Whether a read may arrive as a list of datagrams. False means every
    /// read is one datagram, and `Recv.stride` is always its own length.
    pub fn supportsCoalescing(self: Capability) bool {
        return self.max_recv_segments > 1;
    }

    /// The capability after a `sendmsg` failed with `EIO` or `EINVAL`.
    ///
    /// noq sets `max_gso_segments` to 1 and never raises it again
    /// (`noq-udp/src/unix.rs:436-445`). A driver that cannot segment is
    /// found by sending, not by asking, and a socket that raised the cap back
    /// would find out again on the next send. The receive side is untouched:
    /// a driver that cannot segment can still coalesce.
    pub fn withoutSegmentation(self: Capability) Capability {
        return .{
            .max_send_segments = 1,
            .max_recv_segments = self.max_recv_segments,
        };
    }
};

/// The capability of a socket that answered two probes.
///
/// A socket that accepted `UDP_SEGMENT` gets the kernel's maximum and a
/// socket that did not gets one, which is `Capability.none` on that side
/// alone. The two are independent: the kernel can coalesce on a driver that
/// cannot segment, and noq's probe is per option.
pub fn capability(send: Probe, recv: Probe) Capability {
    return .{
        .max_send_segments = if (send == .accepted) max_segments_linux else 1,
        .max_recv_segments = if (recv == .accepted) max_gro_segments_linux else 1,
    };
}

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
    /// One unless a segment size is set, and then one more than the number of
    /// whole segments in it: every `segment_size` bytes but the last datagram
    /// is one datagram, and the last is whatever is left, including nothing.
    pub fn datagramCount(self: Send) usize {
        const size = self.segment_size orelse return 1;
        return divCeil(self.contents.len, @as(usize, size));
    }

    /// The length of the last datagram, which is the segment size for every
    /// datagram but a short one.
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
pub const Runs = struct {
    /// Every datagram in the batch, back to back.
    contents: []const u8,
    /// The size of one datagram, or null when the batch is one datagram.
    segment_size: ?u16,
    /// The codepoint every datagram carries.
    ecn: ?Ecn,
    /// The most datagrams one run may hold, clamped to at least one so that a
    /// hand-built capability of zero cannot divide anything.
    cap: u16,
    /// Datagrams already handed out.
    index: usize,
    /// Datagrams in the batch.
    total: usize,

    /// The runs for `send` on a socket that answers `caps`.
    ///
    /// The refusal is the same zero-segment-size refusal `relay/frame.zig`
    /// makes, for the same reason: this is the value on its way to the socket
    /// and a zero there names no datagram.
    pub fn init(send: Send, caps: Capability) Error!Runs {
        if (send.segment_size) |size| {
            if (size == 0) return error.ZeroSegmentSize;
        }
        const total = send.datagramCount();
        return .{
            .contents = send.contents,
            .segment_size = send.segment_size,
            .ecn = send.ecn,
            .cap = @max(@as(u16, 1), caps.max_send_segments),
            .index = 0,
            .total = total,
        };
    }

    /// The next run, or null when the batch is exhausted.
    ///
    /// Three rules, and the first is the one that corrupts the send path when
    /// it is missed: a run that holds one datagram carries no segment size,
    /// whatever the batch was segmented for. The second is the fallback — a
    /// socket that cannot segment gets one datagram per run, and the caller
    /// can see it because `segment_size` is null on a run that holds more
    /// than one. The third is that no run is ever cut inside a datagram, so
    /// the runs concatenate back to the batch they came from.
    pub fn next(self: *Runs) ?Send {
        if (self.index >= self.total) return null;
        const size = @as(usize, self.segment_size orelse 0);
        // No segment size means one datagram, and it is the whole payload.
        if (size == 0) {
            self.index = self.total;
            return .{
                .ecn = self.ecn,
                .contents = self.contents,
                .segment_size = null,
            };
        }
        const take = @min(self.cap, self.total - self.index);
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
    /// Equal to the number of `next` calls that are not null, and a caller
    /// that wants the count before it starts sending does not have to walk
    /// twice to get it.
    pub fn count(self: Runs) usize {
        if (self.total == 0) return 0;
        return divCeil(self.total, self.cap);
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
        const start = index * self.stride;
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
/// encoder writes them, appended to `out` and handed back.
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
            .value = .{ .short = send.segment_size.? },
        };
        len = max_cmsg;
    }
    return out[0..len];
}

/// One `setsockopt` call, by name and value.
pub const SocketOption = struct {
    /// The socket level: `SOL_IP`, `SOL_IPV6` or `SOL_UDP`.
    level: u32,
    /// The option name within the level.
    name: u32,
    /// On or off. Every option this seam sets is a flag.
    value: bool,
};

/// The options that have to be set for a socket to carry the codepoint back
/// and to coalesce its reads, in the order to set them.
///
/// Returned as values and not applied: a socket is not this module's
/// business, and a transport layer that cannot set socket options is a
/// different problem from this one.
///
/// The first is the one that is easy to miss, on both families: without
/// `IP_RECVTOS` the kernel sends no traffic class with an IPv4 datagram, and
/// without `IPV6_RECVTCLASS` it sends none with an IPv6 one, so every read
/// reports not-ECT — a silently wrong answer rather than a missing one.
/// noq sets the first on every socket (`noq-udp/src/unix.rs:93`) and the
/// second only for a v6 socket (`:173`), and `Recv.ecnFromBits` cannot tell
/// a datagram that was not-ECT from a codepoint that was never delivered.
///
/// `UDP_GRO` is what asks for coalescing, and setting it off is not failing:
/// noq turns `UDP_SEGMENT` back to zero after probing it
/// (`noq-udp/src/linux.rs:30-34`) so that a control message is the only
/// thing that segments. A socket that refuses `UDP_GRO` has answered, and
/// `capability` is where that answer goes.
pub fn socketOptions(family: Family, coalesce: bool) [2]SocketOption {
    return .{
        .{
            .level = if (family == .v4) linux.ip_level else linux.ipv6_level,
            .name = if (family == .v4) linux.ipv4_recvtos else linux.ipv6_recvtclass,
            .value = true,
        },
        .{ .level = linux.udp_level, .name = linux.gro, .value = coalesce },
    };
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
    /// The driver cannot segment. The run goes out one datagram per
    /// `sendmsg` and the socket's capability stops offering segmentation.
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
    /// The codepoint that went on the wire, or null for none.
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
/// stride from `Recv.init` or a run cap from `Runs.init`, both of which have
/// already refused zero.
fn divCeil(a: usize, b: usize) usize {
    return a / b + @intFromBool(a % b != 0);
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
    const datagram = [_]u8{0xaa} ** 100;
    const send = Send.single(&datagram, null);
    try std_testing.expectEqual(@as(usize, 1), send.datagramCount());
    try std_testing.expect(!send.isSegmented());

    var runs = try Runs.init(send, Capability.linux_full);
    try std_testing.expectEqual(@as(usize, 1), runs.count());
    const run = runs.next().?;
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
    const run = runs.next().?;
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
    const run = runs.next().?;
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
    const first = runs.next().?;
    try std_testing.expectEqual(@as(?u16, 10), first.segment_size);
    try std_testing.expectEqual(@as(usize, 3), first.datagramCount());
    const second = runs.next().?;
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
    const datagram = [_]u8{0x5a} ** 64;
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

test "a stride that names no datagram, or one past the buffer, is refused" {
    const bytes = [_]u8{0} ** 8;
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
        const payload = [_]u8{0} ** 8;
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
    const bytes = [_]u8{0} ** 200;
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
    const payload = [_]u8{0} ** 8;
    const send = Send.single(&payload, null);
    try std_testing.expectEqual(@as(u8, 0b00), tosBits(send));
    try std_testing.expectEqual(@as(?Ecn, null), Recv.ecnFromBits(tosBits(send)));
    var out: [max_cmsg]Cmsg = undefined;
    const cmsgs = cmsg(send, .v4, &out);
    try std_testing.expectEqual(@as(usize, 1), cmsgs.len);
    try std_testing.expectEqual(@as(u8, 0b00), cmsgs[0].value.bits);
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

test "a socket has to be asked for the codepoint on both families" {
    try std_testing.expectEqual(Family.v4, Family.of(.{ .v4 = .{ 127, 0, 0, 1 } }));
    try std_testing.expectEqual(Family.v6, Family.of(.{ .v6 = [_]u8{0} ** 16 }));
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
