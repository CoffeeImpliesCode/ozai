//! What this platform lets a socket do, and the option numbers that say so:
//! the families, the Linux control-message options, the capability a probe
//! produces, and the refusals those numbers define.
//!
//! Split out of `transport/batch.zig`, which is now the facade over this and
//! `batch_run.zig`. The boundary is the platform rather than the payload: every
//! declaration below is a fact about the kernel or about `std.os.linux`, and
//! none of them is about a datagram. `Error` is here because two of its three
//! names are — a segment size is refused against `UDP_SEGMENT`'s width and
//! against `max_send_payload`, both declared in this file — and it is what
//! keeps the dependency one-way: the other module names this one and this one
//! names nothing of the other's.

const std = @import("std");
const builtin = @import("builtin");
const addr = @import("../base/addr.zig");

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
    /// A segment size the `UDP_SEGMENT` control message cannot carry, or one
    /// wider than a single datagram may be (`max_send_payload`). Either way no
    /// run can be built out of it.
    SegmentSizeTooLarge,
    /// A receive stride larger than the buffer it describes. A datagram
    /// cannot be bigger than the bytes that hold it.
    StrideExceedsBuffer,
};

/// The most datagrams one `sendmsg` may carry as ancillary data: the traffic
/// class and the segmentation size. Not a limit on how many datagrams a run
/// holds — that is `Capability.maxRunDatagrams`, which reads two constraints
/// rather than one.
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
    // A number, not a type: the initializer is a value and `u32` its type.
    // zwanzig-disable-next-line: identifier-style
    pub const segment: u32 = std.os.linux.UDP.SEGMENT;
    /// `UDP_GRO`: set once to ask the kernel to coalesce, and read back as a
    /// control message to learn a coalesced buffer's stride.
    // A number, not a type: the initializer is a value and `u32` its type.
    // zwanzig-disable-next-line: identifier-style
    pub const gro: u32 = std.os.linux.UDP.GRO;
    /// `SOL_IP`, 0.
    // A number, not a type: the initializer is a value and `u32` its type.
    // zwanzig-disable-next-line: identifier-style
    pub const ip_level: u32 = std.os.linux.SOL.IP;
    /// `IP_TOS`, where an IPv4 read's codepoint arrives.
    // A number, not a type: the initializer is a value and `u32` its type.
    // zwanzig-disable-next-line: identifier-style
    pub const ipv4_tos: u32 = std.os.linux.IP.TOS;
    /// `IP_RECVTOS`: the socket option that asks for it.
    // A number, not a type: the initializer is a value and `u32` its type.
    // zwanzig-disable-next-line: identifier-style
    pub const ipv4_recvtos: u32 = std.os.linux.IP.RECVTOS;
    /// `SOL_IPV6`, 41.
    // A number, not a type: the initializer is a value and `u32` its type.
    // zwanzig-disable-next-line: identifier-style
    pub const ipv6_level: u32 = std.os.linux.SOL.IPV6;
    /// `IPV6_TCLASS`, where an IPv6 read's codepoint arrives and where a send
    /// puts its own.
    // A number, not a type: the initializer is a value and `u32` its type.
    // zwanzig-disable-next-line: identifier-style
    pub const ipv6_tclass: u32 = std.os.linux.IPV6.TCLASS;
    /// `IPV6_RECVTCLASS`: the socket option that asks for it, and the reason
    /// an IPv6 read is no more self-delivering than an IPv4 one.
    // A number, not a type: the initializer is a value and `u32` its type.
    // zwanzig-disable-next-line: identifier-style
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
///
/// A count, and not the whole answer: the other half binds first. At 1200
/// bytes a segment this allows 64 datagrams where `max_send_payload` allows
/// 54, so a run built from this number alone is a run the kernel answers with
/// `EMSGSIZE`. Measured on this node, 64 segments of 1200 — 76800 bytes — is
/// refused and 54 of them is not.
///
/// Nor is it enforced on this kernel's send path, where 136 segments of 60
/// bytes went out. It is kept because it is noq's answer, not because a probe
/// on this node would have returned it.
pub const max_segments_linux: u16 = 64;

/// The most payload bytes one `sendmsg` may carry, and the second of the two
/// constraints on a run.
///
/// Not `0xffff`. The headers the kernel adds are part of the message by the
/// time it becomes an IP packet, and it is that packet's own 16-bit total
/// length field which has to fit, so the ceiling is `0xffff` less an IP header
/// and the 8-byte UDP one. Measured on this node over loopback with a
/// `UDP_SEGMENT` control message: a run of 64 segments at 1026 bytes is
/// accepted at 65507 total and refused with `EMSGSIZE` at 65508, and the same
/// run over IPv6 is accepted at 65527 and refused at 65528. Those are 65535
/// less 20 and 8, and less 40 and 8.
///
/// IPv4's is the one written down because a `Runs` walk is handed no address
/// and so no family, and of two ceilings the smaller is the one legal on both.
pub const max_send_payload: usize = 65507;

/// `UDP_GRO_CNT_MAX` in `net/ipv4/udp_offload.c`, 64, the value noq installs
/// when `UDP_GRO` is accepted (`noq-udp/src/unix.rs:129-138`). It is not an
/// arbitrary cap: the receive buffer has to be big enough for the largest
/// list the kernel might produce, or a coalesced read is truncated.
///
/// The send side's second constraint is arithmetic and lives in
/// `Capability.maxRunDatagrams`. This one has no second constraint because no
/// walk cuts a read: `Recv` is a buffer that arrived whole, and `Recv.init` is
/// where a stride the buffer cannot hold is refused. A caller that coalesces
/// sizes its own buffer for `max_recv_segments * stride`.
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
    ///
    /// The socket's half of the answer, and not all of it. One `sendmsg` is
    /// also refused above `max_send_payload` bytes, which is the binding half
    /// at every segment size over 1023, so what fits in a run is
    /// `maxRunDatagrams` and never this number alone.
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

    /// The most datagrams one `sendmsg` may carry at `segment_size`, and what
    /// `Runs` cuts its runs at.
    ///
    /// Both constraints meet here and neither of them is a field on this
    /// struct: the count is `max_send_segments`, and the other is
    /// `max_send_payload / segment_size`, a ratio no probe produces and one
    /// that depends on a segment size the probe never saw. Writing down the
    /// count alone is the bug this exists for — `Socket.send` cannot fall
    /// back from the `EMSGSIZE` an over-long run earns, only from a refused
    /// segmentation — so a cap is never read off one of the two alone.
    ///
    /// A zero segment size is refused rather than divided by, and a segment
    /// size above `max_send_payload` is refused rather than divided into zero
    /// datagrams: `UDP_SEGMENT` carries a `u16`, so every size that reaches
    /// here is one a datagram could carry and every answer is at least one.
    pub fn maxRunDatagrams(self: Capability, segment_size: usize) Error!u16 {
        if (segment_size == 0) return error.ZeroSegmentSize;
        if (segment_size > max_send_payload) return error.SegmentSizeTooLarge;
        const by_payload: usize = max_send_payload / segment_size;
        const by_count: usize = @max(1, @as(usize, self.max_send_segments));
        return @intCast(@min(by_count, by_payload));
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
