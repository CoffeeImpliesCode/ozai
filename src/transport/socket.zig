//! The UDP socket underneath `transport/batch.zig`: a `Send` in, datagrams out.
//!
//! `batch.zig` is the specification — what a socket write may be handed, what
//! it may refuse, and which of those refusals is permanent. This file is the
//! only place under `src/` that turns those values into syscalls, and it was
//! left thin on purpose until the batcher above it had decided what a batch is.
//!
//! # Why `std.c` and not `std.Io.net`
//!
//! `docs/DECISIONS/0002-async-substrate.md` names both gaps in the stock
//! surface, and this file is the answer to them:
//!
//! 1. **Control messages.** `std.Io.net` has `OutgoingMessage.control` and
//!    `IncomingMessage.control` in the type, and `Io.Threaded` lowers a
//!    receive to one `recvmsg` with that buffer. Its send path goes through
//!    `netSend`, which folds `errno` into a dozen named answers, and a socket
//!    that cannot tell `EMSGSIZE` from `EAGAIN` has backpressure it invented.
//!    `std.posix` has no `sendmsg` at all. `std.c` has both, and the errno is
//!    the caller's to read.
//! 2. **Socket options.** `BindOptions` carries `ip6_only` and
//!    `allow_broadcast` and nothing else, and `SO_REUSEPORT` only counts when
//!    it is set *before* the bind. A socket created through `netBindIp` cannot
//!    be given one, so the descriptor is created here and no `Io` ever learns
//!    it.
//!
//! # Where `io` is, and where it is not
//!
//! `DECISIONS/0002`: "`rt.io()` is never stored. It is a parameter to the
//! functions that need it." So `Socket` holds a descriptor and no `Io`, and
//! every operation that can be cancelled takes one. What the runtime is asked
//! for is cancellation and nothing else — `Io.Threaded.checkCancel` is an
//! atomic load — because a descriptor this module opened is a descriptor no
//! `Io` backend can poll, and handing it to one would be a claim that only
//! holds for `Threaded`. The wait before a receive is a `poll` on the
//! descriptor for the same reason, and a task cancelled inside the `recvmsg`
//! is not seen until that call returns.
//!
//! # Linux, and only Linux
//!
//! `batch.zig` names its option numbers out of `std.os.linux` and says a
//! platform without them answers `Capability.none`. The same is true here:
//! `SOL_UDP` has no `std` spelling at all and the whole control-message path
//! below is written against the Linux `cmsghdr`. This is ozai's socket, not
//! the vendored core's — `test/vendored_invariants.zig` guards `vendor/`,
//! where neither a socket nor a libc is allowed.
//!
//! # `link_libc`, and what does not cover this file
//!
//! `socket`, `bind`, `getsockname`, `setsockopt`, `sendmsg`, `recvmsg` and
//! `close` are libc's here, so an artifact that calls any of them needs
//! `linkLibC()`. Nothing above them is: the layout work is arithmetic on
//! bytes, which is why every test here reaches libc's code without leaving a
//! syscall behind. The one that names `setsockopt` proves a refusal, and the
//! refusal comes before the call.
//!
//! The other half of that was a gate that did not exist. Zig analyses a
//! function body when it is called, not when it is referenced, so
//! `std.testing.refAllDecls` checks the *signatures* here and none of the
//! bodies below — `create`, `send`, `recvmsg`, the probes. The whole syscall
//! layer went uncompiled until `test/integration_test.zig` opened a socket on
//! loopback, and `build.zig` puts `link_libc` on the module that runs it, so
//! removing either half turns into a link error rather than a silent hole.

const std = @import("std");
const builtin = @import("builtin");
const batch = @import("batch.zig");
const base_addr = @import("../base/addr.zig");

const posix = std.posix;
const c = std.c;
const linux = std.os.linux;

/// `batch.linux`, under the name this file uses for it. The option numbers
/// are named once — in `batch.zig`, with the std line beside each — so that a
/// search for `103` finds that block and not a literal in the middle of a
/// send. Everything else below is named out of `std.os.linux` directly.
const names = batch.linux;

const socklen_t = c.socklen_t;

/// The host's byte order, which is the order a control message's value is in:
/// the kernel copies the bytes rather than converting them, so `UDP_SEGMENT`
/// is read as a native `u16` and a traffic class as whatever width it
/// arrived at. See `trafficClass` for why those two are not the same width.
const endian = builtin.cpu.arch.endian();

/// How many times one syscall is retried after a signal before the call is
/// declared interrupted. A signal is not a fact about a datagram and retrying
/// is the only correct answer; the bound is what stops a storm of them from
/// becoming a hang.
pub const max_syscall_attempts = 4;

// ────────────────────────────────────────────────────── control-message layout

/// `CMSG_ALIGN`: a length rounded up to the alignment of a control-message
/// header. The 0.16 std tree carries no `CMSG_*` macro — a search for
/// `CMSG_LEN` across `lib/std` finds nothing — so the three arithmetic facts
/// are here once and every message below is written and read through them.
pub fn cmsgAlign(length: usize) usize {
    return std.mem.alignForward(usize, length, @alignOf(c.cmsghdr));
}

/// `CMSG_LEN`: the aligned header plus the value, and nothing else. The
/// length a message reports about itself, and the length the kernel checks
/// a value against — a message that reports the padded length instead is a
/// message whose value is two bytes wider than the one that was written.
pub fn cmsgLen(width: usize) usize {
    return cmsgAlign(@sizeOf(c.cmsghdr)) + width;
}

/// `CMSG_SPACE`: `cmsgLen` rounded up, which is what a buffer must hold for
/// this message to be followed by another one.
pub fn cmsgSpace(width: usize) usize {
    return cmsgAlign(cmsgLen(width));
}

/// Bytes of ancillary data one message of this seam needs: a traffic class and
/// a stride or a segment size, and nothing else. It is the size of both the
/// send and the receive buffer, and the receive side fits because a codepoint
/// arrives a byte wide and a `u16` still occupies a whole padded message.
pub const control_size: usize = cmsgSpace(batch.tos_width) + cmsgSpace(@sizeOf(u16));

/// The bytes a `sendmsg` writes its control messages into, and the bytes a
/// `recvmsg` reads them back out of.
///
/// One traffic-class message and one `UDP_GRO` message is every message a
/// socket asked for: `IP_PKTINFO` and `SO_TIMESTAMP` are not set, so the
/// kernel has no other reason to send one. The struct carries its own
/// alignment, because the kernel reads these headers at the alignment a
/// `cmsghdr` has and a bare `[]u8` does not promise it.
pub const ControlBuffer = extern struct {
    bytes: [control_size]u8 align(@alignOf(c.cmsghdr)),
};

/// Why a set of control messages would not fit.
pub const ControlError = error{
    /// The buffer cannot hold what it was handed. A control message that
    /// stops halfway is a different message, not a shorter one: the kernel
    /// reads `cmsg_len` bytes whatever the buffer holds.
    BufferTooSmall,
    /// A header field the ABI's own type cannot hold: a length past what
    /// `socklen_t` spells, or a level or an option past what an `int`
    /// spells. The truncated field would be a header pointing at bytes that
    /// are not there, so it is refused instead of written.
    FieldTooWide,
};

/// Write `messages` into `out` in the order given, and hand back the part of
/// it that was used.
///
/// The order is `batch.cmsg`'s — traffic class, then segment size — and it is
/// the caller's list that fixes it: the seam above decides what a send
/// carries and this function only lays it out.
pub fn writeCmsg(messages: []const batch.Cmsg, out: *ControlBuffer) ControlError![]const u8 {
    var used: usize = 0;
    for (messages) |message| {
        const width: usize = message.value.width();
        const space = cmsgSpace(width);
        if (used + space > out.bytes.len) return error.BufferTooSmall;
        const at = out.bytes[used..];
        try putHeader(at, .{
            .length = cmsgLen(width),
            .level = message.level,
            .kind = message.kind,
        });
        putValue(at, message.value);
        used += space;
    }
    return out.bytes[0..used];
}

/// What one blob of received control data said, in the model's vocabulary.
pub const CmsgRead = struct {
    /// The `UDP_GRO` stride, or null when no such message arrived. A read
    /// with no stride is uncoalesced, and a coalesced read of exactly one
    /// datagram carries the buffer's own length — the same value, which is
    /// what `batch.Recv.init` treats as the same read.
    stride: ?usize,
    /// The codepoint the traffic class carried, or null for a datagram that
    /// carried none. Zero is not-ECT and not a missing message, which is why
    /// this is a value and not the absence of one.
    ecn: ?batch.Ecn,
    /// Whether the blob ended inside a message. This is the one way a
    /// coalesced read can arrive looking uncoalesced, and a caller that cannot
    /// tell has a buffer it must not read as one datagram.
    truncated: bool,
};

/// Read the `UDP_GRO` stride and the traffic class out of a received blob and
/// ignore every other message in it.
///
/// A message this seam did not ask for is skipped rather than ended on: a
/// socket may carry options that add messages, and stopping at the first one
/// nobody recognises would lose the stride that came after it.
pub fn readCmsg(blob: []const u8) CmsgRead {
    var read: CmsgRead = .{ .stride = null, .ecn = null, .truncated = false };
    const value_at = cmsgAlign(@sizeOf(c.cmsghdr));
    var at: usize = 0;
    while (at < blob.len) {
        const rest = blob[at..];
        if (rest.len < @sizeOf(c.cmsghdr)) {
            read.truncated = rest.len != 0;
            break;
        }
        const length: usize = getHeader(rest, "len");
        if (length < @sizeOf(c.cmsghdr) or length > rest.len) {
            read.truncated = true;
            break;
        }
        takeValue(rest, value_at, length, &read);
        at += cmsgAlign(length);
    }
    return read;
}

const Header = struct {
    length: usize,
    level: u32,
    kind: u32,
};

// A header is read and written as bytes, never through a `*cmsghdr`. The
// buffer a caller supplies is a `[]u8` and carries no alignment, so a pointer
// to a header inside it would be a claim the type cannot make; the offsets come
// from the struct itself, which is what makes the ABIs that spell `cmsg_len` as
// a `socklen_t` work without a second spelling of any of this.

fn putHeader(at: []u8, header: Header) ControlError!void {
    // Three narrowings, none of them proved anywhere above: a `cmsghdr`
    // spells its length in `socklen_t` and its level and type in an `int`,
    // and a bare `@intCast` panics in Debug on the value that does not fit
    // rather than writing a defined one. Each is narrowed here, where the
    // bound is, and a header the ABI cannot spell is refused rather than
    // written with a field that describes something else.
    const len_type = @FieldType(c.cmsghdr, "len");
    const length = std.math.cast(len_type, header.length) orelse return error.FieldTooWide;
    const level = std.math.cast(c_int, header.level) orelse return error.FieldTooWide;
    const kind = std.math.cast(c_int, header.kind) orelse return error.FieldTooWide;
    const len_at = @offsetOf(c.cmsghdr, "len");
    switch (@sizeOf(len_type)) {
        4 => std.mem.writeInt(u32, at[len_at..][0..4], length, endian),
        8 => std.mem.writeInt(usize, at[len_at..][0..8], length, endian),
        else => @compileError("a cmsghdr length field is four or eight bytes"),
    }
    const word = @sizeOf(c_int);
    const level_at = @offsetOf(c.cmsghdr, "level");
    const kind_at = @offsetOf(c.cmsghdr, "type");
    std.mem.writeInt(c_int, at[level_at..][0..word], level, endian);
    std.mem.writeInt(c_int, at[kind_at..][0..word], kind, endian);
}

fn getHeader(at: []const u8, comptime field: []const u8) u32 {
    const offset = @offsetOf(c.cmsghdr, field);
    return switch (@sizeOf(@FieldType(c.cmsghdr, field))) {
        4 => std.mem.readInt(u32, at[offset..][0..4], endian),
        8 => @as(u32, @truncate(std.mem.readInt(u64, at[offset..][0..8], endian))),
        else => @compileError("a cmsghdr field is four or eight bytes"),
    };
}

fn putValue(at: []u8, value: batch.Value) void {
    const start = cmsgAlign(@sizeOf(c.cmsghdr));
    switch (value) {
        .bits => |bits| {
            const word = @sizeOf(c_int);
            std.mem.writeInt(c_int, at[start..][0..word], @intCast(bits), endian);
        },
        .short => |short| {
            std.mem.writeInt(u16, at[start..][0..@sizeOf(u16)], short, endian);
        },
    }
}

fn takeValue(header: []const u8, value_at: usize, length: usize, read: *CmsgRead) void {
    const value = header[value_at..length];
    const level = getHeader(header, "level");
    const kind = getHeader(header, "type");
    if (level == names.udp_level and kind == names.gro) {
        // `UDP_GRO` carries a `u16`, which is what `CMSG_LEN` was computed
        // from on the way in; a wider value is a different message.
        if (value.len < @sizeOf(u16)) return;
        read.stride = std.mem.readInt(u16, value[0..@sizeOf(u16)], endian);
        return;
    }
    const carries_class = (level == names.ip_level and kind == names.ipv4_tos) or
        (level == names.ipv6_level and kind == names.ipv6_tclass);
    if (!carries_class) return;
    read.ecn = trafficClass(value);
}

/// The codepoint a traffic-class message carried, or null for a value that
/// carries no byte at all.
///
/// The width here is not `batch.tos_width`, and the difference is the whole
/// reason this function exists. `batch.tos_width` is the width the *option*
/// takes, and it is what a send writes: `ip_cmsg_send` reads
/// `*(int *)CMSG_DATA(cmsg)`, so four bytes on Linux and one on the two BSDs
/// that declare the option a `c_uchar`. A *read* is a different ABI: Linux's
/// `ip_cmsg_put` writes `cmsg_len = CMSG_LEN(sizeof(u8))` and one byte, while
/// the BSDs write one byte too. So on Linux the message that arrives is two
/// bytes shorter than the message that left, and a reader that insists on
/// `tos_width` reads every IPv4 datagram as not-ECT and says nothing.
///
/// Both spellings put the two bits in the low byte on every ABI this builds
/// for, so the value is read at the width the message actually arrived at.
fn trafficClass(value: []const u8) ?batch.Ecn {
    if (value.len == 0) return null;
    if (value.len < @sizeOf(c_int)) return batch.Recv.ecnFromBits(value[0]);
    // The wire carries two bits and the rest of the word is other people's
    // traffic. `batch.Recv.ecnFromBits` masks; zero is not-ECT, not nothing.
    const word = @sizeOf(c_int);
    const raw = std.mem.readInt(c_int, value[0..word], endian);
    return batch.Recv.ecnFromBits(@truncate(@as(u32, @bitCast(raw))));
}

// ───────────────────────────────────────────────────────────── address layout

/// Write `address` into `out` in the kernel's own layout and say how many
/// bytes of `out` are the address.
///
/// The port goes out in network order. The IPv4 address does not get the
/// same treatment, and the reason is worth writing down: `s_addr` is a word
/// whose four bytes *are* the address in wire order, so a bit cast is the
/// conversion and a byte swap would reverse the octets. Everything else
/// about an address belongs to the path and not to the socket.
pub fn writeSockaddr(address: base_addr.SocketAddr, out: *c.sockaddr.storage) socklen_t {
    switch (address.ip) {
        .v4 => |octets| {
            const target: *c.sockaddr.in = @ptrCast(@alignCast(out));
            target.* = .{
                .family = linux.AF.INET,
                .port = std.mem.nativeToBig(u16, address.port),
                .addr = @bitCast(octets),
            };
            return @sizeOf(c.sockaddr.in);
        },
        .v6 => |octets| {
            const target: *c.sockaddr.in6 = @ptrCast(@alignCast(out));
            target.* = .{
                .family = linux.AF.INET6,
                .port = std.mem.nativeToBig(u16, address.port),
                .flowinfo = 0,
                .addr = octets,
                .scope_id = 0,
            };
            return @sizeOf(c.sockaddr.in6);
        },
    }
}

/// Read a name the kernel filled, or null when it is not an address this
/// module speaks — an `AF_UNIX` peer, which a UDP socket can still be handed
/// by a caller that used the wrong type.
pub fn readSockaddr(raw: *const c.sockaddr.storage) ?base_addr.SocketAddr {
    const name: *const c.sockaddr = @ptrCast(@alignCast(raw));
    return switch (name.family) {
        linux.AF.INET => v4: {
            const peer: *const c.sockaddr.in = @ptrCast(@alignCast(raw));
            break :v4 base_addr.SocketAddr{
                .ip = .{ .v4 = @bitCast(peer.addr) },
                .port = std.mem.bigToNative(u16, peer.port),
            };
        },
        linux.AF.INET6 => v6: {
            const peer: *const c.sockaddr.in6 = @ptrCast(@alignCast(raw));
            break :v6 base_addr.SocketAddr{
                .ip = .{ .v6 = peer.addr },
                .port = std.mem.bigToNative(u16, peer.port),
            };
        },
        else => null,
    };
}

// ───────────────────────────────────────────────────────────────── error sets

/// Why a `setsockopt` was refused. `Unsupported` is the whole of a capability
/// probe and nothing else: the option is not here, which for `UDP_SEGMENT` and
/// `UDP_GRO` is an answer and for anything else is a problem.
pub const OptionError = error{
    /// `EINVAL`: the kernel would not take the value.
    InvalidValue,
    /// `ENOPROTOOPT` or `EOPNOTSUPP`: no such option at this level.
    Unsupported,
    /// `ENOBUFS` or `ENOMEM`.
    ResourcesExhausted,
    /// `EACCES` or `EPERM`.
    PermissionDenied,
    /// `EBADF`, `ENOTSOCK`, or an errno this list does not name.
    Unexpected,
};

/// Why a socket could not be opened.
pub const OpenError = error{
    /// `EACCES` or `EPERM`: a capability bit or a sandbox, not the address.
    PermissionDenied,
    /// `EAFNOSUPPORT`: this kernel has no IPv4 or no IPv6.
    AddressFamilyUnsupported,
    /// `EPROTONOSUPPORT`: UDP is not a protocol this kernel has.
    ProtocolUnsupported,
    /// `ESOCKTNOSUPPORT`: no datagram socket.
    SocketModeUnsupported,
    /// `EINVAL`: a flag or an option value the kernel would not take, which
    /// for a socket call is this module writing something wrongly.
    InvalidArgument,
    /// `EMFILE` or `ENFILE`: the process or the system is out of descriptors.
    DescriptorQuotaExceeded,
    /// `ENOBUFS` or `ENOMEM`.
    ResourcesExhausted,
    /// `EADDRINUSE`: the port is taken, and no reuse option was asked for.
    AddressInUse,
    /// `EADDRNOTAVAIL`: the address is not one of this host's.
    AddressNotAvailable,
    /// A congestion option this socket cannot be given. There is no fallback
    /// for it: a socket that was never asked for the codepoint reports every
    /// read as not-ECT, which is a silently wrong answer rather than a
    /// missing one.
    CongestionOptionUnsupported,
    /// A reuse option this platform does not have.
    OptionUnsupported,
    /// `EBADF`, `ENOTSOCK`, `ENOSPC`, or anything else.
    Unexpected,
};

/// Why a send did not go out.
///
/// `WouldBlock` and `MessageTooLarge` are the two that must never share a
/// name: the first is backpressure, which the caller waits out or absorbs, and
/// the second is a datagram this path will never carry, which retrying turns
/// into a stall. Collapsing them is how a congestion signal becomes a hung
/// socket. `ControlError` is in the set because a set names every way a call
/// can fail and not only the ones that are convenient; `batch.cmsg` builds at
/// most two messages out of the model's own constants and `ControlBuffer`
/// holds exactly two, so a caller cannot reach either of `ControlError`'s two
/// members through `Socket.send`.
pub const SendError = batch.Error || ControlError || error{
    /// The task was cancelled before the datagram left. A socket that sends
    /// after its caller has given up is a socket nobody is waiting for.
    Canceled,
    /// `EAGAIN`: the socket's send queue is full and nothing left the host.
    WouldBlock,
    /// `EMSGSIZE`: the payload is larger than the path carries.
    MessageTooLarge,
    /// `ENETUNREACH`: no route to the network.
    NetworkUnreachable,
    /// `EHOSTUNREACH`: no route to that host.
    HostUnreachable,
    /// `ENETDOWN`: the interface that would carry it is down.
    NetworkDown,
    /// `ECONNREFUSED`: a previous send drew an ICMP port unreachable and the
    /// kernel held it back for exactly this call.
    PortUnreachable,
    /// `EADDRNOTAVAIL`: the destination is not one this host may send to.
    AddressNotAvailable,
    /// `EACCES` or `EPERM`.
    PermissionDenied,
    /// `ENOBUFS` or `ENOMEM`: the kernel could not build the datagram.
    ResourcesExhausted,
    /// `EDESTADDRREQ` or `ENOTCONN`.
    SocketUnusable,
    /// `EIO` or `EINVAL` on a run carrying no control message this module is
    /// willing to drop, and on a family whose traffic class is a core option.
    /// The kernel refused a send there without saying which half it disliked,
    /// and guessing would be worse than saying so.
    UnknownControlMessage,
    /// The kernel took fewer bytes than the payload held. UDP has no such
    /// answer, so this is the kernel disagreeing about where the datagram
    /// ends, and the caller has to know that it did.
    PartialDatagram,
    /// `EINTR` on every attempt in the budget.
    Interrupted,
    /// Anything else.
    Unexpected,
};

/// Why a receive did not produce a datagram.
pub const ReceiveError = error{
    /// The task was cancelled before the datagram was taken.
    Canceled,
    /// `EAGAIN`: the queue was empty. From `tryReceive` that is the answer to
    /// the question that was asked; from `receive` it means another task took
    /// the datagram between the wait and the read.
    WouldBlock,
    /// `MSG_TRUNC`: the buffer was smaller than the datagram, so the bytes in
    /// it are a prefix and not the datagram.
    MessageTooLarge,
    /// An error a previous send drew, reported on the next read.
    PortUnreachable,
    NetworkUnreachable,
    HostUnreachable,
    NetworkDown,
    /// `ENOBUFS` or `ENOMEM`.
    ResourcesExhausted,
    /// `MSG_CTRUNC`, or a blob that ended inside a message: the control data
    /// did not fit, so a coalesced read cannot be told from an uncoalesced
    /// one and the buffer is not safe to read. The datagram is here and must
    /// not be taken as one.
    ControlTruncated,
    /// `EINTR` on every attempt in the budget.
    Interrupted,
    /// `ENOTCONN`, `EDESTADDRREQ`, `EBADF`, `ENOTSOCK`, or anything else.
    Unexpected,
};

// ────────────────────────────────────────────────────────────────────── socket

/// What to set on a socket before the bind.
pub const Options = struct {
    /// `SO_REUSEADDR`, for a rebind inside the reuse window. On by default
    /// because an endpoint that comes back on the port it held is the case it
    /// exists for, and it costs nothing when nothing else is bound there.
    reuse_addr: bool = true,
    /// `SO_REUSEPORT`, for a v4 and a v6 socket sharing one port. Off by
    /// default: it lets a second descriptor take the same address and port
    /// and a share of the datagrams, which is a decision to make on purpose.
    reuse_port: bool = false,
};

/// One datagram, or a list coalesced into one buffer.
pub const Received = struct {
    /// The bytes the kernel wrote.
    bytes: []const u8,
    /// Who sent them.
    from: base_addr.SocketAddr,
    /// The `UDP_GRO` stride, or null when the read was not coalesced.
    stride: ?usize,
    /// The codepoint the datagram carried, or null for none.
    ecn: ?batch.Ecn,

    /// The read as `batch.Recv` wants it, which is where a stride is checked
    /// against the buffer it claims to describe.
    pub fn toRecv(self: Received) batch.Error!batch.Recv {
        return batch.Recv.init(self.bytes, self.stride, self.ecn);
    }
};

/// A bound UDP socket that speaks `batch`.
///
/// No `Io` is stored, for the reason `DECISIONS/0002` gives. No buffer is
/// either: the receive buffer and the control buffer are the caller's, which
/// is what lets a stack pool them and what lets a test hand over a stack array.
pub const Socket = struct {
    /// The descriptor. `O_NONBLOCK` from the moment it exists, which is what
    /// makes `EAGAIN` a fact a caller can act on instead of a stall.
    handle: c.fd_t,
    /// Which control message carries the codepoint here.
    family: batch.Family,
    /// What the socket answered when it was asked, and the only field that
    /// changes afterwards. A driver that cannot segment is found by sending,
    /// and the cap is never raised again.
    caps: batch.Capability,
    /// Where it is bound, with the ephemeral port the kernel chose written in.
    address: base_addr.SocketAddr,

    /// Open a socket on `address`, set the options, ask what it can do, and
    /// bind.
    ///
    /// The probe runs here and only here. A `Capability` that is guessed
    /// rather than asked is worse than none, because a driver that quietly
    /// ignores `UDP_SEGMENT` turns every batch into a stalled path and
    /// nothing reports it.
    pub fn create(address: base_addr.SocketAddr, options: Options) OpenError!Socket {
        const family: batch.Family = batch.Family.of(address.ip);
        const handle = try createSocket(family);
        errdefer _ = c.close(handle);
        // Reuse options first and the congestion option after, because both
        // take effect before the bind: the port is not the socket's until
        // `bind` answers.
        if (options.reuse_addr) {
            setFlag(handle, linux.SOL.SOCKET, linux.SO.REUSEADDR, true) catch |err| {
                return openFromOption(err);
            };
        }
        if (options.reuse_port) {
            setFlag(handle, linux.SOL.SOCKET, linux.SO.REUSEPORT, true) catch |err| {
                return openFromOption(err);
            };
        }
        const caps = try probe(handle, family);
        var name: c.sockaddr.storage = undefined;
        const length = writeSockaddr(address, &name);
        try bindSocket(handle, &name, length);
        return .{
            .handle = handle,
            .family = family,
            .caps = caps,
            .address = try boundAddress(handle),
        };
    }

    /// Close the descriptor. Nothing is buffered on this side: a send that
    /// returned has left the socket, and a read that returned has been taken.
    pub fn close(self: *Socket) void {
        _ = c.close(self.handle);
    }

    // A method's receiver is its first parameter, so `io` comes second on
    // the three operations that need the runtime.
    // `docs/DECISIONS/0002-async-substrate.md` wants the runtime threaded
    // rather than stored and does not say which position it takes, and every
    // other method on every other type in this project puts its receiver
    // first.

    /// Send `payload` to `dest` and say what it carried.
    ///
    /// One `sendmsg` per `batch.Runs` run, the segmentation control message
    /// on exactly the runs that are segmented, and the traffic class on every
    /// one — the model's own order, from `batch.cmsg`. A run of one datagram
    /// carries no segment size whatever the batch was, which is the fallback
    /// `DECISIONS/0002` promised and which `Report.degraded` makes visible
    /// instead of silent.
    pub fn send(
        self: *Socket,
        io: std.Io,
        dest: base_addr.SocketAddr,
        payload: batch.Send,
    ) SendError!batch.Report {
        try io.checkCancel();
        var refused = try self.sendBatch(io, dest, payload);
        if (refused == .segmentation) {
            // Found by sending, not by asking, and permanent: noq lowers the
            // cap and never raises it (`noq-udp/src/unix.rs:436-445`),
            // because a driver that could segment on the next send would
            // fail it again on the one after.
            self.caps = self.caps.withoutSegmentation();
            refused = try self.sendBatch(io, dest, payload);
        }
        return batch.report(payload, batch.Family.of(dest.ip), refused);
    }

    /// Take whatever is queued, or answer that nothing is.
    ///
    /// `error.WouldBlock` is a value and not a failure: the socket has been
    /// non-blocking since it was opened, and a caller with nothing else to do
    /// is the one that decides what an empty queue means.
    pub fn tryReceive(
        self: *const Socket,
        io: std.Io,
        buffer: []u8,
        control: *ControlBuffer,
    ) ReceiveError!Received {
        return self.recvmsg(io, buffer, control);
    }

    /// Wait for a datagram and take it. A `timeout_ms` of null waits as long
    /// as the caller means, and time stays the caller's: this reads no clock.
    pub fn receive(
        self: *const Socket,
        io: std.Io,
        buffer: []u8,
        control: *ControlBuffer,
        timeout_ms: ?i32,
    ) ReceiveError!Received {
        try self.awaitReadable(io, timeout_ms);
        return self.recvmsg(io, buffer, control);
    }

    /// One `sendmsg` per run of `payload`, and the refusal worth reporting.
    fn sendBatch(
        self: *Socket,
        io: std.Io,
        dest: base_addr.SocketAddr,
        payload: batch.Send,
    ) SendError!batch.Refused {
        var runs = try batch.Runs.init(payload, self.caps);
        var refused: batch.Refused = .none;
        while (runs.next()) |run| {
            refused = strongest(refused, try self.sendRun(io, dest, run));
        }
        return refused;
    }

    /// One run, and what it cost.
    fn sendRun(
        self: *Socket,
        io: std.Io,
        dest: base_addr.SocketAddr,
        run: batch.Send,
    ) SendError!batch.Refused {
        const family: batch.Family = batch.Family.of(dest.ip);
        var name: c.sockaddr.storage = undefined;
        const name_length = writeSockaddr(dest, &name);
        var messages: [batch.max_cmsg]batch.Cmsg = undefined;
        var control: ControlBuffer = undefined;
        const written = try writeCmsg(batch.cmsg(run, family, &messages), &control);
        if (try self.sendmsg(io, run.contents, &name, name_length, written) == .accepted) {
            return .none;
        }
        // `EIO` and `EINVAL` are one answer from the kernel and two from here.
        // Only a run the segment size made segmented can be refused for
        // segmentation, and only an IPv4 run has a control message this module
        // is willing to drop — `IPV6_TCLASS` and `UDP_SEGMENT` are core
        // options, so an unknown-control-message `EINVAL` is about the newest
        // of the three (`noq-udp/src/unix.rs:608-630`).
        if (run.isSegmented()) return .segmentation;
        if (family != .v4) return error.UnknownControlMessage;
        const retried = try self.sendmsg(io, run.contents, &name, name_length, written[0..0]);
        if (retried == .accepted) return .unknown_control_message;
        return error.UnknownControlMessage;
    }

    /// What one `sendmsg` said, before the model's name is put on it.
    const Outcome = enum {
        /// Every byte of the payload left as one message.
        accepted,
        /// `EIO` or `EINVAL`. Only the run can tell a driver that will not
        /// segment from a kernel that does not know an option.
        refused,
    };

    fn sendmsg(
        self: *const Socket,
        io: std.Io,
        bytes: []const u8,
        name: *const c.sockaddr.storage,
        name_length: socklen_t,
        control: []const u8,
    ) SendError!Outcome {
        var vectors = [_]c.iovec_const{.{ .base = bytes.ptr, .len = bytes.len }};
        const control_ptr: ?*const anyopaque = if (control.len == 0) null else control.ptr;
        var header: c.msghdr_const = .{
            .name = @as(?*const c.sockaddr, @ptrCast(name)),
            .namelen = name_length,
            .iov = vectors[0..].ptr,
            .iovlen = vectors.len,
            .control = control_ptr,
            .controllen = control.len,
            .flags = 0,
        };
        var attempt: usize = 0;
        while (attempt < max_syscall_attempts) : (attempt += 1) {
            // A signal arrived before the datagram did. Asking again is the
            // only correct answer, and the loop is also where a cancellation
            // lands. `NOSIGNAL` because a UDP send to a port nobody is on has
            // to raise `ECONNREFUSED` here rather than `SIGPIPE` there.
            try io.checkCancel();
            const rc = c.sendmsg(self.handle, &header, linux.MSG.NOSIGNAL);
            switch (c.errno(rc)) {
                .SUCCESS => {
                    if (@as(usize, @intCast(rc)) != bytes.len) return error.PartialDatagram;
                    return .accepted;
                },
                .INTR => continue,
                .AGAIN => return error.WouldBlock,
                .MSGSIZE => return error.MessageTooLarge,
                .IO, .INVAL => return .refused,
                .DESTADDRREQ, .NOTCONN => return error.SocketUnusable,
                .ACCES, .PERM => return error.PermissionDenied,
                .ADDRNOTAVAIL => return error.AddressNotAvailable,
                .HOSTUNREACH => return error.HostUnreachable,
                .NETUNREACH => return error.NetworkUnreachable,
                .NETDOWN => return error.NetworkDown,
                .CONNREFUSED => return error.PortUnreachable,
                .NOMEM, .NOBUFS => return error.ResourcesExhausted,
                else => return error.Unexpected,
            }
        }
        return error.Interrupted;
    }

    /// Wait for the descriptor to be readable.
    ///
    /// A `poll` on the descriptor and not an `Io` operation: this module
    /// opened the socket with `std.c.socket`, so no backend has ever been told
    /// the descriptor exists and only `Io.Threaded` would cope with being
    /// handed one. `posix.poll` already retries a signal, and zero ready is
    /// the timeout rather than an error.
    fn awaitReadable(
        self: *const Socket,
        io: std.Io,
        timeout_ms: ?i32,
    ) ReceiveError!void {
        try io.checkCancel();
        var descriptors = [_]posix.pollfd{.{
            .fd = self.handle,
            .events = posix.POLL.IN,
            .revents = 0,
        }};
        _ = posix.poll(&descriptors, timeout_ms orelse -1) catch |err| switch (err) {
            error.NetworkDown => return error.NetworkDown,
            error.SystemResources => return error.ResourcesExhausted,
            error.Unexpected => return error.Unexpected,
        };
    }

    fn recvmsg(
        self: *const Socket,
        io: std.Io,
        buffer: []u8,
        control: *ControlBuffer,
    ) ReceiveError!Received {
        var name: c.sockaddr.storage = undefined;
        var vectors = [_]c.iovec{.{ .base = buffer.ptr, .len = buffer.len }};
        var header: c.msghdr = .{
            .name = @as(*c.sockaddr, @ptrCast(&name)),
            .namelen = @sizeOf(c.sockaddr.storage),
            .iov = vectors[0..].ptr,
            .iovlen = vectors.len,
            .control = @as(?*anyopaque, @ptrCast(control.bytes[0..].ptr)),
            .controllen = control.bytes.len,
            .flags = 0,
        };
        var attempt: usize = 0;
        while (attempt < max_syscall_attempts) : (attempt += 1) {
            try io.checkCancel();
            const rc = c.recvmsg(self.handle, &header, linux.MSG.DONTWAIT);
            switch (c.errno(rc)) {
                .SUCCESS => {
                    if (header.flags & linux.MSG.TRUNC != 0) return error.MessageTooLarge;
                    const used = @min(header.controllen, control.bytes.len);
                    const read = readCmsg(control.bytes[0..used]);
                    if (read.truncated or header.flags & linux.MSG.CTRUNC != 0) {
                        return error.ControlTruncated;
                    }
                    return .{
                        .bytes = buffer[0..@intCast(rc)],
                        .from = readSockaddr(&name) orelse return error.Unexpected,
                        .stride = read.stride,
                        .ecn = read.ecn,
                    };
                },
                .INTR => continue,
                .AGAIN => return error.WouldBlock,
                .CONNREFUSED => return error.PortUnreachable,
                .HOSTUNREACH => return error.HostUnreachable,
                .NETUNREACH => return error.NetworkUnreachable,
                .NETDOWN => return error.NetworkDown,
                .NOMEM, .NOBUFS => return error.ResourcesExhausted,
                else => return error.Unexpected,
            }
        }
        return error.Interrupted;
    }
};

/// The refusal a caller is told about when a batch took more than one run. A
/// lost codepoint outranks a lost segmentation, because nothing downstream can
/// get it back, and a lost segmentation is a slower path rather than a wrong
/// one.
fn strongest(current: batch.Refused, next: batch.Refused) batch.Refused {
    return switch (next) {
        .segmentation => .segmentation,
        .unknown_control_message => if (current == .segmentation) current else next,
        .none => current,
    };
}

fn createSocket(family: batch.Family) OpenError!c.fd_t {
    const domain: c_uint = switch (family) {
        .v4 => linux.AF.INET,
        .v6 => linux.AF.INET6,
    };
    // `NONBLOCK` in the type rather than an `fcntl` afterwards, so there is no
    // window in which the descriptor exists and blocks.
    const kind: c_uint = linux.SOCK.DGRAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK;
    const rc = c.socket(domain, kind, linux.IPPROTO.UDP);
    if (rc >= 0) return rc;
    return switch (c.errno(rc)) {
        .ACCES, .PERM => error.PermissionDenied,
        .AFNOSUPPORT => error.AddressFamilyUnsupported,
        .PROTONOSUPPORT => error.ProtocolUnsupported,
        .SOCKTNOSUPPORT => error.SocketModeUnsupported,
        .INVAL => error.InvalidArgument,
        .MFILE, .NFILE => error.DescriptorQuotaExceeded,
        .NOMEM, .NOBUFS => error.ResourcesExhausted,
        else => error.Unexpected,
    };
}

fn bindSocket(handle: c.fd_t, name: *const c.sockaddr.storage, length: socklen_t) OpenError!void {
    const rc = c.bind(handle, @as(*const c.sockaddr, @ptrCast(name)), @intCast(length));
    switch (c.errno(rc)) {
        .SUCCESS => {},
        .ACCES, .PERM => return error.PermissionDenied,
        .ADDRINUSE => return error.AddressInUse,
        .ADDRNOTAVAIL => return error.AddressNotAvailable,
        .AFNOSUPPORT => return error.AddressFamilyUnsupported,
        .INVAL => return error.InvalidArgument,
        .MFILE, .NFILE => return error.DescriptorQuotaExceeded,
        .NOMEM, .NOBUFS => return error.ResourcesExhausted,
        else => return error.Unexpected,
    }
}

fn boundAddress(handle: c.fd_t) OpenError!base_addr.SocketAddr {
    var name: c.sockaddr.storage = undefined;
    var length: socklen_t = @sizeOf(c.sockaddr.storage);
    const rc = c.getsockname(handle, @as(*c.sockaddr, @ptrCast(&name)), &length);
    if (c.errno(rc) != .SUCCESS) return error.Unexpected;
    return readSockaddr(&name) orelse error.AddressNotAvailable;
}

/// What this socket can do, asked once, at open.
///
/// `batch.socketOptions` names the two answers that matter: the congestion
/// option and `UDP_GRO`. Asking for `UDP_GRO` *is* the probe for it, because
/// a socket that refuses it has said the kernel does not have it and there is
/// nothing to ask twice. The congestion option has no such reading, so a
/// refusal there refuses the socket.
fn probe(handle: c.fd_t, family: batch.Family) OpenError!batch.Capability {
    const requested = batch.socketOptions(family, true);
    try requireCongestionOption(handle, requested[0]);
    const recv = trySetFlag(handle, requested[1]) catch |err| return openFromOption(err);
    const send = probeSegmentation(handle) catch |err| return openFromOption(err);
    return batch.capability(send, recv);
}

/// The congestion option has no fallback, so a refusal refuses the socket: a
/// socket never asked for the codepoint reports every read as not-ECT, which
/// is a silently wrong answer rather than a missing one.
fn requireCongestionOption(handle: c.fd_t, option: batch.SocketOption) OpenError!void {
    setFlag(handle, option.level, option.name, option.value) catch |err| {
        return switch (err) {
            error.Unsupported => error.CongestionOptionUnsupported,
            error.InvalidValue => error.InvalidArgument,
            error.ResourcesExhausted => error.ResourcesExhausted,
            error.PermissionDenied => error.PermissionDenied,
            error.Unexpected => error.Unexpected,
        };
    };
}

fn openFromOption(err: OptionError) OpenError {
    return switch (err) {
        error.Unsupported => error.OptionUnsupported,
        error.InvalidValue => error.InvalidArgument,
        error.ResourcesExhausted => error.ResourcesExhausted,
        error.PermissionDenied => error.PermissionDenied,
        error.Unexpected => error.Unexpected,
    };
}

/// Whether `UDP_SEGMENT` is an option this kernel has, asked the way noq asks
/// (`noq-udp/src/linux.rs:19-46`): set it to a value, read the value back, and
/// leave it at zero so that only a control message segments a send. A socket
/// that refuses it is not an error — it is the one-segment answer a
/// `Capability` already has a name for.
///
/// The width here is an `int` and not the `u16` `batch.Value.short` carries,
/// and the two are not the same ABI: `do_udp_setsockopt` opens with
/// `if (optlen < sizeof(int)) return -EINVAL;`, while `udp_cmsg_send` demands
/// `cmsg_len == CMSG_LEN(sizeof(u16))` and copies two bytes. A probe that
/// hands the option a `u16` is refused with `EINVAL` on a kernel that has the
/// feature, which reads as "this platform cannot segment" and silently costs
/// every batch its segmentation.
fn probeSegmentation(handle: c.fd_t) OptionError!batch.Probe {
    const trial: c_int = 1;
    setOption(handle, names.udp_level, names.segment, std.mem.asBytes(&trial)) catch |err| {
        switch (err) {
            error.Unsupported => return .unsupported,
            else => |e| return e,
        }
    };
    var readback: c_int = undefined;
    var length: socklen_t = @sizeOf(c_int);
    // `getsockopt` spells its level as an `int` and the model names levels as
    // `u32`, so the narrowing is proved here rather than left to a cast that
    // panics in Debug on a level that does not fit.
    const level = std.math.cast(c_int, names.udp_level) orelse return error.InvalidValue;
    if (c.getsockopt(handle, level, names.segment, &readback, &length) != 0) {
        return error.Unexpected;
    }
    if (length != @sizeOf(c_int)) return error.InvalidValue;
    // Cleared, and checked: a socket left at one would segment every send that
    // did not ask for it, which is a worse fault than a socket that cannot
    // segment at all.
    const cleared: c_int = 0;
    try setOption(handle, names.udp_level, names.segment, std.mem.asBytes(&cleared));
    return if (readback == trial) .accepted else .unsupported;
}

fn trySetFlag(handle: c.fd_t, option: batch.SocketOption) OptionError!batch.Probe {
    setFlag(handle, option.level, option.name, option.value) catch |err| switch (err) {
        error.Unsupported => return .unsupported,
        else => |e| return e,
    };
    return .accepted;
}

fn setFlag(handle: c.fd_t, level: u32, name: u32, value: bool) OptionError!void {
    const flag: c_int = if (value) 1 else 0;
    return setOption(handle, level, name, std.mem.asBytes(&flag));
}

fn setOption(handle: c.fd_t, level: u32, name: u32, value: []const u8) OptionError!void {
    // Two narrowings, neither proved anywhere above: `setsockopt` spells its
    // level as an `int`, a `socklen_t` is narrower than a `usize` on every
    // platform, and an out-of-range `@intCast` traps in Debug where a
    // defined wrap would not. An option the ABI cannot spell is one the
    // kernel would refuse anyway, so it is refused here under that name.
    const option_level = std.math.cast(c_int, level) orelse return error.InvalidValue;
    const option_length = std.math.cast(socklen_t, value.len) orelse return error.InvalidValue;
    const rc = c.setsockopt(handle, option_level, name, value.ptr, option_length);
    switch (c.errno(rc)) {
        .SUCCESS => {},
        .INVAL => return error.InvalidValue,
        .NOPROTOOPT, .OPNOTSUPP => return error.Unsupported,
        .NOMEM, .NOBUFS => return error.ResourcesExhausted,
        .ACCES, .PERM => return error.PermissionDenied,
        else => return error.Unexpected,
    }
}

// ───────────────────────────────────────────────────────────────────── tests

const t = std.testing;

test "a control message is a header and an aligned value" {
    // `CMSG_LEN` is what a message says about itself and `CMSG_SPACE` is what
    // a buffer must hold for the next one to follow it, and the two differ
    // whenever the value does not fill the header's padding.
    try t.expectEqual(@sizeOf(c.cmsghdr), cmsgLen(0));
    try t.expectEqual(@sizeOf(c.cmsghdr), cmsgSpace(0));
    const word: usize = @sizeOf(c_int);
    try t.expectEqual(@sizeOf(c.cmsghdr) + word, cmsgLen(word));
    try t.expectEqual(cmsgAlign(@sizeOf(c.cmsghdr) + word), cmsgSpace(word));
    // A `u16` segment size falls short of the header's alignment, so its space
    // is the padded length and not the length itself.
    try t.expect(cmsgSpace(@sizeOf(u16)) > cmsgLen(@sizeOf(u16)));
}

test "a single datagram writes one control message" {
    const payload = [_]u8{0xaa} ** 64;
    const send = batch.Send.single(&payload, .ect1);
    var messages: [batch.max_cmsg]batch.Cmsg = undefined;
    var control: ControlBuffer = undefined;
    const written = try writeCmsg(batch.cmsg(send, .v4, &messages), &control);

    try t.expectEqual(cmsgSpace(batch.tos_width), written.len);
    try t.expectEqual(names.ip_level, messages[0].level);
    try t.expectEqual(names.ipv4_tos, messages[0].kind);
    // Not-ECT is zero, so a send with no codepoint still writes the message
    // rather than letting a codepoint set on the socket leak onto it.
    try t.expectEqual(@as(u8, 0b01), messages[0].value.bits);

    const read = readCmsg(written);
    try t.expect(!read.truncated);
    try t.expectEqual(@as(?usize, null), read.stride);
    try t.expectEqual(@as(?batch.Ecn, .ect1), read.ecn);
}

test "a header field the ABI cannot spell is refused, not a trap" {
    // `cmsg_level` and `cmsg_type` are an `int` and the model names them as
    // `u32`, so a level or an option above `2^31 - 1` has no spelling. A bare
    // `@intCast` panics in Debug on the way to writing one, which is a crash
    // no caller can catch and this function can name.
    var at: [cmsgLen(0)]u8 = undefined;
    try t.expectError(error.FieldTooWide, putHeader(&at, .{
        .length = cmsgLen(0),
        .level = std.math.maxInt(u32),
        .kind = names.gro,
    }));
    try t.expectError(error.FieldTooWide, putHeader(&at, .{
        .length = cmsgLen(0),
        .level = names.udp_level,
        .kind = std.math.maxInt(u32),
    }));

    // A length past what `cmsg_len` spells is the third narrowing and the
    // only arm this test cannot reach: the field is a `socklen_t`, `std.c`
    // spells it from the kernel's own headers, and it is the width of a
    // `usize` on every platform this file supports. The check below says so
    // out loud instead of leaving the gap for another platform to find; the
    // same narrowing out of a real buffer is refused in the option test.
    try t.expectEqual(@sizeOf(usize), @sizeOf(@FieldType(c.cmsghdr, "len")));
}

test "a codepoint comes back one byte wide, not at the send width" {
    // Captured from a real `recvmsg` on this kernel: `ip_cmsg_put` writes
    // `cmsg_len = CMSG_LEN(sizeof(u8))` and one byte, while `batch.tos_width`
    // is the width the *option* takes and is four on Linux. A reader that
    // insists on `tos_width` drops the message and reports not-ECT for every
    // IPv4 datagram, which is a wrong answer rather than a missing one. The
    // bytes below are the ones that kernel produced for a datagram sent with
    // `IP_TOS` = 0b10.
    const captured = [_]u8{
        0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x02,
    };
    try t.expectEqual(cmsgLen(1), captured.len);
    const read = readCmsg(&captured);
    try t.expect(!read.truncated);
    try t.expectEqual(@as(?batch.Ecn, .ect0), read.ecn);
    try t.expectEqual(@as(?usize, null), read.stride);

    // The same message at the send width, which is what a platform that
    // hands the option an `int` back would deliver.
    var messages: [batch.max_cmsg]batch.Cmsg = undefined;
    var control: ControlBuffer = undefined;
    const send = batch.Send.single(&.{}, .ce);
    const wide = try writeCmsg(batch.cmsg(send, .v4, &messages), &control);
    try t.expectEqual(@as(?batch.Ecn, .ce), readCmsg(wide).ecn);

    // Not-ECT is zero and is still a codepoint's absence, not a lost message.
    const not_ect = try writeCmsg(batch.cmsg(
        batch.Send.single(&.{}, null),
        .v6,
        &messages,
    ), &control);
    try t.expectEqual(@as(?batch.Ecn, null), readCmsg(not_ect).ecn);

    // A message with no value at all carries nothing, and says so by being
    // absent rather than by claiming not-ECT.
    var empty: [cmsgLen(0)]u8 = undefined;
    try putHeader(&empty, .{
        .length = cmsgLen(0),
        .level = names.ip_level,
        .kind = names.ipv4_tos,
    });
    try t.expectEqual(@as(?batch.Ecn, null), readCmsg(&empty).ecn);
}

test "a segmented run writes the traffic class then the segment size" {
    const payload = [_]u8{0} ** 200;
    const send = try batch.Send.batch(&payload, 100, .ce);
    var messages: [batch.max_cmsg]batch.Cmsg = undefined;
    var control: ControlBuffer = undefined;
    const written = try writeCmsg(batch.cmsg(send, .v6, &messages), &control);

    try t.expectEqual(2, batch.cmsg(send, .v6, &messages).len);
    try t.expectEqual(cmsgSpace(batch.tos_width) + cmsgSpace(@sizeOf(u16)), written.len);
    try t.expectEqual(control_size, written.len);
    try t.expectEqual(names.ipv6_level, messages[0].level);
    try t.expectEqual(names.ipv6_tclass, messages[0].kind);
    try t.expectEqual(names.udp_level, messages[1].level);
    try t.expectEqual(names.segment, messages[1].kind);
    try t.expectEqual(@as(u16, 100), messages[1].value.short);

    // The traffic class reads back because the send and the receive spell it
    // the same. The segment size does not: a send carries `UDP_SEGMENT` and a
    // read carries `UDP_GRO`, 103 and 104, and a reader that mistook the one
    // for the other would hand a caller a stride no kernel ever sent.
    const read = readCmsg(written);
    try t.expectEqual(@as(?usize, null), read.stride);
    try t.expectEqual(@as(?batch.Ecn, .ce), read.ecn);
    try t.expect(!read.truncated);
}

test "a message this seam did not ask for does not hide the one after it" {
    const payload = [_]u8{0} ** 200;
    const send = try batch.Send.batch(&payload, 100, .ect0);
    var messages: [batch.max_cmsg]batch.Cmsg = undefined;
    var control: ControlBuffer = undefined;
    const written = try writeCmsg(batch.cmsg(send, .v4, &messages), &control);
    const class = cmsgSpace(batch.tos_width);

    // A message between the two, at a level nobody here names. A walk that
    // stopped at the first unrecognised header would lose the stride after
    // it and read a coalesced list as one long datagram.
    const stranger = [_]batch.Cmsg{.{
        .level = 0xdead,
        .kind = 0xbeef,
        .value = .{ .short = 0 },
    }};
    var stranger_control: ControlBuffer = undefined;
    const between = try writeCmsg(&stranger, &stranger_control);
    const stride_message = [_]batch.Cmsg{.{
        .level = names.udp_level,
        .kind = names.gro,
        .value = .{ .short = 100 },
    }};
    var stride_control: ControlBuffer = undefined;
    const stride_bytes = try writeCmsg(&stride_message, &stride_control);

    var blob: [control_size * 3]u8 = undefined;
    var used: usize = 0;
    @memcpy(blob[used..][0..class], written[0..class]);
    used += class;
    @memcpy(blob[used..][0..between.len], between);
    used += between.len;
    @memcpy(blob[used..][0..stride_bytes.len], stride_bytes);
    used += stride_bytes.len;

    const read = readCmsg(blob[0..used]);
    try t.expect(!read.truncated);
    try t.expectEqual(@as(?usize, 100), read.stride);
    try t.expectEqual(@as(?batch.Ecn, .ect0), read.ecn);
}

test "a blob that ends inside a message says so" {
    const payload = [_]u8{0} ** 200;
    const send = try batch.Send.batch(&payload, 100, .ect0);
    var messages: [batch.max_cmsg]batch.Cmsg = undefined;
    var control: ControlBuffer = undefined;
    const written = try writeCmsg(batch.cmsg(send, .v4, &messages), &control);
    const class = cmsgSpace(batch.tos_width);

    // A header that claims more than the blob holds, which is the shape a
    // control buffer too small for the kernel's messages takes.
    var claimed: [control_size]u8 = undefined;
    @memcpy(claimed[0..class], written[0..class]);
    try putHeader(claimed[0..class], .{
        .length = class + 64,
        .level = names.udp_level,
        .kind = names.gro,
    });
    try t.expect(readCmsg(claimed[0..class]).truncated);

    // Trailing bytes too short to be a header at all, and no bytes at all:
    // the first is a message this seam cannot read and the second is no
    // message, which is a read with no stride rather than a broken one.
    const ragged = written[0..4];
    try t.expect(readCmsg(ragged).truncated);
    try t.expect(!readCmsg("").truncated);
}

test "more messages than the buffer holds is refused, not truncated" {
    var messages: [3]batch.Cmsg = undefined;
    for (&messages, 0..) |*message, index| {
        message.* = .{
            .level = names.udp_level,
            .kind = names.segment,
            .value = .{ .short = @intCast(index + 1) },
        };
    }
    var control: ControlBuffer = undefined;
    try t.expectError(error.BufferTooSmall, writeCmsg(messages[0..3], &control));
    // Two is what the model builds and two is what the buffer holds.
    try t.expectEqual(control_size, (try writeCmsg(messages[0..2], &control)).len);
}

test "an address survives the kernel's own layout" {
    var raw: c.sockaddr.storage = undefined;

    const v4: base_addr.SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 33433 };
    try t.expectEqual(@as(socklen_t, @sizeOf(c.sockaddr.in)), writeSockaddr(v4, &raw));
    // The port is network order on the wire and host order in the value: an
    // address that round-trips only because both ends agree to be wrong is
    // not a round trip. The four octets are the four bytes of the word, in
    // the order the wire has them, which is what makes the bit cast the
    // conversion and a byte swap the bug.
    const v4_raw: *const c.sockaddr.in = @ptrCast(@alignCast(&raw));
    try t.expectEqual(std.mem.nativeToBig(u16, 33433), v4_raw.port);
    try t.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, std.mem.asBytes(&v4_raw.addr));
    try t.expectEqual(v4, readSockaddr(&raw).?);

    const v6: base_addr.SocketAddr = .{
        .ip = .{ .v6 = [_]u8{0} ** 15 ++ [_]u8{0x01} },
        .port = 65535,
    };
    try t.expectEqual(@as(socklen_t, @sizeOf(c.sockaddr.in6)), writeSockaddr(v6, &raw));
    const v6_raw: *const c.sockaddr.in6 = @ptrCast(@alignCast(&raw));
    try t.expectEqual(std.mem.nativeToBig(u16, 65535), v6_raw.port);
    try t.expectEqual(v6, readSockaddr(&raw).?);

    // An address of a family this module does not speak reads as nothing
    // rather than as an IPv4 address built from the wrong first two bytes.
    raw.family = linux.AF.LOCAL;
    try t.expect(readSockaddr(&raw) == null);
}

test "an option value the ABI cannot spell is refused, not a trap" {
    // One past what a `socklen_t` holds, and never read: the refusal comes
    // before the syscall, so naming the four gigabytes is cheaper than
    // having them. Without the checked cast this is a panic in Debug.
    const nowhere: [*]const u8 = @ptrFromInt(1);
    const too_wide = nowhere[0 .. @as(usize, std.math.maxInt(socklen_t)) + 1];
    const flag: c_int = 1;
    try t.expectError(
        error.InvalidValue,
        setOption(-1, names.udp_level, names.segment, too_wide),
    );

    // The other narrowing on the same line: `setsockopt` spells its level as
    // an `int`, and `2^32 - 1` is not one. A descriptor of `-1` is what
    // proves the refusal came before the call rather than from it.
    try t.expectError(
        error.InvalidValue,
        setOption(-1, std.math.maxInt(u32), names.segment, std.mem.asBytes(&flag)),
    );
}

test "the two probes answer for a socket, one side at a time" {
    // The decision the probe exists to make, over the answers it can get.
    const both = batch.capability(.accepted, .accepted);
    try t.expect(both.supportsSegmentation());
    try t.expect(both.supportsCoalescing());
    try t.expectEqual(batch.max_segments_linux, both.max_send_segments);
    try t.expectEqual(batch.max_gro_segments_linux, both.max_recv_segments);

    try t.expectEqual(batch.Capability.none, batch.capability(.unsupported, .unsupported));

    // A socket that coalesces but cannot segment is a real one, and the two
    // answers stay independent: the kernel can do either without the other,
    // which is why `capability` reads two probes rather than one.
    const recv_only = batch.capability(.unsupported, .accepted);
    try t.expect(!recv_only.supportsSegmentation());
    try t.expect(recv_only.supportsCoalescing());

    // The permanent fallback, and the receive side it leaves alone: a driver
    // that cannot segment can still coalesce.
    const send_only = batch.Capability.linux_full.withoutSegmentation();
    try t.expectEqual(@as(u16, 1), send_only.max_send_segments);
    try t.expectEqual(batch.max_gro_segments_linux, send_only.max_recv_segments);
}

test "a driver that cannot segment degrades the batch and says so" {
    // The fallback, as the value a caller inspects: a four-datagram batch goes
    // out as four `sendmsg`s and the report says the batch was degraded,
    // rather than leaving the wire to be the only evidence.
    const payload = [_]u8{0} ** 40;
    const send = try batch.Send.batch(&payload, 10, .ect0);
    const degraded = batch.report(send, .v4, .segmentation);
    try t.expect(degraded.degraded);
    try t.expect(degraded.ecnSurvived());
    try t.expectEqual(@as(?batch.Ecn, .ect0), degraded.carried);

    // A single datagram is one `sendmsg` either way, so nothing about it is
    // degraded even when the same refusal happens to it.
    const single = batch.report(batch.Send.single(&payload, .ect0), .v4, .segmentation);
    try t.expect(!single.degraded);
    try t.expect(single.ecnSurvived());

    // The walk a degraded socket then takes, where the codepoint survives: a
    // fallback about segmentation is not collateral damage for the ECN.
    var runs = try batch.Runs.init(send, batch.Capability.linux_full.withoutSegmentation());
    var seen: usize = 0;
    while (runs.next()) |run| {
        try t.expectEqual(@as(?u16, null), run.segment_size);
        try t.expectEqual(@as(usize, 1), run.datagramCount());
        try t.expectEqual(@as(?batch.Ecn, .ect0), run.ecn);
        try t.expectEqual(@as(?batch.Ecn, .ect0), batch.report(run, .v4, .none).carried);
        seen += 1;
    }
    try t.expectEqual(@as(usize, 4), seen);
}

test "a lost codepoint is reported, and only on IPv4" {
    const payload = [_]u8{0} ** 8;
    const send = batch.Send.single(&payload, .ce);
    const lost = batch.report(send, .v4, .unknown_control_message);
    try t.expectEqual(@as(?batch.Ecn, null), lost.carried);
    try t.expectEqual(@as(?batch.Ecn, .ce), lost.wanted);
    try t.expect(!lost.ecnSurvived());

    // `IPV6_TCLASS` is a core option, so the same refusal drops nothing.
    const kept = batch.report(send, .v6, .unknown_control_message);
    try t.expectEqual(@as(?batch.Ecn, .ce), kept.carried);
    try t.expect(kept.ecnSurvived());

    // A send that asked for nothing has nothing to lose.
    const nothing = batch.report(batch.Send.single(&payload, null), .v4, .unknown_control_message);
    try t.expect(nothing.ecnSurvived());
    try t.expectEqual(@as(?batch.Ecn, null), nothing.carried);
}

test "a coalesced read of one datagram is the uncoalesced read" {
    const one = [_]u8{0x5a} ** 16;
    const three = [_]u8{0x5a} ** 48;
    var control: ControlBuffer = undefined;

    // The stride a read gets is the one the `UDP_GRO` message carries, read
    // back out of real bytes rather than handed in by hand.
    const stride_message = [_]batch.Cmsg{.{
        .level = names.udp_level,
        .kind = names.gro,
        .value = .{ .short = 16 },
    }};
    const read = readCmsg(try writeCmsg(&stride_message, &control));
    try t.expectEqual(@as(?usize, 16), read.stride);
    try t.expectEqual(@as(?batch.Ecn, null), read.ecn);

    const coalesced: Received = .{
        .bytes = &three,
        .from = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 1 },
        .stride = read.stride,
        .ecn = null,
    };
    try t.expectEqual(@as(usize, 3), (try coalesced.toRecv()).datagramCount());

    const solo: Received = .{
        .bytes = &one,
        .from = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 1 },
        .stride = read.stride,
        .ecn = null,
    };
    try t.expectEqual(@as(usize, 1), (try solo.toRecv()).datagramCount());

    // A stride equal to the buffer's own length and no stride at all are the
    // same read, which is what makes the null arm safe to act on.
    const with_stride = try batch.Recv.init(&one, read.stride, .ect0);
    const without = try batch.Recv.init(&one, null, .ect0);
    try t.expectEqual(without.stride, with_stride.stride);
    try t.expectEqual(without.datagramCount(), with_stride.datagramCount());
    try t.expectEqual(@as(usize, 1), with_stride.datagramCount());
    try t.expectEqualSlices(u8, &one, with_stride.datagram(0).?);
    try t.expect(with_stride.datagram(1) == null);

    // A stride the buffer cannot hold is refused, not clamped, and a stride of
    // no bytes names no datagram at all.
    try t.expectError(error.StrideExceedsBuffer, batch.Recv.init(&one, 17, null));
    try t.expectError(error.ZeroSegmentSize, batch.Recv.init(&one, 0, null));
    try t.expectError(error.ZeroSegmentSize, batch.Recv.init(&.{}, null, null));
}
