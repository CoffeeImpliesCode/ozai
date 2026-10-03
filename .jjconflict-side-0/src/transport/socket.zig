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
//! functions that need it." So `Socket` holds descriptors and no `Io`, and
//! every operation that can be cancelled takes one. What the runtime is asked
//! for is cancellation and nothing else — `Io.Threaded.checkCancel` is an
//! atomic load — because a descriptor this module opened is a descriptor no
//! `Io` backend can poll, and handing it to one would be a claim that only
//! holds for `Threaded`. The wait before a receive is a `poll` on the
//! descriptor for the same reason, and a task cancelled inside the `recvmsg`
//! is not seen until that call returns.
//!
//! # The second descriptor, and the wait it ends
//!
//! `Socket` owns two of them: the socket, and an `eventfd` that exists to be
//! woken. It is the first thing besides the socket this struct holds, and it
//! is here because a `poll` is asleep in the kernel — there is nowhere to
//! consult a flag from, so a wait that has to be *ended* rather than run to
//! the end of its slice needs a descriptor to become readable. An `eventfd`
//! rather than a self-pipe: one descriptor instead of two, a counter instead
//! of a byte buffer, and `EFD_SEMAPHORE` makes a read take one wake off the
//! counter rather than all of them.
//!
//! What a wake means belongs to `Socket.stop`, and its two halves are in
//! different places on purpose. `stop` raises the wake with one store and one
//! `write`; `discovery/lookup_live.zig` uses it when a lookup is cancelled.
//! The waiter owns queue cleanup, because the cancellation callback may run
//! while the socket is being polled. A send spends any remaining wake before
//! making the socket usable again.
//! The CLI's signal handler only calls `Stop.request`: it does not raise
//! this wake, so a node notices its stop at the next poll timeout.
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
//! `socket`, `bind`, `getsockname`, `setsockopt`, `sendmsg`, `recvmsg`,
//! `eventfd`, `read`, `write` and `close` are libc's here, so an artifact that
//! calls any of them needs `linkLibC()`. Nothing above them is: the layout
//! work is arithmetic on bytes, which is why every test here reaches libc's
//! code without leaving a syscall behind. The one that names `setsockopt`
//! proves a refusal, and the refusal comes before the call.
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

/// Control integers use native byte order. `UDP_SEGMENT` sends a `u16`,
/// `UDP_GRO` returns an integer, and traffic classes arrive as a byte or an integer.
const endian = builtin.cpu.arch.endian();

/// How many times one syscall is retried after a signal before the call is
/// declared interrupted. A signal is not a fact about a datagram and retrying
/// is the only correct answer; the bound is what stops a storm of them from
/// becoming a hang.
pub const max_syscall_attempts = 4;

/// The counter an `eventfd` counts in, which the kernel fixes at eight bytes
/// and both `read` and `write` want all of. It is a value rather than a count
/// of anything in this file, which is the whole of what a wake carries.
const wake_width = @sizeOf(u64);

/// How many datagrams a stop takes off the queue before it stops taking.
///
/// A bound and not a budget. RFC 1035 §7.2 has one query in flight per lookup,
/// so a queue deeper than this is a peer filling it faster than a waiter can
/// empty it, and the next thing to hang would be the resolve that gave up.
pub const max_discarded = 64;

/// How many wake units one cleanup takes off the counter before it says the
/// counter is not spending.
///
/// A bound and not a budget, and the same fact `max_discarded` is about with
/// the other half of a stop: one unit is one `stop`, and a stop belongs to a
/// caller with a wait in progress, so a counter this deep is cancellation
/// being raised faster than a send can spend it. Reaching it is a refusal and
/// not a partial spend, because a unit left standing ends the next wait
/// exactly the way a real stop would and nothing else would take it off.
pub const max_wakes_spent = 64;

// 80 display columns; the rule counts UTF-8 bytes, three per box character.
// ziglint-ignore: Z024
// ────────────────────────────────────────────────────── control-message layout

/// The boundary a control message is padded to, and the one number in this
/// file that decides where a message ends and the next one begins.
///
/// It is `sizeof(size_t)` and not the alignment of a `cmsghdr`, and on musl
/// those are two different numbers: `CMSG_ALIGN` in musl's `sys/socket.h`
/// and in the kernel's `include/linux/socket.h` both round a length up to a
/// word, while glibc declares `cmsg_len` a `size_t`, so its struct is
/// eight-byte aligned and the two agree there. musl aims at POSIX and
/// declares the same field a `socklen_t` with four bytes of padding above it,
/// which makes its struct four-byte aligned and sixteen bytes wide while
/// `CMSG_ALIGN` still rounds to eight — `std/c.zig` says as much over
/// `posix_cmsghdr`.
///
/// Rounding by the struct instead is not cosmetic. The buffer below is ten
/// bytes short of the two messages a coalesced read carries, and the kernel
/// answers a control buffer it cannot fill with `MSG_CTRUNC`; a send's second
/// message lands four bytes before the offset the kernel's own `CMSG_NXTHDR`
/// walks to, so what it reads there is padding rather than a header.
const cmsg_boundary: usize = @sizeOf(usize);

/// `CMSG_ALIGN`: a length rounded up to that boundary. The 0.16 std tree
/// carries no `CMSG_*` macro — a search for `CMSG_LEN` across `lib/std`
/// finds nothing — so the three arithmetic facts are here once and every
/// message below is written and read through them.
pub fn cmsgAlign(length: usize) usize {
    return std.mem.alignForward(usize, length, cmsg_boundary);
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

/// Room for a traffic class and either UDP_SEGMENT's u16 or UDP_GRO's int.
/// The receive integer is wider, so it bounds the shared control buffer.
pub const control_size: usize = cmsgSpace(batch.tos_width) + cmsgSpace(@sizeOf(c_int));

/// The width `msg_controllen` is spelled in: POSIX says `socklen_t` and musl
/// says POSIX, while glibc follows the kernel and spells it a `size_t`.
const ControlExtent = @FieldType(c.msghdr_const, "controllen");

comptime {
    // The bound every narrowing of a control length is taken against. No
    // buffer this file hands to a syscall is longer than `control_size` —
    // `writeCmsg` cannot return more of a `ControlBuffer` than it holds —
    // so this is what proves `sendmsg`'s own narrowing cannot lose a bit.
    std.debug.assert(control_size <= std.math.maxInt(ControlExtent));
}

/// The bytes a `sendmsg` writes its control messages into, and the bytes a
/// `recvmsg` reads them back out of.
///
/// One traffic-class message and one `UDP_GRO` message is every message a
/// socket asked for: `IP_PKTINFO` and `SO_TIMESTAMP` are not set, so the
/// kernel has no other reason to send one. The struct carries its own
/// alignment, because the kernel writes these headers at `cmsg_boundary` and
/// a bare `[]u8` does not promise it.
pub const ControlBuffer = extern struct {
    bytes: [control_size]u8 align(cmsg_boundary),
};

/// Why a set of control messages would not fit.
pub const ControlError = error{
    /// The buffer cannot hold what it was handed. A control message that
    /// stops halfway is a different message, not a shorter one: the kernel
    /// reads `cmsg_len` bytes whatever the buffer holds.
    BufferTooSmall,
    /// A field the ABI's own type cannot hold: a header's length past what
    /// `socklen_t` spells, a level or an option past what an `int` spells, or
    /// a control buffer longer than `msg_controllen` can say. The truncated
    /// field would be a header pointing at bytes that are not there, so it is
    /// refused instead of written.
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
        const length: usize = getLength(rest);
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
    // Three narrowings, none of them proved anywhere above: the C header
    // spells `cmsg_len` a `socklen_t` under musl and a `size_t` under glibc,
    // spells its level and type an `int`, and a bare `@intCast` panics in
    // Debug on a value that does not fit rather than writing a defined one.
    // Each is narrowed here, where the bound is, and a header the ABI cannot
    // spell is refused rather than written with a field that describes
    // something else.
    const ControlLength = @FieldType(c.cmsghdr, "len");
    const length = std.math.cast(ControlLength, header.length) orelse return error.FieldTooWide;
    const level = std.math.cast(c_int, header.level) orelse return error.FieldTooWide;
    const kind = std.math.cast(c_int, header.kind) orelse return error.FieldTooWide;
    // The word that goes out is the kernel's and not the C struct's. `struct
    // cmsghdr` in `include/linux/socket.h` spells `cmsg_len` a
    // `__kernel_size_t` at offset zero of a sixteen-byte header, and
    // `__sys_sendmsg` copies that whole word out of this buffer before
    // `sock_cmsg_send` and `udp_cmsg_send` read it back and check it against
    // `CMSG_OK` and `CMSG_LEN(sizeof(u16))`. musl's own header spells the
    // same field a `socklen_t` and puts four bytes of padding around it —
    // above the field on a little-endian host, below it on a big-endian one —
    // inside that same word. So the word is zeroed and the field written into
    // the middle of it: writing the field alone would hand the kernel a
    // length with whatever the stack held inside it, and whether a send is
    // refused at all would come to depend on that.
    const len_at = @offsetOf(c.cmsghdr, "len");
    const control_width = @sizeOf(ControlLength);
    @memset(at[0..@sizeOf(usize)], 0);
    std.mem.writeInt(ControlLength, at[len_at..][0..control_width], length, endian);
    const word = @sizeOf(c_int);
    const level_at = @offsetOf(c.cmsghdr, "level");
    const kind_at = @offsetOf(c.cmsghdr, "type");
    std.mem.writeInt(c_int, at[level_at..][0..word], level, endian);
    std.mem.writeInt(c_int, at[kind_at..][0..word], kind, endian);
}

/// The length a header reports, read in the width the kernel wrote it.
///
/// One word at offset zero of the header, which is where the kernel's own
/// `__kernel_size_t` is and which therefore holds musl's `socklen_t` and its
/// padding together. The C struct's field offset would be the same number on
/// a little-endian host and would read into the level that follows the length
/// on a big-endian one, so it is the word and not the field that is read.
fn getLength(at: []const u8) usize {
    return std.mem.readInt(usize, at[0..@sizeOf(usize)], endian);
}

/// The level or the option a header names, which are an `int` on every ABI
/// here — `getLength` is the one field that is not the same width twice.
fn getHeader(comptime field: []const u8, at: []const u8) u32 {
    const offset = @offsetOf(c.cmsghdr, field);
    const word = @sizeOf(c_int);
    return @bitCast(std.mem.readInt(c_int, at[offset..][0..word], endian));
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
    const level = getHeader("level", header);
    const kind = getHeader("type", header);
    if (level == names.udp_level and kind == names.gro) {
        // The receive ABI is a full native int, unlike UDP_SEGMENT's u16.
        if (value.len < @sizeOf(c_uint)) return;
        read.stride = std.mem.readInt(c_uint, value[0..@sizeOf(c_uint)], endian);
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

// 79 display columns; the rule counts UTF-8 bytes, three per box character.
// ziglint-ignore: Z024
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

// 79 display columns; the rule counts UTF-8 bytes, three per box character.
// ziglint-ignore: Z024
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
    /// A bound on this call ran out: `EINTR` on every attempt the refused run
    /// had, or a stop whose queue or wake counter a send could not empty within
    /// `max_discarded` and `max_wakes_spent`.
    ///
    /// The bound is on the call and not on the batch. A batch is one
    /// `sendmsg` per run, and every run that finished before this one left the
    /// socket: nothing the refused run carried went out, while datagrams ahead
    /// of it may have. Which is why `Socket.send` returns no sent-prefix count
    /// and why the caller is the one that decides about duplicates — the same
    /// residue every other error here leaves, and this one is no exception.
    ///
    /// A stop this send did not deal with leaves the socket stopped, so asking
    /// again is what drains the rest and makes progress.
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

// 80 display columns; the rule counts UTF-8 bytes, three per box character.
// ziglint-ignore: Z024
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
    /// `bytes` borrows the caller's receive buffer. Reusing or releasing that
    /// buffer invalidates it. The other fields are independent values.
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
/// is what lets a stack pool them and what lets a test hand over a stack
/// array. Two descriptors and one flag, and every one of the three is about
/// being stopped rather than about carrying a datagram; see `stop`.
///
/// A successful `create` owns both descriptors. Close them exactly once after
/// all operations and stop callers finish. Copies share those descriptors.
/// Keep the value at a stable address while a lookup or stop caller borrows it.
/// Serialize sends and receives. Only `stop` may run concurrently with them.
/// An operation borrows `io` and its backend only until the operation returns.
pub const Socket = struct {
    /// The descriptor. `O_NONBLOCK` from the moment it exists, which is what
    /// makes `EAGAIN` a fact a caller can act on instead of a stall.
    handle: c.fd_t,
    /// The descriptor a stop writes to, in the same `poll` set as `handle`
    /// and the only thing that can end a wait before its timeout. The first
    /// descriptor this struct owns that is not the socket.
    wake: c.fd_t,
    /// Set by `stop` and cleared by the next send, which drains on its way
    /// past. Between the two, nothing arriving on this descriptor is an
    /// answer to anything.
    stopped: std.atomic.Value(bool),
    /// Which control message carries the codepoint here.
    family: batch.Family,
    /// Capabilities observed at creation and downgraded after refused sends.
    /// A driver that cannot segment is found by sending; a cap is never raised.
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
        // After the probe: a socket refused on its own options never reached
        // the point of having a wait to wake.
        const wake = try createWake();
        errdefer _ = c.close(wake);
        var name: c.sockaddr.storage = undefined;
        const length = writeSockaddr(address, &name);
        try bindSocket(handle, &name, length);
        return .{
            .handle = handle,
            .wake = wake,
            .stopped = .init(false),
            .family = family,
            .caps = caps,
            .address = try boundAddress(handle),
        };
    }

    /// Close both descriptors. Nothing is buffered on this side: a send that
    /// returned has left the socket, and a read that returned has been taken.
    /// Do not close a copy or call this twice. Neither descriptor is reset.
    pub fn close(self: *Socket) void {
        _ = c.close(self.wake);
        _ = c.close(self.handle);
    }

    /// Name this socket stopped: end the wait in flight, and leave the queue
    /// as though nothing had ever been asked of it.
    ///
    /// A socket outlives whatever stopped it — it is the caller's, and the
    /// next request on this descriptor is the whole reason it is not closed —
    /// so this is not a latch. It is a message: a wait in flight ends at once,
    /// the queue is emptied, and nothing that arrives is wanted until a
    /// datagram goes out. That last part is what leaves the socket usable,
    /// because nothing queued before the next send can be an answer to it, and
    /// it is deliberately not a `shutdown` — which would answer that next
    /// request with a descriptor no read will ever work on again.
    ///
    /// Everything this body does is something a signal handler may do: one
    /// store and one `write`, both on POSIX's list of calls such a handler is
    /// allowed to make. The queue is emptied by the wait this wakes and by the
    /// next send, because `recvmsg` is not on that list.
    ///
    /// Keep the socket alive and open until every concurrent stop returns.
    pub fn stop(self: *Socket) void {
        self.stopped.store(true, .release);
        var one: u64 = 1;
        _ = c.write(self.wake, std.mem.asBytes(&one), wake_width);
    }

    // A method's receiver is its first parameter, so `io` comes second on
    // every operation that needs the runtime — which is all of them except
    // `stop`, and that is the one a signal handler may call.
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
    ///
    /// **Every datagram this call sends reaches the wire once.** A run refused
    /// for segmentation lowers the socket's capability for good and is
    /// answered by sending that run and the runs behind it, one datagram per
    /// `sendmsg`; the runs before it are already on the wire and are not sent
    /// again. A codepoint the retried tail lost is reported as lost, because
    /// the datagram carrying it has gone and no retry can put it back.
    ///
    /// The call is nonblocking and borrows `payload.contents` only for the
    /// call. `error.Canceled` is forwarded. On error, earlier runs may already
    /// have left the socket. No sent-prefix count is returned. Do not replay a
    /// batch unless the protocol tolerates duplicates.
    pub fn send(
        self: *Socket,
        io: std.Io,
        dest: base_addr.SocketAddr,
        payload: batch.Send,
    ) SendError!batch.Report {
        try io.checkCancel();
        // What a stop leaves behind is dealt with first, and it is a whole of
        // its own: `restart` drains the queue and spends the wake.
        try restart(self, io);
        return sendBatch(self, io, dest, payload, &self.caps);
    }

    /// Take whatever is queued, or answer that nothing is.
    ///
    /// `error.WouldBlock` is a value and not a failure: the socket has been
    /// non-blocking since it was opened, and a caller with nothing else to do
    /// is the one that decides what an empty queue means.
    ///
    /// The returned bytes borrow `buffer`, not `control`. Both buffers may be
    /// overwritten even on error. A truncation error consumes the datagram.
    /// `error.Canceled` is forwarded. This call does not wait for readiness.
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
    ///
    /// Zero polls once. Negative values, like `null`, wait without a deadline.
    /// A timeout returns `error.WouldBlock`. `stop` wakes a blocked poll with
    /// `error.Canceled`. An `io` cancellation is checked around the syscalls,
    /// but does not itself wake the poll. Result and error residue follow
    /// `tryReceive`.
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

    // One `sendmsg` per run of `payload` is `walkRuns`, and the two passes
    // deciding what a refused batch costs is `sendBatch`; both are functions
    // of their writer rather than methods, and this is where the batch ends.

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
        // The length narrowed where the bound is, rather than by a bare
        // `@intCast` that traps in Debug on a value which does not fit: under
        // musl `msg_controllen` is a `socklen_t` and a slice length is a
        // `usize`. It cannot fail, because `writeCmsg` hands back no more of a
        // `ControlBuffer` than it holds and `control_size` is proved against
        // this very field at comptime — but the proof is that assertion, and
        // this is the cast that reads it.
        const control_length = std.math.cast(ControlExtent, control.len) orelse
            return error.FieldTooWide;
        const control_ptr: ?*const anyopaque = if (control_length == 0) null else control.ptr;
        var header: c.msghdr_const = .{
            .name = @as(?*const c.sockaddr, @ptrCast(name)),
            .namelen = name_length,
            .iov = vectors[0..].ptr,
            .iovlen = vectors.len,
            .control = control_ptr,
            .controllen = control_length,
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

    /// Wait for the descriptor to be readable, or for a stop to end the wait.
    ///
    /// A `poll` on the descriptor and not an `Io` operation: this module
    /// opened the socket with `std.c.socket`, so no backend has ever been told
    /// the descriptor exists and only `Io.Threaded` would cope with being
    /// handed one. `posix.poll` already retries a signal, and zero ready is
    /// the timeout rather than an error.
    ///
    /// The set has two entries, and that is the whole of how a stop reaches a
    /// wait already in progress: the wake is a descriptor like any other, and
    /// `poll` returns for it exactly as it returns for a datagram. A flag
    /// consulted around the call would be consulted only once the call was
    /// over, which is the failure the wake descriptor exists to remove.
    fn awaitReadable(
        self: *const Socket,
        io: std.Io,
        timeout_ms: ?i32,
    ) ReceiveError!void {
        try io.checkCancel();
        var descriptors = [_]posix.pollfd{
            .{
                .fd = self.handle,
                .events = posix.POLL.IN,
                .revents = 0,
            },
            .{
                .fd = self.wake,
                .events = posix.POLL.IN,
                .revents = 0,
            },
        };
        _ = posix.poll(&descriptors, timeout_ms orelse -1) catch |err| switch (err) {
            error.NetworkDown => return error.NetworkDown,
            error.SystemResources => return error.ResourcesExhausted,
            error.Unexpected => return error.Unexpected,
        };
        // A stop, and not a datagram, and it outranks a datagram the socket
        // may have found in the same pass: the queue is drained, so the bytes
        // this socket is holding are wanted by nobody, and the wait is over
        // rather than starting a read nobody is left to want the answer of.
        if (descriptors[1].revents != 0) {
            // A stop is what ended this wait however the drain made of the
            // queue, and a drain that could not empty it is not a different
            // answer. Nothing here clears the flag or spends the counter, so
            // the socket stays stopped and the next send drains again — and a
            // cancellation reported as anything but `Canceled` is a refusal
            // the caller above this one is not waiting for.
            self.discard(io) catch return error.Canceled;
            return error.Canceled;
        }
    }

    /// Take everything queued on the descriptor and throw it away.
    ///
    /// One byte of buffer, because a datagram leaves the queue whatever the
    /// buffer holds and this is the one read whose bytes nobody asked for. The
    /// wake counter is left alone: a stop stands until the next send, and a
    /// counter emptied here would let the wait after this one block on a
    /// socket that is still stopped.
    ///
    /// A queue deeper than `max_discarded` is refused rather than emptied as
    /// far as it goes, and the caller keeps the socket stopped when it is: the
    /// next send drains again, which is the difference between a straggler it
    /// can see and one the next query would have read as its own answer.
    fn discard(
        self: *const Socket,
        io: std.Io,
    ) error{ Canceled, Interrupted, Unexpected }!void {
        var sink: [1]u8 = undefined;
        var vectors = [_]c.iovec{.{ .base = &sink, .len = sink.len }};
        var header: c.msghdr = .{
            .name = null,
            .namelen = 0,
            .iov = vectors[0..].ptr,
            .iovlen = vectors.len,
            .control = null,
            .controllen = 0,
            .flags = 0,
        };
        var dropped: usize = 0;
        var signals: usize = 0;
        // Two bounds, because a signal is not a fact about the queue: charging
        // one to the other either bounds nothing at all or spends datagrams to
        // pay for a storm. Out of the loop by either is the same refusal, and
        // neither is a claim that the queue is empty.
        while (dropped < max_discarded and signals < max_syscall_attempts) {
            try io.checkCancel();
            const rc = c.recvmsg(self.handle, &header, linux.MSG.DONTWAIT);
            switch (c.errno(rc)) {
                // One datagram off the queue, and the loop above is what bounds
                // how many: every one of them is wanted by nobody, so the depth
                // of the queue is the only thing that decides. A read that
                // returned after this one would leave the rest of the queue
                // standing for the next query to read as its answer.
                .SUCCESS => dropped += 1,
                .AGAIN => return,
                .INTR => signals += 1,
                // A failed read does not prove the queue is empty.
                else => return error.Unexpected,
            }
        }
        return error.Interrupted;
    }

    /// Spend the wake counter, which the send that ends a stop does along with
    /// the queue.
    ///
    /// A wake is a message to a wait and not a latch, so it is spent here and
    /// nowhere else. Left standing, it would wake every wait that followed it
    /// for a stop that has already been dealt with. `EFD_SEMAPHORE` gives a
    /// read one unit rather than the whole count, so spending the counter is
    /// one read per unit and a counter deeper than `max_wakes_spent` is
    /// refused rather than half spent — a unit left on it ends the next wait
    /// exactly the way a real stop would, and nothing else takes it off.
    fn clearWake(self: *const Socket) error{Interrupted}!void {
        var count: u64 = 0;
        var spent: usize = 0;
        var signals: usize = 0;
        // Bounded on the units and on the signals, as `discard` is: a counter
        // that keeps rising under cancellation raised faster than a send can
        // spend it is not a queue to empty, and the refusal leaves the socket
        // stopped for the next send rather than spent half way.
        while (spent < max_wakes_spent and signals < max_syscall_attempts) {
            const rc = c.read(self.wake, std.mem.asBytes(&count), wake_width);
            switch (c.errno(rc)) {
                .SUCCESS => spent += 1,
                // Nothing standing, which is the whole of what spending the
                // counter means.
                .AGAIN => return,
                .INTR => signals += 1,
                // A counter that cannot be read is a counter that cannot be
                // claimed empty.
                else => return error.Interrupted,
            }
        }
        return error.Interrupted;
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

/// End the stopped state this socket is in: take the queue, then spend the
/// wake the stop left behind.
///
/// A stop means nothing arriving on this descriptor is wanted, so whatever is
/// queued goes with it rather than being left for whoever reads next. This is
/// the one place a stopped socket becomes a socket again, and the only place
/// the wake is spent: a counter left standing would wake every wait that
/// followed, for a stop already dealt with.
///
/// `context` is what the recovery runs on and not a `*Socket`, so a test can
/// raise a real `Socket.stop` between the drain and the flag. Another task's
/// stop is the only thing that happens there in production, and whether this
/// erases one is the whole of what the order below has to get right.
fn restart(context: anytype, io: std.Io) error{ Canceled, Interrupted, Unexpected }!void {
    // The old stop is spent *first*, and the order is the whole of this
    // function: a stop raised while the queue is being taken, or while the
    // counter is being emptied, has set the flag again, and a flag cleared
    // after either of those erases that stop outright — nothing queued after it
    // would ever be drained and nothing would end the next wait.
    if (!context.stopped.swap(false, .acq_rel)) return;
    // And it goes back on the paths that leave the socket as they found it: a
    // drain or a counter spend that could not finish leaves the stop standing,
    // so the next send drains again rather than sending over a queue nobody has
    // emptied. Two sends racing here is harmless — one of them finds nothing
    // to take.
    errdefer context.stopped.store(true, .release);
    try context.discard(io);
    // The units this stop left, which are on the counter whatever has arrived
    // since: a unit spent here is a wake for a stop this socket has dealt with,
    // and spending one is what ends the wait after it on the descriptor.
    try context.clearWake();
    // A stop that arrived during the drain or during that read is still
    // outstanding, and the read may have taken the unit it raised. The socket
    // is stopped, so it owes a waiter a wake; `stop` is the socket's own way of
    // raising one, and a stop that arrives after this line writes its own unit
    // instead of finding one to take.
    if (context.stopped.load(.acquire)) context.stop();
}

/// What one pass over a batch left behind.
///
/// The refusal is the codepoint one when there was one, because a codepoint
/// dropped from a run is not on the next one either; a refused segmentation is
/// not a refusal of the codepoint at all and is reported by `tail` being there
/// rather than by being ranked against a loss.
const Pass = struct {
    /// What the runs drew. `.none` when every one of them went out.
    refused: batch.Refused = .none,
    /// The payload from the refused run onwards, and null when there is none:
    /// a run that went out took its datagrams with it, so a pass that refused
    /// nothing has nothing to send again, and a pass that refused one leaves
    /// the tail starting on that run rather than behind it.
    tail: ?batch.Send = null,
};

/// Send `payload` to `dest`, and say what it carried.
///
/// One pass over the runs, and a second over the runs that did not go out when
/// one of them was refused for segmentation. Every datagram reaches the wire
/// once: the runs before the refused one are already there, so the tail starts
/// on the refused run itself and the retry cannot put a second copy of
/// anything on it.
///
/// `context` is the writer the runs go out on, and not the socket type: the
/// refusals below come from the driver, and a driver that refuses a segmented
/// run is a node a test may not be running on. Monomorphised rather than
/// erased, so the production call is `Socket.sendRun` and saying it costs
/// nothing at run time.
fn sendBatch(
    context: anytype,
    io: std.Io,
    dest: base_addr.SocketAddr,
    payload: batch.Send,
    caps: *batch.Capability,
) SendError!batch.Report {
    const family = batch.Family.of(dest.ip);
    const first = try walkRuns(context, io, dest, payload, caps.*);
    const tail = first.tail orelse return batch.report(payload, family, first.refused);
    // Found by sending, not by asking, and permanent: noq lowers the cap and
    // never raises it (`noq-udp/src/unix.rs:436-445`), because a driver that
    // could segment on the next send would fail it again on the one after.
    caps.* = caps.*.withoutSegmentation();
    // Nothing behind that refusal was segmented, so the retry draws no second
    // segmentation and cannot leave a tail of its own.
    const second = try walkRuns(context, io, dest, tail, caps.*);

    // `batch.report` is given the refusal no retry can undo: a codepoint either
    // pass dropped is on the wire without it, and nothing downstream can get it
    // back. A refused segmentation is answered by the retry above and is not a
    // report about the codepoint at all — that fact is `degraded`, below.
    const unrecoverable = if (first.refused == .unknown_control_message)
        first.refused
    else
        second.refused;
    var report = batch.report(payload, family, unrecoverable);
    // The degradation is the other fact and the retry does not undo it: it is
    // the reason there was a retry, and a batch that went out one datagram per
    // `sendmsg` went out that way whatever the retry found. Same rule
    // `batch.report` uses — one datagram is one `sendmsg` either way.
    report.degraded = payload.datagramCount() > 1;
    return report;
}

/// One `context.sendRun` per run of `payload`, and what the pass left behind.
///
/// Stops at the first run refused for segmentation: that run carried nothing,
/// and every run behind it is one this socket will refuse the same way — the
/// cap is lowered by the caller, not argued with here.
fn walkRuns(
    context: anytype,
    io: std.Io,
    dest: base_addr.SocketAddr,
    payload: batch.Send,
    caps: batch.Capability,
) SendError!Pass {
    var runs = try batch.Runs.init(payload, caps);
    var pass: Pass = .{};
    // The bytes already sent, which is where a refused run starts: the runs
    // before it left the socket, so the tail is everything behind them.
    var on_wire: usize = 0;
    while (runs.next()) |run| {
        const refused = try context.sendRun(io, dest, run);
        if (refused == .segmentation) {
            // The tail starts on the refused run and not behind it: that run
            // carried nothing, so a tail measured from its end drops it.
            pass.tail = .{
                .ecn = payload.ecn,
                .contents = payload.contents[on_wire..],
                .segment_size = payload.segment_size,
            };
            return pass;
        }
        // Both answers that are not a refused segmentation left the socket.
        on_wire += run.contents.len;
        // Sticky: the run went out, and it went out without the codepoint. The
        // runs behind it carry their own, so nothing here clears this.
        if (refused == .unknown_control_message) pass.refused = refused;
    }
    return pass;
}

fn createSocket(family: batch.Family) OpenError!c.fd_t {
    // A value, not a type alias: `c_uint` is what the switch below evaluates
    // to, and `domain` is the address family this descriptor is opened for.
    // zwanzig-disable-next-line: identifier-style
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

/// The descriptor a stop wakes a wait on, or a refusal to have one.
///
/// A refusal refuses the socket. A socket whose wait cannot be ended is the
/// failure this descriptor exists to prevent, and a caller that opened one
/// anyway would be handed a cancellation that arrives a slice late with nothing
/// to say that it had.
fn createWake() OpenError!c.fd_t {
    const flags = linux.EFD.SEMAPHORE | linux.EFD.NONBLOCK | linux.EFD.CLOEXEC;
    const handle = c.eventfd(0, flags);
    if (handle >= 0) return handle;
    return switch (c.errno(handle)) {
        .ACCES, .PERM => error.PermissionDenied,
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
    // The level is an `int`; the length can be wider than `socklen_t`.
    // Reject unrepresentable values before the syscall rather than trapping
    // during a narrowing cast.
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

// 78 display columns; the rule counts UTF-8 bytes, three per box character.
// ziglint-ignore: Z024
// ───────────────────────────────────────────────────────────────────── tests

const t = std.testing;

// Linux 6.12 recvmsg capture: GRO has an int payload, not UDP_SEGMENT's u16.
// The receive fixture must not use the send codec that made the width mistake.
const KernelGro = extern struct {
    length: usize,
    level: c_int,
    kind: c_int,
    stride: c_int,
};

fn kernelGro(stride: c_int) KernelGro {
    return .{
        .length = cmsgLen(@sizeOf(c_int)),
        .level = @intCast(names.udp_level),
        .kind = @intCast(names.gro),
        .stride = stride,
    };
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

    // A length past what `cmsg_len` spells is the third narrowing, and no
    // caller reaches it: `writeCmsg` builds its lengths from `cmsgLen` over a
    // buffer of `control_size`, a fixed number well inside what any
    // `socklen_t` holds. What that bound cannot say is the width — musl
    // declares the field a `socklen_t` where the kernel reads a `size_t` — and
    // that is the next test.
}

test "a header spells its length in the width the kernel reads" {
    // The kernel copies one whole word out of this buffer for every send it
    // validates a message from, and musl's own `cmsghdr` puts a `socklen_t`
    // and four bytes of padding inside that same word. A header written
    // through the C struct's declared field alone would leave four bytes of an
    // undefined buffer in the middle of the length the kernel reads, and a
    // send refused or not would come to depend on what the stack held. The
    // buffer is poisoned first, so this fails the same way every time instead
    // of passing on a stack that happened to be zeros.
    var messages: [batch.max_cmsg]batch.Cmsg = undefined;
    var control: ControlBuffer = undefined;
    @memset(&control.bytes, 0xaa);
    const written = try writeCmsg(
        batch.cmsg(batch.Send.single(&.{}, .ect1), .v4, &messages),
        &control,
    );

    const word = std.mem.readInt(usize, control.bytes[0..@sizeOf(usize)], endian);
    try t.expectEqual(cmsgLen(batch.tos_width), word);

    // And the message is still the one that was written: the word is the
    // header's own length and not one field too wide into the level.
    const read = readCmsg(written);
    try t.expect(!read.truncated);
    try t.expectEqual(@as(?batch.Ecn, .ect1), read.ecn);
}

test "an IPv4 ECN byte is read even when shorter than the send option" {
    // The kernel's byte payload differs from the integer send option. Spell
    // its native ABI explicitly; a fixed x86_64 capture is invalid on 32-bit
    // and big-endian targets.
    const KernelByte = extern struct {
        length: usize,
        level: c_int,
        kind: c_int,
        codepoint: u8,
    };
    const captured: KernelByte = .{
        .length = @offsetOf(KernelByte, "codepoint") + @sizeOf(u8),
        .level = @intCast(names.ip_level),
        .kind = @intCast(names.ipv4_tos),
        .codepoint = 0b10,
    };
    const read = readCmsg(std.mem.asBytes(&captured)[0..captured.length]);
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
    const stride_message = kernelGro(100);
    const stride_bytes = std.mem.asBytes(&stride_message)[0..stride_message.length];

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
    if (comptime @bitSizeOf(usize) > @bitSizeOf(socklen_t)) {
        // The refusal precedes the syscall, so no backing allocation is needed.
        const nowhere: [*]const u8 = @ptrFromInt(1);
        const too_wide = nowhere[0 .. @as(usize, std.math.maxInt(socklen_t)) + 1];
        try t.expectError(
            error.InvalidValue,
            setOption(-1, names.udp_level, names.segment, too_wide),
        );
    }
    const flag: c_int = 1;

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

/// A writer that answers what a socket answers, and refuses where a test says
/// to.
///
/// `Socket.sendRun` reads a refusal out of the driver, and a driver that
/// refuses a segmented run is a node this suite may not be running on: the one
/// measured here refuses every count of every segment size that is a multiple
/// of 256, which refuses the first run of a batch and leaves nothing on the
/// wire that a replay could send twice. So the answer is scripted, and what
/// the tests assert is what the policy did with it — the runs it handed here,
/// and the `Report` it gave its caller.
///
/// Two ledgers and not one, because an offer is not a datagram: a run refused
/// for segmentation was handed over and never left the socket, and a test
/// that counted it among the runs that went out would add its datagrams a
/// second time and call the batch whole.
const Scripted = struct {
    /// One answer per run offered, in the order the runs are offered, `.none`
    /// for a run that goes out. A shorter list leaves every run past its end
    /// going out.
    answers: []const batch.Refused,
    /// Every run handed over, in the order it was handed over, a refused run
    /// included.
    offered: [16]batch.Send = undefined,
    /// How many there have been.
    offers: usize = 0,
    /// The runs that reached the wire, in the order they reached it.
    sent: [16]batch.Send = undefined,
    /// How many there have been.
    sends: usize = 0,

    fn sendRun(
        self: *Scripted,
        io: std.Io,
        dest: base_addr.SocketAddr,
        run: batch.Send,
    ) SendError!batch.Refused {
        // The two parameters `walkRuns` calls with that this writer has no use
        // for: it is not a socket, so there is no descriptor to be cancelled
        // on and no address of its own to compare `dest` against.
        _ = io;
        _ = dest;
        std.debug.assert(self.offers < self.offered.len);
        const answer = if (self.offers < self.answers.len) self.answers[self.offers] else .none;
        self.offered[self.offers] = run;
        self.offers += 1;
        // What `Socket.sendRun` does with each answer: a refused segmentation
        // comes back before the kernel was asked to segment anything, so that
        // run is an offer and nothing else. An unknown control message is on
        // the wire — that run went out on the retry which dropped the message
        // — and so is every run that drew no refusal at all.
        if (answer != .segmentation) {
            std.debug.assert(self.sends < self.sent.len);
            self.sent[self.sends] = run;
            self.sends += 1;
        }
        return answer;
    }
};

/// The batch every test below shares: eight datagrams of ten bytes on a socket
/// whose cap takes three per run, which is three runs, with the refusal
/// landing on the middle one.
const RefusedMiddle = struct {
    send: batch.Send,
    caps: batch.Capability,
};

fn refusedMiddleRun(payload: []const u8) batch.Error!RefusedMiddle {
    return .{
        .send = try batch.Send.batch(payload, 10, .ect0),
        .caps = .{ .max_send_segments = 3, .max_recv_segments = 1 },
    };
}

test "a refused segmentation is answered with the runs that did not leave" {
    // The first run is on the wire and the last was never reached, so the
    // answer is the tail from the refused run onwards. The batch again would
    // put the first run's three datagrams on the wire a second time.
    var payload: [8 * 10]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @truncate(index);
    var fixture = try refusedMiddleRun(&payload);
    var writer: Scripted = .{ .answers = &.{ .none, .segmentation } };

    _ = try sendBatch(&writer, t.io, loopback, fixture.send, &fixture.caps);

    // Every datagram on the wire exactly once, in order: the runs that were
    // sent, concatenated, are the payload — no run repeated and none missing.
    // The refused run is not among them, because it never reached the wire;
    // a ledger that counted it would charge its three datagrams twice and
    // still call the batch whole.
    var at: usize = 0;
    for (writer.sent[0..writer.sends]) |run| {
        // The run's own claim on the payload, checked before it reads out of
        // it: a repeat steps `at` off the end, and a test that traps on the
        // defect is a test that cannot say what the defect was.
        try t.expect(run.contents.len <= payload.len - at);
        try t.expectEqualSlices(u8, payload[at..][0..run.contents.len], run.contents);
        at += run.contents.len;
    }
    try t.expectEqual(payload.len, at);

    // Seven runs offered and six sent. The middle one was offered, refused,
    // and is what the retry carried again: three datagrams that were not on
    // the wire at any point before it.
    try t.expectEqual(@as(usize, 7), writer.offers);
    try t.expectEqual(@as(usize, 6), writer.sends);
    try t.expectEqual(@as(usize, 3), writer.offered[1].datagramCount());

    // The first run went out as the socket offered to send it; the tail went
    // out one datagram per `sendmsg`, which is what the lowered cap is for.
    try t.expectEqual(@as(usize, 3), writer.sent[0].datagramCount());
    for (writer.sent[1..writer.sends]) |run| {
        try t.expectEqual(@as(usize, 1), run.datagramCount());
    }

    // And the cap is never raised again, so the next send finds out the same
    // way rather than paying for this discovery twice.
    try t.expectEqual(@as(u16, 1), fixture.caps.max_send_segments);
}

test "a batch that took the fallback says it was degraded" {
    var payload: [8 * 10]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @truncate(index);
    var fixture = try refusedMiddleRun(&payload);
    var writer: Scripted = .{ .answers = &.{ .none, .segmentation } };

    const report = try sendBatch(&writer, t.io, loopback, fixture.send, &fixture.caps);

    // The fallback `DECISIONS/0002` promised, made visible rather than a
    // slower wire to notice: the run this socket could take went out as one
    // `sendmsg` and the five datagrams of the tail it refused went out one
    // each, and the caller is told the batch was degraded rather than left to
    // measure it.
    try t.expect(report.degraded);

    // Nothing about the codepoint, because every run this module wrote carried
    // it — the retried tail included.
    try t.expect(report.ecnSurvived());
    try t.expectEqual(@as(?batch.Ecn, .ect0), report.carried);
}

test "a codepoint lost on the retried tail is reported with the degradation" {
    // Both refusals one send can draw: a driver that will not segment, and an
    // IPv4 kernel that does not know `IP_TOS` on the datagram it retries with.
    // The datagram that lost its codepoint is on the wire anyway, so the batch
    // went out slower than it was asked to *and* lost the one thing nothing
    // downstream can get back — which is two facts and not one.
    var payload: [8 * 10]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @truncate(index);
    var fixture = try refusedMiddleRun(&payload);
    var writer: Scripted = .{ .answers = &.{ .none, .segmentation, .unknown_control_message } };

    const report = try sendBatch(&writer, t.io, loopback, fixture.send, &fixture.caps);

    try t.expect(report.degraded);
    try t.expect(!report.ecnSurvived());
    try t.expectEqual(@as(?batch.Ecn, null), report.carried);
    try t.expectEqual(@as(?batch.Ecn, .ect0), report.wanted);

    // The tail went out anyway: a dropped control message is a datagram with
    // no codepoint on it, not a datagram missing, and the refused run that
    // opened the tail is not counted here either.
    var at: usize = 0;
    for (writer.sent[0..writer.sends]) |run| {
        try t.expect(run.contents.len <= payload.len - at);
        at += run.contents.len;
    }
    try t.expectEqual(payload.len, at);
}

test "a codepoint lost before a refused segmentation is reported too" {
    // The two refusals in the order that hides one: a run that goes out
    // without its codepoint, and then a later run this socket will not segment
    // at all. The retry carries that run and every run behind it and none of
    // them is refused, so a report built from the retry alone says a codepoint
    // survived a send that demonstrably dropped it — which is the one loss a
    // caller cannot work out for itself afterwards.
    var payload: [8 * 10]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @truncate(index);
    var fixture = try refusedMiddleRun(&payload);
    var writer: Scripted = .{ .answers = &.{ .unknown_control_message, .segmentation } };

    const report = try sendBatch(&writer, t.io, loopback, fixture.send, &fixture.caps);

    try t.expect(!report.ecnSurvived());
    try t.expectEqual(@as(?batch.Ecn, null), report.carried);
    try t.expectEqual(@as(?batch.Ecn, .ect0), report.wanted);
    // Both facts: the batch went out one datagram at a time after the refused
    // run whatever the retry found, so it was degraded and it lost the
    // codepoint, and a report that can only name one of them is wrong.
    try t.expect(report.degraded);

    // And the tail still went out once, which is what keeps this a report about
    // a codepoint rather than about a datagram: the one that lost it is on the
    // wire, and nothing behind the refused run is sent twice.
    var at: usize = 0;
    for (writer.sent[0..writer.sends]) |run| {
        try t.expect(run.contents.len <= payload.len - at);
        at += run.contents.len;
    }
    try t.expectEqual(payload.len, at);
}

test "a codepoint lost by one datagram is not put back by the next" {
    // A socket with no segmentation offers every datagram on its own, which is
    // the only shape in which a run can lose its codepoint and be followed by
    // another run: the one behind it carried the message the kernel refused
    // here. The batch lost it, and a later run going out with it does not make
    // the batch whole again — the caller decides what one datagram without a
    // codepoint means, and it can only do that if it is told.
    var payload: [8 * 10]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @truncate(index);
    const send = try batch.Send.batch(&payload, 10, .ect0);
    var caps: batch.Capability = .{ .max_send_segments = 1, .max_recv_segments = 1 };
    var writer: Scripted = .{ .answers = &.{.unknown_control_message} };

    const report = try sendBatch(&writer, t.io, loopback, send, &caps);

    // No segmentation was ever refused here, so nothing about the batch is
    // degraded: one `sendmsg` per datagram is how this socket sends every
    // batch, not a fallback it took.
    try t.expect(!report.degraded);
    try t.expect(!report.ecnSurvived());
    try t.expectEqual(@as(?batch.Ecn, null), report.carried);

    // Every datagram went out anyway, all eight of them, none of them twice.
    // Every offer here was a send as well, which is what makes this the shape
    // where no run is ever refused and the two ledgers cannot differ.
    try t.expectEqual(@as(usize, 8), writer.sends);
    try t.expectEqual(@as(usize, 8), writer.offers);
    var at: usize = 0;
    for (writer.sent[0..writer.sends]) |run| at += run.contents.len;
    try t.expectEqual(payload.len, at);
}

test "a kernel GRO integer defines datagram boundaries, and a short value does not" {
    var message = kernelGro(14);
    const read = readCmsg(std.mem.asBytes(&message)[0..message.length]);
    try t.expectEqual(@as(?usize, 14), read.stride);
    try t.expectEqual(@as(?batch.Ecn, null), read.ecn);
    try t.expect(!read.truncated);

    var payload: [42]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @intCast(index);
    const received = try batch.Recv.init(&payload, read.stride, null);
    try t.expectEqual(@as(usize, 3), received.datagramCount());
    try t.expectEqualSlices(u8, payload[14..28], received.datagram(1).?);
    try t.expect(received.datagram(3) == null);

    message.length = cmsgLen(@sizeOf(u16));
    const short = readCmsg(std.mem.asBytes(&message)[0..message.length]);
    try t.expectEqual(@as(?usize, null), short.stride);
}

// 79 display columns; the rule counts UTF-8 bytes, three per box character.
// ziglint-ignore: Z024
// ──────────────────────────────────────────────────────── a stop, on a socket
//
// The wake descriptor is a claim about two descriptors and a `poll` set, and a
// claim about descriptors is worth only what the kernel says about them. Every
// other test in this file stays above the syscall on purpose; this one does
// not, because there is nothing above the syscall to ask.

/// Loopback on an ephemeral port, so the kernel picks and two tests at once
/// cannot collide. The spelling `test/loopback_test.zig` uses.
const loopback: base_addr.SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 0 };

test "a stop ends its wait, and the next query out takes the queue with it" {
    var server = try Socket.create(loopback, .{});
    defer server.close();
    var client = try Socket.create(loopback, .{});
    defer client.close();
    var untouched = try Socket.create(loopback, .{});
    defer untouched.close();
    var buffer: [64]u8 = undefined;
    var control: ControlBuffer = undefined;
    const straggler = "the answer to a query nobody is waiting for";
    const query = "the next query";

    // What a stop has to deal with, shown first where nothing has stopped
    // anything: on loopback the kernel has the datagram queued by the time
    // `sendmsg` answers, and a read finds it. Without this the `WouldBlock` at
    // the end of the test would be satisfied just as well by nothing having
    // been queued in the first place.
    _ = try server.send(t.io, untouched.address, batch.Send.single(straggler, null));
    const found = try untouched.tryReceive(t.io, &buffer, &control);
    try t.expectEqualStrings(straggler, found.bytes);

    // The wait the stop is aimed at. Five seconds, and it ends long before
    // that: nothing was sent to this socket and nothing can be, so the only
    // thing that can end the wait is the descriptor `stop` wrote to. Leave it
    // out of the `poll` set and this is a wait that runs out and answers
    // `WouldBlock` — a deadline reported for a cancellation that had already
    // been asked for.
    client.stop();
    try t.expectError(error.Canceled, client.receive(t.io, &buffer, &control, 5000));

    // The answer, arriving after the stop. It is the send below that takes it,
    // not the wait above, because nothing was waiting when it landed: a
    // datagram queued before the next query went out cannot be that query's
    // answer, whichever of the two arrived first.
    _ = try server.send(t.io, client.address, batch.Send.single(straggler, null));
    _ = try client.send(t.io, server.address, batch.Send.single(query, null));
    try t.expectError(error.WouldBlock, client.tryReceive(t.io, &buffer, &control));

    // And the socket is the caller's again. The wake was spent with the stop,
    // so this wait waits instead of being ended by one already dealt with, and
    // fifty milliseconds is long enough for a datagram sent first to be there.
    _ = try server.send(t.io, client.address, batch.Send.single(query, null));
    const read = try client.receive(t.io, &buffer, &control, 50);
    try t.expectEqualStrings(query, read.bytes);
    try t.expectEqual(server.address, read.from);
}

test "a stop drains every queued datagram, and the next answer is not a leftover" {
    var server = try Socket.create(loopback, .{});
    defer server.close();
    var client = try Socket.create(loopback, .{});
    defer client.close();
    var buffer: [64]u8 = undefined;
    var control: ControlBuffer = undefined;
    const first = "the answer to a query nobody is waiting for";
    const second = "and the answer to the query after it";
    const query = "the next query";
    const answer = "this query's own answer";

    // Both stragglers are real datagrams, shown first where nothing has
    // stopped anything, so the `WouldBlock` below can only be the queue
    // having been drained rather than never having been filled.
    var untouched = try Socket.create(loopback, .{});
    defer untouched.close();
    _ = try server.send(t.io, untouched.address, batch.Send.single(first, null));
    _ = try server.send(t.io, untouched.address, batch.Send.single(second, null));
    try t.expectEqualStrings(first, (try untouched.tryReceive(t.io, &buffer, &control)).bytes);
    try t.expectEqualStrings(second, (try untouched.tryReceive(t.io, &buffer, &control)).bytes);

    // The same two queued on the socket that is about to be stopped. A stop
    // empties the queue, and two datagrams is the smallest case that can
    // tell emptying it from emptying only the first datagram it read: a
    // drain that stops after one leaves the second, and that second is
    // exactly what the receive at the end would report as the answer.
    _ = try server.send(t.io, client.address, batch.Send.single(first, null));
    _ = try server.send(t.io, client.address, batch.Send.single(second, null));
    client.stop();

    // The send is the drain: this is where a stopped socket becomes usable
    // again, and everything the stop found queued goes with it. `WouldBlock`
    // is the only answer that says the queue is empty rather than that a
    // leftover duplicate is waiting in it.
    _ = try client.send(t.io, server.address, batch.Send.single(query, null));
    try t.expectError(error.WouldBlock, client.tryReceive(t.io, &buffer, &control));

    // And the answer to the query that just went out is the next thing read,
    // from the peer that was asked. Fifty milliseconds bounds the wait; the
    // datagram is already queued by the time `sendmsg` above returned, so the
    // criterion is the bytes and not the clock.
    _ = try server.send(t.io, client.address, batch.Send.single(answer, null));
    const read = try client.receive(t.io, &buffer, &control, 50);
    try t.expectEqualStrings(answer, read.bytes);
    try t.expectEqual(server.address, read.from);
}

test "two stops leave no wake standing for the receive that follows the send" {
    var server = try Socket.create(loopback, .{});
    defer server.close();
    var client = try Socket.create(loopback, .{});
    defer client.close();
    var buffer: [64]u8 = undefined;
    var control: ControlBuffer = undefined;
    const query = "the query the send carries";
    const answer = "this query's own answer";

    // The wake descriptor is an `eventfd` in semaphore mode: each `stop` adds
    // one unit to the counter and each read takes one off. Two stops leave two
    // units standing, and the send that resets the stop has to spend both. A
    // unit left behind is a wake nobody asked for, and it ends the next wait
    // exactly the way a real stop would.
    client.stop();
    client.stop();

    // The send resets the stop, spending the counter as it goes, and carries
    // the query whatever the two stops were about.
    _ = try client.send(t.io, server.address, batch.Send.single(query, null));

    // The answer to the query that just went out. With the counter empty the
    // wait ends on the datagram and reads it; with a unit still standing the
    // wait ends on the wake instead and reports `Canceled` for a stop the send
    // has already dealt with — and takes the answer with it.
    _ = try server.send(t.io, client.address, batch.Send.single(answer, null));
    const read = try client.receive(t.io, &buffer, &control, 50);
    try t.expectEqualStrings(answer, read.bytes);
    try t.expectEqual(server.address, read.from);
}

test "a queue or a counter past its bound is refused, and the next send takes it" {
    var server = try Socket.create(loopback, .{});
    defer server.close();
    var client = try Socket.create(loopback, .{});
    defer client.close();
    var buffer: [64]u8 = undefined;
    var control: ControlBuffer = undefined;
    const query = "the query the send carries";
    const answer = "this query's own answer";
    // One byte, so the whole queue this fills costs the kernel a fraction of
    // the receive buffer it opens with: the datagrams have to be *queued*,
    // and a queue the kernel dropped some of would make the bounds below
    // unreachable rather than wrong.
    const filler = [_]u8{0x5a};

    // One datagram past `max_discarded`, which is the depth at which a drain
    // can no longer promise the queue is empty. The bound is on the datagrams
    // and not on the syscalls, so the read that finds the queue still deep is
    // the one that has to refuse.
    for (0..max_discarded + 1) |_| {
        _ = try server.send(t.io, client.address, batch.Send.single(&filler, null));
    }
    client.stop();

    // Nothing goes out on a refused cleanup, and the socket stays stopped
    // rather than clean with a straggler in it: that straggler was queued
    // before this query went out, so reading it as the answer is the fault
    // the bound exists to prevent.
    try t.expectError(
        error.Interrupted,
        client.send(t.io, server.address, batch.Send.single(query, null)),
    );

    // The next send drains the rest and carries the query, and `WouldBlock`
    // after it says the queue really is empty — not merely emptied as far as
    // one call's bound goes.
    _ = try client.send(t.io, server.address, batch.Send.single(query, null));
    try t.expectError(error.WouldBlock, client.tryReceive(t.io, &buffer, &control));

    // The same bound on the counter, one `stop` past `max_wakes_spent`. A unit
    // left standing is a wake nobody asked for, and it ends the next wait the
    // way a real stop would, so a counter this deep is refused for the same
    // reason and dealt with by the same retry. Nothing is queued here, which
    // is what makes this the counter's bound and not the queue's.
    for (0..max_wakes_spent + 1) |_| client.stop();
    try t.expectError(
        error.Interrupted,
        client.send(t.io, server.address, batch.Send.single(query, null)),
    );

    // And the answer is what the wait after that reads, which is the whole of
    // what spending the counter is for: with a unit still on it the wait would
    // end on the wake and answer `Canceled` for a stop the send has dealt
    // with, taking the answer with it.
    _ = try client.send(t.io, server.address, batch.Send.single(query, null));
    _ = try server.send(t.io, client.address, batch.Send.single(answer, null));
    const read = try client.receive(t.io, &buffer, &control, 50);
    try t.expectEqualStrings(answer, read.bytes);
    try t.expectEqual(server.address, read.from);
}

/// A recovery with a real stop raised inside it.
///
/// The windows are the two moments between taking the queue and the send being
/// a send again, and the only thing that happens in either of them in
/// production is another task's `Socket.stop`. So the test raises one there —
/// on a real socket, with a real drain and a real counter — rather than
/// describing one and asserting the description back.
const StopWindow = enum {
    /// After the drain and before the flag is cleared: the stop has set the
    /// flag again and the line that clears it is next.
    drain,
    /// After the flag is cleared and before the counter is emptied: the check
    /// that decides whether to empty it has answered, and this stop's unit is
    /// the one the read about to take.
    wake,
};

const StopDuringRecovery = struct {
    /// The real socket, so every call below is the real one.
    socket: *Socket,
    /// The real flag, borrowed rather than copied: an atomic copied out of the
    /// socket it belongs to is a second flag, and the whole question here is
    /// what the socket's own flag says.
    stopped: *std.atomic.Value(bool),
    /// Which of the two windows this run raises its stop in.
    window: StopWindow,

    fn discard(
        self: *StopDuringRecovery,
        io: std.Io,
    ) error{ Canceled, Interrupted, Unexpected }!void {
        try self.socket.discard(io);
        if (self.window == .drain) self.socket.stop();
    }

    fn clearWake(self: *StopDuringRecovery) error{Interrupted}!void {
        if (self.window == .wake) self.socket.stop();
        return self.socket.clearWake();
    }

    /// The socket's own way of raising a wake, which a recovery that owes a
    /// waiter one has to use rather than write its own.
    fn stop(self: *StopDuringRecovery) void {
        self.socket.stop();
    }
};

/// What a stop raised inside the recovery must leave behind, in either window:
/// the flag up, and a wake unit standing for it.
///
/// Both halves are needed and neither is enough. A flag that went down loses
/// the stop outright — nothing queued after it would ever be drained again. A
/// unit spent for it leaves a wait that nothing ends, because `awaitReadable`
/// reads the wake descriptor and nothing else.
fn expectStopSurviving(window: StopWindow) !void {
    var speaker = try Socket.create(loopback, .{});
    defer speaker.close();
    var socket = try Socket.create(loopback, .{});
    defer socket.close();
    var buffer: [64]u8 = undefined;
    var control: ControlBuffer = undefined;
    const straggler = "the answer to a query nobody is waiting for";

    // A stopped socket with something queued is the state the recovery exists
    // for: the queue goes with the stop, and the wake that stop left is spent
    // so the wait after this send is not woken for a stop already dealt with.
    _ = try speaker.send(t.io, socket.address, batch.Send.single(straggler, null));
    socket.stop();
    var recovery: StopDuringRecovery = .{
        .socket = &socket,
        .stopped = &socket.stopped,
        .window = window,
    };

    try restart(&recovery, t.io);

    try t.expect(socket.stopped.load(.acquire));

    // Claiming the flag the way a send would leaves exactly what a live stop
    // leaves: an empty queue and one unit for it. The quarter of a second is
    // only there so that a unit which is *not* standing fails in a quarter of
    // a second rather than in five — a unit that is standing ends the wait on
    // the descriptor, with no clock involved at all.
    _ = socket.stopped.swap(false, .acq_rel);
    try t.expectError(error.Canceled, socket.receive(t.io, &buffer, &control, 250));
    try t.expectError(error.WouldBlock, socket.tryReceive(t.io, &buffer, &control));
}

// Two tests and not one with two cases: a case that fails stops the test
// before the next one runs, and these two fail for different reasons — one
// loses the flag, the other loses only the wake — so a single test would
// report the first and hide the second.
test "a stop raised after the drain survives the recovery" {
    try expectStopSurviving(.drain);
}

test "a stop raised as the counter is emptied survives the recovery" {
    try expectStopSurviving(.wake);
}

// 79 display columns; the rule counts UTF-8 bytes, three per box character.
// ziglint-ignore: Z024
// ──────────────────────────────────────────────────────── a batch, on loopback
//
// A duplicate datagram is a fact about the wire and not about a return value:
// a policy that re-sends a run the kernel already took reports the same batch
// and hands its caller the same `Report`, and the only place a second copy of
// a datagram exists is the socket at the other end of it. So this one sends
// for real and reads back what arrived, which is the one claim the scripted
// policy tests cannot make on their own.

/// The most bytes one read may hand back: `UDP_GRO_CNT_MAX` coalesced
/// datagrams of the kilobyte this section sends.
///
/// The count is promoted before the product rather than after it, because it
/// is a `u16` of segments and 64 of them at 1024 bytes is 65536 — one past
/// the largest value the count it came from can hold.
const max_read_bytes: usize = @as(usize, batch.max_gro_segments_linux) * 1024;

test "a batch reaches the wire as its datagrams, once each" {
    var sender = try Socket.create(loopback, .{});
    defer sender.close();
    var receiver = try Socket.create(loopback, .{});
    defer receiver.close();
    // A read this socket hands back may be coalesced: `UDP_GRO` puts as many
    // equal datagrams in one buffer as it is willing to coalesce, each as long
    // as the datagram it took, and a buffer shorter than that gets a read
    // truncated — which `recvmsg` reports as `MSG_TRUNC` and this module as
    // `MessageTooLarge`. Sized for the largest coalesced read rather than for
    // what the sender happened to write.
    var buffer: [max_read_bytes]u8 = undefined;
    var control: ControlBuffer = undefined;

    // Seventy datagrams of a kilobyte: more than one run's worth at this
    // segment size, so the socket has to take the fallback or answer with
    // several `sendmsg`s, and every datagram is filled with its own index so
    // that one which arrives twice is visible in the bytes and not only in
    // the count.
    const datagrams = 70;
    var payload: [datagrams * 1024]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @truncate(index / 1024);

    const sent = try batch.Send.batch(&payload, 1024, .ect0);
    const report = try sender.send(t.io, receiver.address, sent);
    // The codepoint is on every run this module writes, including a fallback's,
    // so a send that reports it lost lost it to a kernel that refused the
    // message rather than to the degradation below.
    try t.expect(report.ecnSurvived());
    try t.expectEqual(@as(?batch.Ecn, .ect0), report.carried);

    // Everything the kernel has, and no more: a datagram sent twice is twice
    // on this wire, and a receiver that stopped at the expected count would
    // step over the second copy rather than see it. The queue is empty when
    // the reads end, and it was filled before `send` returned.
    var seen: usize = 0;
    while (true) {
        const read = receiver.tryReceive(t.io, &buffer, &control) catch |err| switch (err) {
            error.WouldBlock => break,
            else => return err,
        };
        const coalesced = try read.toRecv();
        for (0..coalesced.datagramCount()) |index| {
            const datagram = coalesced.datagram(index) orelse return error.TestUnexpectedResult;
            try t.expect(seen < datagrams);
            try t.expectEqualSlices(u8, payload[seen * 1024 ..][0..datagram.len], datagram);
            seen += 1;
        }
    }
    try t.expectEqual(@as(usize, datagrams), seen);
}
