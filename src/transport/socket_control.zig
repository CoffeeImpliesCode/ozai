//! The descriptors themselves: opening them, naming them, and asking what a
//! kernel will do with them.
//!
//! `transport/socket.zig` owns a `Socket`; this file owns every call that has
//! to happen before there is one or before there is anything to send on it.
//! Four steps, and the one function that runs them in order:
//!
//!   * `createSocket` and `createWake` — the two descriptors, opened with
//!     every flag that has to be set before the first byte.
//!   * `bindSocket` and `boundAddress` — the name the caller asked for and the
//!     name the kernel settled on, ephemeral port included.
//!   * `probe` and what it is built from — the two capability answers, asked
//!     once, where a guessed `Capability` would be worse than none.
//!   * `setOption` and the flags above it — the one `setsockopt` every other
//!     option in this module is a spelling of.
//!
//!   * `open` — the four steps above, in the order they have to happen in.
//!
//! **The order they happen in is a socket-wide fact, so the order is here
//! too.** `open` below is the whole of it: descriptor, reuse options,
//! capability probe, wake, bind, name read back. Both reuse options take
//! effect before the bind, and the congestion option has to be probed after
//! them, because the port is not the socket's until `bind` answers and a
//! socket refused on its own options never reached the point of having a wait
//! to wake. A caller that ran the steps in another order would get a working
//! socket with a wrong capability, which is the failure `probe` exists to
//! prevent.
//!
//! **A `Capability` here is asked for, never assumed.** A driver that quietly
//! ignores `UDP_SEGMENT` turns every batch into a stalled path and nothing
//! reports it, which is why `probe` refuses the socket outright when the
//! congestion option is not there and only lowers the segmentation answer when
//! the kernel says so.
//!
//! `max_syscall_attempts` is here because it is the bound every interrupted
//! syscall on this socket is given, and `socket_send.zig` and
//! `socket_receive.zig` are the loops that read it. It is a socket-wide fact
//! rather than one call's, and the module that owns the descriptor is where a
//! socket-wide fact about it belongs.

const std = @import("std");
const batch = @import("batch.zig");
const base_addr = @import("../base/addr.zig");
const ancillary = @import("ancillary.zig");

const c = std.c;
const linux = std.os.linux;

/// `batch.linux`, under the name this file uses for it.
const names = batch.linux;

const socklen_t = c.socklen_t;

/// How many times one syscall is retried after a signal before the call is
/// declared interrupted. A signal is not a fact about a datagram and retrying
/// is the only correct answer; the bound is what stops a storm of them from
/// becoming a hang.
pub const max_syscall_attempts = 4;

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

/// A socket and its wake, bound and ready to carry a datagram.
///
/// The four values `open` had to learn to build a `Socket`, and nothing else:
/// which descriptors, what the socket can do, which family decides which
/// control message carries the codepoint, and where the kernel actually bound
/// it. It is a value rather than a callback so that `socket.zig`'s `create` is
/// the naming of this and not a second copy of it.
pub const Bound = struct {
    /// The datagram descriptor, `O_NONBLOCK` from the moment it existed.
    handle: c.fd_t,
    /// The descriptor a stop writes to.
    wake: c.fd_t,
    /// What the socket said it can do, asked once at open.
    caps: batch.Capability,
    /// Which control message carries the codepoint here.
    family: batch.Family,
    /// Where it is bound, with the ephemeral port the kernel chose written in.
    address: base_addr.SocketAddr,
};

/// Open a datagram socket on `address`, set `options`, ask what it can do,
/// and bind it.
///
/// The probe runs here and only here. A `Capability` that is guessed rather
/// than asked is worse than none, because a driver that quietly ignores
/// `UDP_SEGMENT` turns every batch into a stalled path and nothing reports it.
///
/// **On success both descriptors are owned by the caller** and a refusal at
/// any step closes the ones already opened: a socket that was never bound and
/// a wake nobody will ever wait on are both leaks, and neither is visible from
/// the error. Do not close either descriptor again; `socket.zig`'s `close` is
/// the one release.
pub fn open(address: base_addr.SocketAddr, options: Options) OpenError!Bound {
    const family: batch.Family = batch.Family.of(address.ip);
    const handle = try createSocket(family);
    errdefer _ = c.close(handle);
    // Reuse options first and the congestion option after, because both take
    // effect before the bind: the port is not the socket's until `bind`
    // answers.
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
    // After the probe: a socket refused on its own options never reached the
    // point of having a wait to wake.
    const wake = try createWake();
    errdefer _ = c.close(wake);
    var name: c.sockaddr.storage = undefined;
    const length = ancillary.writeSockaddr(address, &name);
    try bindSocket(handle, &name, length);
    return .{
        .handle = handle,
        .wake = wake,
        .caps = caps,
        .family = family,
        .address = try boundAddress(handle),
    };
}

/// Open the datagram descriptor for `family`.
pub fn createSocket(family: batch.Family) OpenError!c.fd_t {
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
///
/// An `eventfd` rather than a self-pipe: one descriptor instead of two, a
/// counter instead of a byte buffer, and `EFD_SEMAPHORE` makes a read take one
/// wake off the counter rather than all of them.
pub fn createWake() OpenError!c.fd_t {
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

/// Give `handle` the name the caller asked for, in the kernel's own layout.
pub fn bindSocket(
    handle: c.fd_t,
    name: *const c.sockaddr.storage,
    length: socklen_t,
) OpenError!void {
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

/// The address `handle` is bound to, ephemeral port written in by the kernel.
pub fn boundAddress(handle: c.fd_t) OpenError!base_addr.SocketAddr {
    var name: c.sockaddr.storage = undefined;
    var length: socklen_t = @sizeOf(c.sockaddr.storage);
    const rc = c.getsockname(handle, @as(*c.sockaddr, @ptrCast(&name)), &length);
    if (c.errno(rc) != .SUCCESS) return error.Unexpected;
    return ancillary.readSockaddr(&name) orelse error.AddressNotAvailable;
}

/// What this socket can do, asked once, at open.
///
/// `batch.socketOptions` names the two answers that matter: the congestion
/// option and `UDP_GRO`. Asking for `UDP_GRO` *is* the probe for it, because
/// a socket that refuses it has said the kernel does not have it and there is
/// nothing to ask twice. The congestion option has no such reading, so a
/// refusal there refuses the socket.
pub fn probe(handle: c.fd_t, family: batch.Family) OpenError!batch.Capability {
    const requested = batch.socketOptions(family, true);
    try requireCongestionOption(handle, requested[0]);
    const recv = trySetFlag(handle, requested[1]) catch |err| return openFromOption(err);
    const send = probeSegmentation(handle) catch |err| return openFromOption(err);
    return batch.capability(send, recv);
}

/// Turn a flag on or off, or answer why the kernel would not.
///
/// Both reuse options and the two capability options go through this, so the
/// level's and the length's narrowings are made once for all of them.
pub fn setFlag(handle: c.fd_t, level: u32, name: u32, value: bool) OptionError!void {
    const flag: c_int = if (value) 1 else 0;
    return setOption(handle, level, name, std.mem.asBytes(&flag));
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

/// Why a refused option refuses the socket, for the two reuse options
/// `Socket.create` sets before it probes anything. The congestion option has
/// its own name above and goes through `requireCongestionOption` instead.
pub fn openFromOption(err: OptionError) OpenError {
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
