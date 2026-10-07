//! Opening the descriptor and asking it what it can do: `socket`, `bind`,
//! `setsockopt`, `getsockopt`, `eventfd`, and the two probes.
//!
//! Split out of `transport/socket.zig`, which is now the facade over this and
//! five other named modules. The boundary is the moment before the socket
//! exists: `Socket.create` is what sequences these, and every line below is one
//! syscall wrapper and the errno names it has, with no state of its own. The
//! probe runs here and only here, because a `Capability` that is guessed rather
//! than asked is worse than none — a driver that quietly ignores `UDP_SEGMENT`
//! turns every batch into a stalled path and nothing reports it.

const std = @import("std");
const batch = @import("batch.zig");
const base_addr = @import("../base/addr.zig");
const socket_addr = @import("socket_addr.zig");
const socket_error = @import("socket_error.zig");

const c = std.c;
const linux = std.os.linux;

const socklen_t = c.socklen_t;

/// `batch.linux`, under the name this file uses for it: the two option numbers
/// the segmentation probe names. See `batch.zig` for where they come from.
const names = batch.linux;

const readSockaddr = socket_addr.readSockaddr;
const OptionError = socket_error.OptionError;
const OpenError = socket_error.OpenError;

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

pub fn boundAddress(handle: c.fd_t) OpenError!base_addr.SocketAddr {
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
pub fn probe(handle: c.fd_t, family: batch.Family) OpenError!batch.Capability {
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

pub fn setFlag(handle: c.fd_t, level: u32, name: u32, value: bool) OptionError!void {
    const flag: c_int = if (value) 1 else 0;
    return setOption(handle, level, name, std.mem.asBytes(&flag));
}

pub fn setOption(handle: c.fd_t, level: u32, name: u32, value: []const u8) OptionError!void {
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
