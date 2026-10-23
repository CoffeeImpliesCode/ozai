//! Every syscall a connect-only TCP stream makes, each with the errno names its
//! own answers.
//!
//! Split out of `transport/tcp.zig` for the reason `transport/socket_msg.zig`
//! gives: a struct's methods cannot be split across files, so the calls are
//! free functions over a descriptor that the struct owns. The errno tables sit
//! here with the one call each of them answers for, because a stream that
//! cannot tell `EPIPE` from `EAGAIN` has a failure it invented — the first is
//! a peer that is gone and the second is a send buffer that is full, and
//! collapsing them is how a short write becomes a lost write.
//!
//! The wake descriptor is the one thing here that is not a socket call, and it
//! is not re-implemented: `transport/socket_open.zig`'s `createWake` is the
//! same `eventfd` with the same three flags, and `boundAddress` is the same
//! `getsockname`. This module reuses both rather than writing a second
//! spelling, which is also why it reaches `transport/batch.zig` — through
//! `socket_error`'s `OpenError`, not for anything of its own.
//!
//! `socket(2)` is the one call whose errno table cannot be reused, and the
//! reason is worth saying: `socket_open.createSocket` takes a `batch.Family`
//! and hardcodes `SOCK_DGRAM | IPPROTO_UDP`, because that is the whole of what
//! a UDP socket is. A stream is `SOCK_STREAM | IPPROTO_TCP`, and making that
//! an argument of a function in an owned file is a change this module is not
//! authorised to make. So the table below is spelled once, here, and the two
//! tables agree on every errno they both name.

const std = @import("std");

const base_addr = @import("../base/addr.zig");
const socket_addr = @import("socket_addr.zig");
const socket_open = @import("socket_open.zig");

const tcp_error = @import("tcp_error.zig");

const c = std.c;
const linux = std.os.linux;

const ConnectError = tcp_error.ConnectError;
const OpenError = tcp_error.OpenError;
const ReadError = tcp_error.ReadError;
const WriteError = tcp_error.WriteError;

const socklen_t = c.socklen_t;
const writeSockaddr = socket_addr.writeSockaddr;

/// How many times one syscall is retried after a signal before the call is
/// declared interrupted.
///
/// A signal is not a fact about a connection and retrying is the only correct
/// answer; the bound is what stops a storm of them from becoming a hang.
/// `transport/socket_msg.zig` uses the same figure for the same reason, and
/// this is a re-declaration of it in a file that has no socket message
/// syscall to share the declaration with.
pub const max_syscall_attempts: usize = 4;

/// Open a stream descriptor for `address`'s family, non-blocking from the
/// moment it exists.
pub fn createStream(address: base_addr.IpAddress) OpenError!c.fd_t {
    // A value, not a type alias: `c_uint` is what the switch below evaluates
    // to, and `domain` is the address family this descriptor is opened for.
    // zwanzig-disable-next-line: identifier-style
    const domain: c_uint = switch (address) {
        .v4 => linux.AF.INET,
        .v6 => linux.AF.INET6,
    };
    // `NONBLOCK` in the type rather than an `fcntl` afterwards, so there is no
    // window in which the descriptor exists and blocks. `CLOEXEC` in the same
    // call, so a descriptor cannot leak across an `exec` either.
    const kind: c_uint = linux.SOCK.STREAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK;
    const handle = c.socket(domain, kind, linux.IPPROTO.TCP);
    if (handle >= 0) return handle;
    return switch (c.errno(handle)) {
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

/// Start a connect to `peer` and say whether it finished.
///
/// `true` when the descriptor is connected on return, which is the loopback
/// case and the only one where `connect(2)` answers at once. `false` when the
/// handshake is in the kernel, and the caller has to wait for it — the wait is
/// a `poll` on the descriptor for writability, which is the whole reason it was
/// opened non-blocking.
///
/// A refusal leaves the descriptor exactly as it was. A failed connect does not
/// make a descriptor reusable: it has to be closed, because RFC 9293 §3.4.1
/// leaves the state of a socket after `ECONNREFUSED` implementation-defined and
/// no retry on the same descriptor can rely on it.
pub fn beginConnect(
    io: std.Io,
    handle: c.fd_t,
    peer: base_addr.SocketAddr,
) ConnectError!bool {
    var name: c.sockaddr.storage = undefined;
    const length = writeSockaddr(peer, &name);
    try io.checkCancel();
    const rc = c.connect(handle, @as(*const c.sockaddr, @ptrCast(&name)), length);
    return switch (c.errno(rc)) {
        .SUCCESS => true,
        // EINTR may already have started the handshake; never repeat connect.
        .INPROGRESS, .ALREADY, .AGAIN, .INTR => false,
        else => |errno| connectFromErrno(errno),
    };
}

/// The reason a connect that was in progress did not finish.
///
/// `SO_ERROR`, read back the only way a non-blocking connect learns its own
/// outcome: the syscall that started the handshake returned long before the
/// handshake did, and the errno it would have reported lives on the socket
/// until it is asked for. `error.Unexpected` covers a `getsockopt` that
/// refused or that answered with a width this module does not expect, and both
/// are "the outcome is not knowable" rather than any one failure.
pub fn connectResult(handle: c.fd_t) ConnectError!void {
    var value: c_int = 0;
    var length: socklen_t = @sizeOf(c_int);
    // `getsockopt` spells its level as an `int` and `linux.SO.ERROR` is a
    // `u32`, so the narrowing is proved here rather than left to a cast that
    // traps in Debug on a value which does not fit.
    const level = std.math.cast(c_int, linux.SOL.SOCKET) orelse return error.Unexpected;
    if (c.getsockopt(handle, level, linux.SO.ERROR, &value, &length) != 0) {
        return error.Unexpected;
    }
    if (length != @sizeOf(c_int)) return error.Unexpected;
    if (value == 0) return;
    return connectFromErrno(@enumFromInt(value));
}

fn connectFromErrno(errno: c.E) ConnectError {
    return switch (errno) {
        .CONNREFUSED => error.ConnectionRefused,
        .TIMEDOUT => error.ConnectionTimedOut,
        .NETUNREACH => error.NetworkUnreachable,
        .HOSTUNREACH => error.HostUnreachable,
        .NETDOWN => error.NetworkDown,
        .ADDRNOTAVAIL => error.AddressNotAvailable,
        .ACCES, .PERM => error.PermissionDenied,
        .CONNRESET => error.ConnectionReset,
        .NOMEM, .NOBUFS => error.ResourcesExhausted,
        // SO_ERROR may itself still describe an interrupted outcome.
        .INTR => error.Interrupted,
        // `EAGAIN` here is a kernel that has not decided yet rather than a
        // refusal, and the caller that asked for a result expects a decision.
        .AGAIN => error.Interrupted,
        else => error.Unexpected,
    };
}

/// Put as much of `bytes` on the wire as the stream takes, and say how much
/// that was.
///
/// **A short count is the answer and not a refusal.** A stream has no message
/// boundary and no datagram size limit, so `send(2)` takes whatever fits in
/// the send buffer and returns that count; anything else would have to be an
/// error, and an error here with no count is the one thing that loses a
/// caller's bytes — the caller cannot then tell how much of its buffer left
/// the host and how much to resume from. So the count is the whole contract,
/// and a caller resumes at `bytes[written..]`.
///
/// `NOSIGNAL` because a stream write to a peer that is gone must answer here
/// rather than raise `SIGPIPE` there, which would take down whichever task
/// happened to hold the thread. `EPIPE` then arrives as `error.PeerClosed`
/// with nothing written.
pub fn sendStream(io: std.Io, handle: c.fd_t, bytes: []const u8) WriteError!usize {
    var attempt: usize = 0;
    while (attempt < max_syscall_attempts) : (attempt += 1) {
        try io.checkCancel();
        const rc = c.send(handle, bytes.ptr, bytes.len, linux.MSG.NOSIGNAL);
        switch (c.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            // The send buffer is full. Backpressure the caller waits out, and
            // not one byte of `bytes` left, so there is nothing to reconcile.
            .AGAIN => return error.WouldBlock,
            .PIPE => return error.PeerClosed,
            .CONNRESET => return error.ConnectionReset,
            .NOTCONN, .DESTADDRREQ => return error.NotConnected,
            .NOMEM, .NOBUFS => return error.ResourcesExhausted,
            else => return error.Unexpected,
        }
    }
    return error.Interrupted;
}

/// Take up to `buffer.len` bytes, and say how many there were.
///
/// **A zero is the answer and not a refusal**, and `read(2)` is the standard
/// for why: a return of zero is how POSIX spells end-of-file, and for a stream
/// that is the peer's `shutdown(SHUT_WR)` or its last `close`. It is a count
/// and not an error because the peer that half-closed can still read — the
/// other direction is open until this one closes it — so a refusal here would
/// tell a caller the stream is finished when it is only half finished.
pub fn recvStream(io: std.Io, handle: c.fd_t, buffer: []u8) ReadError!usize {
    var attempt: usize = 0;
    while (attempt < max_syscall_attempts) : (attempt += 1) {
        try io.checkCancel();
        const rc = c.recv(handle, buffer.ptr, buffer.len, 0);
        switch (c.errno(rc)) {
            // Zero falls out of here as a count, which is the decision this
            // function's doc states: EOF is a value.
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            // Nothing queued. A value and not a failure; the caller decides
            // what an empty interval means.
            .AGAIN => return error.WouldBlock,
            .CONNRESET => return error.ConnectionReset,
            .NOTCONN => return error.NotConnected,
            .NOMEM, .NOBUFS => return error.ResourcesExhausted,
            else => return error.Unexpected,
        }
    }
    return error.Interrupted;
}

pub fn listenStream(io: std.Io, handle: c.fd_t) tcp_error.ListenError!void {
    var attempt: usize = 0;
    while (attempt < max_syscall_attempts) : (attempt += 1) {
        try io.checkCancel();
        switch (c.errno(c.listen(handle, 128))) {
            .SUCCESS => return,
            .INTR => continue,
            .ADDRINUSE => return error.AddressInUse,
            .ACCES, .PERM => return error.PermissionDenied,
            .NOMEM, .NOBUFS => return error.ResourcesExhausted,
            .OPNOTSUPP => return error.SocketModeUnsupported,
            .INVAL => return error.InvalidArgument,
            else => return error.Unexpected,
        }
    }
    return error.Interrupted;
}

pub fn acceptStream(
    io: std.Io,
    handle: c.fd_t,
) tcp_error.AcceptError!?@import("tcp_execution.zig").Accepted {
    var attempt: usize = 0;
    while (attempt < max_syscall_attempts) : (attempt += 1) {
        try io.checkCancel();
        var name: c.sockaddr.storage = undefined;
        var length: c.socklen_t = @sizeOf(c.sockaddr.storage);
        const accepted = c.accept4(handle, @ptrCast(&name), &length, linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK);
        if (accepted >= 0) return .{
            .handle = accepted,
            .peer = socket_addr.readSockaddr(&name),
        };
        switch (c.errno(accepted)) {
            .INTR => continue,
            .AGAIN => return null,
            .CONNABORTED => return error.ConnectionAborted,
            .ACCES, .PERM => return error.PermissionDenied,
            .MFILE, .NFILE => return error.DescriptorQuotaExceeded,
            .NOMEM, .NOBUFS => return error.ResourcesExhausted,
            .NETDOWN => return error.NetworkDown,
            .NETUNREACH => return error.NetworkUnreachable,
            .HOSTUNREACH, .HOSTDOWN => return error.HostUnreachable,
            .PROTO, .NOPROTOOPT => return error.ProtocolUnsupported,
            .OPNOTSUPP => return error.SocketModeUnsupported,
            .INVAL => return error.InvalidArgument,
            else => return error.Unexpected,
        }
    }
    return error.Interrupted;
}

pub fn waitStream(
    io: std.Io,
    options: @import("tcp_execution.zig").WaitOptions,
) tcp_error.WaitError!void {
    var descriptors = [_]std.posix.pollfd{
        .{ .fd = options.handle, .events = options.events, .revents = 0 },
        .{ .fd = options.wake, .events = std.posix.POLL.IN, .revents = 0 },
    };
    var attempt: usize = 0;
    while (attempt < max_syscall_attempts) : (attempt += 1) {
        try io.checkCancel();
        const result = c.poll(&descriptors, descriptors.len, options.timeout_ms orelse -1);
        switch (c.errno(result)) {
            .SUCCESS => {
                if (descriptors[1].revents != 0) return error.Canceled;
                if (descriptors[0].revents == 0) return error.WouldBlock;
                return;
            },
            .INTR => continue,
            .NETDOWN => return error.NetworkDown,
            .NOMEM, .NOBUFS => return error.ResourcesExhausted,
            else => return error.Unexpected,
        }
    }
    return error.Interrupted;
}

const t = std.testing;

test "the stream descriptor is opened non-blocking and closed over" {
    // The one property of the descriptor that every other behaviour here rests
    // on: a blocking stream cannot answer `EAGAIN`, and this module's whole
    // vocabulary — `WouldBlock`, a count that is short because a buffer filled
    // — is the vocabulary of a non-blocking one. `getsockopt(SO_TYPE)` and
    // `fcntl(F_GETFL)` read the two facts back rather than asserting them.
    const handle = try createStream(.{ .v4 = .{ 127, 0, 0, 1 } });
    defer _ = c.close(handle);

    var kind: c_int = 0;
    var length: socklen_t = @sizeOf(c_int);
    const level = std.math.cast(c_int, linux.SOL.SOCKET) orelse return error.Unexpected;
    try t.expectEqual(
        @as(c_int, 0),
        c.getsockopt(handle, level, linux.SO.TYPE, &kind, &length),
    );
    try t.expectEqual(@as(c_int, @intCast(linux.SOCK.STREAM)), kind);
    try t.expectEqual(@sizeOf(c_int), length);

    const flags = c.fcntl(handle, c.F.GETFL, @as(c_int, 0));
    try t.expect(flags >= 0);
    const nonblock: c_uint = @bitCast(linux.O{ .NONBLOCK = true });
    try t.expect((@as(c_uint, @bitCast(@as(c_int, flags))) & nonblock) != 0);
}

test "a stream nobody connected refuses the calls a stream makes" {
    // `ENOTCONN` is what a read and a write on a descriptor with no handshake
    // behind it answer, and it has to be an arm of its own rather than
    // `WouldBlock`: the first is a caller's bug and the second is backpressure.
    // A caller that cannot tell them apart waits out a deadline on a
    // connection it never made, and a caller handed `WouldBlock` for a connect
    // it skipped reports the wrong host as down.
    const handle = try createStream(.{ .v4 = .{ 127, 0, 0, 1 } });
    defer _ = c.close(handle);
    var buffer: [8]u8 = undefined;
    try t.expectError(error.NotConnected, recvStream(t.io, handle, &buffer));
    // A write, though, is `EPIPE` and not `ENOTCONN` on Linux: `send(2)` on a
    // TCP socket in `CLOSE` answers `EPIPE` whatever state the socket is in,
    // and `EPIPE` is this module's `PeerClosed`. So the arm the *write* reaches
    // here is the one a peer that closed would reach, and the read above is the
    // one that proves the pair stays distinct from `WouldBlock`.
    try t.expectError(error.PeerClosed, sendStream(t.io, handle, "x"));

    // And the connect outcome of a connect nobody asked for is "no error",
    // which is `SO_ERROR` answering zero. This is the case that would be easy
    // to read as a refusal, and it is the reason `connectResult` reports the
    // absence instead of inventing a failure for it.
    try connectResult(handle);

    // The local address of an unconnected stream is the wildcard on port zero,
    // which is what `connect` overwrites with the ephemeral port the kernel
    // chose — so `Tcp.local` starts there too rather than at a value this
    // module would have to invent.
    try t.expectEqual(@as(u16, 0), (try socket_open.boundAddress(handle)).port);
}
