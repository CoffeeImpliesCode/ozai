//! The two message syscalls: one run out through `sendmsg`, one datagram in
//! through `recvmsg`, each with the errno names its own answers.
//!
//! Split out of `transport/socket.zig`, which is now the facade over this and
//! five other named modules. The boundary is the `msghdr`: above it a control
//! message is bytes this project built, and below it a received blob is a
//! `Received`, so the errno tables sit with the one call each of them answers
//! for. They have to be there: a socket that cannot tell `EMSGSIZE` from
//! `EAGAIN` has backpressure it invented, and collapsing the two is how a
//! congestion signal becomes a hung socket. Both take the descriptor as a
//! parameter, because the socket owns it and this module does not.

const std = @import("std");
const batch = @import("batch.zig");
const base_addr = @import("../base/addr.zig");
const socket_addr = @import("socket_addr.zig");
const socket_cmsg = @import("socket_cmsg.zig");
const socket_error = @import("socket_error.zig");

const c = std.c;
const linux = std.os.linux;

const socklen_t = c.socklen_t;
const ControlBuffer = socket_cmsg.ControlBuffer;
const ControlExtent = socket_cmsg.ControlExtent;
const readCmsg = socket_cmsg.readCmsg;
const readSockaddr = socket_addr.readSockaddr;
const SendError = socket_error.SendError;
const ReceiveError = socket_error.ReceiveError;

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

/// How many times one syscall is retried after a signal before the call is
/// declared interrupted. A signal is not a fact about a datagram and retrying
/// is the only correct answer; the bound is what stops a storm of them from
/// becoming a hang.
pub const max_syscall_attempts = 4;

/// What one `sendmsg` said, before the model's name is put on it.
pub const Outcome = enum {
    /// Every byte of the payload left as one message.
    accepted,
    /// `EIO` or `EINVAL`. Only the run can tell a driver that will not
    /// segment from a kernel that does not know an option.
    refused,
};
pub fn sendmsg(
    io: std.Io,
    handle: c.fd_t,
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
        const rc = c.sendmsg(handle, &header, linux.MSG.NOSIGNAL);
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

pub fn recvmsg(
    io: std.Io,
    handle: c.fd_t,
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
        const rc = c.recvmsg(handle, &header, linux.MSG.DONTWAIT);
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
