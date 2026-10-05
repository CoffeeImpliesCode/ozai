//! Every way a connect-only TCP stream refuses: a connect, a read, a write,
//! and the wait all three share.
//!
//! Split out of `transport/tcp.zig` for the reason `socket_error.zig` gives:
//! the boundary is the vocabulary rather than the code. These four sets are
//! what the operations in that file return, and they are named together
//! because `WouldBlock` and `PeerClosed` must never share a name — the first
//! is a wait the caller schedules and retries, and the second is a stream that
//! will never carry another byte, and collapsing them turns a peer's ordinary
//! close into a retry loop that can never end.
//!
//! # No set here is an open `anyerror`
//!
//! Every arm names an errno or a fact about the stream, and `WaitError` is
//! the only part three sets have in common. A caller that `switch`es on one of
//! them has to handle every arm, which is what `AGENTS.md` §1 asks for and
//! what a `transport/socket.zig` caller already gets.
//!
//! # `OpenError` is not written here
//!
//! `Tcp.create` opens a descriptor with `socket(2)` and an `eventfd(2)`, and
//! those are the calls `transport/socket_open.zig` already wraps with the
//! errno names already attached. This file aliases that set rather than
//! restating it, because a second table for the same two syscalls is a second
//! thing to change on the day a kernel grows an errno.

const std = @import("std");

const socket_error = @import("socket_error.zig");

/// What `Tcp.create` can fail with, which is `socket_error.OpenError` under
/// the name this file's callers spell it with.
///
/// The same two syscalls with the same errnos: `socket(2)` and `eventfd(2)`
/// fail the same way whichever protocol the descriptor carries.
pub const OpenError = socket_error.OpenError;

/// What the wait before a connect, a read or a write can fail with.
///
/// The shared half of three error sets, because the three share one `poll`.
/// `Canceled` is a stop or a task cancellation. `WouldBlock` is the deadline
/// passing with nothing ready, which is the same answer
/// `transport/socket.zig`'s `Socket.receive` gives for a datagram queue that
/// stayed empty, and `Interrupted` is `EINTR` on every attempt the refused
/// call had.
pub const WaitError = error{
    /// The task was cancelled, or `Tcp.stop` ended the wait.
    Canceled,
    /// The deadline passed with the descriptor not ready. A value and not a
    /// failure: the stream is open and the caller decides what an empty
    /// interval means.
    WouldBlock,
    /// `EINTR` on every attempt in the budget, or a `poll` that could not be
    /// made. The call may be tried again.
    Interrupted,
    /// `ENETDOWN`: the interface that would carry the stream is down.
    NetworkDown,
    /// `ENOBUFS` or `ENOMEM`.
    ResourcesExhausted,
    /// `EBADF`, `ENOTSOCK`, or anything else.
    Unexpected,
};

/// Why a `connect` did not produce a connected stream.
pub const ConnectError = WaitError || error{
    /// `ECONNREFUSED`: nothing is listening at that address and port.
    ConnectionRefused,
    /// `ETIMEDOUT`: the handshake ran past the system's own timer, which is a
    /// different fact from this file's deadline passing and a longer wait.
    ConnectionTimedOut,
    /// `ENETUNREACH`: no route to the network.
    NetworkUnreachable,
    /// `EHOSTUNREACH`: no route to that host.
    HostUnreachable,
    /// `EADDRNOTAVAIL`: the destination is not one this host may connect to.
    AddressNotAvailable,
    /// `EACCES` or `EPERM`.
    PermissionDenied,
    /// `ECONNRESET`: the peer answered the handshake with an RST.
    ConnectionReset,
};

/// Why a `read` did not produce bytes.
pub const ReadError = WaitError || error{
    /// `ECONNRESET`: the peer sent an RST.
    ///
    /// **Whatever the peer had already sent may be gone with it.** A reset is
    /// not an orderly end of stream — a `shutdown(SHUT_WR)` is that, and it is
    /// a zero — so a caller that has to know whether the last bytes arrived
    /// needs a length ahead of them rather than trusting this stream to say.
    /// RFC 1035 §4.2.2's two-octet prefix, which `discovery/host_io.zig`
    /// frames and reads, is that mechanism.
    ConnectionReset,
    /// `ENOTCONN`: the connect has not returned, or was never made.
    NotConnected,
};

/// Why a `write` did not put the bytes it was handed on the wire.
pub const WriteError = WaitError || error{
    /// `EPIPE`: the peer is gone, and the kernel answered rather than raising
    /// `SIGPIPE`.
    ///
    /// **Not one byte of the buffer left**, so a caller that receives this has
    /// lost nothing and knows it; there is no partial write to reconcile. The
    /// byte count a successful return carries is the other half of the same
    /// claim, and the two together are what stop a caller from losing track of
    /// its own bytes.
    PeerClosed,
    /// `ECONNRESET`. Like `ReadError`'s, and with the same caveat: the peer
    /// discarded the connection rather than closing it in order.
    ConnectionReset,
    /// `ENOTCONN`: the connect has not returned, or was never made.
    NotConnected,
};

/// Whether the error set `set` carries an arm named `name`.
///
/// **An ordinary function and not a `comptime` one.** Both arguments are
/// compile-time and the loop reads `@typeInfo`, so the body folds to a constant
/// wherever it is called — but a function whose body is a `comptime` block has
/// no runtime body at all, and the counts below call this one at runtime.
/// `@hasDecl` does not accept an error set, so the arms are named rather than
/// asked for by hand, and a set that stops sharing an arm with `WaitError`
/// fails the `comptime` block below rather than one call site's `switch`.
fn hasArm(comptime set: anytype, comptime name: []const u8) bool {
    for (@typeInfo(set).error_set.?) |member| {
        if (std.mem.eql(u8, member.name, name)) return true;
    }
    return false;
}

comptime {
    // `WaitError` is the shared half of three sets, and a wait failure must be
    // spelled the same way in every set that can refuse it. This is the check
    // that says so at compile time, and its direction is `WaitError` into each
    // set: an arm one set has and another does not is a wait failure with two
    // names. The arms a set adds *beside* `WaitError` are its own — a reset is
    // not a wait — so they are deliberately not checked here.
    for (.{ ReadError, WriteError, ConnectError }) |set| {
        for (@typeInfo(WaitError).error_set.?) |member| {
            if (!hasArm(set, member.name)) {
                @compileError("a wait arm is missing from a set: " ++ member.name);
            }
        }
    }
}

const t = std.testing;

test "every wait arm is shared, and only a refused write names a dead peer" {
    // The split, counted rather than described: what is left in each set once
    // `WaitError` is taken out is exactly what that operation alone can
    // refuse. `WouldBlock` is backpressure a caller retries, `PeerClosed` is a
    // stream that is finished, and a set that had both would turn a peer's
    // ordinary close into a retry loop that can never end.
    var read_only: usize = 0;
    var write_only: usize = 0;
    inline for (@typeInfo(ReadError).error_set.?) |member| {
        read_only += @intFromBool(!hasArm(WaitError, member.name));
    }
    inline for (@typeInfo(WriteError).error_set.?) |member| {
        write_only += @intFromBool(!hasArm(WaitError, member.name));
    }
    try t.expectEqual(@as(usize, 2), read_only);
    try t.expectEqual(@as(usize, 3), write_only);

    // `PeerClosed` is a write's own refusal and not a wait's: a wait that ends
    // because the peer is gone is a wait that found the descriptor not
    // writable, and that is `WouldBlock`.
    try t.expect(hasArm(WriteError, "PeerClosed"));
    try t.expect(!hasArm(WaitError, "PeerClosed"));
    try t.expect(!hasArm(ReadError, "PeerClosed"));
    // A read and a write share the reset, because the kernel reports one
    // event to both directions.
    try t.expect(hasArm(ReadError, "ConnectionReset"));
    try t.expect(hasArm(WriteError, "ConnectionReset"));
    try t.expect(hasArm(ConnectError, "ConnectionReset"));
    // And `ConnectionRefused` belongs to the connect alone: no read and no
    // write on a refused stream has anything to say about it.
    try t.expect(hasArm(ConnectError, "ConnectionRefused"));
    try t.expect(!hasArm(ReadError, "ConnectionRefused"));
    try t.expect(!hasArm(WriteError, "ConnectionRefused"));
}
