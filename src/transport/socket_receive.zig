//! What a receive does: one `recvmsg`, the wait in front of it, and the
//! cleanup a stop owes.
//!
//! `transport/socket.zig` owns the descriptors and the public shape of a read;
//! this file owns everything that happens once a caller has asked for one.
//! Four responsibilities, and they are the same four a datagram reader has:
//!
//!   * `recvmsg` — one call, one errno translation, and the control blob
//!     handed to `ancillary.readCmsg` for the stride and the codepoint.
//!   * `awaitReadable` — the `poll` that runs until a datagram, a deadline or
//!     a stop, which is the one thing here that is not a read at all.
//!   * `discard` and `clearWake` — the queue and the wake counter a stop left,
//!     each bounded, each refused rather than half emptied.
//!   * `restart` — the order those two run in, which is the whole of what
//!     makes a second stop during the cleanup survive it.
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
//! Nothing here stores a runtime, allocates, or reads a clock: `timeout_ms` is
//! the caller's number and is handed to `poll` unexamined.

const std = @import("std");
const batch = @import("batch.zig");
const base_addr = @import("../base/addr.zig");
const ancillary = @import("ancillary.zig");
const control = @import("socket_control.zig");

const posix = std.posix;
const c = std.c;
const linux = std.os.linux;

/// Why a receive did not produce a datagram.
pub const ReceiveError = error{
    /// The task was cancelled before the datagram was taken.
    Canceled,
    /// `EAGAIN`: the queue was empty. From `Socket.tryReceive` that is the
    /// answer to the question that was asked; from `Socket.receive` it means
    /// another task took the datagram between the wait and the read.
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

/// The counter an `eventfd` counts in, which the kernel fixes at eight bytes
/// and both `read` and `write` want all of. It is a value rather than a count
/// of anything in this file, which is the whole of what a wake carries, and it
/// is here rather than beside the socket because the counter is what a read
/// spends and a write raises.
pub const wake_width: usize = @sizeOf(u64);

/// How many datagrams a stop takes off the queue before it stops taking.
///
/// A bound and not a budget. RFC 1035 §7.2 has one query in flight per lookup,
/// so a queue deeper than this is a peer filling it faster than a waiter can
/// empty it, and the next thing to hang would be the resolve that gave up.
pub const max_discarded = 64;

/// How many wake units one cleanup takes off the counter before it says the
/// counter is not spending.
///
/// A bound and not a budget, and the same fact `max_discarded` is about with the
/// other half of a stop: one unit is one `stop`, and a stop belongs to a
/// caller with a wait in progress, so a counter this deep is cancellation
/// being raised faster than a send can spend it. Reaching it is a refusal and
/// not a partial spend, because a unit left standing ends the next wait
/// exactly the way a real stop would and nothing else would take it off.
pub const max_wakes_spent = 64;

/// Take one datagram off `handle`, or answer that there is none.
///
/// `buffer` and `control_buffer` are the caller's and may be overwritten
/// either way. A truncation error consumes the datagram: the bytes are here and
/// the read is refused, and there is no second chance at them.
pub fn recvmsg(
    io: std.Io,
    handle: c.fd_t,
    buffer: []u8,
    control_buffer: *ancillary.ControlBuffer,
) ReceiveError!Received {
    var name: c.sockaddr.storage = undefined;
    var vectors = [_]c.iovec{.{ .base = buffer.ptr, .len = buffer.len }};
    var header: c.msghdr = .{
        .name = @as(*c.sockaddr, @ptrCast(&name)),
        .namelen = @sizeOf(c.sockaddr.storage),
        .iov = vectors[0..].ptr,
        .iovlen = vectors.len,
        .control = @as(?*anyopaque, @ptrCast(control_buffer.bytes[0..].ptr)),
        .controllen = control_buffer.bytes.len,
        .flags = 0,
    };
    var attempt: usize = 0;
    while (attempt < control.max_syscall_attempts) : (attempt += 1) {
        try io.checkCancel();
        const rc = c.recvmsg(handle, &header, linux.MSG.DONTWAIT);
        switch (c.errno(rc)) {
            .SUCCESS => {
                if (header.flags & linux.MSG.TRUNC != 0) return error.MessageTooLarge;
                const used = @min(header.controllen, control_buffer.bytes.len);
                const read = ancillary.readCmsg(control_buffer.bytes[0..used]);
                if (read.truncated or header.flags & linux.MSG.CTRUNC != 0) {
                    return error.ControlTruncated;
                }
                return .{
                    .bytes = buffer[0..@intCast(rc)],
                    .from = ancillary.readSockaddr(&name) orelse return error.Unexpected,
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

/// Wait for `handle` to be readable, or for a stop to end the wait.
///
/// A `poll` on the descriptor and not an `Io` operation: this module opened
/// the socket with `std.c.socket`, so no backend has ever been told the
/// descriptor exists and only `Io.Threaded` would cope with being handed one.
/// `posix.poll` already retries a signal, and zero ready is the timeout
/// rather than an error.
///
/// The set has two entries, and that is the whole of how a stop reaches a
/// wait already in progress: the wake is a descriptor like any other, and
/// `poll` returns for it exactly as it returns for a datagram. A flag
/// consulted around the call would be consulted only once the call was over,
/// which is the failure the wake descriptor exists to remove.
pub fn awaitReadable(
    io: std.Io,
    handle: c.fd_t,
    wake: c.fd_t,
    timeout_ms: ?i32,
) ReceiveError!void {
    try io.checkCancel();
    var descriptors = [_]posix.pollfd{
        .{
            .fd = handle,
            .events = posix.POLL.IN,
            .revents = 0,
        },
        .{
            .fd = wake,
            .events = posix.POLL.IN,
            .revents = 0,
        },
    };
    _ = posix.poll(&descriptors, timeout_ms orelse -1) catch |err| switch (err) {
        error.NetworkDown => return error.NetworkDown,
        error.SystemResources => return error.ResourcesExhausted,
        error.Unexpected => return error.Unexpected,
    };
    // A stop, and not a datagram, and it outranks a datagram the socket may
    // have found in the same pass: the queue is drained, so the bytes this
    // socket is holding are wanted by nobody, and the wait is over rather than
    // starting a read nobody is left to want the answer of.
    if (descriptors[1].revents != 0) {
        // A stop is what ended this wait however the drain made of the queue,
        // and a drain that could not empty it is not a different answer.
        // Nothing here clears the flag or spends the counter, so the socket
        // stays stopped and the next send drains again — and a cancellation
        // reported as anything but `Canceled` is a refusal the caller above
        // this one is not waiting for.
        discard(io, handle) catch return error.Canceled;
        return error.Canceled;
    }
}

/// Take everything queued on `handle` and throw it away.
///
/// One byte of buffer, because a datagram leaves the queue whatever the
/// buffer holds and this is the one read whose bytes nobody asked for. The
/// wake counter is left alone: a stop stands until the next send, and a
/// counter emptied here would let the wait after this one block on a socket
/// that is still stopped.
///
/// A queue deeper than `max_discarded` is refused rather than emptied as far as
/// it goes, and the caller keeps the socket stopped when it is: the next send
/// drains again, which is the difference between a straggler it can see and one
/// the next query would have read as its own answer.
pub fn discard(
    io: std.Io,
    handle: c.fd_t,
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
    while (dropped < max_discarded and signals < control.max_syscall_attempts) {
        try io.checkCancel();
        const rc = c.recvmsg(handle, &header, linux.MSG.DONTWAIT);
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

/// Spend the wake counter, which the send that ends a stop does along with the
/// queue.
///
/// A wake is a message to a wait and not a latch, so it is spent here and
/// nowhere else. Left standing, it would wake every wait that followed it for a
/// stop that has already been dealt with. `EFD_SEMAPHORE` gives a read one unit
/// rather than the whole count, so spending the counter is one read per unit and
/// a counter deeper than `max_wakes_spent` is refused rather than half spent — a
/// unit left on it ends the next wait exactly the way a real stop would, and
/// nothing else takes it off.
pub fn clearWake(wake: c.fd_t) error{Interrupted}!void {
    var count: u64 = 0;
    var spent: usize = 0;
    var signals: usize = 0;
    // Bounded on the units and on the signals, as `discard` is: a counter
    // that keeps rising under cancellation raised faster than a send can
    // spend it is not a queue to empty, and the refusal leaves the socket
    // stopped for the next send rather than spent half way.
    while (spent < max_wakes_spent and signals < control.max_syscall_attempts) {
        const rc = c.read(wake, std.mem.asBytes(&count), wake_width);
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

/// Why a recovery did not finish, and the whole of what it can answer with.
///
/// Every member is one the two cleanup operations can already return, so a
/// caller of `restart` sees the same names a direct call to either of them
/// would have given it.
pub const RestartError = error{
    /// The task was cancelled before the queue was empty.
    Canceled,
    /// `max_discarded`, `max_wakes_spent` or a signal budget ran out, so the
    /// stop is dealt with as far as one call's bounds go and stands for the
    /// next send to deal with again.
    Interrupted,
    /// A cleanup that could not be completed at all, which leaves the stop
    /// standing rather than half dealt with.
    Unexpected,
};

/// End the stopped state a socket is in: take the queue, then spend the wake
/// the stop left behind.
///
/// A stop means nothing arriving on this descriptor is wanted, so whatever is
/// queued goes with it rather than being left for whoever reads next. This is
/// the one place a stopped socket becomes a socket again, and the only place
/// the wake is spent: a counter left standing would wake every wait that
/// followed, for a stop already dealt with.
///
/// `context` is what the recovery runs on and not a descriptor, so a test can
/// raise a real `Socket.stop` between the drain and the flag. Its two cleanup
/// operations arrive as `drain_callback` and `spend_wake_callback` rather than
/// as methods, for the reason `socket_send.sendBatch` takes a callback: the
/// production context is a `Socket` whose `discard` and `clearWake` are private
/// to `socket.zig`, and a private declaration cannot be named from this file.
/// A function pointer carries the operation without carrying the access. What
/// `context` itself must still offer is public — the stopped flag and `stop` —
/// because the recovery reads the flag and raises the wake directly.
///
/// `io` comes before the state because a runtime is a parameter of the call
/// and not of the thing it is called on.
pub fn restart(
    comptime Context: type,
    comptime drain_callback: *const fn (Context, std.Io) RestartError!void,
    comptime spend_wake_callback: *const fn (Context) error{Interrupted}!void,
    io: std.Io,
    context: Context,
) RestartError!void {
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
    try drain_callback(context, io);
    // The units this stop left, which are on the counter whatever has arrived
    // since: a unit spent here is a wake for a stop this socket has dealt with,
    // and spending one is what ends the wait after it on the descriptor.
    try spend_wake_callback(context);
    // A stop that arrived during the drain or during that read is still
    // outstanding, and the read may have taken the unit it raised. The socket
    // is stopped, so it owes a waiter a wake; `stop` is the socket's own way of
    // raising one, and a stop that arrives after this line writes its own unit
    // instead of finding one to take.
    if (context.stopped.load(.acquire)) context.stop();
}
