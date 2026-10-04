//! The TCP connection `transport/socket.zig` deliberately is not.
//!
//! `socket.zig` refuses twice on purpose — it is a datagram socket, with no
//! stream, no length prefix and no half-close — and `discovery/lookup_io.zig`
//! refuses a truncated answer (`lookup_io.zig`'s "Truncation is the answer
//! that would need TCP") because of it. RFC 1035 §4.2.2 retries that answer
//! over TCP behind a two-octet length prefix, and this file is the set the
//! retry needs and the set nothing above this seam has: `connect`, `read`,
//! `write`, `halfClose`, `stop`.
//!
//! # `std.c` again, and `DECISIONS/0002` again
//!
//! The two gaps `docs/DECISIONS/0002-async-substrate.md` names are the same two
//! here, because the reasons are: this module opens its descriptor itself, so
//! no `Io` backend has ever been told it exists and only `Io.Threaded` would
//! cope with being handed one, and a stream needs `MSG_NOSIGNAL` on the send
//! and an `SO_ERROR` read after the handshake that the stock surface has
//! nowhere to put. The errno is the caller's to read, as it is there.
//!
//! # The second descriptor, and what a stop means for a stream
//!
//! `stop` is `Socket.stop`'s two halves unchanged — one atomic store and one
//! `write` to an `eventfd`, both of which POSIX says a signal handler may do —
//! and `stopFrom` is the shape `resolve.Cancellation.stop` takes verbatim, so a
//! cancellation reaches a stream without this file naming `discovery` at all.
//! Why a wake descriptor is needed in the first place is `socket.zig`'s
//! argument and it is the same one: a `poll` is asleep in the kernel, and a
//! latch cannot be consulted from there.
//!
//! What a stop *means* is where a stream and a datagram socket must differ.
//! `Socket.send` recovers a stopped socket, because the next request on that
//! descriptor is the whole reason it is not closed: a datagram socket serves
//! query after query. **A stopped stream stays stopped.** A stream is one
//! agreed exchange with one peer, and a caller answered `error.Canceled` has
//! nobody left to wait for — so every later call answers `Canceled` too. That
//! is also why nothing here spends the wake counter: no wait can begin after a
//! stop, only `stop` may run concurrently with the one in flight, and so a
//! unit left standing is on a descriptor no `poll` will read again. `close`
//! releases it.
//!
//! # What this file does not have
//!
//! No listener and no `accept`: `connect` is the only way in, because nothing
//! above this seam accepts a stream yet and a listener would be a surface with
//! no caller. No socket options either, for the same reason — `TCP_NODELAY` and
//! `SO_KEEPALIVE` are decisions a caller makes about its own peer, not ones
//! this file should take on the caller's behalf.
//!
//! # Linux, `link_libc`, and where the bodies get compiled
//!
//! `socket`, `connect`, `send`, `read`, `write`, `shutdown`, `getsockopt`,
//! `getpeername`, `eventfd` and `close` are libc's, so an artifact that reaches
//! any of them needs `linkLibC()`. `socket.zig`'s last section says the rest:
//! `refAllDecls` checks these signatures and none of these bodies, which is why
//! the syscall layer here is only compiled by an artifact that opens a real
//! connection.

const std = @import("std");

/// The address layout is `socket.zig`'s and it is `pub` there for exactly this
/// reason: writing an address is the kernel's `sockaddr`, and a second seam
/// that re-derived those offsets would be a second spelling of one struct.
const socket = @import("socket.zig");
const base_addr = @import("../base/addr.zig");

const posix = std.posix;
const c = std.c;
const linux = std.os.linux;

const socklen_t = c.socklen_t;

/// The counter an `eventfd` counts in, which the kernel fixes at eight bytes
/// and `write` wants all of. It is the whole of what a wake carries.
const wake_width = @sizeOf(u64);

/// How many times one syscall is retried after a signal before the call is
/// declared interrupted. A signal is not a fact about a stream and retrying is
/// the only correct answer; the bound is what stops a storm of them from
/// becoming a hang.
pub const max_syscall_attempts = 4;

comptime {
    // `await`'s `events` argument is written into this field, and the two
    // cannot drift: std widening it would be a compile error here rather than
    // a silent truncation of the wait a caller asked for, and this assertion
    // is which of the two shapes the file above is written against.
    std.debug.assert(@FieldType(posix.pollfd, "events") == i16);
}

// 80 display columns; the rule counts UTF-8 bytes, three per box character.
// ziglint-ignore: Z024
// ────────────────────────────────────────────────────────────────── error sets

/// Why a connection could not be made.
///
/// `WouldBlock` is the caller's own deadline and not the kernel's: a
/// non-blocking connect answers `EINPROGRESS` at once and the refusal arrives
/// on the wait, so a deadline that fires there is a fact about the caller and
/// wears the same name an empty queue wears on `Socket.receive`.
pub const ConnectError = error{
    /// The caller gave up, or a stop ended the wait the handshake was in.
    Canceled,
    /// `EAGAIN`, or a `poll` that returned with nothing ready: the deadline
    /// arrived before the connection did. Nothing was connected.
    WouldBlock,
    /// `ECONNREFUSED`: nothing is listening where this address points.
    ConnectionRefused,
    /// `ETIMEDOUT`, out of `SO_ERROR` after the handshake exhausted its
    /// retries.
    ConnectionTimedOut,
    /// `ENETUNREACH`: no route to the network.
    NetworkUnreachable,
    /// `EHOSTUNREACH`: no route to that host.
    HostUnreachable,
    /// `ENETDOWN`: the interface that would carry it is down.
    NetworkDown,
    /// `EADDRNOTAVAIL`: the address is not one this host may connect to.
    AddressNotAvailable,
    /// `EAFNOSUPPORT`: this kernel has no IPv4 or no IPv6.
    AddressFamilyUnsupported,
    /// `EADDRINUSE`: the local port the kernel picked is already taken.
    AddressInUse,
    /// `EACCES` or `EPERM`: a sandbox, not the address.
    PermissionDenied,
    /// `EINVAL`: a flag or an address length this module wrote wrongly.
    InvalidArgument,
    /// `EMFILE` or `ENFILE`: the process or the system is out of descriptors.
    DescriptorQuotaExceeded,
    /// `ENOBUFS` or `ENOMEM`.
    ResourcesExhausted,
    /// `EINTR` on every attempt in the budget.
    Interrupted,
    /// Anything else, `ENOTCONN` and `EBADF` included.
    Unexpected,
};

/// Why a read did not produce bytes.
///
/// A count of zero is not in this set: it is the peer's half-close, and a value
/// a caller can act on rather than a refusal it has to translate.
pub const ReadError = error{
    /// The caller gave up, or a stop ended the wait the read was in.
    Canceled,
    /// `EAGAIN`: the peer's bytes have not arrived, or the deadline did.
    WouldBlock,
    /// `ECONNRESET` or `ECONNABORTED`: the peer is gone and what it sent
    /// before it went is lost. A reset is not a half-close and cannot be read
    /// as one — this is why it is an error and zero is not.
    ConnectionReset,
    /// `ETIMEDOUT` on the read: the peer's own retransmissions ran out.
    TimedOut,
    /// `ENETDOWN`, or a `poll` that could not run at all.
    NetworkDown,
    /// `ENOBUFS` or `ENOMEM`, or `poll` reporting the process is out of them.
    ResourcesExhausted,
    /// `EINTR` on every attempt in the budget.
    Interrupted,
    /// Anything else.
    Unexpected,
};

/// Why a write did not go out.
pub const WriteError = error{
    /// The caller gave up, or a stop ended the wait the write was in.
    Canceled,
    /// `EAGAIN`: the send queue is full and nothing of this call went out.
    /// Only ever returned where nothing was accepted — a partial send is a
    /// count, not a refusal, so a caller can never lose track of its own bytes.
    WouldBlock,
    /// `EPIPE`: the peer's receive side is closed. Reachable because the send
    /// is `NOSIGNAL`, which is what turns `SIGPIPE` into this name.
    ConnectionBroken,
    /// `ECONNRESET` or `ECONNABORTED`: the peer is gone.
    ConnectionReset,
    /// `ENETDOWN`, or a `poll` that could not run at all.
    NetworkDown,
    /// `ENOBUFS` or `ENOMEM`, or `poll` reporting the process is out of them.
    ResourcesExhausted,
    /// `EINTR` on every attempt in the budget.
    Interrupted,
    /// Anything else.
    Unexpected,
};

/// Why the write side could not be closed.
pub const HalfCloseError = error{
    /// `ENOTCONN`: the connection is already gone — the peer reset it, or the
    /// network went. A `stop` is not what did it: `stop` ends waits and
    /// latches the stream, and never closes one.
    NotConnected,
    /// `EINVAL` or `ENOTSOCK`: the descriptor is not a socket.
    SocketUnusable,
    /// Anything else.
    Unexpected,
};

// 80 display columns; the rule counts UTF-8 bytes, three per box character.
// ziglint-ignore: Z024
// ────────────────────────────────────────────────────────────────────── stream

/// One connected TCP stream: a descriptor, a wake descriptor, and a latch.
///
/// A successful `connect` owns both descriptors. `close` releases them exactly
/// once, after every operation and every stop caller has finished. Copies share
/// those descriptors, so keep the value at a stable address while a
/// `resolve.Cancellation` holds it. Serialize reads, writes and half-closes —
/// they share one descriptor's queue and one send queue, and two writers are
/// two orders of the same bytes. Only `stop` may run concurrently with them.
/// An operation borrows `io` and its backend only until it returns; no `Io` is
/// stored, for `DECISIONS/0002`'s reason and `socket.zig`'s.
pub const Stream = struct {
    /// The descriptor. `NONBLOCK` and `CLOEXEC` from the moment it exists,
    /// which is what makes `EAGAIN` a fact a caller can act on and keeps the
    /// descriptor from surviving the next `exec` into a child that never asked
    /// for a connection.
    handle: c.fd_t,
    /// The descriptor a stop writes to, in the same `poll` set as `handle` and
    /// the only thing that can end a wait before its deadline. Written by
    /// `stop` and read by nobody; the module doc has why that is not a leak.
    wake: c.fd_t,
    /// Set by `stop` and never cleared. Read by every operation before it
    /// waits, which is what makes the write above necessary rather than
    /// decorative: a latch nothing reads is a latch that answers nothing.
    stopped: std.atomic.Value(bool),
    /// Where the peer is, read once the handshake has answered. Not a copy of
    /// the request: the address a caller asked for is a claim, and this is
    /// where the connection landed.
    peer: base_addr.SocketAddr,

    /// Open a stream to `address` and run the handshake to its answer.
    ///
    /// One `socket` call carrying `NONBLOCK`, so the connect answers
    /// `EINPROGRESS` and the wait below is where the handshake happens. This
    /// module has no blocking call and no deadline of its own, which is exactly
    /// what lets a wait be ended rather than run to the end of its slice.
    ///
    /// `timeout_ms` of null waits as long as the caller means, zero polls
    /// once, and a timeout is `error.WouldBlock`. A task cancelled during the
    /// handshake is `error.Canceled` like anywhere else; nothing else can stop
    /// this call, because no `Stream` exists yet for a `stop` to hold — which
    /// is why the caller's own deadline is this call's only bound.
    pub fn connect(
        io: std.Io,
        address: base_addr.SocketAddr,
        timeout_ms: ?i32,
    ) ConnectError!Stream {
        const handle = try createSocket(address);
        errdefer _ = c.close(handle);
        // Before the connect and not after it: the wait below polls the wake,
        // and a wake created after the wait is a wait nothing can end.
        const wake = try createWake();
        errdefer _ = c.close(wake);
        var name: c.sockaddr.storage = undefined;
        const length = socket.writeSockaddr(address, &name);
        try connectSocket(handle, &name, length);
        // The one cancellation this call can see, and it is checked before the
        // wait rather than after it: the wake descriptor below has no `stop`
        // to write to it yet.
        try io.checkCancel();
        try awaitDescriptors(handle, wake, posix.POLL.OUT, timeout_ms);
        // And only now. A refusal that arrives after `connect` returned belongs
        // to `SO_ERROR` and to no call of ours, and it has to be read before the
        // peer is named: a failed handshake has no peer, and `getpeername`'s own
        // `ENOTCONN` would be reported as this module's `Unexpected`.
        try pendingError(handle);
        return .{
            .handle = handle,
            .wake = wake,
            .stopped = .init(false),
            .peer = try peerAddress(handle),
        };
    }

    /// Close both descriptors and end the connection.
    ///
    /// Nothing is buffered on this side: a `write` that returned has left for
    /// the send queue or been refused, and a `read` that returned was taken. A
    /// caller answered `error.Canceled` closes here and nowhere else, because
    /// `stop` may be running where closing a descriptor under an in-flight
    /// read is not a call it may make. Do not close a copy, or call this twice.
    pub fn close(self: *const Stream) void {
        _ = c.close(self.wake);
        _ = c.close(self.handle);
    }

    /// Send the FIN: no byte of this stream goes out after this, and every byte
    /// the peer sends still will.
    ///
    /// This is the operation a datagram socket has no answer for, and it is
    /// half a close rather than all of it — `close` is the other half. A stream
    /// that half-closes and is never closed is a descriptor the caller has to
    /// remember, and that is the cost the separate name is paying for.
    pub fn halfClose(self: *const Stream) HalfCloseError!void {
        const rc = c.shutdown(self.handle, linux.SHUT.WR);
        switch (c.errno(rc)) {
            .SUCCESS => {},
            .NOTCONN => return error.NotConnected,
            .INVAL, .NOTSOCK => return error.SocketUnusable,
            else => return error.Unexpected,
        }
    }

    /// Name this stream stopped: end the wait in flight, and take every later
    /// call's answer with it.
    ///
    /// `Socket.stop`'s two halves, unchanged and for its reasons: both are on
    /// POSIX's list of calls a signal handler may make, and both are needed —
    /// a wait asleep inside `poll` reads nothing, so the store alone would
    /// arrive a slice late with nothing to say that it had. Unlike the datagram
    /// socket there is no recovery here, and the module doc is the argument.
    ///
    /// Keep the stream alive and open until every concurrent stop returns.
    pub fn stop(self: *Stream) void {
        self.stopped.store(true, .release);
        var one: u64 = 1;
        _ = c.write(self.wake, std.mem.asBytes(&one), wake_width);
    }

    /// Wait for the peer's bytes and take what one read gives.
    ///
    /// A count of zero is the peer's half-close: the wait has already returned
    /// for readability, and a readable stream socket with nothing to read is a
    /// socket whose peer closed. An empty `into` is zero bytes and no syscall,
    /// and that is the one count which says nothing about the peer.
    ///
    /// A short count is a value and not a failure — a stream read takes what
    /// arrived and the caller asks again for the rest — and `error.WouldBlock`
    /// is the deadline arriving with nothing. Result and error residue follow
    /// `Socket.receive`.
    pub fn read(self: *const Stream, io: std.Io, into: []u8, timeout_ms: ?i32) ReadError!usize {
        if (self.refused()) return error.Canceled;
        if (into.len == 0) return 0;
        try self.await(io, posix.POLL.IN, timeout_ms);
        return self.take(io, into);
    }

    /// Wait for room in the send queue, then hand the peer what it takes.
    ///
    /// One `send` per call, and a short count is a value: this is a stream, so
    /// the kernel may take part of `bytes` and keep the rest for a later call,
    /// and a caller wanting all of it in one call is asking for a guarantee no
    /// stream makes. `error.WouldBlock` is the deadline arriving with the queue
    /// full, and it is only ever returned where nothing went out.
    ///
    /// `NOSIGNAL` because a peer that has gone away answers `EPIPE` and the
    /// default action for `SIGPIPE` is to kill this process; it is
    /// `socket.zig`'s flag on `sendmsg` and the same argument.
    pub fn write(
        self: *const Stream,
        io: std.Io,
        bytes: []const u8,
        timeout_ms: ?i32,
    ) WriteError!usize {
        if (self.refused()) return error.Canceled;
        if (bytes.len == 0) return 0;
        try self.await(io, posix.POLL.OUT, timeout_ms);
        return self.put(io, bytes);
    }

    /// Wait for `events` on the descriptor, or for a stop to end the wait.
    ///
    /// The runtime's own cancellation is checked here and not after the wait,
    /// which is the only place a task cancelled mid-transfer is seen at all;
    /// `refused` has already answered this module's latch by then.
    fn await(
        self: *const Stream,
        io: std.Io,
        events: i16,
        timeout_ms: ?i32,
    ) error{ Canceled, WouldBlock, NetworkDown, ResourcesExhausted, Unexpected }!void {
        try io.checkCancel();
        try awaitDescriptors(self.handle, self.wake, events, timeout_ms);
    }

    /// The one answer a stopped stream gives, whatever was asked of it.
    ///
    /// Checked ahead of every fast path and not only ahead of the waits: an
    /// empty buffer is answered without a syscall, and a stream that has been
    /// stopped has no operation left to answer at all — which is all that
    /// "a stopped stream stays stopped" means.
    fn refused(self: *const Stream) bool {
        return self.stopped.load(.acquire);
    }

    /// One `read`, retried across a signal and bounded by it.
    fn take(self: *const Stream, io: std.Io, into: []u8) ReadError!usize {
        var attempt: usize = 0;
        while (attempt < max_syscall_attempts) : (attempt += 1) {
            // A signal arrived before the bytes did. Asking again is the only
            // correct answer, and the loop is also where a cancellation lands.
            try io.checkCancel();
            const rc = c.read(self.handle, into.ptr, into.len);
            switch (c.errno(rc)) {
                // Zero here is the peer's half-close, and this read is the only
                // call in the file that can find out.
                .SUCCESS => return @intCast(rc),
                .INTR => continue,
                .AGAIN => return error.WouldBlock,
                .CONNRESET, .CONNABORTED => return error.ConnectionReset,
                .TIMEDOUT => return error.TimedOut,
                .NETDOWN => return error.NetworkDown,
                .NOMEM, .NOBUFS => return error.ResourcesExhausted,
                else => return error.Unexpected,
            }
        }
        return error.Interrupted;
    }

    /// One `send`, retried across a signal and bounded by it. A short count
    /// leaves the rest of `bytes` with the caller, which is the whole of what
    /// "a stream write took what it took" means.
    fn put(self: *const Stream, io: std.Io, bytes: []const u8) WriteError!usize {
        var attempt: usize = 0;
        while (attempt < max_syscall_attempts) : (attempt += 1) {
            try io.checkCancel();
            const rc = c.send(self.handle, @ptrCast(bytes.ptr), bytes.len, linux.MSG.NOSIGNAL);
            switch (c.errno(rc)) {
                .SUCCESS => return @intCast(rc),
                .INTR => continue,
                .AGAIN => return error.WouldBlock,
                .PIPE => return error.ConnectionBroken,
                .CONNRESET, .CONNABORTED => return error.ConnectionReset,
                .NETDOWN => return error.NetworkDown,
                .NOMEM, .NOBUFS => return error.ResourcesExhausted,
                else => return error.Unexpected,
            }
        }
        return error.Interrupted;
    }
};

/// `resolve.Cancellation.stop`, verbatim: a `*Stream` reached by the same cast
/// `discovery/lookup_live.zig` uses for its socket, and nothing else. A caller
/// holding both a stream and a cancellation builds the handle without this file
/// naming `discovery` — transport does not import the layer that resolves names,
/// and a seam that had to would be a dependency in the wrong direction.
pub fn stopFrom(ctx: *anyopaque) void {
    const self: *Stream = @ptrCast(@alignCast(ctx));
    self.stop();
}

/// Poll a descriptor and its wake until one of them is ready.
///
/// `connect` reaches this before a `Stream` exists and `await` reaches it after,
/// so the stop that outranks whatever the pass found has one implementation
/// rather than two that could disagree. A `poll` on the descriptor and not an
/// `Io` operation, for the reason the module doc gives, and a timeout is the
/// caller's own clock running out rather than an error of its own.
fn awaitDescriptors(
    handle: c.fd_t,
    wake: c.fd_t,
    events: i16,
    timeout_ms: ?i32,
) error{ Canceled, WouldBlock, NetworkDown, ResourcesExhausted, Unexpected }!void {
    var descriptors = [_]posix.pollfd{
        .{ .fd = handle, .events = events, .revents = 0 },
        .{ .fd = wake, .events = posix.POLL.IN, .revents = 0 },
    };
    const ready = posix.poll(&descriptors, timeout_ms orelse -1) catch |err| switch (err) {
        error.NetworkDown => return error.NetworkDown,
        error.SystemResources => return error.ResourcesExhausted,
        error.Unexpected => return error.Unexpected,
    };
    // A stop, and not the peer, and it outranks a peer the same pass found
    // ready: whoever fired the cancellation is not waiting for bytes now, and a
    // read taken after the fact would hand bytes to nobody. Nothing here clears
    // the latch, so the next call answers `Canceled` without waiting at all.
    if (descriptors[1].revents != 0) return error.Canceled;
    if (ready == 0) return error.WouldBlock;
}

// 80 display columns; the rule counts UTF-8 bytes, three per box character.
// ziglint-ignore: Z024
// ────────────────────────────────────────────────────────────────── the way in

/// The descriptor a stream runs on: `STREAM`, non-blocking, close-on-exec.
fn createSocket(address: base_addr.SocketAddr) ConnectError!c.fd_t {
    // A value, not a type alias: `c_uint` is what the switch below evaluates
    // to, and `domain` is the address family this descriptor is opened for.
    // zwanzig-disable-next-line: identifier-style
    const domain: c_uint = switch (address.ip) {
        .v4 => linux.AF.INET,
        .v6 => linux.AF.INET6,
    };
    // `NONBLOCK` in the type rather than an `fcntl` afterwards, so there is no
    // window in which the descriptor exists and blocks.
    const kind: c_uint = linux.SOCK.STREAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK;
    const rc = c.socket(domain, kind, linux.IPPROTO.TCP);
    if (rc >= 0) return rc;
    return connectErrno(c.errno(rc));
}

/// The descriptor a stop wakes a wait on, or a refusal to have one.
///
/// A refusal refuses the stream, for `socket.zig`'s reason: a connection whose
/// wait cannot be ended is handed a cancellation that arrives a slice late with
/// nothing to say that it had.
fn createWake() ConnectError!c.fd_t {
    const flags = linux.EFD.SEMAPHORE | linux.EFD.NONBLOCK | linux.EFD.CLOEXEC;
    const handle = c.eventfd(0, flags);
    if (handle >= 0) return handle;
    return connectErrno(c.errno(handle));
}

/// Start the handshake. `EINPROGRESS` is the ordinary answer of a non-blocking
/// connect rather than a refusal — the handshake runs under the wait, and its
/// refusal is `SO_ERROR` — and `SUCCESS` is the same handshake already done on
/// a loopback.
fn connectSocket(
    handle: c.fd_t,
    name: *const c.sockaddr.storage,
    length: socklen_t,
) ConnectError!void {
    const rc = c.connect(handle, @as(*const c.sockaddr, @ptrCast(name)), @intCast(length));
    switch (c.errno(rc)) {
        .SUCCESS, .INPROGRESS => {},
        else => return connectErrno(c.errno(rc)),
    }
}

/// The handshake's answer, which is where a refusal that arrived after
/// `connect` returned is parked.
///
/// Read rather than inferred, and read before the peer is named: a stream whose
/// connect is still in progress has no peer, so the `ENOTCONN` a
/// `getpeername` would answer would be this module's own `Unexpected` standing
/// where the kernel's real refusal belongs.
fn pendingError(handle: c.fd_t) ConnectError!void {
    var code: c_int = 0;
    var length: socklen_t = @sizeOf(c_int);
    const rc = c.getsockopt(handle, linux.SOL.SOCKET, linux.SO.ERROR, @ptrCast(&code), &length);
    if (c.errno(rc) != .SUCCESS) return error.Unexpected;
    if (code == 0) return;
    return connectErrno(@enumFromInt(code));
}

/// Where the peer is, as the kernel has it once the handshake has answered.
fn peerAddress(handle: c.fd_t) ConnectError!base_addr.SocketAddr {
    var name: c.sockaddr.storage = undefined;
    var length: socklen_t = @sizeOf(c.sockaddr.storage);
    const rc = c.getpeername(handle, @as(*c.sockaddr, @ptrCast(&name)), &length);
    if (c.errno(rc) != .SUCCESS) return error.Unexpected;
    return socket.readSockaddr(&name) orelse error.AddressNotAvailable;
}

/// One name per errno for the whole way in, and the reason this is one function
/// and not four is `pendingError`: `SO_ERROR` hands back the kernel's own
/// number, and a refusal that arrived late has to land on the name the same
/// refusal would have had from `connect` itself.
fn connectErrno(err: c.E) ConnectError {
    return switch (err) {
        .ACCES, .PERM => error.PermissionDenied,
        .AFNOSUPPORT => error.AddressFamilyUnsupported,
        .ADDRNOTAVAIL => error.AddressNotAvailable,
        .ADDRINUSE => error.AddressInUse,
        .CONNREFUSED => error.ConnectionRefused,
        .TIMEDOUT => error.ConnectionTimedOut,
        .HOSTUNREACH => error.HostUnreachable,
        .NETUNREACH => error.NetworkUnreachable,
        .NETDOWN => error.NetworkDown,
        .INVAL => error.InvalidArgument,
        .MFILE, .NFILE => error.DescriptorQuotaExceeded,
        .NOMEM, .NOBUFS => error.ResourcesExhausted,
        else => error.Unexpected,
    };
}
