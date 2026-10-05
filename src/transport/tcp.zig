//! The connect-only TCP stream: a descriptor, a stop, and three operations.
//!
//! This file mirrors `transport/socket.zig`, and the mirroring is the point —
//! the datagram socket is the seam this project already established, and a
//! second stream seam that disagreed with it about where `io` lives, about
//! what a stop may do, or about which error a timeout is would be a second
//! convention rather than a second module.
//!
//! # What is mirrored, and what it is for
//!
//! Read `transport/socket.zig` first; the shape is its and this file quotes it
//! rather than restating it. Concretely, each of these is a copy of a decision
//! `socket.zig` already argues for, not a habit:
//!
//! - **`io` is a parameter and is stored nowhere.** `docs/DECISIONS/0002` says
//!   "`rt.io()` is never stored. It is a parameter to the functions that need
//!   it", so `Tcp` holds descriptors and a flag and no `Io`. What the runtime
//!   is asked for is cancellation and nothing else, because a descriptor this
//!   module opened is a descriptor no `Io` backend has been told about, and
//!   handing it to one would be a claim that only holds for `Io.Threaded`.
//! - **`io` is the second parameter**, after the receiver, on every operation
//!   that needs it. `socket.zig` gives the reason: a method's receiver is its
//!   first parameter, and every other method on every other type in this
//!   project puts its receiver first. `stop` is the one operation without an
//!   `io`, and that is the one a signal handler may call.
//! - **The wake descriptor is the second descriptor the struct owns.** A
//!   `poll` is asleep in the kernel; there is nowhere to consult a flag from,
//!   so a wait that has to be *ended* rather than run to the end of its slice
//!   needs a descriptor to become readable. An `eventfd` rather than a
//!   self-pipe, for `socket.zig`'s reasons: one descriptor instead of two, a
//!   counter instead of a byte buffer, and `EFD_SEMAPHORE` so a read takes one
//!   wake off the counter rather than all of them.
//! - **Stop is two signal-handler-safe calls**: one atomic store and one
//!   `write`. Both are on POSIX's list; an `Io` is not, and the drain
//!   `socket.zig`'s stop defers to a send would need `recvmsg`, which is not.
//! - **The wake is polled beside the handle, and stop outranks readiness.** A
//!   stop is a message to the wait, not a fact about the stream, so it is
//!   checked first and it answers `error.Canceled` whatever else the same
//!   `poll` pass found.
//! - **`EINTR` is retried under a fixed bound**, because a signal is not a
//!   fact about a connection and retrying is the only correct answer, and a
//!   timeout answers `error.WouldBlock` — the same answer `Socket.receive`
//!   gives for a datagram queue that stayed empty.
//! - **No buffer is stored.** The caller's buffer is the caller's, which is
//!   what lets a stack pool one and what lets a test hand over a stack array.
//!
//! # Where this file parts company: a stopped stream stays stopped
//!
//! `Socket.stop` is a message, not a latch, because a stopped datagram socket
//! is still usable: the next send drains the queue and spends the counter, and
//! the datagrams in that queue are the kernel's to drop — nobody had read them
//! and nobody is going to. **A stream has no equivalent of that drain**, and
//! that is a fact about streams rather than a decision this module made.
//! Every byte in a stream's receive buffer was put there by the peer and is
//! owed to it, and there is no read that discards a stream's bytes without
//! discarding a protocol message somebody is part way through decoding. So
//! there is nothing to drain, nothing to restart, and no method here that
//! un-stops a stream: `stop` is terminal and a caller that has stopped a
//! stream closes it. The absence is the point — a `Tcp` with a restart path
//! would be a restart that has to invent somewhere to put the bytes it just
//! threw away.
//!
//! # The boundary, and why it is a boundary and not a stub
//!
//! **This seam connects. It does not listen, accept, or set socket options, and
//! none of the three is a stub.** Each is a decision about who owns the other
//! end of a connection, and each names the module that owns it:
//!
//! - **No listener and no accept.** A listener is the other half of a service,
//!   and this project's listeners live in `endpoint/` and `relay/`, which own
//!   them for a reason that has nothing to do with a client seam. The
//!   asymmetry is real: a caller that needs both halves writes them in two
//!   places, which is the correct place for them.
//! - **No socket options.** `SO_REUSEADDR` and `SO_REUSEPORT` are a *bind*
//!   concern, and there is no bind here — the kernel chooses the local address
//!   and the ephemeral port at `connect`. `TCP_NODELAY` and `TCP_KEEPALIVE`
//!   are latency and liveness policies that belong to whatever protocol runs
//!   over the stream, not to the stream: this module cannot tell whether a
//!   caller wants every byte immediately or wants the kernel to coalesce.
//!   Adding an `Options` struct would make a decision that is not this
//!   module's, and would be wrong for at least one caller.
//!
//! So the absence is a *fact* about the surface rather than an unfinished
//! function body: every call this file makes is one whose answer it can name,
//! and no path exists here that could reach an unimplemented arm. A stub
//! would be a call whose answer is guessed; this has no such call.
//!
//! # The half-close, and the short write
//!
//! Two decisions, and they are the ones where a caller can lose track of its
//! own bytes:
//!
//! **A peer's half-close is a `read` of zero, never an error.** `read(2)` is
//! the standard for this: a return of zero is how POSIX spells end-of-file,
//! and for a stream that is the peer's `shutdown(SHUT_WR)` or its last
//! `close`. It is a count rather than a failure because the peer that
//! half-closed can still read — the other direction stays open until this one
//! closes it — so refusing it would tell a caller the stream is finished when
//! it is only half finished, and a caller that believes that will not send the
//! last thing it had to say.
//!
//! **A write that transfers less than it was handed is a short count, never an
//! error.** A stream has no message boundary and no datagram size limit, so
//! `send(2)` takes what fits in the send buffer and returns that count. The
//! alternative would have to be an error, and *an error with no count is the
//! one thing that loses a caller's bytes*: the caller cannot then tell how much
//! of its buffer left the host and where to resume from. So the count is the
//! whole contract, and `error.PeerClosed` — which is `EPIPE` and carries the
//! guarantee that nothing at all was written — is the only write refusal that
//! says anything about bytes, because it says they are all still there.
//!
//! Together the two are the accounting: every byte a caller handed this module
//! either appears in a returned count or is reported with the count unchanged.
//! No path returns an error without saying how much left.
//!
//! # Reuse
//!
//! The address conversions are `transport/socket_addr.zig`'s
//! `writeSockaddr` and `readSockaddr`, reached where they are defined rather
//! than through `socket.zig`, because importing that facade for two functions
//! would pull the whole datagram surface into every caller of a stream. The
//! `eventfd` and the `getsockname` are `transport/socket_open.zig`'s
//! `createWake` and `boundAddress` for the same reason, and the errno
//! vocabulary of the open is that file's `OpenError`. `transport` does not
//! import `discovery`, and this file is where that direction is kept.

const std = @import("std");

const base_addr = @import("../base/addr.zig");
const socket_addr = @import("socket_addr.zig");
const socket_open = @import("socket_open.zig");

const tcp_error = @import("tcp_error.zig");
const tcp_sys = @import("tcp_sys.zig");

const posix = std.posix;
const c = std.c;
const linux = std.os.linux;

/// See `tcp_sys.max_syscall_attempts`.
pub const max_syscall_attempts = tcp_sys.max_syscall_attempts;

/// See `tcp_error.OpenError`.
pub const OpenError = tcp_error.OpenError;
/// See `tcp_error.WaitError`.
pub const WaitError = tcp_error.WaitError;
/// See `tcp_error.ConnectError`.
pub const ConnectError = tcp_error.ConnectError;
/// See `tcp_error.ReadError`.
pub const ReadError = tcp_error.ReadError;
/// See `tcp_error.WriteError`.
pub const WriteError = tcp_error.WriteError;

const readSockaddr = socket_addr.readSockaddr;
const writeSockaddr = socket_addr.writeSockaddr;
const createWake = socket_open.createWake;

/// The counter an `eventfd` counts in, which the kernel fixes at eight bytes
/// and both `read` and `write` want all of. A value rather than a count of
/// anything in this file, which is the whole of what a wake carries.
const wake_width = @sizeOf(u64);

/// A TCP stream that is not yet connected.
///
/// No `Io` is stored, for the reason the module doc gives. No buffer is
/// either: the receive buffer is the caller's, which is what lets a stack pool
/// one and what lets a test hand over a stack array. Two descriptors and one
/// flag, and every one of the three is about being stopped rather than about
/// carrying a byte; see `stop`.
///
/// A successful `create` owns both descriptors. Close them exactly once, with
/// `close`, after all operations and stop callers finish. Copies share those
/// descriptors. Keep the value at a stable address while a stop caller borrows
/// it. Serialize connects, reads and writes. Only `stop` may run concurrently
/// with them. An operation borrows `io` and its backend only until it returns.
///
/// One `connect` per stream: a second one is `EISCONN`, which
/// `tcp_sys.connectFromErrno` reports as `error.Unexpected`, and that is
/// deliberate — a caller that reaches it has a bug this struct will not paper
/// over.
pub const Tcp = struct {
    /// The descriptor. `O_NONBLOCK` from the moment it exists, which is what
    /// makes `EAGAIN` a fact a caller can act on instead of a stall.
    handle: c.fd_t,
    /// The descriptor a stop writes to, in the same `poll` set as `handle`
    /// and the only thing that can end a wait before its timeout.
    wake: c.fd_t,
    /// Set by `stop` and never cleared. There is no restart path and the
    /// module doc says why there cannot be one; every wait on a stopped
    /// stream answers `error.Canceled` at once.
    stopped: std.atomic.Value(bool),
    /// Where this stream was asked to connect, and — after `connect` has
    /// returned — where it is connected to.
    peer: base_addr.SocketAddr,
    /// Where the stream is bound, with the ephemeral port the kernel chose.
    /// Port zero until `connect` returns, because that is what the kernel
    /// spells before the handshake: an unconnected stream is bound to the
    /// wildcard address on no port at all.
    local: base_addr.SocketAddr,

    /// Open a stream for `peer`'s family. Nothing is sent and nothing is
    /// bound: the local address is the kernel's to choose at `connect`, which
    /// is what makes this a client seam and not a server one.
    ///
    /// A refusal refuses the stream, and `createWake`'s doc says why that
    /// matters twice over: a stream whose wait cannot be ended is the failure
    /// the wake descriptor exists to prevent, and a stream opened for the
    /// wrong family cannot connect at all.
    pub fn create(peer: base_addr.SocketAddr) OpenError!Tcp {
        const handle = try tcp_sys.createStream(peer.ip);
        errdefer _ = c.close(handle);
        // After the descriptor, because a socket refused on nothing is one
        // fewer descriptor to leak than a socket refused after its wake.
        const wake = try createWake();
        errdefer _ = c.close(wake);
        return .{
            .handle = handle,
            .wake = wake,
            .stopped = .init(false),
            .peer = peer,
            .local = .{ .ip = peer.ip, .port = 0 },
        };
    }

    /// Close both descriptors. Nothing is buffered on this side: a write that
    /// returned has left the socket and a read that returned has been taken.
    ///
    /// Do not close a copy or call this twice. Neither descriptor is reset and
    /// the stopped flag is left standing, because the value is the caller's
    /// after this and a `defer stream.close()` on a stopped stream must not
    /// be able to hand back something that looks usable.
    pub fn close(self: *Tcp) void {
        _ = c.close(self.wake);
        _ = c.close(self.handle);
    }

    /// Name this stream stopped: end the wait in flight, and answer every
    /// later wait at once.
    ///
    /// Both halves of this body are `transport/socket.zig`'s `Socket.stop` and
    /// both are here for its reasons. Everything the body does is something a
    /// signal handler may do: one store and one `write`, both on POSIX's list
    /// of calls such a handler is allowed to make. A store alone is not a wake
    /// — there is nowhere to consult a flag from, because the waiter is asleep
    /// in the kernel — and the drain `Socket.stop` defers to its next send
    /// would need `recvmsg`, which is not on that list.
    ///
    /// **A stopped stream stays stopped.** See the module doc: a stream's
    /// receive buffer is bytes the peer is owed and nothing may discard them,
    /// so there is no drain to perform and no restart to perform it for. There
    /// is no method that un-stops this value.
    ///
    /// Keep the stream alive and open until every concurrent stop returns.
    pub fn stop(self: *Tcp) void {
        self.stopped.store(true, .release);
        var one: u64 = 1;
        _ = c.write(self.wake, std.mem.asBytes(&one), wake_width);
    }

    /// Connect to `peer`, waiting at most `timeout_ms`, and say what it cost.
    ///
    /// A `timeout_ms` of null waits as long as the caller means, and time
    /// stays the caller's: this reads no clock. A timeout returns
    /// `error.WouldBlock`, the same answer `Socket.receive` gives. `stop`
    /// wakes a blocked poll with `error.Canceled`. An `io` cancellation is
    /// checked around the syscalls but does not itself wake the poll.
    ///
    /// On success `local` carries the ephemeral port the kernel chose. On a
    /// refusal the descriptor is left as it was and **cannot be connected
    /// again**: RFC 9293 §3.4.1 leaves the state of a socket after
    /// `ECONNREFUSED` implementation-defined, so a caller that wants to try
    /// again closes this one and opens another.
    pub fn connect(self: *Tcp, io: std.Io, timeout_ms: ?i32) ConnectError!void {
        // **Ask, then wait.** A `poll` for writability on a descriptor with no
        // handshake behind it is not ready and never will be — the connect has
        // to be started before there is anything to wait for, so the wait is
        // second and there is only one.
        if (try tcp_sys.beginConnect(self.handle, io, self.peer)) {
            self.local = try tcp_sys.localAddress(self.handle);
            return;
        }
        // The handshake is in the kernel now, so the wait for it is a second
        // one — and it is a `poll` for writability, because a connect that is
        // still running is a descriptor that is not yet writable and not yet
        // either of the other two.
        try self.awaitReady(io, timeout_ms, posix.POLL.OUT);
        try tcp_sys.connectResult(self.handle);
        self.local = try tcp_sys.localAddress(self.handle);
    }

    /// Take up to `buffer.len` bytes, waiting for them when asked to, and say
    /// how many there were.
    ///
    /// **A zero is the answer and not a failure**: it is the peer's half-close,
    /// `read(2)`'s own spelling of end-of-file. The other direction stays
    /// open after it, so a caller that wants to send one last thing still can;
    /// see the module doc for why this is a count.
    ///
    /// A `timeout_ms` of null waits as long as the caller means. Zero waits
    /// once, and a timeout returns `error.WouldBlock`. `stop` wakes a blocked
    /// poll with `error.Canceled`. `buffer` may be overwritten even on error.
    pub fn read(
        self: *const Tcp,
        io: std.Io,
        buffer: []u8,
        timeout_ms: ?i32,
    ) ReadError!usize {
        try self.awaitReady(io, timeout_ms, posix.POLL.IN);
        return tcp_sys.recvStream(self.handle, io, buffer);
    }

    /// Put as much of `bytes` on the wire as the stream takes, and say how
    /// many bytes that was.
    ///
    /// **A short count is a success and never an error.** The count is what
    /// leaves this host; resume from `bytes[written..]`. See the module doc
    /// for why this is the one rule the whole surface turns on: a refusal with
    /// no count is how a caller loses track of its own bytes, and the only
    /// refusal here that says anything about bytes — `error.PeerClosed` —
    /// guarantees that none of them left.
    ///
    /// A `timeout_ms` of null waits as long as the caller means. A timeout
    /// returns `error.WouldBlock`. `stop` wakes a blocked poll with
    /// `error.Canceled`.
    pub fn write(
        self: *const Tcp,
        io: std.Io,
        bytes: []const u8,
        timeout_ms: ?i32,
    ) WriteError!usize {
        try self.awaitReady(io, timeout_ms, posix.POLL.OUT);
        return tcp_sys.sendStream(self.handle, io, bytes);
    }

    /// Wait for the descriptor to be ready for `events`, or for a stop to end
    /// the wait.
    ///
    /// A `poll` on the descriptor and not an `Io` operation, for
    /// `transport/socket.zig`'s reason: this module opened the descriptor with
    /// `std.c.socket`, so no backend has ever been told the descriptor exists
    /// and only `Io.Threaded` would cope with being handed one.
    /// `posix.poll` already retries a signal, and zero ready is the timeout
    /// rather than an error.
    ///
    /// The set has two entries, and that is the whole of how a stop reaches a
    /// wait already in progress: the wake is a descriptor like any other and
    /// `poll` returns for it exactly as it returns for a byte. **A stop is
    /// checked first and outranks whatever else the same pass found**: it is a
    /// message to the wait and not a fact about the stream, and a wait that
    /// has been told to stop is over whether or not bytes were ready.
    ///
    /// The wake counter is deliberately left standing. Nothing here spends it,
    /// because there is no restart for it to be spent on: `stop` is terminal,
    /// so a unit standing on the counter is the correct state of a stopped
    /// stream, and every later wait answers `error.Canceled` at once rather
    /// than waiting on a descriptor nobody will use again.
    fn awaitReady(
        self: *const Tcp,
        io: std.Io,
        timeout_ms: ?i32,
        events: i16,
    ) WaitError!void {
        try io.checkCancel();
        var descriptors = [_]posix.pollfd{
            .{
                .fd = self.handle,
                .events = events,
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
        if (descriptors[1].revents != 0) return error.Canceled;
        if (descriptors[0].revents == 0) return error.WouldBlock;
    }
};

const t = std.testing;

/// Loopback, which is where every test here connects. `127.0.0.1` and not a
/// name, because a test that resolves a name is a test that can fail on a
/// machine's `/etc/hosts`.
fn loopback(port: u16) base_addr.SocketAddr {
    return .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = port };
}

/// A real peer on the other end of a real stream, for the tests that need one.
///
/// Built with `std.c` directly and not through this module's own surface. The
/// module doc's "no listener, no accept" is a boundary fact about the *seam*,
/// not a claim that a listener is unwritable — and a fixture that built its
/// peer out of `Tcp` could not tell a forwarding bug from a working one.
const Pair = struct {
    /// The listening end, kept open for the life of the pair so that nothing
    /// else can take the port.
    listener: c.fd_t,
    /// The accepted end: this module's peer, reached only through `std.c`.
    peer: c.fd_t,
    /// The stream under test, at a stable address so `stop` can borrow it.
    stream: Tcp,
    /// Whether `peer` is still a descriptor this fixture owns. A test that
    /// closes the peer itself has to say so, because `deinit` closing it a
    /// second time would be a second `close(2)` on a number the kernel may
    /// have handed to something else in between.
    peer_open: bool = true,

    /// A connected `Tcp` and an accepted peer, with the kernel's own timeout
    /// on every wait so a failure is a failed test and never a hung suite.
    fn open() !Pair {
        const listener = try bindLoopback(0);
        errdefer _ = c.close(listener);
        if (c.listen(listener, 1) != 0) return error.TestFixtureRefused;
        var stream = try Tcp.create(loopback(try portOf(listener)));
        errdefer stream.close();
        try stream.connect(t.io, fixture_timeout_ms);
        return .{ .listener = listener, .peer = try acceptOne(listener), .stream = stream };
    }

    fn deinit(self: *Pair) void {
        self.stream.close();
        if (self.peer_open) _ = c.close(self.peer);
        _ = c.close(self.listener);
    }

    /// Take exactly `buffer.len` bytes from the peer, or say the fixture
    /// failed. Bounded by the same timeout as every other wait here.
    fn take(self: *Pair, buffer: []u8) !usize {
        var at: usize = 0;
        while (at < buffer.len) {
            var descriptors = [_]posix.pollfd{
                .{ .fd = self.peer, .events = posix.POLL.IN, .revents = 0 },
            };
            _ = posix.poll(&descriptors, fixture_timeout_ms) catch return error.TestFixtureRefused;
            if (descriptors[0].revents == 0) return error.TestFixtureRefused;
            const rc = c.recv(
                self.peer,
                @as(?*anyopaque, @ptrCast(buffer.ptr + at)),
                buffer.len - at,
                0,
            );
            if (rc <= 0) return error.TestFixtureRefused;
            at += @intCast(rc);
        }
        return at;
    }
};

/// Every wait in this file's tests is bounded, so a regression costs a failed
/// test rather than a suite that never finishes.
const fixture_timeout_ms: i32 = 5000;

/// Bind a loopback listener on `port`, or the kernel's choice when it is zero.
fn bindLoopback(port: u16) !c.fd_t {
    const handle = c.socket(
        linux.AF.INET,
        linux.SOCK.STREAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK,
        0,
    );
    if (handle < 0) return error.TestFixtureRefused;
    errdefer _ = c.close(handle);
    var name: c.sockaddr.storage = undefined;
    const length = writeSockaddr(loopback(port), &name);
    if (c.bind(handle, @as(*const c.sockaddr, @ptrCast(&name)), length) != 0) {
        return error.TestFixtureRefused;
    }
    return handle;
}

fn portOf(handle: c.fd_t) !u16 {
    var name: c.sockaddr.storage = undefined;
    var length: c.socklen_t = @sizeOf(c.sockaddr.storage);
    if (c.getsockname(handle, @as(*c.sockaddr, @ptrCast(&name)), &length) != 0) {
        return error.TestFixtureRefused;
    }
    return (readSockaddr(&name) orelse return error.TestFixtureRefused).port;
}

/// Take the one connection a pair's listener has, waiting for it if the
/// non-blocking `accept4` has not been given it yet.
fn acceptOne(listener: c.fd_t) !c.fd_t {
    var attempt: usize = 0;
    while (attempt < max_syscall_attempts) : (attempt += 1) {
        const rc = c.accept4(listener, null, null, linux.SOCK.CLOEXEC);
        if (rc >= 0) return rc;
        switch (c.errno(rc)) {
            .SUCCESS => return rc,
            .INTR => continue,
            .AGAIN => {
                var descriptors = [_]posix.pollfd{
                    .{ .fd = listener, .events = posix.POLL.IN, .revents = 0 },
                };
                _ = posix.poll(&descriptors, fixture_timeout_ms) catch
                    return error.TestFixtureRefused;
                if (descriptors[0].revents == 0) return error.TestFixtureRefused;
                continue;
            },
            else => return error.TestFixtureRefused,
        }
    }
    return error.TestFixtureRefused;
}

test "a port that is bound and not listening refuses the connect" {
    // The refusal a client actually meets, and it is deterministic because the
    // fixture keeps the port: a bound-but-not-listening socket is the one
    // state that cannot be taken over by another process, so this does not
    // race a stranger who binds the same number between the close and the
    // connect.
    const listener = try bindLoopback(0);
    defer _ = c.close(listener);
    var stream = try Tcp.create(loopback(try portOf(listener)));
    defer stream.close();

    // The refusal is a named arm and not a bare errno, which is what a
    // caller that has to decide between "this host is down" and "this port is
    // shut" needs. A timeout would be a different fact and is not what a
    // closed port produces.
    try t.expectError(error.ConnectionRefused, stream.connect(t.io, fixture_timeout_ms));
    // A refused connect leaves nothing to retry on, so `local` never learned
    // a port and `peer` is still what the caller asked for.
    try t.expectEqual(@as(u16, 0), stream.local.port);
    try t.expectEqual(loopback(try portOf(listener)), stream.peer);
}

test "a half-close is a zero, the other direction stays open, and a deadline is WouldBlock" {
    // Both halves of the accounting, over a real connection.
    var pair = try Pair.open();
    defer pair.deinit();

    // Bytes out, and the count says all of them left.
    try t.expectEqual(@as(usize, 5), try pair.stream.write(t.io, "hello", fixture_timeout_ms));
    var inbound: [5]u8 = undefined;
    try t.expectEqual(@as(usize, 5), try pair.take(&inbound));
    try t.expectEqualStrings("hello", &inbound);
    try t.expectEqual(@as(usize, 4), try pair.stream.write(t.io, "ping", fixture_timeout_ms));
    try t.expectEqual(@as(usize, 4), try pair.take(inbound[0..4]));
    try t.expectEqualStrings("ping", inbound[0..4]);

    // A deadline with nothing queued is `error.WouldBlock` — the same answer
    // `Socket.receive` gives for a datagram queue that stayed empty — and it
    // is a value rather than a failure, so the peer has to answer before the
    // next read is allowed to take anything.
    try t.expectError(error.WouldBlock, pair.stream.read(t.io, &inbound, 50));

    // The peer's half-close. It will send nothing more, and this is a zero:
    // the module's decision, and `read(2)`'s own spelling of end-of-file.
    try t.expectEqual(@as(c_int, 0), c.shutdown(pair.peer, linux.SHUT.WR));
    try t.expectEqual(@as(usize, 0), try pair.stream.read(t.io, &inbound, fixture_timeout_ms));

    // And the other direction is still open, which is the whole reason a
    // half-close is a count and not a refusal. A module that had made it an
    // error would be telling this caller the stream is finished, and the last
    // four bytes below would never be sent.
    try t.expectEqual(@as(usize, 4), try pair.stream.write(t.io, "last", fixture_timeout_ms));
    try t.expectEqual(@as(usize, 4), try pair.take(inbound[0..4]));
    try t.expectEqualStrings("last", inbound[0..4]);

    // With the peer now gone entirely, the read that follows its close is a
    // zero too rather than an error: an orderly close and a half-close are
    // the same event to the only direction left.
    try t.expectEqual(@as(c_int, 0), c.close(pair.peer));
    pair.peer_open = false;
    try t.expectEqual(@as(usize, 0), try pair.stream.read(t.io, &inbound, fixture_timeout_ms));
}

test "a write the peer cannot take is a short count, not a refusal" {
    // The other half of the accounting, and the half that actually loses
    // bytes when it is wrong. The send buffer is floored and the peer never
    // reads, so the kernel has to take part of a megabyte and say how much;
    // a refusal here would be a refusal with no count, which is exactly the
    // answer a caller cannot resume from.
    var pair = try Pair.open();
    defer pair.deinit();

    var floor: c_int = 4096;
    try t.expectEqual(
        @as(c_int, 0),
        c.setsockopt(
            pair.stream.handle,
            linux.SOL.SOCKET,
            linux.SO.SNDBUF,
            &floor,
            @intCast(@sizeOf(c_int)),
        ),
    );
    const payload = try t.allocator.alloc(u8, 1 << 20);
    defer t.allocator.free(payload);
    @memset(payload, 'x');

    const written = try pair.stream.write(t.io, payload, fixture_timeout_ms);
    // Some left, and not all of it: a send that took everything would mean the
    // bound never bit, and a send that took nothing would mean this is
    // refusing rather than reporting a short count.
    try t.expect(written > 0);
    try t.expect(written < payload.len);
    // And the count is about this host rather than about the kernel's queue:
    // the peer really is holding that many bytes, which is what makes resuming
    // at `payload[written..]` correct rather than merely plausible.
    const held = try t.allocator.alloc(u8, written);
    defer t.allocator.free(held);
    try t.expectEqual(written, try pair.take(held));
    for (held) |byte| try t.expectEqual(@as(u8, 'x'), byte);
}

test "a stop ends a wait in progress, and a stopped stream stays stopped" {
    // The wake descriptor's whole reason for existing. A `poll` is asleep in
    // the kernel, so a flag consulted around the call is consulted only once
    // the call is over — which is the failure the `eventfd` removes. The stop
    // comes from another task, and the read below cannot return until it
    // arrives, because the peer never speaks.
    var pair = try Pair.open();
    defer pair.deinit();

    const stopper = try std.Thread.spawn(.{}, stopAfter, .{ t.io, &pair.stream, 50 });
    var buffer: [8]u8 = undefined;
    const read = pair.stream.read(t.io, &buffer, fixture_timeout_ms);
    stopper.join();
    try t.expectError(error.Canceled, read);

    // Terminal, and that is the part `Socket.stop` is not: there is no restart
    // for this value, so a second wait answers at once instead of sitting out
    // its deadline on a stream nobody will use again. The wake counter is
    // still standing, which is what makes the answer immediate.
    try t.expectError(error.Canceled, pair.stream.read(t.io, &buffer, fixture_timeout_ms));
    // And a stopped stream refuses a write for the same reason, before any
    // byte can leave and be accounted for.
    try t.expectError(error.Canceled, pair.stream.write(t.io, "x", fixture_timeout_ms));
}

/// Stop a stream after `delay_ms`, from a task of its own.
///
/// The delay is an `Io` sleep rather than a `poll`, because this helper is not
/// waiting on a descriptor: it is standing still so the read above is asleep in
/// the kernel when the stop arrives, which is the state under test. Handing it
/// the caller's `Io` keeps the clock in the caller's hands, and a sleep that
/// ends in `error.Canceled` still stops the stream — returning without the stop
/// would leave that read to sit out its deadline instead of being woken.
fn stopAfter(io: std.Io, stream: *Tcp, delay_ms: i64) void {
    // The arm is named rather than swallowed by a bare `catch`, which is the
    // only thing that changes here: `Cancelable` is `error{Canceled}` and the
    // doc above is about exactly that refusal, so it is handled and not
    // discarded. Spelling it out is what makes a second arm in `Cancelable` a
    // build error here instead of a refusal this line stops noticing.
    io.sleep(.fromMilliseconds(delay_ms), .awake) catch |err| switch (err) {
        error.Canceled => {},
    };
    stream.stop();
}
