//! Owned incremental TCP streams with borrowed execution and caller-owned buffers.
const std = @import("std");

const base_addr = @import("../base/addr.zig");
const execution_module = @import("tcp_execution.zig");
const Execution = execution_module.Execution;
const tcp_error = @import("tcp_error.zig");
const tcp_sys = @import("tcp_sys.zig");
const posix = std.posix;
const c = std.c;
const linux = std.os.linux;
const readSockaddr = @import("socket_addr.zig").readSockaddr;
const writeSockaddr = @import("socket_addr.zig").writeSockaddr;

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

/// An owned TCP stream, created unconnected or accepted already connected.
///
/// No Io or buffer is stored. Execution is borrowed through cleanup and all
/// concurrent stop calls, so the provider must outlive this owner.
///
/// A successful `create` owns both descriptors. Close them exactly once, with
/// `close`, after all operations and stop callers finish. Copies share those
/// descriptors. Keep the value at a stable address while a stop caller borrows
/// it. Serialize connects, reads and writes. Only `stop` may run concurrently
/// with them. An operation borrows `io` and its backend only until it returns.
///
/// Connect state is retained, so repeated starts never restart a handshake.
/// A failed handshake requires closing the stream and creating a fresh one.
pub const Tcp = struct {
    /// The descriptor. `O_NONBLOCK` from the moment it exists, which is what
    /// makes `EAGAIN` a fact a caller can act on instead of a stall.
    handle: c.fd_t,
    /// The descriptor a stop writes to, in the same `poll` set as `handle`
    /// and the only thing that can end a wait before its timeout.
    wake: c.fd_t,
    execution: Execution,
    /// Terminal latch: stream bytes cannot be drained to implement a restart.
    stopped: std.atomic.Value(bool),
    /// Requested destination for a client, or the accepted peer for a server.
    peer: base_addr.SocketAddr,
    /// Actual local address after connection or accept. Port zero while a
    /// client has not completed its handshake.
    local: base_addr.SocketAddr,
    /// Handshake state; callers must not mutate it or restart a failed stream.
    connect_state: union(enum) {
        idle,
        connecting,
        connected,
        failed: ConnectError,
    } = .idle,

    /// Open a stream for `peer`'s family. Nothing is sent and nothing is
    /// bound: the local address is the kernel's to choose at `connect`, which
    /// is what makes this a client seam and not a server one.
    ///
    /// A refusal refuses the stream, and `createWake`'s doc says why that
    /// matters twice over: a stream whose wait cannot be ended is the failure
    /// the wake descriptor exists to prevent, and a stream opened for the
    /// wrong family cannot connect at all.
    pub fn create(io: std.Io, peer: base_addr.SocketAddr, execution: Execution) OpenError!Tcp {
        try io.checkCancel();
        const handle = try execution.vtable.createStream(io, execution.context, peer.ip);
        errdefer execution.vtable.close(execution.context, handle);
        try io.checkCancel();
        const wake = try execution.vtable.createWake(io, execution.context);
        errdefer execution.vtable.close(execution.context, wake);
        return .{
            .handle = handle,
            .wake = wake,
            .execution = execution,
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
        self.execution.vtable.close(self.execution.context, self.wake);
        self.execution.vtable.close(self.execution.context, self.handle);
    }

    /// Name this stream stopped: end the wait in flight, and answer every
    /// later wait at once.
    ///
    /// Only native Execution is signal-handler safe. Scripted callbacks must
    /// be called from ordinary execution. Keep this owner and its provider alive
    /// until every concurrent stop returns. Stop never drains stream bytes.
    pub fn stop(self: *Tcp) void {
        self.stopped.store(true, .release);
        self.execution.vtable.wake(self.execution.context, self.wake);
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
        if (try self.startConnect(io)) return;
        try self.awaitReady(io, timeout_ms, posix.POLL.OUT);
        if (!try self.finishConnect(io)) return error.WouldBlock;
    }

    /// Start one nonblocking handshake. True means connected; false means pending.
    /// Repeated calls report the retained state without issuing another connect.
    /// A terminal error is retained until close; the descriptor cannot be reused.
    pub fn startConnect(self: *Tcp, io: std.Io) ConnectError!bool {
        if (self.stopped.load(.acquire)) return error.Canceled;
        try io.checkCancel();
        switch (self.connect_state) {
            .idle => {},
            .connecting => return false,
            .connected => return true,
            .failed => |err| return err,
        }
        const connected = self.execution.vtable.startConnect(
            io,
            self.execution.context,
            self.handle,
            self.peer,
        ) catch |err| {
            self.connect_state = .{ .failed = err };
            return err;
        };
        if (connected) return self.completeConnect(io);
        self.connect_state = .connecting;
        return false;
    }

    /// Poll a pending handshake once with zero timeout, without restarting it.
    /// False means not ready yet. Calling before startConnect is Unexpected.
    pub fn finishConnect(self: *Tcp, io: std.Io) ConnectError!bool {
        if (self.stopped.load(.acquire)) return error.Canceled;
        try io.checkCancel();
        switch (self.connect_state) {
            .idle => return error.Unexpected,
            .connecting => {},
            .connected => return true,
            .failed => |err| return err,
        }
        self.awaitReady(io, 0, posix.POLL.OUT) catch |err| switch (err) {
            error.WouldBlock => return false,
            else => return err,
        };
        self.execution.vtable.connectionError(io, self.execution.context, self.handle) catch |err| {
            self.connect_state = .{ .failed = err };
            return err;
        };
        return self.completeConnect(io);
    }

    fn completeConnect(self: *Tcp, io: std.Io) ConnectError!bool {
        self.local = self.execution.vtable.boundAddress(
            io,
            self.execution.context,
            self.handle,
        ) catch |err| {
            const mapped: ConnectError = switch (err) {
                error.AddressNotAvailable => error.AddressNotAvailable,
                error.Canceled => error.Canceled,
                else => error.Unexpected,
            };
            self.connect_state = .{ .failed = mapped };
            return mapped;
        };
        self.connect_state = .connected;
        return true;
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
        return self.execution.vtable.read(io, self.execution.context, self.handle, buffer);
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
        return self.execution.vtable.write(io, self.execution.context, self.handle, bytes);
    }

    /// Wait for the descriptor to be ready for `events`, or for a stop to end
    /// the wait.
    ///
    /// The owner checks its terminal latch after the callback too: a concurrent
    /// stop outranks readiness and provider errors from the same wait.
    fn awaitReady(
        self: *const Tcp,
        io: std.Io,
        timeout_ms: ?i32,
        events: i16,
    ) WaitError!void {
        if (self.stopped.load(.acquire)) return error.Canceled;
        try io.checkCancel();
        const result = self.execution.vtable.wait(io, self.execution.context, .{
            .handle = self.handle,
            .wake = self.wake,
            .events = events,
            .timeout_ms = timeout_ms,
        });
        if (self.stopped.load(.acquire)) return error.Canceled;
        try io.checkCancel();
        try result;
    }
};

const t = std.testing;

/// Loopback, which is where every test here connects. `127.0.0.1` and not a
/// name, because a test that resolves a name is a test that can fail on a
/// machine's `/etc/hosts`.
fn loopback(port: u16) base_addr.SocketAddr {
    return .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = port };
}

test "a nonblocking listener reports an empty accept queue" {
    // An empty queue must return immediately without allocating a stream or wake.
    var listener = try @import("tcp_listener.zig").Listener.init(t.io, loopback(0), .native);
    defer listener.close();
    try t.expect(listener.local.port != 0);
    try t.expect((try listener.accept(t.io)) == null);
}

test "incremental connect and listener exchange bytes with correct addresses" {
    // Exercise the public server seam and repeated starts without a second handshake.
    var listener = try @import("tcp_listener.zig").Listener.init(t.io, loopback(0), .native);
    defer listener.close();
    var client = try Tcp.create(t.io, listener.local, .native);
    defer client.close();
    const connected = try client.startConnect(t.io);
    try t.expectEqual(connected, try client.startConnect(t.io));
    var ready = [_]posix.pollfd{
        .{ .fd = client.handle, .events = posix.POLL.OUT, .revents = 0 },
        .{ .fd = listener.handle, .events = posix.POLL.IN, .revents = 0 },
    };
    _ = try posix.poll(&ready, fixture_timeout_ms);
    try t.expect(try client.finishConnect(t.io));
    try t.expect(try client.startConnect(t.io));
    try t.expect(try client.finishConnect(t.io));
    var server = (try listener.accept(t.io)) orelse return error.TestFixtureRefused;
    defer server.close();
    try t.expectEqual(listener.local, server.local);
    try t.expectEqual(client.local, server.peer);
    try t.expectEqual(server.local, client.peer);
    const flags = c.fcntl(server.handle, c.F.GETFL, @as(c_int, 0));
    try t.expect(flags >= 0);
    const nonblock: c_uint = @bitCast(linux.O{ .NONBLOCK = true });
    try t.expect((@as(c_uint, @bitCast(@as(c_int, flags))) & nonblock) != 0);
    try t.expectEqual(@as(usize, 4), try client.write(t.io, "ping", fixture_timeout_ms));
    var buffer: [4]u8 = undefined;
    try t.expectEqual(@as(usize, 4), try server.read(t.io, &buffer, fixture_timeout_ms));
    try t.expectEqualStrings("ping", &buffer);
    try t.expectEqual(@as(usize, 4), try server.write(t.io, "pong", fixture_timeout_ms));
    try t.expectEqual(@as(usize, 4), try client.read(t.io, &buffer, fixture_timeout_ms));
    try t.expectEqualStrings("pong", &buffer);
    try t.expect((try listener.accept(t.io)) == null);
    server.stop();
    try t.expectError(error.Canceled, server.read(t.io, &buffer, 0));
    client.stop();
    try t.expectError(error.Canceled, client.startConnect(t.io));
    try t.expectError(error.Canceled, client.finishConnect(t.io));
}

test "incremental connect retains a failed result and never restarts it" {
    // SO_ERROR is consumed by reads, so a refused handshake must retain its result.
    const handle = try bindLoopback(0);
    defer _ = c.close(handle);
    var client = try Tcp.create(t.io, loopback(try portOf(handle)), .native);
    defer client.close();
    try t.expectError(error.Unexpected, client.finishConnect(t.io));
    const connected = client.startConnect(t.io) catch |err| {
        try t.expectEqual(error.ConnectionRefused, err);
        try t.expectError(error.ConnectionRefused, client.startConnect(t.io));
        return;
    };
    try t.expect(!connected);
    var ready = [_]posix.pollfd{
        .{ .fd = client.handle, .events = posix.POLL.OUT, .revents = 0 },
    };
    _ = try posix.poll(&ready, fixture_timeout_ms);
    try t.expectError(error.ConnectionRefused, client.finishConnect(t.io));
    try t.expectError(error.ConnectionRefused, client.finishConnect(t.io));
    try t.expectError(error.ConnectionRefused, client.startConnect(t.io));
}

/// A real peer on the other end of a real stream, for the tests that need one.
///
/// Built with `std.c` directly rather than this module's own listener, so
/// the legacy stream tests retain an independent peer implementation.
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
        var stream = try Tcp.create(t.io, loopback(try portOf(listener)), .native);
        errdefer stream.close();
        try stream.connect(t.io, fixture_timeout_ms);
        return .{ .listener = listener, .peer = try acceptOne(listener), .stream = stream };
    }

    fn deinit(self: *Pair) void {
        self.stream.close();
        if (self.peer_open) _ = c.close(self.peer);
        _ = c.close(self.listener);
        self.* = undefined;
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
    var stream = try Tcp.create(t.io, loopback(try portOf(listener)), .native);
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

const StreamScript = struct {
    fail_at: ?usize = null,
    operation_count: usize = 0,
    acquired: [2]bool = .{ false, false },
    closes: [2]usize = .{ 0, 0 },
    starts: usize = 0,
    waits: usize = 0,
    last_timeout_ms: ?i32 = null,
    pending: bool = true,
    wait_error: ?WaitError = null,
    connection_error: ?ConnectError = null,
    read_calls: usize = 0,
    write_calls: usize = 0,
    stop_during_wait: ?*Tcp = null,
    wakes: usize = 0,

    fn execution(self: *StreamScript) Execution {
        return .{ .context = self, .vtable = &vtable };
    }

    fn state(context: ?*anyopaque) *StreamScript {
        return @ptrCast(@alignCast(context.?));
    }

    fn trip(self: *StreamScript) OpenError!void {
        const index = self.operation_count;
        self.operation_count += 1;
        if (self.fail_at == index) return error.ResourcesExhausted;
    }

    fn createStream(_: std.Io, context: ?*anyopaque, _: base_addr.IpAddress) OpenError!c.fd_t {
        const self = state(context);
        try self.trip();
        self.acquired[0] = true;
        return 0;
    }

    fn createWake(_: std.Io, context: ?*anyopaque) OpenError!c.fd_t {
        const self = state(context);
        try self.trip();
        self.acquired[1] = true;
        return 1;
    }

    fn close(context: ?*anyopaque, handle: c.fd_t) void {
        const self = state(context);
        const index: usize = @intCast(handle);
        std.debug.assert(self.acquired[index]);
        self.closes[index] += 1;
        std.debug.assert(self.closes[index] == 1);
    }

    fn wake(context: ?*anyopaque, handle: c.fd_t) void {
        std.debug.assert(handle == 1);
        state(context).wakes += 1;
    }

    fn startConnect(
        _: std.Io,
        context: ?*anyopaque,
        _: c.fd_t,
        _: base_addr.SocketAddr,
    ) ConnectError!bool {
        const self = state(context);
        self.starts += 1;
        return !self.pending;
    }

    fn wait(_: std.Io, context: ?*anyopaque, options: execution_module.WaitOptions) WaitError!void {
        const self = state(context);
        self.waits += 1;
        self.last_timeout_ms = options.timeout_ms;
        if (self.stop_during_wait) |stream| stream.stop();
        if (self.wait_error) |err| return err;
    }

    fn connectionError(_: std.Io, context: ?*anyopaque, _: c.fd_t) ConnectError!void {
        if (state(context).connection_error) |err| return err;
    }

    fn boundAddress(_: std.Io, _: ?*anyopaque, _: c.fd_t) OpenError!base_addr.SocketAddr {
        return loopback(1234);
    }

    fn read(_: std.Io, context: ?*anyopaque, _: c.fd_t, buffer: []u8) ReadError!usize {
        const self = state(context);
        self.read_calls += 1;
        if (self.read_calls == 1) {
            @memcpy(buffer[0..2], "ab");
            return 2;
        }
        if (self.read_calls == 2) return error.ConnectionReset;
        return 0;
    }

    fn write(_: std.Io, context: ?*anyopaque, _: c.fd_t, bytes: []const u8) WriteError!usize {
        const self = state(context);
        self.write_calls += 1;
        std.debug.assert(bytes.len >= 2);
        if (self.write_calls == 1) return 2;
        return error.PeerClosed;
    }

    const vtable: Execution.VTable = blk: {
        var table = Execution.native.vtable.*;
        table.createStream = createStream;
        table.createWake = createWake;
        table.close = close;
        table.wake = wake;
        table.startConnect = startConnect;
        table.wait = wait;
        table.connectionError = connectionError;
        table.boundAddress = boundAddress;
        table.read = read;
        table.write = write;
        break :blk table;
    };
};

test "scripted stream fail N closes every acquired descriptor once" {
    // Refuse each acquisition in turn, then let construction succeed.
    for (0..3) |failure| {
        var script: StreamScript = .{ .fail_at = failure };
        if (failure < 2) {
            try t.expectError(
                error.ResourcesExhausted,
                Tcp.create(t.io, loopback(80), script.execution()),
            );
        } else {
            var stream = try Tcp.create(t.io, loopback(80), script.execution());
            stream.close();
        }
        for (script.acquired, script.closes) |acquired, count| {
            try t.expectEqual(@as(usize, @intFromBool(acquired)), count);
        }
    }
}

test "scripted pending connect waits once and cancellation rolls back both descriptors" {
    // Cancellation belongs to the owner rollback, not the provider's close callback.
    var script: StreamScript = .{ .wait_error = error.Canceled };
    {
        var stream = try Tcp.create(t.io, loopback(80), script.execution());
        defer stream.close();
        try t.expect(!try stream.startConnect(t.io));
        try t.expect(!try stream.startConnect(t.io));
        try t.expectError(error.Canceled, stream.connect(t.io, 25));
        try t.expectEqual(@as(usize, 1), script.starts);
        try t.expectEqual(@as(usize, 1), script.waits);
        try t.expectEqual(@as(?i32, 25), script.last_timeout_ms);
    }
    try t.expectEqualSlices(usize, &.{ 1, 1 }, &script.closes);
}

test "scripted finish polls zero and retains terminal connection failure" {
    var script: StreamScript = .{ .wait_error = error.WouldBlock };
    var stream = try Tcp.create(t.io, loopback(80), script.execution());
    defer stream.close();
    try t.expect(!try stream.startConnect(t.io));
    try t.expect(!try stream.finishConnect(t.io));
    try t.expectEqual(@as(?i32, 0), script.last_timeout_ms);
    script.wait_error = null;
    script.connection_error = error.ConnectionRefused;
    try t.expectError(error.ConnectionRefused, stream.finishConnect(t.io));
    script.connection_error = null;
    try t.expectError(error.ConnectionRefused, stream.finishConnect(t.io));
    try t.expectError(error.ConnectionRefused, stream.startConnect(t.io));
    try t.expectEqual(@as(usize, 1), script.starts);
}

test "scripted stop outranks readiness and provider failure" {
    var script: StreamScript = .{ .wait_error = error.NetworkDown };
    var stream = try Tcp.create(t.io, loopback(80), script.execution());
    defer stream.close();
    script.stop_during_wait = &stream;
    var buffer: [4]u8 = undefined;
    try t.expectError(error.Canceled, stream.read(t.io, &buffer, 0));
    try t.expectEqual(@as(usize, 1), script.wakes);
    try t.expectEqual(@as(usize, 0), script.read_calls);
}

test "scripted short bytes survive later failures and EOF is zero" {
    var script: StreamScript = .{};
    {
        var stream = try Tcp.create(t.io, loopback(80), script.execution());
        defer stream.close();
        var buffer: [4]u8 = undefined;
        const read_count = try stream.read(t.io, &buffer, 0);
        try t.expectEqual(@as(usize, 2), read_count);
        try t.expectEqualStrings("ab", buffer[0..read_count]);
        try t.expectError(error.ConnectionReset, stream.read(t.io, buffer[read_count..], 0));
        try t.expectEqual(@as(usize, 0), try stream.read(t.io, &buffer, 0));
        const written = try stream.write(t.io, "abcd", 0);
        try t.expectEqual(@as(usize, 2), written);
        try t.expectError(error.PeerClosed, stream.write(t.io, "abcd"[written..], 0));
    }
    try t.expectEqualSlices(usize, &.{ 1, 1 }, &script.closes);
}
