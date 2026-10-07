//! TCP listener ownership over borrowed execution callbacks, without a retained Io.
const std = @import("std");
const addr = @import("../base/addr.zig");
const tcp = @import("tcp.zig");
const execution_module = @import("tcp_execution.zig");
const errors = @import("tcp_error.zig");
const Execution = execution_module.Execution;
const t = std.testing;

/// Owns one listening descriptor; copies share ownership and must not be closed separately.
/// Serialize accept and close. The borrowed execution provider outlives this listener
/// and every accepted Tcp, including their cleanup and stop callers.
pub const Listener = struct {
    /// Owned listening descriptor, released exactly once by `close`.
    handle: std.c.fd_t,
    /// Actual bound address, including the selected ephemeral port.
    local: addr.SocketAddr,
    /// Borrowed callbacks and context used for acquisition and cleanup.
    execution: Execution,

    /// Bind and listen, returning the actual local address. Does not retain `io`.
    /// Checks cancellation before acquisition; any error releases acquired resources.
    /// On success the caller must close the listener exactly once.
    pub fn init(io: std.Io, bind: addr.SocketAddr, execution: Execution) errors.ListenError!Listener {
        try io.checkCancel();
        const handle = try execution.vtable.createStream(io, execution.context, bind.ip);
        errdefer execution.vtable.close(execution.context, handle);
        try execution.vtable.bind(io, execution.context, handle, bind);
        try execution.vtable.listen(io, execution.context, handle);
        const local = try execution.vtable.boundAddress(io, execution.context, handle);
        return .{ .handle = handle, .local = local, .execution = execution };
    }

    /// Accept one stream, or return `null` when none is queued; does not retain `io`.
    /// Checks cancellation before accept and wake acquisition. Errors release any
    /// accepted descriptor, leaving the listener owned and usable. An unsupported
    /// accepted peer returns `error.AddressFamilyUnsupported`. Success transfers
    /// the stream and wake to the returned Tcp, which the caller must close once.
    pub fn accept(self: *const Listener, io: std.Io) errors.AcceptError!?tcp.Tcp {
        try io.checkCancel();
        const execution = self.execution;
        const accepted = (try execution.vtable.accept(
            io,
            execution.context,
            self.handle,
        )) orelse return null;
        errdefer execution.vtable.close(execution.context, accepted.handle);
        const peer = accepted.peer orelse return error.AddressFamilyUnsupported;
        const local = try execution.vtable.boundAddress(io, execution.context, accepted.handle);
        try io.checkCancel();
        const wake = try execution.vtable.createWake(io, execution.context);
        errdefer execution.vtable.close(execution.context, wake);
        return .{
            .handle = accepted.handle,
            .wake = wake,
            .execution = execution,
            .stopped = .init(false),
            .peer = peer,
            .local = local,
            .connect_state = .connected,
        };
    }

    /// Release the listening descriptor without checking cancellation.
    /// Invalidates this owner; accepted streams remain independently owned.
    /// Call only once, after accept calls finish.
    pub fn close(self: *Listener) void {
        self.execution.vtable.close(self.execution.context, self.handle);
    }
};

const Script = struct {
    calls: usize = 0,
    fail_at: ?usize = null,
    empty: bool = false,
    unsupported: bool = false,
    closes: [3]usize = .{ 0, 0, 0 },
    wakes: usize = 0,

    fn execution(self: *Script) Execution {
        return .{ .context = self, .vtable = &vtable };
    }

    fn state(context: ?*anyopaque) *Script {
        return @ptrCast(@alignCast(context.?));
    }

    fn step(self: *Script) error{ResourcesExhausted}!void {
        const index = self.calls;
        self.calls += 1;
        if (self.fail_at == index) return error.ResourcesExhausted;
    }

    const vtable: Execution.VTable = .{
        .createStream = createStream,
        .createWake = createWake,
        .bind = bind,
        .listen = listen,
        .boundAddress = boundAddress,
        .accept = accept,
        .startConnect = startConnect,
        .wait = wait,
        .connectionError = connectionError,
        .read = read,
        .write = write,
        .wake = wake,
        .close = close,
    };

    fn createStream(_: std.Io, context: ?*anyopaque, ip: addr.IpAddress) errors.OpenError!std.c.fd_t {
        std.debug.assert(std.meta.eql(ip, loopback(0).ip));
        try state(context).step();
        return 10;
    }

    fn createWake(_: std.Io, context: ?*anyopaque) errors.OpenError!std.c.fd_t {
        try state(context).step();
        return 12;
    }

    fn bind(_: std.Io, context: ?*anyopaque, handle: std.c.fd_t, address: addr.SocketAddr) errors.OpenError!void {
        std.debug.assert(handle == 10);
        std.debug.assert(std.meta.eql(address, loopback(0)));
        try state(context).step();
    }

    fn listen(_: std.Io, context: ?*anyopaque, handle: std.c.fd_t) errors.ListenError!void {
        std.debug.assert(handle == 10);
        try state(context).step();
    }

    fn boundAddress(_: std.Io, context: ?*anyopaque, handle: std.c.fd_t) errors.OpenError!addr.SocketAddr {
        std.debug.assert(handle == 10 or handle == 11);
        try state(context).step();
        return loopback(4000);
    }

    fn accept(_: std.Io, context: ?*anyopaque, handle: std.c.fd_t) errors.AcceptError!?execution_module.Accepted {
        std.debug.assert(handle == 10);
        const self = state(context);
        try self.step();
        if (self.empty) return null;
        return .{ .handle = 11, .peer = if (self.unsupported) null else loopback(5000) };
    }

    fn startConnect(_: std.Io, _: ?*anyopaque, _: std.c.fd_t, _: addr.SocketAddr) errors.ConnectError!bool {
        return error.Unexpected;
    }

    fn wait(_: std.Io, _: ?*anyopaque, _: execution_module.WaitOptions) errors.WaitError!void {
        return error.Unexpected;
    }

    fn connectionError(_: std.Io, _: ?*anyopaque, _: std.c.fd_t) errors.ConnectError!void {
        return error.Unexpected;
    }

    fn read(_: std.Io, _: ?*anyopaque, _: std.c.fd_t, _: []u8) errors.ReadError!usize {
        return error.Unexpected;
    }

    fn write(_: std.Io, _: ?*anyopaque, _: std.c.fd_t, _: []const u8) errors.WriteError!usize {
        return error.Unexpected;
    }

    fn wake(context: ?*anyopaque, handle: std.c.fd_t) void {
        std.debug.assert(handle == 12);
        state(context).wakes += 1;
    }

    fn close(context: ?*anyopaque, handle: std.c.fd_t) void {
        std.debug.assert(handle >= 10 and handle <= 12);
        state(context).closes[@intCast(handle - 10)] += 1;
    }
};

fn loopback(port: u16) addr.SocketAddr {
    return .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = port };
}

test "listener fail-N closes stream after bind listen and bound failures" {
    // Each fallible initialization operation is refused in acquisition order.
    for (0..4) |fail_at| {
        var script: Script = .{ .fail_at = fail_at };
        try t.expectError(error.ResourcesExhausted, Listener.init(t.io, loopback(0), script.execution()));
        try t.expectEqual(fail_at + 1, script.calls);
        try t.expectEqual(@as(usize, if (fail_at == 0) 0 else 1), script.closes[0]);
        try t.expectEqual(@as(usize, 0), script.closes[1]);
        try t.expectEqual(@as(usize, 0), script.closes[2]);
    }
}

test "listener empty accept acquires no accepted resources" {
    var script: Script = .{ .empty = true };
    var listener = try Listener.init(t.io, loopback(0), script.execution());
    defer listener.close();
    try t.expect((try listener.accept(t.io)) == null);
    try t.expectEqual(@as(usize, 5), script.calls);
    try t.expectEqualSlices(usize, &.{ 0, 0, 0 }, &script.closes);
}

test "listener unsupported accepted peer closes the acquired descriptor" {
    var script: Script = .{ .unsupported = true };
    var listener = try Listener.init(t.io, loopback(0), script.execution());
    defer listener.close();
    try t.expectError(error.AddressFamilyUnsupported, listener.accept(t.io));
    try t.expectEqual(@as(usize, 5), script.calls);
    try t.expectEqualSlices(usize, &.{ 0, 1, 0 }, &script.closes);
}

test "listener accepted fail-N rolls back bound and wake failures" {
    // A refusal before accept acquires nothing; later refusals close the accepted stream.
    for (0..3) |fail_at| {
        var script: Script = .{};
        var listener = try Listener.init(t.io, loopback(0), script.execution());
        script.calls = 0;
        script.fail_at = fail_at;
        try t.expectError(error.ResourcesExhausted, listener.accept(t.io));
        try t.expectEqual(fail_at + 1, script.calls);
        try t.expectEqual(@as(usize, 0), script.closes[0]);
        try t.expectEqual(@as(usize, if (fail_at == 0) 0 else 1), script.closes[1]);
        try t.expectEqual(@as(usize, 0), script.closes[2]);
        listener.close();
        try t.expectEqual(@as(usize, 1), script.closes[0]);
    }
}

test "listener success transfers accepted stream and wake ownership" {
    var script: Script = .{};
    var listener = try Listener.init(t.io, loopback(0), script.execution());
    var stream = (try listener.accept(t.io)).?;
    try t.expectEqual(loopback(4000), listener.local);
    try t.expectEqual(loopback(4000), stream.local);
    try t.expectEqual(loopback(5000), stream.peer);
    try t.expect(stream.connect_state == .connected);
    try t.expect(!stream.stopped.load(.acquire));
    try t.expectEqual(@as(usize, 7), script.calls);
    stream.stop();
    try t.expectEqual(@as(usize, 1), script.wakes);
    stream.close();
    try t.expectEqualSlices(usize, &.{ 0, 1, 1 }, &script.closes);
    listener.close();
    try t.expectEqualSlices(usize, &.{ 1, 1, 1 }, &script.closes);
}

fn canceledCheck(_: ?*anyopaque) std.Io.Cancelable!void {
    return error.Canceled;
}

test "listener cancellation precedes stream acquisition and accept callbacks" {
    var vtable = t.io.vtable.*;
    vtable.checkCancel = canceledCheck;
    const canceled: std.Io = .{ .userdata = null, .vtable = &vtable };
    var script: Script = .{};
    try t.expectError(error.Canceled, Listener.init(canceled, loopback(0), script.execution()));
    try t.expectEqual(@as(usize, 0), script.calls);
    try t.expectEqualSlices(usize, &.{ 0, 0, 0 }, &script.closes);
    var listener = try Listener.init(t.io, loopback(0), script.execution());
    try t.expectError(error.Canceled, listener.accept(canceled));
    try t.expectEqual(@as(usize, 4), script.calls);
    listener.close();
    try t.expectEqualSlices(usize, &.{ 1, 0, 0 }, &script.closes);
}

test "listener cancellation before accepted wake acquisition rolls back the stream" {
    // The second cancellation point fires after accept and boundAddress have succeeded.
    const Cancellation = struct {
        checks: usize = 0,

        fn check(context: ?*anyopaque) std.Io.Cancelable!void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.checks += 1;
            if (self.checks == 2) return error.Canceled;
        }
    };
    var cancellation: Cancellation = .{};
    var vtable = t.io.vtable.*;
    vtable.checkCancel = Cancellation.check;
    const io: std.Io = .{ .userdata = &cancellation, .vtable = &vtable };
    var script: Script = .{};
    var listener = try Listener.init(t.io, loopback(0), script.execution());
    try t.expectError(error.Canceled, listener.accept(io));
    try t.expectEqual(@as(usize, 2), cancellation.checks);
    try t.expectEqual(@as(usize, 6), script.calls);
    try t.expectEqualSlices(usize, &.{ 0, 1, 0 }, &script.closes);
    listener.close();
    try t.expectEqualSlices(usize, &.{ 1, 1, 0 }, &script.closes);
}
