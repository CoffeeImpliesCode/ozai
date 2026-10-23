const std = @import("std");
const exit_probe = @import("child_exit_probe.zig");

// Exercise concrete constructors through their public API without spawning or signalling a PID.
pub fn captureFailureRetention(comptime Process: type) !void {
    inline for (.{ Failure.open, Failure.read }) |failure| {
        var fixture: Fixture = .{ .failure = failure, .base_io = std.testing.io };
        var vtable = fixtureVTable();
        const io: std.Io = .{ .userdata = &fixture, .vtable = &vtable };
        const result = try Process.start(std.testing.allocator, io, .{
            .name = "synthetic-constructor",
            .argv = &.{"synthetic-child"},
            .final_argv = &.{"synthetic-child"},
            .run_ms = 10,
            .probe = .{ .context = &fixture, .inspect = Fixture.inspect },
        });
        const process = resultOwner(Process, result);
        defer releaseOwner(Process, process, io, &fixture);
        // Null synthetic pipes represent EOF; failed-start cleanup must not poll raw handles.
        process.out_done = true;
        process.err_done = true;
        try expectCaptureFailure(Process, result, io, &fixture);

        try std.testing.expectError(error.ChildCleanupDeadlineExceeded, process.finish(io));
        try std.testing.expectEqual(@as(?std.process.Child.Id, 42), process.child.id);
        try std.testing.expect(!process.reaped);
        try std.testing.expect(!process.guard.term_sent);
        try std.testing.expectEqual(@as(u32, 0), fixture.wait_calls);
        try std.testing.expect(fixture.probe_calls > 0);
        try std.testing.expect(fixture.probe_calls <= 32);
        try std.testing.expect(fixture.sleep_calls <= 32);
        try std.testing.expectEqual(process, resultOwner(Process, result));

        fixture.exited = true;
        try process.finish(io);
        try std.testing.expect(process.reaped);
        try std.testing.expectEqual(@as(?std.process.Child.Id, null), process.child.id);
        try std.testing.expectEqual(@as(u32, 1), fixture.wait_calls);
        try std.testing.expectEqual(@as(?std.process.Child.Id, 42), fixture.waited_id);
        try std.testing.expect(!process.guard.term_sent);
    }
}

pub fn captureFailureWaitError(comptime Process: type) !void {
    inline for (.{ Failure.open, Failure.read }) |failure| {
        var fixture: Fixture = .{ .failure = failure, .base_io = std.testing.io };
        var vtable = fixtureVTable();
        const io: std.Io = .{ .userdata = &fixture, .vtable = &vtable };
        const result = try Process.start(std.testing.allocator, io, .{
            .name = "synthetic-wait-error",
            .argv = &.{"synthetic-child"},
            .final_argv = &.{"synthetic-child"},
            .run_ms = 10,
            .probe = .{ .context = &fixture, .inspect = Fixture.inspect },
        });
        const process = resultOwner(Process, result);
        defer releaseOwner(Process, process, io, &fixture);
        process.out_done = true;
        process.err_done = true;
        try expectCaptureFailure(Process, result, io, &fixture);

        fixture.exited = true;
        fixture.wait_error = true;
        try std.testing.expectError(error.AccessDenied, process.finish(io));
        try std.testing.expectEqual(@as(?std.process.Child.Id, 42), process.child.id);
        try std.testing.expect(!process.reaped);
        try std.testing.expect(!process.guard.term_sent);
        try std.testing.expectEqual(@as(u32, 1), fixture.wait_calls);
        try std.testing.expectEqual(@as(?std.process.Child.Id, 42), fixture.waited_id);
        try std.testing.expectEqual(process, resultOwner(Process, result));

        fixture.wait_error = false;
        try process.finish(io);
        try std.testing.expect(process.reaped);
        try std.testing.expectEqual(@as(?std.process.Child.Id, null), process.child.id);
        try std.testing.expectEqual(@as(u32, 2), fixture.wait_calls);
        try std.testing.expectEqual(@as(?std.process.Child.Id, 42), fixture.waited_id);
        try std.testing.expect(!process.guard.term_sent);
    }
}

pub fn preparationFailureOwnership(comptime Process: type) !void {
    var fixture: Fixture = .{ .failure = .open, .base_io = std.testing.io };
    var vtable = fixtureVTable();
    const io: std.Io = .{ .userdata = &fixture, .vtable = &vtable };
    const result = try Process.start(std.testing.allocator, io, .{
        .name = "synthetic-invalid-command",
        .argv = &.{"bad\x00argv"},
        .final_argv = &.{"bad\x00argv"},
        .run_ms = 10,
        .probe = .{ .context = &fixture, .inspect = Fixture.inspect },
    });
    const process = resultOwner(Process, result);
    defer releaseOwner(Process, process, io, &fixture);
    switch (result) {
        .failed => |failed| try std.testing.expectEqual(error.InvalidCommand, failed.cause),
        .ready => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(?std.process.Child.Id, null), process.child.id);
    try std.testing.expect(process.reaped);
    try std.testing.expect(process.failed_start);
    try std.testing.expectEqual(@as(u32, 0), fixture.spawn_calls);
    try std.testing.expectEqual(@as(u32, 0), fixture.wait_calls);
    try std.testing.expectEqual(@as(u32, 0), fixture.open_calls);
    try std.testing.expectEqual(@as(u32, 0), fixture.probe_calls);
    try std.testing.expectError(
        error.OwnershipMismatch,
        process.guard.signal(io, &process.child, .TERM),
    );
    try std.testing.expect(!process.guard.term_sent);
}

fn resultOwner(comptime Process: type, result: Process.StartResult) *Process {
    return switch (result) {
        .ready => |process| process,
        .failed => |failed| failed.process,
    };
}

fn expectCaptureFailure(
    comptime Process: type,
    result: Process.StartResult,
    io: std.Io,
    fixture: *const Fixture,
) !void {
    switch (result) {
        .failed => |failed| try std.testing.expectEqual(error.ProcUnavailable, failed.cause),
        .ready => return error.TestUnexpectedResult,
    }
    const process = resultOwner(Process, result);
    try std.testing.expectEqual(@as(?std.process.Child.Id, 42), process.child.id);
    try std.testing.expectError(
        error.OwnershipMismatch,
        process.guard.signal(io, &process.child, .TERM),
    );
    try std.testing.expect(process.failed_start);
    try std.testing.expect(!process.reaped);
    try std.testing.expect(!process.guard.term_sent);
    try std.testing.expectEqual(@as(u32, 1), fixture.spawn_calls);
    try std.testing.expectEqual(@as(u32, 0), fixture.wait_calls);
    try std.testing.expect(fixture.open_calls > 0);
    switch (fixture.failure) {
        .open => {
            try std.testing.expectEqual(@as(u32, 0), fixture.read_calls);
            try std.testing.expectEqual(@as(u32, 0), fixture.close_calls);
        },
        .read => {
            try std.testing.expect(fixture.read_calls > 0);
            try std.testing.expectEqual(fixture.open_calls, fixture.close_calls);
        },
    }
}

fn releaseOwner(comptime Process: type, process: *Process, io: std.Io, fixture: *Fixture) void {
    // Assertion failures still release allocations, but only after the synthetic child is reaped.
    fixture.exited = true;
    fixture.wait_error = false;
    process.out_done = true;
    process.err_done = true;
    if (!process.reaped and process.child.id != null) {
        process.finish(io) catch @panic("synthetic child recovery failed");
    }
    std.debug.assert(process.reaped or process.child.id == null);
    process.deinit(io);
}

const Failure = enum { open, read };

const Fixture = struct {
    failure: Failure,
    base_io: std.Io,
    exited: bool = false,
    wait_error: bool = false,
    spawn_calls: u32 = 0,
    wait_calls: u32 = 0,
    open_calls: u32 = 0,
    read_calls: u32 = 0,
    close_calls: u32 = 0,
    probe_calls: u32 = 0,
    sleep_calls: u32 = 0,
    now_calls: u32 = 0,
    waited_id: ?std.process.Child.Id = null,

    fn fromIo(context: ?*anyopaque) *Fixture {
        return @ptrCast(@alignCast(context orelse @panic("missing constructor fixture")));
    }

    fn checkCancel(context: ?*anyopaque) std.Io.Cancelable!void {
        const self = fromIo(context);
        return self.base_io.vtable.checkCancel(self.base_io.userdata);
    }

    fn swapCancelProtection(
        context: ?*anyopaque,
        protection: std.Io.CancelProtection,
    ) std.Io.CancelProtection {
        const self = fromIo(context);
        return self.base_io.vtable.swapCancelProtection(self.base_io.userdata, protection);
    }

    fn spawn(
        context: ?*anyopaque,
        _: std.process.SpawnOptions,
    ) std.process.SpawnError!std.process.Child {
        const self = fromIo(context);
        self.spawn_calls += 1;
        return .{
            .id = 42,
            .thread_handle = {},
            .stdin = null,
            .stdout = null,
            .stderr = null,
            .resource_usage_statistics = .{},
            .request_resource_usage_statistics = false,
        };
    }

    fn openFile(
        context: ?*anyopaque,
        _: std.Io.Dir,
        _: []const u8,
        _: std.Io.Dir.OpenFileOptions,
    ) std.Io.File.OpenError!std.Io.File {
        const self = fromIo(context);
        self.open_calls += 1;
        if (self.failure == .open) return error.AccessDenied;
        return .{ .handle = -1, .flags = .{ .nonblocking = false } };
    }

    fn readPositional(
        context: ?*anyopaque,
        file: std.Io.File,
        _: []const []u8,
        _: u64,
    ) std.Io.File.ReadPositionalError!usize {
        const self = fromIo(context);
        std.debug.assert(file.handle == -1);
        self.read_calls += 1;
        return error.InputOutput;
    }

    fn operate(
        context: ?*anyopaque,
        operation: std.Io.Operation,
    ) std.Io.Cancelable!std.Io.Operation.Result {
        const self = fromIo(context);
        return switch (operation) {
            .file_read_streaming => |read| result: {
                std.debug.assert(read.file.handle == -1);
                self.read_calls += 1;
                break :result .{ .file_read_streaming = error.InputOutput };
            },
            else => @panic("unexpected operation in synthetic constructor"),
        };
    }

    fn closeFiles(context: ?*anyopaque, files: []const std.Io.File) void {
        const self = fromIo(context);
        for (files) |file| {
            std.debug.assert(file.handle == -1);
            self.close_calls += 1;
        }
    }

    fn now(context: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
        const self = fromIo(context);
        self.now_calls += 1;
        std.debug.assert(self.now_calls <= 64);
        return .{ .nanoseconds = @as(i96, self.now_calls) * 600 * std.time.ns_per_ms };
    }

    fn sleep(context: ?*anyopaque, _: std.Io.Timeout) std.Io.Cancelable!void {
        const self = fromIo(context);
        self.sleep_calls += 1;
        std.debug.assert(self.sleep_calls <= 32);
    }

    fn wait(
        context: ?*anyopaque,
        child: *std.process.Child,
    ) std.process.Child.WaitError!std.process.Child.Term {
        const self = fromIo(context);
        std.debug.assert(self.exited);
        std.debug.assert(child.id == 42);
        self.wait_calls += 1;
        self.waited_id = child.id;
        if (self.wait_error) return error.AccessDenied;
        child.id = null;
        return .{ .exited = 0 };
    }

    fn inspect(context: ?*anyopaque, id: std.process.Child.Id) exit_probe.Error!bool {
        const self: *Fixture = @ptrCast(@alignCast(context orelse return error.ChildStateUnavailable));
        if (id != 42) return error.OwnershipMismatch;
        self.probe_calls += 1;
        std.debug.assert(self.probe_calls <= 32);
        return self.exited;
    }
};

fn fixtureVTable() std.Io.VTable {
    var vtable = std.testing.io.vtable.*;
    vtable.checkCancel = Fixture.checkCancel;
    vtable.swapCancelProtection = Fixture.swapCancelProtection;
    vtable.processSpawn = Fixture.spawn;
    vtable.dirOpenFile = Fixture.openFile;
    vtable.fileReadPositional = Fixture.readPositional;
    vtable.operate = Fixture.operate;
    vtable.fileClose = Fixture.closeFiles;
    vtable.now = Fixture.now;
    vtable.sleep = Fixture.sleep;
    vtable.childWait = Fixture.wait;
    return vtable;
}
