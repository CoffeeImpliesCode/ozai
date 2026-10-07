//! Bounded cleanup for retained child owners; identity inspection never belongs to this driver.
const std = @import("std");
const proc = @import("nat_proc_safety.zig");
const child_exit = @import("child_exit_probe.zig");
const SignalError = @import("child_signal_safety.zig").SignalError;
const c = std.c;

const Action = enum { term, wait, kill, reap };

fn cleanupAction(exited: bool, term_sent: bool, grace_elapsed: bool) Action {
    if (exited) return .reap;
    if (!term_sent) return .term;
    return if (grace_elapsed) .kill else .wait;
}

test "child cleanup escalation requires term grace and live child" {
    try std.testing.expectEqual(Action.term, cleanupAction(false, false, false));
    try std.testing.expectEqual(Action.wait, cleanupAction(false, true, false));
    try std.testing.expectEqual(Action.kill, cleanupAction(false, true, true));
    try std.testing.expectEqual(Action.reap, cleanupAction(true, true, true));
}

/// Finite operation errors for a cleanup consumer; no failure widens the API to anyerror.
pub fn CleanupError(comptime Process: type) type {
    const Consumer = @typeInfo(Process).pointer.child;
    return Consumer.PumpError || Consumer.WaitError || SignalError || child_exit.Error ||
        std.Io.Cancelable || error{
            IncompleteTermination,
            ChildCleanupDeadlineExceeded,
            ChildDrainDeadlineExceeded,
        };
}

/// Drain throughout the bounded grace period; only wait once proc confirms exit.
pub fn finish(io: std.Io, process: anytype) CleanupError(@TypeOf(process))!void {
    if (process.reaped) return;
    var failure: ?CleanupError(@TypeOf(process)) = null;
    var killed = false;
    const start = std.Io.Timestamp.now(io, .awake).nanoseconds;
    for (0..501) |_| {
        process.pump(io) catch |err| {
            failure = failure orelse err;
        };
        const exited = process.guard.exited(io, &process.child) catch |err|
            return failure orelse err;
        const elapsed = std.Io.Timestamp.now(io, .awake).nanoseconds - start;
        switch (cleanupAction(
            exited,
            process.guard.term_sent,
            elapsed >= 500 * std.time.ns_per_ms,
        )) {
            .reap => {
                // The final reads precede Child.wait, which closes all stdio handles.
                drainExited(io, process) catch |err| {
                    failure = failure orelse err;
                };
                const term = process.child.wait(io) catch |err| return failure orelse err;
                if (process.child.id != null)
                    return failure orelse error.IncompleteTermination;
                process.reaped = true;
                switch (term) {
                    .exited, .signal => {},
                    else => return failure orelse error.IncompleteTermination,
                }
                if (failure) |err| return err;
                return;
            },
            .term => process.guard.signal(io, &process.child, .TERM) catch |err|
                return failure orelse err,
            .kill => if (!killed) {
                process.guard.signal(io, &process.child, .KILL) catch |err|
                    return failure orelse err;
                killed = true;
            },
            .wait => {},
        }
        if (elapsed >= 2500 * std.time.ns_per_ms)
            return failure orelse error.ChildCleanupDeadlineExceeded;
        std.Io.sleep(io, .fromMilliseconds(5), .awake) catch |err| return failure orelse err;
    }
    return failure orelse error.ChildCleanupDeadlineExceeded;
}

/// A failed identity capture grants no signal authority. Only kernel child exit permits wait.
/// The caller retains the owner on every error, including expiry of its declared watchdog.
pub fn finishFailedStart(io: std.Io, process: anytype) CleanupError(@TypeOf(process))!void {
    if (process.reaped) return;
    std.debug.assert(process.run_ms >= 0);
    const limit_ms = @as(i96, process.run_ms) + 2500;
    const start = std.Io.Timestamp.now(io, .awake).nanoseconds;
    const passes: usize = @intCast(@divFloor(limit_ms, 5) + 1);
    var failure: ?CleanupError(@TypeOf(process)) = null;
    for (0..passes) |_| {
        process.pump(io) catch |err| {
            failure = failure orelse err;
        };
        const exited = process.probe.exited(&process.child) catch |err|
            return failure orelse err;
        if (exited) {
            drainExited(io, process) catch |err| {
                failure = failure orelse err;
            };
            const term = process.child.wait(io) catch |err| return failure orelse err;
            if (process.child.id != null) return failure orelse error.IncompleteTermination;
            process.reaped = true;
            switch (term) {
                .exited, .signal => {},
                else => return failure orelse error.IncompleteTermination,
            }
            if (failure) |err| return err;
            return;
        }
        if (std.Io.Timestamp.now(io, .awake).nanoseconds - start >=
            limit_ms * std.time.ns_per_ms)
            return failure orelse error.ChildCleanupDeadlineExceeded;
        std.Io.sleep(io, .fromMilliseconds(5), .awake) catch |err| return failure orelse err;
    }
    return failure orelse error.ChildCleanupDeadlineExceeded;
}

fn drainExited(io: std.Io, process: anytype) CleanupError(@TypeOf(process))!void {
    // Pipes are closed by the exited writer, so no iteration can block on it.
    for (0..4096) |_| {
        if (process.finished()) return;
        try process.pump(io);
    }
    return error.ChildDrainDeadlineExceeded;
}

pub fn waitForExit(io: std.Io, process: anytype) CleanupError(@TypeOf(process))!std.process.Child.Term {
    const start = std.Io.Timestamp.now(io, .awake).nanoseconds;
    for (0..501) |_| {
        try process.pump(io);
        if (try process.guard.exited(io, &process.child)) {
            try drainExited(io, process);
            const term = try process.child.wait(io);
            if (process.child.id != null) return error.IncompleteTermination;
            process.reaped = true;
            switch (term) {
                .exited, .signal => return term,
                else => return error.IncompleteTermination,
            }
        }
        if (std.Io.Timestamp.now(io, .awake).nanoseconds - start >= 2500 * std.time.ns_per_ms)
            return error.ChildCleanupDeadlineExceeded;
        try std.Io.sleep(io, .fromMilliseconds(5), .awake);
    }
    return error.ChildCleanupDeadlineExceeded;
}

// Exercise the public generic cleanup consumer without ever issuing a kernel signal.
const CleanupConsumer = struct {
    const PumpError = error{ FirstPumpFailure, LaterPumpFailure };
    const WaitError = error{WaitFailure};
    const Child = struct {
        id: ?c.pid_t = 42,
        waits: usize = 0,
        fail_wait: bool = false,
        retain_id: bool = false,

        fn wait(self: *Child, _: std.Io) WaitError!std.process.Child.Term {
            self.waits += 1;
            if (self.fail_wait) return error.WaitFailure;
            if (!self.retain_id) self.id = null;
            return .{ .exited = 0 };
        }
    };
    const TestGuard = struct {
        term_sent: bool = false,
        signals: usize = 0,
        unsafe: bool = false,
        live: bool = false,
        identity_io: ?std.Io = null,

        fn exited(self: *TestGuard, _: std.Io, _: *const Child) proc.Error!bool {
            if (self.unsafe) return error.OwnershipMismatch;
            if (self.identity_io) |io| {
                var buffer: [128]u8 = undefined;
                const identity = try proc.namespaceIdentity(io, c.getpid(), .net, &buffer);
                if (identity.len == 0) return error.InvalidProc;
            }
            return !self.live;
        }

        fn signal(self: *TestGuard, _: std.Io, _: *const Child, sig: c.SIG) proc.Error!void {
            if (self.unsafe) return error.OwnershipMismatch;
            self.signals += 1;
            if (sig == .TERM) self.term_sent = true;
        }
    };

    child: Child = .{},
    guard: TestGuard = .{},
    reaped: bool = false,
    pumps: usize = 0,
    fail_pumps: bool = false,

    fn pump(self: *CleanupConsumer, _: std.Io) PumpError!void {
        self.pumps += 1;
        if (!self.fail_pumps) return;
        if (self.pumps == 1) return error.FirstPumpFailure;
        return error.LaterPumpFailure;
    }

    fn finished(self: *const CleanupConsumer) bool {
        return self.pumps >= 3;
    }
};

test "child cleanup retains first pump failure while reaping the owned child" {
    var consumer: CleanupConsumer = .{ .fail_pumps = true };
    const result = finish(std.testing.io, &consumer);
    try std.testing.expect(consumer.reaped);
    try std.testing.expectEqual(@as(?c.pid_t, null), consumer.child.id);
    try std.testing.expectEqual(@as(usize, 1), consumer.child.waits);
    try std.testing.expectEqual(@as(usize, 0), consumer.guard.signals);
    try std.testing.expectError(error.FirstPumpFailure, result);
}

test "child cleanup ownership failure retains child without signaling or waiting" {
    var consumer: CleanupConsumer = .{ .guard = .{ .unsafe = true } };
    try std.testing.expectError(error.OwnershipMismatch, finish(std.testing.io, &consumer));
    try std.testing.expect(!consumer.reaped);
    try std.testing.expectEqual(@as(?c.pid_t, 42), consumer.child.id);
    try std.testing.expectEqual(@as(usize, 0), consumer.child.waits);
    try std.testing.expectEqual(@as(usize, 0), consumer.guard.signals);
}

test "child cleanup has bounded TERM grace KILL and retained deadline state" {
    const Clock = struct {
        elapsed_ms: i96 = 0,
        sleeps: usize = 0,

        fn now(userdata: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            const timestamp: std.Io.Timestamp = .{
                .nanoseconds = self.elapsed_ms * std.time.ns_per_ms,
            };
            self.elapsed_ms += 600;
            return timestamp;
        }

        fn sleep(userdata: ?*anyopaque, _: std.Io.Timeout) std.Io.Cancelable!void {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            self.sleeps += 1;
        }
    };
    var clock: Clock = .{};
    var vtable = std.testing.io.vtable.*;
    vtable.now = Clock.now;
    vtable.sleep = Clock.sleep;
    const io: std.Io = .{ .userdata = &clock, .vtable = &vtable };
    var consumer: CleanupConsumer = .{ .guard = .{ .live = true } };
    try std.testing.expectError(error.ChildCleanupDeadlineExceeded, finish(io, &consumer));
    try std.testing.expectEqual(@as(usize, 2), consumer.guard.signals);
    try std.testing.expectEqual(@as(usize, 0), consumer.child.waits);
    try std.testing.expectEqual(@as(?c.pid_t, 42), consumer.child.id);
    try std.testing.expect(!consumer.reaped);
    try std.testing.expect(clock.sleeps <= 501);
    try std.testing.expect(consumer.pumps <= 501);
}

test "child cleanup injected proc identity failure retains ownership before any signal" {
    const Tripwire = struct {
        fn readLink(
            userdata: ?*anyopaque,
            _: std.Io.Dir,
            _: []const u8,
            _: []u8,
        ) std.Io.Dir.ReadLinkError!usize {
            const calls: *usize = @ptrCast(@alignCast(userdata.?));
            calls.* += 1;
            return error.AccessDenied;
        }
    };
    var calls: usize = 0;
    var vtable = std.testing.io.vtable.*;
    vtable.dirReadLink = Tripwire.readLink;
    const proc_io: std.Io = .{ .userdata = &calls, .vtable = &vtable };
    var consumer: CleanupConsumer = .{
        .guard = .{ .identity_io = proc_io, .live = true },
    };
    // The separate proc backend never supplies the cleanup clock or performs a signal.
    const result = finish(std.testing.io, &consumer);
    try std.testing.expectEqual(@as(usize, 0), consumer.guard.signals);
    try std.testing.expectEqual(@as(usize, 0), consumer.child.waits);
    try std.testing.expectEqual(@as(?c.pid_t, 42), consumer.child.id);
    try std.testing.expect(!consumer.reaped);
    try std.testing.expectEqual(@as(usize, 1), calls);
    try std.testing.expectError(error.ProcUnavailable, result);
}

test "child cleanup keeps first failure and child handle when wait also fails" {
    var consumer: CleanupConsumer = .{
        .child = .{ .fail_wait = true },
        .fail_pumps = true,
    };
    const result = finish(std.testing.io, &consumer);
    try std.testing.expect(!consumer.reaped);
    try std.testing.expectEqual(@as(?c.pid_t, 42), consumer.child.id);
    try std.testing.expectEqual(@as(usize, 1), consumer.child.waits);
    try std.testing.expectEqual(@as(usize, 0), consumer.guard.signals);
    try std.testing.expectError(error.FirstPumpFailure, result);
}

test "child cleanup incomplete wait retains child and does not claim reaping" {
    var consumer: CleanupConsumer = .{ .child = .{ .retain_id = true } };
    try std.testing.expectError(error.IncompleteTermination, finish(std.testing.io, &consumer));
    try std.testing.expect(!consumer.reaped);
    try std.testing.expectEqual(@as(?c.pid_t, 42), consumer.child.id);
    try std.testing.expectEqual(@as(usize, 1), consumer.child.waits);
    try std.testing.expectEqual(@as(usize, 0), consumer.guard.signals);
}
