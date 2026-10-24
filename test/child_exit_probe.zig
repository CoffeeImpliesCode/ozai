const std = @import("std");
const linux = std.os.linux;

/// Inspection failures never authorize signalling or reaping a child.
pub const Error = error{
    ChildStateUnavailable,
    OwnershipMismatch,
};

/// Borrows a retained child ID and, when supplied, the hook's context.
/// The context must remain valid for each call. Hooks must observe only, never reap or signal.
pub const Probe = struct {
    context: ?*anyopaque = null,
    inspect: *const fn (?*anyopaque, std.process.Child.Id) Error!bool = nativeInspect,

    /// Reports a terminal kernel state without changing the child or consuming its exit status.
    /// A missing retained ID is an ownership failure, not evidence that the child exited.
    pub fn exited(self: Probe, child: *const std.process.Child) Error!bool {
        const id = child.id orelse return error.OwnershipMismatch;
        return self.inspect(self.context, id);
    }
};

fn nativeInspect(_: ?*anyopaque, pid: std.process.Child.Id) Error!bool {
    if (pid <= 1) return error.OwnershipMismatch;

    // NOWAIT retains the exit status for the owner's eventual wait. A finite EINTR budget
    // prevents a signal storm from turning a nonblocking observation into an unbounded loop.
    for (0..4) |_| {
        var info = std.mem.zeroes(linux.siginfo_t);
        switch (linux.errno(linux.waitid(
            .PID,
            pid,
            &info,
            linux.W.EXITED | linux.W.NOHANG | linux.W.NOWAIT,
            null,
        ))) {
            .SUCCESS => return classifyObservation(pid, &info),
            .INTR => continue,
            .CHILD => return error.OwnershipMismatch,
            else => return error.ChildStateUnavailable,
        }
    }
    return error.ChildStateUnavailable;
}

fn classifyObservation(pid: std.process.Child.Id, info: *const linux.siginfo_t) Error!bool {
    const observed_pid = info.fields.common.first.piduid.pid;
    if (observed_pid == 0) return false;
    if (observed_pid != pid) return error.OwnershipMismatch;
    return switch (info.code) {
        @backingInt(linux.CLD.EXITED),
        @backingInt(linux.CLD.KILLED),
        @backingInt(linux.CLD.DUMPED),
        => true,
        else => error.ChildStateUnavailable,
    };
}

// Synthetic children and borrowed hooks keep these tests independent of process scheduling.
const FakeInspect = struct {
    result: Error!bool,
    calls: u8 = 0,
    observed_id: ?std.process.Child.Id = null,

    fn inspect(context: ?*anyopaque, id: std.process.Child.Id) Error!bool {
        const self: *FakeInspect = @ptrCast(@alignCast(
            context orelse return error.ChildStateUnavailable,
        ));
        self.calls += 1;
        self.observed_id = id;
        return self.result;
    }
};

fn syntheticChild(id: ?std.process.Child.Id) std.process.Child {
    return .{
        .id = id,
        .thread_handle = {},
        .stdin = null,
        .stdout = null,
        .stderr = null,
        .resource_usage_statistics = .{},
        .request_resource_usage_statistics = false,
    };
}

test "probe refuses absent ownership before invoking its borrowed hook" {
    var fake: FakeInspect = .{ .result = true };
    const probe: Probe = .{ .context = &fake, .inspect = FakeInspect.inspect };
    const child = syntheticChild(null);
    try std.testing.expectError(error.OwnershipMismatch, probe.exited(&child));
    try std.testing.expectEqual(@as(u8, 0), fake.calls);
    try std.testing.expectEqual(@as(?std.process.Child.Id, null), fake.observed_id);
}

test "probe preserves live and exited children without consuming their retained IDs" {
    inline for (.{ false, true }) |exited| {
        var fake: FakeInspect = .{ .result = exited };
        const probe: Probe = .{ .context = &fake, .inspect = FakeInspect.inspect };
        const child = syntheticChild(42);
        const before = child;
        try std.testing.expectEqual(exited, try probe.exited(&child));
        try std.testing.expectEqual(exited, try probe.exited(&child));
        try std.testing.expectEqual(@as(u8, 2), fake.calls);
        try std.testing.expectEqual(child.id, fake.observed_id);
        try std.testing.expectEqualDeep(before, child);
    }
}

test "probe propagates both finite inspection failures without changing ownership" {
    inline for (.{ error.ChildStateUnavailable, error.OwnershipMismatch }) |failure| {
        var fake: FakeInspect = .{ .result = failure };
        const probe: Probe = .{ .context = &fake, .inspect = FakeInspect.inspect };
        const child = syntheticChild(42);
        try std.testing.expectError(failure, probe.exited(&child));
        try std.testing.expectEqual(@as(u8, 1), fake.calls);
        try std.testing.expectEqual(child.id, fake.observed_id);
        try std.testing.expectEqual(@as(?std.process.Child.Id, 42), child.id);
    }
}

test "borrowed inspection may reject missing context without a syscall" {
    const probe: Probe = .{ .inspect = FakeInspect.inspect };
    const child = syntheticChild(42);
    try std.testing.expectError(error.ChildStateUnavailable, probe.exited(&child));
}

test "kernel observation requires an exact child ID and a terminal CLD code" {
    var info = std.mem.zeroes(linux.siginfo_t);
    try std.testing.expect(!try classifyObservation(42, &info));

    info.fields.common.first.piduid.pid = 43;
    info.code = @backingInt(linux.CLD.EXITED);
    try std.testing.expectError(error.OwnershipMismatch, classifyObservation(42, &info));

    info.fields.common.first.piduid.pid = 42;
    inline for (.{ linux.CLD.EXITED, linux.CLD.KILLED, linux.CLD.DUMPED }) |code| {
        info.code = @backingInt(code);
        try std.testing.expect(try classifyObservation(42, &info));
    }
    inline for (.{ linux.CLD.TRAPPED, linux.CLD.STOPPED, linux.CLD.CONTINUED }) |code| {
        info.code = @backingInt(code);
        try std.testing.expectError(error.ChildStateUnavailable, classifyObservation(42, &info));
    }
    info.code = 0;
    try std.testing.expectError(error.ChildStateUnavailable, classifyObservation(42, &info));
}
