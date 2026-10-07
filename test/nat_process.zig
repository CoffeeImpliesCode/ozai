//! Bounded, caller-owned NAT fixture children. Never signal a PID discovered by scanning.
const std = @import("std");
const safety = @import("nat_proc_safety.zig");
const procRead = safety.procRead;
const statusField = safety.statusField;
const checkStatus = safety.checkStatus;
const excludeAncestors = safety.excludeAncestors;
const verifyProcOwner = safety.verifyProcOwner;
const encodeCommand = safety.encodeCommand;

pub const Namespace = safety.Namespace;
pub const Baseline = safety.Baseline;
pub const validateBaseline = safety.validateBaseline;
pub const verifyUidMapping = safety.verifyUidMapping;
pub const namespaceIdentity = safety.namespaceIdentity;
pub const assertPrivate = safety.assertPrivate;
pub const setPrivateForwarding = safety.setPrivateForwarding;
pub const assertOwnedDir = safety.assertOwnedDir;


test "bounded log overflow preserves captured prefix" {
    var storage: [4]u8 = undefined;
    var log = Log{ .buffer = &storage };
    try log.append("ab");
    try log.append("cd");
    try std.testing.expectError(error.LogOverflow, log.append("e"));
    try std.testing.expectEqualSlices(u8, "abcd", log.bytes());
}


const c = std.c;
pub const log_capacity = 64 * 1024;
pub const Error = safety.Error || error{
    InvalidCommand, CommandOverflow, LogOverflow, PipeFailed, SignalFailed,
    DeadlineExceeded, AlreadyStarted, NotStarted, InputOverflow, ChildFailed,
} || std.process.SpawnError || std.process.Child.WaitError;

pub const Log = struct {
    buffer: []u8,
    len: usize = 0,
    overflow: bool = false,

    pub fn bytes(self: *const Log) []const u8 {
        return self.buffer[0..self.len];
    }

    pub fn append(self: *Log, bytes_in: []const u8) Error!void {
        const available = self.buffer.len - self.len;
        const count = @min(available, bytes_in.len);
        @memcpy(self.buffer[self.len..][0..count], bytes_in[0..count]);
        self.len += count;
        if (count != bytes_in.len) self.overflow = true;
        if (self.overflow) return error.LogOverflow;
    }
};

pub const Process = struct {
    child: ?std.process.Child = null,
    /// Remains available after reaping for evidence, never used to signal once reaped.
    pid: ?std.process.Child.Id = null,
    out: Log,
    err: Log,
    command: [8192]u8 = undefined,
    command_len: usize = 0,
    wrapper_command: [8192]u8 = undefined,
    wrapper_command_len: usize = 0,
    term: ?std.process.Child.Term = null,
    caller_uid: u32 = 0,
    parent_pid: c.pid_t = 0,

    pub fn init(self: *Process, stdout_buffer: []u8, stderr_buffer: []u8) void {
        std.debug.assert(stdout_buffer.len <= log_capacity);
        std.debug.assert(stderr_buffer.len <= log_capacity);
        self.* = .{ .out = .{ .buffer = stdout_buffer }, .err = .{ .buffer = stderr_buffer } };
    }

    pub fn stdout(self: *const Process) []const u8 {
        return self.out.bytes();
    }

    pub fn stderr(self: *const Process) []const u8 {
        return self.err.bytes();
    }

    pub fn assertSuccess(self: *const Process) Error!void {
        const term = self.term orelse return error.NotStarted;
        switch (term) {
            .exited => |code| if (code != 0) return error.ChildFailed,
            else => return error.ChildFailed,
        }
        if (self.out.overflow or self.err.overflow) return error.LogOverflow;
    }

    pub fn spawn(self: *Process, io: std.Io, argv: []const []const u8) Error!void {
        return self.spawnAs(io, argv, argv);
    }

    /// Wrappers may exec a keeper; only its explicitly supplied final argv is signalable.
    /// On an error after spawn, the handle remains owned: the caller must call finish.
    pub fn spawnAs(
        self: *Process,
        io: std.Io,
        argv: []const []const u8,
        expected_final_argv: []const []const u8,
    ) Error!void {
        if (self.child != null) return error.AlreadyStarted;
        self.command_len = (try encodeCommand(&self.command, expected_final_argv)).len;
        self.wrapper_command_len = (try encodeCommand(&self.wrapper_command, argv)).len;
        self.caller_uid = c.getuid();
        self.parent_pid = c.getpid();
        self.child = try std.process.spawn(io, .{
            .argv = argv, .stdin = .pipe, .stdout = .pipe, .stderr = .pipe,
        });
        self.pid = self.child.?.id.?;
        try nonblocking(self.child.?.stdout.?.handle);
        try nonblocking(self.child.?.stderr.?.handle);
        try nonblocking(self.child.?.stdin.?.handle);
    }

    pub fn pump(self: *Process, io: std.Io) Error!void {
        _ = io;
        const child = if (self.child) |*value| value else return error.NotStarted;
        if (self.term != null) return;
        // Both streams are serviced even if one overflowed.
        var failure: ?Error = null;
        drain(child.stdout.?.handle, &self.out) catch |err| { failure = err; };
        drain(child.stderr.?.handle, &self.err) catch |err| { failure = err; };
        if (failure) |err| return err;
    }

    /// Nonblocking proc inspection avoids an external waitpid stealing Io's child.
    pub fn exited(self: *Process, io: std.Io) Error!bool {
        if (self.term != null) return true;
        const child = if (self.child) |*value| value else return error.NotStarted;
        var buffer: [4096]u8 = undefined;
        const status = try procRead(self.pid.?, "status", &buffer);
        const state = statusField(status, "State:") orelse return error.InvalidProc;
        if (state.len == 0) return error.InvalidProc;
        if (state[0] != 'Z' and state[0] != 'X') return false;
        // Drain before Child.wait closes pipe handles.
        var failure: ?Error = null;
        self.pump(io) catch |err| { failure = err; };
        self.term = try child.wait(io);
        if (failure) |err| return err;
        return true;
    }

    pub fn writeInput(self: *Process, io: std.Io, input: []const u8) Error!void {
        if (input.len > log_capacity) return error.InputOverflow;
        const child = if (self.child) |*value| value else return error.NotStarted;
        const pipe = child.stdin orelse return error.PipeFailed;
        defer {
            pipe.close(io);
            child.stdin = null;
        }
        const start = std.Io.Timestamp.now(io, .awake).nanoseconds;
        var offset: usize = 0;
        for (0..401) |_| {
            try self.pump(io);
            const count = c.write(pipe.handle, input[offset..].ptr, input.len - offset);
            if (count > 0) offset += @intCast(count) else if (count < 0) {
                switch (c.errno(count)) {
                    .AGAIN, .INTR => {},
                    else => return error.PipeFailed,
                }
            }
            if (offset == input.len) return;
            if (std.Io.Timestamp.now(io, .awake).nanoseconds - start >= 2 * std.time.ns_per_s)
                return error.DeadlineExceeded;
            std.Io.sleep(io, .fromMilliseconds(5), .awake) catch return error.PipeFailed;
        }
        return error.DeadlineExceeded;
    }

    /// Logs survive cleanup, including overflow failures. Foreign or changed commands
    /// fail closed; callers must report this rather than trying a broader kill.
    pub fn finish(self: *Process, io: std.Io) Error!std.process.Child.Term {
        if (self.term) |term| {
            if (self.out.overflow or self.err.overflow) return error.LogOverflow;
            return term;
        }
        var failure: ?Error = null;
        self.pump(io) catch |err| { failure = err; };
        if (try self.exitedIgnoringLogs(io, &failure)) return self.finishResult(failure);
        try self.signalOwned(.TERM);
        const start = std.Io.Timestamp.now(io, .awake).nanoseconds;
        var killed = false;
        for (0..501) |_| {
            self.pump(io) catch |err| { failure = err; };
            if (try self.exitedIgnoringLogs(io, &failure)) return self.finishResult(failure);
            const elapsed = std.Io.Timestamp.now(io, .awake).nanoseconds - start;
            if (!killed and elapsed >= 500 * std.time.ns_per_ms) {
                try self.signalOwned(.KILL);
                killed = true;
            }
            if (elapsed >= 2500 * std.time.ns_per_ms) return error.DeadlineExceeded;
            std.Io.sleep(io, .fromMilliseconds(5), .awake) catch return error.PipeFailed;
        }
        return error.DeadlineExceeded;
    }

    fn exitedIgnoringLogs(self: *Process, io: std.Io, failure: *?Error) Error!bool {
        return self.exited(io) catch |err| switch (err) {
            error.LogOverflow => blk: {
                failure.* = err;
                break :blk self.term != null;
            },
            else => return err,
        };
    }

    fn finishResult(self: *const Process, failure: ?Error) Error!std.process.Child.Term {
        if (failure) |err| return err;
        return self.term.?;
    }

    fn signalOwned(self: *Process, signal: c.SIG) Error!void {
        const child = self.child orelse return error.NotStarted;
        if (child.id == null or child.id.? != self.pid.?) return error.OwnershipMismatch;
        try excludeAncestors(self.pid.?);
        try verifyProcOwner(self.pid.?, self.caller_uid);
        var status_buffer: [4096]u8 = undefined;
        const status = try procRead(self.pid.?, "status", &status_buffer);
        try checkStatus(status, self.caller_uid, self.parent_pid);
        const state = statusField(status, "State:") orelse return error.InvalidProc;
        if (state.len == 0) return error.InvalidProc;
        if (state[0] == 'Z' or state[0] == 'X') return;
        var command_buffer: [8192]u8 = undefined;
        const command = try procRead(self.pid.?, "cmdline", &command_buffer);
        if (command.len == 0) {
            const fresh = try procRead(self.pid.?, "status", &status_buffer);
            const fresh_state = statusField(fresh, "State:") orelse return error.InvalidProc;
            if (fresh_state.len > 0 and (fresh_state[0] == 'Z' or fresh_state[0] == 'X'))
                return;
        }
        const final_matches = std.mem.eql(u8, command, self.command[0..self.command_len]);
        const wrapper_matches = std.mem.eql(u8, command,
            self.wrapper_command[0..self.wrapper_command_len]);
        if (!final_matches and !wrapper_matches) return error.OwnershipMismatch;
        // A direct child cannot have its PID reused while we retain its unreaped handle.
        if (c.kill(self.pid.?, signal) != 0) {
            if (c.errno(@as(c_int, -1)) != .SRCH) return error.SignalFailed;
        }
    }
};


fn nonblocking(fd: c.fd_t) Error!void {
    const flags = c.fcntl(fd, std.posix.F.GETFL);
    if (flags < 0) return error.PipeFailed;
    const nonblock: c_int = @intCast(@as(u32, @bitCast(std.posix.O{ .NONBLOCK = true })));
    if (c.fcntl(fd, std.posix.F.SETFL, flags | nonblock) < 0) return error.PipeFailed;
}

fn drain(fd: c.fd_t, log: *Log) Error!void {
    try nonblocking(fd);
    var buffer: [4096]u8 = undefined;
    for (0..17) |_| {
        const count = c.read(fd, &buffer, buffer.len);
        if (count == 0) break;
        if (count < 0) switch (c.errno(count)) {
            .AGAIN => break,
            .INTR => continue,
            else => return error.PipeFailed,
        } else {
            log.append(buffer[0..@intCast(count)]) catch |err| return err;
        }
    }
    if (log.overflow) return error.LogOverflow;
}


test "success requires a zero natural exit and preserved logs without overflow" {
    var out: [4]u8 = undefined;
    var err: [4]u8 = undefined;
    var process: Process = undefined;
    process.init(&out, &err);
    try std.testing.expectError(error.NotStarted, process.assertSuccess());
    process.term = .{ .exited = 0 };
    try process.assertSuccess();
    process.term = .{ .exited = 1 };
    try std.testing.expectError(error.ChildFailed, process.assertSuccess());
    process.term = .{ .signal = .TERM };
    try std.testing.expectError(error.ChildFailed, process.assertSuccess());
    process.term = .{ .exited = 0 };
    process.out.overflow = true;
    try std.testing.expectError(error.LogOverflow, process.assertSuccess());
}
