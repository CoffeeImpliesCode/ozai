//! Signal policy for the unreaped direct children owned by the mixed-peer tests.
const std = @import("std");
const proc = @import("nat_proc_safety.zig");
const c = std.c;
const child_exit = @import("child_exit_probe.zig");

/// The name outlives the owner; argv outlives construction; probe context outlives cleanup.
pub const StartOptions = struct {
    name: []const u8,
    argv: []const []const u8,
    final_argv: []const []const u8,
    run_ms: i64,
    probe: child_exit.Probe = .{},
};

// These tests exercise the same decision boundary used immediately before each signal.
test "child signal identity rejects owner command ancestor and reused pid" {
    const identity: Identity = .{ .pid = 42, .parent = 7, .uid = 1000, .start_ticks = 99 };
    const status = "PPid:\t7\nUid:\t1000\t1000\t1000\t1000\n";
    try validate(identity, 42, 99, status, "peer\x00a\x00", "peer\x00a\x00", false);
    try std.testing.expectError(
        error.OwnershipMismatch,
        validate(identity, 43, 99, status, "peer\x00a\x00", "peer\x00a\x00", false),
    );
    try std.testing.expectError(
        error.OwnershipMismatch,
        validate(identity, 42, 100, status, "peer\x00a\x00", "peer\x00a\x00", false),
    );
    try std.testing.expectError(
        error.OwnershipMismatch,
        validate(identity, 42, 99, status, "peer\x00b\x00", "peer\x00a\x00", false),
    );
    try std.testing.expectError(
        error.OwnershipMismatch,
        validate(identity, 42, 99, status, "peer\x00a\x00", "peer\x00a\x00", true),
    );
    try std.testing.expectError(
        error.OwnershipMismatch,
        validate(
            identity,
            42,
            99,
            "PPid:\t7\nUid:\t1001\t1001\t1001\t1001\n",
            "peer\x00a\x00",
            "peer\x00a\x00",
            false,
        ),
    );
    try std.testing.expectError(
        error.OwnershipMismatch,
        validate(
            identity,
            42,
            99,
            "PPid:\t8\nUid:\t1000\t1000\t1000\t1000\n",
            "peer\x00a\x00",
            "peer\x00a\x00",
            false,
        ),
    );
    try std.testing.expectError(
        error.OwnershipMismatch,
        validate(identity, 42, 99, status, "peer\x00a", "peer\x00a\x00", false),
    );
}

const Identity = struct {
    pid: c.pid_t,
    parent: c.pid_t,
    uid: u32,
    start_ticks: u64,
};

fn validate(
    identity: Identity,
    pid: c.pid_t,
    start_ticks: u64,
    status: []const u8,
    command: []const u8,
    expected: []const u8,
    ancestor: bool,
) proc.Error!void {
    if (ancestor or pid <= 1 or pid != identity.pid or start_ticks != identity.start_ticks)
        return error.OwnershipMismatch;
    try proc.checkStatus(status, identity.uid, identity.parent);
    if (!std.mem.eql(u8, command, expected)) return error.OwnershipMismatch;
}

fn startTicks(io: std.Io, pid: c.pid_t) proc.Error!u64 {
    var buffer: [4096]u8 = undefined;
    const stat = try proc.procRead(io, pid, "stat", &buffer);
    const end = std.mem.lastIndexOfScalar(u8, stat, ')') orelse return error.InvalidProc;
    var fields = std.mem.tokenizeScalar(u8, stat[end + 1 ..], ' ');
    // The comm field may itself contain spaces and parentheses. Field 22 is starttime.
    for (3..22) |_| _ = fields.next() orelse return error.InvalidProc;
    return std.fmt.parseInt(u64, fields.next() orelse return error.InvalidProc, 10) catch
        return error.InvalidProc;
}

pub const SignalError = proc.Error || std.posix.KillError;

pub const Guard = struct {
    command: [8192]u8 = undefined,
    command_len: usize = 0,
    final_command: [8192]u8 = undefined,
    final_command_len: usize = 0,
    identity: ?Identity = null,
    term_sent: bool = false,

    pub fn prepare(argv: []const []const u8, final_argv: []const []const u8) proc.Error!Guard {
        var guard: Guard = .{};
        guard.command_len = (try proc.encodeCommand(&guard.command, argv)).len;
        guard.final_command_len = (try proc.encodeCommand(&guard.final_command, final_argv)).len;
        return guard;
    }

    pub fn capture(self: *Guard, io: std.Io, child: *const std.process.Child) proc.Error!void {
        const pid = child.id orelse return error.OwnershipMismatch;
        // Optional result-location writes can publish the tag before a later field fails.
        const ticks = try startTicks(io, pid);
        // Capture before any possible wait. Exec preserves this direct-child identity.
        self.identity = .{
            .pid = pid,
            .parent = c.getpid(),
            .uid = c.getuid(),
            .start_ticks = ticks,
        };
    }

    pub fn exited(self: *const Guard, io: std.Io, child: *const std.process.Child) proc.Error!bool {
        const identity = self.identity orelse return error.OwnershipMismatch;
        const pid = child.id orelse return error.OwnershipMismatch;
        if (c.getuid() != identity.uid or c.getpid() != identity.parent)
            return error.OwnershipMismatch;
        if (pid != identity.pid or try startTicks(io, pid) != identity.start_ticks)
            return error.OwnershipMismatch;
        var buffer: [4096]u8 = undefined;
        const status = try proc.procRead(io, pid, "status", &buffer);
        try proc.checkStatus(status, identity.uid, identity.parent);
        const state = proc.statusField(status, "State:") orelse return error.InvalidProc;
        if (state.len == 0) return error.InvalidProc;
        return state[0] == 'Z' or state[0] == 'X';
    }

    pub fn signal(
        self: *Guard,
        io: std.Io,
        child: *const std.process.Child,
        sig: c.SIG,
    ) SignalError!void {
        const identity = self.identity orelse return error.OwnershipMismatch;
        const pid = child.id orelse return error.OwnershipMismatch;
        if (pid != identity.pid) return error.OwnershipMismatch;
        try proc.excludeAncestors(io, pid);
        try proc.verifyProcOwner(pid, c.getuid());
        if (c.getuid() != identity.uid or c.getpid() != identity.parent)
            return error.OwnershipMismatch;
        if (try self.exited(io, child)) return;
        var status_buffer: [4096]u8 = undefined;
        var command_buffer: [8192]u8 = undefined;
        const status = try proc.procRead(io, pid, "status", &status_buffer);
        // procRead probes past a full buffer, so a truncated cmdline never passes.
        const command = try proc.procRead(io, pid, "cmdline", &command_buffer);
        const expected = if (std.mem.eql(
            u8,
            command,
            self.final_command[0..self.final_command_len],
        ))
            self.final_command[0..self.final_command_len]
        else
            self.command[0..self.command_len];
        validate(identity, pid, try startTicks(io, pid), status, command, expected, false) catch |err| {
            // An exit between status and cmdline is not an unsafe command to signal.
            if (try self.exited(io, child)) return;
            return err;
        };
        if (sig == .KILL and !self.term_sent) return error.OwnershipMismatch;
        std.posix.kill(pid, sig) catch |err| {
            if (try self.exited(io, child)) return;
            return err;
        };
        if (sig == .TERM) self.term_sent = true;
    }
};

/// Only an owner already confirmed reaped may dispose any remaining stdio handles.
pub fn closePipes(io: std.Io, child: *std.process.Child) void {
    std.debug.assert(child.id == null);
    if (child.stdin) |pipe| pipe.close(io);
    if (child.stdout) |pipe| pipe.close(io);
    if (child.stderr) |pipe| pipe.close(io);
    child.stdin = null;
    child.stdout = null;
    child.stderr = null;
}

test "child ownership guard rejects missing prepared identity before exit inspection" {
    const child: std.process.Child = .{
        .id = -1,
        .thread_handle = {},
        .stdin = null,
        .stdout = null,
        .stderr = null,
        .request_resource_usage_statistics = false,
    };
    var guard: Guard = .{};
    // A synthetic impossible PID cannot name a foreign process or be signaled.
    try std.testing.expectError(error.OwnershipMismatch, guard.exited(std.testing.io, &child));
    try std.testing.expectError(
        error.OwnershipMismatch,
        guard.signal(std.testing.io, &child, .TERM),
    );
    try std.testing.expect(!guard.term_sent);
}
