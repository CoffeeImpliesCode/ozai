//! One `ozai-node` child, and everything this file reads from it.
//!
//! `Process` is two pipes and a `poll`: the banner, the live snapshots and the
//! final report all arrive on the child's own stdout, and each is read as it
//! completes rather than as a whole. `Plan` is what the child was started with —
//! a fixed identity, a fixed generator seed, a deadline of its own, and whatever
//! peers the test has already seen bind.
//!
//! The roster a process is put on and the progress lines it writes are in
//! `two_process_roster.zig` and `two_process_progress.zig`: a process cannot
//! wait for a state, so it only reports one and someone else decides what to do
//! about a deadline.

const std = @import("std");

const posix = std.posix;

const progress_ns = @import("two_process_progress.zig");
const roster_ns = @import("two_process_roster.zig");
const signal_safety = @import("child_signal_safety.zig");
const cleanup = @import("child_cleanup.zig");

/// Every allocation in this file goes through a handle the caller handed in,
/// which here is `std.testing`'s own allocator: `AGENTS.md` §1 by name.
pub const Allocator = std.mem.Allocator;

/// No peers, for a node that is only going to be dialled.
const no_peers: []const []const u8 = &.{};

// ---------------------------------------------------------------------------
// What a node is started with
// ---------------------------------------------------------------------------

/// A fixed identity, a fixed generator seed, a deadline of its own, and
/// whatever peers the test has already seen bind.
///
/// The identity is a byte repeated into a seed rather than a key literal, so
/// both halves of a run present the same certificate on every run and a failure
/// reproduces rather than having to be re-diagnosed. The generator seeds are
/// distinct per node, so neither half can hand the core a connection id the
/// other has already used.
pub const Plan = struct {
    /// The byte every byte of the ed25519 seed is made of.
    tag: u8,
    /// `--for`, in milliseconds.
    run_ms: i64,
    /// `--seed`.
    seed: u64,
    /// Peers to dial, as `nodeid@ip:port`.
    peers: []const []const u8 = no_peers,
    /// Actual HTTP/WebSocket carrier listener, as `ip:port`.
    relay_listen: ?[]const u8 = null,
    /// Actual carrier connection address, separate from the pinned inner peer.
    relay_server: ?[]const u8 = null,
    /// HTTP Host value for the carrier upgrade.
    relay_host: ?[]const u8 = null,
    /// Pinned inner QUIC peers, as `nodeid@relayURL`.
    peer_relays: []const []const u8 = no_peers,
    /// Flags appended as written, for a command line that is meant to be
    /// refused and has no field above.
    extra: []const []const u8 = &.{},
};

/// One `ozai-node` child, and everything this file reads from it.
///
/// Two pipes and a `poll` carry the banner, live snapshots, and final report.
pub const Process = struct {
    child: std.process.Child,
    guard: signal_safety.Guard = .{},
    gpa: Allocator,
    /// The name every message about this process carries.
    name: []const u8,
    /// The roster this process was put on, so that a failure about one node
    /// can print every other node with it. The report a check reads is the
    /// answer to the question, and the question is usually about a *different*
    /// process than the one that failed to answer: the gate that never
    /// arrived, the peer that was signalled before it had connected.
    roster: ?*roster_ns.Roster = null,
    /// What it wrote to stdout and to stderr, in the order it wrote it. Both are
    /// kept: stderr is where a refused dial is said, and a run that has failed
    /// has to be able to print it.
    out: std.ArrayList(u8) = .empty,
    err_out: std.ArrayList(u8) = .empty,
    /// Set when a pipe said end of file, which is a process that has said
    /// everything it was going to say.
    out_done: bool = false,
    err_done: bool = false,
    /// Whether this file has taken the process back from the kernel. `wait`
    /// closes the pipes, so a reaped process must be off the roster before
    /// anything polls it again.
    reaped: bool = false,
    failed_start: bool = false,
    run_ms: i64 = 0,
    probe: @import("child_exit_probe.zig").Probe = .{},

    pub const StartError = std.process.SpawnError || @import("nat_proc_safety.zig").Error;
    pub const StartResult = union(enum) {
        ready: *Process,
        failed: struct { cause: StartError, process: *Process },
    };
    pub const PumpError = posix.PollError || std.Io.File.Reader.Error ||
        Allocator.Error || error{CheckFailed};
    pub const WaitError = std.process.Child.WaitError;

    /// Allocates the owner before fallible construction. Both result variants own that storage.
    /// The caller must keep a failed result until finish confirms kernel exit and reaps its child.
    pub fn start(
        gpa: Allocator,
        io: std.Io,
        options: signal_safety.StartOptions,
    ) Allocator.Error!StartResult {
        const self = try gpa.create(Process);
        self.* = .{
            .child = .{
                .id = null,
                .thread_handle = {},
                .stdin = null,
                .stdout = null,
                .stderr = null,
                .request_resource_usage_statistics = false,
            },
            .gpa = gpa,
            .name = options.name,
            .reaped = true,
            .failed_start = true,
            .run_ms = options.run_ms,
            .probe = options.probe,
        };
        self.guard = signal_safety.Guard.prepare(options.argv, options.final_argv) catch |err|
            return .{ .failed = .{ .cause = err, .process = self } };
        self.child = std.process.spawn(io, .{
            .argv = options.argv,
            .stdin = .ignore,
            .stdout = .pipe,
            .stderr = .pipe,
        }) catch |err| {
            std.debug.print("two_process: could not start {s} ({t}). Command:\n", .{
                options.name, err,
            });
            for (options.argv) |arg| std.debug.print("  {s}\n", .{arg});
            return .{ .failed = .{ .cause = err, .process = self } };
        };
        self.reaped = false;
        self.guard.capture(io, &self.child) catch |err|
            return .{ .failed = .{ .cause = err, .process = self } };
        self.failed_start = false;
        return .{ .ready = self };
    }

    /// Retains all owner storage on failure; failed construction never grants signal authority.
    pub fn finish(self: *Process, io: std.Io) cleanup.CleanupError(*Process)!void {
        if (self.failed_start) return cleanup.finishFailedStart(io, self);
        return cleanup.finish(io, self);
    }

    /// Fixture disposal requires the declared peer watchdog to terminate failed-start children.
    /// Call finish directly to retain and inspect an owner after any cleanup failure.
    pub fn deinit(self: *Process, io: std.Io) void {
        const name = self.name;
        const pid = self.child.id;
        const failure: ?cleanup.CleanupError(*Process) =
            if (self.finish(io)) |_| null else |err| err;
        if (!self.reaped) {
            std.debug.panic(
                "fixture peer watchdog/ownership contract violated; owner retained: {s} " ++
                    "(pid {?d}, failure {?t})",
                .{ name, pid, failure },
            );
        }
        signal_safety.closePipes(io, &self.child);
        self.out.deinit(self.gpa);
        self.err_out.deinit(self.gpa);
        const gpa = self.gpa;
        gpa.destroy(self);
        if (failure) |err| {
            std.debug.panic("child cleanup failed closed for {s} (pid {?d}): {t}", .{
                name, pid, err,
            });
        }
    }

    /// Take whatever the child has written on one pipe, without waiting for it.
    fn take(
        self: *Process,
        io: std.Io,
        pipe: std.Io.File,
        into: *std.ArrayList(u8),
        done: *bool,
    ) PumpError!void {
        var fds = [_]posix.pollfd{.{
            .fd = pipe.handle,
            .events = posix.POLL.IN,
            .revents = 0,
        }};
        if (try posix.poll(&fds, 0) == 0) return;
        var chunk: [4096]u8 = undefined;
        const got = pipe.readStreaming(io, &.{&chunk}) catch |err| switch (err) {
            // The writer has closed its end: everything this process had to say,
            // it has said.
            error.EndOfStream => {
                done.* = true;
                return;
            },
            else => |read_error| return read_error,
        };
        if (got == 0) done.* = true;
        try into.appendSlice(self.gpa, chunk[0..got]);
    }

    /// `pub` because `two_process_roster.zig` calls it across the file boundary
    /// the split that gave this module its own name introduced.
    pub fn pump(self: *Process, io: std.Io) PumpError!void {
        // `reaped` is what says `wait` has not closed these yet, and `spawn` was
        // asked for both pipes, so a null below is a child in a state this file
        // has no reading for rather than a normal outcome to absorb.
        if (self.reaped) return;
        var failure: ?PumpError = null;
        if (!self.out_done) {
            const pipe = self.child.stdout orelse
                return self.gaveUp("had no stdout pipe, having asked for one", .{});
            self.take(io, pipe, &self.out, &self.out_done) catch |err| {
                failure = err;
            };
        }
        if (!self.err_done) {
            const pipe = self.child.stderr orelse
                return self.gaveUp("had no stderr pipe, having asked for one", .{});
            self.take(io, pipe, &self.err_out, &self.err_done) catch |err| {
                failure = failure orelse err;
            };
        }
        if (failure) |err| return err;
    }

    /// The first line of what this process wrote that begins with `prefix`.
    ///
    /// A line without its newline yet is not a line. The report is read as it
    /// arrives, and half a counter is half a counter.
    ///
    /// `pub` because `two_process_report.zig` calls it across the file boundary
    /// the split that gave this module its own name introduced.
    pub fn line(self: *const Process, prefix: []const u8) ?[]const u8 {
        var rest = self.out.items;
        while (std.mem.findScalar(u8, rest, '\n')) |end| {
            const found = rest[0..end];
            if (std.mem.startsWith(u8, found, prefix)) return found;
            rest = rest[end + 1 ..];
        }
        return null;
    }

    /// What a line said after its label, with the spaces between them gone.
    /// `pub` because `two_process_launch.zig` calls it across the file boundary
    /// the split that gave this module its own name introduced.
    pub fn value(self: *const Process, prefix: []const u8) ?[]const u8 {
        const found = self.line(prefix) orelse return null;
        return std.mem.trim(u8, found[prefix.len..], " ");
    }

    /// The address this node printed it bound, port included.
    /// `pub` because `two_process_launch.zig` calls it across the file boundary
    /// the split that gave this module its own name introduced.
    pub fn bound(self: *const Process) ?[]const u8 {
        return self.value("listening");
    }

    /// Whether this node has said everything it was going to say, which from
    /// out here is the only way to tell a running node from an exited one that
    /// has not been reaped yet.
    /// `pub` because `two_process_roster.zig` calls it across the file boundary
    /// the split that gave this module its own name introduced.
    pub fn finished(self: *const Process) bool {
        return self.out_done and self.err_done;
    }

    /// A node has said where it is listening: it can be dialled.
    /// `pub` because `two_process_test.zig` calls it across the file boundary
    /// the split that gave this module its own name introduced.
    pub fn saidWhereItListens(self: *const Process) bool {
        return self.line("listening") != null;
    }

    /// The production banner's actual TCP carrier listener, including its chosen port.
    pub fn carrierBound(self: *const Process) ?[]const u8 {
        return self.value("relay TCP  serving ");
    }

    pub fn saidWhereCarrierListens(self: *const Process) bool {
        return self.carrierBound() != null;
    }

    /// The newest complete `progress:` line this node has written.
    ///
    /// **The newest, never the oldest**, which is the one thing about these
    /// lines that is easy to get backwards: a node that has been running for a
    /// while has written many, and only the last is the state that matters. A
    /// line without its newline yet is not a line, for the reason `line` gives.
    ///
    /// `pub` because `two_process_progress.zig` calls it across the file
    /// boundary the split that gave this module its own name introduced.
    pub fn progressLine(self: *const Process) ?[]const u8 {
        var rest = self.out.items;
        var newest: ?[]const u8 = null;
        while (std.mem.findScalar(u8, rest, '\n')) |end| {
            const found = rest[0..end];
            if (std.mem.startsWith(u8, found, progress_ns.progress_prefix)) newest = found;
            rest = rest[end + 1 ..];
        }
        return newest;
    }

    /// The newest complete `progress:` line, read as the counts it gives.
    /// `pub` because `two_process_roster.zig` calls it across the file boundary
    /// the split that gave this module its own name introduced.
    pub fn progress(self: *const Process) ?progress_ns.Progress {
        return progress_ns.parseProgress(self.progressLine() orelse return null);
    }

    /// Ask the owned, unreaped node to stop after fresh full proc identity checks.
    pub fn stop(self: *Process, io: std.Io) signal_safety.SignalError!void {
        try self.guard.signal(io, &self.child, .TERM);
    }

    /// EOF alone does not prove exit; bound the wait before handing the child to Io.
    pub fn waitForExit(
        self: *Process,
        io: std.Io,
    ) cleanup.CleanupError(*Process)!std.process.Child.Term {
        return cleanup.waitForExit(io, self);
    }

    /// Print everything this node said, which is what a failure here is read
    /// against.
    /// `pub` because `two_process_roster.zig` calls it across the file boundary
    /// the split that gave this module its own name introduced.
    pub fn dump(self: *const Process) void {
        std.debug.print(
            \\
            \\--- {s} said on stdout ---
            \\{s}
            \\--- {s} said on stderr ---
            \\{s}
            \\
        , .{ self.name, self.out.items, self.name, self.err_out.items });
    }

    /// Say what went wrong with this node and give the run up.
    ///
    /// The whole roster is printed, not just this process: the counter that
    /// did not hold is the symptom, and the cause is nearly always in a
    /// sibling's output — a gate that reports no handshake, a peer that was
    /// signalled before it had connected. One process's dump has been the
    /// wrong half of this diagnostic for the whole life of the file.
    ///
    /// `pub` because `two_process_launch.zig` and `two_process_report.zig` call
    /// it across the file boundary the split that gave this module its name.
    pub fn gaveUp(
        self: *const Process,
        comptime format: []const u8,
        args: anytype,
    ) error{CheckFailed} {
        if (self.roster) |roster| return roster.gaveUp(format, self, null, args);
        std.debug.print("two_process: {s}: " ++ format ++ "\n", .{self.name} ++ args);
        self.dump();
        return error.CheckFailed;
    }
};

test "Node constructor proc capture failure retains exact owner through deadline" {
    try @import("child_constructor_safety.zig").captureFailureRetention(Process);
}

test "Node constructor capture failure and wait failure retain exact owner" {
    try @import("child_constructor_safety.zig").captureFailureWaitError(Process);
}

test "Node constructor preparation failure owns storage without spawning" {
    try @import("child_constructor_safety.zig").preparationFailureOwnership(Process);
}
