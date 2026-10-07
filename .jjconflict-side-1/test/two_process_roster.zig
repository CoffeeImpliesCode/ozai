//! The processes one test is watching, so that one wait watches all of them,
//! and the clock that wait is bounded by.
//!
//! A wait that watched one pipe and let another's fill would be a wait that can
//! wedge the run it is watching, and every node here writes its own banner and
//! its own report on its own pipe. The host clock appears here and nowhere in
//! `src/`: a node takes its instant as data, and a test that spawns a process
//! is outside `ozai.base`. It bounds a failure and never decides one — what a
//! node has reached is answered by the node.

const std = @import("std");
const builtin = @import("builtin");
const ozai = @import("ozai");

const posix = std.posix;

const child = @import("two_process_child.zig");
const progress_ns = @import("two_process_progress.zig");

const Allocator = child.Allocator;
const Process = child.Process;
const Want = progress_ns.Want;

/// Import the loop interval so watchdog arithmetic follows the node's cadence.
const pass_ms: i64 = @intCast(ozai.node.poll_interval_ms);

/// Allow twice the nominal poll interval for scheduler contention.
/// This allowance bounds a failed run. It does not prove that a state was reached.
const pass_slack: i64 = 2;

/// `passes` passes, as the wall clock that is `passes` of them.
pub fn windowMs(passes: i64) i64 {
    return passes * pass_ms * pass_slack;
}

/// The passes one parent wait allows, per target.
///
/// **This bounds the harness, and nothing else.** No wait in
/// `two_process_test.zig` claims anything about a duration: every one of them
/// is gated on a counter the node published after it reached the state that
/// counter names. A deadline that a slow emulator can trip must not be where a
/// correctness claim hides, and what the wall clock decides here is how many of
/// a node's passes fit inside the budget — a fact about the target rather than
/// about the program under test.
///
/// Sixty seconds is the row this project gates on, and the only row where the
/// waits it bounds have been measured in seconds. Every other row of the cross
/// matrices reaches this file through an emulator, where the same waits run an
/// order of magnitude longer and where the harness runs rows beside each other,
/// so those rows get ten times the bound: enough that a wait given up on here is
/// a finding about a node rather than about the machine it ran on.
fn waitPasses() i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => gate_passes,
        else => emulated_passes,
    };
}

/// The gated row's allowance: 120 passes, twice over for contention.
const gate_passes = 120;

/// Ten times that, for a target this project only ever emulates.
const emulated_passes = 10 * gate_passes;

pub const budget_ms: i64 = windowMs(waitPasses());

/// A child must remain alive while its parent observes and signals it.
/// Auto-expiry is a last-resort guard, not the event a lifecycle test awaits.
///
/// It is a function of `budget_ms` for the reason `budget_ms` is a function of
/// the target: `--for` is wall clock, so a slow target gets *fewer* passes
/// before it expires rather than more, and a child that expired mid-run would
/// report `exited before reporting ...` for a run that was only slow.
pub const watchdog_ms: i64 = 4 * budget_ms;

/// How long a single `poll` blocks, so a line one of the nodes writes is noticed
/// while the roster is being read rather than at the end of the wait.
pub const poll_slice_ms: i32 = 100;

/// The largest roster: two peers and a third node supplying another connection.
const max_processes = 3;

/// The processes one test is watching, so that one wait watches all of them.
///
/// A wait that watched one pipe and let another's fill would be a wait that can
/// wedge the run it is watching, and every node here writes its own banner and
/// its own report on its own pipe.
///
/// Most of what follows is `pub`: `two_process_test.zig`, `two_process_child.zig`
/// and `two_process_launch.zig` drive the roster from their own files, and the
/// split that gave this module its own name found the driving surface private
/// to the file that stores the processes. Two stay private, because they are
/// answers only another answer asks: `dumpAll` for `gaveUp`, and `holds` for
/// `awaitWant`.
pub const Roster = struct {
    items: std.ArrayList(*Process) = .empty,

    /// Forget the list. Each process is a `defer` of its own and outlives this.
    ///
    /// `pub` because `two_process_test.zig`, `two_process_child.zig` and
    /// `two_process_launch.zig` call it across the file boundary the split
    /// introduced.
    pub fn deinit(self: *Roster, gpa: Allocator) void {
        self.items.deinit(gpa);
        // An `ArrayList` whose backing store is gone is not a list any more, so
        // the field is put back to empty rather than left holding a freed
        // pointer and a length that reads it. Nothing is lost: the roster owns
        // no process — each one is a `defer` of its own, running before this,
        // because they were deferred after it — and `items` is its only field.
        self.items = .empty;
    }

    /// Take one more process into the one wait that watches them all.
    ///
    /// `pub` because `two_process_launch.zig` calls it across the file boundary
    /// the split introduced.
    pub fn add(self: *Roster, gpa: Allocator, process: *Process) !void {
        process.roster = self;
        try self.items.append(gpa, process);
    }

    /// One pass of every pipe, handing each process its own progress.
    ///
    /// `pub` because `two_process_test.zig` and `two_process_child.zig` call it
    /// across the file boundary the split introduced.
    pub fn pump(self: *Roster, io: std.Io) !void {
        for (self.items.items) |process| try process.pump(io);
    }

    /// Block until one of the pipes has something on it, or `timeout_ms` has
    /// passed without any of them having.
    ///
    /// `pub` because `two_process_child.zig` calls it across the file boundary
    /// the split introduced.
    pub fn wait(self: *Roster, timeout_ms: i32) !void {
        var fds: [max_processes * 2]posix.pollfd = undefined;
        var open: usize = 0;
        for (self.items.items) |process| {
            if (process.reaped) continue;
            for (
                [_]?std.Io.File{ process.child.stdout, process.child.stderr },
                [_]bool{ process.out_done, process.err_done },
            ) |pipe, done| {
                if (done) continue;
                const end = pipe orelse continue;
                fds[open] = .{
                    .fd = end.handle,
                    .events = posix.POLL.IN,
                    .revents = 0,
                };
                open += 1;
            }
        }
        if (open == 0) return;
        _ = try posix.poll(fds[0..open], timeout_ms);
    }

    /// Pump until `ready` holds for `process`, or `budget` passes without it.
    ///
    /// Whether it held. Every caller names what it wanted, because a wait that
    /// times out is worth nothing without the question it was asking.
    ///
    /// `pub` because `two_process_test.zig` calls it across the file boundary
    /// the split introduced.
    pub fn await(
        self: *Roster,
        io: std.Io,
        process: *Process,
        ready: *const fn (*const Process) bool,
        budget: i64,
    ) !bool {
        const deadline = nowMs(io) + budget;
        while (true) {
            try self.pump(io);
            if (ready(process)) return true;
            if (process.finished()) return false;
            const left = deadline - nowMs(io);
            if (left <= 0) return false;
            try self.wait(@intCast(@min(left, poll_slice_ms)));
        }
    }

    /// Wait for a node to finish and take it back from the kernel.
    ///
    /// Null when it did not finish in time, which is a finding rather than a
    /// shape of test to pass: the caller says what it wanted.
    ///
    /// `pub` because `two_process_test.zig` calls it across the file boundary
    /// the split introduced.
    pub fn reap(
        self: *Roster,
        io: std.Io,
        process: *Process,
        budget: i64,
    ) !?std.process.Child.Term {
        if (!try self.await(io, process, &Process.finished, budget)) return null;
        const term = try process.child.wait(io);
        process.reaped = true;
        return term;
    }

    /// Print every child that took part in this run.
    fn dumpAll(self: *const Roster) void {
        for (self.items.items) |each| each.dump();
    }

    /// Wait until `process` has reported the state `want` describes, and give
    /// the run up naming what it was waiting for and which counter stayed put.
    ///
    /// This is the wait every stop in this file is gated on. Nothing here
    /// decides when a node may be signalled by counting milliseconds and
    /// hoping the count was enough: a node publishes what it has after every
    /// pass, so the question is answered by the node rather than by a clock,
    /// and the only deadline left is the watchdog that bounds a failure.
    ///
    /// A conjunction, not a sequence. The counters that witness "it noticed"
    /// do not all move on the same pass, and a gate that took them one at a
    /// time could fire on the first and then read the rest out of a report
    /// written too early — which is the bug this file used to have.
    ///
    /// `pub` because `two_process_test.zig` calls it across the file boundary
    /// the split introduced.
    pub fn awaitWant(
        self: *Roster,
        io: std.Io,
        process: *Process,
        what: []const u8,
        want: Want,
        budget: i64,
    ) !void {
        const deadline = nowMs(io) + budget;
        while (!holds(process, want)) {
            try self.pump(io);
            if (holds(process, want)) return;
            if (process.finished()) return self.gaveUp(
                "exited before reporting {s}",
                process,
                want,
                .{what},
            );
            const left = deadline - nowMs(io);
            if (left <= 0) return self.gaveUp(
                "never reported {s} in {d} ms",
                process,
                want,
                .{ what, budget },
            );
            try self.wait(@intCast(@min(left, poll_slice_ms)));
        }
    }

    /// Whether the newest progress line `process` has written satisfies `want`.
    ///
    /// A node that has written no progress line at all satisfies nothing, which
    /// is the right answer: it has not got to the state, and the failure names
    /// the counters rather than a parser's opinion of them.
    fn holds(process: *const Process, want: Want) bool {
        const seen = process.progress() orelse return false;
        for (want.all) |need| {
            if (!need.holds(seen)) return false;
        }
        if (want.any.len == 0) return true;
        for (want.any) |either| {
            var all_of_them = true;
            for (either) |need| {
                if (!need.holds(seen)) all_of_them = false;
            }
            if (all_of_them) return true;
        }
        return false;
    }

    /// Say what this run was waiting for, name the counters that stayed put,
    /// print every node that took part in it, and give it up.
    ///
    /// `pub` because `two_process_test.zig` calls it across the file boundary
    /// the split introduced.
    pub fn gaveUp(
        self: *const Roster,
        comptime format: []const u8,
        process: *const Process,
        want: ?Want,
        args: anytype,
    ) error{CheckFailed} {
        std.debug.print("two_process: {s}: " ++ format ++ "\n", .{process.name} ++ args);
        if (want) |asked| progress_ns.reportUnmet(process, asked);
        self.dumpAll();
        return error.CheckFailed;
    }
};

/// The monotonic clock, in milliseconds.
///
/// Read here and nowhere in `src/`: a node takes its instant as data, and a
/// test that spawns a process is outside `ozai.base`.
fn nowMs(io: std.Io) i64 {
    return @intCast(@divTrunc(std.Io.Clock.awake.now(io).nanoseconds, std.time.ns_per_ms));
}
