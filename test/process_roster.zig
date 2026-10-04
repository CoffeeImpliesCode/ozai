//! The processes one test is watching, watched together.
//!
//! A wait that watched one pipe and let another's fill would be a wait that can
//! wedge the run it is watching, and every node in these tests writes its own
//! banner and its own report on its own pipe. So one wait here pumps and polls
//! every child on the roster at once, and a gate on one node is answered by a
//! roster that is also draining the others.
//!
//! Every wait is bounded. `await`, `awaitWant` and `reap` take a budget and
//! return whether the thing asked for was seen; a deadline bounds a failure
//! rather than a success, and no wait here decides anything by counting
//! milliseconds and hoping the count was enough.
//!
//! This module owns the *list*, not the children. The `*Process` it holds is
//! owned by `process_driver.zig` for the child's whole life, and each is a
//! `defer` of its own in the test that started it, so the roster never frees
//! one and never outlives one.

const std = @import("std");

const driver = @import("process_driver.zig");
const report = @import("process_report.zig");

const posix = std.posix;
const Allocator = std.mem.Allocator;
const Process = driver.Process;

/// The largest roster: two peers and a third node supplying another connection.
///
/// This is the bound on the poll buffer below rather than an arbitrary limit:
/// every child has two pipes, and a roster larger than this would have nowhere
/// to put the handles for them.
const max_processes = 8;

/// How long a single `poll` blocks, so a line one of the nodes writes is noticed
/// while the roster is being read rather than at the end of the wait.
const poll_slice_ms: i32 = 100;

pub const Roster = struct {
    items: std.ArrayList(*Process) = .empty,

    pub fn deinit(self: *Roster, gpa: Allocator) void {
        self.items.deinit(gpa);
        // An `ArrayList` whose backing store is gone is not a list any more, so
        // the field is put back to empty rather than left holding a freed
        // pointer and a length that reads it. Nothing is lost: the roster owns
        // no process — each one is a `defer` of its own, running before this,
        // because they were deferred after it — and `items` is its only field.
        self.items = .empty;
    }

    /// Put a child on the roster, refusing a roster the poll buffer cannot hold.
    pub fn add(self: *Roster, gpa: Allocator, process: *Process) !void {
        if (self.items.items.len == max_processes) return error.TooManyProcesses;
        try self.items.append(gpa, process);
    }

    pub fn pump(self: *Roster, io: std.Io) !void {
        for (self.items.items) |process| try process.pump(io);
    }

    /// Block until one of the pipes has something on it, or `timeout_ms` has
    /// passed without any of them having.
    fn wait(self: *Roster, timeout_ms: i32) !void {
        var fds: [max_processes * 2]posix.pollfd = undefined;
        var open: usize = 0;
        for (self.items.items) |process| {
            open += process.pollInto(fds[open..]);
        }
        if (open == 0) return;
        _ = try posix.poll(fds[0..open], timeout_ms);
    }

    /// Pump until `ready` holds for `process`, or `budget` passes without it.
    ///
    /// Whether it held. Every caller names what it wanted, because a wait that
    /// times out is worth nothing without the question it was asking.
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

    /// Wait until `process` has reported the state `want` describes, and give
    /// the run up naming what it was waiting for and which counter stayed put.
    ///
    /// This is the wait every stop in these tests is gated on. Nothing here
    /// decides when a node may be signalled by counting milliseconds and
    /// hoping the count was enough: a node publishes what it has after every
    /// pass, so the question is answered by the node rather than by a clock,
    /// and the only deadline left is the watchdog that bounds a failure.
    ///
    /// A conjunction, not a sequence. The counters that witness "it noticed"
    /// do not all move on the same pass, and a gate that took them one at a
    /// time could fire on the first and then read the rest out of a report
    /// written too early — which is the bug these tests used to have, when the
    /// wait and the state it reads were one file and the conjunction above was
    /// added to it.
    pub fn awaitWant(
        self: *Roster,
        io: std.Io,
        process: *Process,
        what: []const u8,
        want: report.Want,
        budget: i64,
    ) !void {
        const deadline = nowMs(io) + budget;
        while (!report.holds(process, want)) {
            try self.pump(io);
            if (report.holds(process, want)) return;
            if (process.finished()) return self.gaveUp(
                process,
                want,
                "exited before reporting {s}",
                .{what},
            );
            const left = deadline - nowMs(io);
            if (left <= 0) return self.gaveUp(
                process,
                want,
                "never reported {s} in {d} ms",
                .{ what, budget },
            );
            try self.wait(@intCast(@min(left, poll_slice_ms)));
        }
    }

    /// Wait for a node to finish and take it back from the kernel.
    ///
    /// Null when it did not finish in time, which is a finding rather than a
    /// shape of test to pass: the caller says what it wanted.
    pub fn reap(
        self: *Roster,
        io: std.Io,
        process: *Process,
        budget: i64,
    ) !?std.process.Child.Term {
        if (!try self.await(io, process, &Process.finished, budget)) return null;
        const term = try process.reap(io);
        return term;
    }

    /// Say what this run was waiting for, name the counters that stayed put
    /// when a gate was waiting on any, print every node that took part in it,
    /// and give it up.
    ///
    /// The whole roster is printed, not just the process named: the counter
    /// that did not hold is the symptom, and the cause is nearly always in a
    /// sibling's output — a gate that reports no handshake, a peer that was
    /// signalled before it had connected. One process's dump has been the
    /// wrong half of this diagnostic for the whole life of these tests.
    // The format stays last among the value parameters, beside the arguments
    // it is written for, because Zig 0.16 rejects a method whose first
    // parameter is not the receiver: Z023's "comptime before other" cannot be
    // satisfied for a method at all, so this is the order that keeps the
    // call sites reading the way every other failure in this tree reads.
    pub fn gaveUp(
        self: *const Roster,
        process: *const Process,
        want: ?report.Want,
        // The ignore is on the parameter rather than on the declaration above
        // it: Z023 reports the parameter, and an ignore comment one node up
        // never reaches what it names.
        // ziglint-ignore: Z023
        comptime format: []const u8,
        args: anytype,
    ) error{CheckFailed} {
        std.debug.print("two_process: {s}: " ++ format ++ "\n", .{process.name} ++ args);
        if (want) |asked| report.reportUnmet(process, asked);
        self.dumpAll();
        return error.CheckFailed;
    }

    /// Print every child that took part in this run.
    fn dumpAll(self: *const Roster) void {
        for (self.items.items) |each| each.dump();
    }
};

/// The monotonic clock, in milliseconds.
///
/// Read here and nowhere in `src/`: a node takes its instant as data, and a
/// test that spawns a process is outside `ozai.base`.
fn nowMs(io: std.Io) i64 {
    return @intCast(@divTrunc(std.Io.Clock.awake.now(io).nanoseconds, std.time.ns_per_ms));
}
