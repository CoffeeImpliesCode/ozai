//! One real `ozai-node` child: the process, its two pipes, and every byte this
//! run reads off them.
//!
//! There is exactly one owner of a child for its whole life. `start` allocates
//! the `Process`, `reap` is the only call that takes the process back from the
//! kernel, and `deinit` is the only call that frees it. Nothing copies a
//! `std.process.Child` or a `std.Io.File` out of here: a roster asks this
//! module for poll handles by index and reads a child's words only through the
//! accessors below. A child therefore cannot be waited for twice, and nothing
//! can read from a pipe `wait` has already closed.
//!
//! What this module deliberately does not know: what a node is told to do
//! (`process_flags.zig` builds the command line and owns the argv), what the
//! other children are doing (`process_roster.zig` watches them together), and
//! what any of the words a child wrote mean (`process_report.zig` reads them).

const std = @import("std");

const posix = std.posix;
const Allocator = std.mem.Allocator;

/// One `ozai-node` child.
///
/// Two pipes and a `poll` carry the banner, the live snapshots, and whatever
/// final report the program chose to write.
pub const Process = struct {
    child: std.process.Child,
    gpa: Allocator,
    /// The name every message about this process carries.
    name: []const u8,
    /// What it wrote to stdout and to stderr, in the order it wrote it. Both are
    /// kept: stderr is where a refused dial and a failure are said, and a run
    /// that has failed has to be able to print it.
    out: std.ArrayList(u8) = .empty,
    err_out: std.ArrayList(u8) = .empty,
    /// Set when a pipe said end of file, which is a process that has said
    /// everything it was going to say.
    out_done: bool = false,
    err_done: bool = false,
    /// Whether this module has taken the process back from the kernel. `wait`
    /// closes the pipes, so a reaped process must be off the roster before
    /// anything polls it again.
    reaped: bool = false,

    /// Start a child and take it.
    ///
    /// `argv` belongs to the caller's arena: it outlives `spawn`, and an arena
    /// is the caller's, so a command line dies with the test that wrote it.
    /// This module spawns it and never reads it again.
    pub fn start(
        gpa: Allocator,
        io: std.Io,
        name: []const u8,
        argv: []const []const u8,
    ) !*Process {
        const self = try gpa.create(Process);
        errdefer gpa.destroy(self);
        self.* = .{
            .child = std.process.spawn(io, .{
                .argv = argv,
                .stdin = .ignore,
                .stdout = .pipe,
                .stderr = .pipe,
            }) catch |err| {
                // Keep the emitted node visible even when argv[0] is the foreign
                // executor, and every flag after it: a spawn that fails is
                // otherwise a refusal with nothing to read.
                std.debug.print(
                    "two_process: could not start {s} ({t}). Command:\n  {s}\n",
                    .{ name, err, argv[0] },
                );
                for (argv[1..]) |arg| std.debug.print("  {s}\n", .{arg});
                return err;
            },
            .gpa = gpa,
            .name = name,
        };
        return self;
    }

    pub fn deinit(self: *Process, io: std.Io) void {
        // The reason this is a `defer` on every test rather than a tidy-up at
        // the end: a node that outlives its test is a process the next run
        // collides with. `Child.kill` sends `SIGTERM` and then waits, so this
        // stops and reaps in one step.
        if (!self.reaped) {
            if (self.out_done) {
                // It has said everything it was going to say and is on its way
                // out. `kill` on a pid that is no longer there is a bug report
                // with a panic attached; `wait` on one that has just gone is
                // immediate.
                const term = self.child.wait(io) catch |err| {
                    std.debug.panic("could not reap {s}: {t}", .{ self.name, err });
                };
                switch (term) {
                    .exited, .signal => {},
                    else => std.debug.panic("incomplete termination of {s}: {any}", .{
                        self.name, term,
                    }),
                }
            } else {
                self.child.kill(io);
            }
        }
        self.out.deinit(self.gpa);
        self.err_out.deinit(self.gpa);
        const gpa = self.gpa;
        gpa.destroy(self);
    }

    /// Take whatever the child has written on one pipe, without waiting for it.
    fn take(
        self: *Process,
        io: std.Io,
        pipe: std.Io.File,
        into: *std.ArrayList(u8),
        done: *bool,
    ) !void {
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
            else => return err,
        };
        try into.appendSlice(self.gpa, chunk[0..got]);
    }

    pub fn pump(self: *Process, io: std.Io) !void {
        // `reaped` is what says `wait` has not closed these yet, and `spawn` was
        // asked for both pipes, so a null below is a child in a state this file
        // has no reading for rather than a normal outcome to absorb.
        if (self.reaped) return;
        if (!self.out_done) {
            const pipe = self.child.stdout orelse
                return self.gaveUp("had no stdout pipe, having asked for one", .{});
            try self.take(io, pipe, &self.out, &self.out_done);
        }
        if (!self.err_done) {
            const pipe = self.child.stderr orelse
                return self.gaveUp("had no stderr pipe, having asked for one", .{});
            try self.take(io, pipe, &self.err_out, &self.err_done);
        }
    }

    /// Write this child's readable pipe handles into `into` and say how many.
    ///
    /// The handles are the one thing about a child that another module needs and
    /// cannot have: a roster watches every child with a single `poll`, and a
    /// descriptor it could keep would outlive the pipe `wait` closes.
    pub fn pollInto(self: *const Process, into: []posix.pollfd) usize {
        if (self.reaped) return 0;
        var open: usize = 0;
        for (
            [_]?std.Io.File{ self.child.stdout, self.child.stderr },
            [_]bool{ self.out_done, self.err_done },
        ) |pipe, done| {
            if (done) continue;
            const end = pipe orelse continue;
            if (open == into.len) break;
            into[open] = .{
                .fd = end.handle,
                .events = posix.POLL.IN,
                .revents = 0,
            };
            open += 1;
        }
        return open;
    }

    /// Wait for this child and take it back from the kernel.
    ///
    /// The one call that closes the pipes, so it is the one call after which
    /// nothing may poll them.
    pub fn reap(self: *Process, io: std.Io) !std.process.Child.Term {
        const term = try self.child.wait(io);
        self.reaped = true;
        return term;
    }

    /// The first line of what this process wrote that begins with `prefix`.
    ///
    /// A line without its newline yet is not a line. The report is read as it
    /// arrives, and half a counter is half a counter.
    pub fn line(self: *const Process, prefix: []const u8) ?[]const u8 {
        var rest = self.out.items;
        while (std.mem.findScalar(u8, rest, '\n')) |end| {
            const found = rest[0..end];
            if (std.mem.startsWith(u8, found, prefix)) return found;
            rest = rest[end + 1 ..];
        }
        return null;
    }

    /// The newest complete line beginning with `prefix`, and null if none is
    /// complete yet.
    ///
    /// **The newest, never the oldest**, which is the one thing about a snapshot
    /// a long-running child writes that is easy to get backwards: a child that
    /// has been running for a while has written many, and only the last is the
    /// state that matters.
    pub fn newestLine(self: *const Process, prefix: []const u8) ?[]const u8 {
        var rest = self.out.items;
        var newest: ?[]const u8 = null;
        while (std.mem.findScalar(u8, rest, '\n')) |end| {
            const found = rest[0..end];
            if (std.mem.startsWith(u8, found, prefix)) newest = found;
            rest = rest[end + 1 ..];
        }
        return newest;
    }

    /// What a line said after its label, with the spaces between them gone.
    pub fn value(self: *const Process, prefix: []const u8) ?[]const u8 {
        const found = self.line(prefix) orelse return null;
        return std.mem.trim(u8, found[prefix.len..], " ");
    }

    /// The address this node printed it bound, port included.
    pub fn bound(self: *const Process) ?[]const u8 {
        return self.value("listening");
    }

    /// Everything this process has written to one stream, in order.
    pub fn stdoutText(self: *const Process) []const u8 {
        return self.out.items;
    }

    pub fn stderrText(self: *const Process) []const u8 {
        return self.err_out.items;
    }

    /// Whether this node has said everything it was going to say, which from
    /// out here is the only way to tell a running node from an exited one that
    /// has not been reaped yet.
    pub fn finished(self: *const Process) bool {
        return self.out_done and self.err_done;
    }

    /// A node has said where it is listening: it can be dialled.
    pub fn saidWhereItListens(self: *const Process) bool {
        return self.line("listening") != null;
    }

    /// Ask this node to stop, the way a supervisor does and the way
    /// `ozai-node` installs a handler for.
    ///
    /// `Child.id` is null once `wait` or `kill` has taken the process back, and
    /// every caller signals a child that is still on the roster, so a null here
    /// is this file signalling something it has already reaped. That is named
    /// rather than unwrapped: it fails the run with the reason on it instead of
    /// aborting the runner with a trap in `stop`.
    pub fn stop(self: *Process) !void {
        const id = self.child.id orelse
            return self.gaveUp("was signalled after it had already been reaped", .{});
        try posix.kill(id, .TERM);
    }

    /// Print everything this node said, which is what a failure here is read
    /// against.
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

    /// Say what went wrong with this node, print what it said, and give the run
    /// up.
    pub fn gaveUp(
        self: *const Process,
        comptime format: []const u8,
        args: anytype,
    ) error{CheckFailed} {
        std.debug.print("two_process: {s}: " ++ format ++ "\n", .{self.name} ++ args);
        self.dump();
        return error.CheckFailed;
    }
};
