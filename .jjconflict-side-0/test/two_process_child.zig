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

const launch = @import("two_process_launch.zig");
const progress_ns = @import("two_process_progress.zig");
const roster_ns = @import("two_process_roster.zig");

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

    /// Start a node with the flags this file needs and nothing else.
    ///
    /// `arena` owns the arguments: they outlive `spawn`, and an arena is the
    /// caller's, so a node's command line dies with the test that wrote it.
    ///
    /// `pub` because `two_process_launch.zig` calls it across the file boundary
    /// the split that gave this module its own name introduced.
    pub fn start(
        gpa: Allocator,
        arena: Allocator,
        io: std.Io,
        name: []const u8,
        plan: Plan,
    ) !*Process {
        const argv = try launch.flags(arena, plan);
        const self = try gpa.create(Process);
        errdefer gpa.destroy(self);
        self.* = .{
            .child = std.process.spawn(io, .{
                .argv = argv,
                .stdin = .ignore,
                .stdout = .pipe,
                .stderr = .pipe,
            }) catch |err| {
                // Keep the emitted node visible even when argv[0] is the foreign executor.
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

    /// `pub` because `two_process_launch.zig` calls it across the file boundary
    /// the split that gave this module its own name introduced.
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

    /// `pub` because `two_process_roster.zig` calls it across the file boundary
    /// the split that gave this module its own name introduced.
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

    /// Ask this node to stop, the way a supervisor does and the way
    /// `ozai-node` installs a handler for.
    ///
    /// `Child.id` is null once `wait` or `kill` has taken the process back, and
    /// every caller signals a child that is still on the roster, so a null here
    /// is this file signalling something it has already reaped. That is named
    /// rather than unwrapped: it fails the run with the reason on it instead of
    /// aborting the runner with a trap in `stop`.
    ///
    /// `pub` because `two_process_test.zig` calls it across the file boundary
    /// the split that gave this module its own name introduced.
    pub fn stop(self: *Process) !void {
        const id = self.child.id orelse
            return self.gaveUp("was signalled after it had already been reaped", .{});
        try posix.kill(id, .TERM);
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
