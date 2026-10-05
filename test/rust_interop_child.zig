//! One `ozai-iroh-peer` child, and everything this test reads from it.
//!
//! `Process` is the shape `test/two_process_child.zig` gives an `ozai-node`
//! child: two pipes and a `poll`, a banner, live `progress:` snapshots and a
//! final report, all arriving on the child's own stdout and each read as it
//! completes. The `progress:` line is the exact 15-field one
//! `test/two_process_progress.zig` parses, so [`progress`] and its `Want` gates
//! are that module's, reused rather than reimplemented.
//!
//! **Why this is not `two_process_child.zig`.** That module's `Process.start`
//! builds its command line with `two_process_launch.flags`, whose `Plan` is an
//! `ozai-node` plan — a fixed seed byte, `--peer`, `--relay-peer`, `--send`.
//! The peer takes a seed in hex, an expected peer node id in hex, a TLS mode and
//! a deadline, and none of those map onto that struct. Widening
//! `two_process_launch.Plan` is the parent's file and this change does not edit
//! it; the alternative would be a cast through a struct whose fields mean
//! something else in both directions.
//!
//! Two things are borrowed verbatim rather than retyped, because a peer that
//! published a second dialect of the same line would need a second parser:
//! `two_process_progress.progress_prefix` and `parseProgress`.
//!
//! Every allocation goes through a handle the caller handed in, which here is
//! `std.testing`'s own allocator: `AGENTS.md` §1 by name.

const std = @import("std");

const posix = std.posix;

const ozai = @import("ozai");

const progress_ns = @import("two_process_progress.zig");
const peer_options = @import("peer_test_options");

/// The peer binary this build emitted.
///
/// It arrives through the options module rather than a path written here, for
/// the reason `two_process_launch.zig:22-38` gives: a path written in a test
/// names whatever a plain `zig build` last left in `zig-out/bin`, which under
/// `cross-test` is a host binary for a different ABI. The emitted path and its
/// options dependency select and build that exact child.
pub const peer_executable = peer_options.peer_executable;

/// No peers, for a peer that is only going to be dialled.
const no_extras: []const []const u8 = &.{};

/// What the peer is started with.
///
/// **Everything it needs to be identifiable, reproducible and finite, and
/// nothing this file reads back.** The identities are hex rather than a
/// repeated seed byte because each side has to name the other's id before the
/// other is running: the Zig side knows its own from the seed it was given, and
/// reads the peer's from the peer's banner.
pub const Plan = struct {
    /// `--tls`: `rpk` for the deviation-free noq peer, `iroh` for the stock
    /// iroh endpoint. See `interop/iroh-peer/src/contract.rs`.
    tls: []const u8 = "rpk",
    /// `--seed-hex`: 64 hex characters, the peer's Ed25519 seed.
    seed_hex: []const u8,
    /// `--expect-peer`: 64 hex characters, the node id the peer must see.
    expect_peer_hex: []const u8,
    /// `--for`, in milliseconds. Bounds a runaway child; it is never what ends
    /// a correct run, which is why every wait in the test is on an observed
    /// counter instead.
    run_ms: i64,
    /// Flags appended as written, for a command line that is meant to be refused
    /// and has no field above.
    extra: []const []const u8 = no_extras,
};

/// The command line for one peer.
pub fn flags(arena: std.mem.Allocator, plan: Plan) ![]const []const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.append(arena, peer_executable);
    try argv.append(arena, "--tls");
    try argv.append(arena, plan.tls);
    try argv.append(arena, "--bind");
    try argv.append(arena, "127.0.0.1:0");
    try argv.append(arena, "--seed-hex");
    try argv.append(arena, plan.seed_hex);
    try argv.append(arena, "--expect-peer");
    try argv.append(arena, plan.expect_peer_hex);
    try argv.append(arena, "--for");
    try argv.append(arena, try std.fmt.allocPrint(arena, "{d}", .{plan.run_ms}));
    try argv.appendSlice(arena, plan.extra);
    return argv.toOwnedSlice(arena);
}

/// One `ozai-iroh-peer` child, and everything this test reads from it.
pub const Process = struct {
    child: std.process.Child,
    gpa: std.mem.Allocator,
    /// The name every message about this process carries.
    name: []const u8,
    /// What it wrote to stdout and to stderr, in the order it wrote it. Both are
    /// kept: a handshake refusal is said on stderr and on stdout, and a run that
    /// has failed has to be able to print it.
    out: std.ArrayList(u8) = .empty,
    err_out: std.ArrayList(u8) = .empty,
    /// Set when a pipe said end of file, which from out here is the only way to
    /// tell a running peer from an exited one that has not been reaped yet.
    out_done: bool = false,
    err_done: bool = false,
    /// Whether this file has taken the process back from the kernel. `wait`
    /// closes the pipes, so a reaped process must not be pumped again.
    reaped: bool = false,

    /// Start a peer with the flags this test needs and nothing else.
    ///
    /// `arena` owns the arguments: they outlive `spawn`, and an arena is the
    /// caller's, so a peer's command line dies with the test that wrote it.
    pub fn start(
        gpa: std.mem.Allocator,
        arena: std.mem.Allocator,
        io: std.Io,
        name: []const u8,
        plan: Plan,
    ) !*Process {
        const argv = try flags(arena, plan);
        const self = try gpa.create(Process);
        errdefer gpa.destroy(self);
        self.* = .{
            .child = std.process.spawn(io, .{
                .argv = argv,
                .stdin = .ignore,
                .stdout = .pipe,
                .stderr = .pipe,
            }) catch |err| {
                // Keep the emitted peer visible even when the spawn itself is
                // what failed: a FileNotFound with no command line is a
                // question about the wiring rather than about the peer.
                std.debug.print(
                    "rust_interop: could not start {s} ({t}). Command:\n  {s}\n",
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

    /// Stop the peer and wait for it.
    ///
    /// This is a `defer` on every test that starts one, and the reason is
    /// `two_process_child.zig:137-138`'s: a peer that outlives its test is a
    /// process the next run collides with. `Child.kill` sends `SIGTERM` and then
    /// waits, so this stops and reaps in one step.
    pub fn deinit(self: *Process, io: std.Io) void {
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

    /// Read both pipes once. Non-blocking: a child that has written nothing yet
    /// is a child that has not got there, not a failure.
    pub fn pump(self: *Process, io: std.Io) !void {
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
    pub fn value(self: *const Process, prefix: []const u8) ?[]const u8 {
        const found = self.line(prefix) orelse return null;
        return std.mem.trim(u8, found[prefix.len..], " ");
    }

    /// Every line beginning with `prefix`, in the order the peer wrote them.
    ///
    /// The peer's `offer` lines are a list rather than one line, and a reader
    /// that kept only the first would compare one ALPN and call it the contract.
    pub fn lines(self: *const Process, prefix: []const u8, arena: std.mem.Allocator) ![][]const u8 {
        var found: std.ArrayList([]const u8) = .empty;
        var rest = self.out.items;
        while (std.mem.findScalar(u8, rest, '\n')) |end| {
            const written = rest[0..end];
            if (std.mem.startsWith(u8, written, prefix)) {
                try found.append(arena, std.mem.trim(u8, written[prefix.len..], " "));
            }
            rest = rest[end + 1 ..];
        }
        return found.toOwnedSlice(arena);
    }

    /// The newest complete `progress:` line this peer has written.
    ///
    /// **The newest, never the oldest**, which is the one thing about these lines
    /// that is easy to get backwards: a peer that has been running for a while has
    /// written many, and only the last is the state that matters.
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
    pub fn progress(self: *const Process) ?progress_ns.Progress {
        return progress_ns.parseProgress(self.progressLine() orelse return null);
    }

    /// Whether this peer has said everything it was going to say.
    pub fn finished(self: *const Process) bool {
        return self.out_done and self.err_done;
    }

    /// Whether this peer exited with a failure.
    ///
    /// A peer that reached its goal exits 0 and one that could not exits 1, and
    /// this file reaps with `Child.wait` so the status is here. The `run` case
    /// returns whether the status was `exited`, which is what a peer asked to
    /// stop reports too.
    pub fn reportFailure(self: *Process, io: std.Io) !bool {
        if (!self.reaped) {
            const term = self.child.wait(io) catch |err| {
                std.debug.panic("could not reap {s}: {t}", .{ self.name, err });
            };
            self.reaped = true;
            switch (term) {
                .exited => |code| return code != 0,
                .signal => return true,
                else => return false,
            }
        }
        return false;
    }

    /// Ask this peer to stop, the way a supervisor does.
    pub fn stop(self: *Process) !void {
        const id = self.child.id orelse
            return self.gaveUp("was signalled after it had already been reaped", .{});
        try posix.kill(id, .TERM);
    }

    /// Fail the run, having said what this peer did say.
    ///
    /// Both pipes are printed because the question is usually about a gate that
    /// never arrived, and the answer to that is in whatever the peer wrote.
    pub fn gaveUp(self: *Process, comptime format: []const u8, args: anytype) noreturn {
        std.debug.print("rust_interop: the peer {s}: ", .{self.name});
        std.debug.print(format, args);
        std.debug.print("\n", .{});
        std.debug.print("  its stdout:\n{s}\n", .{self.out.items});
        std.debug.print("  its stderr:\n{s}\n", .{self.err_out.items});
        if (self.progressLine()) |snapshot| {
            std.debug.print("  its last progress line said:\n  {s}\n", .{snapshot});
        }
        std.debug.panic("rust_interop: see the peer's output above", .{});
    }
};

/// How long a parent wait for one observed state may take, in milliseconds.
///
/// A watchdog, not a success condition: it bounds a run that is never going to
/// converge. Nothing in this test waits for a duration on its own.
pub const budget_ms: i64 = 20_000;

/// One node id as 64 lower-case hex characters, the spelling the peer's
/// `--expect-peer` takes.
pub fn hexId(node_id: ozai.NodeId) [64]u8 {
    var out: [64]u8 = undefined;
    const digits = "0123456789abcdef";
    const bytes = node_id.toBytes();
    for (bytes, 0..) |byte, index| {
        out[index * 2] = digits[byte >> 4];
        out[index * 2 + 1] = digits[byte & 0x0f];
    }
    return out;
}
