//! One `ozai-iroh-peer` child, and everything this test reads from it.
//!
//! `Process` is the shape `test/two_process_child.zig` gives an `ozai-node`
//! child: two pipes and a `poll`, a banner, live `progress:` snapshots and a
//! final report, all arriving on the child's own stdout and each read as it
//! completes. Rust and Node publish the same exact 12-field `progress:` schema,
//! parsed solely by `test/two_process_progress.zig`.
//!
//! **Why this is not `two_process_child.zig`.** That module's `Process.start`
//! builds its command line with `two_process_launch.flags`, whose `Plan` is an
//! `ozai-node` plan — a fixed seed byte, peer routes and application roles.
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
const signal_safety = @import("child_signal_safety.zig");
const cleanup = @import("child_cleanup.zig");

/// The prebuilt peer binary supplied by `-Diroh-peer`.
///
/// The optional interop step runs this explicit executable without making the
/// ordinary test graph depend on Cargo or a Rust installation.
pub const peer_executable = peer_options.peer_executable;

/// What the peer is started with.
///
/// **Everything it needs to be identifiable, reproducible and finite, and
/// nothing this file reads back.** The identities are hex rather than a
/// repeated seed byte because each side has to name the other's id before the
/// other is running: the Zig side knows its own from the seed it was given, and
/// reads the peer's from the peer's banner.
pub const Plan = struct {
    /// `--tls`: `rpk` for the strict direct noq peer, `iroh` for stock iroh.
    /// Both configurations negotiate raw public keys.
    tls: []const u8 = "rpk",
    /// Actual application handler, never an ALPN-labelled transport echo.
    protocol: []const u8 = "transport",
    /// Omit to infer the transport role from `connect_address`.
    role: ?[]const u8 = null,
    /// Explicit gossip topic membership, passed as repeated `--topic-hex`.
    topics_hex: []const []const u8 = &.{},
    /// Actual gossip payload for the dedicated protocol driver.
    message: ?[]const u8 = null,
    /// `--seed-hex`: 64 hex characters, the peer's Ed25519 seed.
    seed_hex: []const u8,
    /// `--expect-peer`: the node id this peer must compare with the raw key.
    expect_peer_hex: []const u8,
    /// Optional address of a Zig endpoint; set to make Rust initiate the QUIC
    /// connection rather than wait as a server.
    connect_address: ?ozai.SocketAddr = null,
    /// `--for`, in milliseconds, bounds the child without ending a successful
    /// exchange.
    run_ms: i64,
};

/// The command line for one peer.
pub fn flags(arena: std.mem.Allocator, plan: Plan) ![]const []const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.append(arena, peer_executable);
    try argv.append(arena, "--tls");
    try argv.append(arena, plan.tls);
    try argv.append(arena, "--protocol");
    try argv.append(arena, plan.protocol);
    if (plan.role) |role| {
        try argv.append(arena, "--role");
        try argv.append(arena, role);
    }
    for (plan.topics_hex) |topic| {
        try argv.append(arena, "--topic-hex");
        try argv.append(arena, topic);
    }
    if (plan.message) |message| {
        try argv.append(arena, "--message");
        try argv.append(arena, message);
    }
    try argv.append(arena, "--bind");
    try argv.append(arena, "127.0.0.1:0");
    try argv.append(arena, "--seed-hex");
    try argv.append(arena, plan.seed_hex);
    try argv.append(arena, "--expect-peer");
    try argv.append(arena, plan.expect_peer_hex);
    try argv.append(arena, "--for");
    try argv.append(arena, try std.fmt.allocPrint(arena, "{d}", .{plan.run_ms}));
    if (plan.connect_address) |address| {
        try argv.append(arena, "--connect");
        try argv.append(arena, try std.fmt.allocPrint(arena, "{f}", .{address}));
    }
    return argv.toOwnedSlice(arena);
}

/// One `ozai-iroh-peer` child, and everything this test reads from it.
pub const Process = struct {
    child: std.process.Child,
    guard: signal_safety.Guard = .{},
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
    failed_start: bool = false,
    run_ms: i64 = 0,
    probe: @import("child_exit_probe.zig").Probe = .{},

    pub const StartError = std.process.SpawnError || @import("nat_proc_safety.zig").Error;
    pub const StartResult = union(enum) {
        ready: *Process,
        failed: struct { cause: StartError, process: *Process },
    };

    pub const PumpError = posix.PollError || std.Io.File.Reader.Error ||
        std.mem.Allocator.Error;
    pub const WaitError = std.process.Child.WaitError;

    /// Start a peer with the flags this test needs and nothing else.
    ///
    /// `arena` owns the arguments: they outlive `spawn`, and an arena is the
    /// caller's, so a peer's command line dies with the test that wrote it.
    pub fn start(
        gpa: std.mem.Allocator,
        io: std.Io,
        options: signal_safety.StartOptions,
    ) std.mem.Allocator.Error!StartResult {
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
            std.debug.print("rust_interop: could not start {s} ({t}). Command:\n", .{
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

    /// Read both pipes once. Non-blocking: a child that has written nothing yet
    /// is a child that has not got there, not a failure.
    pub fn pump(self: *Process, io: std.Io) PumpError!void {
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

    /// The dynamically bound peer address, once its complete banner arrives.
    pub fn address(self: *const Process) !?ozai.SocketAddr {
        const text = self.value("listening") orelse self.value("bound") orelse return null;
        const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse
            return error.InvalidPeerAddress;
        var host_text = text[0..colon];
        if (host_text.len >= 2 and host_text[0] == '[' and
            host_text[host_text.len - 1] == ']')
        {
            host_text = host_text[1 .. host_text.len - 1];
        }
        const host = ozai.IpAddress.parse(host_text) orelse
            return error.InvalidPeerAddress;
        const port = try std.fmt.parseInt(u16, text[colon + 1 ..], 10);
        return .{ .ip = host, .port = port };
    }

    /// Every line beginning with `prefix`, in the order the peer wrote them.
    ///
    /// The peer's `offer` lines are a list rather than one line, and a reader
    /// that kept only the first would compare one ALPN and call it the contract.
    pub fn lines(self: *const Process, arena: std.mem.Allocator, prefix: []const u8) ![][]const u8 {
        var found: std.ArrayList([]const u8) = .empty;
        errdefer found.deinit(arena);
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
            const term = try self.waitForExit(io);
            switch (term) {
                .exited => |code| return code != 0,
                .signal => return true,
                else => return false,
            }
        }
        return false;
    }

    /// Ask this peer to stop, the way a supervisor does.
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
    // zbc does not prove the 32-iteration loop writes both digits to all 64 slots.
    // zbc-disable-next-line: use-undefined
    return out;
}

test "gossip child flags preserve explicit topics and actual role" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const argv = try flags(arena.allocator(), .{
        .tls = "iroh",
        .protocol = "gossip",
        .role = "server",
        .topics_hex = &.{ "topic-a", "topic-b" },
        .message = "actual gossip",
        .seed_hex = "seed",
        .expect_peer_hex = "pin",
        .run_ms = 15000,
    });
    const expected = [_][]const u8{
        peer_executable, "--tls",     "iroh",          "--protocol", "gossip",
        "--role",        "server",    "--topic-hex",   "topic-a",    "--topic-hex",
        "topic-b",       "--message", "actual gossip", "--bind",     "127.0.0.1:0",
        "--seed-hex",    "seed",      "--expect-peer", "pin",        "--for",
        "15000",
    };
    try std.testing.expectEqual(expected.len, argv.len);
    for (expected, argv) |want, actual| {
        try std.testing.expectEqualStrings(want, actual);
    }
}

test "peer address waits for a complete banner and parses its dynamic port" {
    var peer: Process = .{
        .child = undefined,
        .gpa = std.testing.allocator,
        .name = "banner-test",
    };
    defer peer.out.deinit(std.testing.allocator);
    try peer.out.appendSlice(std.testing.allocator, "listening  127.0.0.1:42731");
    try std.testing.expect((try peer.address()) == null);
    try peer.out.append(std.testing.allocator, '\n');
    const parsed = (try peer.address()) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u16, 42731), parsed.port);
    const loopback = ozai.IpAddress.parse("127.0.0.1") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualDeep(loopback, parsed.ip);
    peer.out.clearRetainingCapacity();
    try peer.out.appendSlice(std.testing.allocator, "bound  [::1]:42732\n");
    const ipv6 = (try peer.address()) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u16, 42732), ipv6.port);
    const loopback_ipv6 = ozai.IpAddress.parse("::1") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualDeep(loopback_ipv6, ipv6.ip);
}

test "transport child selects the real transport handler and client route" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const loopback = ozai.IpAddress.parse("127.0.0.1") orelse return error.TestUnexpectedResult;
    const argv = try flags(arena.allocator(), .{
        .tls = "iroh",
        .seed_hex = "seed",
        .expect_peer_hex = "pin",
        .connect_address = .{
            .ip = loopback,
            .port = 42731,
        },
        .run_ms = 15000,
    });
    const expected = [_][]const u8{
        peer_executable, "--tls",       "iroh",       "--protocol", "transport",
        "--bind",        "127.0.0.1:0", "--seed-hex", "seed",       "--expect-peer",
        "pin",           "--for",       "15000",      "--connect",  "127.0.0.1:42731",
    };
    try std.testing.expectEqual(expected.len, argv.len);
    for (expected, argv) |want, actual| {
        try std.testing.expectEqualStrings(want, actual);
    }
}

test "Rust constructor proc capture failure retains exact owner through deadline" {
    try @import("child_constructor_safety.zig").captureFailureRetention(Process);
}

test "Rust constructor capture failure and wait failure retain exact owner" {
    try @import("child_constructor_safety.zig").captureFailureWaitError(Process);
}

test "Rust constructor preparation failure owns storage without spawning" {
    try @import("child_constructor_safety.zig").preparationFailureOwnership(Process);
}
