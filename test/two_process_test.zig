//! Two `ozai-node` processes, meeting on a real socket for the first time.
//!
//! Every test in this repository that puts two endpoints on a wire puts them in
//! one process: `test/loopback_test.zig` runs two, `test/protocol_loopback_test.zig`
//! runs four, and `src/node/node.zig` drives a whole connection from two `Node`s
//! in one allocator with one clock. That is worth a great deal, and it hides
//! one class of failure completely — one process means one allocator, one
//! cancellation scope and one lifetime, so every path that only bites when two
//! things die independently is never reached.
//!
//! `zig build run-ozai-node` starts one node. This file starts several, and it
//! is the first thing in the tree that can watch one of them die.
//!
//! # The report is the only status surface
//!
//! `ozai-node` prints a banner when it has bound a socket and a counter report
//! when it has finished, and it prints nothing in between. There is no live
//! surface: no port to poll, no file, nothing a supervisor can ask. So every
//! assertion here is read out of a report a node printed on its way out, and
//! every wait in this file is a wait for one of those two lines to arrive.
//!
//! That has a consequence worth writing down, because it shapes everything
//! below. A report appears when a node *exits*, so a test cannot read one node's
//! report and then signal it: the signal would arrive after the node was gone.
//! Every test here that signals anything therefore gates the signal on a third
//! process — the gate — whose only job is to publish the fact the signal
//! depends on and then get out of the way. The gate is a node of its own with a
//! short `--for`, and the node the test is going to signal is the one dialling
//! it, so the gate's report says that this run dialled a peer and finished a
//! handshake with it, and the signal lands on a node that is connected.
//!
//! Signalling a node that had not finished connecting is not a slow test, it is
//! a wrong one: measured on this machine, the two nodes then report one pass
//! each, no datagrams received and no connection, and every claim below would be
//! made about a handshake that never happened.
//!
//! # Nothing here waits for a length of time
//!
//! Every wait polls a pipe for a line with a deadline behind it, and a deadline
//! that passes prints everything every node said before it gives up. A test that
//! spawns processes races the machine, and a fixed sleep is that race written
//! down. The durations that do appear are `--for`, and they belong to the nodes:
//! they are how a node is given a deadline of its own, and they are what the
//! waits here poll for.
//!
//! # Why there is a control
//!
//! `connections finished` is how a node says a connection ended. If a node's own
//! shutdown retired its connections, that counter would read 1 for every node
//! that ever ran, would say nothing at all about a peer going away, and two of
//! the four tests below would pass on a stack that never notices anything. The
//! second test is the control that rules that out: two connected nodes signalled
//! in the same instant, so neither can have seen the other go, and the counter
//! is 0 on the side whose only peer stopped with it.
//!
//! # Every child is reaped
//!
//! Each process's `deinit` is a `defer` in the test that started it, and it
//! stops the process and waits for it. A node left running by a failed test is a
//! node the next run collides with, which makes the run after a failure worse
//! than the failure.
//!
//! # Time
//!
//! Roughly thirty seconds of wall clock, nearly all of it spent letting nodes
//! reach their own `--for`. The clock is read here and nowhere in `src/`: a node
//! takes its instant as data, and a test that spawns a process is outside
//! `ozai.base`.

const std = @import("std");
const ozai = @import("ozai");

const t = std.testing;

const posix = std.posix;
const base32 = ozai.base32;
const SecretKey = ozai.SecretKey;

/// Every allocation in this file goes through a handle the caller handed in,
/// which here is `std.testing`'s own allocator: `AGENTS.md` §1 by name.
const Allocator = std.mem.Allocator;

/// Where `b.installArtifact` puts the node, relative to the build root this
/// run step is pinned to.
///
/// Spelled rather than passed, because the generated and the custom test runner
/// both refuse an argument they do not recognise, and a path invented here would
/// have to be rewritten by hand every time the prefix moves.
const node_exe = "zig-out/bin/ozai-node";

/// Where every node binds. Port zero, so the kernel chooses it: two nodes on
/// one machine both listen, and nothing here collides with the run before it.
const loopback = "127.0.0.1:0";

/// `--for` for a node that only has to be here long enough to be looked at and
/// then get out of the way.
///
/// It has to outlast a handshake, which is a poll interval per flight and
/// `Node.poll_interval_ms` is a quarter of a second, and it is what lets the
/// signal a test sends next land on a node that has finished connecting.
const gate_ms: i64 = 4_000;

/// `--for` for the node that outlives its peer. It is started alongside the
/// gate, so it is already up when the signal goes out, and it has to still be
/// up once the core has given the connection up — which is a loss-detection
/// timer measured in poll intervals rather than a round trip.
const survivor_ms: i64 = 9_000;

/// `--for` for a node that nothing here is going to wait on. Past every budget
/// in this file by an order of magnitude, so that the only thing which can end
/// such a node is the signal the test sends it.
const forever_ms: i64 = 300_000;

/// How long any one wait may take before it is a finding.
///
/// Generous, because what is being waited for is a whole process and a build
/// running this beside five other artifacts can be slow. A deadline that fires
/// on a busy machine teaches nothing, and every one of them names its question.
const budget_ms: i64 = 30_000;

/// How long a single `poll` blocks, so a line one of the nodes writes is noticed
/// while the roster is being read rather than at the end of the wait.
const poll_slice_ms: i32 = 100;

/// How many nodes one test runs at once: the gate, and the two that are talking
/// to each other.
const max_processes = 3;

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
const Plan = struct {
    /// The byte every byte of the ed25519 seed is made of.
    tag: u8,
    /// `--for`, in milliseconds.
    run_ms: i64,
    /// `--seed`.
    seed: u64,
    /// Peers to dial, as `nodeid@ip:port`.
    peers: []const []const u8 = no_peers,
};

/// One `ozai-node` child, and everything this file reads from it.
///
/// Two pipes and a `poll`. The report is the only status surface the program
/// has and it is written at exit, so the wait for it is a wait for bytes.
const Process = struct {
    child: std.process.Child,
    gpa: Allocator,
    /// The name every message about this process carries.
    name: []const u8,
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
    fn start(
        io: std.Io,
        gpa: Allocator,
        arena: Allocator,
        name: []const u8,
        plan: Plan,
    ) !*Process {
        const self = try gpa.create(Process);
        errdefer gpa.destroy(self);
        self.* = .{
            .child = std.process.spawn(io, .{
                .argv = try flags(arena, plan),
                .stdin = .ignore,
                .stdout = .pipe,
                .stderr = .pipe,
            }) catch |err| {
                std.debug.print(
                    "two_process: could not start {s} ({t}). `zig build` makes it:\n" ++
                        "  {s} --listen {s} --for {d}\n",
                    .{ name, err, node_exe, loopback, plan.run_ms },
                );
                return err;
            },
            .gpa = gpa,
            .name = name,
        };
        return self;
    }

    fn deinit(self: *Process, io: std.Io) void {
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
                _ = self.child.wait(io) catch {};
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

    fn pump(self: *Process, io: std.Io) !void {
        if (self.reaped) return;
        if (!self.out_done) try self.take(io, self.child.stdout.?, &self.out, &self.out_done);
        if (!self.err_done) try self.take(io, self.child.stderr.?, &self.err_out, &self.err_done);
    }

    /// The first line of what this process wrote that begins with `prefix`.
    ///
    /// A line without its newline yet is not a line. The report is read as it
    /// arrives, and half a counter is half a counter.
    fn line(self: *const Process, prefix: []const u8) ?[]const u8 {
        var rest = self.out.items;
        while (std.mem.indexOfScalar(u8, rest, '\n')) |end| {
            const found = rest[0..end];
            if (std.mem.startsWith(u8, found, prefix)) return found;
            rest = rest[end + 1 ..];
        }
        return null;
    }

    /// What a line said after its label, with the spaces between them gone.
    fn value(self: *const Process, prefix: []const u8) ?[]const u8 {
        const found = self.line(prefix) orelse return null;
        return std.mem.trim(u8, found[prefix.len..], " ");
    }

    /// The address this node printed it bound, port included.
    fn bound(self: *const Process) ?[]const u8 {
        return self.value("listening");
    }

    /// Whether this node has said everything it was going to say, which from
    /// out here is the only way to tell a running node from an exited one that
    /// has not been reaped yet.
    fn finished(self: *const Process) bool {
        return self.out_done and self.err_done;
    }

    /// A node has said where it is listening: it can be dialled.
    fn saidWhereItListens(self: *const Process) bool {
        return self.line("listening") != null;
    }

    /// Ask this node to stop, the way a supervisor does and the way
    /// `ozai-node` installs a handler for.
    fn stop(self: *Process) !void {
        try posix.kill(self.child.id.?, .TERM);
    }

    /// Print everything this node said, which is what a failure here is read
    /// against.
    fn dump(self: *const Process) void {
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
    fn gaveUp(
        self: *const Process,
        comptime format: []const u8,
        args: anytype,
    ) error{CheckFailed} {
        std.debug.print("two_process: {s}: " ++ format ++ "\n", .{self.name} ++ args);
        self.dump();
        return error.CheckFailed;
    }
};

/// The processes one test is watching, so that one wait watches all of them.
///
/// A wait that watched one pipe and let another's fill would be a wait that can
/// wedge the run it is watching, and every node here writes its own banner and
/// its own report on its own pipe.
const Roster = struct {
    items: std.ArrayList(*Process) = .empty,

    fn deinit(self: *Roster, gpa: Allocator) void {
        self.items.deinit(gpa);
    }

    fn add(self: *Roster, gpa: Allocator, process: *Process) !void {
        try self.items.append(gpa, process);
    }

    fn pump(self: *Roster, io: std.Io) !void {
        for (self.items.items) |process| try process.pump(io);
    }

    /// Block until one of the pipes has something on it, or `timeout_ms` has
    /// passed without any of them having.
    fn wait(self: *Roster, timeout_ms: i32) !void {
        var fds: [max_processes * 2]posix.pollfd = undefined;
        var open: usize = 0;
        for (self.items.items) |process| {
            if (process.reaped) continue;
            for ([_]?std.Io.File{ process.child.stdout, process.child.stderr }) |pipe| {
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
    fn await(
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
            const left = deadline - nowMs(io);
            if (left <= 0) return false;
            try self.wait(@intCast(@min(left, poll_slice_ms)));
        }
    }

    /// Wait for a node to finish and take it back from the kernel.
    ///
    /// Null when it did not finish in time, which is a finding rather than a
    /// shape of test to pass: the caller says what it wanted.
    fn reap(
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
};

// ---------------------------------------------------------------------------
// Reading a report
// ---------------------------------------------------------------------------

/// One counter to check in a node's report: the line it is on, the word that
/// introduces it, and what it has to be.
///
/// The label rather than the position, because a report is prose and prose
/// moves: a counter that changed sentence on its own line is still read, and one
/// whose label no longer introduces a number fails and says so. On the shutdown
/// line the label is the phase's own comma, because that is what comes before
/// the handler count.
const Count = struct {
    line: []const u8,
    label: []const u8,
    want: u64,
    /// Set when `want` is the least that will do rather than the whole answer.
    at_least: bool = false,
};

/// One word to check in a node's report: the line, what introduces it, and the
/// word itself. The shutdown phase and the socket are words, not counts.
const Text = struct {
    line: []const u8,
    label: []const u8,
    want: []const u8,
};

/// The number a label introduces on a line.
fn numberAfter(line_text: []const u8, label: []const u8) ?u64 {
    var from: usize = 0;
    while (std.mem.indexOfPos(u8, line_text, from, label)) |at| {
        from = at + label.len;
        var digits = from;
        while (digits < line_text.len and line_text[digits] == ' ') digits += 1;
        var end = digits;
        while (end < line_text.len and std.ascii.isDigit(line_text[end])) end += 1;
        if (end == digits) continue;
        return std.fmt.parseInt(u64, line_text[digits..end], 10) catch null;
    }
    return null;
}

/// The word a label introduces: from after the label to the end of the line or
/// to its next comma, whichever comes first.
fn textAfter(line_text: []const u8, label: []const u8) ?[]const u8 {
    const at = std.mem.indexOf(u8, line_text, label) orelse return null;
    const rest = line_text[at + label.len ..];
    const comma = std.mem.indexOf(u8, rest, ", ") orelse rest.len;
    return std.mem.trim(u8, rest[0..comma], " ");
}

/// Check the counters a run is about, having printed the node's whole output
/// if one of them does not hold: a counter that did not hold is half an answer.
fn expectCounts(process: *const Process, counts: []const Count) !void {
    for (counts) |count| {
        const line_text = process.line(count.line) orelse
            return process.gaveUp("its report has no line starting '{s}'", .{count.line});
        const got = numberAfter(line_text, count.label) orelse return process.gaveUp(
            "the '{s}' line says no number after '{s}'",
            .{ count.line, count.label },
        );
        const held = if (count.at_least) got >= count.want else got == count.want;
        if (!held) {
            return process.gaveUp(
                "reported {s} = {d} on '{s}', and the run needed {s}{d}",
                .{
                    count.label,
                    got,
                    count.line,
                    if (count.at_least) "at least " else "",
                    count.want,
                },
            );
        }
    }
}

fn expectTexts(process: *const Process, texts: []const Text) !void {
    for (texts) |text| {
        const line_text = process.line(text.line) orelse
            return process.gaveUp("its report has no line starting '{s}'", .{text.line});
        const got = textAfter(line_text, text.label) orelse return process.gaveUp(
            "the '{s}' line says nothing after '{s}'",
            .{ text.line, text.label },
        );
        if (!std.mem.eql(u8, got, text.want)) {
            return process.gaveUp(
                "reported {s} as '{s}' on '{s}', and the run needed '{s}'",
                .{ text.label, got, text.line, text.want },
            );
        }
    }
}

/// A node stopped the way it is supposed to: it exited, and it exited zero.
fn expectExit(process: *const Process, term: ?std.process.Child.Term) !void {
    const ended = term orelse
        return process.gaveUp("was still running when this file ran out of patience", .{});
    const status = switch (ended) {
        .exited => |code| code,
        else => return process.gaveUp("was {s} rather than an exit", .{@tagName(ended)}),
    };
    if (status != 0) return process.gaveUp("exited with {d}", .{status});
}

/// Every node ends the same way, and every node here ends the same way: the
/// handler shut down, the phase reached `closed`, and the socket is gone.
fn expectWoundDown(process: *const Process, term: ?std.process.Child.Term) !void {
    try expectExit(process, term);
    try expectTexts(process, &.{
        .{ .line = "shutdown:", .label = "shutdown: ", .want = "closed" },
        .{ .line = "shutdown:", .label = "cancelled, socket ", .want = "closed" },
    });
    try expectCounts(process, &.{
        .{ .line = "shutdown:", .label = "closed, ", .want = 1 },
    });
}

/// The gate's whole claim: a handshake completed between two processes, counted
/// by the process that accepted the arrival, and the gate then shut itself down
/// in order.
fn expectGate(gate: *const Process, term: ?std.process.Child.Term) !void {
    try expectWoundDown(gate, term);
    try expectCounts(gate, &.{
        .{ .line = "stopped:", .label = "passes, ", .want = 1, .at_least = true },
        .{ .line = "stopped:", .label = "datagrams in, ", .want = 1, .at_least = true },
        // One arrival offered to the filter, one task spawned, one handler
        // accept. The last of those is after the handshake and nowhere before
        // it, which is what makes it the proof.
        .{ .line = "accept loop:", .label = "accept loop: ", .want = 1 },
        .{ .line = "accept loop:", .label = "attempts, ", .want = 1 },
        .{ .line = "accept loop:", .label = "spawned, ", .want = 1 },
        .{ .line = "dials:", .label = "dials: ", .want = 0 },
        .{ .line = "dials:", .label = " of ", .want = 0 },
    });
}

// ---------------------------------------------------------------------------
// Starting nodes
// ---------------------------------------------------------------------------

/// The command line for one node.
///
/// Everything the node needs to be identifiable, reproducible and finite, and
/// nothing else: it prints its own name and address, and this file reads them
/// back rather than predicting them.
fn flags(arena: Allocator, plan: Plan) ![]const []const u8 {
    var seed_bytes: [SecretKey.seed_length]u8 = @splat(plan.tag);
    const key_seed = base32.encode(base32.z32, SecretKey.seed_length, &seed_bytes);
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.append(arena, node_exe);
    try argv.append(arena, "--listen");
    try argv.append(arena, loopback);
    try argv.append(arena, "--key-seed");
    try argv.append(arena, try std.fmt.allocPrint(arena, "{s}", .{&key_seed}));
    try argv.append(arena, "--seed");
    try argv.append(arena, try std.fmt.allocPrint(arena, "{d}", .{plan.seed}));
    try argv.append(arena, "--for");
    try argv.append(arena, try std.fmt.allocPrint(arena, "{d}", .{plan.run_ms}));
    for (plan.peers) |target| {
        try argv.append(arena, "--peer");
        try argv.append(arena, target);
    }
    return argv.toOwnedSlice(arena);
}

/// Start a node and put it on the roster, so that one wait in the test watches
/// every node the test started.
fn startNode(
    roster: *Roster,
    io: std.Io,
    gpa: Allocator,
    arena: Allocator,
    name: []const u8,
    plan: Plan,
) !*Process {
    const process = try Process.start(io, gpa, arena, name, plan);
    errdefer process.deinit(io);
    try roster.add(gpa, process);
    return process;
}

/// The two things a peer needs about a node that has bound: who it is, and
/// where it is. A node that printed one without the other has said nothing
/// useful, and this is where that is caught.
fn named(process: *const Process) !struct { id: []const u8, address: []const u8 } {
    const id = process.value("z-base-32") orelse
        return process.gaveUp("printed a banner with no node id in it", .{});
    const address = process.bound() orelse
        return process.gaveUp("printed a banner with no address in it", .{});
    return .{ .id = id, .address = address };
}

/// The `--peer` value naming one node: its z-base-32 id and the address it
/// bound, in the spelling `ozai-node` parses.
fn peer(arena: Allocator, listener: *const Process) ![]const u8 {
    const side = try named(listener);
    return std.fmt.allocPrint(arena, "{s}@{s}", .{ side.id, side.address });
}

/// The `--peer` values naming two nodes.
fn peers(
    arena: Allocator,
    one: *const Process,
    two: *const Process,
) ![]const []const u8 {
    const list = try arena.alloc([]const u8, 2);
    list[0] = try peer(arena, one);
    list[1] = try peer(arena, two);
    return list;
}

/// The monotonic clock, in milliseconds.
///
/// Read here and nowhere in `src/`: a node takes its instant as data, and a
/// test that spawns a process is outside `ozai.base`.
fn nowMs(io: std.Io) i64 {
    return @intCast(@divTrunc(std.Io.Clock.awake.now(io).nanoseconds, std.time.ns_per_ms));
}

// ---------------------------------------------------------------------------
// Two processes, both of them reaching their own `--for`
// ---------------------------------------------------------------------------

test "two node processes meet on a socket and both wind down in order" {
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    var roster: Roster = .{};
    defer roster.deinit(t.allocator);

    const listener = try startNode(&roster, t.io, t.allocator, arena.allocator(), "listener", .{
        .tag = 0x51,
        .run_ms = gate_ms,
        .seed = 0x1111,
    });
    defer listener.deinit(t.io);
    if (!try roster.await(t.io, listener, &Process.saidWhereItListens, budget_ms)) {
        return listener.gaveUp("never said where it was listening", .{});
    }

    const one_peer = [_][]const u8{try peer(arena.allocator(), listener)};
    const dialer = try startNode(&roster, t.io, t.allocator, arena.allocator(), "dialer", .{
        .tag = 0xc1,
        .run_ms = gate_ms,
        .seed = 0x2222,
        .peers = &one_peer,
    });
    defer dialer.deinit(t.io);
    if (!try roster.await(t.io, dialer, &Process.saidWhereItListens, budget_ms)) {
        return dialer.gaveUp("never said where it was listening", .{});
    }

    // Two identities and two bound addresses, so this is two nodes and not one
    // node hearing its own certificate twice. Both ports are the kernel's,
    // which is why neither is written down and both differ.
    const listener_side = try named(listener);
    const dialer_side = try named(dialer);
    try t.expect(!std.mem.eql(u8, listener_side.id, dialer_side.id));
    try t.expect(!std.mem.eql(u8, listener_side.address, dialer_side.address));

    // Both end on their own `--for`, with no signal from here at all.
    const listener_term = try roster.reap(t.io, listener, budget_ms);
    const dialer_term = try roster.reap(t.io, dialer, budget_ms);
    try expectWoundDown(listener, listener_term);
    try expectWoundDown(dialer, dialer_term);

    // The listener's own account of the handshake: datagrams moved both ways,
    // the arrival was offered to the filter, the loop spawned a task for it and
    // the task ran the handler's accept. Nothing in that chain can happen
    // before the handshake and all of it has to happen for a connection.
    try expectCounts(listener, &.{
        .{ .line = "stopped:", .label = "stopped: ", .want = 1, .at_least = true },
        .{ .line = "stopped:", .label = "passes, ", .want = 1, .at_least = true },
        .{ .line = "stopped:", .label = "datagrams in, ", .want = 1, .at_least = true },
        .{ .line = "accept loop:", .label = "accept loop: ", .want = 1 },
        .{ .line = "accept loop:", .label = "attempts, ", .want = 1 },
        .{ .line = "accept loop:", .label = "spawned, ", .want = 1 },
        // It dialled nobody, and its one connection was still up when it closed:
        // there was nothing to cancel and nothing that had ended on its own.
        .{ .line = "dials:", .label = "dials: ", .want = 0 },
        .{ .line = "dials:", .label = " of ", .want = 0 },
        .{ .line = "shutdown:", .label = "handler shutdowns, ", .want = 0 },
    });

    // The dialling process's own account of the same handshake, from the other
    // side of it: one peer named, none refused, datagrams both ways — and no
    // accept, because a node that dialled is not an arrival. That is why the
    // listener's `spawned` is the only place the handshake is proved from.
    try expectCounts(dialer, &.{
        .{ .line = "stopped:", .label = "stopped: ", .want = 1, .at_least = true },
        .{ .line = "stopped:", .label = "passes, ", .want = 1, .at_least = true },
        .{ .line = "stopped:", .label = "datagrams in, ", .want = 1, .at_least = true },
        .{ .line = "accept loop:", .label = "accept loop: ", .want = 0 },
        .{ .line = "dials:", .label = "dials: ", .want = 1 },
        .{ .line = "dials:", .label = " of ", .want = 0 },
        .{ .line = "shutdown:", .label = "handler shutdowns, ", .want = 0 },
    });

    // The one place the two processes say the same thing about each other: the
    // peer the dialling process was given, in the spelling both of them print,
    // came back out of its own gossip layer having survived a process boundary.
    try t.expectEqualStrings(
        listener.value("node") orelse
            return listener.gaveUp("printed a banner with no node id in it", .{}),
        dialer.value("gossip named:") orelse
            return dialer.gaveUp("named no peer at all", .{}),
    );
}

// ---------------------------------------------------------------------------
// The control the other two read against
// ---------------------------------------------------------------------------

test "a node stopped in the same instant as its peer retires nothing" {
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    var roster: Roster = .{};
    defer roster.deinit(t.allocator);

    const gate = try startNode(&roster, t.io, t.allocator, arena.allocator(), "gate", .{
        .tag = 0x33,
        .run_ms = gate_ms,
        .seed = 0x3333,
    });
    defer gate.deinit(t.io);
    const listener = try startNode(&roster, t.io, t.allocator, arena.allocator(), "listener", .{
        .tag = 0x51,
        .run_ms = forever_ms,
        .seed = 0x1111,
    });
    defer listener.deinit(t.io);
    if (!try roster.await(t.io, listener, &Process.saidWhereItListens, budget_ms)) {
        return listener.gaveUp("never said where it was listening", .{});
    }
    if (!try roster.await(t.io, gate, &Process.saidWhereItListens, budget_ms)) {
        return gate.gaveUp("never said where it was listening", .{});
    }

    const both_peers = try peers(arena.allocator(), gate, listener);
    const dialer = try startNode(&roster, t.io, t.allocator, arena.allocator(), "dialer", .{
        .tag = 0xc1,
        .run_ms = forever_ms,
        .seed = 0x2222,
        .peers = both_peers,
    });
    defer dialer.deinit(t.io);
    if (!try roster.await(t.io, dialer, &Process.saidWhereItListens, budget_ms)) {
        return dialer.gaveUp("never said where it was listening", .{});
    }

    const gate_term = try roster.reap(t.io, gate, budget_ms);
    try expectGate(gate, gate_term);

    // The control. Two connected nodes, one signal apiece and nothing in
    // between, so neither can have seen the other go: whatever the listener
    // reports from here on is its own shutdown and nothing else. The listener's
    // count is the one that matters and not the dialer's, because the dialer's
    // other peer is the gate — which died moments ago, and whether the core had
    // given that connection up yet is a race this file has no business joining.
    try listener.stop();
    try dialer.stop();
    const listener_term = try roster.reap(t.io, listener, budget_ms);
    const dialer_term = try roster.reap(t.io, dialer, budget_ms);
    try expectWoundDown(listener, listener_term);
    try expectWoundDown(dialer, dialer_term);
    try expectCounts(listener, &.{
        .{ .line = "accept loop:", .label = "spawned, ", .want = 1 },
        .{ .line = "dials:", .label = " of ", .want = 0 },
        // The zero the next two tests turn on.
        .{ .line = "dials:", .label = "refused; ", .want = 0 },
    });
    try expectCounts(dialer, &.{
        .{ .line = "dials:", .label = "dials: ", .want = 2 },
        .{ .line = "dials:", .label = " of ", .want = 0 },
    });
}

// ---------------------------------------------------------------------------
// A SIGTERM to one, and the other noticing
// ---------------------------------------------------------------------------

test "a SIGTERM to the dialling process leaves the listening one running, and it notices" {
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    var roster: Roster = .{};
    defer roster.deinit(t.allocator);

    const gate = try startNode(&roster, t.io, t.allocator, arena.allocator(), "gate", .{
        .tag = 0x33,
        .run_ms = gate_ms,
        .seed = 0x3333,
    });
    defer gate.deinit(t.io);
    const listener = try startNode(&roster, t.io, t.allocator, arena.allocator(), "listener", .{
        .tag = 0x51,
        .run_ms = survivor_ms,
        .seed = 0x1111,
    });
    defer listener.deinit(t.io);
    if (!try roster.await(t.io, listener, &Process.saidWhereItListens, budget_ms)) {
        return listener.gaveUp("never said where it was listening", .{});
    }
    if (!try roster.await(t.io, gate, &Process.saidWhereItListens, budget_ms)) {
        return gate.gaveUp("never said where it was listening", .{});
    }

    const both_peers = try peers(arena.allocator(), gate, listener);
    const dialer = try startNode(&roster, t.io, t.allocator, arena.allocator(), "dialer", .{
        .tag = 0xc1,
        .run_ms = forever_ms,
        .seed = 0x2222,
        .peers = both_peers,
    });
    defer dialer.deinit(t.io);
    if (!try roster.await(t.io, dialer, &Process.saidWhereItListens, budget_ms)) {
        return dialer.gaveUp("never said where it was listening", .{});
    }

    // The gate first: its report is what makes the signal below land on a node
    // that has finished connecting rather than one that has just started.
    const gate_term = try roster.reap(t.io, gate, budget_ms);
    try expectGate(gate, gate_term);

    try dialer.stop();
    const dialer_term = try roster.reap(t.io, dialer, budget_ms);
    try expectWoundDown(dialer, dialer_term);
    try expectCounts(dialer, &.{
        .{ .line = "stopped:", .label = "passes, ", .want = 1, .at_least = true },
        .{ .line = "stopped:", .label = "datagrams in, ", .want = 1, .at_least = true },
        // Both peers it was given were dialled and neither refused it.
        .{ .line = "dials:", .label = "dials: ", .want = 2 },
        .{ .line = "dials:", .label = " of ", .want = 0 },
        // A node that dialled is not an arrival, and this is the half of the
        // handshake only the listener can be asked about.
        .{ .line = "accept loop:", .label = "accept loop: ", .want = 0 },
    });

    // The listener is up. Its pipe has not closed, so it has not exited: a
    // process that took its peer down with it would have nothing left to say.
    try roster.pump(t.io);
    if (listener.finished()) {
        return listener.gaveUp("stopped when the process that dialled it was signalled", .{});
    }

    // The survivor reaches its own `--for` and reports what happened while it
    // was on its own: one arrival accepted, and then that connection gone.
    const listener_term = try roster.reap(t.io, listener, budget_ms);
    try expectWoundDown(listener, listener_term);
    try expectCounts(listener, &.{
        .{ .line = "stopped:", .label = "passes, ", .want = 1, .at_least = true },
        .{ .line = "accept loop:", .label = "accept loop: ", .want = 1 },
        .{ .line = "accept loop:", .label = "attempts, ", .want = 1 },
        .{ .line = "accept loop:", .label = "spawned, ", .want = 1 },
        .{ .line = "dials:", .label = "dials: ", .want = 0 },
        .{ .line = "dials:", .label = " of ", .want = 0 },
        // The peer is out of its table. One peer dialled this node, so there was
        // one connection, and the counter the control above leaves at zero is
        // the one that moved — while this node was still running.
        .{ .line = "dials:", .label = "refused; ", .want = 1 },
    });
}

test "a SIGTERM to the listening process leaves the dialling one running, and it notices" {
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    var roster: Roster = .{};
    defer roster.deinit(t.allocator);

    const gate = try startNode(&roster, t.io, t.allocator, arena.allocator(), "gate", .{
        .tag = 0x33,
        .run_ms = gate_ms,
        .seed = 0x3333,
    });
    defer gate.deinit(t.io);
    const listener = try startNode(&roster, t.io, t.allocator, arena.allocator(), "listener", .{
        .tag = 0x51,
        .run_ms = forever_ms,
        .seed = 0x1111,
    });
    defer listener.deinit(t.io);
    if (!try roster.await(t.io, listener, &Process.saidWhereItListens, budget_ms)) {
        return listener.gaveUp("never said where it was listening", .{});
    }
    if (!try roster.await(t.io, gate, &Process.saidWhereItListens, budget_ms)) {
        return gate.gaveUp("never said where it was listening", .{});
    }

    const both_peers = try peers(arena.allocator(), gate, listener);
    const dialer = try startNode(&roster, t.io, t.allocator, arena.allocator(), "dialer", .{
        .tag = 0xc1,
        .run_ms = survivor_ms,
        .seed = 0x2222,
        .peers = both_peers,
    });
    defer dialer.deinit(t.io);
    if (!try roster.await(t.io, dialer, &Process.saidWhereItListens, budget_ms)) {
        return dialer.gaveUp("never said where it was listening", .{});
    }

    const gate_term = try roster.reap(t.io, gate, budget_ms);
    try expectGate(gate, gate_term);

    // The other direction: the node that answers is the one that is stopped,
    // and the node that dialled has to be the one that notices.
    try listener.stop();
    const listener_term = try roster.reap(t.io, listener, budget_ms);
    try expectWoundDown(listener, listener_term);
    try expectCounts(listener, &.{
        .{ .line = "accept loop:", .label = "accept loop: ", .want = 1 },
        .{ .line = "accept loop:", .label = "attempts, ", .want = 1 },
        .{ .line = "accept loop:", .label = "spawned, ", .want = 1 },
        .{ .line = "dials:", .label = "dials: ", .want = 0 },
        .{ .line = "dials:", .label = " of ", .want = 0 },
        // It was stopped, not abandoned: its own shutdown takes nothing with it
        // and its connection was still up when it closed.
        .{ .line = "dials:", .label = "refused; ", .want = 0 },
    });

    try roster.pump(t.io);
    if (dialer.finished()) {
        return dialer.gaveUp("stopped when the process that dialled it was stopped", .{});
    }

    const dialer_term = try roster.reap(t.io, dialer, budget_ms);
    try expectWoundDown(dialer, dialer_term);
    try expectCounts(dialer, &.{
        .{ .line = "stopped:", .label = "passes, ", .want = 1, .at_least = true },
        .{ .line = "stopped:", .label = "datagrams in, ", .want = 1, .at_least = true },
        .{ .line = "accept loop:", .label = "accept loop: ", .want = 0 },
        .{ .line = "dials:", .label = "dials: ", .want = 2 },
        .{ .line = "dials:", .label = " of ", .want = 0 },
        // Both of its peers are gone and both connections were given up, by a
        // process that was still running for the whole of it.
        .{ .line = "dials:", .label = "refused; ", .want = 2 },
    });
}
