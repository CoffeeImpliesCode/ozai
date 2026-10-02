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
//! # Live state and final reports
//!
//! Every child uses `--progress`. The node flushes a snapshot after each pass
//! that changes its counters. Tests read the latest complete snapshot before
//! they signal a child. The final report checks the same counters after shutdown.
//!
//! The third process in some tests supplies another connection. It no longer
//! proves readiness by reaching a fixed lifetime. Each connection under test
//! must reach its own observed handshake state before either peer is stopped.
//!
//! # Watchdogs are not success conditions
//!
//! Tests wait for a handshake, delivery, or peer departure, not for a chosen
//! duration. `--for` bounds a runaway child. Each parent wait also has a deadline.
//! A timeout names the missing counters and prints every child's stdout and stderr.
//! No finite deadline guarantees success under arbitrary scheduler starvation.
//!
//! # Why there is a control
//!
//! `connections finished` is how a node says a connection ended. If a node's own
//! shutdown retired its connections, that counter would read 1 for every node
//! that ever ran, would say nothing at all about a peer going away, and the two
//! SIGTERM tests below would pass on a stack that never notices anything. The
//! second test is the control that rules that out: two connected nodes signalled
//! one after the other, back to back, so neither is given a pass in which it
//! could see the other go. Nothing here makes that window atomic, and the claim
//! is the counter rather than the timing: it reads 0 on the side whose only
//! peer stopped with it.
//!
//! # Every child is reaped
//!
//! Each process's `deinit` is a `defer` in the test that started it, and it
//! stops the process and waits for it. A node left running by a failed test is a
//! node the next run collides with, which makes the run after a failure worse
//! than the failure.
//!
//! # A relay in a process of its own
//!
//! `ozai-node --relay` makes a process serve as a relay, and
//! `ozai-node --relay-peer <nodeid>@<url>` makes another one reach it by relay
//! URL, so the tests at the bottom of this file are the first place in the tree
//! where a relay is a process. `test/relay_wire_test.zig` drives the same relay
//! from three nodes inside one process; what a process boundary adds is the two
//! things a process is for — the client's handshake costs a pass per frame, and
//! either side can die without the other going with it.
//!
//! **The clients are given a URL and nothing else.** The `--relay-peer` value
//! below is built out of the address the relay printed, and nothing after that
//! reads the address again: the URL becomes a socket inside `ozai-node`, by
//! `RelayUrl.socketAddr`, which refuses a host that is a name outright. So the
//! step a peer takes to find a relay is taken by the program under test rather
//! than by the test watching it, and the one check here is that the URL still
//! names the relay this file started.
//!
//! # What a second process cannot see about a relay
//!
//! A relay's two queues are its own storage, and the ordering half of
//! invariant 9 — a control frame written *ahead* of the datagrams — is
//! therefore **not asserted here**: this file is outside the relay, reading a
//! pipe after the process has exited, and the depth and the order of a queue
//! belong to the process that owns it. `test/relay_wire_test.zig` is one
//! process closer, holds the relay itself, and still does not assert it, for
//! the reason its own module doc gives. What a second process *can* see is the
//! half that is observable from anywhere, and that is what these tests assert:
//! a datagram the relay forwarded came out at the client it was for, with its
//! bytes, and a relay whose queue had refused one would have forwarded fewer.
//!
//! The relay tests carry their own control, and it is the `relay held` line.
//! A report is written after the node's own shutdown, which gives every client
//! and every connection away, so a count read then cannot tell a peer that left
//! while this node was running from one that was still there. The count on that
//! line is read before the close and printed after it, which is why "0 node
//! ids registered, at the stop" is a finding about a survivor and not about a
//! relay that tidied up.
//!
//! # Time
//!
//! These tests use the host clock only to bound waits. The node receives time
//! as data. Completion depends on observed state, not on a sleep.

const std = @import("std");
const ozai = @import("ozai");

const t = std.testing;

const posix = std.posix;
const base32 = ozai.base32;
const SecretKey = ozai.SecretKey;

/// Every allocation in this file goes through a handle the caller handed in,
/// which here is `std.testing`'s own allocator: `AGENTS.md` §1 by name.
const Allocator = std.mem.Allocator;

/// The `ozai-node` this run starts: the exact executable the build that
/// compiled this test just emitted, at this run's own target and optimize mode
/// and, under coverage, its instrumented compile. It arrives through the
/// options module rather than being spelled here, because a path written in
/// this file names whatever a plain `zig build` last left in `zig-out/bin` —
/// which under `cross-test`, whose builds install under a `--prefix` of their
/// own, is a host binary for a different ABI and no coverage counters at all.
/// Ten scenarios asserting on process behaviour would then be asserting on a
/// program this build never made.
///
/// The cost is that this file is no longer compilable on its own: `zig test
/// test/two_process_test.zig` has no `node_test_options` module to import. That
/// was never a supported way to run it — the file needs `ozai`, `link_libc`
/// and the custom runner, so `zig build test` was always the way in — and the
/// alternative was a build that can silently run a stale binary, which is the
/// one failure this cannot have.
const node_test_options = @import("node_test_options");
const node_exe = node_test_options.node_executable;

/// Where every node binds. Port zero, so the kernel chooses it: two nodes on
/// one machine both listen, and nothing here collides with the run before it.
const loopback = "127.0.0.1:0";

/// Import the loop interval so watchdog arithmetic follows the node's cadence.
const pass_ms: i64 = @intCast(ozai.node.poll_interval_ms);

/// Allow twice the nominal poll interval for scheduler contention.
/// This allowance bounds a failed run. It does not prove that a state was reached.
const pass_slack: i64 = 2;

/// `passes` passes, as the wall clock that is `passes` of them.
fn windowMs(passes: i64) i64 {
    return passes * pass_ms * pass_slack;
}

/// Each observation and reap remains bounded to sixty seconds.
const wait_passes = 120;
const budget_ms: i64 = windowMs(wait_passes);

/// A child must remain alive while its parent observes and signals it.
/// Auto-expiry is a last-resort guard, not the event a lifecycle test awaits.
const watchdog_ms: i64 = 4 * budget_ms;

/// A short `--for`, for a child whose command line must never need one.
///
/// A refusal is the parse refusing and the program leaving, so this is not
/// what ends a correct run: it is here to bound a command line the program
/// *wrongly* accepted, so that such a run fails inside this file's time
/// rather than at the far end of `watchdog_ms`. What the refusal check reads
/// is the exit code and the line, and never how long anything took.
const short_watchdog_ms: i64 = windowMs(1);

/// How long a single `poll` blocks, so a line one of the nodes writes is noticed
/// while the roster is being read rather than at the end of the wait.
const poll_slice_ms: i32 = 100;

/// The largest roster: two peers and a third node supplying another connection.
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
    /// `--relay`: this node serves as a relay rather than answering peers.
    serve_relay: bool = false,
    /// `--relay-peer <nodeid>@<url>`: the relay to reach, in the spelling a
    /// peer is handed one. **A peer holds a URL and nothing else**, so this is
    /// a URL and never a socket this file kept to itself: the program under
    /// test is the one that turns it into an address.
    relay_peer: ?[]const u8 = null,
    /// `--send <nodeid>:<bytes>`: one datagram to put on the relay wire, once
    /// the relay connection is up. The gossip codec's job, asked for by hand.
    send: ?[]const u8 = null,
    /// Flags appended as written, for a command line that is meant to be
    /// refused and has no field above.
    extra: []const []const u8 = &.{},
};

/// One `ozai-node` child, and everything this file reads from it.
///
/// Two pipes and a `poll` carry the banner, live snapshots, and final report.
const Process = struct {
    child: std.process.Child,
    gpa: Allocator,
    /// The name every message about this process carries.
    name: []const u8,
    /// The roster this process was put on, so that a failure about one node
    /// can print every other node with it. The report a check reads is the
    /// answer to the question, and the question is usually about a *different*
    /// process than the one that failed to answer: the gate that never
    /// arrived, the peer that was signalled before it had connected.
    roster: ?*Roster = null,
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
        gpa: Allocator,
        arena: Allocator,
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

    fn pump(self: *Process, io: std.Io) !void {
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
    fn line(self: *const Process, prefix: []const u8) ?[]const u8 {
        var rest = self.out.items;
        while (std.mem.findScalar(u8, rest, '\n')) |end| {
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

    /// The newest complete `progress:` line this node has written.
    ///
    /// **The newest, never the oldest**, which is the one thing about these
    /// lines that is easy to get backwards: a node that has been running for a
    /// while has written many, and only the last is the state that matters. A
    /// line without its newline yet is not a line, for the reason `line` gives.
    fn progressLine(self: *const Process) ?[]const u8 {
        var rest = self.out.items;
        var newest: ?[]const u8 = null;
        while (std.mem.findScalar(u8, rest, '\n')) |end| {
            const found = rest[0..end];
            if (std.mem.startsWith(u8, found, progress_prefix)) newest = found;
            rest = rest[end + 1 ..];
        }
        return newest;
    }

    /// The newest complete `progress:` line, read as the counts it gives.
    fn progress(self: *const Process) ?Progress {
        return parseProgress(self.progressLine() orelse return null);
    }

    /// Ask this node to stop, the way a supervisor does and the way
    /// `ozai-node` installs a handler for.
    ///
    /// `Child.id` is null once `wait` or `kill` has taken the process back, and
    /// every caller signals a child that is still on the roster, so a null here
    /// is this file signalling something it has already reaped. That is named
    /// rather than unwrapped: it fails the run with the reason on it instead of
    /// aborting the runner with a trap in `stop`.
    fn stop(self: *Process) !void {
        const id = self.child.id orelse
            return self.gaveUp("was signalled after it had already been reaped", .{});
        try posix.kill(id, .TERM);
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
    ///
    /// The whole roster is printed, not just this process: the counter that
    /// did not hold is the symptom, and the cause is nearly always in a
    /// sibling's output — a gate that reports no handshake, a peer that was
    /// signalled before it had connected. One process's dump has been the
    /// wrong half of this diagnostic for the whole life of the file.
    fn gaveUp(
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

/// The processes one test is watching, so that one wait watches all of them.
///
/// A wait that watched one pipe and let another's fill would be a wait that can
/// wedge the run it is watching, and every node here writes its own banner and
/// its own report on its own pipe.
const Roster = struct {
    items: std.ArrayList(*Process) = .empty,

    fn deinit(self: *Roster, gpa: Allocator) void {
        self.items.deinit(gpa);
        // An `ArrayList` whose backing store is gone is not a list any more, so
        // the field is put back to empty rather than left holding a freed
        // pointer and a length that reads it. Nothing is lost: the roster owns
        // no process — each one is a `defer` of its own, running before this,
        // because they were deferred after it — and `items` is its only field.
        self.items = .empty;
    }

    fn add(self: *Roster, gpa: Allocator, process: *Process) !void {
        process.roster = self;
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
    fn awaitWant(
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
    fn gaveUp(
        self: *const Roster,
        comptime format: []const u8,
        process: *const Process,
        want: ?Want,
        args: anytype,
    ) error{CheckFailed} {
        std.debug.print("two_process: {s}: " ++ format ++ "\n", .{process.name} ++ args);
        if (want) |asked| reportUnmet(process, asked);
        self.dumpAll();
        return error.CheckFailed;
    }
};

// ---------------------------------------------------------------------------
// Reading a progress line, and waiting on one
// ---------------------------------------------------------------------------

/// What every `progress:` line begins with.
const progress_prefix = "progress: ";

/// Named counters in the CLI snapshot. An array permits runtime iteration.
const progress_fields = [_][]const u8{
    "dials",     "refused",     "accepted",   "finished",     "up",
    "admitted",  "established", "registered", "sent",         "received",
    "forwarded", "attempts",    "spawned",    "disconnected", "closed",
};

/// One `progress:` line, read whole.
const Progress = struct {
    counts: [progress_fields.len]u64 = @splat(0),

    /// The number this line gave for `field`.
    fn count(self: Progress, field: []const u8) u64 {
        for (progress_fields, self.counts) |name, value| {
            if (std.mem.eql(u8, name, field)) return value;
        }
        // A field this file names that the program does not publish is a bug in
        // this file, and a gate that quietly matched nothing would turn it into
        // a timeout instead.
        std.debug.panic("no progress field named '{s}'", .{field});
    }
};

/// A whole `progress:` line, or null when it is not one this file can read.
///
/// Strict on purpose: the field names are matched against `progress_fields` in
/// order and a number that does not parse is a refusal, so a program that
/// changes its line produces a named failure here rather than a gate that
/// quietly never holds.
fn parseProgress(line_text: []const u8) ?Progress {
    var result: Progress = .{};
    var rest = line_text[progress_prefix.len..];
    for (progress_fields, 0..) |name, at| {
        const piece, const rest_after = splitOnce(rest) orelse return null;
        if (!std.mem.startsWith(u8, piece, name)) return null;
        const digits = std.mem.trim(u8, piece[name.len..], " ");
        if (digits.len == 0) return null;
        result.counts[at] = std.fmt.parseInt(u64, digits, 10) catch return null;
        rest = rest_after;
    }
    return if (std.mem.trim(u8, rest, " ").len == 0) result else null;
}

/// One comma-separated piece and everything after it.
fn splitOnce(text: []const u8) ?struct { []const u8, []const u8 } {
    const comma = std.mem.indexOf(u8, text, ", ") orelse
        return .{ text, text[text.len..] };
    return .{ text[0..comma], text[comma + 2 ..] };
}

/// One number this file needs a node to have reported, and the sense of it.
const Need = struct {
    field: []const u8,
    want: u64,
    /// Set when the number has to have come *down* to `want` rather than up.
    at_most: bool = false,

    fn holds(self: Need, seen: Progress) bool {
        const got = seen.count(self.field);
        return if (self.at_most) got <= self.want else got >= self.want;
    }

    fn say(self: Need) void {
        std.debug.print(
            "  {s} {s} {d}\n",
            .{ self.field, if (self.at_most) "at most" else "at least", self.want },
        );
    }
};

/// A state this file waits for: every `Need` in `all` holds, and — when `any`
/// is given — at least one of its groups holds as well.
///
/// The `any` half exists for one honest reason. A counter that has to come
/// *down*, `up` reaching zero, is also true before anything happened, so it
/// witnesses nothing on its own; a monotonic counter has to stand beside it,
/// and which monotonic counter moves first is a property of the core rather
/// than of this file. Asking for either is the truthful form of "it noticed",
/// where naming one of them would be a bet.
const Want = struct {
    all: []const Need = &.{},
    any: []const []const Need = &.{},
};

/// Name the counters that were being waited for and what the node last said.
fn reportUnmet(process: *const Process, want: Want) void {
    std.debug.print("  it was waiting for:\n", .{});
    for (want.all) |need| need.say();
    for (want.any) |group| {
        std.debug.print("  and at least one of:\n", .{});
        for (group) |need| need.say();
    }
    if (process.progressLine()) |line_text| {
        std.debug.print("  its last progress line said:\n  {s}\n", .{line_text});
    } else {
        std.debug.print("  and it had written no progress line at all\n", .{});
    }
}

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
    while (std.mem.findPos(u8, line_text, from, label)) |at| {
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

/// A relay's whole claim, for the clients it was given: it admitted each of
/// them once, each arrival was offered to the filter and given a handler, and
/// every departure was reported exactly once.
///
/// The three zeros are the half that matters. A departure that is reported
/// twice is a registry that let go of a connection twice, and one that is
/// swallowed is a connection the registry has let go of while the relay still
/// believes it has one: `disconnects` alone cannot tell those apart, so the
/// arms that would absorb a report are asserted at zero rather than left to
/// the sum — for the same reason and in the same words `relay_wire_test.zig`
/// gives, one process closer.
fn expectRelayServed(
    relay: *const Process,
    term: ?std.process.Child.Term,
    clients: u64,
) !void {
    try expectWoundDown(relay, term);
    try expectCounts(relay, &.{
        .{ .line = "relay in:", .label = "admitted ", .want = clients },
        .{ .line = "relay in:", .label = "replaced ", .want = 0 },
        .{ .line = "relay in:", .label = "promoted ", .want = 0 },
        .{ .line = "relay in:", .label = "refused ", .want = 0 },
        // One arrival per client offered to the filter, one task spawned for
        // it, one handler connection. All of that is after the QUIC handshake
        // and before the relay's challenge, and none of it can happen for a
        // client that did not arrive.
        .{ .line = "accept loop:", .label = "accept loop: ", .want = clients },
        .{ .line = "accept loop:", .label = "attempts, ", .want = clients },
        .{ .line = "relay away:", .label = "disconnects ", .want = clients },
        .{ .line = "relay away:", .label = "already gone ", .want = 0 },
        .{ .line = "relay away:", .label = "told displaced ", .want = 0 },
    });
}

/// A relay client's whole claim against the relay it was handed: it dialled
/// once, the relay did not refuse it, and the handshake came back.
///
/// The accept counters are at zero and are part of the claim: a client that
/// reaches a relay is an arrival *to it* and accepts nothing on this socket,
/// so a nonzero count here would be a node that dialled and answered.
///
/// `peer gone` is **not** in here: it says a datagram found nobody at the
/// relay, which is a fact about what this client was asked to send rather than
/// about whether it reached the relay. The tests that send nothing assert it at
/// zero themselves, and the test that sends something expects it to be
/// whatever the relay answered.
fn expectClientReached(client: *const Process, term: ?std.process.Child.Term) !void {
    try expectWoundDown(client, term);
    try expectCounts(client, &.{
        .{ .line = "relay in:", .label = "dialled ", .want = 1 },
        .{ .line = "relay in:", .label = "refused ", .want = 0 },
        .{ .line = "relay in:", .label = "auth sent ", .want = 1 },
        .{ .line = "relay in:", .label = "established ", .want = 1 },
        .{ .line = "relay in:", .label = "displaced ", .want = 0 },
        .{ .line = "accept loop:", .label = "accept loop: ", .want = 0 },
        .{ .line = "dials:", .label = "dials: ", .want = 0 },
    });
}

/// One datagram came out of the relay and arrived here, from the peer named,
/// with the bytes it was sent.
///
/// The count is the relay's arithmetic and this is the payload, so a relay
/// that forwarded the right number of datagrams to the wrong client, or the
/// right one with the wrong bytes, prints something else here. The sender is
/// what says the datagram crossed *through* the relay: it is the other
/// process's node id, and the relay was the only path between the two sockets.
fn expectHanded(
    process: *const Process,
    from: *const Process,
    payload: []const u8,
) !void {
    try expectCounts(process, &.{
        .{ .line = "relay out:", .label = "handed to this node ", .want = 1 },
        .{ .line = "relay inbox:", .label = "datagrams ", .want = 1 },
        .{ .line = "relay inbox[0]:", .label = "bytes ", .want = @intCast(payload.len) },
    });
    const line_text = process.line("relay inbox[0]:") orelse
        return process.gaveUp("printed no line saying what its relay handed it", .{});
    const from_word = " from ";
    const at = std.mem.indexOf(u8, line_text, from_word) orelse
        return process.gaveUp("the datagram it was handed says nothing about its sender", .{});
    const rest = line_text[at + from_word.len ..];
    const space = std.mem.findScalar(u8, rest, ' ') orelse
        return process.gaveUp("the datagram it was handed has no bytes after its sender", .{});
    const sender = from.value("node") orelse
        return from.gaveUp("printed a banner with no node id in it", .{});
    if (!std.mem.eql(u8, rest[0..space], sender)) return process.gaveUp(
        "was handed a datagram from {s}, and the peer that sent one is {s}",
        .{ rest[0..space], sender },
    );
    // The bytes, hexed the way the report prints them and into a room big
    // enough for the most a report will ever show of one. These payloads are
    // shorter than the program's cut, so what it printed is all of them.
    var room: [128]u8 = undefined;
    var out = std.Io.Writer.fixed(&room);
    try out.print("{x}", .{payload});
    if (!std.mem.eql(u8, out.buffered(), rest[space + 1 ..])) return process.gaveUp(
        "was handed {s}, and the bytes that were sent are {s}",
        .{ rest[space + 1 ..], out.buffered() },
    );
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
    if (node_test_options.node_executor) |executor| try argv.append(arena, executor);
    try argv.append(arena, node_exe);
    try argv.append(arena, "--listen");
    try argv.append(arena, loopback);
    try argv.append(arena, "--key-seed");
    try argv.append(arena, try std.fmt.allocPrint(arena, "{s}", .{&key_seed}));
    try argv.append(arena, "--seed");
    try argv.append(arena, try std.fmt.allocPrint(arena, "{d}", .{plan.seed}));
    try argv.append(arena, "--for");
    try argv.append(arena, try std.fmt.allocPrint(arena, "{d}", .{plan.run_ms}));
    // Every node publishes its state, so no wait in this file has to guess how
    // long something took. A node that refuses its command line never reaches
    // a pass and so never writes one, which is why the refusal test is
    // unaffected by this being unconditional.
    try argv.append(arena, "--progress");
    for (plan.peers) |target| {
        try argv.append(arena, "--peer");
        try argv.append(arena, target);
    }
    if (plan.serve_relay) try argv.append(arena, "--relay");
    if (plan.relay_peer) |target| {
        try argv.append(arena, "--relay-peer");
        try argv.append(arena, target);
    }
    if (plan.send) |datagram| {
        try argv.append(arena, "--send");
        try argv.append(arena, datagram);
    }
    try argv.appendSlice(arena, plan.extra);

    return argv.toOwnedSlice(arena);
}

/// Start a node and put it on the roster, so that one wait in the test watches
/// every node the test started.
fn startNode(
    roster: *Roster,
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    name: []const u8,
    plan: Plan,
) !*Process {
    const process = try Process.start(gpa, arena, io, name, plan);
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

/// The `--relay-peer` value naming one relay: its node id and the URL that names
/// it, in the spelling a peer is handed one and `ozai-node` parses.
///
/// **The URL is the whole of what a peer holds**, and this is where it is
/// built: out of the address the relay printed, once. Nothing after this reads
/// that address again — the clients below are given this string, and the
/// program under test is what turns it into a socket.
///
/// The check in the middle is the step being taken at all, and it is the only
/// thing this file asserts about the resolution: `RelayUrl.socketAddr` is
/// literal-only and answers `error.NotAnIpLiteral` for a name, so a URL that
/// came out naming somewhere else would name a relay this file did not start.
fn relayPeer(arena: Allocator, relay: *const Process) ![]const u8 {
    const side = try named(relay);
    const url = try std.fmt.allocPrint(arena, "http://{s}/", .{side.address});
    const parsed = ozai.RelayUrl.parse(url) catch |err| return relay.gaveUp(
        "is bound at {s}, which is not a relay URL host: {t}",
        .{ side.address, err },
    );
    const route = parsed.socketAddr() catch |err| return relay.gaveUp(
        "is bound at {s}, which no relay URL can name: {t}",
        .{ side.address, err },
    );
    var text: [80]u8 = undefined;
    var out = std.Io.Writer.fixed(&text);
    try route.format(&out);
    if (!std.mem.eql(u8, out.buffered(), side.address)) return relay.gaveUp(
        "is bound at {s} and its own relay URL resolves to {s}",
        .{ side.address, out.buffered() },
    );
    return std.fmt.allocPrint(arena, "{s}@{s}", .{ side.id, url });
}

/// The z-base-32 node id a plan with this `tag` will present.
///
/// A plan's identity is a byte repeated into a seed (`flags`), so the id is
/// known before the process is started, and that is what lets two clients name
/// each other on their command lines: `--send` names its peer as text, and a
/// report appears only at exit. Every test that uses this compares it against
/// what the node printed, so a change to how a plan's identity is built fails
/// loudly here rather than quietly sending a datagram to a stranger.
fn nodeIdOf(arena: Allocator, tag: u8) ![]const u8 {
    var key = try SecretKey.fromSeed(@splat(tag));
    defer key.deinit();
    return arena.dupe(u8, &key.nodeId().toZ32());
}

/// The `--send` value: one datagram for the node a plan with `tag` presents.
fn sendValue(arena: Allocator, tag: u8, payload: []const u8) ![]const u8 {
    return std.fmt.allocPrint(arena, "{s}:{s}", .{ try nodeIdOf(arena, tag), payload });
}

/// A refused command line: exit 1, the refusal on one line, and no trace.
///
/// The two markers are the whole of what an error return looks like from out
/// here — `error:` and the `file:line` frames under it — and stderr is empty
/// because a program's own refusal is its interface rather than a failure of
/// the program. So this is also the test that adding a flag did not change
/// what a bad command line does.
fn expectRefused(
    process: *const Process,
    term: ?std.process.Child.Term,
    refusal: []const u8,
) !void {
    const ended = term orelse
        return process.gaveUp("was still running when this file ran out of patience", .{});
    const status = switch (ended) {
        .exited => |code| code,
        else => return process.gaveUp("was {s} rather than an exit", .{@tagName(ended)}),
    };
    if (status != 1) return process.gaveUp("exited with {d}, and a refusal is 1", .{status});
    if (process.err_out.items.len != 0) return process.gaveUp(
        "wrote to stderr, and a refusal is not a failure of the program:\n{s}",
        .{process.err_out.items},
    );
    for ([_][]const u8{ "error:", "??" }) |marker| {
        if (std.mem.indexOf(u8, process.out.items, marker) != null) return process.gaveUp(
            "printed '{s}', which is what an error return looks like from out here",
            .{marker},
        );
    }
    const line_text = process.line("ozai-node: ") orelse
        return process.gaveUp("printed no line refusing anything", .{});
    if (std.mem.indexOf(u8, line_text, refusal) == null) return process.gaveUp(
        "refused with '{s}', and the run needed a line naming '{s}'",
        .{ line_text, refusal },
    );
}

/// The monotonic clock, in milliseconds.
///
/// Read here and nowhere in `src/`: a node takes its instant as data, and a
/// test that spawns a process is outside `ozai.base`.
fn nowMs(io: std.Io) i64 {
    return @intCast(@divTrunc(std.Io.Clock.awake.now(io).nanoseconds, std.time.ns_per_ms));
}

/// The states this file waits for, named once.
///
/// Named rather than written longhand at each call site, because most of the
/// tests below want one of the same five, and a gate spelled out twice is a
/// gate that can come to mean two different things in two tests that both
/// believe they are waiting for the same thing.
///
/// Each is a conjunction of everything that has to be true together, never the
/// first of them: a dialer's `dials` counter moves before its connection is
/// established, and gating on it alone would signal a node that had not
/// finished connecting — which is the mistake this file's module doc opens by
/// refusing to make.
/// An arrival reached this node and was handled: offered to the filter, a task
/// spawned for it, and the handler's accept run.
const arrived: Want = .{ .all = &.{
    .{ .field = "attempts", .want = 1 },
    .{ .field = "spawned", .want = 1 },
    .{ .field = "accepted", .want = 1 },
} };

/// This node dialled, the dial was not refused, and the connection came up.
const dialled: Want = .{ .all = &.{
    .{ .field = "dials", .want = 1 },
    .{ .field = "refused", .want = 0, .at_most = true },
    .{ .field = "up", .want = 1 },
} };

/// This node is a client of a relay and the relay's answer came back.
const relay_linked: Want = .{ .all = &.{
    .{ .field = "established", .want = 1 },
    .{ .field = "up", .want = 1 },
} };

/// The core gave one connection up. The same counter the survivor tests assert
/// as `refused; 1`, so the gate and the assertion read one witness rather than
/// a gate waiting for something and an assertion checking something else.
const one_gave_up: Want = .{ .all = &.{.{ .field = "finished", .want = 1 }} };

/// And two of them.
const two_gave_up: Want = .{ .all = &.{.{ .field = "finished", .want = 2 }} };

/// A serving relay has taken `count` clients in.
fn admitted(comptime count: u64) Want {
    return .{ .all = &.{.{ .field = "admitted", .want = count }} };
}

/// No connection is established any more, and something monotonic says so.
///
/// The `any` half is not belt and braces. `up` at zero is also true of a node
/// that never had a connection, so on its own it witnesses nothing, and a gate
/// on it alone would fire on the first progress line of a client whose relay
/// has not even been dialled yet. Which monotonic counter moves first is a
/// property of the core — `closed` is the client half and `disconnected` the
/// server half — so this asks for either rather than betting on one.
fn noneUp(comptime field: []const u8, comptime witness: u64) Want {
    return .{
        .all = &.{.{ .field = "up", .want = 0, .at_most = true }},
        .any = &.{
            &.{.{ .field = field, .want = witness }},
            &.{.{ .field = "finished", .want = witness }},
        },
    };
}

// ---------------------------------------------------------------------------
// Two processes, and the test stopping both of them
// ---------------------------------------------------------------------------

test "two node processes meet on a socket and both wind down in order" {
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    var roster: Roster = .{};
    defer roster.deinit(t.allocator);

    const listener = try startNode(&roster, t.allocator, arena.allocator(), t.io, "listener", .{
        .tag = 0x51,
        .run_ms = watchdog_ms,
        .seed = 0x1111,
    });
    defer listener.deinit(t.io);
    if (!try roster.await(t.io, listener, &Process.saidWhereItListens, budget_ms)) {
        return listener.gaveUp("never said where it was listening", .{});
    }

    const one_peer = [_][]const u8{try peer(arena.allocator(), listener)};
    const dialer = try startNode(&roster, t.allocator, arena.allocator(), t.io, "dialer", .{
        .tag = 0xc1,
        .run_ms = watchdog_ms,
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

    // Both are stopped here, and only here, and only once the state each of
    // them has reached is the state this test is about. Nothing above waits for
    // a handshake: the listener says an arrival was handled, the dialling
    // process says its dial came up, and both are read off a line the node
    // wrote after a pass of its own.
    try roster.awaitWant(t.io, listener, "an arrival it had handled", arrived, budget_ms);
    try roster.awaitWant(t.io, dialer, "a dialled connection that was up", dialled, budget_ms);
    // Back to back, with nothing in between them, and that is all this test
    // claims about the timing: two `kill` calls are not one instant and nothing
    // here keeps either node from running another pass between them, so the
    // window is narrow rather than shut. What the signals are not allowed to
    // have between them is a pass, which is why they are not staggered — that
    // is the shape the control test below builds on purpose, and a pass in
    // between would make this the two SIGTERM tests instead.
    try dialer.stop();
    try listener.stop();
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
        // It dialled nobody, and its own close cancelled no accept: the count
        // that follows `handler shutdowns, ` is `accepts cancelled`, so this
        // says how each process shut itself down and nothing about the other.
        // What either made of the other's departure is not read here — the
        // counter for that is `connections finished` on the `dials:` line,
        // and the control test below is where it is read at 0.
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

test "two connected nodes stopped back to back wind down" {
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    var roster: Roster = .{};
    defer roster.deinit(t.allocator);

    const gate = try startNode(&roster, t.allocator, arena.allocator(), t.io, "gate", .{
        .tag = 0x33,
        .run_ms = watchdog_ms,
        .seed = 0x3333,
    });
    defer gate.deinit(t.io);
    const listener = try startNode(&roster, t.allocator, arena.allocator(), t.io, "listener", .{
        .tag = 0x51,
        .run_ms = watchdog_ms,
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
    const dialer = try startNode(&roster, t.allocator, arena.allocator(), t.io, "dialer", .{
        .tag = 0xc1,
        .run_ms = watchdog_ms,
        .seed = 0x2222,
        .peers = both_peers,
    });
    defer dialer.deinit(t.io);
    if (!try roster.await(t.io, dialer, &Process.saidWhereItListens, budget_ms)) {
        return dialer.gaveUp("never said where it was listening", .{});
    }

    // The gate is stopped once it says it handled the arrival, and the listener
    // once it says the same about its own. The second of those is new: this
    // test used to send both signals the moment the gate's `--for` expired,
    // which proved the *gate* had connected and said nothing about whether the
    // listener had. Both arrivals are now observed, so the two signals below
    // land on nodes that have finished connecting.
    try roster.awaitWant(t.io, gate, "an arrival it had handled", arrived, budget_ms);
    try roster.awaitWant(t.io, listener, "an arrival it had handled", arrived, budget_ms);
    try gate.stop();
    const gate_term = try roster.reap(t.io, gate, budget_ms);
    try expectGate(gate, gate_term);

    // The control. Two connected nodes, one signal apiece and nothing in
    // between, which narrows the window rather than closing it: whatever the
    // listener reports from here on is its own shutdown and nothing else, and
    // the count read below is what says so, not the order of the two signals.
    // The listener's count is the one that matters and not the dialer's,
    // because the dialer's other peer is the gate — which died moments ago,
    // and whether the core had given that connection up yet is a race this
    // file has no business joining.
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

    const gate = try startNode(&roster, t.allocator, arena.allocator(), t.io, "gate", .{
        .tag = 0x33,
        .run_ms = watchdog_ms,
        .seed = 0x3333,
    });
    defer gate.deinit(t.io);
    const listener = try startNode(&roster, t.allocator, arena.allocator(), t.io, "listener", .{
        .tag = 0x51,
        .run_ms = watchdog_ms,
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
    const dialer = try startNode(&roster, t.allocator, arena.allocator(), t.io, "dialer", .{
        .tag = 0xc1,
        .run_ms = watchdog_ms,
        .seed = 0x2222,
        .peers = both_peers,
    });
    defer dialer.deinit(t.io);
    if (!try roster.await(t.io, dialer, &Process.saidWhereItListens, budget_ms)) {
        return dialer.gaveUp("never said where it was listening", .{});
    }

    // Both arrivals are observed before anything is signalled: the gate's, so
    // the signal below lands on a node that has finished connecting rather
    // than one that has just started, and the listener's, so the survivor is
    // stopped only once it holds a connection this test can then watch end.
    try roster.awaitWant(t.io, gate, "an arrival it had handled", arrived, budget_ms);
    try roster.awaitWant(t.io, listener, "an arrival it had handled", arrived, budget_ms);
    try gate.stop();
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

    // **The survivor is stopped on its notice, not on a timer.** This is the
    // whole of the change: the counter below is read at a moment this file
    // chose because the node said the connection was gone, where it used to be
    // read at whatever moment a `--for` this file had picked happened to
    // expire. The gate and the expected value are the same ones as before —
    // `one_gave_up` is `finished`, which is what `refused; 1` reports — so the
    // claim is unchanged and only the moment it is read at has stopped being a
    // guess.
    try roster.awaitWant(t.io, listener, "a connection it had given up", one_gave_up, budget_ms);
    try listener.stop();
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

    const gate = try startNode(&roster, t.allocator, arena.allocator(), t.io, "gate", .{
        .tag = 0x33,
        .run_ms = watchdog_ms,
        .seed = 0x3333,
    });
    defer gate.deinit(t.io);
    const listener = try startNode(&roster, t.allocator, arena.allocator(), t.io, "listener", .{
        .tag = 0x51,
        .run_ms = watchdog_ms,
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
    const dialer = try startNode(&roster, t.allocator, arena.allocator(), t.io, "dialer", .{
        .tag = 0xc1,
        .run_ms = watchdog_ms,
        .seed = 0x2222,
        .peers = both_peers,
    });
    defer dialer.deinit(t.io);
    if (!try roster.await(t.io, dialer, &Process.saidWhereItListens, budget_ms)) {
        return dialer.gaveUp("never said where it was listening", .{});
    }

    // The same two observed arrivals as the test above, and for the same
    // reasons: one says the node about to be signalled has finished
    // connecting, and the other says the node that has to notice holds the
    // connection this test then watches end.
    try roster.awaitWant(t.io, gate, "an arrival it had handled", arrived, budget_ms);
    try roster.awaitWant(t.io, listener, "an arrival it had handled", arrived, budget_ms);
    try gate.stop();
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

    // **The survivor is stopped on its notice, not on a timer**, exactly as in
    // the test above. `two_gave_up` is `finished` at two, which is what the
    // `refused; 2` below reports — this node dialled two peers and both are
    // gone, so the gate's departure and the listener's are both counted, and
    // the gate that read one of them has already been reaped above.
    try roster.awaitWant(t.io, dialer, "both connections it had given up", two_gave_up, budget_ms);
    try dialer.stop();
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

// ---------------------------------------------------------------------------
// What a shutdown said, and what it bought
// ---------------------------------------------------------------------------

// A close is one CONNECTION_CLOSE per connection, written once, and nothing
// waits for it: RFC 9000 gives a close no acknowledgement and the core
// retransmits one only when a packet arrives. So the report says what was
// written, and a peer that was **still running** is what says whether the one
// datagram landed.
//
// The counts on the closing side are read as *at least* rather than exactly,
// because one of them is what the core held at the stop and the handshake's
// own timing decides that. The zeros beside them are exact, and they are the
// half of the line that cannot move.
//
// A number is read by the words **before** it, as everywhere else in this
// file: the report counts number-then-noun, so `connections owed, ` introduces
// the datagram count and `close datagrams written, ` introduces the count of
// acknowledgements.
test "a closing node counts what its close told, and a peer left running shows it landed" {
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    var roster: Roster = .{};
    defer roster.deinit(t.allocator);

    // Both nodes run on the watchdog and are stopped by this file. The one
    // that closes first is stopped once its own connection is up, so the close
    // it writes below really is a close over a live connection and not a node
    // that had nothing to tell anyone.
    const listener = try startNode(&roster, t.allocator, arena.allocator(), t.io, "listener", .{
        .tag = 0x51,
        .run_ms = watchdog_ms,
        .seed = 0x1111,
    });
    defer listener.deinit(t.io);
    if (!try roster.await(t.io, listener, &Process.saidWhereItListens, budget_ms)) {
        return listener.gaveUp("never said where it was listening", .{});
    }

    const one_peer = [_][]const u8{try peer(arena.allocator(), listener)};
    const dialer = try startNode(&roster, t.allocator, arena.allocator(), t.io, "dialer", .{
        .tag = 0xc1,
        .run_ms = watchdog_ms,
        .seed = 0x2222,
        .peers = &one_peer,
    });
    defer dialer.deinit(t.io);

    // The one that closes first, on a signal from here, so the close it writes
    // is the only notice the other half of this test is ever going to get. The
    // gate is the connection being up: `connections owed, 1` below is a claim
    // about a connection that existed, and it is the gate rather than a
    // `--for` that now establishes that.
    try roster.awaitWant(t.io, listener, "an arrival it had handled", arrived, budget_ms);
    try roster.awaitWant(t.io, dialer, "a dialled connection that was up", dialled, budget_ms);
    try dialer.stop();
    const dialer_term = try roster.reap(t.io, dialer, budget_ms);
    try expectWoundDown(dialer, dialer_term);
    try expectCounts(dialer, &.{
        // It dialled once and the handshake came back, so there was a
        // connection to tell and this is not a node that closed over nothing.
        .{ .line = "dials:", .label = "dials: ", .want = 1 },
        .{ .line = "dials:", .label = " of ", .want = 0 },
        .{ .line = "accept loop:", .label = "accept loop: ", .want = 0 },
        .{ .line = "close:", .label = "close: ", .want = 1, .at_least = true },
        .{ .line = "close:", .label = "connections owed, ", .want = 1, .at_least = true },
        .{ .line = "close:", .label = "close datagrams written, ", .want = 0 },
    });

    // The survivor, which is the proof that the datagram above was worth
    // something. It is stopped once it says it gave the connection up, and
    // there was then nothing left for its close to say — which is the other
    // half of the line and not a missing one.
    //
    // This is where the old `survivor_ms - gate_ms` margin went: the test used
    // to hope five seconds was long enough for the core to retire a
    // connection, and read the counter at the end of it. It now reads the
    // counter at the pass where the core says it retired one, which is the
    // same claim with the guess taken out.
    try roster.awaitWant(t.io, listener, "a connection it had given up", one_gave_up, budget_ms);
    try listener.stop();
    const listener_term = try roster.reap(t.io, listener, budget_ms);
    try expectWoundDown(listener, listener_term);
    try expectCounts(listener, &.{
        .{ .line = "accept loop:", .label = "accept loop: ", .want = 1 },
        .{ .line = "dials:", .label = " of ", .want = 0 },
        .{ .line = "dials:", .label = "refused; ", .want = 1 },
        .{ .line = "close:", .label = "close: ", .want = 0 },
        .{ .line = "close:", .label = "connections owed, ", .want = 0 },
        .{ .line = "close:", .label = "close datagrams written, ", .want = 0 },
    });
}

test "a node that never reached a peer reports a close with nothing in it" {
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    var roster: Roster = .{};
    defer roster.deinit(t.allocator);

    // Nobody to reach and nobody signalled until it has said where it
    // listens, so the shutdown below is the first thing this node has ever
    // done to a connection. The watchdog is long enough that the signal is the
    // only thing in the run that can end it.
    const alone = try startNode(&roster, t.allocator, arena.allocator(), t.io, "alone", .{
        .tag = 0x33,
        .run_ms = watchdog_ms,
        .seed = 0x3333,
    });
    defer alone.deinit(t.io);
    if (!try roster.await(t.io, alone, &Process.saidWhereItListens, budget_ms)) {
        return alone.gaveUp("never said where it was listening", .{});
    }
    try alone.stop();

    const alone_term = try roster.reap(t.io, alone, budget_ms);
    try expectWoundDown(alone, alone_term);
    // Why this is a second test and not the first one's expectation loosened:
    // the line is a count rather than a constant, so a node that owed nothing
    // has to say so in the same place a node that owed one close does.
    try expectCounts(alone, &.{
        .{ .line = "dials:", .label = "dials: ", .want = 0 },
        .{ .line = "close:", .label = "close: ", .want = 0 },
        .{ .line = "close:", .label = "connections owed, ", .want = 0 },
        .{ .line = "close:", .label = "close datagrams written, ", .want = 0 },
    });
}

// ---------------------------------------------------------------------------
// A relay in a process of its own
// ---------------------------------------------------------------------------

/// What one client is asked to put on the wire for the other: seventeen bytes
/// naming the direction, so a payload that arrived swapped, duplicated or
/// truncated is a difference in the hex rather than a count that happens to
/// match.
const to_second = "first-to-second!!";
const to_first = "second-to-first!!";

test "a relay in a process of its own, reached by URL, and a datagram crosses both ways" {
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    var roster: Roster = .{};
    defer roster.deinit(t.allocator);

    const relay = try startNode(&roster, t.allocator, arena.allocator(), t.io, "relay", .{
        .tag = 0x5e,
        .run_ms = watchdog_ms,
        .seed = 0x5150,
        .serve_relay = true,
    });
    defer relay.deinit(t.io);
    if (!try roster.await(t.io, relay, &Process.saidWhereItListens, budget_ms)) {
        return relay.gaveUp("never said where it was listening", .{});
    }
    // The only reading of a relay's address in this file. Everything after
    // this hands a client a URL and nothing else.
    const route = try relayPeer(arena.allocator(), relay);

    const first = try startNode(&roster, t.allocator, arena.allocator(), t.io, "first", .{
        .tag = 0xa1,
        .run_ms = watchdog_ms,
        .seed = 0xa1a1,
        .relay_peer = route,
        .send = try sendValue(arena.allocator(), 0xb2, to_second),
    });
    defer first.deinit(t.io);
    if (!try roster.await(t.io, first, &Process.saidWhereItListens, budget_ms)) {
        return first.gaveUp("never said where it was listening", .{});
    }
    const second = try startNode(&roster, t.allocator, arena.allocator(), t.io, "second", .{
        .tag = 0xb2,
        .run_ms = watchdog_ms,
        .seed = 0xb2b2,
        .relay_peer = route,
        .send = try sendValue(arena.allocator(), 0xa1, to_first),
    });
    defer second.deinit(t.io);
    if (!try roster.await(t.io, second, &Process.saidWhereItListens, budget_ms)) {
        return second.gaveUp("never said where it was listening", .{});
    }

    // The identities this file predicted are the identities the nodes
    // presented, so each `--send` named a real peer. Three identities besides:
    // no end of this can be the other, which is what stops a datagram that
    // went nowhere from looking like one that came back.
    for ([_]struct { node: *const Process, tag: u8 }{
        .{ .node = first, .tag = 0xa1 },
        .{ .node = second, .tag = 0xb2 },
    }) |each| {
        const side = try named(each.node);
        const predicted = try nodeIdOf(arena.allocator(), each.tag);
        if (!std.mem.eql(u8, side.id, predicted)) return each.node.gaveUp(
            "presented {s}, and a plan built from tag {x} presents {s}",
            .{ side.id, each.tag, predicted },
        );
    }

    // Each client is stopped once the relay has handed it a datagram, which is
    // the whole claim of this test observed rather than waited for: `received`
    // is the same counter `relay inbox: datagrams` reports, so the gate and the
    // assertion below are one witness. The relay is stopped last and only once
    // it says both clients are gone, which is what its `disconnects 2` needs.
    try roster.awaitWant(t.io, relay, "two clients it had taken in", admitted(2), budget_ms);
    for ([_]*Process{ first, second }) |client| {
        try roster.awaitWant(t.io, client, "a relay link that was up", relay_linked, budget_ms);
    }
    for ([_]*Process{ first, second }) |client| {
        try roster.awaitWant(t.io, client, "a datagram the relay had handed it", .{
            .all = &.{.{ .field = "received", .want = 1 }},
        }, budget_ms);
    }
    try roster.awaitWant(t.io, relay, "two datagrams it had forwarded", .{
        .all = &.{.{ .field = "forwarded", .want = 2 }},
    }, budget_ms);
    try first.stop();
    try second.stop();
    const first_term = try roster.reap(t.io, first, budget_ms);
    const second_term = try roster.reap(t.io, second, budget_ms);
    try roster.awaitWant(
        t.io,
        relay,
        "both clients gone and no connection up",
        noneUp("disconnected", 2),
        budget_ms,
    );
    try relay.stop();
    const relay_term = try roster.reap(t.io, relay, budget_ms);

    // The relay's own account: one arrival per client, each admitted once, both
    // departures reported once — and the two datagrams, which is the whole
    // claim, because no other path exists between these two sockets and the
    // relay is the only thing that saw either one.
    try expectRelayServed(relay, relay_term, 2);
    try expectCounts(relay, &.{
        // A datagram each way, read off a client and forwarded. **At least**
        // two of each and not exactly two: a client whose peer had not reached
        // the relay yet is told so and offers its datagram again, and the
        // relay read and refused that first offer. Which of the two clients
        // that is depends on which handshake the relay finished first, which is
        // a race between two processes and not a property of either — so the
        // bytes in the two inboxes below are what say the datagrams crossed,
        // and this is the arithmetic that has to be at least right.
        .{ .line = "relay out:", .label = "read ", .want = 2, .at_least = true },
        .{ .line = "relay out:", .label = "forwarded ", .want = 2, .at_least = true },
        // A queue that refused one would be a different failure, and this
        // shape cannot produce it: two datagrams against a queue of 64.
        .{ .line = "relay out:", .label = "full queue ", .want = 0 },
        .{ .line = "relay out:", .label = "oversized ", .want = 0 },
    });

    // Each client, from its own side of the wire: one dial, one handshake, at
    // least one datagram out — and one in, carrying the other process's node
    // id and the bytes that process was told to send.
    try expectClientReached(first, first_term);
    try expectClientReached(second, second_term);
    try expectCounts(first, &.{
        .{ .line = "relay out:", .label = "sent ", .want = 1, .at_least = true },
    });
    try expectCounts(second, &.{
        .{ .line = "relay out:", .label = "sent ", .want = 1, .at_least = true },
    });
    try expectHanded(first, second, to_first);
    try expectHanded(second, first, to_second);
}

test "a SIGTERM to a client of the relay leaves the relay running, and it notices" {
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    var roster: Roster = .{};
    defer roster.deinit(t.allocator);

    const relay = try startNode(&roster, t.allocator, arena.allocator(), t.io, "relay", .{
        .tag = 0x5e,
        .run_ms = watchdog_ms,
        .seed = 0x5150,
        .serve_relay = true,
    });
    defer relay.deinit(t.io);
    if (!try roster.await(t.io, relay, &Process.saidWhereItListens, budget_ms)) {
        return relay.gaveUp("never said where it was listening", .{});
    }
    const route = try relayPeer(arena.allocator(), relay);

    // The gate, for the reason every test here that signals anything has one:
    // a signal is only worth sending to a node that has finished reaching the
    // relay, and what says it has is the gate's own state rather than the
    // moment a `--for` of ours expires.
    const gate = try startNode(&roster, t.allocator, arena.allocator(), t.io, "gate", .{
        .tag = 0x33,
        .run_ms = watchdog_ms,
        .seed = 0x3333,
        .relay_peer = route,
    });
    defer gate.deinit(t.io);
    const client = try startNode(&roster, t.allocator, arena.allocator(), t.io, "client", .{
        .tag = 0xc1,
        .run_ms = watchdog_ms,
        .seed = 0xc1c1,
        .relay_peer = route,
    });
    defer client.deinit(t.io);
    if (!try roster.await(t.io, client, &Process.saidWhereItListens, budget_ms)) {
        return client.gaveUp("never said where it was listening", .{});
    }

    try roster.awaitWant(t.io, gate, "a relay link that was up", relay_linked, budget_ms);
    try roster.awaitWant(t.io, client, "a relay link that was up", relay_linked, budget_ms);
    try roster.awaitWant(t.io, relay, "two clients it had taken in", admitted(2), budget_ms);
    try gate.stop();
    const gate_term = try roster.reap(t.io, gate, budget_ms);
    try expectClientReached(gate, gate_term);

    try client.stop();
    const client_term = try roster.reap(t.io, client, budget_ms);
    try expectClientReached(client, client_term);

    // The relay is up. Its pipe has not closed, so it has not exited: a relay
    // that took its client down with it would have nothing left to say.
    try roster.pump(t.io);
    if (relay.finished()) {
        return relay.gaveUp("stopped when the client that reached it was signalled", .{});
    }

    // **The survivor is stopped on its notice, not on a timer.** `disconnected`
    // is the counter `relay away: disconnects` reports and `up` is the one
    // `relay held: connections up 0` reports, so the two gates below and the two
    // assertions they exist for are one witness each. The old
    // `relay_survivor_ms` left a margin nobody had to keep in step with
    // `relay_gate_ms`; this has no margin to keep in step.
    try roster.awaitWant(
        t.io,
        relay,
        "both clients gone and no connection up",
        noneUp("disconnected", 2),
        budget_ms,
    );
    try relay.stop();
    const relay_term = try roster.reap(t.io, relay, budget_ms);
    try expectRelayServed(relay, relay_term, 2);
    try expectCounts(relay, &.{
        // Both clients ceased being established before the relay's own close.
        // Closed or draining peers also read as not established; zero here
        // does not require their timer-driven retirement to have finished.
        .{ .line = "relay held:", .label = "connections up ", .want = 0 },
        // One retirement proves the relay noticed. The other may still be
        // draining, so requiring two would introduce a timing assumption.
        .{ .line = "dials:", .label = "refused; ", .want = 1, .at_least = true },
        // Neither client was asked to send anything, so a relay that counted a
        // datagram here would be counting one nobody put on the wire.
        .{ .line = "relay out:", .label = "read ", .want = 0 },
        .{ .line = "relay out:", .label = "forwarded ", .want = 0 },
    });
}

test "a SIGTERM to the relay leaves its client running, and it notices" {
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    var roster: Roster = .{};
    defer roster.deinit(t.allocator);

    const relay = try startNode(&roster, t.allocator, arena.allocator(), t.io, "relay", .{
        .tag = 0x5e,
        .run_ms = watchdog_ms,
        .seed = 0x5150,
        .serve_relay = true,
    });
    defer relay.deinit(t.io);
    if (!try roster.await(t.io, relay, &Process.saidWhereItListens, budget_ms)) {
        return relay.gaveUp("never said where it was listening", .{});
    }
    const route = try relayPeer(arena.allocator(), relay);

    const gate = try startNode(&roster, t.allocator, arena.allocator(), t.io, "gate", .{
        .tag = 0x33,
        .run_ms = watchdog_ms,
        .seed = 0x3333,
        .relay_peer = route,
    });
    defer gate.deinit(t.io);
    const client = try startNode(&roster, t.allocator, arena.allocator(), t.io, "client", .{
        .tag = 0xc1,
        .run_ms = watchdog_ms,
        .seed = 0xc1c1,
        .relay_peer = route,
    });
    defer client.deinit(t.io);
    if (!try roster.await(t.io, client, &Process.saidWhereItListens, budget_ms)) {
        return client.gaveUp("never said where it was listening", .{});
    }

    try roster.awaitWant(t.io, gate, "a relay link that was up", relay_linked, budget_ms);
    try roster.awaitWant(t.io, client, "a relay link that was up", relay_linked, budget_ms);
    try roster.awaitWant(t.io, relay, "two clients it had taken in", admitted(2), budget_ms);
    try gate.stop();
    const gate_term = try roster.reap(t.io, gate, budget_ms);
    try expectClientReached(gate, gate_term);

    // The other direction: the node that serves is the one that is stopped, and
    // the node that dialled has to be the one that notices.
    try relay.stop();
    const relay_term = try roster.reap(t.io, relay, budget_ms);
    try expectRelayServed(relay, relay_term, 2);
    try expectCounts(relay, &.{
        // It was stopped, not abandoned. A client is released only once the core
        // has dropped its connection, and a connection a peer has closed stays
        // in the table while it drains, so both clients are still in the
        // registry here: every departure `expectRelayServed` counted is this
        // relay's own close and not a peer that went away. **This is the
        // control the test above reads against** — same relay, same counter,
        // opposite answer.
        .{ .line = "relay held:", .label = "node ids ", .want = 2 },
        // The node under test is up, which is what makes the count above a
        // statement about the relay being signalled. Not "two up": a connection
        // that has been told to close is still in the table and no longer
        // established, and the gate's has been for a moment by now.
        .{ .line = "relay held:", .label = "connections up ", .want = 1, .at_least = true },
        // And the core finished nothing, because nothing had drained: the
        // counter the test above needs to have moved had it not been signalled
        // first.
        .{ .line = "dials:", .label = "refused; ", .want = 0 },
    });

    try roster.pump(t.io);
    if (client.finished()) {
        return client.gaveUp("stopped when the relay it dialled was signalled", .{});
    }

    // **The survivor is stopped on its notice, not on a timer.** This is the
    // test whose old numbers were the tightest in the file: a client window of
    // `relay_client_survivor_ms - relay_gate_ms` is 4000 ms of margin under this
    // file's own measured ~5 s for a relay client to see a dead relay, and the
    // two numbers it came from had to be kept in step by hand. The gate below
    // is `up` at zero beside `closed`, which is the client's own account of
    // losing the relay — so the counter is read at the pass that says so rather
    // than at a moment chosen to be probably late enough.
    try roster.awaitWant(
        t.io,
        client,
        "no connection to the relay left",
        noneUp("closed", 1),
        budget_ms,
    );
    try client.stop();
    const client_term = try roster.reap(t.io, client, budget_ms);
    try expectClientReached(client, client_term);
    try expectCounts(client, &.{
        // **The noticing**: the connection to the relay is not established any
        // more, and this count was read before this node's own close — which is
        // what makes it a statement about the relay going away rather than
        // about a node tidying up. The relay that was stopped first, one test
        // above, is the control: it read one up with both its clients held.
        //
        // `connections finished` is deliberately not asserted here, and now for
        // a reason that is about the counter rather than about a window: the
        // core keeps a closed connection while it drains, so it moves later
        // than the connection ceasing to be established, and it is `up` that
        // says the relay went away. It is still on the line above, as a
        // monotonic witness for the gate, which is what it is good for.
        .{ .line = "relay held:", .label = "connections up ", .want = 0 },
        // This node was never asked to put a datagram on the wire, and a relay
        // is not a client of itself, so nothing here was forwarded anywhere.
        .{ .line = "relay out:", .label = "sent ", .want = 0 },
        .{ .line = "relay out:", .label = "handed to this node ", .want = 0 },
        // And the relay never told it that a peer was not there, because this
        // node put nothing on the wire for it to have an opinion about.
        .{ .line = "relay in:", .label = "peer gone ", .want = 0 },
    });
}

test "a flag this program refuses exits 1, on one line, with no stack trace" {
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    var roster: Roster = .{};
    defer roster.deinit(t.allocator);

    // A node id for the flag to name. It only has to be one a peer could hold:
    // the URL beside it is what these command lines are about.
    const held = try nodeIdOf(arena.allocator(), 0x39);

    // A relay URL whose host is a name. `RelayUrl.socketAddr` refuses those
    // outright — nothing in this project resolves a name — and this is that
    // refusal arriving at a command line: exit 1 and a line, rather than a node
    // that went looking for a relay it was never told where.
    const by_name = [_][]const u8{
        "--relay-peer",
        try std.fmt.allocPrint(arena.allocator(), "{s}@http://relay.example.com/", .{held}),
    };
    const named_relay = try startNode(&roster, t.allocator, arena.allocator(), t.io, "by name", .{
        .tag = 0x39,
        .run_ms = watchdog_ms,
        .seed = 0x3939,
        .extra = &by_name,
    });
    defer named_relay.deinit(t.io);
    const named_term = try roster.reap(t.io, named_relay, budget_ms);
    try expectRefused(named_relay, named_term, "NotAnIpLiteral");

    // And the one refusal that is about the relay flags disagreeing with each
    // other: a datagram for a node that has no relay to put it on. Left to the
    // loop this would be a `NoRelay` out of `sendThrough` on its first pass,
    // which is a stack trace rather than a line.
    const wireless = [_][]const u8{
        "--send",
        try std.fmt.allocPrint(arena.allocator(), "{s}:nowhere", .{held}),
    };
    const no_relay = try startNode(&roster, t.allocator, arena.allocator(), t.io, "no relay", .{
        .tag = 0x3b,
        .run_ms = watchdog_ms,
        .seed = 0x3b3b,
        .extra = &wireless,
    });
    defer no_relay.deinit(t.io);
    const no_relay_term = try roster.reap(t.io, no_relay, budget_ms);
    try expectRefused(no_relay, no_relay_term, "SendNeedsARelayClient");

    // And the same refusal one role further on: this process is the relay, and
    // it is carrying a datagram for a peer besides. A serving relay is not a
    // client of itself, so the datagram has nowhere to go — it would be held
    // by a node that can never put it on a wire, and the run would end saying
    // nothing at all about the flag the caller got wrong. The same node id and
    // the same payload as the line above, and the same refusal: the only
    // difference is which half of the relay handshake this process took.
    //
    // **Its `--for` is one pass rather than this file's.** A refused command
    // line is answered before there is a node to bound, so that watchdog is
    // not what ends a correct run — it is here so that a command line the
    // program wrongly accepts fails in this file's time and names itself,
    // rather than hanging the red behind a long one. Nothing below waits for
    // a duration; the exit code and the line are the whole of the claim.
    const serving_send = try startNode(
        &roster,
        t.allocator,
        arena.allocator(),
        t.io,
        "serving relay sends",
        .{
            .tag = 0x3c,
            .run_ms = short_watchdog_ms,
            .seed = 0x3c3c,
            .serve_relay = true,
            .send = try std.fmt.allocPrint(arena.allocator(), "{s}:nowhere", .{held}),
        },
    );
    defer serving_send.deinit(t.io);
    const serving_send_term = try roster.reap(t.io, serving_send, budget_ms);
    try expectRefused(serving_send, serving_send_term, "SendNeedsARelayClient");
    // And it never became a node: this refusal is the parse, so there is no
    // socket behind it and nothing was ever listening on this process's word.
    if (serving_send.line("listening") != null) return serving_send.gaveUp(
        "was listening, and a command line that is wrong before the node exists never binds",
        .{},
    );

    // And a flag this program has never heard of, which is the refusal that was
    // already here: the relay flags must not have changed its shape.
    const unknown = [_][]const u8{ "--not-a-flag", "value" };
    const stranger = try startNode(&roster, t.allocator, arena.allocator(), t.io, "no flag", .{
        .tag = 0x3a,
        .run_ms = watchdog_ms,
        .seed = 0x3a3a,
        .extra = &unknown,
    });
    defer stranger.deinit(t.io);
    const stranger_term = try roster.reap(t.io, stranger, budget_ms);
    try expectRefused(stranger, stranger_term, "is not an option");
}
