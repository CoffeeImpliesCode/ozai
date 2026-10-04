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
//! # Where the work is
//!
//! Four modules carry the machinery, and this file carries the scenarios:
//!
//! - `process_driver.zig` owns a child — the process, its two pipes, and every
//!   byte read off them — for the child's whole life.
//! - `process_roster.zig` watches a set of children with one wait, and every
//!   wait in here is bounded.
//! - `process_flags.zig` builds a command line from a plan, and the identities
//!   that plan implies.
//! - `process_report.zig` reads what a child said: the live `progress:` snapshot
//!   a wait is gated on, and the final report a finished run is checked against.
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

const driver = @import("process_driver.zig");
const flags = @import("process_flags.zig");
const report = @import("process_report.zig");
const roster_mod = @import("process_roster.zig");

const t = std.testing;

/// Every allocation in this file goes through a handle the caller handed in,
/// which here is `std.testing`'s own allocator: `AGENTS.md` §1 by name.
const Allocator = std.mem.Allocator;

const Process = driver.Process;
const Roster = roster_mod.Roster;
const Want = report.Want;

/// Import the loop interval so watchdog arithmetic follows the node's cadence.
const pass_ms: i64 = @intCast(ozai.node_config.poll_interval_ms);

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

// ---------------------------------------------------------------------------
// Starting nodes
// ---------------------------------------------------------------------------

/// Start a node and put it on the roster, so that one wait in the test watches
/// every node the test started.
fn startNode(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    roster: *Roster,
    name: []const u8,
    plan: flags.Plan,
) !*Process {
    const argv = try flags.flags(arena, plan);
    const process = try Process.start(gpa, io, name, argv);
    errdefer process.deinit(io);
    try roster.add(gpa, process);
    return process;
}

// ---------------------------------------------------------------------------
// The states this file waits for, named once
// ---------------------------------------------------------------------------

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
// One relay datagram, as this scenario claims it
// ---------------------------------------------------------------------------

/// One datagram came out of the relay and arrived at `process`, from the peer
/// named, with the bytes it was sent.
///
/// The count is the relay's arithmetic and this is the payload, so a relay
/// that forwarded the right number of datagrams to the wrong client, or the
/// right one with the wrong bytes, prints something else here. The sender is
/// what says the datagram crossed *through* the relay: it is the other
/// process's node id, and the relay was the only path between the two sockets.
///
/// This is the claim of one scenario rather than of the file, so it stays with
/// that scenario rather than in `process_report.zig`.
fn expectHanded(
    process: *const Process,
    from: *const Process,
    payload: []const u8,
) !void {
    try report.expectCounts(process, &.{
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
// Two processes, and the test stopping both of them
// ---------------------------------------------------------------------------

test "two node processes meet on a socket and both wind down in order" {
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    var roster: Roster = .{};
    defer roster.deinit(t.allocator);

    const listener = try startNode(t.allocator, arena.allocator(), t.io, &roster, "listener", .{
        .tag = 0x51,
        .run_ms = watchdog_ms,
    });
    defer listener.deinit(t.io);
    if (!try roster.await(t.io, listener, &Process.saidWhereItListens, budget_ms)) {
        return roster.gaveUp(listener, null, "never said where it was listening", .{});
    }

    const one_peer = [_][]const u8{try flags.peer(arena.allocator(), listener)};
    const dialer = try startNode(t.allocator, arena.allocator(), t.io, &roster, "dialer", .{
        .tag = 0xc1,
        .run_ms = watchdog_ms,
        .peers = &one_peer,
    });
    defer dialer.deinit(t.io);
    if (!try roster.await(t.io, dialer, &Process.saidWhereItListens, budget_ms)) {
        return roster.gaveUp(dialer, null, "never said where it was listening", .{});
    }

    // Two identities and two bound addresses, so this is two nodes and not one
    // node hearing its own certificate twice. Both ports are the kernel's,
    // which is why neither is written down and both differ.
    const listener_side = try flags.named(listener);
    const dialer_side = try flags.named(dialer);
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
    try report.expectWoundDown(listener, listener_term);
    try report.expectWoundDown(dialer, dialer_term);

    // The listener's own account of the handshake: datagrams moved both ways,
    // the arrival was offered to the filter, the loop spawned a task for it and
    // the task ran the handler's accept. Nothing in that chain can happen
    // before the handshake and all of it has to happen for a connection.
    try report.expectCounts(listener, &.{
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
    try report.expectCounts(dialer, &.{
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
            return roster.gaveUp(listener, null, "printed a banner with no node id in it", .{}),
        dialer.value("gossip named:") orelse
            return roster.gaveUp(dialer, null, "named no peer at all", .{}),
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

    const gate = try startNode(t.allocator, arena.allocator(), t.io, &roster, "gate", .{
        .tag = 0x33,
        .run_ms = watchdog_ms,
    });
    defer gate.deinit(t.io);
    const listener = try startNode(t.allocator, arena.allocator(), t.io, &roster, "listener", .{
        .tag = 0x51,
        .run_ms = watchdog_ms,
    });
    defer listener.deinit(t.io);
    if (!try roster.await(t.io, listener, &Process.saidWhereItListens, budget_ms)) {
        return roster.gaveUp(listener, null, "never said where it was listening", .{});
    }
    if (!try roster.await(t.io, gate, &Process.saidWhereItListens, budget_ms)) {
        return roster.gaveUp(gate, null, "never said where it was listening", .{});
    }

    const both_peers = try flags.peers(arena.allocator(), gate, listener);
    const dialer = try startNode(t.allocator, arena.allocator(), t.io, &roster, "dialer", .{
        .tag = 0xc1,
        .run_ms = watchdog_ms,
        .peers = both_peers,
    });
    defer dialer.deinit(t.io);
    if (!try roster.await(t.io, dialer, &Process.saidWhereItListens, budget_ms)) {
        return roster.gaveUp(dialer, null, "never said where it was listening", .{});
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
    try report.expectGate(gate, gate_term);

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
    try report.expectWoundDown(listener, listener_term);
    try report.expectWoundDown(dialer, dialer_term);
    try report.expectCounts(listener, &.{
        .{ .line = "accept loop:", .label = "spawned, ", .want = 1 },
        .{ .line = "dials:", .label = " of ", .want = 0 },
        // The zero the next two tests turn on.
        .{ .line = "dials:", .label = "refused; ", .want = 0 },
    });
    try report.expectCounts(dialer, &.{
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

    const gate = try startNode(t.allocator, arena.allocator(), t.io, &roster, "gate", .{
        .tag = 0x33,
        .run_ms = watchdog_ms,
    });
    defer gate.deinit(t.io);
    const listener = try startNode(t.allocator, arena.allocator(), t.io, &roster, "listener", .{
        .tag = 0x51,
        .run_ms = watchdog_ms,
    });
    defer listener.deinit(t.io);
    if (!try roster.await(t.io, listener, &Process.saidWhereItListens, budget_ms)) {
        return roster.gaveUp(listener, null, "never said where it was listening", .{});
    }
    if (!try roster.await(t.io, gate, &Process.saidWhereItListens, budget_ms)) {
        return roster.gaveUp(gate, null, "never said where it was listening", .{});
    }

    const both_peers = try flags.peers(arena.allocator(), gate, listener);
    const dialer = try startNode(t.allocator, arena.allocator(), t.io, &roster, "dialer", .{
        .tag = 0xc1,
        .run_ms = watchdog_ms,
        .peers = both_peers,
    });
    defer dialer.deinit(t.io);
    if (!try roster.await(t.io, dialer, &Process.saidWhereItListens, budget_ms)) {
        return roster.gaveUp(dialer, null, "never said where it was listening", .{});
    }

    // Both arrivals are observed before anything is signalled: the gate's, so
    // the signal below lands on a node that has finished connecting rather
    // than one that has just started, and the listener's, so the survivor is
    // stopped only once it holds a connection this test can then watch end.
    try roster.awaitWant(t.io, gate, "an arrival it had handled", arrived, budget_ms);
    try roster.awaitWant(t.io, listener, "an arrival it had handled", arrived, budget_ms);
    try gate.stop();
    const gate_term = try roster.reap(t.io, gate, budget_ms);
    try report.expectGate(gate, gate_term);

    try dialer.stop();
    const dialer_term = try roster.reap(t.io, dialer, budget_ms);
    try report.expectWoundDown(dialer, dialer_term);
    try report.expectCounts(dialer, &.{
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
        return roster.gaveUp(
            listener,
            null,
            "stopped when the process that dialled it was signalled",
            .{},
        );
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
    try report.expectWoundDown(listener, listener_term);
    try report.expectCounts(listener, &.{
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

    const gate = try startNode(t.allocator, arena.allocator(), t.io, &roster, "gate", .{
        .tag = 0x33,
        .run_ms = watchdog_ms,
    });
    defer gate.deinit(t.io);
    const listener = try startNode(t.allocator, arena.allocator(), t.io, &roster, "listener", .{
        .tag = 0x51,
        .run_ms = watchdog_ms,
    });
    defer listener.deinit(t.io);
    if (!try roster.await(t.io, listener, &Process.saidWhereItListens, budget_ms)) {
        return roster.gaveUp(listener, null, "never said where it was listening", .{});
    }
    if (!try roster.await(t.io, gate, &Process.saidWhereItListens, budget_ms)) {
        return roster.gaveUp(gate, null, "never said where it was listening", .{});
    }

    const both_peers = try flags.peers(arena.allocator(), gate, listener);
    const dialer = try startNode(t.allocator, arena.allocator(), t.io, &roster, "dialer", .{
        .tag = 0xc1,
        .run_ms = watchdog_ms,
        .peers = both_peers,
    });
    defer dialer.deinit(t.io);
    if (!try roster.await(t.io, dialer, &Process.saidWhereItListens, budget_ms)) {
        return roster.gaveUp(dialer, null, "never said where it was listening", .{});
    }

    // The same two observed arrivals as the test above, and for the same
    // reasons: one says the node about to be signalled has finished
    // connecting, and the other says the node that has to notice holds the
    // connection this test then watches end.
    try roster.awaitWant(t.io, gate, "an arrival it had handled", arrived, budget_ms);
    try roster.awaitWant(t.io, listener, "an arrival it had handled", arrived, budget_ms);
    try gate.stop();
    const gate_term = try roster.reap(t.io, gate, budget_ms);
    try report.expectGate(gate, gate_term);

    // The other direction: the node that answers is the one that is stopped,
    // and the node that dialled has to be the one that notices.
    try listener.stop();
    const listener_term = try roster.reap(t.io, listener, budget_ms);
    try report.expectWoundDown(listener, listener_term);
    try report.expectCounts(listener, &.{
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
        return roster.gaveUp(
            dialer,
            null,
            "stopped when the process that dialled it was stopped",
            .{},
        );
    }

    // **The survivor is stopped on its notice, not on a timer**, exactly as in
    // the test above. `two_gave_up` is `finished` at two, which is what the
    // `refused; 2` below reports — this node dialled two peers and both are
    // gone, so the gate's departure and the listener's are both counted, and
    // the gate that read one of them has already been reaped above.
    try roster.awaitWant(t.io, dialer, "both connections it had given up", two_gave_up, budget_ms);
    try dialer.stop();
    const dialer_term = try roster.reap(t.io, dialer, budget_ms);
    try report.expectWoundDown(dialer, dialer_term);
    try report.expectCounts(dialer, &.{
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
    const listener = try startNode(t.allocator, arena.allocator(), t.io, &roster, "listener", .{
        .tag = 0x51,
        .run_ms = watchdog_ms,
    });
    defer listener.deinit(t.io);
    if (!try roster.await(t.io, listener, &Process.saidWhereItListens, budget_ms)) {
        return roster.gaveUp(listener, null, "never said where it was listening", .{});
    }

    const one_peer = [_][]const u8{try flags.peer(arena.allocator(), listener)};
    const dialer = try startNode(t.allocator, arena.allocator(), t.io, &roster, "dialer", .{
        .tag = 0xc1,
        .run_ms = watchdog_ms,
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
    try report.expectWoundDown(dialer, dialer_term);
    try report.expectCounts(dialer, &.{
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
    try report.expectWoundDown(listener, listener_term);
    try report.expectCounts(listener, &.{
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
    const alone = try startNode(t.allocator, arena.allocator(), t.io, &roster, "alone", .{
        .tag = 0x33,
        .run_ms = watchdog_ms,
    });
    defer alone.deinit(t.io);
    if (!try roster.await(t.io, alone, &Process.saidWhereItListens, budget_ms)) {
        return roster.gaveUp(alone, null, "never said where it was listening", .{});
    }
    try alone.stop();

    const alone_term = try roster.reap(t.io, alone, budget_ms);
    try report.expectWoundDown(alone, alone_term);
    // Why this is a second test and not the first one's expectation loosened:
    // the line is a count rather than a constant, so a node that owed nothing
    // has to say so in the same place a node that owed one close does.
    try report.expectCounts(alone, &.{
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

    const relay = try startNode(t.allocator, arena.allocator(), t.io, &roster, "relay", .{
        .tag = 0x5e,
        .run_ms = watchdog_ms,
        .serve_relay = true,
    });
    defer relay.deinit(t.io);
    if (!try roster.await(t.io, relay, &Process.saidWhereItListens, budget_ms)) {
        return roster.gaveUp(relay, null, "never said where it was listening", .{});
    }
    // The only reading of a relay's address in this file. Everything after
    // this hands a client a URL and nothing else.
    const route = try flags.relayPeer(arena.allocator(), relay);

    const first = try startNode(t.allocator, arena.allocator(), t.io, &roster, "first", .{
        .tag = 0xa1,
        .run_ms = watchdog_ms,
        .relay_peer = route,
        .send = try flags.sendValue(arena.allocator(), 0xb2, to_second),
    });
    defer first.deinit(t.io);
    if (!try roster.await(t.io, first, &Process.saidWhereItListens, budget_ms)) {
        return roster.gaveUp(first, null, "never said where it was listening", .{});
    }
    const second = try startNode(t.allocator, arena.allocator(), t.io, &roster, "second", .{
        .tag = 0xb2,
        .run_ms = watchdog_ms,
        .relay_peer = route,
        .send = try flags.sendValue(arena.allocator(), 0xa1, to_first),
    });
    defer second.deinit(t.io);
    if (!try roster.await(t.io, second, &Process.saidWhereItListens, budget_ms)) {
        return roster.gaveUp(second, null, "never said where it was listening", .{});
    }

    // The identities this file predicted are the identities the nodes
    // presented, so each `--send` named a real peer. Three identities besides:
    // no end of this can be the other, which is what stops a datagram that
    // went nowhere from looking like one that came back.
    for ([_]struct { node: *const Process, tag: u8 }{
        .{ .node = first, .tag = 0xa1 },
        .{ .node = second, .tag = 0xb2 },
    }) |each| {
        const side = try flags.named(each.node);
        const predicted = try flags.nodeIdOf(arena.allocator(), each.tag);
        if (!std.mem.eql(u8, side.id, predicted)) return roster.gaveUp(
            each.node,
            null,
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
    try report.expectRelayServed(relay, relay_term, 2);
    try report.expectCounts(relay, &.{
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
    try report.expectClientReached(first, first_term);
    try report.expectClientReached(second, second_term);
    try report.expectCounts(first, &.{
        .{ .line = "relay out:", .label = "sent ", .want = 1, .at_least = true },
    });
    try report.expectCounts(second, &.{
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

    const relay = try startNode(t.allocator, arena.allocator(), t.io, &roster, "relay", .{
        .tag = 0x5e,
        .run_ms = watchdog_ms,
        .serve_relay = true,
    });
    defer relay.deinit(t.io);
    if (!try roster.await(t.io, relay, &Process.saidWhereItListens, budget_ms)) {
        return roster.gaveUp(relay, null, "never said where it was listening", .{});
    }
    const route = try flags.relayPeer(arena.allocator(), relay);

    // The gate, for the reason every test here that signals anything has one:
    // a signal is only worth sending to a node that has finished reaching the
    // relay, and what says it has is the gate's own state rather than the
    // moment a `--for` of ours expires.
    const gate = try startNode(t.allocator, arena.allocator(), t.io, &roster, "gate", .{
        .tag = 0x33,
        .run_ms = watchdog_ms,
        .relay_peer = route,
    });
    defer gate.deinit(t.io);
    const client = try startNode(t.allocator, arena.allocator(), t.io, &roster, "client", .{
        .tag = 0xc1,
        .run_ms = watchdog_ms,
        .relay_peer = route,
    });
    defer client.deinit(t.io);
    if (!try roster.await(t.io, client, &Process.saidWhereItListens, budget_ms)) {
        return roster.gaveUp(client, null, "never said where it was listening", .{});
    }

    try roster.awaitWant(t.io, gate, "a relay link that was up", relay_linked, budget_ms);
    try roster.awaitWant(t.io, client, "a relay link that was up", relay_linked, budget_ms);
    try roster.awaitWant(t.io, relay, "two clients it had taken in", admitted(2), budget_ms);
    try gate.stop();
    const gate_term = try roster.reap(t.io, gate, budget_ms);
    try report.expectClientReached(gate, gate_term);

    try client.stop();
    const client_term = try roster.reap(t.io, client, budget_ms);
    try report.expectClientReached(client, client_term);

    // The relay is up. Its pipe has not closed, so it has not exited: a relay
    // that took its client down with it would have nothing left to say.
    try roster.pump(t.io);
    if (relay.finished()) {
        return roster.gaveUp(
            relay,
            null,
            "stopped when the client that reached it was signalled",
            .{},
        );
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
    try report.expectRelayServed(relay, relay_term, 2);
    try report.expectCounts(relay, &.{
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

    const relay = try startNode(t.allocator, arena.allocator(), t.io, &roster, "relay", .{
        .tag = 0x5e,
        .run_ms = watchdog_ms,
        .serve_relay = true,
    });
    defer relay.deinit(t.io);
    if (!try roster.await(t.io, relay, &Process.saidWhereItListens, budget_ms)) {
        return roster.gaveUp(relay, null, "never said where it was listening", .{});
    }
    const route = try flags.relayPeer(arena.allocator(), relay);

    const gate = try startNode(t.allocator, arena.allocator(), t.io, &roster, "gate", .{
        .tag = 0x33,
        .run_ms = watchdog_ms,
        .relay_peer = route,
    });
    defer gate.deinit(t.io);
    const client = try startNode(t.allocator, arena.allocator(), t.io, &roster, "client", .{
        .tag = 0xc1,
        .run_ms = watchdog_ms,
        .relay_peer = route,
    });
    defer client.deinit(t.io);
    if (!try roster.await(t.io, client, &Process.saidWhereItListens, budget_ms)) {
        return roster.gaveUp(client, null, "never said where it was listening", .{});
    }

    try roster.awaitWant(t.io, gate, "a relay link that was up", relay_linked, budget_ms);
    try roster.awaitWant(t.io, client, "a relay link that was up", relay_linked, budget_ms);
    try roster.awaitWant(t.io, relay, "two clients it had taken in", admitted(2), budget_ms);
    try gate.stop();
    const gate_term = try roster.reap(t.io, gate, budget_ms);
    try report.expectClientReached(gate, gate_term);

    // The other direction: the node that serves is the one that is stopped, and
    // the node that dialled has to be the one that notices.
    try relay.stop();
    const relay_term = try roster.reap(t.io, relay, budget_ms);
    try report.expectRelayServed(relay, relay_term, 2);
    try report.expectCounts(relay, &.{
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
        return roster.gaveUp(
            client,
            null,
            "stopped when the relay it dialled was signalled",
            .{},
        );
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
    try report.expectClientReached(client, client_term);
    try report.expectCounts(client, &.{
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

// ---------------------------------------------------------------------------
// A command line the program refuses, and a driver that fails after it began
// ---------------------------------------------------------------------------

test "a flag this program refuses exits 1, on one line, with no stack trace" {
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    var roster: Roster = .{};
    defer roster.deinit(t.allocator);

    // A node id for the flag to name. It only has to be one a peer could hold:
    // the URL beside it is what these command lines are about.
    const held = try flags.nodeIdOf(arena.allocator(), 0x39);

    // A relay URL whose host is a name. `RelayUrl.socketAddr` refuses those
    // outright — nothing in this project resolves a name — and this is that
    // refusal arriving at a command line: exit 1 and a line, rather than a node
    // that went looking for a relay it was never told where.
    const by_name = [_][]const u8{
        "--relay-peer",
        try std.fmt.allocPrint(arena.allocator(), "{s}@http://relay.example.com/", .{held}),
    };
    const named_relay = try startNode(t.allocator, arena.allocator(), t.io, &roster, "by name", .{
        .tag = 0x39,
        .run_ms = watchdog_ms,
        .extra = &by_name,
    });
    defer named_relay.deinit(t.io);
    const named_term = try roster.reap(t.io, named_relay, budget_ms);
    try report.expectRefused(named_relay, named_term, "NotAnIpLiteral");

    // And the one refusal that is about the relay flags disagreeing with each
    // other: a datagram for a node that has no relay to put it on. Left to the
    // loop this would be a `NoRelay` out of `node_relay_client.sendThrough` on
    // its first pass, which is a stack trace rather than a line.
    const wireless = [_][]const u8{
        "--send",
        try std.fmt.allocPrint(arena.allocator(), "{s}:nowhere", .{held}),
    };
    const no_relay = try startNode(t.allocator, arena.allocator(), t.io, &roster, "no relay", .{
        .tag = 0x3b,
        .run_ms = watchdog_ms,
        .extra = &wireless,
    });
    defer no_relay.deinit(t.io);
    const no_relay_term = try roster.reap(t.io, no_relay, budget_ms);
    try report.expectRefused(no_relay, no_relay_term, "SendNeedsARelayClient");

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
        t.allocator,
        arena.allocator(),
        t.io,
        &roster,
        "serving relay sends",
        .{
            .tag = 0x3c,
            .run_ms = short_watchdog_ms,
            .serve_relay = true,
            .send = try std.fmt.allocPrint(arena.allocator(), "{s}:nowhere", .{held}),
        },
    );
    defer serving_send.deinit(t.io);
    const serving_send_term = try roster.reap(t.io, serving_send, budget_ms);
    try report.expectRefused(serving_send, serving_send_term, "SendNeedsARelayClient");
    // And it never became a node: this refusal is the parse, so there is no
    // socket behind it and nothing was ever listening on this process's word.
    if (serving_send.line("listening") != null) return roster.gaveUp(
        serving_send,
        null,
        "was listening, and a command line that is wrong before the node exists never binds",
        .{},
    );

    // And a flag this program has never heard of, which is the refusal that was
    // already here: the relay flags must not have changed its shape.
    const unknown = [_][]const u8{ "--not-a-flag", "value" };
    const stranger = try startNode(t.allocator, arena.allocator(), t.io, &roster, "no flag", .{
        .tag = 0x3a,
        .run_ms = watchdog_ms,
        .extra = &unknown,
    });
    defer stranger.deinit(t.io);
    const stranger_term = try roster.reap(t.io, stranger, budget_ms);
    try report.expectRefused(stranger, stranger_term, "is not an option");
}

// The driver this program actually runs, on an error it can reach from a
// command line.
//
// `node_runtime.run` closes on every exit, but `src/node/main.zig`'s `drive` is
// a second loop over the same node and once had no `errdefer` at all: a pass
// that failed left `main` to return the error over a node still in `serving`,
// and the `defer node_lifecycle.deinit()` behind it dropped it. So this asserts
// the driver boundary rather than `node_runtime.run`'s, which was never the
// broken one.
//
// **`--peer` nine times is the failure, and it is a real one.**
// `node_runtime.start` refuses a bootstrap list longer than
// `hyparview.max_bootstrap` after it has dialled, and `drive` calls `start` on
// its first pass — so the node exists, the banner is printed and the loop is
// entered, and the failure is forced after creation from the command line
// alone. Nothing here needs a flag this program does not already have.
test "a driver that fails after the node exists winds the node down and keeps the failure" {
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    var roster: Roster = .{};
    defer roster.deinit(t.allocator);

    // One more peer than a bootstrap list may carry. The ids are real — a node
    // id has to be on the curve for the command line to parse — and the
    // addresses are loopback ports nothing is bound to, which is the ordinary
    // "peer was not reached" case this project's `Config.peers` treats as a
    // fact about the network rather than a refusal.
    const no_listener = "127.0.0.1:9";
    var peers: [ozai.gossip_hyparview.max_bootstrap + 1][]const u8 = undefined;
    for (&peers, 0..) |*slot, index| {
        slot.* = try std.fmt.allocPrint(
            arena.allocator(),
            "{s}@{s}",
            .{ try flags.nodeIdOf(arena.allocator(), @intCast(0xe0 + index)), no_listener },
        );
    }

    const doomed = try startNode(t.allocator, arena.allocator(), t.io, &roster, "overlong", .{
        .tag = 0xd0,
        .run_ms = short_watchdog_ms,
        .peers = &peers,
    });
    defer doomed.deinit(t.io);

    // The banner came first, so this failure is after the node was built and is
    // not a command line the parse refused — which is the whole distinction
    // between this test and the refusal test above.
    if (!try roster.await(t.io, doomed, &Process.saidWhereItListens, budget_ms)) {
        return roster.gaveUp(doomed, null, "never said where it was listening", .{});
    }

    const term = try roster.reap(t.io, doomed, budget_ms);

    // The original failure survives the teardown. `drive`'s error is what the
    // caller has to hear: a wind-down that swallowed it, or replaced it with a
    // close error, would exit zero or exit with the wrong name, and a caller
    // scripting this would be told the wrong thing went wrong.
    const ended = term orelse
        return roster.gaveUp(doomed, null, "was still running when this file ran out of patience", .{});
    const status = switch (ended) {
        .exited => |code| code,
        else => return roster.gaveUp(
            doomed,
            null,
            "was {s} rather than an exit",
            .{@tagName(ended)},
        ),
    };
    if (status == 0) return roster.gaveUp(
        doomed,
        null,
        "exited 0, and the failure its own loop reported is what the caller must hear",
        .{},
    );
    if (std.mem.indexOf(u8, doomed.stderrText(), "BootstrapListTooLong") == null) {
        return roster.gaveUp(
            doomed,
            null,
            "did not report the failure its loop hit:\n{s}",
            .{doomed.stderrText()},
        );
    }

    // **And the node it was driving was wound down, which is the half that was
    // missing.** The claim is made from the one thing this failure actually
    // prints. `main` registers `node_runtime.windDown` before it writes the
    // banner, so a failing pass closes the node and hands the
    // `defer node_lifecycle.deinit()` behind it a lease that is already
    // `closed`. Dropped in `serving` instead, `node_lifecycle.deinit`
    // reports the abandonment at **error level**, on the stderr this run has
    // just proved carries the failure — and an error-level log from this
    // program's own teardown is a finding about the program, not a stray
    // warning. So the check is that the line is absent, against a stderr that is
    // known not to be empty.
    //
    // **No shutdown report is asked for here.** `report` belongs to the normal
    // path: `drive` returning an error never reaches `shut`, so no `shutdown:`
    // line exists to read. Demanding one would be inventing telemetry to serve
    // an assertion, and its absence would say nothing at all about a
    // descriptor — the wind-down releases the socket whether or not anyone
    // reports having done so.
    if (std.mem.indexOf(u8, doomed.stderrText(), "was dropped in phase") != null) {
        return roster.gaveUp(
            doomed,
            null,
            "dropped a node it was still serving, and its own teardown said so:\n{s}",
            .{doomed.stderrText()},
        );
    }
}
