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
//! **That deadline bounds this file, not the program under test.** Every gate
//! below is a counter a node published after it reached the state that counter
//! names, and none of them is a statement about how long anything took. The
//! deadline is therefore per target (`budget_ms` in `two_process_roster.zig`,
//! ten times larger on every row this project does not gate on) and generous
//! there, so a slow emulator cannot fail a run that was correct.
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
//! # Time
//!
//! These tests use the host clock only to bound waits. The node receives time
//! as data. Completion depends on observed state, not on a sleep.

const std = @import("std");

const t = std.testing;

const child = @import("two_process_child.zig");
const launch = @import("two_process_launch.zig");
const progress_ns = @import("two_process_progress.zig");
const report_ns = @import("two_process_report.zig");
const roster_ns = @import("two_process_roster.zig");

const Process = child.Process;
const Roster = roster_ns.Roster;
const Want = progress_ns.Want;

// The names the scenarios below were written with. A module import is not a
// re-export, and a test body that had to say `roster_ns.` on every gate would
// read as a different file from the one these tests were written in.
const startNode = launch.startNode;
const budget_ms = roster_ns.budget_ms;
const watchdog_ms = roster_ns.watchdog_ms;

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

/// The core gave one connection up. The same counter the survivor tests assert
/// as `refused; 1`, so the gate and the assertion read one witness rather than
/// a gate waiting for something and an assertion checking something else.
const one_gave_up: Want = .{ .all = &.{.{ .field = "finished", .want = 1 }} };

/// And two of them.
const two_gave_up: Want = .{ .all = &.{.{ .field = "finished", .want = 2 }} };

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

    const one_peer = [_][]const u8{try launch.peer(arena.allocator(), listener)};
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
    const listener_side = try launch.named(listener);
    const dialer_side = try launch.named(dialer);
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
    try report_ns.expectWoundDown(listener, listener_term);
    try report_ns.expectWoundDown(dialer, dialer_term);

    // The listener's own account of the handshake: datagrams moved both ways,
    // the arrival was offered to the filter, the loop spawned a task for it and
    // the task ran the handler's accept. Nothing in that chain can happen
    // before the handshake and all of it has to happen for a connection.
    try report_ns.expectCounts(listener, &.{
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
    try report_ns.expectCounts(dialer, &.{
        .{ .line = "stopped:", .label = "stopped: ", .want = 1, .at_least = true },
        .{ .line = "stopped:", .label = "passes, ", .want = 1, .at_least = true },
        .{ .line = "stopped:", .label = "datagrams in, ", .want = 1, .at_least = true },
        .{ .line = "accept loop:", .label = "accept loop: ", .want = 0 },
        .{ .line = "dials:", .label = "dials: ", .want = 1 },
        .{ .line = "dials:", .label = " of ", .want = 0 },
        .{ .line = "shutdown:", .label = "handler shutdowns, ", .want = 0 },
    });
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

    const both_peers = try launch.peers(arena.allocator(), gate, listener);
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
    try report_ns.expectGate(gate, gate_term);

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
    try report_ns.expectWoundDown(listener, listener_term);
    try report_ns.expectWoundDown(dialer, dialer_term);
    try report_ns.expectCounts(listener, &.{
        .{ .line = "accept loop:", .label = "spawned, ", .want = 1 },
        .{ .line = "dials:", .label = " of ", .want = 0 },
        // The zero the next two tests turn on.
        .{ .line = "dials:", .label = "refused; ", .want = 0 },
    });
    try report_ns.expectCounts(dialer, &.{
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

    const both_peers = try launch.peers(arena.allocator(), gate, listener);
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
    try report_ns.expectGate(gate, gate_term);

    try dialer.stop();
    const dialer_term = try roster.reap(t.io, dialer, budget_ms);
    try report_ns.expectWoundDown(dialer, dialer_term);
    try report_ns.expectCounts(dialer, &.{
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
    try report_ns.expectWoundDown(listener, listener_term);
    try report_ns.expectCounts(listener, &.{
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

    const both_peers = try launch.peers(arena.allocator(), gate, listener);
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
    try report_ns.expectGate(gate, gate_term);

    // The other direction: the node that answers is the one that is stopped,
    // and the node that dialled has to be the one that notices.
    try listener.stop();
    const listener_term = try roster.reap(t.io, listener, budget_ms);
    try report_ns.expectWoundDown(listener, listener_term);
    try report_ns.expectCounts(listener, &.{
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
    try report_ns.expectWoundDown(dialer, dialer_term);
    try report_ns.expectCounts(dialer, &.{
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

    const one_peer = [_][]const u8{try launch.peer(arena.allocator(), listener)};
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
    try report_ns.expectWoundDown(dialer, dialer_term);
    try report_ns.expectCounts(dialer, &.{
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
    try report_ns.expectWoundDown(listener, listener_term);
    try report_ns.expectCounts(listener, &.{
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
    try report_ns.expectWoundDown(alone, alone_term);
    // Why this is a second test and not the first one's expectation loosened:
    // the line is a count rather than a constant, so a node that owed nothing
    // has to say so in the same place a node that owed one close does.
    try report_ns.expectCounts(alone, &.{
        .{ .line = "dials:", .label = "dials: ", .want = 0 },
        .{ .line = "close:", .label = "close: ", .want = 0 },
        .{ .line = "close:", .label = "connections owed, ", .want = 0 },
        .{ .line = "close:", .label = "close datagrams written, ", .want = 0 },
    });
}

// A schema change must fail at the sole parser, not become a process wait timeout.
test "process progress parser accepts exact twelve fields and rejects obsolete or malformed lines" {
    const fields =
        "dials 1, refused 2, accepted 3, finished 4, up 5, attempts 6, spawned 7, " ++
        "neighbour up 8, broadcasts received 9, blob transfers completed 10, " ++
        "blob sent bytes 11, blob received bytes 12";
    const line = "progress: " ++ fields;
    const parsed = progress_ns.parseProgress(line) orelse return error.TestUnexpectedResult;
    try t.expectEqualSlices(u64, &.{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 }, &parsed.counts);

    const rejected = [_][]const u8{
        // The deleted custom relay schema must not remain a second accepted format.
        "progress: dials 1, refused 2, accepted 3, finished 4, up 5, admitted 6, " ++
            "established 7, registered 8, sent 9, received 10, forwarded 11, attempts 12, " ++
            "spawned 13, disconnected 14, closed 15",
        "state: " ++ fields,
        " progress: " ++ fields,
        "progress:" ++ fields,
        "progress: dials nope, refused 2, accepted 3, finished 4, up 5, attempts 6, " ++
            "spawned 7, neighbour up 8, broadcasts received 9, blob transfers completed 10, " ++
            "blob sent bytes 11, blob received bytes 12",
        "progress: dials , refused 2, accepted 3, finished 4, up 5, attempts 6, " ++
            "spawned 7, neighbour up 8, broadcasts received 9, blob transfers completed 10, " ++
            "blob sent bytes 11, blob received bytes 12",
        "progress: dials -1, refused 2, accepted 3, finished 4, up 5, attempts 6, " ++
            "spawned 7, neighbour up 8, broadcasts received 9, blob transfers completed 10, " ++
            "blob sent bytes 11, blob received bytes 12",
        "progress: dials 18446744073709551616, refused 2, accepted 3, finished 4, up 5, " ++
            "attempts 6, spawned 7, neighbour up 8, broadcasts received 9, " ++
            "blob transfers completed 10, blob sent bytes 11, blob received bytes 12",
        "progress: refused 2, dials 1, accepted 3, finished 4, up 5, attempts 6, spawned 7, " ++
            "neighbour up 8, broadcasts received 9, blob transfers completed 10, " ++
            "blob sent bytes 11, blob received bytes 12",
        "progress: dials 1, refused 2, accepted 3, finished 4, up 5, attempts 6, spawned 7, " ++
            "neighbour up 8, broadcasts received 9, blob transfers completed 10, blob sent bytes 11",
        line ++ ", obsolete 13",
        line ++ ", ",
        line ++ " trailing",
    };
    for (rejected) |invalid| {
        try t.expectEqual(@as(?progress_ns.Progress, null), progress_ns.parseProgress(invalid));
    }
}
