//! `ozai-node`: the first ozai program.
//!
//! Run it with `zig build run-ozai-node`. It starts a node, says who it is and
//! where it is listening, dials whatever peers it was given, and then drives
//! its own loop until a stop is asked for — at which point it winds down
//! through the router's ordering and exits.
//!
//! The grammar is `cli.zig` and `cli_values.zig`: pure parsers handed the
//! arguments and a writer, reading nothing else. Everything below is the
//! program edge — the runtime, the loop, and what a run reports.
//!
//! # What it does and what it does not
//!
//! It serves. The socket is real, the QUIC core is driven over it, peers are
//! dialled, and an arriving connection goes through the filter, the router's
//! ALPN dispatch and the handler's `accept` — every `Action`
//! `endpoint/endpoint.zig` owes a caller for, performed by
//! `src/node/node.zig`'s loop.
//!
//! It does **not** gossip on the wire, and it says so on the way out rather
//! than letting a reader infer it from silence. The gossip state machine runs
//! for as long as the node does; `src/gossip/hyparview.zig` has no codec, and
//! the only encoder in this repository belongs to a test and is explicitly not
//! the project's wire format. So every message membership asks to be sent is
//! counted and printed, and that count is the whole of what happened to it.
//!
//! # The stop signal
//!
//! `SIGINT` and `SIGTERM` set one atomic flag, and the loop reads it between
//! passes. A `poll` retries a signal rather than letting it out
//! (`socket.zig`'s `awaitReadable`), so a stop is acted on at the next
//! `Node.poll_interval_ms` and not at the next datagram. `--for` sets a
//! deadline on the same value instead, which is what makes this runnable from
//! a script without anybody having to signal it.
//!
//! # The close, and what it promises
//!
//! A stop ends this program with one `Node.close`, and that call is the whole
//! of the way a peer is told: one CONNECTION_CLOSE per connection, written
//! once, and then the socket is shut — the same call, at one instant
//! (`node.zig`'s `.close_endpoint`). Nothing here retries it, confirms it or
//! waits for it, and that is a decision rather than an omission.
//!
//! There is nothing to wait *for*: RFC 9000 gives a close no acknowledgement,
//! because CONNECTION_CLOSE is not ack-eliciting, and a peer that takes one is
//! in the draining state with nothing left to say. Nor is there anything to
//! wait *with*: the core retransmits a close only when a packet arrives
//! (`vendor/quic`'s `sendAt`, on `needs_close_retransmit`), so a window after
//! the close cannot produce a second datagram — and the socket is shut before
//! such a window opens. A window would in any case make this process worse
//! rather than the peer better informed: a node that will not exit is a worse
//! neighbour than one that exits having lost a close.
//!
//! **So the loss is bounded, and the bound is printed.** One datagram per
//! connection, written once, at the last instant this process has. A peer that
//! misses one keeps the connection until its own idle timeout — thirty seconds
//! in this project's transport configuration — and nothing here shortens that.
//! `close:` in the report is how many connections were owed one and how many
//! datagrams actually said so, measured either side of `Node.close`, which is
//! the only place a caller can measure it.
//!
//! # The relay, and the datagram in its place
//!
//! `--relay` makes this process a relay: it admits clients, forwards the
//! datagrams between them, and answers the challenge that admits one.
//! `--relay-peer <nodeid>@<url>` makes it a client of a relay it was given a
//! **URL** for, which is all a peer holds — `RelayUrl.socketAddr` is the step
//! from that URL to the socket the dial is told, it refuses a host that is a
//! name outright, and the refusal is this program's answer on a line rather
//! than a stack trace.
//!
//! A node speaks one protocol and a relay cannot also gossip (`node.zig`'s own
//! reason), so a relay flag picks the ALPN and a command line that also asked
//! for one is refused rather than half-honoured.
//!
//! `--send <nodeid>:<bytes>` puts one datagram on that wire. **Writing a
//! gossip message is the codec's job and the codec does not exist**, so a
//! caller who wants to see the wire move asks for a datagram by hand and this
//! program writes it: when the relay connection is up, and again on the passes
//! after a relay says the peer is not there yet, which is what a relay does
//! with a datagram for a peer it has not admitted and the reason two nodes can
//! race for one relay. It is also why the program drives its own loop —
//! `Node.run` has no place between two passes, and this program's one duty is
//! between two of them.
//!
//! That wire is the one a client holds to a relay, so `--send` names the same
//! thing `--relay-peer` does and a line carrying it without one is refused:
//! `--relay` is the far end of that wire rather than a peer of it, and a node
//! that was never told of a relay has no wire to put a datagram on at all.

const std = @import("std");
const builtin = @import("builtin");
const ozai = @import("ozai");
const coverage_abi = @import("coverage_abi");

// Coverage links the fuzz runtime even though this CLI starts no fuzz session.
// Force its fail-fast ABI exports only then; a plain build has no dependency
// on this module and never resolves the lazy import.
comptime {
    if (builtin.fuzz) _ = coverage_abi;
}

const node_mod = ozai.node;
const Node = node_mod.Node;
const Stop = node_mod.Stop;
const Instant = ozai.transport_quic_bridge.Instant;

const SecretKey = ozai.SecretKey;

const cli = @import("cli.zig");
const Progress = @import("progress.zig").Snapshot;

/// How loud this program is.
///
/// The vendored QUIC core logs every handshake step at `info` and every
/// received frame at `debug`, which is the right thing for a library with no
/// opinion and the wrong thing for a binary whose own report is six lines
/// long. `std_options` in the root is what a program has to say; a library must
/// not, because it would be deciding for every importer that imported it.
pub const std_options: std.Options = .{ .log_level = .warn };

/// The stop signal, at file scope because a C signal handler is handed nothing
/// but the signal number.
///
/// `std.posix.Sigaction.handler_fn` takes a `SIG` and nothing else, so the
/// handle the handler sets has to be somewhere the handler can name, and
/// "somewhere" is process-wide. It is here rather than in `src/node/` because
/// this is the program edge: the library holds no global, no `std.Io` and no
/// clock, and a second loop in the same process gets its own handle by giving
/// `run` another `Stop` of its own.
var stopped = Stop.init();

/// The signals a process is asked to stop on. `SIGTERM` is here because a
/// supervisor's stop is a `SIGTERM` and a binary that only answers `SIGINT`
/// has to be killed.
const stop_signals = [_]std.posix.SIG{ .INT, .TERM };

/// How many datagrams a report prints, and how many bytes of each.
///
/// A datagram is up to `Node.max_datagram` bytes and a report is read by a
/// person and by a test, so the bytes are hexed and cut: enough to see that
/// the payload arrived, and a count of what was not shown.
const inbox_datagrams_printed: usize = 4;
const inbox_bytes_printed: usize = 24;

/// How many passes a `--send` datagram is re-offered on while the relay says
/// that peer is not there.
///
/// A relay forwards to a client it holds, and a peer that has not reached it
/// yet is not one it holds: the frame comes back as `peer_gone` and the
/// datagram is dropped, which is upstream's behaviour and the reason a peer's
/// first datagram can be lost to a relay that is perfectly healthy. Two nodes
/// racing to reach one relay is the ordinary case and not a fault, so the
/// answer is to offer the datagram again on the next pass — which is what
/// upstream's client does with the same message.
///
/// Bounded because a loop with no bound is a loop `AGENTS.md` §1 does not
/// allow: at one `Node.poll_interval_ms` apiece this is five seconds of
/// offering, which is longer than any relay handshake measured on this machine
/// and longer than the run a caller who named a peer has usually asked for.
const max_send_passes: u64 = 20;

/// How many of this node's closes a peer acknowledged: none, ever.
///
/// **A constant, and printed rather than assumed**, because it is the finding
/// and not a counter — CONNECTION_CLOSE is not ack-eliciting (RFC 9000 §19.3),
/// so a peer never ACKs one and the best it can do is go quiet. A report that
/// counted acknowledgements without saying there are none would read as though
/// the number could move. See `reportClose`.
const closes_acknowledged: u64 = 0;

/// What the relay was still holding when this node was asked to stop.
///
/// Read before the close and printed after it, because the two ends of a run
/// answer different questions. By the time a report is written this node's own
/// shutdown has given every client and every connection away, so a count read
/// then is the same for a peer that left while this node was running and for
/// one that was still there. Read here they differ, and that difference is the
/// only thing a caller on the other side of a pipe can use to say that a
/// survivor noticed.
const Holding = struct {
    /// Node ids in this relay's registry: its clients, or none for a node that
    /// is not one.
    node_ids: usize,
    /// Connections the core still held, whoever opened them.
    connections: usize,
};

/// What the shutdown owed a peer, and what it wrote for it.
///
/// Measured either side of `Node.close` rather than asked of the node
/// afterwards, because a close is the one thing the node does that leaves no
/// counter of its own: it is a drain on the way out and not a pass, so the
/// difference in the report's own `datagrams out` is the whole of what it put
/// on the wire.
const Close = struct {
    /// Connections the shutdown still owed a CONNECTION_CLOSE, read with
    /// `Node.establishedCount` before the close. **Zero here does not mean
    /// the core held nothing**: a connection the core has already given up is
    /// one with nothing left to say, so it is not counted and its close wrote
    /// no datagram either. That is why these two numbers read zero together.
    connections: usize,
    /// Datagrams written for them. At least one apiece, and more for a
    /// connection still handshaking, which the core tells at every encryption
    /// level it holds rather than only the one it would prefer.
    datagrams: u64,
};

/// A `SIGINT` or a `SIGTERM`: set the flag and return.
///
/// Async-signal-safe, because `Stop.request` is one atomic store and nothing
/// else — which is the only reason that function exists in that shape.
fn onSignal(sig: std.posix.SIG) callconv(.c) void {
    // The C ABI hands every handler the signal it was called for and nothing
    // else to do with it: this one sets the same flag for both, so the number
    // is information nobody here acts on.
    _ = sig;
    stopped.request();
}

/// Ask to be stopped on `SIGINT` and `SIGTERM`, replacing the default action
/// for both. The default for `SIGTERM` is to die, and dying is the ungraceful
/// exit `docs/DECISIONS/0001` records as an error rather than a cleanup.
fn watchForStop() void {
    const act: std.posix.Sigaction = .{
        .handler = .{ .handler = onSignal },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    for (stop_signals) |sig| {
        std.posix.sigaction(sig, &act, null);
    }
}

/// What the program edge refuses on its own, over the ones the parser and
/// `Node` publish.
///
/// Only the clock is here, and it is not in `cli.Error` because it is a fact
/// about the runtime rather than about a value a caller wrote — which is the
/// same reason a pure parser cannot raise it.
const RuntimeError = error{
    /// The monotonic clock could not be read, or read a value `Instant` cannot
    /// hold.
    NoClock,
};

/// The monotonic clock as the core is driven at, in nanoseconds.
///
/// Read only here and only by the program edge: `Node.step` takes its instant
/// as data, and this is the one place a value for it comes from. `Clock.awake`
/// rather than `.real` because a QUIC timer must not jump because NTP moved
/// the wall clock.
fn nowNs(io: std.Io) RuntimeError!Instant {
    const stamp = std.Io.Clock.awake.now(io);
    return std.math.cast(Instant, stamp.nanoseconds) orelse error.NoClock;
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var out_buffer: [512]u8 = undefined;
    var out = std.Io.File.stdout().writerStreaming(io, &out_buffer);
    const text = &out.interface;

    const options = switch (try cli.Options.parse(
        init.arena.allocator(),
        init.minimal.args,
        text,
    )) {
        .run => |run| run,
        .help => {
            try out.flush();
            return;
        },
        .rejected => |err| {
            try out.flush();
            // `std.process.exit` rather than an error return: a usage error is
            // the program's own answer, and a stack trace over it is noise a
            // caller has to learn to ignore.
            std.process.exit(1);
            err;
        },
    };

    // Which half of the relay handshake this process runs, and the protocol
    // that half speaks. Both come from the command line and nowhere else, and
    // the parser has already refused a line that asked for two of anything, so
    // this is a choice rather than a guess.
    const role: node_mod.Role = if (options.serve)
        .{ .serve = .{} }
    else if (options.relay_peer) |target|
        .{ .client = target.peer }
    else
        .off;
    const alpn = options.alpn orelse switch (role) {
        .off => node_mod.gossip_alpn,
        .serve, .client => node_mod.relay_alpn,
    };

    // Drawn rather than demanded, and printed either way: a node that cannot
    // say who it is is not a node, and a caller that wants a fixed identity
    // passes `--key-seed`.
    //
    // No fallback generator: `generate` draws the seed from `io.randomSecure`,
    // and a node that cannot be given a secure identity must not run.
    var secret = options.secret orelse try SecretKey.generate(io);
    defer secret.deinit();

    const node = try Node.create(init.gpa, io, .{
        .secret = secret,
        .listen = options.listen,
        .peers = options.peers.items,
        .alpn = alpn,
        .relay = .{ .role = role },
    });
    defer node.deinit();

    // From this line the node owns an open descriptor, so every exit that is
    // not the graceful one owes it a teardown — the banner writes included, not
    // only the loop. Cleared on the graceful path so a normal run is wound down
    // exactly once: `shut` below is this node's deliberate close.
    //
    // The close is stamped with the instant the last pass ran at, the only one
    // true of the connections those passes built. Null until the first pass
    // reads one, and `windDown` reads that as "no instant to stamp with" rather
    // than as "no teardown".
    var last: ?Instant = null;
    var wound_down = false;
    errdefer if (!wound_down) node.windDown(io, last);

    // A supervisor may signal as soon as the listening banner reaches its pipe.
    watchForStop();

    try text.print("node       {f}\n", .{node.nodeId()});
    try text.print("z-base-32  {s}\n", .{node.nodeId().toZ32()});
    try text.print("listening  {f}\n", .{node.address()});
    try text.print("alpn       {s}\n", .{alpn});
    try sayRole(text, options);

    if (options.peers.items.len == 0) {
        try text.writeAll("peers      none — this node answers and is ready to be asked\n");
    } else {
        for (options.peers.items) |peer| {
            try text.print("peer       {f} at {f}\n", .{ peer.id, peer.addr });
        }
    }
    try text.print("running    {d} ms, then a graceful close\n", .{options.run_ms});
    try text.writeAll(
        \\
        \\not wired: the gossip wire codec. The membership state machine runs for
        \\as long as this node does and every message it asks to be sent is
        \\counted below; none of them goes on the wire, because this project has
        \\no gossip wire format yet. See src/node/node.zig's module doc.
        \\
    );
    try out.flush();

    const started = try nowNs(io);
    stopped.expireAt(started + options.run_ms * std.time.ns_per_ms);

    try drive(io, node, options.send, if (options.progress) text else null, &last);
    // Read here, before the close that will empty both of these: see `Holding`.
    const holding: Holding = .{
        .node_ids = node.clientCount(),
        .connections = node.establishedCount(),
    };
    // And what the close wrote, measured across that call rather than read
    // after it, for the same reason and because nothing is left to read: see
    // `shut`.
    const close = try shut(io, node, holding.connections);
    // Cleared before the report so a failure in reporting cannot run the guard
    // over a node that is already closed and log about a second shutdown.
    wound_down = true;

    try report(text, node, holding, close);
    try out.flush();
}

/// The banner's one line about relays, in the spelling the command line used.
///
/// A URL for a client because that is the fact a caller can act on — the
/// socket it resolved to is in the report, and a caller who named a relay this
/// program did not reach can see that here rather than having to trust a dial
/// nobody outside this process can watch.
fn sayRole(text: *std.Io.Writer, options: cli.Options) !void {
    if (options.serve) {
        try text.print(
            "relay      serving {d} clients, {d} datagrams deep\n",
            .{ node_mod.max_relay_clients, node_mod.default_relay_queue_depth },
        );
    } else if (options.relay_peer) |target| {
        try text.print("relay      client of {f} at {s}\n", .{ target.peer.id, target.url });
    } else {
        try text.writeAll("relay      none — this node is dialled at its own address\n");
    }
}

/// The loop, and the one duty `Node.run` has no place for.
///
/// `run` is the right loop for a node with nothing to say between two passes,
/// and this node has something to say: the datagram `--send` named goes on the
/// wire as soon as the relay connection is up. So the program drives the
/// passes itself, in `run`'s order, and this is `run` plus that one duty and
/// minus its close — the close is the caller's, because the caller has to read
/// what was still standing before it runs.
///
/// A failing pass leaves this loop through `main`, whose guard winds the node
/// down — `run` can keep that guard to itself only because the close is inside
/// it.
///
/// **`at` is carried out of the loop rather than read again here**, and that is
/// the point of the local: a close stamped with a second clock read is a close
/// on a time this process had already moved past.
fn drive(
    io: std.Io,
    node: *Node,
    send: ?cli.Send,
    progress: ?*std.Io.Writer,
    last: *?Instant,
) (node_mod.Error || RuntimeError || std.Io.Writer.Error)!void {
    var dialled = false;
    var offered = false;
    var retried: u64 = 0;
    var previous: ?Progress = null;
    // What the relay had answered about absent peers when the datagram went
    // out, so one answer is one re-offer rather than one per pass after it.
    var told_gone: u64 = 0;
    while (true) {
        const at = try nowNs(io);
        last.* = at;
        if (stopped.expired(at)) break;
        // The dials on the first pass, for `run`'s reason: a stop raised before
        // the loop is entered closes a node that never dialled.
        if (!dialled) {
            dialled = true;
            try node.start(at, node.generator());
        }
        // Before the pass rather than after it, so the frame is in a stream the
        // core owns before the pass that drains that stream runs.
        if (send) |out| {
            const answered = node.stats.relay_peer_gone;
            if (!offered and node.stats.relay_established > 0) {
                try node.sendThrough(out.peer, out.bytes);
                offered = true;
                told_gone = answered;
            } else if (offered and answered > told_gone and retried < max_send_passes) {
                // The relay said that peer is not there, so the datagram was
                // dropped rather than queued: see `max_send_passes` for why the
                // answer is to offer it again.
                try node.sendThrough(out.peer, out.bytes);
                told_gone = answered;
                retried += 1;
            }
        }
        _ = try node.step(io, at, node.generator());
        if (progress) |writer| {
            const current = Progress.capture(node);
            if (previous == null or !std.meta.eql(previous.?, current)) {
                try writer.print("{f}", .{&current});
                try writer.flush();
                previous = current;
            }
        }
        try node.wait(io, node_mod.poll_interval_ms);
    }
}

/// Wind the node down, and measure what that wrote.
///
/// One call, one instant, and the whole of the shutdown inside it: a
/// CONNECTION_CLOSE per connection, each written once, and then the socket is
/// shut. There is no window here to keep the node alive in and nothing this
/// could pump with — the module doc gives both, and they are why this is a
/// measurement rather than a wait.
///
/// `owed` is the caller's read of the connections still held, taken before the
/// close because afterwards the core holds none and the question has no answer
/// left to give.
fn shut(
    io: std.Io,
    node: *Node,
    owed: usize,
) (node_mod.Error || RuntimeError)!Close {
    const before = node.stats.datagrams_out;
    try node.close(io, try nowNs(io), node.generator());
    return .{ .connections = owed, .datagrams = node.stats.datagrams_out - before };
}

/// What the run did, and how it ended.
///
/// Every line here is a number a caller of `Node` could not get any other way,
/// and the two counters that stop at a count are printed next to what they
/// would have been had the codec existed — so the gap is visible rather than
/// inferred from the absence of traffic.
fn report(
    text: *std.Io.Writer,
    node: *const Node,
    holding: Holding,
    close: Close,
) !void {
    const stats = node.stats;
    try reportRelay(text, node, holding);
    try text.print(
        \\
        \\stopped: {d} passes, {d} datagrams in, {d} out ({d} degraded, {d} codepoints lost)
        \\accept loop: {d} attempts, {d} spawned, {d} handler connections
        \\  {d} refusals, {d} ignores
        \\dials: {d} of {d} refused; {d} connections finished
        \\gossip: {d} events, {d} timers scheduled, {d} fired
        \\  {d} membership and {d} broadcast messages asked for and not sent
        \\  neighbour up {d}, down {d}; broadcasts received {d}; peer data {d}
        \\shutdown: {t}, {d} handler shutdowns, {d} accepts cancelled, socket {s}
        \\
    , .{
        stats.steps,
        stats.datagrams_in,
        stats.datagrams_out,
        stats.sends_degraded,
        stats.ecn_lost,
        stats.attempts,
        stats.spawned,
        stats.handler_connections,
        stats.refusals,
        stats.ignores,
        stats.dials,
        stats.dials_refused,
        stats.connections_finished,
        stats.gossip_events,
        stats.gossip_timers_scheduled,
        stats.gossip_timers_fired,
        stats.gossip_membership_asked,
        stats.gossip_broadcast_asked,
        stats.neighbor_up,
        stats.neighbor_down,
        stats.broadcasts_received,
        stats.peer_data_seen,
        node.accept.shutdown.phase,
        stats.handler_shutdowns,
        stats.accepts_cancelled,
        if (node.socket_open) "still open" else "closed",
    });
    try reportClose(text, close);

    if (node.namedPeers().len == 0) return;
    try text.writeAll("gossip named: ");
    for (node.namedPeers(), 0..) |peer, index| {
        if (index > 0) try text.writeAll(", ");
        try text.print("{f}", .{peer});
    }
    try text.writeAll("\n");
}

/// What the shutdown wrote, and the answer it will never be given.
///
/// The three numbers are the loss's whole extent and the only truth available
/// about it: what was owed a close, what was written for it, and what came
/// back — which is nothing, because nothing comes back. All three are printed
/// at zero as well, because a node with nothing to tell and a node whose close
/// may never have landed are different reports, and the one that printed
/// nothing at all is how a reader would have to guess which it was.
fn reportClose(text: *std.Io.Writer, close: Close) !void {
    try text.print(
        "close: {d} connections owed, {d} close datagrams written, " ++
            "{d} acknowledged by any peer\n",
        .{ close.connections, close.datagrams, closes_acknowledged },
    );
}

/// What the relay did, and what of it was still standing at the stop.
///
/// The role is the first line and it is printed for every node, because a node
/// that cannot relay and a node that relayed nothing are told apart by that
/// line and not by the absence of traffic under it. The rest is the role's own
/// counters, and a node that is not a relay has none of them to print.
///
/// **Every count carries its own name before it**, which is what the rest of
/// this report does and what a reader of one expects: "refused 0" is a refusal
/// that did not happen, and "0 refused" is the same fact with the words on the
/// wrong side of the number. It is also what lets a caller that is not a person
/// — `test/two_process_test.zig` reads these lines by label — ask for one
/// counter without counting the ones in front of it.
///
/// A client's line says the socket its URL resolved to, and the banner said
/// the URL: the two are printed from the two places that own them because a
/// report showing only one of them would be half an address.
fn reportRelay(text: *std.Io.Writer, node: *const Node, holding: Holding) !void {
    const stats = node.stats;
    switch (node.config.relay.role) {
        .off => try text.writeAll(
            "relay: none — this node is dialled at its own address\n",
        ),
        .serve => {
            try text.print(
                "relay: serving {d} clients, {d} datagrams deep\n",
                .{ node_mod.max_relay_clients, node_mod.default_relay_queue_depth },
            );
            try text.print(
                "relay in: admitted {d}, replaced {d}, promoted {d}, refused {d}, " ++
                    "deferred {d}\n",
                .{
                    stats.relay_admitted,
                    stats.relay_replaced,
                    stats.relay_promoted,
                    stats.relay_refused,
                    stats.relay_stream_deferred,
                },
            );
            try text.print(
                "relay held: node ids {d}, connections up {d}, at the stop\n",
                .{ holding.node_ids, holding.connections },
            );
            try text.print(
                "relay out: read {d}, forwarded {d}, unknown target {d}, " ++
                    "full queue {d}, oversized {d}\n",
                .{
                    stats.relay_datagrams_in,
                    stats.relay_forwarded,
                    stats.relay_unknown_target,
                    stats.relay_queue_full,
                    stats.relay_oversized,
                },
            );
            try text.print(
                "relay away: disconnects {d}, already gone {d}, told displaced {d}, " ++
                    "promoted {d}\n",
                .{
                    stats.relay_disconnects,
                    stats.relay_double_reports,
                    stats.relay_told_displaced,
                    stats.relay_promoted,
                },
            );
        },
        .client => |peer| {
            try text.print(
                "relay: client of {f} at {f}\n",
                .{ peer.id, peer.addr },
            );
            try text.print(
                "relay in: dialled {d}, refused {d}, auth sent {d}, established {d}, " ++
                    "displaced {d}, peer gone {d}\n",
                .{
                    stats.relay_dials,
                    stats.relay_dials_refused,
                    stats.relay_auth_sent,
                    stats.relay_established,
                    stats.relay_displaced,
                    stats.relay_peer_gone,
                },
            );
            // The connections, and not a registry: a client has none, so
            // `Holding` carries a zero for it that this line does not print.
            try text.print(
                "relay held: connections up {d}, at the stop\n",
                .{holding.connections},
            );
            try text.print(
                "relay out: sent {d}, handed to this node {d}\n",
                .{ stats.relay_sent, stats.relay_datagrams_out },
            );
            try text.print(
                "relay away: closed by the relay {d}, duplicate reports {d}\n",
                .{ stats.relay_closed, stats.relay_double_reports },
            );
        },
    }
    try reportInbox(text, node);
}

/// What this node's relay handed back, oldest first.
///
/// The payloads are hexed and cut: a datagram is up to `Node.max_datagram`
/// bytes, and a report is read by a person and by a test, and both want the
/// first bytes and the length rather than the whole thing. A node that was
/// handed nothing prints nothing here — the count above already says zero —
/// and a node that was handed more than `inbox_datagrams_printed` says how
/// many it did not print, because a count that stops is a lie about the rest.
fn reportInbox(text: *std.Io.Writer, node: *const Node) !void {
    const handed = node.delivered();
    if (handed.len == 0) return;
    var bytes: usize = 0;
    var cut: usize = 0;
    for (handed) |item| {
        bytes += item.data.len;
        if (item.data.len > inbox_bytes_printed) cut += 1;
    }
    try text.print(
        "relay inbox: datagrams {d}, bytes in all {d}",
        .{ handed.len, bytes },
    );
    if (cut != 0) {
        try text.print(", hex cut to {d} bytes on {d} of them", .{
            inbox_bytes_printed,
            cut,
        });
    }
    try text.writeAll("\n");
    for (handed, 0..) |item, index| {
        if (index == inbox_datagrams_printed) {
            try text.print(
                "relay inbox: {d} more datagrams, not printed\n",
                .{handed.len - index},
            );
            return;
        }
        try text.print(
            "relay inbox[{d}]: bytes {d} from {f} {x}\n",
            .{
                index,
                item.data.len,
                item.src,
                item.data[0..@min(item.data.len, inbox_bytes_printed)],
            },
        );
    }
}
