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
//! `src/node/node_runtime.zig`'s loop.
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
//! `node_config.poll_interval_ms` and not at the next datagram. `--for` sets a
//! deadline on the same value instead, which is what makes this runnable from
//! a script without anybody having to signal it.
//!
//! # The close, and what it promises
//!
//! A stop ends this program with one `node_close.close`, and that call is the whole
//! of the way a peer is told: one CONNECTION_CLOSE per connection, written
//! once, and then the socket is shut — the same call, at one instant
//! (`node_dispatch.zig`'s `.close_endpoint`). Nothing here retries it, confirms it or
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
//! datagrams actually said so, measured either side of `node_close.close`, which is
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
//! A relay flag picks the protocol — `node_config.Config.protocols` may hold more
//! than one, and this program configures one — so a command line that also
//! asked for one beside a relay role is refused rather than half-honoured.
//!
//! `--send <nodeid>:<bytes>` puts one datagram on that wire. **Writing a
//! gossip message is the codec's job and the codec does not exist**, so a
//! caller who wants to see the wire move asks for a datagram by hand and this
//! program writes it: when the relay connection is up, and again on the passes
//! after a relay says the peer is not there yet, which is what a relay does
//! with a datagram for a peer it has not admitted and the reason two nodes can
//! race for one relay. It is also why the program drives its own loop —
//! `node_runtime.run` has no place between two passes, and this program's one duty is
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
const Instant = ozai.transport_quic_conn.Instant;

const SecretKey = ozai.SecretKey;

const cli = @import("cli.zig");
const Progress = @import("progress.zig").Snapshot;
const lifecycle = ozai.node_lifecycle;
const runtime = ozai.node_runtime;
const node_close = ozai.node_close;
const node_error = ozai.node_error;
const config = ozai.node_config;
const protocol = ozai.node_protocol;
const relay_client = ozai.node_relay_client;
const node_report = ozai.node_report;

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
/// allow: at one `node_config.poll_interval_ms` apiece this is five seconds of
/// offering, which is longer than any relay handshake measured on this machine
/// and longer than the run a caller who named a peer has usually asked for.
const max_send_passes: u64 = 20;

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
/// Read only here and only by the program edge: `node_runtime.step` takes its instant
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
    const role: config.Role = if (options.serve)
        .{ .serve = .{} }
    else if (options.relay_peer) |target|
        .{ .client = target.peer }
    else
        .off;
    const alpn = options.alpn orelse switch (role) {
        .off => protocol.gossip_alpn,
        .serve, .client => protocol.relay_alpn,
    };

    // Drawn rather than demanded, and printed either way: a node that cannot
    // say who it is is not a node, and a caller that wants a fixed identity
    // passes `--key-seed`.
    //
    // No fallback generator: `generate` draws the seed from `io.randomSecure`,
    // and a node that cannot be given a secure identity must not run.
    var secret = options.secret orelse try SecretKey.generate(io);
    defer secret.deinit();

    const node = try lifecycle.create(init.gpa, io, .{
        .secret = secret,
        .listen = options.listen,
        .peers = options.peers.items,
        // The CLI names one protocol and the node takes registrations, so the
        // flag's answer is a one-element list of a built-in rather than a second
        // spelling of it. A caller that wants a protocol of its own configures
        // `Config.protocols` directly, with a handler beside the ALPN.
        .protocols = &.{.{ .alpn = alpn }},
        .relay = .{ .role = role },
    });
    defer lifecycle.deinit(node);

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
    errdefer if (!wound_down) runtime.windDown(io, node, last);

    // A supervisor may signal as soon as the listening banner reaches its pipe.
    watchForStop();

    try text.print("node       {f}\n", .{node_mod.nodeId(node)});
    try text.print("z-base-32  {s}\n", .{node_mod.nodeId(node).toZ32()});
    try text.print("listening  {f}\n", .{node_mod.address(node)});
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
    // Read here, before the close that empties both: see `node_report.Holding`.
    const holding: node_report.Holding = .{
        .node_ids = relay_client.clientCount(node),
        .connections = node_mod.establishedCount(node),
    };
    // And what the close wrote, measured across that call rather than read
    // after it, for the same reason and because nothing is left to read: see
    // `shut`.
    const close = try shut(io, node, holding.connections);
    // Cleared before the report so a failure in reporting cannot run the guard
    // over a node that is already closed and log about a second shutdown.
    wound_down = true;

    try node_report.report(text, node, holding, close);
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
            .{ config.max_relay_clients, config.default_relay_queue_depth },
        );
    } else if (options.relay_peer) |target| {
        try text.print("relay      client of {f} at {s}\n", .{ target.peer.id, target.url });
    } else {
        try text.writeAll("relay      none — this node is dialled at its own address\n");
    }
}

/// The loop, and the one duty `node_runtime.run` has no place for.
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
) (node_error.Error || RuntimeError || std.Io.Writer.Error)!void {
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
            try runtime.start(node, at, node_mod.generator(node));
        }
        // Before the pass rather than after it, so the frame is in a stream the
        // core owns before the pass that drains that stream runs.
        if (send) |out| {
            const answered = node.stats.relay_peer_gone;
            if (!offered and node.stats.relay_established > 0) {
                try relay_client.sendThrough(node, out.peer, out.bytes);
                offered = true;
                told_gone = answered;
            } else if (offered and answered > told_gone and retried < max_send_passes) {
                // The relay said that peer is not there, so the datagram was
                // dropped rather than queued: see `max_send_passes` for why the
                // answer is to offer it again.
                try relay_client.sendThrough(node, out.peer, out.bytes);
                told_gone = answered;
                retried += 1;
            }
        }
        _ = try runtime.step(io, node, at, node_mod.generator(node));
        if (progress) |writer| {
            const current = Progress.capture(node);
            if (previous == null or !std.meta.eql(previous.?, current)) {
                try writer.print("{f}", .{&current});
                try writer.flush();
                previous = current;
            }
        }
        try runtime.wait(io, node, config.poll_interval_ms);
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
) (node_error.Error || RuntimeError)!node_report.Close {
    const before = node.stats.datagrams_out;
    try node_close.close(io, node, try nowNs(io), node_mod.generator(node));
    return .{ .connections = owed, .datagrams = node.stats.datagrams_out - before };
}
