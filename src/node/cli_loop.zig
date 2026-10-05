//! The loop this program drives itself, the signals that stop it, and the clock
//! both read.
//!
//! `Node.run` is the right loop for a node with nothing to say between two
//! passes, and this program has something to say: the datagram `--send` named
//! goes on the wire as soon as the relay connection is up. So `drive` runs the
//! passes in `run`'s order and is `run` plus that one duty and minus its close
//! — the close is the caller's, because the caller has to read what was still
//! standing before it runs. `shut` is that close, measured either side of itself.

const std = @import("std");

const ozai = @import("ozai");
const cli_values = @import("cli_values.zig");
const cli_report = @import("cli_report.zig");

const node_mod = ozai.node;
const Node = node_mod.Node;
const Stop = node_mod.Stop;
const Instant = ozai.transport_quic_bridge.Instant;
const CliError = cli_values.CliError;
const Send = cli_values.Send;
const Close = cli_report.Close;

const Progress = @import("progress.zig").Snapshot;

/// The stop signal, at file scope because a C signal handler is handed nothing
/// but the signal number.
///
/// `std.posix.Sigaction.handler_fn` takes a `SIG` and nothing else, so the
/// handle the handler sets has to be somewhere the handler can name, and
/// "somewhere" is process-wide. It is here, in the program and not in the
/// library, because this is the program edge: the library holds no global, no
/// `std.Io` and no clock, and a second loop in the same process gets its own
/// handle by giving `run` another `Stop` of its own.
pub var stopped = Stop.init();

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
/// allow: at one `Node.poll_interval_ms` apiece this is five seconds of
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
pub fn watchForStop() void {
    const act: std.posix.Sigaction = .{
        .handler = .{ .handler = onSignal },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    for (stop_signals) |sig| {
        std.posix.sigaction(sig, &act, null);
    }
}

/// The monotonic clock as the core is driven at, in nanoseconds.
///
/// Read only here and only by the program edge: `Node.step` takes its instant
/// as data, and this is the one place a value for it comes from. `Clock.awake`
/// rather than `.real` because a QUIC timer must not jump because NTP moved
/// the wall clock.
pub fn nowNs(io: std.Io) CliError!Instant {
    const stamp = std.Io.Clock.awake.now(io);
    return std.math.cast(Instant, stamp.nanoseconds) orelse error.NoClock;
}

/// The loop, and the one duty `Node.run` has no place for.
///
/// `run` is the right loop for a node with nothing to say between two passes,
/// and this node has something to say: the datagram `--send` named goes on the
/// wire as soon as the relay connection is up. So the program drives the
/// passes itself, in `run`'s order, and this is `run` plus that one duty and
/// minus its close — the close is the caller's, because the caller has to read
/// what was still standing before it runs.
pub fn drive(
    io: std.Io,
    node: *Node,
    send: ?Send,
    progress: ?*std.Io.Writer,
) (node_mod.Error || CliError || std.Io.Writer.Error)!void {
    var dialled = false;
    var offered = false;
    var retried: u64 = 0;
    var previous: ?Progress = null;
    // What the relay had answered about absent peers when the datagram went
    // out, so one answer is one re-offer rather than one per pass after it.
    var told_gone: u64 = 0;
    while (true) {
        const at = try nowNs(io);
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
pub fn shut(
    io: std.Io,
    node: *Node,
    owed: usize,
) (node_mod.Error || CliError)!Close {
    const before = node.stats.datagrams_out;
    try node.close(io, try nowNs(io), node.generator());
    return .{ .connections = owed, .datagrams = node.stats.datagrams_out - before };
}
