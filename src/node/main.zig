//! `ozai-node`: the first ozai program.
//!
//! Run it with `zig build run-ozai-node`. It starts a node, says who it is and
//! where it is listening, dials whatever peers it was given, and then drives
//! its own loop until a stop is asked for — at which point it winds down
//! through the router's ordering and exits.
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

const std = @import("std");
const ozai = @import("ozai");

const node_mod = ozai.node;
const Node = node_mod.Node;
const Peer = node_mod.Peer;
const Stop = node_mod.Stop;
const Instant = ozai.transport_quic_bridge.Instant;

const NodeId = ozai.NodeId;
const SecretKey = ozai.SecretKey;
const SocketAddr = ozai.SocketAddr;

/// How loud this program is.
///
/// The vendored QUIC core logs every handshake step at `info` and every
/// received frame at `debug`, which is the right thing for a library with no
/// opinion and the wrong thing for a binary whose own report is six lines
/// long. `std_options` in the root is what a program has to say; a library must
/// not, because it would be deciding for every importer that imported it.
pub const std_options: std.Options = .{ .log_level = .warn };

/// Every allocation in this program is through a handle the caller handed in,
/// and none of them is a global — `AGENTS.md` §1 by name.
const Allocator = std.mem.Allocator;

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

/// How long a run lasts when `--for` does not say. A binary that ran until a
/// signal forever could not be smoke-tested from a script, and a script that
/// cannot run it is a binary nobody runs.
const default_run_ms: i64 = 500;

/// What the command line asked for.
const Options = struct {
    /// Where to bind. Port zero lets the kernel choose, which is what lets two
    /// nodes on one machine both listen.
    listen: SocketAddr = .{
        .ip = .{ .v4 = .{ 127, 0, 0, 1 } },
        .port = 0,
    },
    /// Who to dial, in the order the flags named them.
    peers: std.ArrayList(Peer) = .empty,
    /// This node's identity, drawn when the caller does not supply one.
    secret: ?SecretKey = null,
    /// The protocol to offer.
    alpn: []const u8 = node_mod.gossip_alpn,
    /// The generator's seed. Fixed by default, so two runs of the same command
    /// line present the same connection ids and a failure reproduces.
    seed: u64 = 0x6f7a_69,
    /// When to stop on our own.
    run_ms: i64 = default_run_ms,

    /// What the usage text says, and nothing it does not.
    const usage =
        \\usage: ozai-node [options]
        \\
        \\  --listen <ip:port>     where to bind. Port 0 lets the kernel choose.
        \\  --peer <nodeid@ip:port>
        \\                          dial this peer. May be repeated.
        \\  --key-seed <base32>    this node's ed25519 seed, z-base-32. Drawn
        \\                          when absent; the node id is printed either
        \\                          way.
        \\  --alpn <bytes>         the protocol to offer. Default: the gossip
        \\                          ALPN.
        \\  --seed <u64>           the generator seed. Default: fixed, so a run
        \\                          reproduces.
        \\  --for <ms>             stop after this long, gracefully. Default: 500.
        \\  --help                 print this.
        \\
        \\A node id is z-base-32, as `ozai-node-id` prints it.
        \\
    ;

    /// Read the command line.
    ///
    /// Three answers rather than a `?Options`, because three are true: a run,
    /// `--help`, and a rejection. The last is a different answer from the
    /// middle one and a caller can tell them apart, which is why the exit code
    /// can be 1 for one and 0 for the other.
    fn parse(
        args: std.process.Args,
        arena: Allocator,
        out: *std.Io.Writer,
    ) !Parse {
        var options: Options = .{};
        var it = std.process.Args.iterate(args);
        defer it.deinit();
        _ = it.skip();
        while (it.next()) |flag| {
            if (std.mem.eql(u8, flag, "--help")) {
                try out.writeAll(usage);
                return .help;
            }
            const value = it.next() orelse {
                try out.print("ozai-node: {s} wants a value\n", .{flag});
                return .{ .rejected = error.FlagWithoutValue };
            };
            if (std.mem.eql(u8, flag, "--listen")) {
                options.listen = parseSocket(value) catch |err| {
                    try reject(out, flag, value, err);
                    return .{ .rejected = err };
                };
            } else if (std.mem.eql(u8, flag, "--peer")) {
                const peer = parsePeer(value) catch |err| {
                    try reject(out, flag, value, err);
                    return .{ .rejected = err };
                };
                // The arena is the process's and does not grow on its own, so
                // this can only fail if the process is out of memory — which
                // is propagated rather than dressed up as a bad argument.
                try options.peers.append(arena, peer);
            } else if (std.mem.eql(u8, flag, "--key-seed")) {
                const seed = ozai.base32.decode(
                    ozai.base32.z32,
                    SecretKey.seed_length,
                    value,
                ) catch |err| {
                    try reject(out, flag, value, err);
                    return .{ .rejected = err };
                };
                options.secret = SecretKey.fromSeed(seed) catch |err| {
                    try reject(out, flag, value, err);
                    return .{ .rejected = err };
                };
            } else if (std.mem.eql(u8, flag, "--alpn")) {
                options.alpn = value;
            } else if (std.mem.eql(u8, flag, "--seed")) {
                options.seed = std.fmt.parseInt(u64, value, 10) catch {
                    try reject(out, flag, value, error.NotASeed);
                    return .{ .rejected = error.NotASeed };
                };
            } else if (std.mem.eql(u8, flag, "--for")) {
                options.run_ms = std.fmt.parseInt(i64, value, 10) catch {
                    try reject(out, flag, value, error.NotMilliseconds);
                    return .{ .rejected = error.NotMilliseconds };
                };
            } else {
                try out.print("ozai-node: {s} is not an option\n", .{flag});
                try out.writeAll(usage);
                return .{ .rejected = error.NotAnOption };
            }
        }
        return .{ .run = options };
    }
};

/// What the command line turned out to mean.
const Parse = union(enum) {
    run: Options,
    /// `--help`. Exit 0: the program was asked a question and answered it.
    help: void,
    /// Something it will not do. Exit 1: a caller scripting this wants a
    /// failure and not a node that quietly ran with defaults.
    rejected: CliError,
};

/// What this program refuses, over and above the ones `Node` publishes.
///
/// The two that are its own are a value the caller wrote and a flag it does
/// not recognise, and both are answered with a line rather than a stack trace:
/// a program's own refusals are its interface.
/// `base32`'s and `key`'s refusals are included rather than restated, for the
/// reason `hyparview.zig` gives for the same shape: a varint that does not end
/// and a node id that is not on the curve are both refusals a caller can
/// provoke, and they read better as the seam's own names.
const CliError = ozai.base32.DecodeError || ozai.KeyError || error{
    /// A flag that is not one this program has.
    NotAnOption,
    /// A flag that takes a value, and the command line ended.
    FlagWithoutValue,
    /// An address with no port, a port that is not a number, or a host that is
    /// neither a v4 nor a v6 literal.
    AddressNotReachable,
    /// A peer flag with no `@`, or an address after it that is not one.
    PeerWithoutAddress,
    PeerAddressUnreachable,
    /// `--seed` was not a `u64`.
    NotASeed,
    /// `--for` was not a millisecond count.
    NotMilliseconds,
    /// The monotonic clock could not be read, or read a value `Instant` cannot
    /// hold.
    NoClock,
};

/// Say what was wrong with a value, and why, on one line.
fn reject(
    out: *std.Io.Writer,
    flag: []const u8,
    value: []const u8,
    err: anyerror,
) !void {
    try out.print("ozai-node: {s} '{s}': {t}\n", .{ flag, value, err });
}

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

/// The monotonic clock as the core is driven at, in nanoseconds.
///
/// Read only here and only by the program edge: `Node.step` takes its instant
/// as data, and this is the one place a value for it comes from. `Clock.awake`
/// rather than `.real` because a QUIC timer must not jump because NTP moved
/// the wall clock.
fn nowNs(io: std.Io) CliError!Instant {
    const stamp = std.Io.Clock.awake.now(io);
    return std.math.cast(Instant, stamp.nanoseconds) orelse error.NoClock;
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var out_buffer: [512]u8 = undefined;
    var out = std.Io.File.stdout().writerStreaming(io, &out_buffer);
    const text = &out.interface;

    const options = switch (try Options.parse(init.minimal.args, init.arena.allocator(), text)) {
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

    // Drawn rather than demanded, and printed either way: a node that cannot
    // say who it is is not a node, and a caller that wants a fixed identity
    // passes `--key-seed`.
    var secret = options.secret orelse SecretKey.generate(io);
    defer secret.deinit();

    const node = try Node.create(io, init.gpa, .{
        .secret = secret,
        .listen = options.listen,
        .peers = options.peers.items,
        .alpn = options.alpn,
    }, options.seed);
    defer node.deinit();

    try text.print("node       {f}\n", .{node.nodeId()});
    try text.print("z-base-32  {s}\n", .{node.nodeId().toZ32()});
    try text.print("listening  {f}\n", .{node.address()});
    try text.print("alpn       {s}\n", .{options.alpn});
    try text.print("seed       {d}\n", .{options.seed});
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

    watchForStop();
    const started = try nowNs(io);
    stopped.expireAt(started + options.run_ms * std.time.ns_per_ms);

    // `run` owns the dials: it does them on its first pass, so a signal that
    // lands before the loop is entered closes a node that never dialled.
    try node.run(io, &stopped);

    try report(text, node);
    try out.flush();
}

/// What the run did, and how it ended.
///
/// Every line here is a number a caller of `Node` could not get any other way,
/// and the two counters that stop at a count are printed next to what they
/// would have been had the codec existed — so the gap is visible rather than
/// inferred from the absence of traffic.
fn report(text: *std.Io.Writer, node: *const Node) !void {
    const stats = node.stats;
    try text.print(
        \\
        \\stopped: {d} passes, {d} datagrams in, {d} out ({d} degraded, {d} codepoints lost)
        \\accept loop: {d} attempts, {d} spawned, {d} handler connections
        \\  {d} retries asked and not sent, {d} refusals, {d} ignores
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
        stats.retry_validation_asked + stats.retry_cost_asked,
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
    if (node.namedPeers().len == 0) return;
    try text.writeAll("gossip named: ");
    for (node.namedPeers(), 0..) |peer, index| {
        if (index > 0) try text.writeAll(", ");
        try text.print("{f}", .{peer});
    }
    try text.writeAll("\n");
}

/// `ip:port`, with an IPv6 literal written in brackets.
fn parseSocket(text_in: []const u8) CliError!SocketAddr {
    const colon = std.mem.lastIndexOfScalar(u8, text_in, ':') orelse
        return error.AddressNotReachable;
    const port = std.fmt.parseInt(u16, text_in[colon + 1 ..], 10) catch
        return error.AddressNotReachable;
    var host = text_in[0..colon];
    if (std.mem.startsWith(u8, host, "[") and std.mem.endsWith(u8, host, "]")) {
        host = host[1 .. host.len - 1];
    }
    return .{
        .ip = ozai.IpAddress.parse(host) orelse return error.AddressNotReachable,
        .port = port,
    };
}

/// `nodeid@ip:port`: a z-base-32 node id, and where to reach it.
///
/// The two halves keep their own refusals: a node id that is not on the curve
/// and an address with no port are different mistakes, and one name for both
/// would leave the caller guessing which one it typed.
fn parsePeer(text_in: []const u8) CliError!Peer {
    const at = std.mem.indexOfScalar(u8, text_in, '@') orelse return error.PeerWithoutAddress;
    const socket = parseSocket(text_in[at + 1 ..]) catch return error.PeerAddressUnreachable;
    return .{ .id = try NodeId.parseZ32(text_in[0..at]), .addr = .{ .ip = socket } };
}
