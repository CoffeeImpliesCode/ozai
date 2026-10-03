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
const Peer = node_mod.Peer;
const Stop = node_mod.Stop;
const Instant = ozai.transport_quic_bridge.Instant;

const NodeId = ozai.NodeId;
const SecretKey = ozai.SecretKey;
const SocketAddr = ozai.SocketAddr;

const Progress = @import("progress.zig").Snapshot;

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
    /// The protocol to offer, or null for the default: the gossip ALPN, or the
    /// relay one when a relay flag below asked for a role.
    alpn: ?[]const u8 = null,
    /// Whether this process serves as a relay.
    serve: bool = false,
    /// The relay this process is a client of, if it is one.
    relay_peer: ?RelayPeer = null,
    /// The one datagram to put on the relay wire, if one was asked for.
    send: ?Send = null,

    /// The generator's seed. Fixed by default, so two runs of the same command
    /// line present the same connection ids and a failure reproduces.
    seed: u64 = 0x6f7a_69,
    /// When to stop on our own.
    run_ms: i64 = default_run_ms,
    /// Emit live state changes so supervisors can wait on state rather than time.
    progress: bool = false,

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
        \\                          ALPN, or the relay one when a relay flag
        \\                          below asked for a role.
        \\
        \\  --relay                 serve as a relay: admit clients, and forward
        \\                          the datagrams between them.
        \\  --relay-peer <nodeid>@<relay-url>
        \\                          reach this relay by URL, which is all a peer
        \\                          holds. A host that is a name is refused:
        \\                          nothing here resolves names.
        \\  --send <nodeid>:<bytes>
        \\                          put one datagram on the relay wire to this
        \\                          peer, once the relay connection is up, and
        \\                          offer it again while the relay says that peer
        \\                          is not there. The gossip codec's job, done
        \\                          here by hand.
        \\
        \\  --seed <u64>           the generator seed. Default: fixed, so a run
        \\                          reproduces.
        \\  --for <ms>             stop after this long, gracefully. Default: 500.
        \\  --progress             flush live counter changes while running.
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
        arena: Allocator,
        args: std.process.Args,
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
            if (std.mem.eql(u8, flag, "--progress")) {
                options.progress = true;
                continue;
            }
            if (std.mem.eql(u8, flag, "--relay")) {
                options.serve = true;
                continue;
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
            } else if (std.mem.eql(u8, flag, "--relay-peer")) {
                options.relay_peer = parseRelayPeer(value) catch |err| {
                    try reject(out, flag, value, err);
                    return .{ .rejected = err };
                };
            } else if (std.mem.eql(u8, flag, "--send")) {
                options.send = parseSend(value) catch |err| {
                    try reject(out, flag, value, err);
                    return .{ .rejected = err };
                };
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
        if (try contradictions(out, options)) |refusal| return .{ .rejected = refusal };

        return .{ .run = options };
    }

    /// The refusal a command line earns by naming two things one node cannot
    /// be, and the line saying so.
    ///
    /// A node runs one protocol, one half of the relay handshake, and reaches
    /// peers one way. Each arm below is a command line that named two of them,
    /// and each is answered on its own line because a caller's mistake is
    /// worth naming exactly rather than resolving silently: both relay roles
    /// at once, an ALPN beside a relay role, a peer list beside a relay role,
    /// and a datagram on a node that is not a relay's client.
    ///
    /// The arms run in that order and none of them is nested inside another,
    /// because a line that is wrong twice is refused for the first reason it
    /// can be named rather than for whichever one an arm happens to reach last.
    /// That is why the datagram check stands on its own rather than inside the
    /// relay arm: a node serving a relay is refused for the datagram too, and
    /// an arm that returned early is a flag silently carried in silence.
    ///
    /// **The refusal comes back as a value and not as an error.** An error
    /// returned out of `parse` is a failure of this program, and it reaches the
    /// caller as a stack trace; a refusal is the program's own answer and has
    /// to arrive as something `main` can print and exit 1 over. The write is
    /// the one thing here that really can fail, and it is the only thing this
    /// function returns as an error.
    fn contradictions(
        out: *std.Io.Writer,
        options: Options,
    ) std.Io.Writer.Error!?CliError {
        if (options.relay_peer) |target| {
            // `node.Role` is a union, so one process runs one half. Choosing
            // one here would drop the other without a word.
            if (options.serve) {
                try reject(out, "--relay-peer", target.url, error.TwoRelayRoles);
                return @as(?CliError, error.TwoRelayRoles);
            }
        }
        if (options.serve or options.relay_peer != null) {
            if (options.alpn) |named| {
                try reject(out, "--alpn", named, error.RelayChoosesTheAlpn);
                return @as(?CliError, error.RelayChoosesTheAlpn);
            }
            if (options.peers.items.len != 0) {
                for (options.peers.items) |peer| try out.print(
                    "ozai-node: --peer {f}: {t}\n",
                    .{ peer.id, error.RelayDialsNobody },
                );
                return @as(?CliError, error.RelayDialsNobody);
            }
        }
        // A datagram needs a relay's client, and only a client has one: the
        // wire it goes on is the one this process holds to a relay. `--relay`
        // is the far end of that wire rather than a peer of it, and a node
        // with no relay flag at all is dialled at its own address and reaches
        // nobody. Left to the loop, the second of those is a `NoRelay` out of
        // `sendThrough` on the first pass that tried and the first is a flag
        // that is carried in silence for the whole run — both stack traces or
        // nothing at all for a flag that was wrong before the node was built.
        if (options.send) |datagram| {
            if (options.relay_peer == null) {
                try reject(out, "--send", datagram.bytes, error.SendNeedsARelayClient);
                return @as(?CliError, error.SendNeedsARelayClient);
            }
        }
        return null;
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
const CliError = ozai.base32.DecodeError || ozai.KeyError ||
    ozai.addr.RelayUrlParseError || ozai.addr.RelayUrlResolveError || error{
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
    /// A relay flag with no `@`, so no node id beside the URL. The id is what
    /// a client presents to the relay and the URL is where it is: one without
    /// the other names nothing.
    RelayWithoutId,
    /// `--send` with no payload after the node id, or with a colon and nothing
    /// behind it. A datagram of no bytes is a flag that said nothing.
    SendWithoutBytes,
    /// `--send` with a payload longer than `Node.max_datagram`. A relay
    /// forwards datagrams and that is the length of one, so a longer one is a
    /// flag asking for something this program will not send.
    SendTooLong,
    /// Both relay roles at once. `node.Role` is a union, so this program runs
    /// one half of the relay handshake or the other.
    TwoRelayRoles,
    /// An ALPN beside a relay role. A relay node speaks the relay protocol
    /// because it cannot also gossip, so there is nothing here to choose.
    RelayChoosesTheAlpn,
    /// A peer list beside a relay role. A relay reaches peers through a relay
    /// rather than at their own addresses, so a dial list is a dial to a
    /// protocol that would not answer.
    RelayDialsNobody,
    /// `--send` on a node that is not a relay's client, which is the only node
    /// with a wire to put a datagram on.
    SendNeedsARelayClient,
    /// `--seed` was not a `u64`.
    NotASeed,
    /// `--for` was not a millisecond count.
    NotMilliseconds,
    /// The monotonic clock could not be read, or read a value `Instant` cannot
    /// hold.
    NoClock,
};

/// A relay this process reaches for, in the two spellings that matter: the URL
/// a caller named it by, and the peer that URL resolved to.
///
/// Both are kept because they answer different questions and only one of them
/// is what the dial was told. The URL is the whole of what a peer holds;
/// `peer` is what `RelayUrl.socketAddr` made of it. A command line that named
/// one relay and reached another is invisible if only one of the two is
/// printed, so the banner says the first and the report says the second.
const RelayPeer = struct {
    url: []const u8,
    peer: Peer,
};

/// One datagram to put on the relay wire, and the peer it is for.
const Send = struct {
    peer: NodeId,
    bytes: []const u8,
};

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

/// Say what was wrong with a value, and why, on one line.
///
/// The error is one of `CliError`'s and the only way this can fail is the
/// write, so both are named rather than inferred: a refusal whose type is
/// `anyerror` is a refusal that can be handed anything.
fn reject(
    out: *std.Io.Writer,
    flag: []const u8,
    value: []const u8,
    err: CliError,
) std.Io.Writer.Error!void {
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

    const options = switch (try Options.parse(init.arena.allocator(), init.minimal.args, text)) {
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
    // `Options.contradictions` has already refused a line that asked for two
    // of anything, so this is a choice rather than a guess.
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
    var secret = options.secret orelse SecretKey.generate(io);
    defer secret.deinit();

    const node = try Node.create(init.gpa, io, .{
        .secret = secret,
        .listen = options.listen,
        .peers = options.peers.items,
        .alpn = alpn,
        .relay = .{ .role = role },
    }, options.seed);
    defer node.deinit();

    // A supervisor may signal as soon as the listening banner reaches its pipe.
    watchForStop();

    try text.print("node       {f}\n", .{node.nodeId()});
    try text.print("z-base-32  {s}\n", .{node.nodeId().toZ32()});
    try text.print("listening  {f}\n", .{node.address()});
    try text.print("alpn       {s}\n", .{alpn});
    try sayRole(text, options);
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

    const started = try nowNs(io);
    stopped.expireAt(started + options.run_ms * std.time.ns_per_ms);

    try drive(io, node, options.send, if (options.progress) text else null);
    // Read here, before the close that will empty both of these: see `Holding`.
    // A serving relay's registry is the count of its clients, and a client has
    // none — `Node.initRelay` builds one for a relay that serves and for
    // nothing else — so that count is read only where one exists rather than
    // out of storage nobody initialised.
    const holding: Holding = .{
        .node_ids = if (role == .serve) node.clientCount() else 0,
        .connections = node.establishedCount(),
    };
    // And what the close wrote, measured across that call rather than read
    // after it, for the same reason and because nothing is left to read: see
    // `shut`.
    const close = try shut(io, node, holding.connections);

    try report(text, node, holding, close);
    try out.flush();
}

/// The banner's one line about relays, in the spelling the command line used.
///
/// A URL for a client because that is the fact a caller can act on — the
/// socket it resolved to is in the report, and a caller who named a relay this
/// program did not reach can see that here rather than having to trust a dial
/// nobody outside this process can watch.
fn sayRole(text: *std.Io.Writer, options: Options) !void {
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
fn drive(
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
fn shut(
    io: std.Io,
    node: *Node,
    owed: usize,
) (node_mod.Error || CliError)!Close {
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

/// `<nodeid>@<relay-url>`: who a relay is, and where it is, in the spelling a
/// peer is handed one.
///
/// **The URL is the whole of what a peer holds about a relay**, so it is
/// resolved here rather than handed over as a socket: `RelayUrl.socketAddr` is
/// the step, and it refuses a host that is a name outright because nothing in
/// this program resolves one. That refusal is this program's answer on a line,
/// for the reason every other bad value here is.
fn parseRelayPeer(text_in: []const u8) CliError!RelayPeer {
    const at = std.mem.indexOfScalar(u8, text_in, '@') orelse
        return error.RelayWithoutId;
    const url = text_in[at + 1 ..];
    // The URL's own refusals and the step that turns it into an address both
    // keep the names the seam gives them: see `CliError`.
    const parsed = try ozai.RelayUrl.parse(url);
    return .{
        .url = url,
        .peer = .{
            .id = try NodeId.parseZ32(text_in[0..at]),
            .addr = .{ .ip = try parsed.socketAddr() },
        },
    };
}

/// `<nodeid>:<bytes>`: one datagram, and the peer it is for.
///
/// A node id is z-base-32 and carries no colon, so the first one separates the
/// two and everything behind it is the payload — colons included, which is why
/// this splits on the first and not the last. The payload is the command line's
/// own bytes rather than a decoded form of them: a datagram is an opaque
/// payload, and a program that cannot spell one cannot send one.
fn parseSend(text_in: []const u8) CliError!Send {
    const colon = std.mem.indexOfScalar(u8, text_in, ':') orelse
        return error.SendWithoutBytes;
    if (colon + 1 == text_in.len) return error.SendWithoutBytes;
    const bytes = text_in[colon + 1 ..];
    // A relay forwards datagrams and this is the length of one, so a longer
    // payload is refused here rather than becoming a `DatagramTooLarge` out of
    // `sendThrough` on a pass of the loop: same mistake, one line either way,
    // and only one of them is a line.
    if (bytes.len > node_mod.max_datagram) return error.SendTooLong;
    return .{ .peer = try NodeId.parseZ32(text_in[0..colon]), .bytes = bytes };
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
