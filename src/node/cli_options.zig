//! What the command line asked for.
//!
//! `Options` is the whole of the program's vocabulary: a listen address, a peer
//! list, an identity, a protocol, a relay role and a run. `parse` turns
//! arguments into one of three answers — a run, a `--help`, or a refusal — and
//! `contradictions` is what refuses a line naming two things one node cannot
//! be. The flags it accepts are named in the usage text beside them.

const std = @import("std");

const ozai = @import("ozai");
const cli_values = @import("cli_values.zig");

const node_mod = ozai.node;
const Allocator = std.mem.Allocator;
const Peer = node_mod.Peer;
const SocketAddr = ozai.SocketAddr;
const SecretKey = ozai.SecretKey;
const CliError = cli_values.CliError;
const RelayPeer = cli_values.RelayPeer;
const Send = cli_values.Send;

/// How long a run lasts when `--for` does not say. A binary that ran until a
/// signal forever could not be smoke-tested from a script, and a script that
/// cannot run it is a binary nobody runs.
const default_run_ms: i64 = 500;

/// What the command line asked for.
pub const Options = struct {
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
    ///
    /// `pub` because `main.zig` calls it from outside this file. This module
    /// is a split out of `main.zig`, and `main.zig` is the only caller: it
    /// owns the arena and the writer that are parsed into.
    pub fn parse(
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
                options.listen = cli_values.parseSocket(value) catch |err| {
                    try cli_values.reject(out, flag, value, err);
                    return .{ .rejected = err };
                };
            } else if (std.mem.eql(u8, flag, "--peer")) {
                const peer = cli_values.parsePeer(value) catch |err| {
                    try cli_values.reject(out, flag, value, err);
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
                    try cli_values.reject(out, flag, value, err);
                    return .{ .rejected = err };
                };
                options.secret = SecretKey.fromSeed(seed) catch |err| {
                    try cli_values.reject(out, flag, value, err);
                    return .{ .rejected = err };
                };
            } else if (std.mem.eql(u8, flag, "--alpn")) {
                options.alpn = value;
            } else if (std.mem.eql(u8, flag, "--relay-peer")) {
                options.relay_peer = cli_values.parseRelayPeer(value) catch |err| {
                    try cli_values.reject(out, flag, value, err);
                    return .{ .rejected = err };
                };
            } else if (std.mem.eql(u8, flag, "--send")) {
                options.send = cli_values.parseSend(value) catch |err| {
                    try cli_values.reject(out, flag, value, err);
                    return .{ .rejected = err };
                };
            } else if (std.mem.eql(u8, flag, "--seed")) {
                options.seed = std.fmt.parseInt(u64, value, 10) catch {
                    try cli_values.reject(out, flag, value, error.NotASeed);
                    return .{ .rejected = error.NotASeed };
                };
            } else if (std.mem.eql(u8, flag, "--for")) {
                options.run_ms = std.fmt.parseInt(i64, value, 10) catch {
                    try cli_values.reject(out, flag, value, error.NotMilliseconds);
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
                try cli_values.reject(out, "--relay-peer", target.url, error.TwoRelayRoles);
                return @as(?CliError, error.TwoRelayRoles);
            }
        }
        if (options.serve or options.relay_peer != null) {
            if (options.alpn) |named| {
                try cli_values.reject(out, "--alpn", named, error.RelayChoosesTheAlpn);
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
                try cli_values.reject(out, "--send", datagram.bytes, error.SendNeedsARelayClient);
                return @as(?CliError, error.SendNeedsARelayClient);
            }
        }
        return null;
    }
};

/// What the command line turned out to mean.
pub const Parse = union(enum) {
    run: Options,
    /// `--help`. Exit 0: the program was asked a question and answered it.
    help: void,
    /// Something it will not do. Exit 1: a caller scripting this wants a
    /// failure and not a node that quietly ran with defaults.
    rejected: CliError,
};
