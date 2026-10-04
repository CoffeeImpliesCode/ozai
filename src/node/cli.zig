//! The `ozai-node` command line: what a run was asked for, and what it is
//! refused.
//!
//! Pure over bytes. The arguments are handed in, the writer every answer goes
//! to is injected, and nothing here reads an `Io`, a clock or the environment:
//! `main` owns all three. This module owns the grammar — what each flag means,
//! which flag values name nothing, and which combinations of flags no node can
//! be — and `cli_values.zig` owns the spelling of a single value.
//!
//! **A refusal is a value and not an error.** `Parse.rejected` carries the
//! reason so `main` can print it and exit 1, where an error returned out of
//! `parse` would reach the caller as a stack trace: a program's own refusals
//! are its interface. What `parse` fails on is its own writer and its one
//! allocation, and both are named.

const std = @import("std");
const ozai = @import("ozai");
const values = @import("cli_values.zig");
pub const Send = values.Send;
pub const RelayPeer = values.RelayPeer;

/// Every allocation here is through a handle the caller handed in — the arena
/// `main` already owns — and none of them is a global (`AGENTS.md` §1 by name).
const Allocator = std.mem.Allocator;

/// How long a run lasts when `--for` does not say. A binary that ran until a
/// signal forever could not be smoke-tested from a script, and a script that
/// cannot run it is a binary nobody runs.
const default_run_ms: i64 = 500;

/// What the command line asked for.
///
/// Every borrowed field — `alpn`, each `peers` item, the relay URL and the
/// datagram payload — points into the argument bytes `parse` was handed, so
/// they live exactly as long as those do. Nothing here copies a flag's value;
/// `peers` is the only thing that allocates, and only to hold the peers.
pub const Options = struct {
    /// Where to bind. Port zero lets the kernel choose, which is what lets two
    /// nodes on one machine both listen.
    listen: ozai.SocketAddr = .{
        .ip = .{ .v4 = .{ 127, 0, 0, 1 } },
        .port = 0,
    },
    /// Who to dial, in the order the flags named them.
    peers: std.ArrayList(ozai.node_config.Peer) = .empty,
    /// This node's identity, drawn when the caller does not supply one.
    secret: ?ozai.SecretKey = null,
    /// The protocol to offer, or null for the default: the gossip ALPN, or the
    /// relay one when a relay flag below asked for a role.
    alpn: ?[]const u8 = null,
    /// Whether this process serves as a relay.
    serve: bool = false,
    /// The relay this process is a client of, if it is one.
    relay_peer: ?values.RelayPeer = null,
    /// The one datagram to put on the relay wire, if one was asked for.
    send: ?values.Send = null,
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
    pub fn parse(
        arena: Allocator,
        args: std.process.Args,
        out: *std.Io.Writer,
    ) (Error || Allocator.Error || std.Io.Writer.Error)!Parse {
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
                options.listen = values.socket(value) catch |err| {
                    try reject(out, flag, value, err);
                    return .{ .rejected = err };
                };
            } else if (std.mem.eql(u8, flag, "--peer")) {
                const named = values.peer(value) catch |err| {
                    try reject(out, flag, value, err);
                    return .{ .rejected = err };
                };
                // The arena is the process's and does not grow on its own, so
                // this can only fail if the process is out of memory — which
                // is propagated rather than dressed up as a bad argument.
                try options.peers.append(arena, named);
            } else if (std.mem.eql(u8, flag, "--key-seed")) {
                const seed = ozai.base32.decode(
                    ozai.base32.z32,
                    ozai.SecretKey.seed_length,
                    value,
                ) catch |err| {
                    try reject(out, flag, value, err);
                    return .{ .rejected = err };
                };
                options.secret = ozai.SecretKey.fromSeed(seed) catch |err| {
                    try reject(out, flag, value, err);
                    return .{ .rejected = err };
                };
            } else if (std.mem.eql(u8, flag, "--alpn")) {
                options.alpn = value;
            } else if (std.mem.eql(u8, flag, "--relay-peer")) {
                options.relay_peer = values.relayPeer(value) catch |err| {
                    try reject(out, flag, value, err);
                    return .{ .rejected = err };
                };
            } else if (std.mem.eql(u8, flag, "--send")) {
                options.send = values.send(value) catch |err| {
                    try reject(out, flag, value, err);
                    return .{ .rejected = err };
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
    /// A node is one half of the relay handshake and reaches peers one way, and
    /// `--alpn` names the one protocol this program configures a node with — a
    /// second one is `node_config.Config.protocols`, which a command line does not
    /// reach.
    ///
    /// Each arm below is a command line that named two of those answers, and
    /// each is answered on its own line because a caller's mistake is worth
    /// naming exactly rather than resolving silently: both relay roles at once,
    /// an ALPN beside a relay role, a peer list beside a relay role, and a
    /// datagram on a node that is not a relay's client.
    ///
    /// The arms run in that order and none of them is nested inside another,
    /// because a line that is wrong twice is refused for the first reason it
    /// can be named rather than for whichever one an arm happens to reach last.
    /// That is why the datagram check stands on its own rather than inside the
    /// relay arm: a node serving a relay is refused for the datagram too, and
    /// an arm that returned early is a flag silently carried in silence.
    fn contradictions(
        out: *std.Io.Writer,
        options: Options,
    ) std.Io.Writer.Error!?Error {
        if (options.relay_peer) |target| {
            // `node_config.Role` is a union, so one process runs one half. Choosing
            // one here would drop the other without a word.
            if (options.serve) {
                try reject(out, "--relay-peer", target.url, error.TwoRelayRoles);
                return @as(?Error, error.TwoRelayRoles);
            }
        }
        if (options.serve or options.relay_peer != null) {
            // A relay role already answers for the protocol: the role picks the
            // ALPN when the flag does not name one, so a flag beside it is two
            // sources for one value rather than a second protocol. A node may
            // serve two (`node_protocol.max_alpns`); this program configures one.
            if (options.alpn) |named| {
                try reject(out, "--alpn", named, error.RelayChoosesTheAlpn);
                return @as(?Error, error.RelayChoosesTheAlpn);
            }
            if (options.peers.items.len != 0) {
                for (options.peers.items) |peer| try out.print(
                    "ozai-node: --peer {f}: {t}\n",
                    .{ peer.id, error.RelayDialsNobody },
                );
                return @as(?Error, error.RelayDialsNobody);
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
                return @as(?Error, error.SendNeedsARelayClient);
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
    rejected: Error,
};

/// What this program refuses, over and above the ones `Node` publishes.
///
/// The ones that are its own are a value the caller wrote and a flag it does
/// not recognise, and both are answered with a line rather than a stack trace.
/// `cli_values.ValueError` supplies the refusals that belong to a single
/// value's spelling; these are the ones about the command line itself.
pub const Error = values.ValueError || error{
    /// A flag that is not one this program has.
    NotAnOption,
    /// A flag that takes a value, and the command line ended.
    FlagWithoutValue,
    /// Both relay roles at once. `node_config.Role` is a union, so this program runs
    /// one half of the relay handshake or the other.
    TwoRelayRoles,
    /// An ALPN beside a relay role. A relay role already answers for the
    /// protocol — it picks one when `--alpn` does not — so naming one here is
    /// (`node_protocol.max_alpns`); this program configures one.
    RelayChoosesTheAlpn,
    /// A peer list beside a relay role. A relay reaches peers through a relay
    /// rather than at their own addresses, so a dial list is a dial to a
    /// protocol that would not answer.
    RelayDialsNobody,
    /// `--send` on a node that is not a relay's client, which is the only node
    /// with a wire to put a datagram on.
    SendNeedsARelayClient,
    /// `--for` was not a millisecond count.
    NotMilliseconds,
};

/// Say what was wrong with a value, and why, on one line.
///
/// The error is one of `Error`'s and the only way this can fail is the write,
/// so both are named rather than inferred: a refusal whose type is `anyerror`
/// is a refusal that can be handed anything.
fn reject(
    out: *std.Io.Writer,
    flag: []const u8,
    value: []const u8,
    err: Error,
) std.Io.Writer.Error!void {
    try out.print("ozai-node: {s} '{s}': {t}\n", .{ flag, value, err });
}
