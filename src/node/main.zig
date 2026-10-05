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

const cli_options = @import("cli_options.zig");
const cli_loop = @import("cli_loop.zig");
const cli_report = @import("cli_report.zig");

const node_mod = ozai.node;
const Node = node_mod.Node;
const SecretKey = ozai.SecretKey;

const Options = cli_options.Options;

/// How loud this program is.
///
/// The vendored QUIC core logs every handshake step at `info` and every
/// received frame at `debug`, which is the right thing for a library with no
/// opinion and the wrong thing for a binary whose own report is six lines
/// long. `std_options` in the root is what a program has to say; a library must
/// not, because it would be deciding for every importer that imported it.
pub const std_options: std.Options = .{ .log_level = .warn };

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
    cli_loop.watchForStop();

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

    const started = try cli_loop.nowNs(io);
    cli_loop.stopped.expireAt(started + options.run_ms * std.time.ns_per_ms);

    try cli_loop.drive(io, node, options.send, if (options.progress) text else null);
    // Read here, before the close that will empty both of these: see `Holding`.
    const holding: cli_report.Holding = .{
        .node_ids = node.clientCount(),
        .connections = node.establishedCount(),
    };
    // And what the close wrote, measured across that call rather than read
    // after it, for the same reason and because nothing is left to read: see
    // `shut`.
    const close = try cli_loop.shut(io, node, holding.connections);

    try cli_report.report(text, node, holding, close);
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
