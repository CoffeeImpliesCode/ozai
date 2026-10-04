//! The command line one `ozai-node` child is started with, and the identity it
//! will present because of it.
//!
//! A `Plan` is what a test asks for; `flags` is what `ozai-node` is handed. The
//! two are kept apart because they answer different questions: a plan says "a
//! node that dials that peer", and a command line says `--peer <nodeid>@<ip>`.
//! Everything a child needs to be identifiable, reproducible and finite, and
//! nothing else: it prints its own name and address, and the tests read them
//! back rather than predicting them.
//!
//! The identity is a byte repeated into a seed rather than a key literal, so
//! both halves of a run present the same certificate on every run and a failure
//! reproduces rather than having to be re-diagnosed. Production randomness comes
//! from each child's own secure runtime provider; only the identity is fixed
//! here.

const std = @import("std");
const ozai = @import("ozai");

const driver = @import("process_driver.zig");

const Allocator = std.mem.Allocator;
const Process = driver.Process;
const base32 = ozai.base32;
const SecretKey = ozai.SecretKey;

/// The `ozai-node` this run starts: the exact executable the build that
/// compiled this test just emitted, at this run's own target and optimize mode
/// and, under coverage, its instrumented compile. It arrives through the
/// options module rather than being spelled here, because a path written in a
/// test names whatever a plain `zig build` last left in `zig-out/bin` — which
/// under `cross-test`, whose builds install under a `--prefix` of their own, is
/// a host binary for a different ABI and no coverage counters at all. A dozen
/// scenarios asserting on process behaviour would then be asserting on a
/// program this build never made.
///
/// The cost is that these tests are no longer compilable on their own: `zig
/// test test/two_process_test.zig` has no `node_test_options` module to import.
/// That was never a supported way to run them — the file needs `ozai`,
/// `link_libc` and the custom runner, so `zig build test` was always the way in
/// — and the alternative was a build that can silently run a stale binary,
/// which is the one failure this cannot have.
const node_test_options = @import("node_test_options");
const node_exe = node_test_options.node_executable;

/// Where every node binds. Port zero, so the kernel chooses it: two nodes on
/// one machine both listen, and nothing here collides with the run before it.
const loopback = "127.0.0.1:0";

/// No peers, for a node that is only going to be dialled.
const no_peers: []const []const u8 = &.{};

/// A fixed identity, a deadline of its own, and whatever peers the test has
/// already seen bind.
pub const Plan = struct {
    /// The byte every byte of the ed25519 seed is made of.
    tag: u8,
    /// `--for`, in milliseconds.
    run_ms: i64,
    /// Peers to dial, as `nodeid@ip:port`.
    peers: []const []const u8 = no_peers,
    /// `--relay`: this node serves as a relay rather than answering peers.
    serve_relay: bool = false,
    /// `--relay-peer <nodeid>@<url>`: the relay to reach, in the spelling a
    /// peer is handed one. **A peer holds a URL and nothing else**, so this is
    /// a URL and never a socket a test kept to itself: the program under test
    /// is the one that turns it into an address.
    relay_peer: ?[]const u8 = null,
    /// `--send <nodeid>:<bytes>`: one datagram to put on the relay wire, once
    /// the relay connection is up. The gossip codec's job, asked for by hand.
    send: ?[]const u8 = null,
    /// Flags appended as written, for a command line that is meant to be
    /// refused and has no field above.
    extra: []const []const u8 = &.{},
};

/// The command line for one node.
///
/// Everything goes into `arena`, so the arguments outlive `spawn` and die with
/// the test that wrote them rather than with this call.
pub fn flags(arena: Allocator, plan: Plan) ![]const []const u8 {
    var seed_bytes: [SecretKey.seed_length]u8 = @splat(plan.tag);
    const key_seed = base32.encode(base32.z32, SecretKey.seed_length, &seed_bytes);
    var argv: std.ArrayList([]const u8) = .empty;
    if (node_test_options.node_executor) |executor| try argv.append(arena, executor);
    try argv.append(arena, node_exe);
    try argv.append(arena, "--listen");
    try argv.append(arena, loopback);
    try argv.append(arena, "--key-seed");
    try argv.append(arena, try std.fmt.allocPrint(arena, "{s}", .{&key_seed}));
    try argv.append(arena, "--for");
    try argv.append(arena, try std.fmt.allocPrint(arena, "{d}", .{plan.run_ms}));
    // Every node publishes its state, so no wait in these tests has to guess how
    // long something took. A node that refuses its command line never reaches
    // a pass and so never writes one, which is why the refusal test is
    // unaffected by this being unconditional.
    try argv.append(arena, "--progress");
    for (plan.peers) |target| {
        try argv.append(arena, "--peer");
        try argv.append(arena, target);
    }
    if (plan.serve_relay) try argv.append(arena, "--relay");
    if (plan.relay_peer) |target| {
        try argv.append(arena, "--relay-peer");
        try argv.append(arena, target);
    }
    if (plan.send) |datagram| {
        try argv.append(arena, "--send");
        try argv.append(arena, datagram);
    }
    try argv.appendSlice(arena, plan.extra);

    return argv.toOwnedSlice(arena);
}

/// The two things a peer needs about a node that has bound: who it is, and
/// where it is. A node that printed one without the other has said nothing
/// useful, and this is where that is caught.
pub fn named(process: *const Process) !struct { id: []const u8, address: []const u8 } {
    const id = process.value("z-base-32") orelse
        return process.gaveUp("printed a banner with no node id in it", .{});
    const address = process.bound() orelse
        return process.gaveUp("printed a banner with no address in it", .{});
    return .{ .id = id, .address = address };
}

/// The `--peer` value naming one node: its z-base-32 id and the address it
/// bound, in the spelling `ozai-node` parses.
pub fn peer(arena: Allocator, listener: *const Process) ![]const u8 {
    const side = try named(listener);
    return std.fmt.allocPrint(arena, "{s}@{s}", .{ side.id, side.address });
}

/// The `--peer` values naming two nodes.
pub fn peers(
    arena: Allocator,
    one: *const Process,
    two: *const Process,
) ![]const []const u8 {
    const list = try arena.alloc([]const u8, 2);
    list[0] = try peer(arena, one);
    list[1] = try peer(arena, two);
    return list;
}

/// The `--relay-peer` value naming one relay: its node id and the URL that names
/// it, in the spelling a peer is handed one and `ozai-node` parses.
///
/// **The URL is the whole of what a peer holds**, and this is where it is
/// built: out of the address the relay printed, once. Nothing after this reads
/// that address again — the clients are given this string, and the program
/// under test is what turns it into a socket.
///
/// The check in the middle is the step being taken at all, and it is the only
/// thing asserted about the resolution: `RelayUrl.socketAddr` is literal-only
/// and answers `error.NotAnIpLiteral` for a name, so a URL that came out naming
/// somewhere else would name a relay no test started.
pub fn relayPeer(arena: Allocator, relay: *const Process) ![]const u8 {
    const side = try named(relay);
    // `arena` is the caller's (a `std.heap.ArenaAllocator` the suite owns),
    // which releases every byte it handed out in one `deinit`; the URL outlives
    // this function because the client is given it, so there is no per-allocation
    // free to make here and a `free` would double-free into the arena.
    // zwanzig-disable-next-line: store-violations-engine
    const url = try std.fmt.allocPrint(arena, "http://{s}/", .{side.address});
    const parsed = ozai.RelayUrl.parse(url) catch |err| return relay.gaveUp(
        "is bound at {s}, which is not a relay URL host: {t}",
        .{ side.address, err },
    );
    const route = parsed.socketAddr() catch |err| return relay.gaveUp(
        "is bound at {s}, which no relay URL can name: {t}",
        .{ side.address, err },
    );
    var text: [80]u8 = undefined;
    var out = std.Io.Writer.fixed(&text);
    try route.format(&out);
    if (!std.mem.eql(u8, out.buffered(), side.address)) return relay.gaveUp(
        "is bound at {s} and its own relay URL resolves to {s}",
        .{ side.address, out.buffered() },
    );
    return std.fmt.allocPrint(arena, "{s}@{s}", .{ side.id, url });
}

/// The z-base-32 node id a plan with this `tag` will present.
///
/// A plan's identity is a byte repeated into a seed (`flags`), so the id is
/// known before the process is started, and that is what lets two clients name
/// each other on their command lines: `--send` names its peer as text, and a
/// report appears only at exit. Every test that uses this compares it against
/// what the node printed, so a change to how a plan's identity is built fails
/// loudly here rather than quietly sending a datagram to a stranger.
pub fn nodeIdOf(arena: Allocator, tag: u8) ![]const u8 {
    var key = try SecretKey.fromSeed(@splat(tag));
    defer key.deinit();
    return arena.dupe(u8, &key.nodeId().toZ32());
}

/// The `--send` value: one datagram for the node a plan with `tag` presents.
pub fn sendValue(arena: Allocator, tag: u8, payload: []const u8) ![]const u8 {
    return std.fmt.allocPrint(arena, "{s}:{s}", .{ try nodeIdOf(arena, tag), payload });
}
