//! What a node is started with, and what a peer is handed to reach it.
//!
//! `flags` is the command line and nothing else: everything the node needs to be
//! identifiable, reproducible and finite, and nothing this file reads back.
//! `peer` and `peers` name direct pinned peers. `relayUrl` names the actual TCP
//! carrier listener, not the node's UDP socket or a relay identity.

const std = @import("std");
const ozai = @import("ozai");

const base32 = ozai.base32;
const SecretKey = ozai.SecretKey;

const child = @import("two_process_child.zig");
const roster_ns = @import("two_process_roster.zig");

const Allocator = child.Allocator;

/// The `ozai-node` this run starts: the exact executable the build that
/// compiled this test just emitted, at this run's own target and optimize mode
/// and, under coverage, its instrumented compile. It arrives through the
/// options module rather than being spelled here, because a path written in
/// this file names whatever a plain `zig build` last left in `zig-out/bin` —
/// which under `cross-test`, whose builds install under a `--prefix` of their
/// own, is a host binary for a different ABI and no coverage counters at all.
/// Ten scenarios asserting on process behaviour would then be asserting on a
/// program this build never made.
///
/// The cost is that this file is no longer compilable on its own: `zig test
/// test/two_process_test.zig` has no `node_test_options` module to import. That
/// was never a supported way to run it — the file needs `ozai`, `link_libc`
/// and the custom runner, so `zig build test` was always the way in — and the
/// alternative was a build that can silently run a stale binary, which is the
/// one failure this cannot have.
const node_test_options = @import("node_test_options");
const node_exe = node_test_options.node_executable;

/// Where every node binds. Port zero, so the kernel chooses it: two nodes on
/// one machine both listen, and nothing here collides with the run before it.
const loopback = "127.0.0.1:0";

// ---------------------------------------------------------------------------
// Starting nodes
// ---------------------------------------------------------------------------

/// The command line for one node.
///
/// Everything the node needs to be identifiable, reproducible and finite, and
/// nothing else: it prints its own name and address, and this file reads them
/// back rather than predicting them.
pub fn flags(arena: Allocator, plan: child.Plan) ![]const []const u8 {
    var seed_bytes: [SecretKey.seed_length]u8 = @splat(plan.tag);
    const key_seed = base32.encode(base32.z32, SecretKey.seed_length, &seed_bytes);
    var argv: std.ArrayList([]const u8) = .empty;
    if (node_test_options.node_executor) |executor| try argv.append(arena, executor);
    try argv.append(arena, node_exe);
    try argv.append(arena, "--listen");
    try argv.append(arena, loopback);
    try argv.append(arena, "--key-seed");
    try argv.append(arena, try std.fmt.allocPrint(arena, "{s}", .{&key_seed}));
    try argv.append(arena, "--seed");
    try argv.append(arena, try std.fmt.allocPrint(arena, "{d}", .{plan.seed}));
    try argv.append(arena, "--for");
    try argv.append(arena, try std.fmt.allocPrint(arena, "{d}", .{plan.run_ms}));
    // Every node publishes its state, so no wait in this file has to guess how
    // long something took. A node that refuses its command line never reaches
    // a pass and so never writes one, which is why the refusal test is
    // unaffected by this being unconditional.
    try argv.append(arena, "--progress");
    for (plan.peers) |target| {
        try argv.append(arena, "--peer");
        try argv.append(arena, target);
    }
    if (plan.relay_listen) |address| {
        try argv.append(arena, "--relay-listen");
        try argv.append(arena, address);
    }
    if (plan.relay_server) |address| {
        try argv.append(arena, "--relay-server");
        try argv.append(arena, address);
    }
    if (plan.relay_host) |host| {
        try argv.append(arena, "--relay-host");
        try argv.append(arena, host);
    }
    for (plan.peer_relays) |target| {
        try argv.append(arena, "--peer-relay");
        try argv.append(arena, target);
    }
    try argv.appendSlice(arena, plan.extra);

    return argv.toOwnedSlice(arena);
}

/// Start a node and put it on the roster, so that one wait in the test watches
/// every node the test started.
pub fn startNode(
    io: std.Io,
    gpa: Allocator,
    arena: Allocator,
    roster: *roster_ns.Roster,
    name: []const u8,
    plan: child.Plan,
) !*child.Process {
    const argv = try flags(arena, plan);
    const started = try child.Process.start(gpa, io, .{
        .name = name,
        .argv = argv,
        .final_argv = if (node_test_options.node_executor != null) argv[1..] else argv,
        .run_ms = plan.run_ms,
    });
    const process = switch (started) {
        .ready => |value| value,
        .failed => |failure| {
            failure.process.deinit(io);
            return failure.cause;
        },
    };
    errdefer process.deinit(io);
    try roster.add(gpa, process);
    return process;
}

/// The two things a peer needs about a node that has bound: who it is, and
/// where it is. A node that printed one without the other has said nothing
/// useful, and this is where that is caught.
pub fn named(process: *const child.Process) !struct { id: []const u8, address: []const u8 } {
    const id = process.value("z-base-32") orelse
        return process.gaveUp("printed a banner with no node id in it", .{});
    const address = process.bound() orelse
        return process.gaveUp("printed a banner with no address in it", .{});
    return .{ .id = id, .address = address };
}

/// The `--peer` value naming one node: its z-base-32 id and the address it
/// bound, in the spelling `ozai-node` parses.
pub fn peer(arena: Allocator, listener: *const child.Process) ![]const u8 {
    const side = try named(listener);
    return std.fmt.allocPrint(arena, "{s}@{s}", .{ side.id, side.address });
}

/// The `--peer` values naming two nodes.
pub fn peers(
    arena: Allocator,
    one: *const child.Process,
    two: *const child.Process,
) ![]const []const u8 {
    const list = try arena.alloc([]const u8, 2);
    list[0] = try peer(arena, one);
    list[1] = try peer(arena, two);
    return list;
}
