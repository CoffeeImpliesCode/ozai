//! The simulator: convergence, eviction, broadcast, and determinism.
//!
//! This is the test the whole membership layer exists to be able to run. A
//! state machine tested only by feeding it messages has never checked that two
//! of them agree.

const std = @import("std");
const key = @import("../../base/key.zig");
const node_id = @import("node_id.zig");
const settings = @import("config.zig");
const topic = @import("topic.zig");
const sim = @import("sim.zig");

const t = std.testing;

const NodeId = key.NodeId;
const sameNode = node_id.sameNode;
const Peers = settings.Peers;
const Command = topic.Command;

/// Feed one byte to a running digest, so a run can be fingerprinted without
/// being printed.
fn fold(hasher: anytype, value: u8) void {
    var one = [_]u8{value};
    hasher.update(&one);
}

/// A whole run, reduced to a digest: every neighbour change in order, then
/// every node's active view. Two runs agree exactly when these agree.
fn runDigest(seed: u64, peers: u8) sim.HarnessError![32]u8 {
    var simulator: sim.Simulator = try sim.Simulator.init(t.allocator, .{
        .rng_seed = seed,
        .peers = peers,
    }, .{
        .latency = .default_fixed,
        .membership = .{ .active_view_capacity = 3 },
    });
    defer simulator.deinit();
    try simulator.bootstrap(.single);
    var buffer: [sim.max_neighbour_events]sim.NeighbourEvent = undefined;
    var hasher = std.crypto.hash.Blake3.init(.{});
    for (simulator.network.neighbourEvents(&buffer)) |event| {
        fold(&hasher, event.a);
        fold(&hasher, event.b);
        fold(&hasher, @intFromBool(event.up));
    }
    var found: [sim.max_peers]u8 = undefined;
    var index: u8 = 0;
    while (index < peers) : (index += 1) {
        const count = simulator.network.neighborIndices(index, &found);
        fold(&hasher, @intCast(count));
        for (found[0..count]) |neighbour| fold(&hasher, neighbour);
    }
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

fn sameEvents(got: []const sim.NeighbourEvent, want: []const sim.NeighbourEvent) bool {
    if (got.len != want.len) return false;
    for (got, want) |a, b| {
        if (a.a != b.a or a.b != b.b or a.up != b.up) return false;
    }
    return true;
}

fn countReceived(events: []const sim.SimEvent) usize {
    var count: usize = 0;
    for (events) |event| {
        if (event.event == .received) count += 1;
    }
    return count;
}

fn joinOf(peers: []const NodeId) sim.HarnessError!Command {
    return .{ .join = try Peers.init(peers) };
}

// Upstream `proto::test::hyparview_smoke`: four nodes, an active view of two,
// a fixed latency, and three join commands. The expected neighbour events and
// the three surviving links are upstream's own assertions, captured from
// `proto.rs` at the commit named at the top of this file.
test "four nodes converge on the three links upstream does" {
    var simulator: sim.Simulator = try sim.Simulator.init(t.allocator, .{
        .rng_seed = 0,
        .peers = 4,
    }, .{
        .latency = .default_fixed,
        .membership = .{ .active_view_capacity = 2 },
    });
    defer simulator.deinit();
    const network = &simulator.network;
    var index: u8 = 0;
    while (index < 4) : (index += 1) try network.insert(index);

    try network.command(0, try joinOf(&.{ try sim.nodeIdFor(1), try sim.nodeIdFor(2) }));
    try network.command(1, try joinOf(&.{try sim.nodeIdFor(2)}));
    try network.command(2, try joinOf(&.{}));
    try network.runTrips(3);

    var buffer: [sim.max_neighbour_events]sim.NeighbourEvent = undefined;
    const expected = [_]sim.NeighbourEvent{
        .{ .up = true, .a = 0, .b = 1 },
        .{ .up = true, .a = 0, .b = 2 },
        .{ .up = true, .a = 1, .b = 0 },
        .{ .up = true, .a = 1, .b = 2 },
        .{ .up = true, .a = 2, .b = 0 },
        .{ .up = true, .a = 2, .b = 1 },
    };
    try t.expect(sameEvents(network.neighbourEvents(&buffer), &expected));
    try t.expectEqual(@as(usize, 3), network.conns().len);
    try t.expect(network.checkSynchronicity());
    // Node 3 was inserted but never asked to join, so it is in no view.
    try t.expectEqual(@as(usize, 0), network.neighborCount(3));
}

// The rest of upstream's `hyparview_smoke`: a fourth node joins a full view.
// Upstream accepts either outcome, because which peer node 0 drops is a
// random choice, and asserts the connections and the synchrony either way.
test "a node joining a full view evicts one peer, either one, and stays synchronous" {
    var simulator: sim.Simulator = try sim.Simulator.init(t.allocator, .{
        .rng_seed = 0,
        .peers = 4,
    }, .{
        .latency = .default_fixed,
        .membership = .{ .active_view_capacity = 2 },
    });
    defer simulator.deinit();
    const network = &simulator.network;
    var index: u8 = 0;
    while (index < 4) : (index += 1) try network.insert(index);
    try network.command(0, try joinOf(&.{ try sim.nodeIdFor(1), try sim.nodeIdFor(2) }));
    try network.command(1, try joinOf(&.{try sim.nodeIdFor(2)}));
    try network.command(2, try joinOf(&.{}));
    try network.runTrips(3);

    network.events.clearRetainingCapacity();
    try network.command(3, try joinOf(&.{try sim.nodeIdFor(0)}));
    try network.runTrips(2);

    // The two possible neighbour-event lists, as upstream writes them. The
    // eviction is random; the shape is not.
    const kept_one = [_]sim.NeighbourEvent{
        .{ .up = false, .a = 0, .b = 1 },
        .{ .up = true, .a = 0, .b = 3 },
        .{ .up = false, .a = 1, .b = 0 },
        .{ .up = true, .a = 3, .b = 0 },
    };
    const kept_two = [_]sim.NeighbourEvent{
        .{ .up = false, .a = 0, .b = 2 },
        .{ .up = true, .a = 0, .b = 3 },
        .{ .up = false, .a = 2, .b = 0 },
        .{ .up = true, .a = 3, .b = 0 },
    };
    var buffer: [sim.max_neighbour_events]sim.NeighbourEvent = undefined;
    const events = network.neighbourEvents(&buffer);
    try t.expect(sameEvents(events, &kept_one) or sameEvents(events, &kept_two));

    try t.expect(network.hasNeighbor(0, 3));
    try t.expect(network.hasNeighbor(3, 0));
    try t.expectEqual(@as(usize, 3), network.conns().len);
    try t.expect(network.checkSynchronicity());
}

// Upstream `proto::test::quit`: a chain of four joins, then the last one
// leaves, and everybody else is still connected to somebody.
test "a node that quits leaves the swarm and the rest stay connected" {
    var simulator: sim.Simulator = try sim.Simulator.init(t.allocator, .{
        .rng_seed = 0,
        .peers = 4,
    }, .{
        .latency = .default_fixed,
        .membership = .{ .active_view_capacity = 2 },
    });
    defer simulator.deinit();
    const network = &simulator.network;
    var index: u8 = 0;
    while (index < 4) : (index += 1) try network.insert(index);
    try network.command(0, try joinOf(&.{}));
    try network.command(1, try joinOf(&.{try sim.nodeIdFor(0)}));
    try network.command(2, try joinOf(&.{try sim.nodeIdFor(1)}));
    try network.command(3, try joinOf(&.{try sim.nodeIdFor(2)}));
    try network.runTrips(2);

    var seen = [_]bool{false} ** sim.max_peers;
    index = 0;
    while (index < 4) : (index += 1) {
        for (network.neighbors(index)) |neighbour| {
            const found = network.peerIndexOf(neighbour) orelse return error.TestUnexpectedResult;
            seen[found] = true;
        }
    }
    for (seen[0..4]) |present| try t.expect(present);
    try t.expect(network.checkSynchronicity());

    try network.command(3, .quit);
    try network.runTrips(4);

    // Upstream asserts the topic state is gone, which here is the node no
    // longer counting as joined and no longer holding a link.
    try t.expect(!network.hasJoined(3));
    try t.expectEqual(@as(usize, 0), network.neighborCount(3));
    var after = [_]bool{false} ** sim.max_peers;
    index = 0;
    while (index < 3) : (index += 1) {
        for (network.neighbors(index)) |neighbour| {
            const found = network.peerIndexOf(neighbour) orelse return error.TestUnexpectedResult;
            after[found] = true;
        }
    }
    try t.expect(after[0]);
    try t.expect(after[1]);
    try t.expect(after[2]);
    try t.expect(!after[3]);
    try t.expect(network.checkSynchronicity());
}

// Upstream `proto::test::plumtree_smoke`: six nodes in two components, a
// broadcast that reaches two nodes, the components joined, and a broadcast
// that then reaches all five others.
test "a broadcast reaches the whole swarm, once the halves are joined" {
    var simulator: sim.Simulator = try sim.Simulator.init(t.allocator, .{
        .rng_seed = 0,
        .peers = 6,
    }, .{
        .latency = .default_fixed,
        .membership = .{ .active_view_capacity = 3 },
    });
    defer simulator.deinit();
    const network = &simulator.network;
    var index: u8 = 0;
    while (index < 6) : (index += 1) try network.insert(index);

    try network.command(0, try joinOf(&.{}));
    try network.command(1, try joinOf(&.{try sim.nodeIdFor(0)}));
    try network.command(2, try joinOf(&.{try sim.nodeIdFor(0)}));
    try network.command(3, try joinOf(&.{}));
    try network.command(4, try joinOf(&.{try sim.nodeIdFor(3)}));
    try network.command(5, try joinOf(&.{try sim.nodeIdFor(3)}));
    try network.runTrips(4);
    network.events.clearRetainingCapacity();
    try t.expect(network.checkSynchronicity());

    // In the half node 1 is in, two others.
    try network.command(1, .{ .broadcast = .{ .content = "hi1", .scope = .swarm } });
    try network.runTrips(4);
    try t.expectEqual(@as(usize, 2), countReceived(network.events.items));
    try t.expect(network.checkSynchronicity());

    // Join the two halves and broadcast again.
    network.events.clearRetainingCapacity();
    try network.command(2, try joinOf(&.{try sim.nodeIdFor(5)}));
    try network.runTrips(3);
    network.events.clearRetainingCapacity();
    try network.command(1, .{ .broadcast = .{ .content = "hi2", .scope = .swarm } });
    try network.runTrips(5);
    try t.expectEqual(@as(usize, 5), countReceived(network.events.items));
    try t.expect(network.checkSynchronicity());
}

// The plan's bar: two or more nodes agree on membership, which is a property
// of a network and not of any one state machine. Every node is connected, and
// every link is held by both ends.
test "a bootstrapped swarm converges: nobody is alone, and the disagreement stops" {
    var simulator: sim.Simulator = try sim.Simulator.init(t.allocator, .{
        .rng_seed = 7,
        .peers = 8,
    }, .{
        .latency = .default_drawn,
        .membership = .{ .active_view_capacity = 3 },
    });
    defer simulator.deinit();
    try simulator.bootstrap(.single);

    // Upstream's own bar for a bootstrapped swarm: nobody is left with no
    // neighbours at all. That is the assertion `big_hyparview` makes, and it
    // is the one a node that never joined would fail.
    try t.expectEqual(@as(usize, 0), simulator.network.peersWithoutNeighbors());
    const extent = simulator.network.activeExtent();
    try t.expect(extent.max <= 3);
    try t.expect(extent.min >= 1);

    // Convergence, as opposed to merely being non-empty: the run keeps going
    // with nothing left to join, and the disagreement count does not grow. A
    // swarm that kept acquiring one-sided links would be failing, and one
    // that had acquired some and stopped would be merely unlucky — which is
    // upstream's position and is written down in `asymmetricLinks`.
    const early = simulator.network.asymmetricLinks();
    try simulator.network.runTrips(40);
    try t.expectEqual(@as(usize, 0), simulator.network.peersWithoutNeighbors());
    try t.expectEqual(early, simulator.network.asymmetricLinks());

    // And the broadcast built on top of that membership reaches every other
    // node exactly once, without disturbing the membership it was built on.
    const settled = simulator.network.asymmetricLinks();
    const stats = try simulator.gossipRound(0, "hello");
    try t.expectEqual(stats.expected, stats.delivered);
    try t.expectEqual(@as(usize, 0), stats.duplicated);
    try t.expectEqual(settled, simulator.network.asymmetricLinks());
}

// The same run twice, from the same seed, is the same run. Upstream's
// simulator cannot say this: its pending-request and alive-disconnect sets
// are hash sets on a per-process seed, and it iterates one of them.
test "the same seed gives the same run, byte for byte" {
    const first = try runDigest(0x5eed, 8);
    const second = try runDigest(0x5eed, 8);
    try t.expectEqualSlices(u8, &first, &second);
}

// And the seed is what makes it so: a different seed is a different run, and
// an unseeded one would be a different run every time.
test "a different seed is a different run" {
    const first = try runDigest(1, 8);
    const second = try runDigest(2, 8);
    try t.expect(!std.mem.eql(u8, &first, &second));
}

// The second bootstrap mode: a core forms first, then everybody else joins a
// random core member. Same convergence, different topology.
test "a core bootstrap converges the same way" {
    var simulator: sim.Simulator = try sim.Simulator.init(t.allocator, .{
        .rng_seed = 3,
        .peers = 8,
    }, .{
        .latency = .default_drawn,
        .membership = .{ .active_view_capacity = 3 },
    });
    defer simulator.deinit();
    try simulator.bootstrap(.{ .core = 3 });
    try t.expectEqual(@as(usize, 0), simulator.network.peersWithoutNeighbors());
    const early = simulator.network.asymmetricLinks();
    try simulator.network.runTrips(40);
    try t.expectEqual(@as(usize, 0), simulator.network.peersWithoutNeighbors());
    try t.expectEqual(early, simulator.network.asymmetricLinks());
}

// The harness refuses what it cannot hold, rather than quietly truncating.
test "the simulator refuses a thirteenth node and a duplicate" {
    var simulator: sim.Simulator = try sim.Simulator.init(t.allocator, .{
        .rng_seed = 0,
        .peers = 2,
    }, .{ .latency = .default_fixed });
    defer simulator.deinit();
    try simulator.network.insert(0);
    try t.expectError(error.DuplicatePeer, simulator.network.insert(0));
    try t.expectError(error.PeerIndexOutOfRange, simulator.network.insert(sim.max_peers));
}

// The simulator's identities are a fixture, and a fixture that quietly
// produced the same node twice would turn every convergence assertion into a
// tautology. This walks the whole index range, so a degenerate seed panics
// here rather than passing.
test "every simulated node has its own identity" {
    var index: u8 = 0;
    while (index < sim.max_peers) : (index += 1) {
        const mine = try sim.nodeIdFor(index);
        try t.expect(sameNode(mine, try sim.nodeIdFor(index)));
        var other: u8 = 0;
        while (other < sim.max_peers) : (other += 1) {
            if (other == index) continue;
            try t.expect(!sameNode(mine, try sim.nodeIdFor(other)));
        }
    }
}
