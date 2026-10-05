//! The nodes in the simulated network, and the type that holds them.
//!
//! Upstream `proto/sim.rs`'s `Network` has three jobs and this tree gives each
//! one a file. This one holds the swarm: nodes in fixed slots, which slots are
//! occupied, the identity and `TopicState` each one carries, and the accessors
//! that read a node's views back out. `Network` itself is declared here because
//! those fixed arrays are its fields.
//!
//! `sim_run.zig` is the discrete-event half — the ordered queue, the links, one
//! drawn latency per link, and `tick` — and `sim_report.zig` reads a run back:
//! synchrony, one-sided links, orphans and the neighbour-event list.
//!
//! **The simulator and the thing it simulates are not separable here.** `Peer`
//! carries a whole `TopicState`, tens of kilobytes, and it is inline in the
//! array rather than behind a pointer; splitting the swarm from the run would
//! mean boxing it or threading a second parameter through every event, and
//! both change what the code allocates rather than what it does. So the line is
//! drawn by responsibility — the nodes, the clock, the reading — not by
//! "which half is the harness".
const std = @import("std");
const key = @import("../../base/key.zig");
const plumtree = @import("../plumtree.zig");
const bounds = @import("bounds.zig");
const entropy = @import("rng.zig");
const node_id = @import("node_id.zig");
const settings = @import("config.zig");
const topic = @import("topic.zig");
const harness = @import("sim_harness.zig");
const report = @import("sim_report.zig");
const run = @import("sim_run.zig");

const Allocator = std.mem.Allocator;
const NodeId = key.NodeId;
const Nanos = plumtree.Nanos;
const max_bootstrap = bounds.max_bootstrap;
const Rng = entropy.Rng;
const sameNode = node_id.sameNode;
const Peers = settings.Peers;
const Command = topic.Command;
const InEvent = topic.InEvent;
const TopicState = topic.TopicState;
const max_peers = harness.max_peers;
const max_conns = harness.max_conns;
const max_neighbour_events = harness.max_neighbour_events;
const HarnessError = harness.HarnessError;
const nodeIdFor = harness.nodeIdFor;
const NetworkConfig = harness.NetworkConfig;
const SimEvent = harness.SimEvent;
const NeighbourEvent = harness.NeighbourEvent;

/// One simulated node, carrying a whole `TopicState`. That is tens of
/// kilobytes per slot, so whether a slot holds a node is answered by
/// `Network.occupied` and never by reading a `Peer` `insert` has not
/// written: the bytes of an unwritten one are the compiler's `undefined`
/// fill, and asking them whether node 4 is in the swarm is asking a `bool`
/// field for a bit pattern that is not a bool.
pub const Peer = struct {
    id: NodeId,
    /// Whether the node is still on the topic. Upstream drops the whole
    /// per-topic state on `Quit` and then ignores every later event for
    /// it, which is what this flag reproduces: a node that left does not
    /// start answering `Join` requests again because a message arrived.
    joined: bool = false,
    state: TopicState,
};

const QueueEntry = struct {
    time: Nanos,
    peer: u8,
    event: InEvent,
};

pub const Conn = struct { a: u8, b: u8 };

pub const Latency = struct { conn: Conn, latency: Nanos };

pub const Network = struct {
    gpa: Allocator,
    /// Where payloads of parked messages are copied. This is the one place
    /// a message outlives the state that produced it, and it is where the
    /// borrow rule both layers document is discharged.
    arena: std.heap.ArenaAllocator,
    rng: Rng,
    config: NetworkConfig,
    time: Nanos,
    /// The three fixed arrays below stay `undefined`, and that is safe for
    /// exactly one reason each: every read of `links` and `latencies` is
    /// cut by its own counter, and every read of `peers` is cut by
    /// `occupied`. Occupancy is therefore a field of its own and not a
    /// flag inside a `Peer` nobody has written.
    peers: [max_peers]Peer,
    /// Which slots hold a node. The only defined record of that.
    occupied: [max_peers]bool,
    peer_count: usize,
    queue: std.ArrayList(QueueEntry),
    events: std.ArrayList(SimEvent),
    links: [max_conns]Conn,
    conn_count: usize,
    latencies: [max_conns]Latency,
    latency_count: usize,

    // ziglint-ignore: Z012 Z015
    pub fn init(
        gpa: Allocator,
        config: NetworkConfig,
        seed: u64,
    ) HarnessError!Network {
        try config.membership.validate();
        return .{
            .gpa = gpa,
            .arena = std.heap.ArenaAllocator.init(gpa),
            .rng = .init(seed),
            .config = config,
            .time = 0,
            .peers = undefined,
            .occupied = [_]bool{false} ** max_peers,
            .peer_count = 0,
            .queue = .empty,
            .events = .empty,
            .links = undefined,
            .conn_count = 0,
            .latencies = undefined,
            .latency_count = 0,
        };
    }

    pub fn deinit(self: *Network) void {
        self.queue.deinit(self.gpa);
        self.events.deinit(self.gpa);
        self.arena.deinit();
        // Everything above is freed, so the struct is poisoned rather than
        // half-reset: a field that still looked like a network would read
        // as a plausible run instead of as the use-after-free that it is.
        self.* = undefined;
    }

    // ziglint-ignore: Z015
    /// Add a node. Upstream `Network::insert_with_config`.
    pub fn insert(self: *Network, index: u8) HarnessError!void {
        if (index >= max_peers) return error.PeerIndexOutOfRange;
        if (self.occupied[index]) return error.DuplicatePeer;
        // Upstream draws each node's generator from the network's, so two
        // nodes in one simulation do not walk in lockstep.
        const rng = self.rng.child();
        // Minted before the slot is written and used twice: a `NodeId` is
        // a key derivation, not a lookup, and a slot written from one
        // `id` and another `state.id` would be a swarm that disagrees
        // with itself about who it is.
        const id = try nodeIdFor(index);
        self.peers[index] = .{
            .id = id,
            .joined = true,
            .state = try TopicState.init(
                id,
                null,
                self.config.topicConfig(),
                rng,
            ),
        };
        // Marked after the state is built: a `TopicState.init` that fails
        // leaves the slot as it found it.
        self.occupied[index] = true;
        if (index + 1 > self.peer_count) self.peer_count = index + 1;
    }

    // ziglint-ignore: Z015
    /// Add a node and send it a join command. Upstream
    /// `Network::insert_and_join`.
    pub fn insertAndJoin(
        self: *Network,
        index: u8,
        bootstrap: []const u8,
    ) HarnessError!void {
        try self.insert(index);
        var peers: [max_bootstrap]NodeId = undefined;
        for (bootstrap, 0..) |peer, position| peers[position] = try nodeIdFor(peer);
        try run.command(self, index, .{ .join = try Peers.init(peers[0..bootstrap.len]) });
    }

    pub fn peerOf(self: *const Network, index: u8) ?*const Peer {
        if (index >= max_peers) return null;
        if (!self.occupied[index]) return null;
        return &self.peers[index];
    }

    pub fn peerSlot(self: *Network, index: u8) ?*Peer {
        if (index >= max_peers) return null;
        if (!self.occupied[index]) return null;
        return &self.peers[index];
    }

    pub fn peerIndexOf(self: *const Network, id: NodeId) ?u8 {
        for (self.peers[0..self.peer_count], 0..) |peer, index| {
            if (!self.occupied[index]) continue;
            if (sameNode(peer.id, id)) return @intCast(index);
        }
        return null;
    }

    /// The membership layer's active view for one node, as node ids.
    pub fn neighbors(self: *const Network, index: u8) []const NodeId {
        const peer = self.peerOf(index) orelse return &.{};
        if (!peer.joined) return &.{};
        return peer.state.swarm.activeView();
    }

    /// Whether a node is still on the topic. Upstream asserts this after a
    /// quit with `network.peer(&3).unwrap().state(&t).is_none()`.
    pub fn hasJoined(self: *const Network, index: u8) bool {
        const peer = self.peerOf(index) orelse return false;
        return peer.joined;
    }

    /// The same view as node indices, which is what a test asserts on.
    pub fn neighborIndices(self: *const Network, index: u8, out: *[max_peers]u8) usize {
        var count: usize = 0;
        for (self.neighbors(index)) |peer| {
            const found = self.peerIndexOf(peer) orelse continue;
            out[count] = found;
            count += 1;
        }
        return count;
    }

    /// The broadcast layer's eager set as node indices.
    pub fn eagerIndices(self: *const Network, index: u8, out: *[max_peers]u8) usize {
        const peer = self.peerOf(index) orelse return 0;
        var count: usize = 0;
        for (peer.state.gossip.eagerPeers()) |eager| {
            const found = self.peerIndexOf(eager) orelse continue;
            out[count] = found;
            count += 1;
        }
        return count;
    }

    pub fn hasNeighbor(self: *const Network, index: u8, other: u8) bool {
        var found: [max_peers]u8 = undefined;
        const count = self.neighborIndices(index, &found);
        for (found[0..count]) |candidate| {
            if (candidate == other) return true;
        }
        return false;
    }

    pub fn neighborCount(self: *const Network, index: u8) usize {
        return self.neighbors(index).len;
    }

    // The methods below are the run and the report, which live in their own
    // files. They stay methods here because `sim.zig` hands `Network` to
    // `sim_simulator.zig` and `sim_test.zig`, which call them as methods, and
    // a forwarder is what keeps those call sites as they are.

    pub fn tick(self: *Network) HarnessError!void {
        return run.tick(self);
    }

    // ziglint-ignore: Z015
    /// Hand a command to a node, then run whatever the current instant
    /// has queued. Upstream `Network::command`.
    pub fn command(self: *Network, index: u8, request: Command) HarnessError!void {
        return run.command(self, index, request);
    }

    // ziglint-ignore: Z015
    pub fn runTrips(self: *Network, count: u64) HarnessError!void {
        return run.runTrips(self, count);
    }

    // ziglint-ignore: Z015
    pub fn runDuration(self: *Network, duration: Nanos) HarnessError!void {
        return run.runDuration(self, duration);
    }

    /// When the next queued event is due, or `null` when nothing is
    /// pending. A gossip round uses this to stop on its timeout.
    pub fn nextTime(self: *const Network) ?Nanos {
        return run.nextTime(self);
    }

    /// Every open link. Upstream `Network::conns`.
    pub fn conns(self: *const Network) []const Conn {
        return run.conns(self);
    }

    /// Are both layers synchronous? In `sim_report.zig`.
    pub fn checkSynchronicity(self: *const Network) bool {
        return report.checkSynchronicity(self);
    }

    /// Links one end still believes in and the other end does not. In
    /// `sim_report.zig`.
    pub fn asymmetricLinks(self: *const Network) usize {
        return report.asymmetricLinks(self);
    }

    /// How many nodes have no neighbours at all. In `sim_report.zig`.
    pub fn peersWithoutNeighbors(self: *const Network) usize {
        return report.peersWithoutNeighbors(self);
    }

    /// The smallest and largest active view in the swarm. In `sim_report.zig`.
    pub fn activeExtent(self: *const Network) report.Extent {
        return report.activeExtent(self);
    }

    /// The neighbour changes seen so far, sorted. In `sim_report.zig`.
    pub fn neighbourEvents(
        self: *const Network,
        out: *[max_neighbour_events]NeighbourEvent,
    ) []NeighbourEvent {
        return report.neighbourEvents(self, out);
    }
};
