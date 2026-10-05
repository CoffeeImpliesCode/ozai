//! Reading a run back: what the swarm believes, and how far it is from
//! agreeing with itself.
//!
//! These are the questions a state-machine test cannot answer, because they
//! are questions about two nodes rather than about one: whether every active
//! neighbour lists us, whether every eager peer lists us, how many links one
//! end believes in and the other does not, and which neighbour changes the run
//! saw. None of them advances the clock.
const std = @import("std");
const harness = @import("sim_harness.zig");
const swarm = @import("sim_swarm.zig");

/// The two ends of the active-view histogram, reduced to what a port can be
/// held to. Named because `sim_swarm.zig` forwards the method and two
/// separately written anonymous structs are two distinct types.
pub const Extent = struct { min: usize, max: usize };

const max_peers = harness.max_peers;
const max_neighbour_events = harness.max_neighbour_events;
const NeighbourEvent = harness.NeighbourEvent;
const Network = swarm.Network;

/// Are both layers synchronous? Upstream `check_synchronicity`: every
/// active neighbour of ours lists us, and every eager peer of ours
/// lists us.
///
/// This is the check the protocol exists to make true, and the one
/// thing a state-machine test cannot make. A membership layer that
/// inserts on `ForwardJoin` passes every message-level test and fails
/// here, because a node that inserted a peer it never reached believes
/// in a link the other end has no record of.
pub fn checkSynchronicity(self: *const Network) bool {
    var ours: [max_peers]u8 = undefined;
    var theirs: [max_peers]u8 = undefined;
    for (self.peers[0..self.peer_count], 0..) |peer, index| {
        if (!self.occupied[index] or !peer.joined) continue;
        const me: u8 = @intCast(index);
        for (peer.state.swarm.activeView()) |neighbour| {
            const other = self.peerIndexOf(neighbour) orelse continue;
            // A node that has left the topic has no view to be held
            // to, which is why upstream's check reaches for a state
            // that a quit has already removed.
            if (!self.hasJoined(other)) continue;
            const count = self.neighborIndices(other, &theirs);
            if (!hasIndex(theirs[0..count], me)) return false;
        }
        for (peer.state.gossip.eagerPeers()) |eager| {
            const other = self.peerIndexOf(eager) orelse continue;
            if (!self.hasJoined(other)) continue;
            const count = self.eagerIndices(other, &ours);
            if (!hasIndex(ours[0..count], me)) return false;
        }
    }
    return true;
}

/// Links one end still believes in and the other end does not.
///
/// A healthy converged swarm has none, and this is the number that says
/// so more honestly than "no node is alone": a node can have three
/// neighbours and one of them can be a fiction.
///
/// It is not always zero, and that is upstream rather than a port
/// defect. `on_neighbor` treats a `Neighbor` as a *reply* whenever the
/// sender is in `pending_neighbor_requests`, and a reply is not
/// answered. So a node that evicts a peer for room, and then receives
/// the `Neighbor` that peer had sent moments earlier, silently puts it
/// back — and then processes the `Disconnect` the eviction produced,
/// which removes the *other* end. The two views disagree and, because
/// the requester's pending entry is spent, nothing ever asks again.
/// Upstream has the identical code path; `check_synchronicity` is a
/// helper, not a property it claims, and its own convergence test
/// asserts only that no node is left without neighbours.
///
/// What must hold — and what this is for — is that the count does not
/// grow: a swarm that has stopped joining stops disagreeing.
pub fn asymmetricLinks(self: *const Network) usize {
    var count: usize = 0;
    var index: u8 = 0;
    while (index < self.peer_count) : (index += 1) {
        if (!self.hasJoined(index)) continue;
        for (self.neighbors(index)) |neighbour| {
            const other = self.peerIndexOf(neighbour) orelse continue;
            if (other <= index) continue;
            if (self.hasNeighbor(other, index)) continue;
            count += 1;
        }
    }
    return count;
}

/// How many nodes have no neighbours at all. A converged swarm has
/// none, and upstream's bootstrap asserts exactly this.
pub fn peersWithoutNeighbors(self: *const Network) usize {
    var count: usize = 0;
    for (self.peers[0..self.peer_count], 0..) |_, index| {
        if (!self.occupied[index]) continue;
        if (self.neighborCount(@intCast(index)) == 0) count += 1;
    }
    return count;
}

/// The smallest and largest active view in the swarm. Upstream
/// `NetworkReport`'s active histogram, reduced to its two ends: a mean
/// would hide the one node that came out empty, which is the number
/// that matters.
pub fn activeExtent(self: *const Network) Extent {
    var smallest: usize = max_peers;
    var largest: usize = 0;
    for (self.peers[0..self.peer_count], 0..) |_, index| {
        if (!self.occupied[index]) continue;
        const count = self.neighborCount(@intCast(index));
        smallest = @min(smallest, count);
        largest = @max(largest, count);
    }
    return .{ .min = smallest, .max = largest };
}

/// The neighbour changes seen so far, sorted, so a test can hold a run
/// against upstream's expected event lists.
pub fn neighbourEvents(
    self: *const Network,
    out: *[max_neighbour_events]NeighbourEvent,
) []NeighbourEvent {
    var count: usize = 0;
    for (self.events.items) |seen| switch (seen.event) {
        .neighbor_up => |peer| {
            if (count == max_neighbour_events) break;
            const other = self.peerIndexOf(peer) orelse continue;
            out[count] = .{ .up = true, .a = seen.peer, .b = other };
            count += 1;
        },
        .neighbor_down => |peer| {
            if (count == max_neighbour_events) break;
            const other = self.peerIndexOf(peer) orelse continue;
            out[count] = .{ .up = false, .a = seen.peer, .b = other };
            count += 1;
        },
        .received => {},
    };
    const slice = out[0..count];
    std.mem.sort(NeighbourEvent, slice, {}, lessNeighbourEvent);
    return slice;
}

fn lessNeighbourEvent(_: void, a: NeighbourEvent, b: NeighbourEvent) bool {
    if (a.a != b.a) return a.a < b.a;
    if (a.b != b.b) return a.b < b.b;
    return !a.up and b.up;
}

fn hasIndex(indices: []const u8, wanted: u8) bool {
    for (indices) |index| {
        if (index == wanted) return true;
    }
    return false;
}