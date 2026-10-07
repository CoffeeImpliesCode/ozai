//! The random walk that mixes the two views.
//!
//! A `Shuffle` and a `ShuffleReply` in both directions, plus the timer that
//! starts a walk, and the reply builder they share: a random slice of the
//! passive view topped up from the active one. The views it draws from and
//! refills are in `state_views.zig`, and the contact data a listed peer carries
//! is read through `state_machine.zig`.
const std = @import("std");
const key = @import("../../base/key.zig");
const plumtree = @import("../plumtree.zig");
const codec = @import("../codec.zig");
const bounds = @import("bounds.zig");
const peers = @import("peer_data.zig");
const wire = @import("message.zig");
const machine = @import("state_machine.zig");
const views = @import("state_views.zig");
const node_id = @import("node_id.zig");
const entropy = @import("rng.zig");
const index_set = @import("index_set.zig");

const Allocator = std.mem.Allocator;
const NodeId = key.NodeId;
const Actions = plumtree.Actions;
const Error = bounds.Error;
const max_shuffle_nodes = bounds.max_shuffle_nodes;
const PeerInfo = peers.PeerInfo;
const PeerInfos = peers.PeerInfos;
const Shuffle = wire.Shuffle;
const ShuffleReply = wire.ShuffleReply;
const SwarmOutEvent = wire.SwarmOutEvent;
const State = machine.State;

/// Upstream `on_shuffle`.
pub fn onShuffle(
    self: *State,
    from: NodeId,
    message: Shuffle,
    out: *Actions(SwarmOutEvent),
) (Error || Allocator.Error)!void {
    // "A node q that receives a Shuffle request will first decrease its
    // time to live. If the time to live of the message is greater than zero
    // and the number of nodes in q's active view is greater than 1, the
    // node will select a random node from its active view, different from
    // the one he received this shuffle message from, and simply forwards
    // the Shuffle request. Otherwise, node q accepts the Shuffle request
    // and send back (p.8)"
    if (message.ttl.expired() or self.active_view.count() <= 1) {
        try acceptShuffle(self, message, out);
        return;
    }
    const excluded = [_]NodeId{ message.origin, from };
    var rng = self.rng;
    const next = self.active_view.pickRandomWithout(&excluded, &rng) orelse {
        // Nothing to forward to: answer instead of dropping the shuffle,
        // which is what upstream's `else` arm does by falling through to
        // the end of the function and losing the message.
        try acceptShuffle(self, message, out);
        return;
    };
    const forward: wire.SwarmMessage = .{ .shuffle = .{
        .origin = message.origin,
        .nodes = message.nodes,
        .ttl = message.ttl.next(),
    } };
    if (codec.encodedLen(.{ .swarm = forward }) >= codec.max_message_size) {
        return error.MessageTooLarge;
    }
    self.rng = rng;
    try out.push(.{ .send_message = .{
        .to = next,
        .message = forward,
    } });
}

/// Upstream `send_shuffle_reply`: a random slice of the passive view,
/// topped up from the active view if the passive one is too short.
/// `without` names the peers neither half may offer.
pub fn sendShuffleReply(
    self: *State,
    to: NodeId,
    without: []const NodeId,
    len: usize,
    out: *Actions(SwarmOutEvent),
) (Error || Allocator.Error)!void {
    var rng = self.rng;
    const nodes = try replyNodes(self, &self.passive_view, without, len, &rng);
    const message: wire.SwarmMessage = .{ .shuffle_reply = .{ .nodes = nodes } };
    if (codec.encodedLen(.{ .swarm = message }) >= codec.max_message_size) {
        return error.MessageTooLarge;
    }
    self.rng = rng;
    try out.push(.{ .send_message = .{ .to = to, .message = message } });
}

fn replyNodes(
    self: *const State,
    passive: *const index_set.IndexSet(bounds.max_passive),
    without: []const NodeId,
    len: usize,
    rng: *entropy.Rng,
) Error!PeerInfos {
    var chosen: [max_shuffle_nodes]NodeId = undefined;
    const wanted = @min(len, max_shuffle_nodes);
    var count = passive.shuffledWithoutAndCapped(without, wanted, rng, &chosen);
    if (count < wanted) {
        count += self.active_view.shuffledWithoutAndCapped(
            without,
            wanted - count,
            rng,
            chosen[count..],
        );
    }
    var listed: [max_shuffle_nodes]PeerInfo = undefined;
    for (chosen[0..count], 0..) |peer, index| self.peerInfoInto(peer, &listed[index]);
    return PeerInfos.init(listed[0..count]);
}

fn acceptShuffle(
    self: *State,
    message: Shuffle,
    out: *Actions(SwarmOutEvent),
) (Error || Allocator.Error)!void {
    // Project only ids and entropy: the contact table is too large to snapshot.
    var passive = self.passive_view;
    var rng = self.rng;
    for (message.nodes.slice()) |node| {
        if (node_id.sameNode(node.id, self.me) or
            self.active_view.contains(node.id) or passive.contains(node.id)) continue;
        if (passive.count() >= self.config.passive_view_capacity) {
            const index = passive.pickRandomIndex(&rng) orelse continue;
            _ = passive.removeAt(index);
        }
        _ = try passive.insert(node.id);
    }
    var nodes = try replyNodes(self, &passive, &.{}, message.nodes.count, &rng);
    // A received contact replaces the stored one before the reply is sampled.
    for (nodes.items[0..nodes.count]) |*listed| {
        for (message.nodes.slice()) |node| {
            if (node_id.sameNode(listed.id, node.id)) {
                if (node.data) |data| listed.data = data;
            }
        }
    }
    const reply: wire.SwarmMessage = .{ .shuffle_reply = .{ .nodes = nodes } };
    if (codec.encodedLen(.{ .swarm = reply }) >= codec.max_message_size) {
        return error.MessageTooLarge;
    }
    for (message.nodes.slice()) |node| try views.addPassive(self, node.id, node.data, out);
    self.rng = rng;
    // Output borrows the committed table, never the incoming contact slices.
    for (nodes.items[0..nodes.count]) |*listed| self.peerInfoInto(listed.id, listed);
    try out.push(.{ .send_message = .{
        .to = message.origin,
        .message = .{ .shuffle_reply = .{ .nodes = nodes } },
    } });
}

/// Upstream `on_shuffle_reply`: take what we were given, then fill any gap
/// in the active view from what we now know.
pub fn onShuffleReply(
    self: *State,
    message: ShuffleReply,
    out: *Actions(SwarmOutEvent),
) (Error || Allocator.Error)!void {
    for (message.nodes.slice()) |node| try views.addPassive(self, node.id, node.data, out);
    try views.refillActiveFromPassive(self, &.{}, out);
}

/// Upstream `handle_shuffle_timer`: start a walk from a random active
/// peer, carrying part of both views and ourselves. The walk after this one
/// is armed by the tail of `handle`, which is the only thing that arms one.
pub fn handleShuffleTimer(
    self: *State,
    out: *Actions(SwarmOutEvent),
) (Error || Allocator.Error)!void {
    // A size refusal leaves the candidate and RNG uncommitted. Once it fits,
    // release the consumed timer's latch before the fallible output append so
    // an allocation refusal cannot leave an outstanding-timer claim behind.
    var rng = self.rng;
    if (self.active_view.pickRandom(&rng)) |node| {
        var chosen: [max_shuffle_nodes]NodeId = undefined;
        var count = self.active_view.shuffledWithoutAndCapped(
            &.{node},
            self.config.shuffle_active_view_count,
            &rng,
            &chosen,
        );
        count += self.passive_view.shuffledWithoutAndCapped(
            &.{node},
            self.config.shuffle_passive_view_count,
            &rng,
            chosen[count..],
        );
        var listed: [max_shuffle_nodes]PeerInfo = undefined;
        for (chosen[0..count], 0..) |peer, index| self.peerInfoInto(peer, &listed[index]);
        listed[count] = .{ .id = self.me, .data = self.myData() };
        const message: wire.SwarmMessage = .{ .shuffle = .{
            .origin = self.me,
            .nodes = try PeerInfos.init(listed[0 .. count + 1]),
            .ttl = self.config.shuffle_random_walk_length,
        } };
        if (codec.encodedLen(.{ .swarm = message }) >= codec.max_message_size) {
            return error.MessageTooLarge;
        }
        self.rng = rng;
        self.shuffle_scheduled = false;
        try out.push(.{ .send_message = .{ .to = node, .message = message } });
    }
    self.shuffle_scheduled = false;
}
