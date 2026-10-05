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
const bounds = @import("bounds.zig");
const peers = @import("peer_data.zig");
const wire = @import("message.zig");
const machine = @import("state_machine.zig");
const views = @import("state_views.zig");

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
        const len = message.nodes.count;
        for (message.nodes.slice()) |node| try views.addPassive(self, node.id, node.data, out);
        try sendShuffleReply(self, message.origin, &.{}, len, out);
        return;
    }
    const excluded = [_]NodeId{ message.origin, from };
    const next = self.active_view.pickRandomWithout(&excluded, &self.rng) orelse {
        // Nothing to forward to: answer instead of dropping the shuffle,
        // which is what upstream's `else` arm does by falling through to
        // the end of the function and losing the message.
        const len = message.nodes.count;
        for (message.nodes.slice()) |node| try views.addPassive(self, node.id, node.data, out);
        try sendShuffleReply(self, message.origin, &.{}, len, out);
        return;
    };
    try out.push(.{ .send_message = .{
        .to = next,
        .message = .{ .shuffle = .{
            .origin = message.origin,
            .nodes = message.nodes,
            .ttl = message.ttl.next(),
        } },
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
    var chosen: [max_shuffle_nodes]NodeId = undefined;
    const wanted = @min(len, max_shuffle_nodes);
    var count = self.passive_view.shuffledWithoutAndCapped(without, wanted, &self.rng, &chosen);
    if (count < wanted) {
        count += self.active_view.shuffledWithoutAndCapped(
            without,
            wanted - count,
            &self.rng,
            chosen[count..],
        );
    }
    var listed: [max_shuffle_nodes]PeerInfo = undefined;
    for (chosen[0..count], 0..) |peer, index| self.peerInfoInto(peer, &listed[index]);
    try out.push(.{ .send_message = .{
        .to = to,
        .message = .{ .shuffle_reply = .{ .nodes = try PeerInfos.init(listed[0..count]) } },
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
    // The timer this call answers has already left the caller's queue, so
    // the latch is released before any append below can be refused. Held
    // across them it would be a claim that a timer exists which nothing
    // will ever fire: `handle` arms the next one only while this is clear,
    // so releasing it here is what lets the next event arm one.
    self.shuffle_scheduled = false;
    if (self.active_view.pickRandom(&self.rng)) |node| {
        var chosen: [max_shuffle_nodes]NodeId = undefined;
        var count = self.active_view.shuffledWithoutAndCapped(
            &.{node},
            self.config.shuffle_active_view_count,
            &self.rng,
            &chosen,
        );
        count += self.passive_view.shuffledWithoutAndCapped(
            &.{node},
            self.config.shuffle_passive_view_count,
            &self.rng,
            chosen[count..],
        );
        var listed: [max_shuffle_nodes]PeerInfo = undefined;
        for (chosen[0..count], 0..) |peer, index| self.peerInfoInto(peer, &listed[index]);
        listed[count] = .{ .id = self.me, .data = self.myData() };
        try out.push(.{ .send_message = .{
            .to = node,
            .message = .{ .shuffle = .{
                .origin = self.me,
                .nodes = try PeerInfos.init(listed[0 .. count + 1]),
                .ttl = self.config.shuffle_random_walk_length,
            } },
        } });
    }
}
