//! A peer leaving, and this node leaving.
//!
//! Two ways out and one way to announce either: a `Disconnect` that arrived, a
//! connection that closed under us, and the `Quit` that drops the whole state.
//! What each does to the views is `state_views.zig`'s, and the `ShuffleReply`
//! a departing peer is owed — enough of our view to keep it connected — is
//! `state_shuffle.zig`'s.
const std = @import("std");
const key = @import("../../base/key.zig");
const plumtree = @import("../plumtree.zig");
const bounds = @import("bounds.zig");
const wire = @import("message.zig");
const machine = @import("state_machine.zig");
const shuffle = @import("state_shuffle.zig");
const views = @import("state_views.zig");

const Allocator = std.mem.Allocator;
const NodeId = key.NodeId;
const Actions = plumtree.Actions;
const Error = bounds.Error;
const Disconnect = wire.Disconnect;
const SwarmOutEvent = wire.SwarmOutEvent;
const State = machine.State;

/// Upstream `on_disconnect`.
pub fn onDisconnect(
    self: *State,
    peer: NodeId,
    details: Disconnect,
    out: *Actions(SwarmOutEvent),
) (Error || Allocator.Error)!void {
    _ = self.pending_neighbor_requests.remove(peer);
    if (self.active_view.contains(peer)) {
        try views.removeActive(self, peer, .{ .disconnect_received = details.alive }, out);
    } else if (details.alive and self.passive_view.contains(peer)) {
        _ = try self.alive_disconnect_peers.insert(peer);
    }
}

/// Upstream `handle_connection_closed`.
pub fn handleConnectionClosed(
    self: *State,
    peer: NodeId,
    out: *Actions(SwarmOutEvent),
) (Error || Allocator.Error)!void {
    _ = self.pending_neighbor_requests.remove(peer);
    if (self.active_view.contains(peer)) {
        try views.removeActive(self, peer, .connection_closed, out);
    } else if (!self.alive_disconnect_peers.remove(peer)) {
        _ = self.passive_view.remove(peer);
    }
}

/// Upstream `handle_quit`, and all of what a quit drops.
///
/// The active view goes first and noisily: every peer in it owes a
/// `ShuffleReply` and a `Disconnect` so it is not left holding a half-open
/// belief about a neighbour that has gone. That output is the one part of
/// leaving a caller can observe, and it is why the loop drains the view
/// rather than clearing it.
///
/// Everything else is dropped in silence, and all of it is state about the
/// topic rather than about this node: the passive view, the unanswered
/// neighbour requests, the peers that said they were still alive as they
/// disconnected, and the contact data. `peer_data` is the one that matters
/// beyond tidiness: those are the bytes this node would offer those peers
/// to somebody else, and clearing the table is what stops it.
///
/// `me_data` survives, because it is this node's own contact data and not
/// the topic's; so does `stats`, which reports what the node did while it
/// was here. `shuffle_scheduled` goes, because `left` has taken over the
/// question of whether any timer is still wanted.
///
/// **A failure part way leaves a partial drain, not a partial quit.** A peer
/// leaves the active view only once its whole `sendDisconnect` has been
/// appended, so at every refusal the peer being told is still in the view
/// and `left` is not yet set — a caller that retries gets the same peer
/// again, and the drain can finish.
/// That is deliberate: a peer forgotten without a `Disconnect` leaves the
/// other side holding a neighbour belief nothing will correct, and no
/// retry can reach it.
///
/// What a refusal does leave is a published prefix. `sendDisconnect`
/// appends a `ShuffleReply`, then the `Disconnect`, then the
/// `disconnect_peer`, so a refusal at the second or third append leaves the
/// reply on the wire with the peer still in the view, and the retry sends a
/// second one before the `Disconnect`. That is the residue; no retry is
/// promised to be free of it, and the price is a duplicate node list rather
/// than anything the other node has to reconcile. Nothing else has moved:
/// the tables dropped below are untouched until the drain finishes.
pub fn handleQuit(self: *State, out: *Actions(SwarmOutEvent)) (Error || Allocator.Error)!void {
    while (self.active_view.count() > 0) {
        const peer = self.active_view.at(0);
        // Told first, forgotten second, for the reason the failure paragraph
        // gives: a peer taken out of the view before its `Disconnect` was
        // published is one no retry can reach. `sendDisconnect` reads the
        // views and the contact table and writes none of them, so the peer
        // is still in the view while its farewell is built — which is why
        // the farewell excludes it by name.
        try sendDisconnect(self, peer, false, out);
        _ = self.active_view.removeAt(0);
    }
    self.passive_view.clear();
    self.pending_neighbor_requests.clear();
    self.alive_disconnect_peers.clear();
    self.peer_data.clear();
    self.shuffle_scheduled = false;
    self.left = true;
}

/// Upstream `send_disconnect`. A `ShuffleReply` goes out first, with
/// enough of our view to keep the other node connected: it is about to
/// lose us, and if it has just joined the swarm it may have nobody else.
/// How much of the view is still standing is the caller's business, not
/// this one's: on the quit path the drain empties it as it goes, so the
/// peer told last is offered whatever is left, which is nothing once it is
/// alone. The peer is excluded from whatever that list turned out to be,
/// so it is never recommended to itself, which is what keeps the quit path
/// honest while the peer is still in the active view when this runs.
pub fn sendDisconnect(
    self: *State,
    peer: NodeId,
    alive: bool,
    out: *Actions(SwarmOutEvent),
) (Error || Allocator.Error)!void {
    const offered =
        self.config.shuffle_active_view_count + self.config.shuffle_passive_view_count;
    try shuffle.sendShuffleReply(self, peer, &.{peer}, offered, out);
    try out.push(.{ .send_message = .{
        .to = peer,
        .message = .{ .disconnect = .{ .alive = alive } },
    } });
    try out.push(.{ .disconnect_peer = peer });
}
