//! What a received membership message makes the node do.
//!
//! `handleMessage` and the arms it chooses between, up to and including
//! `onNeighbor`: the join path, the forwarded join that carries the module's
//! one departure from the paper, and the `Neighbor` exchange that answers
//! both. Each arm changes the views and the contact table through
//! `state_views.zig` and `state_machine.zig`; the two `Shuffle` arms are in
//! `state_shuffle.zig`, which owns the walk they belong to, and the `Disconnect`
//! arm is in `state_departure.zig`, with the rest of what a peer leaving does.
const std = @import("std");
const key = @import("../../base/key.zig");
const plumtree = @import("../plumtree.zig");
const bounds = @import("bounds.zig");
const peers = @import("peer_data.zig");
const wire = @import("message.zig");
const node_id = @import("node_id.zig");
const machine = @import("state_machine.zig");
const departure = @import("state_departure.zig");
const shuffle = @import("state_shuffle.zig");
const views = @import("state_views.zig");

const Allocator = std.mem.Allocator;
const NodeId = key.NodeId;
const Actions = plumtree.Actions;
const Error = bounds.Error;
const PeerInfo = peers.PeerInfo;
const Neighbor = wire.Neighbor;
const ForwardJoin = wire.ForwardJoin;
const SwarmMessage = wire.SwarmMessage;
const SwarmOutEvent = wire.SwarmOutEvent;
const State = machine.State;

/// Upstream `handle_message`.
pub fn handleMessage(
    self: *State,
    from: NodeId,
    message: SwarmMessage,
    out: *Actions(SwarmOutEvent),
) (Error || Allocator.Error)!void {
    const is_disconnect = message == .disconnect;
    if (!is_disconnect and !self.active_view.contains(from)) {
        self.stats.total_connections += 1;
    }
    switch (message) {
        .join => |data| try onJoin(self, from, data, out),
        .forward_join => |details| try onForwardJoin(self, from, details, out),
        .shuffle => |details| try shuffle.onShuffle(self, from, details, out),
        .shuffle_reply => |details| try shuffle.onShuffleReply(self, details, out),
        .neighbor => |details| try onNeighbor(self, from, details, out),
        .disconnect => |details| try departure.onDisconnect(self, from, details, out),
    }
    // "Disconnect from passive nodes right after receiving a message."
    // Upstream's own comment is that it is not sure this is correct; it is
    // kept because the simulator is compared against upstream, and a
    // difference here changes which connections exist after a run.
    if (!is_disconnect and !self.active_view.contains(from)) {
        try out.push(.{ .disconnect_peer = from });
    }
}

/// Upstream `handle_join`: ask a known peer to let us in.
pub fn handleJoin(
    self: *State,
    peer: NodeId,
    out: *Actions(SwarmOutEvent),
) (Error || Allocator.Error)!void {
    try out.push(.{ .send_message = .{
        .to = peer,
        .message = .{ .join = self.myData() },
    } });
}

/// Upstream `on_join`.
///
/// This arm inserts eagerly, exactly as the paper says, and it is worth
/// being explicit about the difference from the deviation below: a direct
/// `Join` arrives from a peer that reached us over a connection it
/// already has, so there is nothing to prove. A `ForwardJoin` arrives from
/// a walk, naming a peer that may never have heard of us.
pub fn onJoin(
    self: *State,
    peer: NodeId,
    data: ?[]const u8,
    out: *Actions(SwarmOutEvent),
) (Error || Allocator.Error)!void {
    // "A node that receives a join request will start by adding the new
    // node to its active view, even if it has to drop a random node from
    // it. (6)"
    _ = try views.addActive(self, peer, data, .high, true, out);

    // "The contact node c will then send to all other nodes in its active
    // view a ForwardJoin request containing the new node identifier. (7)"
    const ttl = self.config.active_random_walk_length;
    const info: PeerInfo = .{ .id = peer, .data = data };
    var index: usize = 0;
    while (index < self.active_view.count()) : (index += 1) {
        const node = self.active_view.at(index);
        if (node_id.sameNode(node, peer)) continue;
        try out.push(.{ .send_message = .{
            .to = node,
            .message = .{ .forward_join = .{ .peer = info, .ttl = ttl } },
        } });
    }
}

/// Upstream `on_forward_join`, and the place this module departs from the
/// paper.
pub fn onForwardJoin(
    self: *State,
    sender: NodeId,
    message: ForwardJoin,
    out: *Actions(SwarmOutEvent),
) (Error || Allocator.Error)!void {
    const peer_id = message.peer.id;
    // Already a neighbour: renew, by asking again.
    if (self.active_view.contains(peer_id)) {
        try self.insertPeerInfo(message.peer, out);
        try views.sendNeighbor(self, peer_id, .high, out);
        return;
    }

    // "i) If the time to live is equal to zero or if the number of nodes in
    // p's active view is equal to one, it will add the new node to its
    // active view (7)"
    //
    // Modification from paper: Instead of adding the peer directly to our
    // active view, we only send the Neighbor message. We will add the peer
    // to our active view once we receive a reply from our neighbor. This
    // prevents us adding unreachable peers to our active view.
    //                                          — upstream, verbatim
    if (message.ttl.expired() or self.active_view.count() <= 1) {
        try self.insertPeerInfo(message.peer, out);
        try views.sendNeighbor(self, peer_id, .high, out);
        return;
    }

    // "ii) If the time to live is equal to PRWL, p will insert the new node
    // into its passive view"
    if (message.ttl.eql(self.config.passive_random_walk_length)) {
        try views.addPassive(self, peer_id, message.peer.data, out);
    }
    // "iii) The time to live field is decremented. iv) If, at this point, n
    // has not been inserted in p's active view, p will forward the request
    // to a random node in its active view (different from the one from
    // which the request was received)."
    if (self.active_view.contains(peer_id)) return;
    if (self.pending_neighbor_requests.contains(peer_id)) return;
    // The active view holds at least two peers here, so excluding the
    // sender always leaves one; the `orelse` is a bound, not a guess.
    const next = self.active_view.pickRandomWithout(&.{sender}, &self.rng) orelse return;
    try out.push(.{ .send_message = .{
        .to = next,
        .message = .{ .forward_join = .{
            .peer = message.peer,
            .ttl = message.ttl.next(),
        } },
    } });
}

/// Upstream `on_neighbor`, the other half of the deviation.
pub fn onNeighbor(
    self: *State,
    from: NodeId,
    details: Neighbor,
    out: *Actions(SwarmOutEvent),
) (Error || Allocator.Error)!void {
    // A `Neighbor` that answers one of ours is a reply, and a reply is
    // what causes the insertion; anything else is a request we have to
    // answer ourselves. The classification is upstream's and it is not
    // sound in one corner: a `Neighbor` that arrives after we have already
    // evicted that peer is still taken for a reply, so the peer is put
    // back silently and the `Disconnect` our eviction produced then
    // removes *us* from *its* view. The two halves disagree and, the
    // pending entry being spent, nothing asks again.
    // `sim.Network.asymmetricLinks` measures that, and says the same.
    const is_reply = self.pending_neighbor_requests.remove(from);
    const do_reply = !is_reply;
    // "A node q that receives a high priority neighbor request will always
    // accept the request, even if it has to drop a random member from its
    // active view. If a node q receives a low priority Neighbor request, it
    // will only accept the request if it has a free slot in its active
    // view, otherwise it will refuse the request."
    if (!try views.addActive(self, from, details.data, details.priority, do_reply, out)) {
        try departure.sendDisconnect(self, from, true, out);
    }
}
