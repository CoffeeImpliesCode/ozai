//! The active and passive views: what joins them, what evicts from them, and
//! what refills them.
//!
//! Every function here changes one of the two `IndexSet`s or the pending-request
//! set beside them, and none of them chooses which peer: that is the random
//! walk in `state_shuffle.zig` and the arms in `state_arms.zig`. The reason a
//! peer is told about its removal, and the `Disconnect` itself, are in
//! `state_departure.zig`.
//! Derived refills decline an unwritable local `Neighbor` without changing
//! caller-owned contact or departure transitions. Explicit `sendNeighbor`
//! requests still report `MessageTooLarge`.
const std = @import("std");
const key = @import("../../base/key.zig");
const plumtree = @import("../plumtree.zig");
const codec = @import("../codec.zig");
const bounds = @import("bounds.zig");
const wire = @import("message.zig");
const node_id = @import("node_id.zig");
const machine = @import("state_machine.zig");
const departure = @import("state_departure.zig");

const Allocator = std.mem.Allocator;
const NodeId = key.NodeId;
const Actions = plumtree.Actions;
const Error = bounds.Error;
const max_active = bounds.max_active;
const max_passive = bounds.max_passive;
const Priority = wire.Priority;
const SwarmOutEvent = wire.SwarmOutEvent;
const RemovalReason = machine.RemovalReason;
const State = machine.State;

fn passiveIsFull(self: *const State) bool {
    return self.passive_view.count() >= self.config.passive_view_capacity;
}

fn activeIsFull(self: *const State) bool {
    return self.active_view.count() >= self.config.active_view_capacity;
}

/// Upstream `add_passive`. A peer that is active is not also passive, and
/// neither is this node.
pub fn addPassive(
    self: *State,
    peer: NodeId,
    data: ?[]const u8,
    out: *Actions(SwarmOutEvent),
) (Error || Allocator.Error)!void {
    try self.insertPeerInfo(.{ .id = peer, .data = data }, out);
    if (node_id.sameNode(peer, self.me)) return;
    if (self.active_view.contains(peer)) return;
    if (self.passive_view.contains(peer)) return;
    if (passiveIsFull(self)) {
        const index = self.passive_view.pickRandomIndex(&self.rng) orelse return;
        _ = self.passive_view.removeAt(index);
    }
    _ = try self.passive_view.insert(peer);
}

/// Upstream `remove_active`.
pub fn removeActive(
    self: *State,
    peer: NodeId,
    reason: RemovalReason,
    out: *Actions(SwarmOutEvent),
) (Error || Allocator.Error)!void {
    const index = self.active_view.indexOf(peer) orelse return;
    const gone = try removeActiveByIndex(self, index, reason, out);
    const skip = [_]NodeId{gone};
    try refillActiveFromPassive(self, &skip, out);
}

/// Upstream `refill_active_from_passive`.
///
/// Note what this does *not* do: it does not add the peer to the active
/// view. It sends a `Neighbor`, which starts the exchange that ends with
/// the peer being added — or not. A refill that added eagerly would put
/// unreachable peers into the view, which is the same bug the deviation
/// fixes, in the path that runs most often.
pub fn refillActiveFromPassive(
    self: *State,
    skip: []const NodeId,
    out: *Actions(SwarmOutEvent),
) (Error || Allocator.Error)!void {
    if (self.active_view.count() + self.pending_neighbor_requests.count() >=
        self.config.active_view_capacity)
    {
        return;
    }
    const priority: Priority = if (self.active_view.count() == 0) .high else .low;
    const message: wire.SwarmMessage = .{ .neighbor = .{
        .priority = priority,
        .data = self.myData(),
    } };
    // A refill is derived work: decline it before choosing a peer or claiming
    // a request, without rejecting the contact or departure that triggered it.
    if (codec.encodedLen(.{ .swarm = message }) >= codec.max_message_size) return;
    // "When a node p suspects that one of the nodes present in its active
    // view has failed ..., it selects a random node q from its passive view
    // and attempts to establish a connection with q. If the connection
    // fails to establish, node q is considered failed and removed from p's
    // passive view; another node q' is selected at random and a new attempt
    // is made." (p7)
    var skip_all: [max_passive + max_active]NodeId = undefined;
    var count: usize = 0;
    for (skip) |peer| {
        skip_all[count] = peer;
        count += 1;
    }
    for (self.pending_neighbor_requests.slice()) |peer| {
        skip_all[count] = peer;
        count += 1;
    }
    const node = self.passive_view.pickRandomWithout(skip_all[0..count], &self.rng) orelse
        return;
    try sendNeighborAdmitted(self, node, message, out);
    try out.push(.{ .schedule_timer = .{
        .after = self.config.neighbor_request_timeout,
        .timer = .{ .pending_neighbor_request = node },
    } });
}

/// Upstream `handle_pending_neighbor_timer`: the `Neighbor` was never
/// answered, so the peer is unreachable and is dropped.
pub fn handlePendingNeighborTimer(
    self: *State,
    peer: NodeId,
    out: *Actions(SwarmOutEvent),
) (Error || Allocator.Error)!void {
    if (!self.pending_neighbor_requests.remove(peer)) return;
    _ = self.passive_view.remove(peer);
    try refillActiveFromPassive(self, &.{}, out);
}

/// Upstream `remove_active_by_index`. Returns the peer that left, which
/// the caller must not ask about again.
fn removeActiveByIndex(
    self: *State,
    index: usize,
    reason: RemovalReason,
    out: *Actions(SwarmOutEvent),
) (Error || Allocator.Error)!NodeId {
    const peer = self.active_view.removeAt(index);
    try out.push(.{ .emit_event = .{ .neighbor_down = peer } });
    switch (reason) {
        // Send a disconnect message, then close the connection.
        .random => try departure.sendDisconnect(self, peer, true, out),
        // Close the connection without sending anything further.
        .disconnect_received, .connection_closed => try out.push(.{ .disconnect_peer = peer }),
    }
    const keep_as_passive = switch (reason) {
        // Keep it if it had already told us it was only closing.
        .connection_closed => self.alive_disconnect_peers.remove(peer),
        // Keep it if the peer said it is still in the swarm.
        .disconnect_received => |is_alive| is_alive,
        // We are the one removing it, for now.
        .random => true,
    };
    if (keep_as_passive) {
        // The slice borrows the table entry, and `addPassive` writes back
        // into that same table, so nothing may be removed first.
        const data = self.peer_data.get(peer);
        try addPassive(self, peer, if (data) |held| held.slice() else null, out);
        const was_a_close = switch (reason) {
            .connection_closed => true,
            else => false,
        };
        if (!was_a_close) _ = try self.alive_disconnect_peers.insert(peer);
    }
    return peer;
}

/// Upstream `free_random_slot_in_active_view`.
fn freeRandomSlotInActiveView(
    self: *State,
    out: *Actions(SwarmOutEvent),
) (Error || Allocator.Error)!void {
    const index = self.active_view.pickRandomIndex(&self.rng) orelse return;
    _ = try removeActiveByIndex(self, index, .random, out);
}

/// Upstream `add_active`. `false` means the request was refused, and the
/// caller sends a `Disconnect` for it.
pub fn addActive(
    self: *State,
    peer: NodeId,
    data: ?[]const u8,
    priority: Priority,
    reply: bool,
    out: *Actions(SwarmOutEvent),
) (Error || Allocator.Error)!bool {
    if (node_id.sameNode(peer, self.me)) return false;
    if (reply and !self.pending_neighbor_requests.contains(peer) and
        (priority == .high or !activeIsFull(self) or self.active_view.contains(peer)))
    {
        const message: wire.SwarmMessage = .{ .neighbor = .{
            .priority = priority,
            .data = self.myData(),
        } };
        if (codec.encodedLen(.{ .swarm = message }) >= codec.max_message_size) {
            return error.MessageTooLarge;
        }
    }
    try self.insertPeerInfo(.{ .id = peer, .data = data }, out);
    if (self.active_view.contains(peer)) {
        if (reply) try sendNeighbor(self, peer, priority, out);
        return true;
    }
    if (priority == .high) {
        if (activeIsFull(self)) try freeRandomSlotInActiveView(self, out);
        try addActiveUnchecked(self, peer, .high, reply, out);
        return true;
    }
    if (activeIsFull(self)) return false;
    try addActiveUnchecked(self, peer, .low, reply, out);
    return true;
}

fn addActiveUnchecked(
    self: *State,
    peer: NodeId,
    priority: Priority,
    reply: bool,
    out: *Actions(SwarmOutEvent),
) (Error || Allocator.Error)!void {
    _ = self.passive_view.remove(peer);
    if (try self.active_view.insert(peer)) {
        try out.push(.{ .emit_event = .{ .neighbor_up = peer } });
        if (reply) try sendNeighbor(self, peer, priority, out);
    }
}

/// Upstream `send_neighbor`: one `Neighbor` per request, no more. The
/// pending entry is the claim that the request was made, so it is withdrawn
/// with the request rather than left standing on a refused append.
pub fn sendNeighbor(
    self: *State,
    peer: NodeId,
    priority: Priority,
    out: *Actions(SwarmOutEvent),
) (Error || Allocator.Error)!void {
    if (self.pending_neighbor_requests.contains(peer)) return;
    const message: wire.SwarmMessage = .{ .neighbor = .{
        .priority = priority,
        .data = self.myData(),
    } };
    if (codec.encodedLen(.{ .swarm = message }) >= codec.max_message_size) {
        return error.MessageTooLarge;
    }
    try sendNeighborAdmitted(self, peer, message, out);
}

/// Commits a `Neighbor` whose actual envelope already passed write admission.
fn sendNeighborAdmitted(
    self: *State,
    peer: NodeId,
    message: wire.SwarmMessage,
    out: *Actions(SwarmOutEvent),
) (Error || Allocator.Error)!void {
    if (!try self.pending_neighbor_requests.insert(peer)) return;
    // The timer that clears this entry is queued by the caller after this
    // returns, so a claim left behind by a refused append is one nothing
    // owns: every later refill skips the peer and counts it against the
    // active-view capacity, and nothing ever times it out.
    errdefer std.debug.assert(self.pending_neighbor_requests.remove(peer));
    try out.push(.{ .send_message = .{
        .to = peer,
        .message = message,
    } });
}
