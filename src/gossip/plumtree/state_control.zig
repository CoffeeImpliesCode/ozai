//! The control messages — `Prune`, `IHave`, `Graft` — and the tree optimisation
//! they drive.
//!
//! Nothing here carries a payload: each arm changes which peers the payload
//! paths in `state_push.zig` will reach next time, and records the claim that
//! decides it in the table `state_missing.zig` keeps.
const std = @import("std");
const key = @import("../../base/key.zig");
const actions = @import("actions.zig");
const codec = @import("../codec.zig");
const claim_table = @import("claim_table.zig");
const limits = @import("limits.zig");
const wire = @import("message.zig");
const message_id = @import("message_id.zig");
const node_id = @import("node_id.zig");
const tree = @import("state_tree.zig");
const missing = @import("state_missing.zig");
const push = @import("state_push.zig");

const Allocator = std.mem.Allocator;
const NodeId = key.NodeId;
const Actions = actions.Actions;
const Claim = claim_table.Claim;
const Error = limits.Error;
const MessageId = message_id.MessageId;
const Graft = wire.Graft;
const IHave = wire.IHave;
const Round = wire.Round;
const OutEvent = wire.OutEvent;
const State = tree.State;

/// Upstream `optimize_tree`: if a peer claimed a much shorter path to this
/// message than the sender we actually got it from, graft the claimant and
/// prune the sender. Bending the tree towards the shortest path anybody
/// has mentioned is the only self-optimisation PlumTree does.
pub fn optimizeTree(
    self: *State,
    gossip_sender: NodeId,
    round: Round,
    claims: []const Claim,
    out: *Actions(OutEvent),
) (Error || Allocator.Error)!void {
    var best: ?Claim = null;
    for (claims) |claim| {
        if (best == null or claim.round.value < best.?.round.value) best = claim;
    }
    const claim = best orelse return;
    if (claim.round.value >= round.value) return;
    if (round.hopsSince(claim.round) < self.config.optimization_threshold.value) return;

    if (!self.eager_push_peers.contains(claim.peer)) {
        try push.addEager(self, claim.peer);
        try out.push(.{ .send_message = .{ .to = claim.peer, .message = .{ .graft = .{
            .id = null,
            .round = claim.round,
        } } } });
    }
    try push.addLazy(self, gossip_sender);
    try out.push(.{ .send_message = .{
        .to = gossip_sender,
        .message = .{ .prune = {} },
    } });
}

/// Upstream `on_prune`.
pub fn onPrune(self: *State, sender: NodeId) void {
    _ = self.lazy_push_peers.remove(sender);
}

/// Upstream `on_ihave`: remember who claims the message, and start the
/// graft timer once per message rather than once per claim.
pub fn onIHave(
    self: *State,
    sender: NodeId,
    ihaves: []const IHave,
    out: *Actions(OutEvent),
) (Error || Allocator.Error)!void {
    for (ihaves) |ihave| {
        if (self.received_messages.contains(ihave.id)) continue;
        const claim: Claim = .{ .peer = sender, .round = ihave.round };
        const entry = try missing.pushClaim(self, ihave.id, claim);
        if (entry.graft_timer_scheduled) continue;
        // Queued before the flag is set, and that order is the contract:
        // a latch set first is a claim that a timer exists which the
        // caller never received, so an allocator that refuses the append
        // loses the graft for ever — the entry keeps saying one is
        // outstanding and none will ever fire. The append can only fail, so
        // doing it first loses nothing.
        try out.push(.{ .schedule_timer = .{
            .after = self.config.graft_timeout_1,
            .timer = .{ .send_graft = ihave.id },
        } });
        entry.graft_timer_scheduled = true;
    }
}

/// Upstream `on_send_graft_timer`: ask the first peer that advertised the
/// message, then ask the next one if that fails too.
pub fn onSendGraftTimer(
    self: *State,
    id: MessageId,
    out: *Actions(OutEvent),
) (Error || Allocator.Error)!void {
    missing.forgetGraftTimer(self, id);
    // The eager push may have beaten the timer, in which case there is
    // nothing to ask for, and asking anyway would graft a peer over a
    // message we already have.
    if (self.received_messages.contains(id)) return;
    const claim = missing.takeOldestClaim(self, id) orelse return;
    try push.addEager(self, claim.peer);
    try out.push(.{ .send_message = .{ .to = claim.peer, .message = .{ .graft = .{
        .id = id,
        .round = claim.round,
    } } } });
    try out.push(.{ .schedule_timer = .{
        .after = self.config.graft_timeout_2,
        .timer = .{ .send_graft = id },
    } });
}

/// Upstream `on_graft`: promote the sender, and if a payload was asked
/// for, send it from the cache. A stored payload must fit the actual writer
/// before promotion: the public cache also accepts receive-capacity entries.
/// An unwritable candidate returns `MessageTooLarge` without changing peer
/// sets or emitting a payload. A swept message is silently unanswered.
pub fn onGraft(
    self: *State,
    sender: NodeId,
    details: Graft,
    out: *Actions(OutEvent),
) (Error || Allocator.Error)!void {
    const message = if (details.id) |id| self.cache.get(id) else null;
    if (message) |candidate| {
        if (codec.encodedLen(.{ .gossip = .{ .gossip = candidate } }) >=
            codec.max_message_size)
        {
            return error.MessageTooLarge;
        }
    }
    try push.addEager(self, sender);
    if (message) |candidate| {
        try out.push(.{ .send_message = .{
            .to = sender,
            .message = .{ .gossip = candidate },
        } });
    }
}

/// Upstream `on_neighbor_down`: a neighbour is gone, so drop it from both
/// sets and from the claim history, and forget any graft we owed it. An
/// entry left with no claims stays, because an absent entry and an empty
/// one read the same on every path that consults them.
pub fn onNeighborDown(self: *State, peer: NodeId) void {
    for (self.missing_messages[0..self.missing_messages_len]) |*entry| {
        var kept: u16 = 0;
        for (entry.peers[0..entry.count], entry.rounds[0..entry.count]) |claimed, round| {
            if (node_id.sameNode(claimed, peer)) continue;
            entry.peers[kept] = claimed;
            entry.rounds[kept] = round;
            kept += 1;
        }
        entry.count = kept;
    }
    _ = self.eager_push_peers.remove(peer);
    _ = self.lazy_push_peers.remove(peer);
}
