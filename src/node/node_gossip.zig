//! Drive configured topics, process borrowed actions synchronously, and assemble real UNI traffic.
const std = @import("std");
const Node = @import("node.zig").Node;
const Error = @import("node_config.zig").Error;
const wire = @import("node_gossip_wire.zig");
const bridge = @import("../transport/quic_bridge.zig");
const hyparview = @import("../gossip/hyparview.zig");
const plumtree = @import("../gossip/plumtree.zig");
const NodeId = @import("../base/key.zig").NodeId;

pub const named_ring = 8;
pub const max_timers = 4096;
pub const Pending = struct {
    topic_index: usize,
    due: hyparview.Nanos,
    timer: hyparview.Timer,
};

pub fn start(self: *Node, bootstrap: []const NodeId, now: hyparview.Nanos) Error!void {
    wire.learn(self);
    const peers = try hyparview.Peers.init(bootstrap);
    for (self.gossip_topics, 0..) |_, index| {
        try feedGossip(self, index, .{ .command = .{ .join = peers } }, now);
    }
}

pub fn broadcast(
    self: *Node,
    topic: hyparview.TopicId,
    content: []const u8,
    scope: plumtree.Scope,
    at: bridge.Instant,
) Error!void {
    wire.learn(self);
    const now = try gossipNow(at);
    for (self.config.gossip_topics, 0..) |configured, index| {
        if (!configured.eql(topic)) continue;
        try feedGossip(self, index, .{ .command = .{ .broadcast = .{ .content = content, .scope = scope } } }, now);
        return;
    }
    return error.UnknownGossipTopic;
}

pub fn quit(self: *Node, at: bridge.Instant) Error!void {
    const now = try gossipNow(at);
    for (self.gossip_topics, 0..) |_, index| {
        try feedGossip(self, index, .{ .command = .quit }, now);
    }
    self.timers.clearRetainingCapacity();
}

pub fn receive(self: *Node, at: bridge.Instant) Error!bool {
    const now = try gossipNow(at);
    wire.learn(self);
    var moved = try reapStale(self, now);
    moved = wire.flush(self) or moved;
    return (try wire.receive(self, now)) or moved;
}

pub fn gossip(self: *Node, at: bridge.Instant) Error!bool {
    const now = try gossipNow(at);
    wire.learn(self);
    var moved = try reapStale(self, now);
    moved = wire.flush(self) or moved;
    var position: usize = 0;
    // Only timers present at entry are eligible; a timer may reschedule itself.
    var remaining = self.timers.items.len;
    while (position < self.timers.items.len and remaining > 0) : (remaining -= 1) {
        if (self.timers.items[position].due > now) {
            position += 1;
            continue;
        }
        const due = self.timers.orderedRemove(position);
        self.stats.gossip_timers_fired += 1;
        moved = true;
        try feedGossip(self, due.topic_index, .{ .timer_expired = due.timer }, now);
    }
    return moved;
}

fn reapStale(self: *Node, now: hyparview.Nanos) Error!bool {
    const stale = wire.takeStalePeers(self);
    for (stale.peers[0..stale.len]) |peer| {
        for (self.gossip_topics, 0..) |_, index| {
            try feedGossip(self, index, .{ .peer_disconnected = peer }, now);
        }
    }
    return stale.len != 0;
}

pub fn feedGossip(self: *Node, topic_index: usize, event: hyparview.InEvent, now: hyparview.Nanos) Error!void {
    std.debug.assert(topic_index < self.gossip_topics.len);
    var out: hyparview.Actions(hyparview.OutEvent) = .init(self.gpa);
    defer out.deinit();
    try self.gossip_topics[topic_index].handle(event, now, &out);
    self.stats.gossip_events += 1;
    var broadcast_initial = false;
    for (out.slice()) |produced| switch (produced) {
        .send_message => |send| {
            noteNamed(self, send.to);
            switch (send.message) {
                .swarm => self.stats.gossip_membership_asked += 1,
                .gossip => self.stats.gossip_broadcast_asked += 1,
            }
            const outcome = wire.send(self, topic_index, send.to, send.message);
            if (outcome != .sent and outcome != .queued)
                std.log.debug("gossip send refused: {t}", .{outcome});
        },
        .schedule_timer => |schedule| {
            if (self.timers.items.len == max_timers) return error.CoreRefused;
            self.stats.gossip_timers_scheduled += 1;
            try self.timers.append(self.gpa, .{
                .topic_index = topic_index,
                .due = now +| schedule.after,
                .timer = schedule.timer,
            });
        },
        .disconnect_peer => |peer| {
            // A topic disconnect does not close another topic or protocol on this connection.
            self.stats.gossip_disconnects_asked += 1;
            noteNamed(self, peer);
        },
        .emit_event => |app| switch (app) {
            .neighbor_up => {
                self.stats.neighbor_up += 1;
                broadcast_initial = self.config.gossip_message != null and !self.gossip.initial_sent[topic_index];
            },
            .neighbor_down => self.stats.neighbor_down += 1,
            .received => |received| {
                self.stats.broadcasts_received += 1;
                if (self.config.on_gossip) |callback| callback(
                    self.config.on_gossip_context,
                    self.config.gossip_topics[topic_index],
                    received.delivered_from,
                    received.content,
                );
            },
        },
        .peer_data => self.stats.peer_data_seen += 1,
    };
    // `received.content` may borrow from this frame/cache; every action is consumed before return.
    if (broadcast_initial) {
        self.gossip.initial_sent[topic_index] = true;
        try feedGossip(self, topic_index, .{ .command = .{ .broadcast = .{
            .content = self.config.gossip_message.?,
            .scope = .neighbors,
        } } }, now);
    }
}

pub fn peerGone(self: *Node, peer: NodeId, at: bridge.Instant) Error!void {
    wire.forget(self, peer);
    const now = try gossipNow(at);
    for (self.gossip_topics, 0..) |_, index| {
        try feedGossip(self, index, .{ .peer_disconnected = peer }, now);
    }
}

pub fn gossipNow(at: bridge.Instant) Error!hyparview.Nanos {
    return std.math.cast(hyparview.Nanos, at) orelse error.InstantOutOfRange;
}

pub fn noteNamed(self: *Node, peer: NodeId) void {
    if (self.named_len == named_ring) {
        @memmove(self.named[0 .. named_ring - 1], self.named[1..]);
        self.named_len -= 1;
    }
    self.named[self.named_len] = peer;
    self.named_len += 1;
}
