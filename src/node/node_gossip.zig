//! The gossip layer's turn, and the peers it names.
//!
//! `gossip` fires the timers membership asked for, `feedGossip` hands the layer
//! one event and does what it asks for, and `peerGone` is the only way this
//! project tells membership that a peer went away. The gap the module doc of
//! `node.zig` names is here and not elsewhere: the layer has no codec, so every
//! message it asks to be sent is counted and named rather than sent.

const std = @import("std");

const node_mod = @import("node.zig");
const node_config = @import("node_config.zig");

const bridge_mod = @import("../transport/quic_bridge.zig");
const hyparview = @import("../gossip/hyparview.zig");
const base_key = @import("../base/key.zig");

const Node = node_mod.Node;
const Error = node_config.Error;
const Instant = bridge_mod.Instant;
const NodeId = base_key.NodeId;

/// How many peers a gossip action's name is kept for.
///
/// The state machine names a peer for every message it asks to be sent and
/// every disconnect it asks for, and the message itself stops at a counter.
/// A reader that wants to know *who* is being talked about reads this rather
/// than the count, and the two disagreeing is a finding.
pub const named_ring = 8;

/// A timer the gossip layers asked for, and the instant it comes due.
pub const Pending = struct {
    due: hyparview.Nanos,
    timer: hyparview.Timer,
};

/// One turn of the gossip layer.
///
/// This is the long-lived loop the milestone is about. The wire test
/// converges in a bounded number of rounds because it is a test
/// (`test/protocol_loopback_test.zig`, `max_rounds = 512`), and a node
/// keeps going: nothing here counts rounds, and the timers membership
/// asked for are the only thing that decides when this runs again.
pub fn gossip(self: *Node, at: Instant) Error!bool {
    var moved = false;
    const now = try gossipNow(at);
    // In the order they were asked for, so a node that has been idle wakes
    // up on the same schedule every time.
    var position: usize = 0;
    while (position < self.timers.items.len) {
        if (self.timers.items[position].due > now) {
            position += 1;
            continue;
        }
        const due = self.timers.orderedRemove(position);
        self.stats.gossip_timers_fired += 1;
        moved = true;
        try feedGossip(self, .{ .timer_expired = due.timer }, now);
    }
    return moved;
}

/// Hand one event to the gossip layer and do what it asks for.
pub fn feedGossip(self: *Node, event: hyparview.InEvent, now: hyparview.Nanos) Error!void {
    var out: hyparview.Actions(hyparview.OutEvent) = .init(self.gpa);
    defer out.deinit();
    try self.topic.handle(event, now, &out);
    self.stats.gossip_events += 1;
    for (out.slice()) |produced| switch (produced) {
        // **Not wired.** The gossip wire format does not exist in this
        // project — `gossip/hyparview.zig` says of itself that it has no
        // codec, and the only encoder here is a test's. So the request is
        // counted, split by the layer that asked, and the peer is named;
        // nothing is sent. See `node.zig`'s module doc.
        .send_message => |send| {
            noteNamed(self, send.to);
            switch (send.message) {
                .swarm => self.stats.gossip_membership_asked += 1,
                .gossip => self.stats.gossip_broadcast_asked += 1,
            }
        },
        .schedule_timer => |schedule| {
            self.stats.gossip_timers_scheduled += 1;
            try self.timers.append(self.gpa, .{
                .due = now + schedule.after,
                .timer = schedule.timer,
            });
        },
        // Also not wired, for the same reason: a `disconnect_peer` names a
        // node, and this node finds a connection by an address the map or
        // the dialer holds, never by an id. Counting it is the honest
        // report; tearing a connection down by node id belongs with the
        // codec, which is what would have carried the message the state
        // machine is asking to be believed about.
        .disconnect_peer => |peer| {
            self.stats.gossip_disconnects_asked += 1;
            noteNamed(self, peer);
        },
        .emit_event => switch (produced.emit_event) {
            .neighbor_up => self.stats.neighbor_up += 1,
            .neighbor_down => self.stats.neighbor_down += 1,
            .received => self.stats.broadcasts_received += 1,
        },
        .peer_data => self.stats.peer_data_seen += 1,
    };
}

/// Tell the gossip layer a peer went away, which is how membership is told
/// anything at all in this project: there is no `Disconnect` message on the
/// wire, because there is no wire.
pub fn peerGone(self: *Node, peer: NodeId, at: Instant) Error!void {
    try feedGossip(self, .{ .peer_disconnected = peer }, try gossipNow(at));
}

/// The loop's instant in the gossip clocks' own unit.
///
/// `Instant` is signed because the QUIC core's is — the transport treats an
/// instant before its own epoch as a legitimate one — and `Nanos` is unsigned
/// because a timer duration cannot be negative. The cast is the whole of the
/// translation, and it is refused rather than wrapped: a clock that went
/// backwards past zero has no answer here, and `Error.InstantOutOfRange` is
/// what a caller would have to handle either way.
pub fn gossipNow(at: Instant) Error!hyparview.Nanos {
    return std.math.cast(hyparview.Nanos, at) orelse error.InstantOutOfRange;
}

/// Keep the peer an action named, for the report and for nothing else.
pub fn noteNamed(self: *Node, peer: NodeId) void {
    if (self.named_len == named_ring) {
        @memmove(self.named[0 .. named_ring - 1], self.named[1..]);
        self.named_len -= 1;
    }
    self.named[self.named_len] = peer;
    self.named_len += 1;
}
