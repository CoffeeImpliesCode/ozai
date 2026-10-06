//! The gossip layer's turn, and the peers it names.
//!
//! `gossip` fires the timers membership asked for, `feedGossip` hands the layer
//! one event and does what it asks for, and `peerGone` is the only way this
//! project tells membership that a peer went away.
//!
//! **What a `send_message` gets is a frame on a stream, not a name.** The
//! codec the module doc of `node.zig` names as unwired is wired here:
//! `feedGossip` encodes the message the layer produced with
//! `gossip_codec.encode` and hands the frame to the connection table
//! (`node_gossip_wire.zig`), which is the only place in this tree that
//! encodes a gossip message. The peer is still named, because a send that
//! could not happen is a send a reader still has to be able to find — and a
//! refusal is counted under its own name rather than raised, since one peer
//! this node cannot write to is a fact about that peer.

const std = @import("std");

const node_mod = @import("node.zig");
const node_config = @import("node_config.zig");
const node_gossip_wire = @import("node_gossip_wire.zig");

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
    // The directory is refreshed here rather than in `gossip` alone, because
    // `feedGossip` is every entry point into the layer: a timer from the pass,
    // the join `start` feeds, and the `peerGone` `expire` feeds. A connection
    // that handshook between two passes is routable on the very next event.
    node_gossip_wire.learn(self);
    self.stats.gossip_events += 1;
    for (out.slice()) |produced| switch (produced) {
        .send_message => |send| {
            // The name comes first and comes whatever the send does, so a
            // refused peer is a named peer and `Node.namedPeers` still answers
            // "who is being talked about" for every action of the last pass.
            noteNamed(self, send.to);
            switch (send.message) {
                .swarm => self.stats.gossip_membership_asked += 1,
                .gossip => self.stats.gossip_broadcast_asked += 1,
            }
            // The counter above counts what the layer asked for, which is what
            // it has always counted; what became of the ask is the wire's own
            // answer, and the two halves are read together. See
            // `node_gossip_wire.Wire`'s note on `refused`.
            _ = node_gossip_wire.send(self, send.to, send.message);
        },
        .schedule_timer => |schedule| {
            self.stats.gossip_timers_scheduled += 1;
            try self.timers.append(self.gpa, .{
                .due = now + schedule.after,
                .timer = schedule.timer,
            });
        },
        // **Not wired, and for the second reason rather than the first.** The
        // lookup this needed is here now — `node_gossip_wire` answers "which
        // connection is this peer on", which is what the connection table was
        // for — but closing that connection is a core operation, and
        // `bridge_conn.Conn` names no door to it: `Conn` reads state, drains
        // egress and hands over a stream, and that is all. So the action is
        // counted and the peer is named, which is what this arm did before the
        // codec was wired and is still the whole of what it can say.
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
/// anything at all in this project.
///
/// **The peer leaves the connection table here, before the layer is told**, so
/// a `send_message` naming it in this same event is refused by name instead
/// of being written to a connection the core has finished with. Only
/// `node_transport.expire` calls this, and it calls it after the core has
/// taken the connection out of its own table, so the directory does not fill
/// it straight back in. No `Disconnect` message reaches a peer from here
/// either: the codec that writes that byte is wired (`node_gossip_wire.send`
/// sends it like any other message), but this event is local in both
/// directions, because the peer it names has nowhere to carry one.
pub fn peerGone(self: *Node, peer: NodeId, at: Instant) Error!void {
    node_gossip_wire.forget(self, peer);
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
