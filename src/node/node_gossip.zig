//! What a gossip state machine asked for, performed: a frame on a stream, a
//! connection closed, contact data kept.
//!
//! **The state machines request; this file acts.** `gossip_state.State.feed`
//! leaves every request in a list the caller owns and keeps only what belongs
//! to the topic — its timers — because a timer is the topic's own and no other
//! module knows when it was asked for. Turning the rest into bytes needs three
//! answers this file reads off two tables and nothing else: `conn_index` says
//! which connection a node id is on, `topic_table` says which stream a topic
//! writes that peer on, and `gossip/codec.zig` says what the frame is.
//!
//! **One walk per event, in the order the state machine produced.** Upstream's
//! `TopicState.handle` runs three passes and the order of what comes out decides
//! which peers a message reaches in the event that produced it, so nothing here
//! sorts, filters or defers: a request is acted on where it stands.
//!
//! **Every refusal is counted, and none of them is fatal.** A peer with no
//! connection, a frame the codec will not cut, a peer whose window is spent and
//! a route pool at its bound are four different facts about the network, and a
//! caller that could not tell them apart would be reading one counter as if it
//! were a fault. `gossip_sends_written` against `gossip_sends_dropped` is that
//! pair.

const std = @import("std");
const node_mod = @import("node.zig");
const node_error = @import("node_error.zig");
const node_config = @import("node_config.zig");
const gossip_state = @import("gossip_state.zig");
const topic_table = @import("topic_table.zig");
const codec = @import("../gossip/codec.zig");
const hyparview = @import("../gossip/hyparview.zig");
const quic_conn = @import("../transport/quic_conn.zig");
const base_key = @import("../base/key.zig");

const NodeId = base_key.NodeId;
const Instant = quic_conn.Instant;
const Nanos = hyparview.Nanos;

/// The widest frame this node will ever cut, plus the u32-BE prefix that names
/// its length. Fixed, so a send allocates nothing and the codec — not a buffer
/// sized to whatever a peer happened to send — decides what fits.
const frame_room = codec.max_message_size + codec.frame_prefix_length;

/// The 32 bytes a `StreamHeader` is, named here from the topic's own length
/// rather than from the codec: it is the same number, and the node needs it
/// for its own buffer before it has a codec to ask.
const stream_header_length = hyparview.topic_id_length;

/// The application error code and reason a peer is closed with when membership
/// asks for it. The `Disconnect` message is the protocol's way of saying this;
/// the code is the transport-level answer when the message could not be sent,
/// and both ends already know which swarm they were in.
const close_error: u64 = 1;
const close_reason = "gossip";

/// Every topic's timers that are due, fed in the order they came due.
pub fn gossip(self: *node_mod.Node, at: Instant) node_error.Error!bool {
    const now = try gossipNow(at);
    const TopicState = gossip_state.State(node_config.named_ring);
    var moved = false;
    var index: usize = 0;
    while (index < self.topics.count()) : (index += 1) {
        var due: TopicState.Due = .{ .state = &self.topics.at(index).state, .now = now };
        while (due.next()) |timer| {
            self.stats.gossip_timers_fired += 1;
            moved = true;
            try feedTopic(self, self.topics.at(index), .{ .timer_expired = timer }, now);
        }
    }
    return moved;
}

/// Feed one event to the topic this node was built with — the one
/// `node_config.Config.topic_id` names — and perform what it asked for.
///
/// This is the node's own entry point: `node_runtime.start` hands its join
/// here. A timer walk and a lost peer reach *every* topic instead, which is a
/// different question and has its own functions.
pub fn feedGossip(
    self: *node_mod.Node,
    event: hyparview.InEvent,
    now: Nanos,
) node_error.Error!void {
    std.debug.assert(self.topics.count() > 0);
    try feedTopic(self, self.topics.at(0), event, now);
}

/// Tell every topic a peer is gone.
///
/// **All of them, not one.** A connection is one, and the streams it carried
/// belonged to every swarm it was serving; a topic left uninformed would go on
/// naming a peer it can no longer reach and would answer its own timers about a
/// view that no longer has that neighbour.
pub fn peerGone(
    self: *node_mod.Node,
    peer: base_key.NodeId,
    at: Instant,
) node_error.Error!void {
    const now = try gossipNow(at);
    var index: usize = 0;
    while (index < self.topics.count()) : (index += 1) {
        try feedTopic(self, self.topics.at(index), .{ .peer_disconnected = peer }, now);
    }
}

/// QUIC instants are signed; membership durations must not wrap before the epoch.
pub fn gossipNow(at: Instant) node_error.Error!Nanos {
    return std.math.cast(Nanos, at) orelse error.InstantOutOfRange;
}

/// One event into one topic, and everything it asked for.
fn feedTopic(
    self: *node_mod.Node,
    topic: *topic_table.Topic,
    event: hyparview.InEvent,
    now: Nanos,
) node_error.Error!void {
    var tally: gossip_state.Tally = .{};
    // The caller's list, and the only allocator this call needs: the state
    // machine appends to it and the timers it asks for are taken from the same
    // one, so a caller cannot pair a list with the wrong allocator.
    var actions: hyparview.Actions(hyparview.OutEvent) = .init(self.gpa);
    defer actions.deinit();
    try topic.state.feed(event, now, &tally, &actions);

    self.stats.gossip_events += tally.events;
    self.stats.gossip_timers_scheduled += tally.timers_scheduled;
    self.stats.gossip_membership_asked += tally.membership_asked;
    self.stats.gossip_broadcast_asked += tally.broadcast_asked;
    self.stats.gossip_disconnects_asked += tally.disconnects_asked;
    self.stats.neighbor_up += tally.neighbor_up;
    self.stats.neighbor_down += tally.neighbor_down;
    self.stats.broadcasts_received += tally.broadcasts_received;
    self.stats.peer_data_seen += tally.peer_data_seen;
    try perform(self, topic, actions.slice(), now);
}

fn perform(
    self: *node_mod.Node,
    topic: *topic_table.Topic,
    actions: []const hyparview.OutEvent,
    now: Nanos,
) node_error.Error!void {
    for (actions) |produced| switch (produced) {
        .send_message => |send| try deliver(self, topic, send.to, send.message),
        .disconnect_peer => |peer| try disconnect(self, peer, now),
        .peer_data => |data| keepData(topic, data.peer, data.data),
        // The timer was kept and the report counted by `gossip_state`, and
        // neither is this file's to repeat.
        .schedule_timer, .emit_event => {},
    };
}

/// One frame to one peer, on a stream this topic holds for it.
fn deliver(
    self: *node_mod.Node,
    topic: *topic_table.Topic,
    peer: NodeId,
    message: hyparview.Message,
) node_error.Error!void {
    var buffer: [frame_room]u8 = undefined;
    const frame = codec.encodeFrame(&buffer, message) catch |err| {
        // A frame the codec will not cut is neither truncated nor retried: the
        // tree asks again for anything it still wants, and a shortened frame
        // would be a different message that a peer would act on.
        std.log.debug("node: gossip frame to {f} not encoded: {t}", .{
            peer.shortHex(), err,
        });
        self.stats.gossip_sends_dropped += 1;
        return;
    };
    const conn = self.connections.connFor(peer) orelse {
        // Membership names a peer before this node has reached one, and says so
        // with its own timer; the send that has nowhere to go is counted and
        // the next shuffle asks again.
        self.stats.gossip_sends_dropped += 1;
        return;
    };
    // Sized with the naming bytes even on a stream that already carries them:
    // `routeFor` cannot know which of a peer's routes it will hand back, and a
    // test that is 32 bytes strict only sends the frame to the second stream
    // of the pair, which is what the second stream is for.
    var route = topic.routeFor(peer, frame.len + stream_header_length);
    if (route == null) route = try openRoute(topic, peer, conn);
    const found = route orelse {
        self.stats.gossip_sends_dropped += 1;
        return;
    };
    // Asked again here, and for the naming bytes too when this stream has not
    // carried them yet: a stream opened this instant has no credit at all
    // until the peer's MAX_STREAM_DATA arrives, and `error.NoSendCredit` raised
    // out of a pass would be a fact about the network reported as a fault of
    // this node. Dropped and counted instead.
    const needed = frame.len + @as(usize, @intFromBool(!found.header_written)) *
        stream_header_length;
    if (!found.room(needed)) {
        self.stats.gossip_sends_dropped += 1;
        return;
    }
    if (!found.header_written) try nameStream(topic, found);
    if (try found.stream.write(frame) != frame.len) return error.CoreRefused;
    self.stats.gossip_sends_written += 1;
}

/// Name a stream for the topic it carries, once per stream.
///
/// Upstream writes `StreamHeader{topic_id}` as the first bytes on every
/// unidirectional stream and reads a topic off the stream a frame arrived on
/// rather than out of the frame. Half a topic id is worse than none — the peer
/// would read a topic that is neither this one nor the last — so a short write
/// is refused here rather than discovered on the far side.
fn nameStream(topic: *topic_table.Topic, route: *topic_table.Route) node_error.Error!void {
    var header: [hyparview.topic_id_length]u8 = undefined;
    const naming = try codec.encodeStreamHeader(&header, topic.id);
    if (try route.stream.write(naming) != naming.len) return error.CoreRefused;
    route.header_written = true;
}

/// A stream to `peer` for this topic, opened when no one already held has
/// credit, or null when the peer's window or this topic's pool says no.
fn openRoute(
    topic: *topic_table.Topic,
    peer: NodeId,
    conn: quic_conn.Conn,
) node_error.Error!?*topic_table.Route {
    const stream = conn.openUni() catch |err| switch (err) {
        // The peer's transport parameters have not been read, or it has granted
        // no more unidirectional streams. Both are "not now", and both re-open
        // without anyone asking.
        error.NoStreamRoom => {
            std.log.debug("node: gossip stream to {f} refused: {t}", .{
                peer.shortHex(), err,
            });
            return null;
        },
        else => |rest| return rest,
    };
    return topic.routeOpen(peer, stream) catch |err| switch (err) {
        // The pool is spent, which is a peer that is not reading this topic.
        error.RouteSlotsFull => {
            std.log.debug("node: gossip routes to {f} are all spent: {t}", .{
                peer.shortHex(), err,
            });
            return null;
        },
    };
}

/// Close the connection a `disconnect_peer` named, and stop naming it.
///
/// **The entry and the streams go now, not at the reap.** Upstream's
/// simulator reads this action as "kill the link", and enqueues
/// `.peer_disconnected` to the *other* end only (`hyparview.zig:2290-2313`) —
/// the node that asked already removed the peer, which is why it asked. So the
/// connection is forgotten here: `expire` then finds no entry, tells no topic,
/// and the report reaches the peer that actually needs it. Keeping the entry
/// would also let a send that arrives before the core finishes this connection
/// be counted as written to a peer that will never read it.
fn disconnect(
    self: *node_mod.Node,
    peer: NodeId,
    now: Nanos,
) node_error.Error!void {
    const conn = self.connections.forgetPeer(peer) orelse {
        // Nothing to close: this node never reached the peer, or `expire` has
        // already reaped it. The state machine asked, and the answer was
        // already true.
        std.log.debug("node: gossip disconnect to {f} has no connection", .{
            peer.shortHex(),
        });
        return;
    };
    self.stats.gossip_routes_dropped += self.topics.routeForgetPeer(peer);
    // The same narrowing `gossipNow` proves in the other direction, proved here
    // because this is the only place an instant is needed.
    const at = std.math.cast(Instant, now) orelse return error.InstantOutOfRange;
    conn.close(close_error, close_reason, at);
    self.stats.gossip_disconnects_acted += 1;
}

/// Keep the contact data membership reported upwards.
///
/// **A bound this node chose is not a failure of the protocol.** The state
/// machine holds its own copy of the same data and will offer it again in the
/// next shuffle, so a table at its ceiling costs a repeat rather than a peer.
fn keepData(
    topic: *topic_table.Topic,
    peer: NodeId,
    data: []const u8,
) void {
    topic.peerPut(peer, data) catch |err| switch (err) {
        error.PeerDataFull, error.PeerDataTooLong => {
            std.log.debug("node: gossip contact data for {f} not kept: {t}", .{
                peer.shortHex(), err,
            });
            return;
        },
    };
}