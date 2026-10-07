//! The membership layer's wire vocabulary: hops, priorities, the six messages,
//! the two timers, and the events in and out of the state machine.
//!
//! `SwarmMessage` is what a `Neighbor`, a `ForwardJoin`, a `Shuffle`, a
//! `ShuffleReply`, a `Disconnect` and a `Join` are when one of them travels.
//! Nothing here holds state; `State` in `state.zig` is what interprets these,
//! and `swarm.State` is where the deviation lives.
//! The protocol-wide story — the `Neighbor` deviation, the `TopicId` privacy
//! note and the purity rules — is in `../hyparview.zig`, which is the module
//! callers import. This file is one piece of it.

const key = @import("../../base/key.zig");
const plumtree = @import("../plumtree.zig");
const peers = @import("peer_data.zig");

const NodeId = key.NodeId;
const Nanos = plumtree.Nanos;
const PeerData = peers.PeerData;
const PeerInfo = peers.PeerInfo;
const PeerInfos = peers.PeerInfos;

/// Hops left before a message must stop. Upstream `hyparview::Ttl`.
pub const Ttl = struct {
    value: u16,

    pub fn expired(self: Ttl) bool {
        return self.value == 0;
    }

    /// Saturating, because a message that arrives with a zero TTL is forwarded
    /// once with a zero TTL rather than wrapping to 65535 and touring the
    /// whole swarm.
    pub fn next(self: Ttl) Ttl {
        return .{ .value = self.value -| 1 };
    }

    pub fn eql(a: Ttl, b: Ttl) bool {
        return a.value == b.value;
    }
};

/// Whether a `Join` or `ForwardJoin` may be refused. Upstream `Priority`.
pub const Priority = enum {
    /// May not be denied, even at the cost of dropping an active peer. Only a
    /// peer with no active peers may send one.
    high,
    /// Denied if the active view is full.
    low,
};

/// "I want you in my active view." Upstream `hyparview::Neighbor`.
///
/// The doc comment upstream carries says it is sent *after* adding the peer,
/// and that is the deviation: it is sent instead.
pub const Neighbor = struct {
    /// The priority of the `Join` or `ForwardJoin` that triggered this.
    priority: Priority,
    /// The sender's own contact data.
    data: ?[]const u8,
};

/// "I am closing the connection." Upstream `hyparview::Disconnect`.
///
/// Upstream's obsolete `_respond` bool is emitted as false and consumed by
/// the codec. State carries only `alive`, because the obsolete field has no
/// effect on membership.
pub const Disconnect = struct {
    /// Whether the sender is still in the swarm, in which case the receiver
    /// keeps it in its passive view rather than forgetting it.
    alive: bool,
};

/// "A peer joined; introduce it." Upstream `hyparview::ForwardJoin`.
pub const ForwardJoin = struct {
    peer: PeerInfo,
    ttl: Ttl,
};

/// "Exchange a slice of my view for a slice of yours." Upstream
/// `hyparview::Shuffle`.
pub const Shuffle = struct {
    /// The peer that started the walk, which is who the reply goes to.
    origin: NodeId,
    nodes: PeerInfos,
    ttl: Ttl,
};

/// The answer to a `Shuffle`. Upstream `hyparview::ShuffleReply`.
pub const ShuffleReply = struct {
    nodes: PeerInfos,
};

/// The membership layer's wire messages. Upstream `hyparview::Message`.
pub const SwarmMessage = union(enum) {
    /// "Let me in", sent to a peer that is already in the swarm.
    join: ?[]const u8,
    forward_join: ForwardJoin,
    shuffle: Shuffle,
    shuffle_reply: ShuffleReply,
    neighbor: Neighbor,
    disconnect: Disconnect,
};

/// The timers membership schedules. Upstream `hyparview::Timer`.
pub const SwarmTimer = union(enum) {
    do_shuffle: void,
    /// A `Neighbor` we sent that has not been answered. Fired, the peer is
    /// dropped from the passive view and another is tried; this timer exists
    /// only because of the deviation described in the module doc.
    pending_neighbor_request: NodeId,
};

/// What membership tells the application. Upstream `hyparview::Event`.
pub const Event = union(enum) {
    neighbor_up: NodeId,
    neighbor_down: NodeId,
};

/// What the state machine is told. Upstream `hyparview::InEvent`.
pub const SwarmInEvent = union(enum) {
    recv_message: struct { from: NodeId, message: SwarmMessage },
    timer_expired: SwarmTimer,
    peer_disconnected: NodeId,
    request_join: NodeId,
    update_peer_data: PeerData,
    quit: void,
};

/// What the state machine asks for. Upstream `hyparview::OutEvent`.
pub const SwarmOutEvent = union(enum) {
    send_message: struct { to: NodeId, message: SwarmMessage },
    schedule_timer: struct { after: Nanos, timer: SwarmTimer },
    disconnect_peer: NodeId,
    emit_event: Event,
    /// Contact data for a peer, handed upwards so the application can dial it.
    peer_data: struct { peer: NodeId, data: []const u8 },
};
