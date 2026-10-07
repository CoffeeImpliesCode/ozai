//! Membership and broadcast, composed: one node's state for one topic.
//!
//! Upstream `proto/topic.rs`. A `TopicState` owns a `State` and a
//! `plumtree.State`, dispatches an event to one or the other, and then runs the
//! two passes that lift each layer's output into the topic's own. The order of
//! those passes is the contract and `TopicState.handle` says so in full.
//!
//! `TopicId` is not here: it names the swarm, and the swarm is the subject of
//! `../hyparview.zig` rather than of either layer.
//! The protocol-wide story — the `Neighbor` deviation, the `TopicId` privacy
//! note and the purity rules — is in `../hyparview.zig`, which is the module
//! callers import. This file is one piece of it.

const std = @import("std");
const key = @import("../../base/key.zig");
const plumtree = @import("../plumtree.zig");
const bounds = @import("bounds.zig");
const contact = @import("peer_data.zig");
const wire = @import("message.zig");
const entropy = @import("rng.zig");
const settings = @import("config.zig");
const swarm = @import("state.zig");

const Allocator = std.mem.Allocator;
const NodeId = key.NodeId;
const Nanos = plumtree.Nanos;
const Actions = plumtree.Actions;
const Error = bounds.Error;
const PeerData = contact.PeerData;
const SwarmMessage = wire.SwarmMessage;
const SwarmTimer = wire.SwarmTimer;
const SwarmOutEvent = wire.SwarmOutEvent;
const Rng = entropy.Rng;
const Peers = settings.Peers;
const Config = settings.Config;
const State = swarm.State;

/// A protocol message, whichever layer it belongs to. Upstream
/// `proto::topic::Message`.
pub const Message = union(enum) {
    swarm: SwarmMessage,
    gossip: plumtree.Message,
};

/// What the application asks for. Upstream `proto::topic::Command`.
pub const Command = union(enum) {
    /// Join this topic by asking these peers for an introduction. An empty
    /// list means "be ready to be asked", which is how a bootstrap node starts.
    join: Peers,
    broadcast: struct { content: []const u8, scope: plumtree.Scope },
    /// Leave the topic and drop its state.
    quit: void,
};

/// A timer either layer asked for. Upstream `proto::topic::Timer`.
pub const Timer = union(enum) {
    swarm: SwarmTimer,
    gossip: plumtree.Timer,
};

/// What a node is told. Upstream `proto::topic::InEvent`.
pub const InEvent = union(enum) {
    recv_message: struct { from: NodeId, message: Message },
    command: Command,
    timer_expired: Timer,
    peer_disconnected: NodeId,
    update_peer_data: PeerData,
};

/// What a node reports upwards. Upstream `proto::topic::Event`.
pub const AppEvent = union(enum) {
    neighbor_up: NodeId,
    neighbor_down: NodeId,
    received: plumtree.GossipEvent,
};

/// What a node asks the outside world to do. Upstream `proto::topic::OutEvent`.
pub const OutEvent = union(enum) {
    send_message: struct { to: NodeId, message: Message },
    schedule_timer: struct { after: Nanos, timer: Timer },
    disconnect_peer: NodeId,
    emit_event: AppEvent,
    peer_data: struct { peer: NodeId, data: []const u8 },
};

/// Both layers' configuration. Upstream `proto::topic::Config`, minus
/// `max_message_size`, which sizes a wire frame and belongs with the codec.
pub const TopicConfig = struct {
    membership: Config = .{},
    broadcast: plumtree.Config = .{},

    pub fn validate(self: TopicConfig) Error!void {
        try self.membership.validate();
    }
};

/// Per-topic counters. Upstream `proto::topic::Stats`.
pub const Stats = struct {
    messages_sent: u64 = 0,
    messages_received: u64 = 0,
};

/// One node's state for one topic: membership plus broadcast tree. Upstream
/// `proto::topic::State`.
pub const TopicState = struct {
    /// This node's identity, fixed by `init`. `handle` never reads it: both
    /// layers were built with their own copy, in `swarm.me` and `gossip.me`,
    /// so writing this field after `init` changes nothing about what the node
    /// does. Zig fields are not private — those two are the live identities.
    me: NodeId,
    /// The membership layer. `handle` drives it and `hasActivePeers` reads it
    /// back, and those are the supported ways in. Writing it is neither refused
    /// nor repaired: this layer's `left` and the topic's `left` are separate
    /// flags, so replacing it under a live `gossip` can leave the two out of
    /// step.
    swarm: State,
    /// The broadcast layer, and the door a caller reaches the tree through
    /// directly: `topic.gossip.broadcast(...)` needs no `handle`, which is why
    /// `Command.quit` calls `plumtree.State.leave` and that call sets this
    /// layer's own `left`. After a quit the layer is inert — `broadcast` and
    /// `handle` both return without touching a cache, a queue or a latch — so
    /// a caller that reaches in after leaving gets silence rather than a fresh
    /// tree. Writing it is neither refused nor repaired, and a layer written
    /// with `left == false` will answer for a topic that has left.
    gossip: plumtree.State,
    /// Per-topic counters, zeroed by `init` and moved only by `handle`: one
    /// `messages_received` per received frame of either layer, and one
    /// `messages_sent` per `send_message` this call appends to `out`. They
    /// count what crossed the topic's boundary, not what each layer did —
    /// `swarm.stats` and `gossip.stats` are the per-layer counts — and they
    /// survive `Command.quit`, as do the layers' own.
    stats: Stats,

    /// Whether this node has left the topic. Set by `Command.quit` and checked
    /// before every dispatch, so a topic that has been left is inert: it
    /// succeeds, appends nothing and changes nothing.
    ///
    /// This is the topic's flag and not the membership layer's `State.left`,
    /// and both are needed because they answer for different machines. A
    /// membership-only driver that quits gets a membership state that is inert;
    /// this one has to be inert too, because `Command.broadcast` and a
    /// `.gossip` message reach the broadcast layer directly. `plumtree.State`
    /// carries its own `left`, and `leave` sets it: a broadcast layer that was
    /// emptied without a latch would answer the next broadcast with a fresh
    /// cache entry.
    ///
    /// Terminal: a node rejoins by building a new `TopicState`, as upstream
    /// rejoins by building a new topic actor. `init` never returns one with
    /// this set.
    left: bool = false,

    pub fn init(
        me: NodeId,
        me_data: ?PeerData,
        config: TopicConfig,
        rng: Rng,
    ) Error!TopicState {
        try config.validate();
        return .{
            .me = me,
            .swarm = try State.init(me, me_data, config.membership, rng),
            .gossip = plumtree.State.init(me, config.broadcast),
            .stats = .{},
        };
    }

    pub fn hasActivePeers(self: *const TopicState) bool {
        return self.swarm.active_view.count() > 0;
    }

    /// Handle one event. `now` is the caller's clock; neither layer reads one.
    ///
    /// **A topic that has been left is inert.** `Command.quit` drops the
    /// broadcast layer, tells the membership layer to disconnect and forget, and
    /// sets `left`; every later event is accepted and produces nothing. That is
    /// upstream's behaviour — the topic actor is dropped and every later event
    /// for it ignored — expressed as a fact about this value rather than as
    /// bookkeeping in the driver.
    ///
    /// **Not transactional, and the residue is named rather than hidden.** The
    /// event advances both layers as it goes and the passes at the end copy
    /// their output into `out` as they go, so an error out of either leaves the
    /// topic advanced as far as that event got. Nothing is left half-written —
    /// every mutation in both layers is checked — but the state is not the state
    /// the caller handed in, and a `plumtree.Error` the broadcast layer refused
    /// with arrives here unchanged.
    ///
    /// The recovery is the caller's and is the one `plumtree.State.handle` states
    /// in full: snapshot the value before the call and restore it on error, which
    /// works because `TopicState` is a plain value holding no slice of its own
    /// storage — both layers are inline in it, caches and all — so the copy is
    /// `@sizeOf(TopicState)` and no allocation, and it restores the borrowed
    /// payload bytes a failed call handed to `out` along with the value. Three
    /// bounds apply. It restores `self` and nothing else, so a caller that acts
    /// on `out` as it drains it has already sent what it read; it restores `out`
    /// only when `out` was empty when the call started, because `Actions` cannot
    /// truncate to a saved length; and it restores neither layer's timers, since
    /// a topic timer event is delivered because the caller removed that timer to
    /// fire it. A caller that accumulates output across events, or that cannot
    /// keep a copy, must abandon instead: treat the failed `handle` as the end of
    /// this topic's run. Replaying the event is not promised to be idempotent.
    ///
    /// One detail of *where* the failure lands, because it changes what a
    /// caller sees: the two layers fill scratch containers this function owns,
    /// and only the two passes at the end copy them into the caller's `out`. A
    /// failure inside a layer therefore leaves `out` untouched and the layers
    /// advanced; a failure in a pass leaves `out` holding the entries copied
    /// before it. `out` is never rolled back here in either case.
    ///
    /// **What the entries in `out` borrow.** `Actions` owns the list and not the
    /// bytes its entries name, and it keeps neither layer's claim on them. A
    /// `swarm` entry names one of the three places `State.handle` names: the
    /// decoded frame the caller brought, a `peer_data` slot or a `me_data`
    /// slot, the last two stored inline in this value. A `gossip` message and
    /// an `emit_event.received` borrow either the caller's broadcast buffer or
    /// the broadcast layer's cache, which is inline in `gossip`. What advances
    /// each is what those two `handle` docs name: the next `handle` on this
    /// state, `Command.quit`, and — for a `me_data` slice alone — a
    /// `.update_peer_data` event. A caller that keeps an output list across any
    /// of them must copy. See `plumtree.Actions` for the container's own
    /// rules.
    ///
    /// **The order of the two passes below is the contract, and it is not
    /// tidy.** Upstream `proto/topic.rs` dispatches the event to one layer,
    /// which fills an outbox, and only *then* walks that outbox to hand every
    /// `NeighborUp` and `NeighborDown` to the broadcast layer. Membership
    /// changes are therefore applied to the iTree after the whole event has
    /// been processed, in outbox order, and not at the instant they occurred.
    ///
    /// The observable consequence: a `NeighborUp` produced by the event being
    /// processed does not affect any send the *same* event makes. A node that
    /// receives a `Neighbor` from a new peer and, in the same handling, learns
    /// a message from somebody else fans that message out to the tree as it
    /// was before the new peer joined. Reversing the two passes — forwarding
    /// membership changes as they are emitted, or running the second pass
    /// before the first — changes which peers a message reaches in that event,
    /// and under load it changes how many. The same goes for the order of the
    /// arms inside each layer, which is documented where the arms are. A
    /// reader who finds any of this untidy should not sort it.
    pub fn handle(
        self: *TopicState,
        event: InEvent,
        now: Nanos,
        out: *Actions(OutEvent),
    ) (Error || plumtree.Error || Allocator.Error)!void {
        // Before the scratch containers, so an inert call allocates nothing at
        // all: three `Actions` over one allocator is three chances to fail on a
        // topic that has nothing left to say.
        if (self.left) return;
        var membership: Actions(SwarmOutEvent) = .init(out.gpa);
        defer membership.deinit();
        var payload: plumtree.Actions(plumtree.OutEvent) = .init(out.gpa);
        defer payload.deinit();
        var topology: plumtree.Actions(plumtree.OutEvent) = .init(out.gpa);
        defer topology.deinit();

        switch (event) {
            .command => |command| switch (command) {
                .join => |peers| for (peers.slice()) |peer| {
                    try self.swarm.handle(.{ .request_join = peer }, &membership);
                },
                .broadcast => |b| try self.gossip.handle(.{
                    .broadcast = .{ .content = b.content, .scope = b.scope },
                }, now, &payload),
                .quit => {
                    // Membership first: it is the layer that owes output a
                    // caller can observe, and that output is lifted into `out`
                    // by the passes below like everything else this call makes.
                    try self.swarm.handle(.quit, &membership);
                    self.gossip.leave();
                    self.left = true;
                },
            },
            .recv_message => |recv| {
                self.stats.messages_received += 1;
                switch (recv.message) {
                    .swarm => |message| try self.swarm.handle(.{
                        .recv_message = .{ .from = recv.from, .message = message },
                    }, &membership),
                    .gossip => |message| try self.gossip.handle(.{
                        .recv_message = .{ .from = recv.from, .message = message },
                    }, now, &payload),
                }
            },
            .timer_expired => |timer| switch (timer) {
                .swarm => |inner| try self.swarm.handle(
                    .{ .timer_expired = inner },
                    &membership,
                ),
                .gossip => |inner| try self.gossip.handle(
                    .{ .timer_expired = inner },
                    now,
                    &payload,
                ),
            },
            .peer_disconnected => |peer| {
                try self.swarm.handle(.{ .peer_disconnected = peer }, &membership);
                try self.gossip.handle(.{ .neighbor_down = peer }, now, &payload);
            },
            .update_peer_data => |data| try self.swarm.handle(.{
                .update_peer_data = data,
            }, &membership),
        }

        for (membership.slice()) |reported| switch (reported) {
            .emit_event => |change| switch (change) {
                .neighbor_up => |peer| try self.gossip.handle(
                    .{ .neighbor_up = peer },
                    now,
                    &topology,
                ),
                .neighbor_down => |peer| try self.gossip.handle(
                    .{ .neighbor_down = peer },
                    now,
                    &topology,
                ),
            },
            else => {},
        };

        for (membership.slice()) |produced| {
            self.stats.messages_sent += @intFromBool(produced == .send_message);
            try appendMembership(out, produced);
        }
        for ([_][]const plumtree.OutEvent{ payload.slice(), topology.slice() }) |list| {
            for (list) |produced| {
                self.stats.messages_sent += @intFromBool(produced == .send_message);
                try appendPayload(out, produced);
            }
        }
    }
};

/// Lift a membership-layer event into a topic-level one.
fn appendMembership(out: *Actions(OutEvent), event: SwarmOutEvent) Allocator.Error!void {
    try out.push(switch (event) {
        .send_message => |send| .{ .send_message = .{
            .to = send.to,
            .message = .{ .swarm = send.message },
        } },
        .schedule_timer => |schedule| .{ .schedule_timer = .{
            .after = schedule.after,
            .timer = .{ .swarm = schedule.timer },
        } },
        .disconnect_peer => |peer| .{ .disconnect_peer = peer },
        .emit_event => |change| .{ .emit_event = switch (change) {
            .neighbor_up => |peer| .{ .neighbor_up = peer },
            .neighbor_down => |peer| .{ .neighbor_down = peer },
        } },
        .peer_data => |data| .{ .peer_data = .{ .peer = data.peer, .data = data.data } },
    });
}

/// Lift a broadcast-layer event into a topic-level one.
fn appendPayload(out: *Actions(OutEvent), event: plumtree.OutEvent) Allocator.Error!void {
    try out.push(switch (event) {
        .send_message => |send| .{ .send_message = .{
            .to = send.to,
            .message = .{ .gossip = send.message },
        } },
        .schedule_timer => |schedule| .{ .schedule_timer = .{
            .after = schedule.after,
            .timer = .{ .gossip = schedule.timer },
        } },
        .emit_event => |received| .{ .emit_event = .{ .received = received } },
    });
}
