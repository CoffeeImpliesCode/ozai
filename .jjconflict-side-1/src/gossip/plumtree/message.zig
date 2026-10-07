//! The wire vocabulary of one topic: rounds, scopes, the four messages a
//! PlumTree peer sends, and the events in and out of the state machine.
//!
//! `Round` is the hop counter every scope and every `IHave` is written in,
//! `DeliveryScope` is where a received message came from, and `Message`,
//! `Timer`, `InEvent` and `OutEvent` are what crosses the boundary. Nothing
//! here holds state; `State` in `state.zig` is what interprets these.
//!
//! The protocol-wide story — the `MessageId` rule, re-validation, the iTree,
//! purity, bounds and divergences — is in `../plumtree.zig`, which is the module
//! callers import. This file is one piece of it.

const key = @import("../../base/key.zig");
const limits = @import("limits.zig");
const message_id = @import("message_id.zig");

const NodeId = key.NodeId;
const MessageId = message_id.MessageId;
const Nanos = limits.Nanos;
const max_ihaves_per_message = limits.max_ihaves_per_message;
const Error = limits.Error;

/// How many delivery hops a message has taken: one per forwarding node, so
/// `Swarm(0)` is the message at its origin and the round *is* the distance to
/// the origin.
pub const Round = struct {
    /// The round a broadcast starts at: the origin's own hop count is zero.
    pub const zero: Round = .{ .value = 0 };

    /// The hop count this message has travelled, which *is* the distance to
    /// the origin. `u16` and it wraps: a swarm outlives 65 535 hops, so `next`
    /// wraps rather than clamping and `hopsSince` is saturating rather than
    /// subtracting a wrapped counter.
    value: u16,

    /// The next hop's round. Wrapping, deliberately: a clamp would pin a swarm
    /// at 65535 forever and make every later round indistinguishable from it,
    /// while the only comparison a hop count is put to — `hopsSince` — already
    /// refuses to read a wrapped pair as a distance.
    pub fn next(self: Round) Round {
        return .{ .value = self.value +% 1 };
    }

    /// Saturating, because the only caller has already checked the order and a
    /// debug build must not turn a rounding error into a crash.
    pub fn hopsSince(self: Round, earlier: Round) u16 {
        return self.value -| earlier.value;
    }
};

/// Which peers a received message reached, and how it got here.
pub const DeliveryScope = union(enum) {
    /// Received from the swarm, this many hops from the original broadcaster.
    swarm: Round,
    /// Received from a direct neighbour that broadcast to neighbours only.
    neighbors: void,

    /// Whether this message came straight from its publisher.
    pub fn isDirect(self: DeliveryScope) bool {
        return switch (self) {
            .neighbors => true,
            .swarm => |round| round.value == 0,
        };
    }
};

/// What the application asked to broadcast.
pub const Scope = enum {
    swarm,
    neighbors,
};

/// The scope a broadcast goes out under. `Swarm` starts at round 0 and every
/// forwarding hop adds one.
pub fn deliveryScope(scope: Scope) DeliveryScope {
    return switch (scope) {
        .neighbors => .neighbors,
        .swarm => .{ .swarm = Round.zero },
    };
}

/// A payload in flight. Upstream `plumtree::Gossip`.
///
/// `content` borrows: from the caller's buffer when this node broadcast, from
/// this state's payload cache when this is a `Graft` reply. Both are valid
/// until the next `handle` on that state, and a driver that queues an output
/// across a call must copy it.
pub const Gossip = struct {
    id: MessageId,
    content: []const u8,
    scope: DeliveryScope,

    /// The round this message is at, or `null` for a neighbours-only message,
    /// which has no place in the tree. Upstream `Gossip::round`.
    pub fn round(self: Gossip) ?Round {
        return switch (self.scope) {
            .neighbors => null,
            .swarm => |hops| hops,
        };
    }

    /// The same message one hop further on, or `null` when there is nowhere
    /// further to go. Upstream `Gossip::next_round`.
    pub fn nextRound(self: Gossip) ?Gossip {
        return switch (self.scope) {
            .neighbors => null,
            .swarm => |hops| .{
                .id = self.id,
                .content = self.content,
                .scope = .{ .swarm = hops.next() },
            },
        };
    }

    /// Whether the id is the BLAKE3 hash of the content. Upstream
    /// `Gossip::validate`, `plumtree.rs:212-216`.
    pub fn validate(self: Gossip) bool {
        return MessageId.fromContent(self.content).eql(self.id);
    }
};

/// "I have this message, this far from its origin." Sent instead of the
/// payload to a lazy peer.
pub const IHave = struct {
    id: MessageId,
    round: Round,
};

/// A bounded list of `IHave`s: one `Message::IHave` on the wire.
pub const IHaves = struct {
    count: u16,
    items: [max_ihaves_per_message]IHave,

    /// The entries past `count` are never written and never read, so a decoded
    /// or constructed `IHaves` carries no obligation about them.
    /// An owned list of up to `max_ihaves_per_message`, or
    /// `error.IHaveListTooLong`.
    ///
    /// Fixed-size rather than a slice, because a `Message::IHave` is a value
    /// that outlives the frame it was cut from and this module has no
    /// allocator. The count is proved here, at the cast: `u16` holds anything
    /// `max_ihaves_per_message` does, so the cast admits nothing the length
    /// check did not. The entries are copied, so the list borrows nothing from
    /// `items` afterwards.
    pub fn init(items: []const IHave) Error!IHaves {
        if (items.len > max_ihaves_per_message) return error.IHaveListTooLong;
        var list: IHaves = undefined;
        list.count = @intCast(items.len);
        @memcpy(list.items[0..items.len], items);
        return list;
    }

    /// The first `count` entries. Pointer receiver for the reason
    /// `RelayUrl.hostSlice` takes one: a by-value receiver can hand back a
    /// slice into a temporary that dies the moment it returns.
    pub fn slice(self: *const IHaves) []const IHave {
        return self.items[0..self.count];
    }
};

/// "Send me that message, and from now on push it to me whole." Moves the
/// sender into the eager set either way.
pub const Graft = struct {
    /// The message asked for, or `null` when the `Graft` carries only the
    /// promotion half of the tree optimisation.
    id: ?MessageId,
    /// The round of the `IHave` that triggered this `Graft`.
    round: Round,
};

/// What a PlumTree peer sends. Upstream `plumtree::Message`.
pub const Message = union(enum) {
    /// New payload, to be forwarded.
    gossip: Gossip,
    /// You are a lazy peer now.
    prune: void,
    graft: Graft,
    i_have: IHaves,
};

/// Caller-scheduled timer values. After `State.leave`, discard pending timers;
/// late delivery is harmless because the left state ignores every event.
pub const Timer = union(enum) {
    /// Ask for the payload of a `MessageId` from a peer that sent an `IHave`.
    send_graft: MessageId,
    /// Flush the queued `IHave`s.
    dispatch_lazy_push: void,
    /// Sweep the two time-bound caches.
    evict_cache: void,
};

/// What the application is told when a message is delivered. Upstream
/// `plumtree::GossipEvent`, wrapped in the single-variant
/// `plumtree::Event::Received`.
pub const GossipEvent = struct {
    content: []const u8,
    /// The peer this arrived from, which is the node before us on the gossip
    /// path and not the node that broadcast it. Upstream is explicit that
    /// these differ, and code that conflates them attributes a message to the
    /// wrong author.
    delivered_from: NodeId,
    scope: DeliveryScope,
};

/// What the state machine asks the outside world to do. Upstream
/// `plumtree::OutEvent`.
pub const OutEvent = union(enum) {
    send_message: struct { to: NodeId, message: Message },
    schedule_timer: struct { after: Nanos, timer: Timer },
    emit_event: GossipEvent,
};

/// What the state machine is told. Upstream `plumtree::InEvent`.
pub const InEvent = union(enum) {
    recv_message: struct { from: NodeId, message: Message },
    broadcast: struct { content: []const u8, scope: Scope },
    timer_expired: Timer,
    /// A peer joined the topic's active view.
    neighbor_up: NodeId,
    /// A peer left the topic's active view.
    neighbor_down: NodeId,
};
