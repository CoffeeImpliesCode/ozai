//! PlumTree: the epidemic broadcast tree that runs on top of HyParView's
//! active view.
//!
//! Ported from `n0-computer/iroh-gossip`, `src/proto/plumtree.rs`, at commit
//! `2885dd9f1120e46aca5acbcd7f212e4c64e278b9`, fetched 2026-09-30. Every
//! behaviour below names the function it came from, because the value of this
//! module is that a second implementation lands on the same bytes and the
//! same orderings as the reference.
//!
//! # `MessageId` is `blake3(content)`, and that is the whole rule
//!
//! `MessageId::from_content` (`plumtree.rs:33-38`) is `blake3::hash(message)`
//! over the payload bytes. No context string, no topic mixed in, no round, no
//! sender. An implementation that "helpfully" derives the id under a domain
//! separator produces different ids, no peer recognises the other's messages,
//! every broadcast degenerates into a flood of `IHave` and `Graft`, and nothing
//! reports an error — the messages simply never arrive.
//! `domainSeparatedId` exists for one reason: the test that a domain-separated
//! id is rejected uses it, so the wrong id is a real digest and not a strawman.
//!
//! # Re-validation, and what it does not do
//!
//! Every received `Gossip` is re-hashed and compared to the id it carries
//! (`on_gossip`, `plumtree.rs:491-499`). A mismatch is dropped: the function
//! returns before anything is recorded, forwarded, cached, scheduled or
//! emitted, and nothing is sent back to the peer. In particular the sender is
//! **not** moved to the lazy set, **not** sent a `Prune`, and **not** recorded
//! as a misbehaving neighbour. The upstream comment above that arm asks
//! whether any measure should be taken against the sender and leaves it
//! unanswered; the answer the code gives is no, and the answer is the
//! invariant. A re-validation path that also punishes is a different protocol,
//! and a peer that wanted to empty a victim's iTree would send one bad frame
//! per neighbour.
//!
//! One thing *is* counted: `payload_messages_received` is incremented in
//! `handle_message` before the arm is chosen, so a spoofed frame is counted as
//! received and then discarded. That is upstream's behaviour and it is
//! deliberate here too — it is a receive counter, not a delivery counter — and
//! the test that a spoofed message is not penalised asserts on everything
//! *except* that counter.
//!
//! # The iTree
//!
//! A node's neighbours are split in two. `eager` peers get the whole payload;
//! `lazy` peers get only the `MessageId`, in an `IHave`, after a timer. A
//! `Graft` moves a peer from lazy to eager and asks it for the payload it
//! advertised. The eager edges *are* the broadcast tree, and the forwarding
//! rule is one line: on a new `Gossip`, push the full message to every eager
//! peer except the one it came from, and queue the id for the lazy ones. The
//! tree then optimises itself, and `optimize_tree` (`plumtree.rs:552-583`) is
//! the only thing that makes a broadcast cheaper than a flood: it prunes the
//! sender of a `Gossip` and grafts the peer whose `IHave` claimed a much
//! shorter path, once the gap is at least `optimization_threshold` rounds.
//!
//! # Purity
//!
//! No clock, no environment, no global, no allocator, no I/O. Time enters as
//! the `now` argument of `handle`; the caller owns it, which is what lets the
//! simulator drive the same state machine from its own integer clock. The
//! allocator is held by the `Actions` container the caller hands in, so no
//! protocol function takes one: the protocol only appends to a list it was
//! given.
//!
//! # Bounds
//!
//! Upstream's collections are unbounded and time-expiring. Allocation-free
//! means fixed-capacity here, so every bound below is a real one and each
//! raises an explicit error rather than dropping a message on the floor: a set
//! that is full is `error.PeerSetFull`, a payload over `max_content` is
//! `error.MessageTooLarge` whether it was broadcast here or received there, a
//! missing-id table with more than `max_missing` distinct ids or more than
//! `max_claims` claims for one id is
//! `error.MissingTableFull`, a lazy-push queue with more than
//! `max_queued_ihaves` entries for one peer is `error.LazyQueueFull`, and an
//! `IHave` list longer than `max_ihaves_per_message` is
//! `error.IHaveListTooLong`. The two caches do not error: they evict whichever
//! entry expires soonest, which is the same choice as running a sweep early,
//! and a cache that cannot hold a message can still answer a late `Graft`
//! rather than never.
//!
//! # Divergences, and why each is forced
//!
//! - **Bounded collections instead of unbounded ones.** See above. That is
//!   what "no allocator" costs, and the alternative is a protocol function
//!   that takes a heap.
//! - **`IHave` batches are cut by count, not by bytes.** Upstream cuts them so
//!   that the encoded size fits `max_message_size` (`on_dispatch_timer`). The
//!   frame size depends on how a `NodeId` and a `TopicId` are written on the
//!   wire, and that codec is not in this ticket; guessing its size here would
//!   put one number in two places that could disagree.
//! - **Batches and payloads borrow their content.** A `Gossip` handed to
//!   `OutEvent.send_message` borrows either the caller's buffer (a local
//!   broadcast) or this state's own cache (a `Graft` reply). Both are valid
//!   until the next `handle` on the same state, and a driver that keeps an
//!   output list across a call must copy. That is the one lifetime rule in
//!   this module, and it is stated on `Gossip` as well as here.

const std = @import("std");
const key = @import("../base/key.zig");

const NodeId = key.NodeId;
const Allocator = std.mem.Allocator;

/// Simulated time is an integer count of nanoseconds handed in by the caller.
/// The protocol never reads a clock; it is told what time it is.
pub const Nanos = u64;

pub const nanos_per_milli: Nanos = 1_000_000;
pub const nanos_per_second: Nanos = 1_000_000_000;

/// A `MessageId` is BLAKE3's output width and nothing else.
pub const id_length = 32;

/// The largest payload one cached message may hold, in bytes.
pub const max_content = 1024;

/// How many messages the payload cache holds at once.
pub const cache_slots = 16;

/// How many message ids the "have I seen this" table holds at once.
pub const max_received_ids = 128;

/// How many peers one of the iTree sets holds. Both sets are subsets of the
/// membership layer's active view, whose capacity `hyparview.Config` caps.
pub const max_peers = 32;

/// How many distinct missing message ids are tracked at once, which is also
/// how many `Graft` timers can be outstanding.
pub const max_missing = 32;

/// How many `(peer, round)` claims are remembered per missing id. Upstream's
/// `VecDeque` grows; this is the same queue with a bound.
pub const max_claims = 8;

/// How many `IHave`s may be queued for one lazy peer before the dispatch timer
/// is expected to have run.
pub const max_queued_ihaves = 16;

/// The largest `IHave` list put in one `Message::IHave`.
pub const max_ihaves_per_message = 16;

/// How many peers may have a lazy-push queue at once.
pub const max_queue_peers = 32;

/// Every way this state machine can refuse to do what it was asked.
pub const Error = error{
    /// An iTree peer set would have grown past `max_peers`.
    PeerSetFull,
    /// A payload is longer than `max_content`.
    MessageTooLarge,
    /// More distinct missing ids than `max_missing`, or more claims for one
    /// id than `max_claims`.
    MissingTableFull,
    /// One peer's lazy-push queue is full, or more peers are queued than
    /// `max_queue_peers`.
    LazyQueueFull,
    /// An `IHave` list is longer than `max_ihaves_per_message`.
    IHaveListTooLong,
};

/// A caller-owned list of output events.
///
/// The allocator lives here and not in `handle`, so no protocol function takes
/// one: the caller hands in a container and the state machine appends to it.
/// The membership layer's actions container is this same type over its own
/// events.
pub fn Actions(comptime Out: type) type {
    return struct {
        const Self = @This();

        gpa: Allocator,
        items: std.ArrayList(Out),

        pub fn init(gpa: Allocator) Self {
            return .{ .gpa = gpa, .items = .empty };
        }

        pub fn deinit(self: *Self) void {
            self.items.deinit(self.gpa);
        }

        /// Keep the allocation, drop the events. A driver that handles events
        /// in a loop clears rather than rebuilds.
        pub fn clear(self: *Self) void {
            self.items.clearRetainingCapacity();
        }

        pub fn count(self: *const Self) usize {
            return self.items.items.len;
        }

        pub fn at(self: *const Self, index: usize) Out {
            return self.items.items[index];
        }

        pub fn slice(self: *const Self) []const Out {
            return self.items.items;
        }

        pub fn push(self: *Self, item: Out) Allocator.Error!void {
            try self.items.append(self.gpa, item);
        }
    };
}

/// How many delivery hops a message has taken: one per forwarding node, so
/// `Swarm(0)` is the message at its origin and the round *is* the distance to
/// the origin.
pub const Round = struct {
    pub const zero: Round = .{ .value = 0 };

    value: u16,

    pub fn next(self: Round) Round {
        return .{ .value = self.value +% 1 };
    }

    /// Saturating, because the only caller has already checked the order and a
    /// debug build must not turn a rounding error into a crash.
    pub fn hopsSince(self: Round, earlier: Round) u16 {
        return self.value -| earlier.value;
    }
};

/// What a `MessageId` is: the content's BLAKE3 hash, with no domain
/// separation. See the module doc for why that is not an oversight.
pub const MessageId = struct {
    bytes: [id_length]u8,

    /// `blake3(content)`. Upstream `MessageId::from_content`, `plumtree.rs:35-37`.
    pub fn fromContent(content: []const u8) MessageId {
        var id: MessageId = undefined;
        std.crypto.hash.Blake3.hash(content, &id.bytes, .{});
        return id;
    }

    pub fn fromBytes(bytes: [id_length]u8) MessageId {
        return .{ .bytes = bytes };
    }

    pub fn toBytes(self: MessageId) [id_length]u8 {
        return self.bytes;
    }

    pub fn eql(a: MessageId, b: MessageId) bool {
        return std.mem.eql(u8, &a.bytes, &b.bytes);
    }

    pub fn order(a: MessageId, b: MessageId) std.math.Order {
        return std.mem.order(u8, &a.bytes, &b.bytes);
    }
};

/// A `MessageId` computed the way it must *not* be.
///
/// `blake3::derive_key` is the natural-looking "do it properly" choice and it
/// is wrong here: a peer that derived the id under a context string computes a
/// different value from every other peer for the same content, and the
/// mismatch is indistinguishable from a spoof. It exists so the rejection test
/// can use a real domain-separated digest rather than a made-up one.
pub fn domainSeparatedId(context: []const u8, content: []const u8) MessageId {
    var hasher = std.crypto.hash.Blake3.initKdf(context, .{});
    hasher.update(content);
    var id: MessageId = undefined;
    hasher.final(&id.bytes);
    return id;
}

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

    pub fn init(items: []const IHave) Error!IHaves {
        if (items.len > max_ihaves_per_message) return error.IHaveListTooLong;
        var list: IHaves = undefined;
        list.count = @intCast(items.len);
        @memcpy(list.items[0..items.len], items);
        return list;
    }

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

/// A timer the state machine asked for. The caller owns time and fires these.
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

/// Upstream `plumtree::Config`, with durations as integer nanoseconds because
/// nothing here may read a clock.
pub const Config = struct {
    /// How long to wait for an eager push after an `IHave` before grafting.
    /// Paper p8: a function of the overlay diameter and the application's
    /// recovery-latency target. Upstream default 80 ms.
    graft_timeout_1: Nanos = 80 * nanos_per_milli,
    /// How long to wait for the payload after a `Graft` before grafting
    /// somebody else. Paper p9: smaller than the first, about one round trip.
    /// Upstream default 40 ms.
    graft_timeout_2: Nanos = 40 * nanos_per_milli,
    /// How long `IHave`s are batched before being sent. Upstream default 5 ms.
    dispatch_timeout: Nanos = 5 * nanos_per_milli,
    /// How many rounds closer a lazy peer must claim to be before the tree is
    /// optimised. Paper p12. Upstream default 7.
    optimization_threshold: Round = .{ .value = 7 },
    /// How long a payload stays available to answer a late `Graft`. Upstream
    /// default 30 s.
    message_cache_retention: Nanos = 30 * nanos_per_second,
    /// How long a message id is remembered, which is what makes a duplicate a
    /// duplicate. Upstream default 90 s.
    message_id_retention: Nanos = 90 * nanos_per_second,
    /// How often the caches are swept. Upstream default 1 s.
    cache_evict_interval: Nanos = nanos_per_second,
};

/// Counters, upstream `plumtree::Stats`. `payload_messages_received` counts
/// payloads that arrived, including ones re-validation then dropped; see the
/// module doc.
pub const Stats = struct {
    payload_messages_received: u64 = 0,
    control_messages_received: u64 = 0,
    max_last_delivery_hop: u16 = 0,
};

/// Upstream's eager and lazy peer sets are `BTreeSet`s, so they iterate in
/// sorted order and a fan-out reaches peers in sorted order. This is one
/// sorted array: the sets hold at most `max_peers` members, and a linear
/// insert beats a tree at that size.
///
/// The order is observable. Two implementations that fan out in insertion
/// order rather than sorted order send the same bytes to the same peers in a
/// different order, and under load that is the difference between a peer being
/// reached by the first retransmission and the last.
fn PeerSet(comptime N: usize) type {
    return struct {
        const Self = @This();

        items: [N]NodeId = undefined,
        len: usize = 0,

        pub fn count(self: *const Self) usize {
            return self.len;
        }

        pub fn at(self: *const Self, index: usize) NodeId {
            return self.items[index];
        }

        pub fn slice(self: *const Self) []const NodeId {
            return self.items[0..self.len];
        }

        pub fn contains(self: *const Self, peer: NodeId) bool {
            for (self.slice()) |item| {
                if (sameNode(item, peer)) return true;
            }
            return false;
        }

        /// Insert in sorted position, leaving an existing member where it is.
        pub fn insert(self: *Self, peer: NodeId) Error!void {
            var slot = self.len;
            for (self.slice(), 0..) |item, index| {
                if (sameNode(item, peer)) return;
                if (item.order(peer) == .gt) {
                    slot = index;
                    break;
                }
            }
            if (self.len == N) return error.PeerSetFull;
            std.mem.copyBackwards(
                NodeId,
                self.items[slot + 1 .. self.len + 1],
                self.items[slot..self.len],
            );
            self.items[slot] = peer;
            self.len += 1;
        }

        pub fn remove(self: *Self, peer: NodeId) bool {
            for (self.slice(), 0..) |item, index| {
                if (!sameNode(item, peer)) continue;
                self.removeAt(index);
                self.len -= 1;
                return true;
            }
            return false;
        }

        fn removeAt(self: *Self, index: usize) void {
            std.mem.copyForwards(
                NodeId,
                self.items[index..self.len],
                self.items[index + 1 .. self.len],
            );
        }
    };
}

/// Upstream `TimeBoundCache<MessageId, ()>`: ids with an expiry, checked
/// against `now` only when a sweep runs. A re-insert overwrites in place,
/// which is upstream's "the entry was re-added with a later time" case.
fn IdCache(comptime N: usize) type {
    return struct {
        const Self = @This();

        const Entry = struct { id: MessageId, expires_at: Nanos };

        entries: [N]Entry = undefined,
        len: usize = 0,

        pub fn count(self: *const Self) usize {
            return self.len;
        }

        pub fn contains(self: *const Self, id: MessageId) bool {
            for (self.entries[0..self.len]) |entry| {
                if (entry.id.eql(id)) return true;
            }
            return false;
        }

        pub fn put(self: *Self, id: MessageId, expires_at: Nanos) void {
            for (self.entries[0..self.len]) |*entry| {
                if (!entry.id.eql(id)) continue;
                entry.expires_at = expires_at;
                return;
            }
            const at = self.evictSlot();
            self.entries[at] = .{ .id = id, .expires_at = expires_at };
        }

        /// Remove everything that has expired at or before `now`.
        pub fn expireUntil(self: *Self, now: Nanos) void {
            var kept: usize = 0;
            for (self.entries[0..self.len]) |entry| {
                if (entry.expires_at > now) {
                    self.entries[kept] = entry;
                    kept += 1;
                }
            }
            self.len = kept;
        }

        /// The slot to write when the id is new: a free one, or the entry that
        /// expires soonest. A forgotten id costs one duplicate delivery, which
        /// the receiving end also tolerates, so evicting is not a failure.
        fn evictSlot(self: *Self) usize {
            if (self.len < N) {
                defer self.len += 1;
                return self.len;
            }
            var soonest: usize = 0;
            for (self.entries[0..self.len], 0..) |entry, index| {
                if (entry.expires_at < self.entries[soonest].expires_at) soonest = index;
            }
            return soonest;
        }
    };
}

/// The payload half of `TimeBoundCache`: a copy of each message, kept so a
/// peer that grafts late can still be answered. The copy is what lets a
/// `Graft` reply borrow from the state rather than from the caller.
fn MessageCache(comptime Slots: usize) type {
    return struct {
        const Self = @This();

        const Stored = struct {
            id: MessageId,
            expires_at: Nanos,
            scope: DeliveryScope,
            len: u16,
            bytes: [max_content]u8,
        };

        entries: [Slots]Stored = undefined,
        len: usize = 0,

        pub fn count(self: *const Self) usize {
            return self.len;
        }

        pub fn get(self: *const Self, id: MessageId) ?Gossip {
            for (self.entries[0..self.len]) |*entry| {
                if (!entry.id.eql(id)) continue;
                return .{
                    .id = entry.id,
                    .content = entry.bytes[0..entry.len],
                    .scope = entry.scope,
                };
            }
            return null;
        }

        /// `error.MessageTooLarge` once, for both reasons a payload can be
        /// unstorable: the length does not fit the entry's `len`, or it fits
        /// and is still over the bytes the entry holds. The two are proved
        /// here, at the write, and not in the caller — a gossip off the wire
        /// is validated by its hash, and its hash says nothing about length.
        pub fn put(self: *Self, gossip: Gossip, expires_at: Nanos) Error!void {
            // Narrow once, where the bound is proved: the cast admits only a
            // length a `u16` holds, and the comparison is the ceiling of
            // `bytes`. One error answers both, because a payload this entry
            // cannot spell is a payload it cannot keep, and one it truncates
            // answers a `Graft` with bytes that are not the message asked for.
            const length: u16 = std.math.cast(u16, gossip.content.len) orelse
                return error.MessageTooLarge;
            if (length > max_content) return error.MessageTooLarge;

            var at: ?usize = null;
            for (self.entries[0..self.len], 0..) |*entry, index| {
                if (!entry.id.eql(gossip.id)) continue;
                at = index;
                break;
            }
            if (at == null) at = self.evictSlot();
            const entry = &self.entries[at.?];
            entry.id = gossip.id;
            entry.expires_at = expires_at;
            entry.scope = gossip.scope;
            entry.len = length;
            @memcpy(entry.bytes[0..length], gossip.content);
        }

        pub fn expireUntil(self: *Self, now: Nanos) void {
            var kept: usize = 0;
            for (self.entries[0..self.len]) |entry| {
                if (entry.expires_at > now) {
                    self.entries[kept] = entry;
                    kept += 1;
                }
            }
            self.len = kept;
        }

        /// See `IdCache.evictSlot`: a full cache drops the payload that expires
        /// soonest rather than failing a broadcast.
        fn evictSlot(self: *Self) usize {
            if (self.len < Slots) {
                defer self.len += 1;
                return self.len;
            }
            var soonest: usize = 0;
            for (self.entries[0..self.len], 0..) |entry, index| {
                if (entry.expires_at < self.entries[soonest].expires_at) soonest = index;
            }
            return soonest;
        }
    };
}

/// One "peer X claims message M, Y hops from the origin" claim.
const Claim = struct { peer: NodeId, round: Round };

/// `missing_messages`: for each id a peer advertised but we never received,
/// who claimed it, how far they claimed to be, and whether a `Graft` timer is
/// already running for it. Upstream's `HashMap<MessageId, VecDeque<(PI, Round)>>`
/// plus `graft_timer_scheduled: HashSet<MessageId>`, with the two merged.
///
/// The merge is not a simplification, it is a bound: the flag is only ever set
/// on an id that has an entry here, so the number of outstanding graft timers
/// cannot exceed `max_missing` and needs no second table. An entry whose
/// claims have all been pruned stays as an entry with `count == 0`, which is
/// indistinguishable from an absent one on every path that reads it.
const MissingEntry = struct {
    id: MessageId,
    count: u16,
    graft_timer_scheduled: bool,
    peers: [max_claims]NodeId,
    rounds: [max_claims]Round,
};

/// The lazy-push queue: `IHave`s waiting for the dispatch timer, per peer.
const QueueEntry = struct {
    peer: NodeId,
    count: u16,
    items: [max_queued_ihaves]IHave,
};

/// The state of one node's broadcast tree for one topic. Upstream
/// `plumtree::State`.
///
/// It knows nothing about membership: the active view arrives as
/// `neighbor_up` and `neighbor_down`, and everything else is the tree's own
/// bookkeeping.
pub const State = struct {
    me: NodeId,
    config: Config,

    /// Peers that get whole payloads. The eager edges are the iTree.
    eager_push_peers: PeerSet(max_peers) = .{},
    /// Peers that get ids only, after a delay.
    lazy_push_peers: PeerSet(max_peers) = .{},

    lazy_push_queue: [max_queue_peers]QueueEntry = undefined,
    lazy_push_queue_len: usize = 0,
    /// Whether a `DispatchLazyPush` is outstanding. Latched, so a burst of
    /// broadcasts batches into one timer rather than one timer per message.
    dispatch_timer_scheduled: bool = false,

    missing_messages: [max_missing]MissingEntry = undefined,
    missing_messages_len: usize = 0,

    received_messages: IdCache(max_received_ids) = .{},
    cache: MessageCache(cache_slots) = .{},

    /// Whether the first call has run. The cache sweep is scheduled once, on
    /// entry, exactly as upstream does it in `handle`. Named `started` rather
    /// than `init` because the constructor is `init`.
    started: bool = false,

    stats: Stats = .{},

    pub fn init(me: NodeId, config: Config) State {
        return .{ .me = me, .config = config };
    }

    pub fn eagerPeers(self: *const State) []const NodeId {
        return self.eager_push_peers.slice();
    }

    pub fn lazyPeers(self: *const State) []const NodeId {
        return self.lazy_push_peers.slice();
    }

    /// Handle one event. `now` is the caller's clock; nothing here reads one.
    ///
    /// **The arms below run in this order, and the order is the contract.**
    /// Within `onGossip` the arms are: validate, then either the duplicate
    /// branch or the forward branch, and inside the forward branch the order
    /// is remember the id, cache the payload, push to eager peers, queue ids
    /// for lazy peers, drop the graft timer, run the tree optimisation, and
    /// only then tell the application. Reordering those changes what a caller
    /// observes: the `Graft` and `Prune` of an optimisation go out *before* the
    /// `Received` event, so a driver that has not been told the message
    /// arrived still sees the tree move under it. It is also why the
    /// `schedule_timer` for the dispatch flush appears once for a burst rather
    /// than once per message, because the flag is latched. A reader who finds
    /// the sequence untidy should not sort it.
    pub fn handle(
        self: *State,
        event: InEvent,
        now: Nanos,
        out: *Actions(OutEvent),
    ) (Error || Allocator.Error)!void {
        if (!self.started) {
            self.started = true;
            try self.onEvictCacheTimer(now, out);
        }
        switch (event) {
            .recv_message => |recv| try self.handleMessage(recv.from, recv.message, now, out),
            .broadcast => |b| try self.broadcast(b.content, b.scope, now, out),
            .timer_expired => |timer| try self.handleTimer(timer, now, out),
            .neighbor_up => |peer| try self.addEager(peer),
            .neighbor_down => |peer| self.onNeighborDown(peer),
        }
    }

    fn handleTimer(
        self: *State,
        timer: Timer,
        now: Nanos,
        out: *Actions(OutEvent),
    ) (Error || Allocator.Error)!void {
        switch (timer) {
            .dispatch_lazy_push => try self.onDispatchTimer(out),
            .send_graft => |id| try self.onSendGraftTimer(id, out),
            .evict_cache => try self.onEvictCacheTimer(now, out),
        }
    }

    /// Upstream `handle_message`. The payload counter moves before the arm is
    /// chosen, so a spoofed frame is counted and then dropped; see the module
    /// doc.
    fn handleMessage(
        self: *State,
        from: NodeId,
        message: Message,
        now: Nanos,
        out: *Actions(OutEvent),
    ) (Error || Allocator.Error)!void {
        switch (message) {
            .gossip => |gossip| {
                self.stats.payload_messages_received += 1;
                try self.onGossip(from, gossip, now, out);
            },
            .prune => {
                self.stats.control_messages_received += 1;
                self.onPrune(from);
            },
            .i_have => |ihaves| {
                self.stats.control_messages_received += 1;
                try self.onIHave(from, ihaves.slice(), out);
            },
            .graft => |graft| {
                self.stats.control_messages_received += 1;
                try self.onGraft(from, graft, out);
            },
        }
    }

    /// Upstream `broadcast`.
    ///
    /// The payload goes to the eager peers now and the ids to the lazy peers
    /// after `dispatch_timeout`, and that split is the point: a lazy peer that
    /// shares a path with an eager one should get the payload from the eager
    /// peer first and only ask for it if that fails.
    pub fn broadcast(
        self: *State,
        content: []const u8,
        scope: Scope,
        now: Nanos,
        out: *Actions(OutEvent),
    ) (Error || Allocator.Error)!void {
        if (content.len > max_content) return error.MessageTooLarge;
        const id = MessageId.fromContent(content);
        const message: Gossip = .{
            .id = id,
            .content = content,
            .scope = deliveryScope(scope),
        };
        if (isSwarm(message.scope)) {
            self.received_messages.put(id, now + self.config.message_id_retention);
            try self.cache.put(message, now + self.config.message_cache_retention);
            try self.lazyPush(message, self.me, out);
        }
        try self.eagerPush(message, self.me, out);
    }

    /// Upstream `on_gossip`.
    ///
    /// The first arm is the invariant this module exists to hold: a message
    /// whose id is not the hash of its content is dropped, and dropping it
    /// does nothing at all to the sender. No `Prune`, no demotion to lazy, no
    /// record, no reply, no timer.
    fn onGossip(
        self: *State,
        sender: NodeId,
        message: Gossip,
        now: Nanos,
        out: *Actions(OutEvent),
    ) (Error || Allocator.Error)!void {
        if (!message.validate()) return;

        if (self.received_messages.contains(message.id)) {
            // A duplicate. The sender has a path to us that we do not need, so
            // it moves to the lazy side of the tree and is told so.
            try self.addLazy(sender);
            try out.push(.{
                .send_message = .{ .to = sender, .message = .{ .prune = {} } },
            });
            return;
        }

        if (isSwarm(message.scope)) {
            const arrived_at = message.round().?.value;
            self.received_messages.put(message.id, now + self.config.message_id_retention);
            const forwarded = message.nextRound().?;
            try self.cache.put(forwarded, now + self.config.message_cache_retention);
            try self.eagerPush(forwarded, sender, out);
            try self.lazyPush(forwarded, sender, out);
            self.forgetGraftTimer(message.id);
            if (self.takeMissing(message.id)) |claims| {
                try self.optimizeTree(sender, forwarded, claims, out);
            }
            self.stats.max_last_delivery_hop = @max(self.stats.max_last_delivery_hop, arrived_at);
        }

        try out.push(.{ .emit_event = .{
            .content = message.content,
            .delivered_from = sender,
            .scope = message.scope,
        } });
    }

    /// Upstream `optimize_tree`: if a peer claimed a much shorter path to this
    /// message than the sender we actually got it from, graft the claimant and
    /// prune the sender. Bending the tree towards the shortest path anybody
    /// has mentioned is the only self-optimisation PlumTree does.
    fn optimizeTree(
        self: *State,
        gossip_sender: NodeId,
        message: Gossip,
        claims: []const Claim,
        out: *Actions(OutEvent),
    ) (Error || Allocator.Error)!void {
        const round = message.round().?;
        var best: ?Claim = null;
        for (claims) |claim| {
            if (best == null or claim.round.value < best.?.round.value) best = claim;
        }
        const claim = best orelse return;
        if (claim.round.value >= round.value) return;
        if (round.hopsSince(claim.round) < self.config.optimization_threshold.value) return;

        if (!self.eager_push_peers.contains(claim.peer)) {
            try self.addEager(claim.peer);
            try out.push(.{ .send_message = .{ .to = claim.peer, .message = .{ .graft = .{
                .id = null,
                .round = claim.round,
            } } } });
        }
        try self.addLazy(gossip_sender);
        try out.push(.{ .send_message = .{
            .to = gossip_sender,
            .message = .{ .prune = {} },
        } });
    }

    /// Upstream `on_prune`.
    fn onPrune(self: *State, sender: NodeId) void {
        _ = self.lazy_push_peers.remove(sender);
    }

    /// Upstream `on_ihave`: remember who claims the message, and start the
    /// graft timer once per message rather than once per claim.
    fn onIHave(
        self: *State,
        sender: NodeId,
        ihaves: []const IHave,
        out: *Actions(OutEvent),
    ) (Error || Allocator.Error)!void {
        for (ihaves) |ihave| {
            if (self.received_messages.contains(ihave.id)) continue;
            try self.pushClaim(ihave.id, .{ .peer = sender, .round = ihave.round });
            if (self.graftTimerScheduled(ihave.id)) continue;
            self.rememberGraftTimer(ihave.id);
            try out.push(.{ .schedule_timer = .{
                .after = self.config.graft_timeout_1,
                .timer = .{ .send_graft = ihave.id },
            } });
        }
    }

    /// Upstream `on_send_graft_timer`: ask the first peer that advertised the
    /// message, then ask the next one if that fails too.
    fn onSendGraftTimer(
        self: *State,
        id: MessageId,
        out: *Actions(OutEvent),
    ) (Error || Allocator.Error)!void {
        self.forgetGraftTimer(id);
        // The eager push may have beaten the timer, in which case there is
        // nothing to ask for, and asking anyway would graft a peer over a
        // message we already have.
        if (self.received_messages.contains(id)) return;
        const claim = self.takeOldestClaim(id) orelse return;
        try self.addEager(claim.peer);
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
    /// for, send it from the cache. A graft for a message that has been swept
    /// is silently unanswered, which is right: the message is gone, and the
    /// only honest reply would be silence.
    fn onGraft(
        self: *State,
        sender: NodeId,
        details: Graft,
        out: *Actions(OutEvent),
    ) (Error || Allocator.Error)!void {
        try self.addEager(sender);
        const id = details.id orelse return;
        const message = self.cache.get(id) orelse return;
        try out.push(.{ .send_message = .{ .to = sender, .message = .{ .gossip = message } } });
    }

    /// Upstream `on_neighbor_down`: a neighbour is gone, so drop it from both
    /// sets and from the claim history, and forget any graft we owed it. An
    /// entry left with no claims stays, because an absent entry and an empty
    /// one read the same on every path that consults them.
    fn onNeighborDown(self: *State, peer: NodeId) void {
        for (self.missing_messages[0..self.missing_messages_len]) |*entry| {
            var kept: u16 = 0;
            for (entry.peers[0..entry.count], entry.rounds[0..entry.count]) |claimed, round| {
                if (sameNode(claimed, peer)) continue;
                entry.peers[kept] = claimed;
                entry.rounds[kept] = round;
                kept += 1;
            }
            entry.count = kept;
        }
        _ = self.eager_push_peers.remove(peer);
        _ = self.lazy_push_peers.remove(peer);
    }

    /// Upstream `on_evict_cache_timer`.
    fn onEvictCacheTimer(
        self: *State,
        now: Nanos,
        out: *Actions(OutEvent),
    ) (Error || Allocator.Error)!void {
        self.cache.expireUntil(now);
        self.received_messages.expireUntil(now);
        try out.push(.{ .schedule_timer = .{
            .after = self.config.cache_evict_interval,
            .timer = .evict_cache,
        } });
    }

    /// Upstream `on_dispatch_timer`. Peers flush in sorted order, and one long
    /// queue is cut into several messages rather than overrunning a frame.
    fn onDispatchTimer(self: *State, out: *Actions(OutEvent)) (Error || Allocator.Error)!void {
        while (self.lazy_push_queue_len > 0) {
            const entry = self.lazy_push_queue[0];
            var sent: usize = 0;
            while (sent < entry.count) {
                const n = @min(max_ihaves_per_message, entry.count - sent);
                const list = try IHaves.init(entry.items[sent..][0..n]);
                try out.push(.{ .send_message = .{
                    .to = entry.peer,
                    .message = .{ .i_have = list },
                } });
                sent += n;
            }
            std.mem.copyForwards(
                QueueEntry,
                self.lazy_push_queue[0 .. self.lazy_push_queue_len - 1],
                self.lazy_push_queue[1..self.lazy_push_queue_len],
            );
            self.lazy_push_queue_len -= 1;
        }
        self.dispatch_timer_scheduled = false;
    }

    /// Upstream `eager_push`: the whole payload, to every eager peer but the
    /// one it came from and but ourselves.
    fn eagerPush(
        self: *State,
        gossip: Gossip,
        sender: NodeId,
        out: *Actions(OutEvent),
    ) (Error || Allocator.Error)!void {
        for (self.eager_push_peers.slice()) |peer| {
            if (sameNode(peer, self.me) or sameNode(peer, sender)) continue;
            try out.push(.{ .send_message = .{
                .to = peer,
                .message = .{ .gossip = gossip },
            } });
        }
    }

    /// Upstream `lazy_push`: ids only, batched. The dispatch timer is
    /// scheduled even when there is no lazy peer, which is upstream's
    /// behaviour and shows up in the ported unit tests: the timer exists to
    /// coalesce a burst, and a burst that happens to have no lazy peer still
    /// armed one.
    fn lazyPush(
        self: *State,
        gossip: Gossip,
        sender: NodeId,
        out: *Actions(OutEvent),
    ) (Error || Allocator.Error)!void {
        const round = gossip.round() orelse return;
        for (self.lazy_push_peers.slice()) |peer| {
            if (sameNode(peer, sender)) continue;
            try self.queueIHave(peer, .{ .id = gossip.id, .round = round });
        }
        if (!self.dispatch_timer_scheduled) {
            self.dispatch_timer_scheduled = true;
            try out.push(.{ .schedule_timer = .{
                .after = self.config.dispatch_timeout,
                .timer = .dispatch_lazy_push,
            } });
        }
    }

    /// Upstream `add_eager`.
    fn addEager(self: *State, peer: NodeId) Error!void {
        _ = self.lazy_push_peers.remove(peer);
        try self.eager_push_peers.insert(peer);
    }

    /// Upstream `add_lazy`.
    fn addLazy(self: *State, peer: NodeId) Error!void {
        _ = self.eager_push_peers.remove(peer);
        try self.lazy_push_peers.insert(peer);
    }

    fn queueIHave(self: *State, peer: NodeId, ihave: IHave) Error!void {
        for (self.lazy_push_queue[0..self.lazy_push_queue_len]) |*entry| {
            if (!sameNode(entry.peer, peer)) continue;
            if (entry.count == max_queued_ihaves) return error.LazyQueueFull;
            entry.items[entry.count] = ihave;
            entry.count += 1;
            return;
        }
        if (self.lazy_push_queue_len == max_queue_peers) return error.LazyQueueFull;
        const entry = &self.lazy_push_queue[self.lazy_push_queue_len];
        entry.peer = peer;
        entry.count = 1;
        entry.items[0] = ihave;
        self.lazy_push_queue_len += 1;
    }

    fn findMissing(self: *State, id: MessageId) ?*MissingEntry {
        for (self.missing_messages[0..self.missing_messages_len]) |*entry| {
            if (entry.id.eql(id)) return entry;
        }
        return null;
    }

    fn pushClaim(self: *State, id: MessageId, claim: Claim) Error!void {
        if (self.findMissing(id)) |entry| {
            if (entry.count == max_claims) return error.MissingTableFull;
            entry.peers[entry.count] = claim.peer;
            entry.rounds[entry.count] = claim.round;
            entry.count += 1;
            return;
        }
        if (self.missing_messages_len == max_missing) return error.MissingTableFull;
        const entry = &self.missing_messages[self.missing_messages_len];
        entry.id = id;
        entry.count = 1;
        entry.graft_timer_scheduled = false;
        entry.peers[0] = claim.peer;
        entry.rounds[0] = claim.round;
        self.missing_messages_len += 1;
    }

    fn takeMissing(self: *State, id: MessageId) ?[]const Claim {
        const index = self.missingIndex(id) orelse return null;
        var claims: [max_claims]Claim = undefined;
        const entry = self.missing_messages[index];
        for (entry.peers[0..entry.count], entry.rounds[0..entry.count], 0..) |peer, round, at| {
            claims[at] = .{ .peer = peer, .round = round };
        }
        self.removeMissing(index);
        return claims[0..entry.count];
    }

    /// Pop the front of one id's claim queue, which is the peer we graft next.
    fn takeOldestClaim(self: *State, id: MessageId) ?Claim {
        const index = self.missingIndex(id) orelse return null;
        const entry = &self.missing_messages[index];
        const claim = Claim{ .peer = entry.peers[0], .round = entry.rounds[0] };
        var at: usize = 1;
        while (at < entry.count) : (at += 1) {
            entry.peers[at - 1] = entry.peers[at];
            entry.rounds[at - 1] = entry.rounds[at];
        }
        entry.count -= 1;
        if (entry.count == 0) self.removeMissing(index);
        return claim;
    }

    fn missingIndex(self: *State, id: MessageId) ?usize {
        for (self.missing_messages[0..self.missing_messages_len], 0..) |entry, index| {
            if (entry.id.eql(id)) return index;
        }
        return null;
    }

    fn removeMissing(self: *State, index: usize) void {
        std.mem.copyForwards(
            MissingEntry,
            self.missing_messages[index .. self.missing_messages_len - 1],
            self.missing_messages[index + 1 .. self.missing_messages_len],
        );
        self.missing_messages_len -= 1;
    }

    fn graftTimerScheduled(self: *State, id: MessageId) bool {
        const entry = self.findMissing(id) orelse return false;
        return entry.graft_timer_scheduled;
    }

    /// The caller has just created or found the entry, so the write cannot
    /// miss; that is the whole reason this takes no error.
    fn rememberGraftTimer(self: *State, id: MessageId) void {
        self.findMissing(id).?.graft_timer_scheduled = true;
    }

    fn forgetGraftTimer(self: *State, id: MessageId) void {
        const entry = self.findMissing(id) orelse return;
        entry.graft_timer_scheduled = false;
    }
};

fn isSwarm(scope: DeliveryScope) bool {
    return switch (scope) {
        .swarm => true,
        .neighbors => false,
    };
}

fn sameNode(a: NodeId, b: NodeId) bool {
    return a.order(b) == .eq;
}

const t = std.testing;

/// Node ids from fixed seeds, as `discovery/item.zig` does them. A `NodeId`
/// cannot be built from arbitrary bytes — `fromBytes` rejects a non-point — so
/// a test pool draws from seeds.
fn testNodeId(index: u8) NodeId {
    var seed: [key.SecretKey.seed_length]u8 = undefined;
    @memset(&seed, 0xa5);
    seed[0] = index;
    return (key.SecretKey.fromSeed(seed) catch unreachable).nodeId();
}

/// The input of a BLAKE3 test-vector case: 0, 1, ... 250 repeating.
fn blake3Input(len: usize) []u8 {
    const input = t.allocator.alloc(u8, len) catch unreachable;
    for (input, 0..) |*byte, index| byte.* = @intCast(index % 251);
    return input;
}

/// BLAKE3 test vectors from `BLAKE3-team/BLAKE3`,
/// `test_vectors/test_vectors.json`, commit
/// `6aab490a26124663329dfd3961b8469f8fdb158b`, fetched 2026-09-30. The input of
/// each case is the 251-byte sequence 0, 1, ... 250 repeating, per the
/// `COMMENT` in `test_vectors/src/lib.rs` at the same commit.
///
/// `hash` is the plain hash, which is what a `MessageId` is. `derive_key` is
/// the same input under the key-derivation mode and the context string
/// `BLAKE3 2019-12-27 16:29:52 test vectors context`; it is here so the
/// rejection test can use a real domain-separated digest.
/// The 32 bytes behind a 64-character hex digest, decoded at run time.
/// A `MessageId` is a byte array, so a table of published digests has to be
/// decoded before it can be compared with one, and a comptime decode of two
/// dozen literals costs more compile time than the whole rest of the module.
fn messageIdFromHex(hex: []const u8) MessageId {
    if (hex.len != id_length * 2) @panic("a digest literal must be 64 hex characters");
    var bytes: [id_length]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, hex) catch @panic("a digest literal must be hex");
    return MessageId.fromBytes(bytes);
}

const Blake3Vector = struct {
    len: usize,
    /// The plain hash: this is what a `MessageId` is.
    hash: []const u8,
    /// The same input under key derivation and the published context string.
    derive_key: []const u8,
};

const blake3_vectors = [_]Blake3Vector{
    .{
        .len = 0,
        .hash = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        .derive_key = "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d",
    },
    .{
        .len = 1,
        .hash = "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
        .derive_key = "b3e2e340a117a499c6cf2398a19ee0d29cca2bb7404c73063382693bf66cb06c",
    },
    .{
        .len = 2,
        .hash = "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63",
        .derive_key = "1f166565a7df0098ee65922d7fea425fb18b9943f19d6161e2d17939356168e6",
    },
    .{
        .len = 3,
        .hash = "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f",
        .derive_key = "440aba35cb006b61fc17c0529255de438efc06a8c9ebf3f2ddac3b5a86705797",
    },
    .{
        .len = 8,
        .hash = "2351207d04fc16ade43ccab08600939c7c1fa70a5c0aaca76063d04c3228eaeb",
        .derive_key = "2b166978cef14d9d438046c720519d8b1cad707e199746f1562d0c87fbd32940",
    },
    .{
        .len = 63,
        .hash = "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b",
        .derive_key = "b6451e30b953c206e34644c6803724e9d2725e0893039cfc49584f991f451af3",
    },
    .{
        .len = 64,
        .hash = "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98",
        .derive_key = "a5c4a7053fa86b64746d4bb688d06ad1f02a18fce9afd3e818fefaa7126bf73e",
    },
    .{
        .len = 127,
        .hash = "d81293fda863f008c09e92fc382a81f5a0b4a1251cba1634016a0f86a6bd640d",
        .derive_key = "c91c090ceee3a3ac81902da31838012625bbcd73fcb92e7d7e56f78deba4f0c3",
    },
    .{
        .len = 128,
        .hash = "f17e570564b26578c33bb7f44643f539624b05df1a76c81f30acd548c44b45ef",
        .derive_key = "81720f34452f58a0120a58b6b4608384b5c51d11f39ce97161a0c0e442ca0225",
    },
    .{
        .len = 1023,
        .hash = "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11",
        .derive_key = "74a16c1c3d44368a86e1ca6df64be6a2f64cce8f09220787450722d85725dea5",
    },
    .{
        .len = 1024,
        .hash = "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
        .derive_key = "7356cd7720d5b66b6d0697eb3177d9f8d73a4a5c5e968896eb6a689684302706",
    },
};
// A `MessageId` is the plain BLAKE3 hash of the content, checked against the
// published vectors rather than against this implementation's own output.
test "a message id is blake3 of the content, and nothing else" {
    for (blake3_vectors) |vector| {
        const input = blake3Input(vector.len);
        defer t.allocator.free(input);
        try t.expectEqualStrings(vector.hash, &std.fmt.bytesToHex(
            MessageId.fromContent(input).toBytes(),
            .lower,
        ));
        try t.expect(messageIdFromHex(vector.hash).eql(MessageId.fromContent(input)));
        try t.expect(!messageIdFromHex(vector.derive_key).eql(MessageId.fromContent(input)));
    }
}

// The failure this module is most likely to suffer: an id computed under a
// context string. It is a different value for the same content, so it is not
// an id, and a message carrying one is dropped.
test "a domain-separated id is not a message id" {
    const content = blake3Input(2);
    defer t.allocator.free(content);
    const context = "BLAKE3 2019-12-27 16:29:52 test vectors context";
    const separated = domainSeparatedId(context, content);
    try t.expect(!MessageId.fromContent(content).eql(separated));

    for (blake3_vectors) |vector| {
        const input = blake3Input(vector.len);
        defer t.allocator.free(input);
        const wrong = messageIdFromHex(vector.derive_key);
        const gossip: Gossip = .{
            .id = wrong,
            .content = input,
            .scope = .{ .swarm = Round.zero },
        };
        try t.expect(!gossip.validate());
    }
}

// The second half of the invariant: a spoofed id is dropped, and dropping it
// does not touch the peer that sent it. A path that also punished would let
// one bad frame per neighbour empty a victim's iTree.
test "a spoofed message id is dropped without penalising the peer" {
    const me = testNodeId(1);
    const peer = testNodeId(2);
    const content = blake3Input(2);
    defer t.allocator.free(content);
    const id = MessageId.fromContent(content);

    var state: State = .init(me, .{});
    var out: Actions(OutEvent) = .init(t.allocator);
    defer out.deinit();

    // A well-formed message from the peer: the peer is promoted, the payload
    // is announced to the application, and the dispatch timer is armed.
    try state.handle(.{ .neighbor_up = peer }, 0, &out);
    out.clear();
    try state.handle(.{ .recv_message = .{
        .from = peer,
        .message = .{ .gossip = .{
            .id = id,
            .content = content,
            .scope = .{ .swarm = .{ .value = 1 } },
        } },
    } }, 0, &out);
    try t.expectEqual(@as(usize, 2), out.count());
    try t.expect(out.at(0) == .schedule_timer);
    try t.expect(out.at(0).schedule_timer.timer == .dispatch_lazy_push);
    try t.expect(out.at(1) == .emit_event);
    try t.expect(state.eager_push_peers.contains(peer));

    // The same peer, the same content, an id that is not the hash of it.
    const wrong = messageIdFromHex(blake3_vectors[2].derive_key);
    const received_before = state.stats.payload_messages_received;
    out.clear();
    try state.handle(.{ .recv_message = .{
        .from = peer,
        .message = .{ .gossip = .{
            .id = wrong,
            .content = content,
            .scope = .{ .swarm = .{ .value = 1 } },
        } },
    } }, 0, &out);

    // Half one: nothing at all comes out. No `Prune`, no `Graft`, no event, no
    // timer, nothing queued for later.
    try t.expectEqual(@as(usize, 0), out.count());
    // Half two: nothing about the peer changed. It is still eager, still not
    // in the claim table, and the id was not remembered as seen.
    try t.expect(state.eager_push_peers.contains(peer));
    try t.expect(!state.lazy_push_peers.contains(peer));
    try t.expect(!state.received_messages.contains(wrong));
    try t.expectEqual(@as(usize, 0), state.missing_messages_len);
    try t.expectEqual(@as(usize, 0), state.lazy_push_queue_len);
    // The one thing that does move, by upstream's design: the frame was
    // received. This is a receive counter, not a delivery counter.
    try t.expectEqual(received_before + 1, state.stats.payload_messages_received);
}

// The iTree on a three-node topology: `2` and `3` are eager children, `4` is
// a lazy edge. A payload arriving from `2` goes whole to `3` and by id to
// `4`, and nothing goes back to `2`.
test "the iTree forwards along eager edges and announces along lazy ones" {
    const me = testNodeId(1);
    const from = testNodeId(2);
    const eager_child = testNodeId(3);
    const lazy_child = testNodeId(4);
    const content = blake3Input(3);
    defer t.allocator.free(content);
    const id = MessageId.fromContent(content);

    var state: State = .init(me, .{});
    var out: Actions(OutEvent) = .init(t.allocator);
    defer out.deinit();

    try state.handle(.{ .neighbor_up = from }, 0, &out);
    try state.handle(.{ .neighbor_up = eager_child }, 0, &out);
    out.clear();
    // `lazy_child` is a neighbour but the tree put it on the lazy side.
    try state.addLazy(lazy_child);
    try t.expectEqual(@as(usize, 2), state.eagerPeers().len);
    try t.expectEqual(@as(usize, 1), state.lazyPeers().len);

    out.clear();
    try state.handle(.{ .recv_message = .{
        .from = from,
        .message = .{ .gossip = .{
            .id = id,
            .content = content,
            .scope = .{ .swarm = .{ .value = 3 } },
        } },
    } }, 0, &out);

    // The whole payload to the eager child at round 4, then the dispatch
    // timer, then the application event. The `IHave` to the lazy child is
    // still queued, which is the delay the lazy side exists for.
    try t.expectEqual(@as(usize, 3), out.count());
    try t.expect(out.at(0) == .send_message);
    try t.expect(sameNode(out.at(0).send_message.to, eager_child));
    try t.expectEqual(@as(u16, 4), out.at(0).send_message.message.gossip.round().?.value);
    try t.expect(!sameNode(out.at(0).send_message.to, from));
    try t.expect(out.at(1) == .schedule_timer);
    try t.expect(out.at(1).schedule_timer.timer == .dispatch_lazy_push);
    try t.expect(out.at(2) == .emit_event);
    try t.expectEqual(@as(u16, 3), state.stats.max_last_delivery_hop);

    // Firing the dispatch timer is what turns the queued id into an `IHave`.
    out.clear();
    try state.handle(.{ .timer_expired = .dispatch_lazy_push }, 0, &out);
    try t.expectEqual(@as(usize, 1), out.count());
    try t.expect(out.at(0) == .send_message);
    try t.expect(sameNode(out.at(0).send_message.to, lazy_child));
    const ihaves = out.at(0).send_message.message.i_have.slice();
    try t.expectEqual(@as(usize, 1), ihaves.len);
    try t.expect(ihaves[0].id.eql(id));
    try t.expectEqual(@as(u16, 4), ihaves[0].round.value);
}

// The first half of the recovery path: a peer advertises a message this node
// never received, the timer fires, and the peer is grafted and asked for it.
test "an iHave that is not followed by a payload becomes a graft" {
    const me = testNodeId(1);
    const peer = testNodeId(2);
    const content = blake3Input(8);
    defer t.allocator.free(content);
    const id = MessageId.fromContent(content);

    var state: State = .init(me, .{});
    var out: Actions(OutEvent) = .init(t.allocator);
    defer out.deinit();

    try state.handle(.{ .neighbor_up = peer }, 0, &out);
    out.clear();
    try state.handle(.{ .recv_message = .{
        .from = peer,
        .message = .{ .i_have = try IHaves.init(&.{.{ .id = id, .round = .{ .value = 2 } }}) },
    } }, 0, &out);
    try t.expectEqual(@as(usize, 1), out.count());
    try t.expect(out.at(0) == .schedule_timer);
    try t.expectEqual(state.config.graft_timeout_1, out.at(0).schedule_timer.after);

    // Before the timer fires, the peer is still only a neighbour and not a
    // tree edge.
    try t.expect(state.eager_push_peers.contains(peer));

    out.clear();
    try state.handle(.{ .timer_expired = .{ .send_graft = id } }, 0, &out);
    try t.expectEqual(@as(usize, 2), out.count());
    try t.expect(out.at(0) == .send_message);
    try t.expect(out.at(0).send_message.message.graft.id != null);
    try t.expect(out.at(0).send_message.message.graft.id.?.eql(id));
    try t.expect(out.at(1) == .schedule_timer);
    try t.expectEqual(state.config.graft_timeout_2, out.at(1).schedule_timer.after);
    try t.expectEqual(@as(usize, 0), state.cache.count());
}

// The second half: a peer that hears the same id from a third party grafts us
// directly, and the cache is what answers. The payload is copied on the way in
// precisely so that this reply can be made after the original message is gone.
test "a graft is answered from the cache" {
    const me = testNodeId(1);
    const holder = testNodeId(3);
    const asker = testNodeId(2);
    const content = blake3Input(8);
    defer t.allocator.free(content);
    const id = MessageId.fromContent(content);

    var state: State = .init(me, .{});
    var out: Actions(OutEvent) = .init(t.allocator);
    defer out.deinit();

    try state.handle(.{ .neighbor_up = holder }, 0, &out);
    try state.handle(.{ .neighbor_up = asker }, 0, &out);
    out.clear();
    try state.handle(.{ .recv_message = .{
        .from = holder,
        .message = .{ .gossip = .{
            .id = id,
            .content = content,
            .scope = .{ .swarm = .{ .value = 1 } },
        } },
    } }, 0, &out);
    try t.expectEqual(@as(usize, 1), state.cache.count());

    out.clear();
    try state.handle(.{ .recv_message = .{
        .from = asker,
        .message = .{ .graft = .{ .id = id, .round = .{ .value = 2 } } },
    } }, 0, &out);
    try t.expectEqual(@as(usize, 1), out.count());
    try t.expect(out.at(0) == .send_message);
    try t.expect(sameNode(out.at(0).send_message.to, asker));
    try t.expectEqualStrings(content, out.at(0).send_message.message.gossip.content);
    try t.expect(state.eager_push_peers.contains(asker));
}

// A graft for a message this node has itself is a no-op beyond the promotion,
// and one for a message the cache has already swept is silent.
test "a graft the cache cannot answer is silent" {
    const me = testNodeId(1);
    const peer = testNodeId(2);
    const content = blake3Input(2);
    defer t.allocator.free(content);
    const id = MessageId.fromContent(content);

    var state: State = .init(me, .{});
    var out: Actions(OutEvent) = .init(t.allocator);
    defer out.deinit();

    out.clear();
    try state.handle(.{ .recv_message = .{
        .from = peer,
        .message = .{ .graft = .{ .id = id, .round = .{ .value = 1 } } },
    } }, 0, &out);
    // Only the cache sweep, from the init latch. The peer is promoted, and
    // nothing is invented in reply.
    try t.expectEqual(@as(usize, 1), out.count());
    try t.expect(out.at(0) == .schedule_timer);
    try t.expect(state.eager_push_peers.contains(peer));
}

// Upstream `plumtree::test::optimize_tree`, pinned. The first run leaves the
// sender three rounds closer than the threshold and does nothing; the second
// leaves it nine rounds closer and grafts and prunes. The dispatch timer is
// armed once across both, which is what makes the second run's expected list
// shorter than the first's.
test "the tree optimises towards the shortest path anybody claimed" {
    const me = testNodeId(1);
    const claimant = testNodeId(2);
    const sender = testNodeId(3);

    const near = blake3Input(2);
    defer t.allocator.free(near);
    const far = blake3Input(3);
    defer t.allocator.free(far);
    const near_id = messageIdFromHex(blake3_vectors[2].hash);
    const far_id = messageIdFromHex(blake3_vectors[3].hash);

    var state: State = .init(me, .{});
    var out: Actions(OutEvent) = .init(t.allocator);
    defer out.deinit();

    try state.handle(.{ .recv_message = .{
        .from = claimant,
        .message = .{ .i_have = try IHaves.init(&.{.{ .id = near_id, .round = .{ .value = 2 } }}) },
    } }, 0, &out);
    out.clear();
    try state.handle(.{ .recv_message = .{
        .from = sender,
        .message = .{ .gossip = .{
            .id = near_id,
            .content = near,
            .scope = .{ .swarm = .{ .value = 6 } },
        } },
    } }, 0, &out);
    try t.expectEqual(@as(usize, 2), out.count());
    try t.expect(out.at(0) == .schedule_timer);
    try t.expect(out.at(0).schedule_timer.timer == .dispatch_lazy_push);
    try t.expect(out.at(1) == .emit_event);
    try t.expect(sameNode(out.at(1).emit_event.delivered_from, sender));
    out.clear();

    try state.handle(.{ .recv_message = .{
        .from = claimant,
        .message = .{ .i_have = try IHaves.init(&.{.{ .id = far_id, .round = .{ .value = 2 } }}) },
    } }, 0, &out);
    out.clear();
    try state.handle(.{ .recv_message = .{
        .from = sender,
        .message = .{ .gossip = .{
            .id = far_id,
            .content = far,
            .scope = .{ .swarm = .{ .value = 9 } },
        } },
    } }, 0, &out);
    try t.expectEqual(@as(usize, 3), out.count());
    try t.expect(out.at(0) == .send_message);
    try t.expect(sameNode(out.at(0).send_message.to, claimant));
    try t.expect(out.at(0).send_message.message.graft.id == null);
    try t.expectEqual(@as(u16, 2), out.at(0).send_message.message.graft.round.value);
    try t.expect(out.at(1) == .send_message);
    try t.expect(sameNode(out.at(1).send_message.to, sender));
    try t.expect(out.at(1).send_message.message == .prune);
    try t.expect(out.at(2) == .emit_event);
    try t.expect(state.eager_push_peers.contains(claimant));
    try t.expect(state.lazy_push_peers.contains(sender));
}

// A second copy of a message already held is not forwarded and not announced;
// it costs the sender its eager edge.
test "a duplicate moves the sender to the lazy side" {
    const me = testNodeId(1);
    const sender = testNodeId(2);
    const content = blake3Input(2);
    defer t.allocator.free(content);
    const id = messageIdFromHex(blake3_vectors[2].hash);
    const gossip: Gossip = .{
        .id = id,
        .content = content,
        .scope = .{ .swarm = .{ .value = 1 } },
    };

    var state: State = .init(me, .{});
    var out: Actions(OutEvent) = .init(t.allocator);
    defer out.deinit();

    try state.handle(.{ .neighbor_up = sender }, 0, &out);
    out.clear();
    const arrival: InEvent = .{ .recv_message = .{
        .from = sender,
        .message = .{ .gossip = gossip },
    } };
    try state.handle(arrival, 0, &out);
    try t.expect(out.at(out.count() - 1) == .emit_event);

    out.clear();
    try state.handle(arrival, 0, &out);
    try t.expectEqual(@as(usize, 1), out.count());
    try t.expect(out.at(0) == .send_message);
    try t.expect(out.at(0).send_message.message == .prune);
    try t.expect(sameNode(out.at(0).send_message.to, sender));
    try t.expect(state.lazy_push_peers.contains(sender));
    try t.expect(!state.eager_push_peers.contains(sender));
}

// A neighbour that goes away leaves both sets and the claim table.
test "a neighbour down leaves the tree" {
    const me = testNodeId(1);
    const eager = testNodeId(2);
    const content = blake3Input(2);
    defer t.allocator.free(content);
    const id = messageIdFromHex(blake3_vectors[2].hash);

    var state: State = .init(me, .{});
    var out: Actions(OutEvent) = .init(t.allocator);
    defer out.deinit();

    try state.handle(.{ .neighbor_up = eager }, 0, &out);
    try state.addLazy(testNodeId(3));
    try state.pushClaim(id, .{ .peer = eager, .round = .{ .value = 2 } });
    out.clear();
    try state.handle(.{ .neighbor_down = eager }, 0, &out);
    try t.expectEqual(@as(usize, 0), out.count());
    try t.expectEqual(@as(usize, 0), state.eagerPeers().len);
    try t.expectEqual(@as(usize, 1), state.lazyPeers().len);
    try t.expect(!state.lazy_push_peers.contains(eager));
    try t.expectEqual(@as(u16, 0), state.missing_messages[0].count);
}

// Upstream `plumtree::test::cache_is_evicted`: the payload cache holds a
// message for `message_cache_retention` and not one tick longer.
test "the payload cache is evicted on its own clock" {
    const me = testNodeId(1);
    const peer = testNodeId(2);
    const content = blake3Input(2);
    defer t.allocator.free(content);
    const id = messageIdFromHex(blake3_vectors[2].hash);

    var state: State = .init(me, .{});
    var out: Actions(OutEvent) = .init(t.allocator);
    defer out.deinit();

    try state.handle(.{ .neighbor_up = peer }, 0, &out);
    try state.handle(.{ .recv_message = .{ .from = peer, .message = .{ .gossip = .{
        .id = id,
        .content = content,
        .scope = .{ .swarm = .{ .value = 1 } },
    } } } }, 0, &out);
    try t.expectEqual(@as(usize, 1), state.cache.count());

    out.clear();
    const one_interval = state.config.cache_evict_interval;
    try state.handle(.{ .timer_expired = .evict_cache }, one_interval, &out);
    try t.expectEqual(@as(usize, 1), state.cache.count());

    out.clear();
    try state.handle(
        .{ .timer_expired = .evict_cache },
        one_interval + state.config.message_cache_retention,
        &out,
    );
    try t.expectEqual(@as(usize, 0), state.cache.count());
    // The id is still remembered: `message_id_retention` is three times
    // `message_cache_retention`, which is what stops a late graft being
    // answered with a payload we have already forgotten but still recognise.
    try t.expectEqual(@as(usize, 1), state.received_messages.count());
}

// The eager and lazy sets are sorted, and a fan-out follows that order, so
// two implementations agree on who is asked first.
test "the iTree sets are sorted" {
    const me = testNodeId(9);
    var state: State = .init(me, .{});
    var out: Actions(OutEvent) = .init(t.allocator);
    defer out.deinit();

    for ([_]u8{ 5, 1, 8, 3 }) |index| try state.addEager(testNodeId(index));
    try t.expectEqual(@as(usize, 4), state.eagerPeers().len);
    var at: usize = 1;
    while (at < state.eagerPeers().len) : (at += 1) {
        try t.expect(state.eagerPeers()[at - 1].order(state.eagerPeers()[at]) == .lt);
    }

    const content = blake3Input(1);
    defer t.allocator.free(content);
    out.clear();
    try state.broadcast(content, .swarm, 0, &out);
    // Four payloads and one dispatch timer, the timer first because the lazy
    // push is queued before the eager one goes out.
    try t.expectEqual(@as(usize, 5), out.count());
    try t.expect(out.at(0) == .schedule_timer);
    at = 2;
    while (at < out.count()) : (at += 1) {
        const before = out.at(at - 1).send_message.to;
        const after = out.at(at).send_message.to;
        try t.expect(before.order(after) == .lt);
    }
}

// A payload over the cache's bound is refused rather than truncated, because
// a truncated payload with the right id is a message nobody can verify.
test "a payload over the bound is refused" {
    const me = testNodeId(1);
    const content = try t.allocator.alloc(u8, max_content + 1);
    defer t.allocator.free(content);
    @memset(content, 0x5a);

    var state: State = .init(me, .{});
    var out: Actions(OutEvent) = .init(t.allocator);
    defer out.deinit();

    try t.expectError(
        error.MessageTooLarge,
        state.broadcast(content, .swarm, 0, &out),
    );
    try t.expectEqual(@as(usize, 0), state.cache.count());
}

// The receive path bounds the payload as well, and the bound belongs in the
// cache: an oversized gossip off the wire must be refused there, never
// truncated into an entry whose id is the hash of a longer message.
test "a received payload over the bound is refused" {
    const me = testNodeId(1);
    const content = try t.allocator.alloc(u8, max_content + 1);
    defer t.allocator.free(content);
    @memset(content, 0x5a);

    var state: State = .init(me, .{});
    var out: Actions(OutEvent) = .init(t.allocator);
    defer out.deinit();

    try t.expectError(
        error.MessageTooLarge,
        state.handle(.{ .recv_message = .{ .from = testNodeId(2), .message = .{ .gossip = .{
            .id = MessageId.fromContent(content),
            .content = content,
            .scope = .{ .swarm = Round.zero },
        } } } }, 0, &out),
    );
    try t.expectEqual(@as(usize, 0), state.cache.count());
}

// `max_content + 1` fits a `u16` and this does not, so the two bounds are
// separate arms and this pins the narrowing one. With the ceiling alone and a
// bare `@intCast`, this length truncates to zero in an unchecked build and
// traps in this one — either way the entry ends up an empty payload under the
// hash of 65536 bytes.
test "a received payload too long to record is refused" {
    const me = testNodeId(1);
    const content = try t.allocator.alloc(u8, std.math.maxInt(u16) + 1);
    defer t.allocator.free(content);
    @memset(content, 0x5a);

    var state: State = .init(me, .{});
    var out: Actions(OutEvent) = .init(t.allocator);
    defer out.deinit();

    try t.expectError(
        error.MessageTooLarge,
        state.handle(.{ .recv_message = .{ .from = testNodeId(2), .message = .{ .gossip = .{
            .id = MessageId.fromContent(content),
            .content = content,
            .scope = .{ .swarm = Round.zero },
        } } } }, 0, &out),
    );
    try t.expectEqual(@as(usize, 0), state.cache.count());
}
