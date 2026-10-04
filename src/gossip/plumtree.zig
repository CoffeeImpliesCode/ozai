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

/// Nanoseconds in a millisecond and in a second, the two units every `Config`
/// duration in this module is written in. They are named rather than spelled
/// out because a round number written `1_000_000_000` at four call sites is
/// four chances to be `1_000_000`.
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
///
/// **It owns the list, and not the bytes the entries name.** An `Out` here is
/// a value with slices in it, and those slices borrow: a payload the state
/// forwarded, or one it is holding in its cache for a peer that may graft
/// later, or a `PeerData` a message carried. `push` copies the `Out` value and
/// nothing more, so the entry stays valid exactly as long as the borrow is, and
/// not one moment longer. See `State.handle` for which borrow each event kind
/// carries and what invalidates it.
///
/// **Allocator identity is the caller's throughout.** `init` stores the
/// allocator and both `push` and `deinit` use that one, so the allocator a
/// caller passes is the allocator that must free the list. Growing the list
/// reallocates; `clear` keeps the allocation; `deinit` releases it, once.
/// `push` is the only fallible member, and it fails only with
/// `error.OutOfMemory` — the state machine never refuses to record an event for
/// a protocol reason, because the protocol reasons are its own errors and they
/// travel through `handle`.
///
/// Not thread-safe and not reentrant: two calls appending through one
/// `Actions` interleave. `handle` never calls back into the container it was
/// given, so a state machine holding one is not itself a reentrancy hazard.
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

    /// The id these 32 bytes are, for a caller that decoded them rather than
    /// hashing a payload. No validation happens here and none is possible: any
    /// 32 bytes are a well-formed id, and whether they name a real message is
    /// answered by `Gossip.validate` on the payload that arrives with it.
    pub fn fromBytes(bytes: [id_length]u8) MessageId {
        return .{ .bytes = bytes };
    }

    /// A copy of the digest, for a caller storing it or writing it out. By
    /// value: the digest is 32 bytes and a borrow of a temporary would outlive
    /// the call.
    pub fn toBytes(self: MessageId) [id_length]u8 {
        return self.bytes;
    }

    /// Whether two ids are the same message. Total over the whole digest, so
    /// this is `==` on the struct spelled out; it is here because a caller
    /// reaching for the id through a union arm cannot use `==` without naming
    /// the payload beside it.
    pub fn eql(a: MessageId, b: MessageId) bool {
        return std.mem.eql(u8, &a.bytes, &b.bytes);
    }

    /// Digest order, ascending, which is what every id-sorted structure in this
    /// module orders by. Arbitrary but total and stable, so two nodes that
    /// disagree about nothing still agree about it.
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
fn PeerSet(comptime capacity: usize) type {
    return struct {
        const Self = @This();

        items: [capacity]NodeId = undefined,
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

        /// Forget every peer. The slots past `len` keep whatever they held and
        /// are never read again; `len` is what every reader consults.
        pub fn clear(self: *Self) void {
            self.len = 0;
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
            if (self.len == capacity) return error.PeerSetFull;
            @memmove(
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
            @memmove(
                self.items[index .. self.len - 1],
                self.items[index + 1 .. self.len],
            );
        }
    };
}

/// Upstream `TimeBoundCache<MessageId, ()>`: ids with an expiry, checked
/// against `now` only when a sweep runs. A re-insert overwrites in place,
/// which is upstream's "the entry was re-added with a later time" case.
fn IdCache(comptime capacity: usize) type {
    return struct {
        const Self = @This();

        const Entry = struct { id: MessageId, expires_at: Nanos };

        entries: [capacity]Entry = undefined,
        len: usize = 0,

        pub fn count(self: *const Self) usize {
            return self.len;
        }

        /// Forget every id, cached or not. Expiry is a sweep, not a
        /// destructor: dropping the topic drops the table outright rather than
        /// waiting for entries to age out.
        pub fn clear(self: *Self) void {
            self.len = 0;
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
            if (self.len < capacity) {
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
fn MessageCache(comptime capacity: usize) type {
    return struct {
        const Self = @This();

        const Stored = struct {
            id: MessageId,
            expires_at: Nanos,
            scope: DeliveryScope,
            len: u16,
            bytes: [max_content]u8,
        };

        entries: [capacity]Stored = undefined,
        len: usize = 0,

        pub fn count(self: *const Self) usize {
            return self.len;
        }

        /// Forget every payload. The bytes past `len` in each slot stay as they
        /// were and are never read, so this drops the messages without touching
        /// a kilobyte per slot.
        pub fn clear(self: *Self) void {
            self.len = 0;
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

            const at: usize = slot: {
                for (self.entries[0..self.len], 0..) |*entry, index| {
                    if (!entry.id.eql(gossip.id)) continue;
                    break :slot index;
                }
                break :slot self.evictSlot();
            };
            const entry = &self.entries[at];
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
            if (self.len < capacity) {
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
///
/// `pub` because `takeMissing` drains into a `*[max_claims]Claim` the caller
/// owns: a caller in another file has to name that type to declare the buffer,
/// and the claim list has to outlive the drain.
pub const Claim = struct { peer: NodeId, round: Round };

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
    /// This node's identity, fixed by `init`. It is the one peer the tree never
    /// forwards to: `eagerPush` skips any peer equal to it, and `lazyPush`
    /// queues against it, so writing it after `init` changes which peers a
    /// broadcast reaches and which queued `IHave`s are suppressed. Zig fields
    /// are not private — this one is fixed by convention and by `init`, not by
    /// the language.
    me: NodeId,
    /// Retention, timeout and round settings, fixed by `init` and not
    /// re-validated afterwards. It is read per event — every cache write,
    /// every timer arming and every tree optimisation — so writing it after
    /// `init` changes the behaviour of entries that were written under the
    /// old values; nothing rewrites them.
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

    /// Whether the entry sweep has been queued. The sweep is scheduled once,
    /// on entry, exactly as upstream does it in `handle`. Named `started`
    /// rather than `init` because the constructor is `init`.
    ///
    /// It is set only after the append that publishes that sweep, so a refusal
    /// leaves the state wanting one: the next event queues it. It is a claim
    /// about a timer the caller holds, and `handle` never makes it true about a
    /// timer nobody received.
    started: bool = false,

    /// Whether `leave` has run. A state that has left holds no tree and answers
    /// nothing, and this is the latch that says so rather than the emptiness of
    /// the fields themselves. Both doors into the tree read it — `handle` and
    /// `broadcast` — so a caller holding this value cannot reach past it.
    left: bool = false,

    /// How many hops and payloads this tree has seen. Counters about what the
    /// node did while it was on the topic, not protocol state: they survive
    /// `leave`, so a caller can report what happened before it left.
    ///
    /// `payload_messages_received` counts every received `Gossip` *before* the
    /// arm is chosen, so a spoofed frame is counted as received and then
    /// discarded. That is a receive counter and not a delivery counter, and the
    /// test that a spoofed message is not penalised asserts on everything
    /// except it.
    stats: Stats = .{},

    /// A tree with no edges, no queue and no cache, for `me` under `config`.
    ///
    /// Infallible and allocation-free: `Config` is six durations and one round
    /// threshold rather than something to validate, and every bound in this
    /// module is a compile-time constant, so there is nothing here that can be
    /// refused. Nothing is scheduled until the first `handle`.
    ///
    /// Copyable: `State` holds no slice of its own storage, so a snapshot the
    /// caller restores after a failed `handle` is a plain copy. See `handle`.
    pub fn init(me: NodeId, config: Config) State {
        return .{ .me = me, .config = config };
    }

    /// The eager edges, in sorted order: the peers a new payload is pushed to.
    ///
    /// Pointer receiver and a borrowed slice, so the result lives as long as
    /// this state and no longer; the next `handle` can remove an edge, and
    /// `leave` empties the set. Read it, do not keep it.
    pub fn eagerPeers(self: *const State) []const NodeId {
        return self.eager_push_peers.slice();
    }

    /// The lazy edges, in sorted order: the peers an id is announced to, after
    /// the dispatch timer. Same borrow rule as `eagerPeers`, and the two sets
    /// are disjoint by construction: a peer is in exactly one of them.
    pub fn lazyPeers(self: *const State) []const NodeId {
        return self.lazy_push_peers.slice();
    }

    /// Forget the topic: drop every peer, queue, claim and cache entry, and
    /// leave the state ready to answer nothing.
    ///
    /// `hyparview.TopicState` calls this when the application sends
    /// `Command.quit`, and the promise it is keeping is the one on that
    /// command — a node that has left does not keep a broadcast tree, a lazy
    /// queue or a payload cache that a later event could still reach. Dropping
    /// them here rather than clearing them lazily is what makes "left" a fact
    /// about the state and not about the caller's bookkeeping.
    ///
    /// **Idempotent, and it produces no output.** The disconnects a leaving
    /// node owes its neighbours are membership's to send, and this half has
    /// none: by the time a `Quit` reaches this layer, membership has already
    /// dropped the neighbours whose trees these were.
    ///
    /// `stats` survives, because a counter is a report about what the node did
    /// while it was on the topic rather than state it was carrying. `me` and
    /// `config` survive because they identify the state and not its contents.
    /// `started` survives as the first-event latch. The caller owns scheduled
    /// timers and may discard them; late events cannot restart cache eviction.
    pub fn leave(self: *State) void {
        self.eager_push_peers.clear();
        self.lazy_push_peers.clear();
        self.lazy_push_queue_len = 0;
        self.dispatch_timer_scheduled = false;
        self.missing_messages_len = 0;
        self.received_messages.clear();
        self.cache.clear();
        self.left = true;
    }

    /// Handle one event. `now` is the caller's clock; nothing here reads one.
    ///
    /// **Not transactional, and the residue is named rather than hidden.** An
    /// event advances `self` and appends to `out` as it goes, so an
    /// `error.OutOfMemory` out of an append leaves the state advanced as far as
    /// that event got and leaves the appends that succeeded in `out`. The state
    /// is still a valid `State` — every mutation here is checked, so nothing is
    /// left half-written — but it is not the state the caller handed in.
    ///
    /// Three ways out, and only the first is a promise:
    ///
    /// - **Snapshot.** `State` is a plain value holding no slice of its own
    ///   storage, so a caller that needs all-or-nothing copies it before the
    ///   call and restores that copy on error. The copy is `@sizeOf(State)`
    ///   bytes and no allocation, and it is not small: the payload cache, the
    ///   lazy-push queue, the claim table and the id table are all inline, so
    ///   what dominates it is `max_content * cache_slots` and
    ///   `max_queue_peers * max_queued_ihaves`. A caller sizing a stack or
    ///   arena slot measures `@sizeOf(State)` on its own target rather than
    ///   assuming. It is per-event work — a copy taken and dropped around every
    ///   message is a `@sizeOf(State)` memcpy on the hot path — so a caller
    ///   that keeps one keeps it per topic, outside the event loop. Three
    ///   things bound what the restore recovers, and all three are the caller's
    ///   to arrange:
    ///
    ///   1. **It recovers `self` and nothing else.** Every protocol function in
    ///      this module writes no memory outside `self` and `out` — the caches,
    ///      the queues and the claim table are all inline in `State` — so the
    ///      borrowed payload bytes a failed call handed to `out` *are* restored
    ///      with the value. What is not restored is anything the caller did with
    ///      them: a caller that acts on `out` as it drains it has already sent
    ///      what it read, and a restored state does not unsend it.
    ///   2. **It recovers `out` only if `out` was empty when the call started.**
    ///      That is the precondition, and `out.clear()` is then exactly the undo
    ///      because there is nothing else in the list. `Actions` has no
    ///      truncate-to-a-saved-length, so a caller that accumulates output
    ///      across events cannot use this recovery at all and must abandon.
    ///   3. **It does not restore the caller's timers.** This state owns no
    ///      timer queue — the caller's `out` names the timers it must run — so
    ///      a `.timer_expired` event is delivered *because* the caller took
    ///      that timer out of its queue to fire it. A restored copy therefore
    ///      carries whatever latch that timer had set, with no timer behind it:
    ///      `dispatch_timer_scheduled`, or an entry's
    ///      `graft_timer_scheduled`. A caller that restores a copy taken
    ///      before a timer event must re-queue the timer it consumed, or leave
    ///      that latch clear.
    ///
    /// - **Abandon.** A caller that cannot snapshot — because it accumulates
    ///   output, or because it has no copy to keep — treats a failed `handle` as
    ///   the end of this topic's run: drop the state, tell the transport to
    ///   close whatever it has open, and build a new `State` if the node comes
    ///   back. `node/node_gossip.zig`'s `feedGossip` makes the same choice: it
    ///   keeps no copy, and a refused event unwinds the node — the `errdefer` in
    ///   `node/node_runtime.zig`'s `run` is what winds it down.
    /// - **Replay**, which is *not* promised. Re-sending the same event does not
    ///   undo the neighbour already promoted, the payload already cached or the
    ///   `IHave` already queued, and making it would put a second opinion about
    ///   the protocol on the path of every event.
    ///
    /// Whatever is already in `out` is real work the state did, and whether to
    /// act on it, clear it or snapshot over it is the caller's choice.
    ///
    /// **What the entries in `out` borrow.** `Actions` owns the list and not the
    /// bytes its entries name: a `send_message` payload and an `emit_event`
    /// payload borrow either the caller's own buffer or `self.cache`, and the
    /// next `handle` on this state sweeps that cache and may evict the very
    /// entry being forwarded. A caller that keeps an output list across a
    /// `handle` copies the bytes.
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
    /// than once per message, because the flag is latched. The entry sweep is
    /// the same rule at the front of the function: it is queued before
    /// `started` is set, so a refusal costs one sweep and not all of them. A
    /// reader who finds the sequence untidy should not sort it.
    pub fn handle(
        self: *State,
        event: InEvent,
        now: Nanos,
        out: *Actions(OutEvent),
    ) (Error || Allocator.Error)!void {
        // A state that has left answers nothing. `Command.quit` says the node
        // is done with this topic, and an event that arrives after it is a
        // driver that has not stopped feeding; there is nothing to do and no
        // error to hand back for doing nothing.
        if (self.left) return;
        if (!self.started) {
            // Queued before the latch is set, for the reason `onIHave` gives.
            // A refused append is the one event that would leave this tree
            // without its entry sweep for ever: nothing else queues an
            // `evict_cache`, and the latch set first would say one was
            // outstanding while the caller holds none.
            try self.onEvictCacheTimer(now, out);
            self.started = true;
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
    ///
    /// **Inert on a state that has left**, exactly as `handle` is: it returns
    /// before it touches a cache, a queue or the dispatch latch, so the direct
    /// route into a tree `leave` emptied cannot refill it. A caller that
    /// broadcasts after a `Command.quit` gets silence, not a fresh tree —
    /// and silence means it appends nothing: the events the caller is already
    /// holding stay the caller's, because neither `leave` nor this call
    /// reaches into the list to take them back.
    pub fn broadcast(
        self: *State,
        content: []const u8,
        scope: Scope,
        now: Nanos,
        out: *Actions(OutEvent),
    ) (Error || Allocator.Error)!void {
        if (self.left) return;
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

        switch (message.scope) {
            .swarm => |arrived| {
                const next = arrived.next();
                const forwarded: Gossip = .{
                    .id = message.id,
                    .content = message.content,
                    .scope = .{ .swarm = next },
                };
                self.received_messages.put(message.id, now + self.config.message_id_retention);
                try self.cache.put(forwarded, now + self.config.message_cache_retention);
                try self.eagerPush(forwarded, sender, out);
                try self.lazyPush(forwarded, sender, out);
                self.forgetGraftTimer(message.id);
                var claims: [max_claims]Claim = undefined;
                if (self.takeMissing(message.id, &claims)) |drained| {
                    try self.optimizeTree(sender, next, drained, out);
                }
                self.stats.max_last_delivery_hop =
                    @max(self.stats.max_last_delivery_hop, arrived.value);
            },
            .neighbors => {},
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
    /// `pub` only so `plumtree_tests.zig`, a file of its own, can drive it.
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
            const claim: Claim = .{ .peer = sender, .round = ihave.round };
            const entry = try self.pushClaim(ihave.id, claim);
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

    /// Upstream `on_dispatch_timer`. One long queue is cut into several
    /// messages rather than overrunning a frame. The queue is in the order the
    /// ids were queued, which is sorted within one `lazyPush` call — `queueIHave`
    /// appends and `lazy_push_peers` iterates sorted — and in burst order
    /// across calls.
    fn onDispatchTimer(self: *State, out: *Actions(OutEvent)) (Error || Allocator.Error)!void {
        // Released before the flush, not after it, for the reason `onIHave`
        // gives: the caller handed us the timer this call consumes, so a latch
        // still set when an append below is refused is a claim that a timer
        // exists which nothing will ever fire. `lazyPush` arms one only while
        // the latch is clear, so clearing it here is what lets the next event
        // arm one — and the ids still queued go out on that timer.
        self.dispatch_timer_scheduled = false;
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
            @memmove(
                self.lazy_push_queue[0 .. self.lazy_push_queue_len - 1],
                self.lazy_push_queue[1..self.lazy_push_queue_len],
            );
            self.lazy_push_queue_len -= 1;
        }
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
            // Queued before the flag is set, for the reason `onIHave` gives.
            try out.push(.{ .schedule_timer = .{
                .after = self.config.dispatch_timeout,
                .timer = .dispatch_lazy_push,
            } });
            self.dispatch_timer_scheduled = true;
        }
    }

    /// Upstream `add_eager`.
    /// `pub` only so `plumtree_tests.zig`, a file of its own, can drive it.
    pub fn addEager(self: *State, peer: NodeId) Error!void {
        _ = self.lazy_push_peers.remove(peer);
        try self.eager_push_peers.insert(peer);
    }

    /// Upstream `add_lazy`.
    /// `pub` only so `plumtree_tests.zig`, a file of its own, can drive it.
    pub fn addLazy(self: *State, peer: NodeId) Error!void {
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

    /// The entry the claim landed in, which is also the entry a graft timer is
    /// owed against. It is handed back rather than looked up again because the
    /// caller has just created or found it, so the write that follows cannot
    /// miss; that is what lets the graft timer need no error of its own.
    /// `pub` only so `plumtree_tests.zig`, a file of its own, can drive it.
    pub fn pushClaim(self: *State, id: MessageId, claim: Claim) Error!*MissingEntry {
        if (self.findMissing(id)) |entry| {
            if (entry.count == max_claims) return error.MissingTableFull;
            entry.peers[entry.count] = claim.peer;
            entry.rounds[entry.count] = claim.round;
            entry.count += 1;
            return entry;
        }
        if (self.missing_messages_len == max_missing) return error.MissingTableFull;
        const entry = &self.missing_messages[self.missing_messages_len];
        entry.id = id;
        entry.count = 1;
        entry.graft_timer_scheduled = false;
        entry.peers[0] = claim.peer;
        entry.rounds[0] = claim.round;
        self.missing_messages_len += 1;
        return entry;
    }

    /// Drain one id's claims into the caller's buffer and return the filled
    /// part of it. The entry is gone after the call, so the list cannot borrow
    /// it, and a buffer in this frame would be dead before `optimizeTree` is
    /// done reading it.
    /// `pub` only so `plumtree_tests.zig`, a file of its own, can drive it.
    pub fn takeMissing(self: *State, id: MessageId, storage: *[max_claims]Claim) ?[]const Claim {
        const index = self.missingIndex(id) orelse return null;
        const entry = &self.missing_messages[index];
        const count = entry.count;
        for (entry.peers[0..count], entry.rounds[0..count], 0..) |peer, round, at| {
            storage[at] = .{ .peer = peer, .round = round };
        }
        self.removeMissing(index);
        return storage[0..count];
    }

    /// Pop the front of one id's claim queue, which is the peer we graft next.
    fn takeOldestClaim(self: *State, id: MessageId) ?Claim {
        const index = self.missingIndex(id) orelse return null;
        const entry = &self.missing_messages[index];
        const claim: Claim = .{ .peer = entry.peers[0], .round = entry.rounds[0] };
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
        @memmove(
            self.missing_messages[index .. self.missing_messages_len - 1],
            self.missing_messages[index + 1 .. self.missing_messages_len],
        );
        self.missing_messages_len -= 1;
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
