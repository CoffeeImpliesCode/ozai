//! HyParView: swarm membership, and the deterministic simulator that decides
//! whether this module agrees with the reference.
//!
//! Ported from `n0-computer/iroh-gossip`, `src/proto/hyparview.rs`, `proto.rs`,
//! `proto/topic.rs`, `proto/state.rs` and `proto/sim.rs`, at commit
//! `2885dd9f1120e46aca5acbcd7f212e4c64e278b9`, fetched 2026-09-30.
//!
//! # The deviation that decides whether two implementations agree
//!
//! Paper rule 7 says a node that receives a `ForwardJoin` at the end of its
//! time-to-live "will add the new node to its active view". Upstream does not.
//! It sends a `Neighbor` and does **not** insert, and the peer enters the
//! active view only when it answers with a `Neighbor` of its own — see
//! `onForwardJoin`, where the comment upstream carries is quoted in full.
//!
//! The two rules differ in one observable way and it is a large one. Eager
//! insertion puts a peer in the active view on the strength of a message that
//! peer may be unable to answer, so the view fills with nodes that are
//! unreachable, the `active_view_capacity` is spent on them, and the honest
//! ones are dropped to make room. The two halves also stop agreeing, and not
//! briefly: the inserting node believes it has a neighbour, and nothing in
//! either node ever asks the other. Under the deviation the two halves agree
//! at every instant, because the insertion *is* the reply.
//!
//! That is what makes this the one behaviour in this module that a second
//! implementation gets wrong while still passing every byte-level test, and
//! it is why `sim` exists at all: an implementation that inserts eagerly is
//! indistinguishable from this one until two of its nodes are run against
//! each other. `Config.neighbor_request_timeout` exists for the same reason —
//! a `Neighbor` that is never answered has to time out, and that timer is
//! the only thing standing between a lost reply and a permanently spent slot.
//!
//! The other half of the same invariant is in `onNeighbor`. A `Neighbor` that
//! answers one of ours is a *reply*, and a reply is what makes the insertion
//! happen; one that answers nothing is a fresh request and is answered in
//! turn. `pending_neighbor_requests` is the set that tells the two apart, and
//! removing the peer from it — not adding the peer to the view — is what
//! marks the transition.
//!
//! # What is in this file and why
//!
//! Three layers, in dependency order:
//!
//! 1. `State`, the membership state machine. Two views, a pending-request set,
//!    a table of peers' contact data, and a caller-seeded generator.
//! 2. `TopicState`, the composition: HyParView for membership and
//!    `plumtree.State` for broadcast, with the event ordering that couples
//!    them. This is upstream's `proto/topic.rs`.
//! 3. `sim`, a discrete-event in-process network that runs both. This is
//!    upstream's `proto/sim.rs`, and it is the first test of the module rather
//!    than an afterthought: a membership layer that only ever exchanges bytes
//!    has not been tested at all.
//!
//! `TopicId` lives here rather than in `plumtree.zig` because it is the outer
//! of the two concepts: it names a swarm, and a swarm is a membership view
//! plus a broadcast tree.
//!
//! # `TopicId` is 32 opaque bytes, and there is no privacy story
//!
//! Upstream `TopicId([u8; 32])` is supplied by the application. Nothing derives
//! it, nothing checks it, nothing scopes it, and nothing encrypts the traffic
//! under it. A peer learns a topic id by being told one, and can then read
//! every message on it.
//!
//! ozai keeps that and says it plainly rather than inventing a scheme here.
//! A topic scheme invented in this module would be one nobody else
//! implements, so it would protect nothing while looking like protection, and a
//! reader would have to work out whether it was on. Privacy belongs above:
//! `iroh-relay`'s encrypted datagrams already cover a gossip message in
//! transit, and application-level confidentiality over a topic is a
//! key-agreement and a membership question, not a broadcast question. A
//! future milestone that answers it should add it here with a vector for the
//! scheme, not a plausible-looking default now.
//!
//! # Purity
//!
//! No clock, no environment, no global, no global RNG, no allocator, no I/O.
//! Time is the `now` argument of `handle`; the generator is a value the caller
//! seeds and the state carries; the allocator belongs to the `Actions`
//! container the caller hands in. The simulator allocates, because a test
//! harness is allowed to, and it takes its allocator as an argument like
//! everything else here.

const std = @import("std");
const key = @import("../base/key.zig");
const plumtree = @import("plumtree.zig");

const NodeId = key.NodeId;
const Allocator = std.mem.Allocator;

/// Simulated time, in nanoseconds, handed in by the caller. See
/// `plumtree.Nanos`.
pub const Nanos = plumtree.Nanos;

pub const nanos_per_milli = plumtree.nanos_per_milli;
pub const nanos_per_second = plumtree.nanos_per_second;

/// The output container. The same shape as the broadcast layer's, over this
/// module's events, because both are "a list the caller owns and the state
/// machine appends to".
pub const Actions = plumtree.Actions;

// ---------------------------------------------------------------------------
// Topic identity
// ---------------------------------------------------------------------------

/// 32 bytes an application chose. Upstream `TopicId([u8; 32])`, `proto/state.rs:21`.
pub const topic_id_length = 32;

/// The swarm a set of messages travels over.
///
/// There is no derivation, no scope, no public/private distinction and no
/// encryption, here or upstream. See the module doc: privacy goes above this,
/// and a scheme invented here would protect nothing.
pub const TopicId = struct {
    bytes: [topic_id_length]u8,

    pub fn fromBytes(bytes: [topic_id_length]u8) TopicId {
        return .{ .bytes = bytes };
    }

    pub fn toBytes(self: TopicId) [topic_id_length]u8 {
        return self.bytes;
    }

    pub fn eql(a: TopicId, b: TopicId) bool {
        return std.mem.eql(u8, &a.bytes, &b.bytes);
    }

    /// Lexicographic, so two implementations agree on which of two topics is
    /// "first" without agreeing on anything else.
    pub fn order(a: TopicId, b: TopicId) std.math.Order {
        return std.mem.order(u8, &a.bytes, &b.bytes);
    }

    /// The first five bytes as hex, which is upstream `TopicId::fmt_short` and
    /// the only reason that function exists: a log line about a topic should
    /// not be 64 characters long.
    pub fn shortHex(self: TopicId) [10]u8 {
        const prefix = std.fmt.bytesToHex(self.bytes[0..5], .lower);
        return prefix[0..10].*;
    }
};

// ---------------------------------------------------------------------------
// Peer contact data
// ---------------------------------------------------------------------------

/// The largest `PeerData` a node will hold or carry. Upstream's is a
/// `Bytes` with no bound; a bound is what "no allocator" costs, and a node
/// address with a couple of paths on it fits.
pub const peer_data_max = 256;

/// How many peers a node remembers contact data for.
pub const max_known_peers = 32;

/// Opaque contact bytes, as upstream `PeerData(Bytes)`.
///
/// Stored inline in the state, bounded, and copied out on the way in. What
/// travels in a *message* is a `[]const u8` slice of one of these, which is
/// the same borrow-by-handle upstream gets from cloning a `Bytes`: valid until
/// the next `handle` on the same state.
pub const PeerData = struct {
    /// Zeroed, and only `len` bytes of it mean anything.
    bytes: [peer_data_max]u8 = [_]u8{0} ** peer_data_max,
    /// `u16` rather than `u8` because `peer_data_max` is 256 and a length of
    /// 255 is a legal value, not the largest one.
    len: u16 = 0,

    pub fn fromBytes(bytes: []const u8) Error!PeerData {
        // Narrow once, where the bound is proved: the cast admits only a
        // length `len` is able to spell, and the comparison is the array's own
        // ceiling. One error answers both, because a length this record
        // cannot spell is a length it cannot own.
        const len: u16 = std.math.cast(u16, bytes.len) orelse
            return error.PeerDataTooLong;
        if (len > peer_data_max) return error.PeerDataTooLong;
        var data: PeerData = .{};
        @memcpy(data.bytes[0..len], bytes);
        data.len = len;
        return data;
    }

    pub fn slice(self: *const PeerData) []const u8 {
        return self.bytes[0..self.len];
    }

    pub fn isEmpty(self: *const PeerData) bool {
        return self.len == 0;
    }

    pub fn eql(a: *const PeerData, b: *const PeerData) bool {
        return std.mem.eql(u8, a.slice(), b.slice());
    }
};

/// A peer and whatever contact data was offered for it. Upstream `PeerInfo`.
pub const PeerInfo = struct {
    id: NodeId,
    /// Borrowed from the state's `peer_data` table or from a message.
    data: ?[]const u8,
};

/// The largest `Shuffle` or `ShuffleReply` node list. The default config
/// already fills it: three active, four passive, and ourselves.
pub const max_shuffle_nodes = 8;

/// A bounded list of `PeerInfo`.
pub const PeerInfos = struct {
    count: u8,
    items: [max_shuffle_nodes]PeerInfo,

    pub fn init(items: []const PeerInfo) Error!PeerInfos {
        if (items.len > max_shuffle_nodes) return error.ShuffleNodeListTooLong;
        var list: PeerInfos = undefined;
        list.count = @intCast(items.len);
        @memcpy(list.items[0..items.len], items);
        return list;
    }

    pub fn slice(self: *const PeerInfos) []const PeerInfo {
        return self.items[0..self.count];
    }
};

/// A table of peers' contact data. Upstream `HashMap<PI, PeerData>`.
const PeerDataMap = struct {
    const Entry = struct { peer: NodeId, data: PeerData };

    entries: [max_known_peers]Entry = undefined,
    len: usize = 0,

    fn count(self: *const PeerDataMap) usize {
        return self.len;
    }

    fn get(self: *const PeerDataMap, peer: NodeId) ?*const PeerData {
        for (self.entries[0..self.len]) |*entry| {
            if (sameNode(entry.peer, peer)) return &entry.data;
        }
        return null;
    }

    /// Copies before writing, because the slice handed in is often a borrow of
    /// the entry being replaced.
    ///
    /// The bound is proved here, at the copy, because nothing above this line
    /// proves it: the slice is a peer's claim about itself, carried in a
    /// message, and a message is not obliged to be short. Refusing is the only
    /// honest answer, and it is also what leaves every `PeerData` in the table
    /// one `fromBytes` would have built, so `get`'s `slice` is in bounds by
    /// construction rather than by hope.
    fn put(self: *PeerDataMap, peer: NodeId, data: []const u8) Error!void {
        const len: u16 = std.math.cast(u16, data.len) orelse
            return error.PeerDataTooLong;
        if (len > peer_data_max) return error.PeerDataTooLong;
        var copy: PeerData = .{};
        @memcpy(copy.bytes[0..len], data);
        copy.len = len;
        for (self.entries[0..self.len]) |*entry| {
            if (sameNode(entry.peer, peer)) {
                entry.data = copy;
                return;
            }
        }
        if (self.len == max_known_peers) return error.PeerDataFull;
        self.entries[self.len] = .{ .peer = peer, .data = copy };
        self.len += 1;
    }
};

// ---------------------------------------------------------------------------
// Membership messages
// ---------------------------------------------------------------------------

/// The largest active view. A node keeps five by default; thirty-two is the
/// bound at which a test can drive a swarm wider than the default without
/// making every state machine in a test enormous.
pub const max_active = 32;

/// The largest passive view. Thirty by default; sixty-four is the bound.
pub const max_passive = 64;

/// The largest bootstrap list a `Command.join` may carry.
pub const max_bootstrap = 8;

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
/// Upstream carries a second field, `_respond`, marked obsolete and kept for
/// wire compatibility. It is not carried here: this module has no wire codec,
/// and a field nothing reads is a field a reader has to work out the meaning
/// of. When the codec lands, the byte goes in.
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

/// Every way membership refuses to do what it was asked.
pub const Error = error{
    /// The active view is at `max_active` and the request may not be denied.
    ActiveViewFull,
    /// The passive view is at `max_passive` and nothing may be dropped to make
    /// room for the new peer.
    PassiveViewFull,
    /// The pending-`Neighbor` table is full.
    NeighborRequestTableFull,
    /// The contact-data table is at `max_known_peers`.
    PeerDataFull,
    /// Contact data longer than `peer_data_max`.
    PeerDataTooLong,
    /// A shuffle node list longer than `max_shuffle_nodes`.
    ShuffleNodeListTooLong,
    /// A bootstrap list longer than `max_bootstrap`.
    BootstrapListTooLong,
};

/// The random choices membership makes, as a value the caller seeds.
///
/// Upstream threads a `rand::Rng` through `State::new` and uses a
/// `rand::thread_rng()` by default. A process-global generator is forbidden
/// here — `docs/ARCHITECTURE.md` invariant 2 is about sorted collections and
/// invariant 14 is about purity, and a global generator breaks every test
/// that has to run twice — so the generator is a field, and
/// `Rng.init(seed)` is how a caller gets a reproducible one.
pub const Rng = struct {
    prng: std.Random.Xoshiro256,

    pub fn init(seed: u64) Rng {
        return .{ .prng = std.Random.Xoshiro256.init(seed) };
    }

    pub fn next(self: *Rng) u64 {
        return self.prng.next();
    }

    /// Uniform in `[0, n)`, and `0` for `n == 0` so a caller can write
    /// `pick(x) orelse fallback` without a separate empty check.
    pub fn below(self: *Rng, n: usize) usize {
        if (n == 0) return 0;
        return self.prng.random().intRangeLessThan(usize, 0, n);
    }

    /// Uniform in `[lo, hi)`.
    pub fn range(self: *Rng, lo: u64, hi: u64) u64 {
        if (hi <= lo) return lo;
        return self.prng.random().intRangeLessThan(u64, lo, hi);
    }

    /// A child generator, drawn from this one. This is what
    /// `Network::insert_with_config` gives each simulated node upstream
    /// (`R::from_rng(&mut self.rng)`), and the reason two nodes in the same
    /// simulation do not walk in lockstep.
    pub fn child(self: *Rng) Rng {
        return .init(self.next());
    }

    /// Fisher-Yates over node ids. Upstream `IndexSet::shuffled` calls
    /// `slice::shuffle`, which is the same algorithm and therefore the same
    /// permutation for the same input order.
    pub fn shuffle(self: *Rng, items: []NodeId) void {
        var index = items.len;
        while (index > 1) {
            index -= 1;
            const other = self.below(index + 1);
            std.mem.swap(NodeId, &items[index], &items[other]);
        }
    }
};

/// Upstream's `IndexSet`: a set whose iteration order is *insertion* order.
///
/// That order is observable: `onJoin` sends a `ForwardJoin` to
/// `active_view.iter_without(peer)` in it, so a node with the same set of
/// neighbours in a different insertion order sends the same bytes in a
/// different order. It is kept because it is upstream's, and the sets here are
/// small enough that the difference is a copy rather than a tree.
pub fn IndexSet(comptime capacity: usize) type {
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

        pub fn contains(self: *const Self, peer: NodeId) bool {
            for (self.slice()) |item| {
                if (sameNode(item, peer)) return true;
            }
            return false;
        }

        /// `true` when the peer was not already a member, which is what
        /// upstream's `IndexSet::insert` returns and what `sendNeighbor` uses
        /// to send exactly one `Neighbor` per request.
        pub fn insert(self: *Self, peer: NodeId) Error!bool {
            if (self.contains(peer)) return false;
            if (self.len == capacity) return error.ActiveViewFull;
            self.items[self.len] = peer;
            self.len += 1;
            return true;
        }

        pub fn remove(self: *Self, peer: NodeId) bool {
            const index = self.indexOf(peer) orelse return false;
            _ = self.removeAt(index);
            return true;
        }

        pub fn indexOf(self: *const Self, peer: NodeId) ?usize {
            for (self.slice(), 0..) |item, index| {
                if (sameNode(item, peer)) return index;
            }
            return null;
        }

        pub fn removeAt(self: *Self, index: usize) NodeId {
            const removed = self.items[index];
            @memmove(
                self.items[index .. self.len - 1],
                self.items[index + 1 .. self.len],
            );
            self.len -= 1;
            return removed;
        }

        /// Upstream `pick_random`.
        pub fn pickRandom(self: *const Self, rng: *Rng) ?NodeId {
            if (self.len == 0) return null;
            return self.items[rng.below(self.len)];
        }

        /// Upstream `pick_random_index`.
        pub fn pickRandomIndex(self: *const Self, rng: *Rng) ?usize {
            if (self.len == 0) return null;
            return rng.below(self.len);
        }

        /// Upstream `pick_random_without`: uniform over the members that are
        /// not in `without`.
        pub fn pickRandomWithout(self: *const Self, without: []const NodeId, rng: *Rng) ?NodeId {
            var candidates: [capacity]NodeId = undefined;
            var found: usize = 0;
            for (self.slice()) |item| {
                if (containsNode(without, item)) continue;
                candidates[found] = item;
                found += 1;
            }
            if (found == 0) return null;
            return candidates[rng.below(found)];
        }

        /// Upstream `shuffled_without_and_capped`: a random `len` members,
        /// excluding `without`.
        pub fn shuffledWithoutAndCapped(
            self: *const Self,
            without: []const NodeId,
            len: usize,
            rng: *Rng,
            out: []NodeId,
        ) usize {
            var scratch: [capacity]NodeId = undefined;
            var found: usize = 0;
            for (self.slice()) |item| {
                if (containsNode(without, item)) continue;
                scratch[found] = item;
                found += 1;
            }
            rng.shuffle(scratch[0..found]);
            const take = @min(len, @min(found, out.len));
            @memcpy(out[0..take], scratch[0..take]);
            return take;
        }
    };
}

/// A short list of peers, as a `Command.join` carries it.
pub const Peers = struct {
    count: u8,
    items: [max_bootstrap]NodeId,

    pub fn init(items: []const NodeId) Error!Peers {
        // The same two halves as `PeerData.fromBytes`, for the same reason:
        // `count` is a `u8` and the list is short, and neither fact is visible
        // where the value is used.
        const count: u8 = std.math.cast(u8, items.len) orelse
            return error.BootstrapListTooLong;
        if (count > max_bootstrap) return error.BootstrapListTooLong;
        var list: Peers = undefined;
        list.count = count;
        @memcpy(list.items[0..count], items);
        return list;
    }

    pub fn slice(self: *const Peers) []const NodeId {
        return self.items[0..self.count];
    }
};

/// Membership configuration. Upstream `hyparview::Config`, whose defaults are
/// the paper's (p9) where it has any and a labelled guess where it does not.
pub const Config = struct {
    /// Peers we keep an active connection to. Paper p9: 5.
    active_view_capacity: usize = 5,
    /// Peers we remember but are not connected to. Paper p9: 30.
    passive_view_capacity: usize = 30,
    /// How far a `ForwardJoin` is propagated. Paper p9: 6.
    active_random_walk_length: Ttl = .{ .value = 6 },
    /// Where in that walk a peer enters the *passive* view. Paper p9: 3.
    passive_random_walk_length: Ttl = .{ .value = 3 },
    /// How far a `Shuffle` is propagated. Paper p9: 6.
    shuffle_random_walk_length: Ttl = .{ .value = 6 },
    /// Active peers carried in a `Shuffle`. Paper p9: 3.
    shuffle_active_view_count: usize = 3,
    /// Passive peers carried in a `Shuffle`. Paper p9: 4.
    shuffle_passive_view_count: usize = 4,
    /// Upstream's own comment is "Wild guess". 60 s.
    shuffle_interval: Nanos = 60 * nanos_per_second,
    /// Also a wild guess upstream, and it only exists because of the
    /// `Neighbor` deviation: 500 ms.
    neighbor_request_timeout: Nanos = 500 * nanos_per_milli,

    /// A config the fixed-capacity sets cannot hold is rejected here rather
    /// than discovered as a `PeerSetFull` twenty messages into a run.
    pub fn validate(self: Config) Error!void {
        if (self.active_view_capacity > max_active) return error.ActiveViewFull;
        if (self.passive_view_capacity > max_passive) return error.PassiveViewFull;
        if (self.shuffle_active_view_count == 0) return error.ShuffleNodeListTooLong;
        const wanted = self.shuffle_active_view_count + self.shuffle_passive_view_count + 1;
        if (wanted > max_shuffle_nodes) {
            return error.ShuffleNodeListTooLong;
        }
        return;
    }
};

/// Counters, upstream `hyparview::Stats`.
pub const SwarmStats = struct {
    total_connections: u64 = 0,
};

/// Why a peer left the active view. Upstream `RemovalReason`, with its
/// `DisconnectReceived { is_alive }` payload kept as the union's `bool`.
const RemovalReason = union(enum) {
    /// The connection closed without a `Disconnect`. The peer is dropped.
    connection_closed: void,
    /// A `Disconnect` arrived. The peer is kept if the sender is still alive.
    disconnect_received: bool,
    /// Dropped at random to make room. The peer is kept.
    random: void,
};

/// The membership state of one node. Upstream `hyparview::State`.
///
/// `active_view` is the set of peers this node believes it is connected to,
/// and — because of the `Neighbor` exchange — those peers hold the same
/// belief about it. That is what "the active view is bidirectional" means in
/// code: not a symmetric data structure, but two nodes that reach the same
/// view by each asking the other and waiting.
pub const State = struct {
    me: NodeId,
    me_data: ?PeerData,
    /// Peers we are connected to. Insertion-ordered, as upstream's.
    active_view: IndexSet(max_active) = .{},
    /// Peers we know about and are not connected to.
    passive_view: IndexSet(max_passive) = .{},
    config: Config,
    /// Whether the shuffle timer is outstanding. Latched on the first call.
    shuffle_scheduled: bool = false,
    /// The caller's generator, carried as state so the whole module is a
    /// function of `(state, input)`.
    rng: Rng,
    stats: SwarmStats = .{},
    /// `Neighbor` messages we sent that have not been answered. This set *is*
    /// the deviation: a peer in it is one we have asked to be neighbours with
    /// and is not yet one.
    pending_neighbor_requests: IndexSet(max_active) = .{},
    peer_data: PeerDataMap = .{},
    /// Peers that disconnected while saying they were still alive, and so must
    /// survive the connection closing.
    alive_disconnect_peers: IndexSet(max_active) = .{},

    pub fn init(me: NodeId, me_data: ?PeerData, config: Config, rng: Rng) Error!State {
        try config.validate();
        return .{
            .me = me,
            .me_data = me_data,
            .config = config,
            .rng = rng,
        };
    }

    pub fn activeView(self: *const State) []const NodeId {
        return self.active_view.slice();
    }

    pub fn passiveView(self: *const State) []const NodeId {
        return self.passive_view.slice();
    }

    /// Handle one event.
    ///
    /// The shuffle timer is armed on the first call whatever that call was,
    /// which is upstream's `handle`: the tail of the function, after the
    /// dispatch, not a constructor side effect. It matters because a node that
    /// only ever received messages still has to shuffle, and one that armed the
    /// timer in its constructor would arm it at a different moment in the run.
    pub fn handle(
        self: *State,
        event: SwarmInEvent,
        out: *Actions(SwarmOutEvent),
    ) (Error || Allocator.Error)!void {
        switch (event) {
            .recv_message => |recv| try self.handleMessage(recv.from, recv.message, out),
            .timer_expired => |timer| switch (timer) {
                .do_shuffle => try self.handleShuffleTimer(out),
                .pending_neighbor_request => |peer| try self.handlePendingNeighborTimer(peer, out),
            },
            .peer_disconnected => |peer| try self.handleConnectionClosed(peer, out),
            .request_join => |peer| try self.handleJoin(peer, out),
            .update_peer_data => |data| self.me_data = data,
            .quit => try self.handleQuit(out),
        }
        if (self.shuffle_scheduled) return;
        self.shuffle_scheduled = true;
        try out.push(.{ .schedule_timer = .{
            .after = self.config.shuffle_interval,
            .timer = .do_shuffle,
        } });
    }

    /// Upstream `handle_message`.
    fn handleMessage(
        self: *State,
        from: NodeId,
        message: SwarmMessage,
        out: *Actions(SwarmOutEvent),
    ) (Error || Allocator.Error)!void {
        const is_disconnect = message == .disconnect;
        if (!is_disconnect and !self.active_view.contains(from)) {
            self.stats.total_connections += 1;
        }
        switch (message) {
            .join => |data| try self.onJoin(from, data, out),
            .forward_join => |details| try self.onForwardJoin(from, details, out),
            .shuffle => |details| try self.onShuffle(from, details, out),
            .shuffle_reply => |details| try self.onShuffleReply(details, out),
            .neighbor => |details| try self.onNeighbor(from, details, out),
            .disconnect => |details| try self.onDisconnect(from, details, out),
        }
        // "Disconnect from passive nodes right after receiving a message."
        // Upstream's own comment is that it is not sure this is correct; it is
        // kept because the simulator is compared against upstream, and a
        // difference here changes which connections exist after a run.
        if (!is_disconnect and !self.active_view.contains(from)) {
            try out.push(.{ .disconnect_peer = from });
        }
    }

    /// Upstream `handle_join`: ask a known peer to let us in.
    fn handleJoin(
        self: *State,
        peer: NodeId,
        out: *Actions(SwarmOutEvent),
    ) (Error || Allocator.Error)!void {
        try out.push(.{ .send_message = .{
            .to = peer,
            .message = .{ .join = self.myData() },
        } });
    }

    /// Upstream `on_disconnect`.
    fn onDisconnect(
        self: *State,
        peer: NodeId,
        details: Disconnect,
        out: *Actions(SwarmOutEvent),
    ) (Error || Allocator.Error)!void {
        _ = self.pending_neighbor_requests.remove(peer);
        if (self.active_view.contains(peer)) {
            try self.removeActive(peer, .{ .disconnect_received = details.alive }, out);
        } else if (details.alive and self.passive_view.contains(peer)) {
            _ = try self.alive_disconnect_peers.insert(peer);
        }
    }

    /// Upstream `handle_connection_closed`.
    fn handleConnectionClosed(
        self: *State,
        peer: NodeId,
        out: *Actions(SwarmOutEvent),
    ) (Error || Allocator.Error)!void {
        _ = self.pending_neighbor_requests.remove(peer);
        if (self.active_view.contains(peer)) {
            try self.removeActive(peer, .connection_closed, out);
        } else if (!self.alive_disconnect_peers.remove(peer)) {
            _ = self.passive_view.remove(peer);
        }
    }

    /// Upstream `handle_quit`.
    fn handleQuit(self: *State, out: *Actions(SwarmOutEvent)) (Error || Allocator.Error)!void {
        while (self.active_view.count() > 0) {
            const peer = self.active_view.at(0);
            _ = self.active_view.removeAt(0);
            try self.sendDisconnect(peer, false, out);
        }
    }

    /// Upstream `send_disconnect`. A `ShuffleReply` goes out first, with
    /// enough of our view to keep the other node connected: it is about to
    /// lose us, and if it has just joined the swarm it may have nobody else.
    fn sendDisconnect(
        self: *State,
        peer: NodeId,
        alive: bool,
        out: *Actions(SwarmOutEvent),
    ) (Error || Allocator.Error)!void {
        const offered =
            self.config.shuffle_active_view_count + self.config.shuffle_passive_view_count;
        try self.sendShuffleReply(peer, offered, out);
        try out.push(.{ .send_message = .{
            .to = peer,
            .message = .{ .disconnect = .{ .alive = alive } },
        } });
        try out.push(.{ .disconnect_peer = peer });
    }

    /// Upstream `on_join`.
    ///
    /// This arm inserts eagerly, exactly as the paper says, and it is worth
    /// being explicit about the difference from the deviation below: a direct
    /// `Join` arrives from a peer that reached us over a connection it
    /// already has, so there is nothing to prove. A `ForwardJoin` arrives from
    /// a walk, naming a peer that may never have heard of us.
    fn onJoin(
        self: *State,
        peer: NodeId,
        data: ?[]const u8,
        out: *Actions(SwarmOutEvent),
    ) (Error || Allocator.Error)!void {
        // "A node that receives a join request will start by adding the new
        // node to its active view, even if it has to drop a random node from
        // it. (6)"
        _ = try self.addActive(peer, data, .high, true, out);

        // "The contact node c will then send to all other nodes in its active
        // view a ForwardJoin request containing the new node identifier. (7)"
        const ttl = self.config.active_random_walk_length;
        const info: PeerInfo = .{ .id = peer, .data = data };
        var index: usize = 0;
        while (index < self.active_view.count()) : (index += 1) {
            const node = self.active_view.at(index);
            if (sameNode(node, peer)) continue;
            try out.push(.{ .send_message = .{
                .to = node,
                .message = .{ .forward_join = .{ .peer = info, .ttl = ttl } },
            } });
        }
    }

    /// Upstream `on_forward_join`, and the place this module departs from the
    /// paper.
    fn onForwardJoin(
        self: *State,
        sender: NodeId,
        message: ForwardJoin,
        out: *Actions(SwarmOutEvent),
    ) (Error || Allocator.Error)!void {
        const peer_id = message.peer.id;
        // Already a neighbour: renew, by asking again.
        if (self.active_view.contains(peer_id)) {
            try self.insertPeerInfo(message.peer, out);
            try self.sendNeighbor(peer_id, .high, out);
            return;
        }

        // "i) If the time to live is equal to zero or if the number of nodes in
        // p's active view is equal to one, it will add the new node to its
        // active view (7)"
        //
        // Modification from paper: Instead of adding the peer directly to our
        // active view, we only send the Neighbor message. We will add the peer
        // to our active view once we receive a reply from our neighbor. This
        // prevents us adding unreachable peers to our active view.
        //                                          — upstream, verbatim
        if (message.ttl.expired() or self.active_view.count() <= 1) {
            try self.insertPeerInfo(message.peer, out);
            try self.sendNeighbor(peer_id, .high, out);
            return;
        }

        // "ii) If the time to live is equal to PRWL, p will insert the new node
        // into its passive view"
        if (message.ttl.eql(self.config.passive_random_walk_length)) {
            try self.addPassive(peer_id, message.peer.data, out);
        }
        // "iii) The time to live field is decremented. iv) If, at this point, n
        // has not been inserted in p's active view, p will forward the request
        // to a random node in its active view (different from the one from
        // which the request was received)."
        if (self.active_view.contains(peer_id)) return;
        if (self.pending_neighbor_requests.contains(peer_id)) return;
        // The active view holds at least two peers here, so excluding the
        // sender always leaves one; the `orelse` is a bound, not a guess.
        const next = self.active_view.pickRandomWithout(&.{sender}, &self.rng) orelse return;
        try out.push(.{ .send_message = .{
            .to = next,
            .message = .{ .forward_join = .{
                .peer = message.peer,
                .ttl = message.ttl.next(),
            } },
        } });
    }

    /// Upstream `on_neighbor`, the other half of the deviation.
    fn onNeighbor(
        self: *State,
        from: NodeId,
        details: Neighbor,
        out: *Actions(SwarmOutEvent),
    ) (Error || Allocator.Error)!void {
        // A `Neighbor` that answers one of ours is a reply, and a reply is
        // what causes the insertion; anything else is a request we have to
        // answer ourselves. The classification is upstream's and it is not
        // sound in one corner: a `Neighbor` that arrives after we have already
        // evicted that peer is still taken for a reply, so the peer is put
        // back silently and the `Disconnect` our eviction produced then
        // removes *us* from *its* view. The two halves disagree and, the
        // pending entry being spent, nothing asks again.
        // `sim.Network.asymmetricLinks` measures that, and says the same.
        const is_reply = self.pending_neighbor_requests.remove(from);
        const do_reply = !is_reply;
        // "A node q that receives a high priority neighbor request will always
        // accept the request, even if it has to drop a random member from its
        // active view. If a node q receives a low priority Neighbor request, it
        // will only accept the request if it has a free slot in its active
        // view, otherwise it will refuse the request."
        if (!try self.addActive(from, details.data, details.priority, do_reply, out)) {
            try self.sendDisconnect(from, true, out);
        }
    }

    /// Upstream `insert_peer_info`: record contact data, and tell the
    /// application when it is new.
    fn insertPeerInfo(
        self: *State,
        info: PeerInfo,
        out: *Actions(SwarmOutEvent),
    ) (Error || Allocator.Error)!void {
        const data = info.data orelse return;
        const old = self.peer_data.get(info.id);
        const same = if (old) |held| std.mem.eql(u8, held.slice(), data) else false;
        if (!same and data.len != 0) {
            try out.push(.{ .peer_data = .{ .peer = info.id, .data = data } });
        }
        try self.peer_data.put(info.id, data);
    }

    /// Upstream `on_shuffle`.
    fn onShuffle(
        self: *State,
        from: NodeId,
        message: Shuffle,
        out: *Actions(SwarmOutEvent),
    ) (Error || Allocator.Error)!void {
        // "A node q that receives a Shuffle request will first decrease its
        // time to live. If the time to live of the message is greater than zero
        // and the number of nodes in q's active view is greater than 1, the
        // node will select a random node from its active view, different from
        // the one he received this shuffle message from, and simply forwards
        // the Shuffle request. Otherwise, node q accepts the Shuffle request
        // and send back (p.8)"
        if (message.ttl.expired() or self.active_view.count() <= 1) {
            const len = message.nodes.count;
            for (message.nodes.slice()) |node| try self.addPassive(node.id, node.data, out);
            try self.sendShuffleReply(message.origin, len, out);
            return;
        }
        const excluded = [_]NodeId{ message.origin, from };
        const next = self.active_view.pickRandomWithout(&excluded, &self.rng) orelse {
            // Nothing to forward to: answer instead of dropping the shuffle,
            // which is what upstream's `else` arm does by falling through to
            // the end of the function and losing the message.
            const len = message.nodes.count;
            for (message.nodes.slice()) |node| try self.addPassive(node.id, node.data, out);
            try self.sendShuffleReply(message.origin, len, out);
            return;
        };
        try out.push(.{ .send_message = .{
            .to = next,
            .message = .{ .shuffle = .{
                .origin = message.origin,
                .nodes = message.nodes,
                .ttl = message.ttl.next(),
            } },
        } });
    }

    /// Upstream `send_shuffle_reply`: a random slice of the passive view,
    /// topped up from the active view if the passive one is too short.
    fn sendShuffleReply(
        self: *State,
        to: NodeId,
        len: usize,
        out: *Actions(SwarmOutEvent),
    ) (Error || Allocator.Error)!void {
        var chosen: [max_shuffle_nodes]NodeId = undefined;
        const wanted = @min(len, max_shuffle_nodes);
        var count = self.passive_view.shuffledWithoutAndCapped(&.{}, wanted, &self.rng, &chosen);
        if (count < wanted) {
            count += self.active_view.shuffledWithoutAndCapped(
                &.{},
                wanted - count,
                &self.rng,
                chosen[count..],
            );
        }
        var listed: [max_shuffle_nodes]PeerInfo = undefined;
        for (chosen[0..count], 0..) |peer, index| self.peerInfoInto(peer, &listed[index]);
        try out.push(.{ .send_message = .{
            .to = to,
            .message = .{ .shuffle_reply = .{ .nodes = try PeerInfos.init(listed[0..count]) } },
        } });
    }

    /// Upstream `on_shuffle_reply`: take what we were given, then fill any gap
    /// in the active view from what we now know.
    fn onShuffleReply(
        self: *State,
        message: ShuffleReply,
        out: *Actions(SwarmOutEvent),
    ) (Error || Allocator.Error)!void {
        for (message.nodes.slice()) |node| try self.addPassive(node.id, node.data, out);
        try self.refillActiveFromPassive(&.{}, out);
    }

    /// Upstream `handle_shuffle_timer`: start a walk from a random active
    /// peer, carrying part of both views and ourselves.
    fn handleShuffleTimer(
        self: *State,
        out: *Actions(SwarmOutEvent),
    ) (Error || Allocator.Error)!void {
        if (self.active_view.pickRandom(&self.rng)) |node| {
            var chosen: [max_shuffle_nodes]NodeId = undefined;
            var count = self.active_view.shuffledWithoutAndCapped(
                &.{node},
                self.config.shuffle_active_view_count,
                &self.rng,
                &chosen,
            );
            count += self.passive_view.shuffledWithoutAndCapped(
                &.{node},
                self.config.shuffle_passive_view_count,
                &self.rng,
                chosen[count..],
            );
            var listed: [max_shuffle_nodes]PeerInfo = undefined;
            for (chosen[0..count], 0..) |peer, index| self.peerInfoInto(peer, &listed[index]);
            listed[count] = .{ .id = self.me, .data = self.myData() };
            try out.push(.{ .send_message = .{
                .to = node,
                .message = .{ .shuffle = .{
                    .origin = self.me,
                    .nodes = try PeerInfos.init(listed[0 .. count + 1]),
                    .ttl = self.config.shuffle_random_walk_length,
                } },
            } });
        }
        try out.push(.{ .schedule_timer = .{
            .after = self.config.shuffle_interval,
            .timer = .do_shuffle,
        } });
    }

    fn passiveIsFull(self: *const State) bool {
        return self.passive_view.count() >= self.config.passive_view_capacity;
    }

    fn activeIsFull(self: *const State) bool {
        return self.active_view.count() >= self.config.active_view_capacity;
    }

    /// Upstream `add_passive`. A peer that is active is not also passive, and
    /// neither is this node.
    fn addPassive(
        self: *State,
        peer: NodeId,
        data: ?[]const u8,
        out: *Actions(SwarmOutEvent),
    ) (Error || Allocator.Error)!void {
        try self.insertPeerInfo(.{ .id = peer, .data = data }, out);
        if (sameNode(peer, self.me)) return;
        if (self.active_view.contains(peer)) return;
        if (self.passive_view.contains(peer)) return;
        if (self.passiveIsFull()) {
            const index = self.passive_view.pickRandomIndex(&self.rng) orelse return;
            _ = self.passive_view.removeAt(index);
        }
        _ = try self.passive_view.insert(peer);
    }

    /// Upstream `remove_active`.
    fn removeActive(
        self: *State,
        peer: NodeId,
        reason: RemovalReason,
        out: *Actions(SwarmOutEvent),
    ) (Error || Allocator.Error)!void {
        const index = self.active_view.indexOf(peer) orelse return;
        const gone = try self.removeActiveByIndex(index, reason, out);
        const skip = [_]NodeId{gone};
        try self.refillActiveFromPassive(&skip, out);
    }

    /// Upstream `refill_active_from_passive`.
    ///
    /// Note what this does *not* do: it does not add the peer to the active
    /// view. It sends a `Neighbor`, which starts the exchange that ends with
    /// the peer being added — or not. A refill that added eagerly would put
    /// unreachable peers into the view, which is the same bug the deviation
    /// fixes, in the path that runs most often.
    fn refillActiveFromPassive(
        self: *State,
        skip: []const NodeId,
        out: *Actions(SwarmOutEvent),
    ) (Error || Allocator.Error)!void {
        if (self.active_view.count() + self.pending_neighbor_requests.count() >=
            self.config.active_view_capacity)
        {
            return;
        }
        // "When a node p suspects that one of the nodes present in its active
        // view has failed ..., it selects a random node q from its passive view
        // and attempts to establish a connection with q. If the connection
        // fails to establish, node q is considered failed and removed from p's
        // passive view; another node q' is selected at random and a new attempt
        // is made." (p7)
        var skip_all: [max_passive + max_active]NodeId = undefined;
        var count: usize = 0;
        for (skip) |peer| {
            skip_all[count] = peer;
            count += 1;
        }
        for (self.pending_neighbor_requests.slice()) |peer| {
            skip_all[count] = peer;
            count += 1;
        }
        const node = self.passive_view.pickRandomWithout(skip_all[0..count], &self.rng) orelse
            return;
        const priority: Priority = if (self.active_view.count() == 0) .high else .low;
        try self.sendNeighbor(node, priority, out);
        try out.push(.{ .schedule_timer = .{
            .after = self.config.neighbor_request_timeout,
            .timer = .{ .pending_neighbor_request = node },
        } });
    }

    /// Upstream `handle_pending_neighbor_timer`: the `Neighbor` was never
    /// answered, so the peer is unreachable and is dropped.
    fn handlePendingNeighborTimer(
        self: *State,
        peer: NodeId,
        out: *Actions(SwarmOutEvent),
    ) (Error || Allocator.Error)!void {
        if (!self.pending_neighbor_requests.remove(peer)) return;
        _ = self.passive_view.remove(peer);
        try self.refillActiveFromPassive(&.{}, out);
    }

    /// Upstream `remove_active_by_index`. Returns the peer that left, which
    /// the caller must not ask about again.
    fn removeActiveByIndex(
        self: *State,
        index: usize,
        reason: RemovalReason,
        out: *Actions(SwarmOutEvent),
    ) (Error || Allocator.Error)!NodeId {
        const peer = self.active_view.removeAt(index);
        try out.push(.{ .emit_event = .{ .neighbor_down = peer } });
        switch (reason) {
            // Send a disconnect message, then close the connection.
            .random => try self.sendDisconnect(peer, true, out),
            // Close the connection without sending anything further.
            .disconnect_received, .connection_closed => try out.push(.{ .disconnect_peer = peer }),
        }
        const keep_as_passive = switch (reason) {
            // Keep it if it had already told us it was only closing.
            .connection_closed => self.alive_disconnect_peers.remove(peer),
            // Keep it if the peer said it is still in the swarm.
            .disconnect_received => |is_alive| is_alive,
            // We are the one removing it, for now.
            .random => true,
        };
        if (keep_as_passive) {
            // The slice borrows the table entry, and `addPassive` writes back
            // into that same table, so nothing may be removed first.
            const data = self.peer_data.get(peer);
            try self.addPassive(peer, if (data) |held| held.slice() else null, out);
            const was_a_close = switch (reason) {
                .connection_closed => true,
                else => false,
            };
            if (!was_a_close) _ = try self.alive_disconnect_peers.insert(peer);
        }
        return peer;
    }

    /// Upstream `free_random_slot_in_active_view`.
    fn freeRandomSlotInActiveView(
        self: *State,
        out: *Actions(SwarmOutEvent),
    ) (Error || Allocator.Error)!void {
        const index = self.active_view.pickRandomIndex(&self.rng) orelse return;
        _ = try self.removeActiveByIndex(index, .random, out);
    }

    /// Upstream `add_active`. `false` means the request was refused, and the
    /// caller sends a `Disconnect` for it.
    fn addActive(
        self: *State,
        peer: NodeId,
        data: ?[]const u8,
        priority: Priority,
        reply: bool,
        out: *Actions(SwarmOutEvent),
    ) (Error || Allocator.Error)!bool {
        if (sameNode(peer, self.me)) return false;
        try self.insertPeerInfo(.{ .id = peer, .data = data }, out);
        if (self.active_view.contains(peer)) {
            if (reply) try self.sendNeighbor(peer, priority, out);
            return true;
        }
        if (priority == .high) {
            if (self.activeIsFull()) try self.freeRandomSlotInActiveView(out);
            try self.addActiveUnchecked(peer, .high, reply, out);
            return true;
        }
        if (self.activeIsFull()) return false;
        try self.addActiveUnchecked(peer, .low, reply, out);
        return true;
    }

    fn addActiveUnchecked(
        self: *State,
        peer: NodeId,
        priority: Priority,
        reply: bool,
        out: *Actions(SwarmOutEvent),
    ) (Error || Allocator.Error)!void {
        _ = self.passive_view.remove(peer);
        if (try self.active_view.insert(peer)) {
            try out.push(.{ .emit_event = .{ .neighbor_up = peer } });
            if (reply) try self.sendNeighbor(peer, priority, out);
        }
    }

    /// Upstream `send_neighbor`: one `Neighbor` per request, no more.
    fn sendNeighbor(
        self: *State,
        peer: NodeId,
        priority: Priority,
        out: *Actions(SwarmOutEvent),
    ) (Error || Allocator.Error)!void {
        if (!try self.pending_neighbor_requests.insert(peer)) return;
        try out.push(.{ .send_message = .{
            .to = peer,
            .message = .{ .neighbor = .{ .priority = priority, .data = self.myData() } },
        } });
    }

    fn myData(self: *const State) ?[]const u8 {
        // `&`, not a copy. The slice goes into a `Neighbor`, a `Join` and a
        // `Shuffle`, every one of which outlives this frame; a local
        // `const data` would hand back a pointer into a frame that dies on
        // return. Nothing here reports it — the bytes read back are whatever
        // the next call left in the dead slot — so the address is the fix and
        // this line is not load-bearing to tidy away.
        const data = &(self.me_data orelse return null);
        if (data.isEmpty()) return null;
        return data.slice();
    }

    /// Upstream `peer_info`: a node and the contact data we hold for it.
    fn peerInfoInto(self: *const State, peer: NodeId, into: *PeerInfo) void {
        const data = self.peer_data.get(peer);
        into.* = .{ .id = peer, .data = if (data) |held| held.slice() else null };
    }
};

fn sameNode(a: NodeId, b: NodeId) bool {
    return a.order(b) == .eq;
}

fn containsNode(peers: []const NodeId, peer: NodeId) bool {
    for (peers) |item| {
        if (sameNode(item, peer)) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// The two layers together
// ---------------------------------------------------------------------------

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
    me: NodeId,
    swarm: State,
    gossip: plumtree.State,
    stats: Stats,

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

    /// Handle one event.
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
                .quit => try self.swarm.handle(.quit, &membership),
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

// ---------------------------------------------------------------------------
// The simulator
// ---------------------------------------------------------------------------

/// A deterministic in-process network. Upstream `proto/sim.rs`.
///
/// # Why it is here and not in a test
///
/// Upstream's own comment on the module is that the gossip protocol is
/// I/O-free and `sim.rs` is the way to test it. That is right, and the reason
/// is sharper than "it is convenient": HyParView is a protocol about
/// *agreement*, and a state machine tested only by feeding it messages never
/// checks that two of them agree. The convergence of two nodes' active views
/// is a property of the network, not of either node, and there is no way to
/// observe it without one.
///
/// # Determinism, and where upstream's is not
///
/// Time is a counter this module owns, so there is no clock. Every random
/// choice comes from a generator the caller seeds, and every per-node
/// generator is drawn from the network's, so one seed fixes the whole run.
/// The event queue breaks ties by insertion order, not by a sort.
///
/// Upstream's simulator is *not* reproducible across processes, and cannot be:
/// `pending_neighbor_requests` and `alive_disconnect_peers` are `HashSet`s
/// built on `RandomState`, whose seed is per-process and per-instance, and
/// `refill_active_from_passive` iterates one of them. Two runs of the same
/// binary with the same `SEED` take different paths. Every such set here is a
/// bounded array, so `zig build test` gives the same answer on every machine
/// and in CI, which is the property a simulator has to have to be a test.
/// That is a deliberate divergence and it is the reason the `Zig` port's
/// numbers are not comparable to upstream's event-for-event.
///
/// The bits are not comparable anyway: upstream seeds `ChaCha12` and this
/// seeds `xoshiro256`, so even with identical control flow the two would
/// draw different peers. What *is* comparable, and what the tests here pin, is
/// the outcome: the same neighbour sets, the same `NeighborUp` events, the
/// same number of broadcast deliveries, the same synchrony. Those come from
/// the reference's own test expectations, captured from its source at the
/// commit named at the top of this file.
pub const sim = struct {
    /// How many nodes one simulated swarm holds.
    pub const max_peers = 12;
    /// An undirected link is one unordered pair, so this is the ceiling on how
    /// many can exist.
    const max_conns = max_peers * (max_peers - 1) / 2;
    /// Enough for every link to be torn down inside one tick.
    const max_kills = max_conns;
    /// A microsecond, which is upstream's own grace period. The comment
    /// upstream gives it is the reason it exists: an event queued at the
    /// current instant must land before the disconnect that follows it, so a
    /// node is not removed while a message is on its way to it.
    const disconnect_grace: Nanos = 1_000;
    /// The topic the simulator runs: 32 zero bytes, which is upstream's
    /// `sim::TOPIC` and a fixture rather than a value anyone would choose.
    pub const topic: TopicId = TopicId.fromBytes([_]u8{0} ** topic_id_length);
    /// The number of neighbour events one `neighbourEvents` buffer holds.
    /// Sized for a swarm that reshuffles several times over, which is several
    /// times the node count.
    pub const max_neighbour_events = max_peers * 8;

    /// Everything that can go wrong in the harness rather than in the
    /// protocol. Separate from `Error` because none of it is a protocol
    /// refusal: a simulator asked to add a thirteenth node, or to add one
    /// twice, has been asked something impossible.
    pub const SimError = error{
        PeerIndexOutOfRange,
        DuplicatePeer,
        TooManyDisconnects,
    };

    /// Every way this harness can fail, over both layers. `key.KeyError` is
    /// here because `nodeIdFor` mints a real key from a seed, and a seed that
    /// derives the identity point is a harness input like any other.
    pub const HarnessError = Error || plumtree.Error || SimError ||
        key.KeyError || Allocator.Error;

    /// A node's identity, from a fixed seed. A `NodeId` cannot be made from
    /// arbitrary bytes — `NodeId.fromBytes` rejects anything that is not a
    /// point on the curve — so a simulator of `u64` peer ids has to mint real
    /// keys, deterministically.
    ///
    /// Fallible because `SecretKey.fromSeed` refuses a seed that derives the
    /// identity point, and a `0x5c` fill says nothing about the twelve
    /// indices a swarm holds. A harness caller reports it, a test fails on
    /// it, and both name the seed; `unreachable` could do neither and would
    /// have taken the process down instead.
    pub fn nodeIdFor(index: u8) key.KeyError!NodeId {
        var seed: [key.SecretKey.seed_length]u8 = undefined;
        @memset(&seed, 0x5c);
        seed[0] = index;
        return (try key.SecretKey.fromSeed(seed)).nodeId();
    }

    /// How long a message takes to cross a link. Upstream `LatencyConfig`.
    pub const LatencyConfig = union(enum) {
        /// The same on every link. Upstream `LatencyConfig::Static`.
        fixed: Nanos,
        /// Drawn once per link. Upstream `LatencyConfig::Dynamic`.
        drawn: struct { min: Nanos, max: Nanos },

        pub const default_fixed: LatencyConfig = .{ .fixed = 50 * nanos_per_milli };
        pub const default_drawn: LatencyConfig = .{
            .drawn = .{ .min = 10 * nanos_per_milli, .max = 100 * nanos_per_milli },
        };

        pub fn maxLatency(self: LatencyConfig) Nanos {
            return switch (self) {
                .fixed => |value| value,
                .drawn => |range| range.max,
            };
        }

        fn draw(self: LatencyConfig, rng: *Rng) Nanos {
            return switch (self) {
                .fixed => |value| value,
                .drawn => |range| rng.range(range.min, range.max),
            };
        }
    };

    pub const NetworkConfig = struct {
        latency: LatencyConfig = LatencyConfig.default_drawn,
        membership: Config = .{},
        broadcast: plumtree.Config = .{},

        // `pub` under `pub const sim`; ziglint's visibility map is top-level decls.
        // ziglint-ignore: Z012
        pub fn topicConfig(self: NetworkConfig) TopicConfig {
            return .{ .membership = self.membership, .broadcast = self.broadcast };
        }
    };

    pub const SimulatorConfig = struct {
        /// The one seed that fixes the whole run.
        rng_seed: u64 = 0,
        peers: u8 = 8,
        gossip_round_timeout: Nanos = 5 * nanos_per_second,
    };

    /// How a swarm is brought up. Upstream `sim::BootstrapMode`.
    pub const BootstrapMode = union(enum) {
        /// Every peer joins one peer.
        single,
        /// The first `count` form a core; the rest join a random core member.
        core: u8,
    };

    /// Something the application saw. Upstream's is a `(PI, TopicId, Event)`
    /// triple; a simulated node is on one topic, so the topic is not repeated.
    pub const SimEvent = struct {
        peer: u8,
        event: AppEvent,
    };

    /// A neighbour change, reduced to two indices and a direction, so a test
    /// can hold a run against upstream's expected event lists.
    pub const NeighbourEvent = struct {
        up: bool,
        a: u8,
        b: u8,
    };

    /// One simulated node, carrying a whole `TopicState`. That is tens of
    /// kilobytes per slot, so whether a slot holds a node is answered by
    /// `Network.occupied` and never by reading a `Peer` `insert` has not
    /// written: the bytes of an unwritten one are the compiler's `undefined`
    /// fill, and asking them whether node 4 is in the swarm is asking a `bool`
    /// field for a bit pattern that is not a bool.
    const Peer = struct {
        id: NodeId,
        /// Whether the node is still on the topic. Upstream drops the whole
        /// per-topic state on `Quit` and then ignores every later event for
        /// it, which is what this flag reproduces: a node that left does not
        /// start answering `Join` requests again because a message arrived.
        joined: bool = false,
        state: TopicState,
    };

    const QueueEntry = struct {
        time: Nanos,
        peer: u8,
        event: InEvent,
    };

    const Conn = struct { a: u8, b: u8 };

    const Latency = struct { conn: Conn, latency: Nanos };

    pub const Network = struct {
        gpa: Allocator,
        /// Where payloads of parked messages are copied. This is the one place
        /// a message outlives the state that produced it, and it is where the
        /// borrow rule both layers document is discharged.
        arena: std.heap.ArenaAllocator,
        rng: Rng,
        config: NetworkConfig,
        time: Nanos,
        /// The three fixed arrays below stay `undefined`, and that is safe for
        /// exactly one reason each: every read of `links` and `latencies` is
        /// cut by its own counter, and every read of `peers` is cut by
        /// `occupied`. Occupancy is therefore a field of its own and not a
        /// flag inside a `Peer` nobody has written.
        peers: [max_peers]Peer,
        /// Which slots hold a node. The only defined record of that.
        occupied: [max_peers]bool,
        peer_count: usize,
        queue: std.ArrayList(QueueEntry),
        events: std.ArrayList(SimEvent),
        links: [max_conns]Conn,
        conn_count: usize,
        latencies: [max_conns]Latency,
        latency_count: usize,

        // `pub` under `pub const sim`; ziglint's visibility map is top-level decls.
        // ziglint-ignore: Z012 Z015
        pub fn init(
            gpa: Allocator,
            config: NetworkConfig,
            seed: u64,
        ) HarnessError!Network {
            try config.membership.validate();
            return .{
                .gpa = gpa,
                .arena = std.heap.ArenaAllocator.init(gpa),
                .rng = .init(seed),
                .config = config,
                .time = 0,
                .peers = undefined,
                .occupied = [_]bool{false} ** max_peers,
                .peer_count = 0,
                .queue = .empty,
                .events = .empty,
                .links = undefined,
                .conn_count = 0,
                .latencies = undefined,
                .latency_count = 0,
            };
        }

        pub fn deinit(self: *Network) void {
            self.queue.deinit(self.gpa);
            self.events.deinit(self.gpa);
            self.arena.deinit();
            // Everything above is freed, so the struct is poisoned rather than
            // half-reset: a field that still looked like a network would read
            // as a plausible run instead of as the use-after-free that it is.
            self.* = undefined;
        }

        // `pub` under `pub const sim`; ziglint's visibility map is top-level decls.
        // ziglint-ignore: Z015
        /// Add a node. Upstream `Network::insert_with_config`.
        pub fn insert(self: *Network, index: u8) HarnessError!void {
            if (index >= max_peers) return error.PeerIndexOutOfRange;
            if (self.occupied[index]) return error.DuplicatePeer;
            // Upstream draws each node's generator from the network's, so two
            // nodes in one simulation do not walk in lockstep.
            const rng = self.rng.child();
            // Minted before the slot is written and used twice: a `NodeId` is
            // a key derivation, not a lookup, and a slot written from one
            // `id` and another `state.id` would be a swarm that disagrees
            // with itself about who it is.
            const id = try nodeIdFor(index);
            self.peers[index] = .{
                .id = id,
                .joined = true,
                .state = try TopicState.init(
                    id,
                    null,
                    self.config.topicConfig(),
                    rng,
                ),
            };
            // Marked after the state is built: a `TopicState.init` that fails
            // leaves the slot as it found it.
            self.occupied[index] = true;
            if (index + 1 > self.peer_count) self.peer_count = index + 1;
        }

        // `pub` under `pub const sim`; ziglint's visibility map is top-level decls.
        // ziglint-ignore: Z015
        /// Add a node and send it a join command. Upstream
        /// `Network::insert_and_join`.
        pub fn insertAndJoin(
            self: *Network,
            index: u8,
            bootstrap: []const u8,
        ) HarnessError!void {
            try self.insert(index);
            var peers: [max_bootstrap]NodeId = undefined;
            for (bootstrap, 0..) |peer, position| peers[position] = try nodeIdFor(peer);
            try self.command(index, .{ .join = try Peers.init(peers[0..bootstrap.len]) });
        }

        pub fn peerOf(self: *const Network, index: u8) ?*const Peer {
            if (index >= max_peers) return null;
            if (!self.occupied[index]) return null;
            return &self.peers[index];
        }

        fn peerSlot(self: *Network, index: u8) ?*Peer {
            if (index >= max_peers) return null;
            if (!self.occupied[index]) return null;
            return &self.peers[index];
        }

        pub fn peerIndexOf(self: *const Network, id: NodeId) ?u8 {
            for (self.peers[0..self.peer_count], 0..) |peer, index| {
                if (!self.occupied[index]) continue;
                if (sameNode(peer.id, id)) return @intCast(index);
            }
            return null;
        }

        /// The membership layer's active view for one node, as node ids.
        pub fn neighbors(self: *const Network, index: u8) []const NodeId {
            const peer = self.peerOf(index) orelse return &.{};
            if (!peer.joined) return &.{};
            return peer.state.swarm.activeView();
        }

        /// Whether a node is still on the topic. Upstream asserts this after a
        /// quit with `network.peer(&3).unwrap().state(&t).is_none()`.
        pub fn hasJoined(self: *const Network, index: u8) bool {
            const peer = self.peerOf(index) orelse return false;
            return peer.joined;
        }

        /// The same view as node indices, which is what a test asserts on.
        pub fn neighborIndices(self: *const Network, index: u8, out: *[max_peers]u8) usize {
            var count: usize = 0;
            for (self.neighbors(index)) |peer| {
                const found = self.peerIndexOf(peer) orelse continue;
                out[count] = found;
                count += 1;
            }
            return count;
        }

        /// The broadcast layer's eager set as node indices.
        pub fn eagerIndices(self: *const Network, index: u8, out: *[max_peers]u8) usize {
            const peer = self.peerOf(index) orelse return 0;
            var count: usize = 0;
            for (peer.state.gossip.eagerPeers()) |eager| {
                const found = self.peerIndexOf(eager) orelse continue;
                out[count] = found;
                count += 1;
            }
            return count;
        }

        pub fn hasNeighbor(self: *const Network, index: u8, other: u8) bool {
            var found: [max_peers]u8 = undefined;
            const count = self.neighborIndices(index, &found);
            for (found[0..count]) |candidate| {
                if (candidate == other) return true;
            }
            return false;
        }

        pub fn neighborCount(self: *const Network, index: u8) usize {
            return self.neighbors(index).len;
        }

        // `pub` under `pub const sim`; ziglint's visibility map is top-level decls.
        // ziglint-ignore: Z015
        /// Hand a command to a node, then run whatever the current instant
        /// has queued. Upstream `Network::command`.
        pub fn command(self: *Network, index: u8, request: Command) HarnessError!void {
            const leaving = request == .quit;
            const parked = try self.park(.{ .command = request });
            try self.enqueue(self.time, index, parked);
            try self.tick();
            if (!leaving) return;
            if (self.peerSlot(index)) |peer| peer.joined = false;
        }

        // `pub` under `pub const sim`; ziglint's visibility map is top-level decls.
        // ziglint-ignore: Z015
        pub fn runTrips(self: *Network, count: u64) HarnessError!void {
            try self.runDuration(self.config.latency.maxLatency() * count);
        }

        // `pub` under `pub const sim`; ziglint's visibility map is top-level decls.
        // ziglint-ignore: Z015
        pub fn runDuration(self: *Network, duration: Nanos) HarnessError!void {
            const end = self.time + duration;
            while (self.queue.items.len > 0 and self.queue.items[0].time <= end) {
                try self.tick();
            }
            self.time = end;
        }

        /// When the next queued event is due, or `null` when nothing is
        /// pending. A gossip round uses this to stop on its timeout.
        pub fn nextTime(self: *const Network) ?Nanos {
            if (self.queue.items.len == 0) return null;
            return self.queue.items[0].time;
        }

        /// Insert keeping the queue ordered by `(time, insertion order)`.
        ///
        /// **The tie-break is part of the contract.** Among events due at the
        /// same instant the earliest *inserted* is handled first, so a node
        /// sees a message before the disconnect that follows it, and a
        /// `Neighbor` before whatever provoked it. Inserting after every entry
        /// whose time is less than or equal to the new one gives that for
        /// free, and it is exactly what upstream's
        /// `BinaryHeap<(TimedEvent, i32)>` does: a reversed `Ord` on the time
        /// and a negated sequence number as the second key, which together pop
        /// equal times first-in-first-out. A queue sorted by peer id, or with
        /// any other tie-break, silently changes the run, and because the
        /// protocol is symmetric the change is invisible in the final views
        /// and visible only in the event counts.
        fn enqueue(
            self: *Network,
            time: Nanos,
            index: u8,
            event: InEvent,
        ) HarnessError!void {
            var at = self.queue.items.len;
            for (self.queue.items, 0..) |entry, position| {
                if (entry.time > time) {
                    at = position;
                    break;
                }
            }
            try self.queue.insert(self.gpa, at, .{
                .time = time,
                .peer = index,
                .event = event,
            });
        }

        fn tick(self: *Network) HarnessError!void {
            if (self.queue.items.len == 0) return;
            const entry = self.queue.orderedRemove(0);
            self.time = entry.time;
            const peer = self.peerSlot(entry.peer) orelse return;
            if (!peer.joined) return;
            if (entry.event == .recv_message) {
                if (self.peerIndexOf(entry.event.recv_message.from)) |other| {
                    self.addConn(other, entry.peer);
                }
            }
            var out: Actions(OutEvent) = .init(self.gpa);
            defer out.deinit();
            try peer.state.handle(entry.event, self.time, &out);

            var kills: [max_kills]Conn = undefined;
            var kill_count: usize = 0;
            for (out.slice()) |event| switch (event) {
                .send_message => |send| {
                    const to = self.peerIndexOf(send.to) orelse continue;
                    const latency = self.latencyBetween(entry.peer, to);
                    const parked = try self.park(.{
                        .recv_message = .{ .from = peer.id, .message = send.message },
                    });
                    try self.enqueue(self.time + latency, to, parked);
                },
                .schedule_timer => |schedule| {
                    const parked = try self.park(.{ .timer_expired = schedule.timer });
                    try self.enqueue(self.time + schedule.after, entry.peer, parked);
                },
                .disconnect_peer => |other| {
                    const to = self.peerIndexOf(other) orelse continue;
                    if (kill_count == max_kills) return error.TooManyDisconnects;
                    kills[kill_count] = .{ .a = @min(entry.peer, to), .b = @max(entry.peer, to) };
                    kill_count += 1;
                },
                .emit_event => |reported| try self.events.append(self.gpa, .{
                    .peer = entry.peer,
                    .event = try self.parkEvent(reported),
                }),
                .peer_data => {},
            };
            for (kills[0..kill_count]) |conn| try self.killConnection(conn.a, conn.b);
        }

        /// Break a link; the other end hears about it one microsecond after the
        /// usual latency, so anything already in flight lands first.
        fn killConnection(self: *Network, a: u8, b: u8) HarnessError!void {
            if (!self.removeConn(a, b)) return;
            const latency = self.latencyBetween(a, b) + disconnect_grace;
            try self.enqueue(self.time + latency, b, .{
                .peer_disconnected = try nodeIdFor(a),
            });
        }

        fn addConn(self: *Network, a: u8, b: u8) void {
            if (a == b) return;
            if (self.findConn(a, b) != null) return;
            if (self.conn_count == max_conns) return;
            self.links[self.conn_count] = .{ .a = @min(a, b), .b = @max(a, b) };
            self.conn_count += 1;
        }

        fn removeConn(self: *Network, a: u8, b: u8) bool {
            for (self.links[0..self.conn_count], 0..) |conn, index| {
                if (conn.a != @min(a, b) or conn.b != @max(a, b)) continue;
                @memmove(
                    self.links[index .. self.conn_count - 1],
                    self.links[index + 1 .. self.conn_count],
                );
                self.conn_count -= 1;
                return true;
            }
            return false;
        }

        fn findConn(self: *const Network, a: u8, b: u8) ?Conn {
            for (self.links[0..self.conn_count]) |conn| {
                if (conn.a == @min(a, b) and conn.b == @max(a, b)) return conn;
            }
            return null;
        }

        /// One latency per link, drawn the first time the link is used and
        /// kept. A link whose speed changed every message would be a different
        /// network on every tick, and the run would stop being reproducible.
        fn latencyBetween(self: *Network, a: u8, b: u8) Nanos {
            const conn: Conn = .{ .a = @min(a, b), .b = @max(a, b) };
            for (self.latencies[0..self.latency_count]) |entry| {
                if (entry.conn.a == conn.a and entry.conn.b == conn.b) return entry.latency;
            }
            const drawn = self.config.latency.draw(&self.rng);
            if (self.latency_count == max_conns) return drawn;
            self.latencies[self.latency_count] = .{ .conn = conn, .latency = drawn };
            self.latency_count += 1;
            return drawn;
        }

        /// Deep-copy an event's payloads into the arena, so a queued message
        /// does not point into the state that emitted it.
        fn park(self: *Network, event: InEvent) HarnessError!InEvent {
            const a = self.arena.allocator();
            return switch (event) {
                .recv_message => |recv| .{ .recv_message = .{
                    .from = recv.from,
                    .message = try parkMessage(a, recv.message),
                } },
                .command => |requested| switch (requested) {
                    .broadcast => |b| .{ .command = .{ .broadcast = .{
                        .content = try a.dupe(u8, b.content),
                        .scope = b.scope,
                    } } },
                    else => .{ .command = requested },
                },
                else => event,
            };
        }

        fn parkEvent(self: *Network, event: AppEvent) HarnessError!AppEvent {
            return switch (event) {
                .received => |received| .{ .received = .{
                    .content = try self.arena.allocator().dupe(u8, received.content),
                    .delivered_from = received.delivered_from,
                    .scope = received.scope,
                } },
                else => event,
            };
        }

        /// Are both layers synchronous? Upstream `check_synchronicity`: every
        /// active neighbour of ours lists us, and every eager peer of ours
        /// lists us.
        ///
        /// This is the check the protocol exists to make true, and the one
        /// thing a state-machine test cannot make. A membership layer that
        /// inserts on `ForwardJoin` passes every message-level test and fails
        /// here, because a node that inserted a peer it never reached believes
        /// in a link the other end has no record of.
        pub fn checkSynchronicity(self: *const Network) bool {
            var ours: [max_peers]u8 = undefined;
            var theirs: [max_peers]u8 = undefined;
            for (self.peers[0..self.peer_count], 0..) |peer, index| {
                if (!self.occupied[index] or !peer.joined) continue;
                const me: u8 = @intCast(index);
                for (peer.state.swarm.activeView()) |neighbour| {
                    const other = self.peerIndexOf(neighbour) orelse continue;
                    // A node that has left the topic has no view to be held
                    // to, which is why upstream's check reaches for a state
                    // that a quit has already removed.
                    if (!self.hasJoined(other)) continue;
                    const count = self.neighborIndices(other, &theirs);
                    if (!hasIndex(theirs[0..count], me)) return false;
                }
                for (peer.state.gossip.eagerPeers()) |eager| {
                    const other = self.peerIndexOf(eager) orelse continue;
                    if (!self.hasJoined(other)) continue;
                    const count = self.eagerIndices(other, &ours);
                    if (!hasIndex(ours[0..count], me)) return false;
                }
            }
            return true;
        }

        /// Links one end still believes in and the other end does not.
        ///
        /// A healthy converged swarm has none, and this is the number that says
        /// so more honestly than "no node is alone": a node can have three
        /// neighbours and one of them can be a fiction.
        ///
        /// It is not always zero, and that is upstream rather than a port
        /// defect. `on_neighbor` treats a `Neighbor` as a *reply* whenever the
        /// sender is in `pending_neighbor_requests`, and a reply is not
        /// answered. So a node that evicts a peer for room, and then receives
        /// the `Neighbor` that peer had sent moments earlier, silently puts it
        /// back — and then processes the `Disconnect` the eviction produced,
        /// which removes the *other* end. The two views disagree and, because
        /// the requester's pending entry is spent, nothing ever asks again.
        /// Upstream has the identical code path; `check_synchronicity` is a
        /// helper, not a property it claims, and its own convergence test
        /// asserts only that no node is left without neighbours.
        ///
        /// What must hold — and what this is for — is that the count does not
        /// grow: a swarm that has stopped joining stops disagreeing.
        pub fn asymmetricLinks(self: *const Network) usize {
            var count: usize = 0;
            var index: u8 = 0;
            while (index < self.peer_count) : (index += 1) {
                if (!self.hasJoined(index)) continue;
                for (self.neighbors(index)) |neighbour| {
                    const other = self.peerIndexOf(neighbour) orelse continue;
                    if (other <= index) continue;
                    if (self.hasNeighbor(other, index)) continue;
                    count += 1;
                }
            }
            return count;
        }

        /// How many nodes have no neighbours at all. A converged swarm has
        /// none, and upstream's bootstrap asserts exactly this.
        pub fn peersWithoutNeighbors(self: *const Network) usize {
            var count: usize = 0;
            for (self.peers[0..self.peer_count], 0..) |_, index| {
                if (!self.occupied[index]) continue;
                if (self.neighborCount(@intCast(index)) == 0) count += 1;
            }
            return count;
        }

        /// The smallest and largest active view in the swarm. Upstream
        /// `NetworkReport`'s active histogram, reduced to its two ends: a mean
        /// would hide the one node that came out empty, which is the number
        /// that matters.
        pub fn activeExtent(self: *const Network) struct { min: usize, max: usize } {
            var smallest: usize = max_peers;
            var largest: usize = 0;
            for (self.peers[0..self.peer_count], 0..) |_, index| {
                if (!self.occupied[index]) continue;
                const count = self.neighborCount(@intCast(index));
                smallest = @min(smallest, count);
                largest = @max(largest, count);
            }
            return .{ .min = smallest, .max = largest };
        }

        /// Every open link. Upstream `Network::conns`.
        pub fn conns(self: *const Network) []const Conn {
            return self.links[0..self.conn_count];
        }

        /// The neighbour changes seen so far, sorted, so a test can hold a run
        /// against upstream's expected event lists.
        pub fn neighbourEvents(
            self: *const Network,
            out: *[max_neighbour_events]NeighbourEvent,
        ) []NeighbourEvent {
            var count: usize = 0;
            for (self.events.items) |seen| switch (seen.event) {
                .neighbor_up => |peer| {
                    if (count == max_neighbour_events) break;
                    const other = self.peerIndexOf(peer) orelse continue;
                    out[count] = .{ .up = true, .a = seen.peer, .b = other };
                    count += 1;
                },
                .neighbor_down => |peer| {
                    if (count == max_neighbour_events) break;
                    const other = self.peerIndexOf(peer) orelse continue;
                    out[count] = .{ .up = false, .a = seen.peer, .b = other };
                    count += 1;
                },
                .received => {},
            };
            const slice = out[0..count];
            std.mem.sort(NeighbourEvent, slice, {}, lessNeighbourEvent);
            return slice;
        }
    };

    fn lessNeighbourEvent(_: void, a: NeighbourEvent, b: NeighbourEvent) bool {
        if (a.a != b.a) return a.a < b.a;
        if (a.b != b.b) return a.b < b.b;
        return !a.up and b.up;
    }

    fn hasIndex(indices: []const u8, wanted: u8) bool {
        for (indices) |index| {
            if (index == wanted) return true;
        }
        return false;
    }

    fn parkMessage(a: Allocator, message: Message) HarnessError!Message {
        return switch (message) {
            .swarm => |swarm| .{ .swarm = try parkSwarm(a, swarm) },
            .gossip => |gossip| switch (gossip) {
                .gossip => |inner| .{ .gossip = .{ .gossip = .{
                    .id = inner.id,
                    .content = try a.dupe(u8, inner.content),
                    .scope = inner.scope,
                } } },
                else => .{ .gossip = gossip },
            },
        };
    }

    fn parkSwarm(a: Allocator, message: SwarmMessage) HarnessError!SwarmMessage {
        return switch (message) {
            .join => |data| .{ .join = try parkData(a, data) },
            .neighbor => |neighbor| .{ .neighbor = .{
                .priority = neighbor.priority,
                .data = try parkData(a, neighbor.data),
            } },
            .forward_join => |forward| .{ .forward_join = .{
                .peer = try parkInfo(a, forward.peer),
                .ttl = forward.ttl,
            } },
            .shuffle => |shuffle| .{ .shuffle = .{
                .origin = shuffle.origin,
                .nodes = try parkInfos(a, shuffle.nodes),
                .ttl = shuffle.ttl,
            } },
            .shuffle_reply => |reply| .{ .shuffle_reply = .{
                .nodes = try parkInfos(a, reply.nodes),
            } },
            .disconnect => |disconnect| .{ .disconnect = disconnect },
        };
    }

    fn parkData(a: Allocator, data: ?[]const u8) HarnessError!?[]const u8 {
        const held = data orelse return null;
        const parked = try a.dupe(u8, held);
        return parked;
    }

    fn parkInfo(a: Allocator, info: PeerInfo) HarnessError!PeerInfo {
        return .{ .id = info.id, .data = try parkData(a, info.data) };
    }

    fn parkInfos(a: Allocator, list: PeerInfos) HarnessError!PeerInfos {
        var parked: [max_shuffle_nodes]PeerInfo = undefined;
        const items = list.slice();
        for (items, 0..) |info, index| parked[index] = try parkInfo(a, info);
        return PeerInfos.init(parked[0..items.len]);
    }

    /// What one broadcast round cost. Upstream's `RoundStats` without its three
    /// ratios: those measure a run against upstream's numbers, and this port's
    /// numbers are not comparable — see the determinism note on `sim`. What is
    /// left is what a port can be held to.
    pub const RoundStats = struct {
        /// Nodes that were supposed to get the message.
        expected: usize,
        /// Nodes that did, counted once each.
        delivered: usize,
        /// `Received` events for a node that already had one. Upstream treats
        /// this as a panic, because deduplication is supposed to make it
        /// impossible; here it is a number a test asserts is zero, which is the
        /// same statement without taking the process down.
        duplicated: usize,
        /// The furthest a message got, in hops from its origin.
        max_round: u16,
    };

    /// A swarm under test. Upstream `proto::sim::Simulator`.
    pub const Simulator = struct {
        network: Network,
        config: SimulatorConfig,

        // `pub` under `pub const sim`; ziglint's visibility map is top-level decls.
        // ziglint-ignore: Z012 Z015
        pub fn init(
            gpa: Allocator,
            config: SimulatorConfig,
            network_config: NetworkConfig,
        ) HarnessError!Simulator {
            return .{
                .network = try Network.init(gpa, network_config, config.rng_seed),
                .config = config,
            };
        }

        pub fn deinit(self: *Simulator) void {
            self.network.deinit();
            self.* = undefined;
        }

        // `pub` under `pub const sim`; ziglint's visibility map is top-level decls.
        // ziglint-ignore: Z012 Z015
        /// Bring the swarm up. Upstream `Simulator::bootstrap`.
        pub fn bootstrap(self: *Simulator, mode: BootstrapMode) HarnessError!void {
            const count = self.config.peers;
            switch (mode) {
                .single => {
                    try self.network.insertAndJoin(0, &[_]u8{});
                    var index: u8 = 1;
                    while (index < count) : (index += 1) {
                        try self.network.insertAndJoin(index, &[_]u8{0});
                    }
                    try self.network.runTrips(20);
                },
                .core => {
                    const core = @min(mode.core, count);
                    try self.network.insertAndJoin(0, &[_]u8{});
                    var index: u8 = 1;
                    while (index < core) : (index += 1) {
                        try self.network.insertAndJoin(index, &[_]u8{0});
                    }
                    try self.network.runTrips(7);
                    while (index < count) : (index += 1) {
                        const contact: u8 = @intCast(
                            self.network.rng.below(@as(usize, core)),
                        );
                        try self.network.insertAndJoin(index, &[_]u8{contact});
                    }
                    try self.network.runTrips(20);
                },
            }
        }

        // `pub` under `pub const sim`; ziglint's visibility map is top-level decls.
        // ziglint-ignore: Z012 Z015
        /// Broadcast from one node and count who got it. Upstream
        /// `Simulator::gossip_round`, reduced to a single sender: the
        /// multiple-sender case differs only in how many messages are in
        /// flight, and this port's iTree is the thing under test.
        pub fn gossipRound(
            self: *Simulator,
            from: u8,
            content: []const u8,
        ) HarnessError!RoundStats {
            const expected = if (self.network.peer_count > 0) self.network.peer_count - 1 else 0;
            var stats: RoundStats = .{
                .expected = expected,
                .delivered = 0,
                .duplicated = 0,
                .max_round = 0,
            };
            var seen = [_]bool{false} ** max_peers;
            self.network.events.clearRetainingCapacity();
            try self.network.command(from, .{
                .broadcast = .{ .content = content, .scope = .swarm },
            });
            self.harvest(&stats, &seen);
            const end = self.network.time + self.config.gossip_round_timeout;
            while (stats.delivered < expected) {
                const at = self.network.nextTime() orelse break;
                if (at > end) break;
                try self.network.tick();
                self.harvest(&stats, &seen);
            }
            return stats;
        }

        fn harvest(self: *Simulator, stats: *RoundStats, seen: *[max_peers]bool) void {
            for (self.network.events.items) |event| {
                switch (event.event) {
                    .received => |received| {
                        if (seen[event.peer]) stats.duplicated += 1;
                        seen[event.peer] = true;
                        stats.delivered += 1;
                        stats.max_round = switch (received.scope) {
                            .swarm => |round| @max(stats.max_round, round.value),
                            .neighbors => stats.max_round,
                        };
                    },
                    else => {},
                }
            }
            self.network.events.clearRetainingCapacity();
        }
    };
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const t = std.testing;

/// Run one throwaway event so the shuffle timer that the first call arms is
/// out of the way, leaving the next call's actions to be about that call. The
/// latch itself is real behaviour and has its own test below.
fn prime(state: *State, out: *Actions(SwarmOutEvent)) !void {
    out.clear();
    try state.handle(.{ .update_peer_data = PeerData{} }, out);
    out.clear();
}

fn newMembership(index: u8, config: Config, seed: u64) (Error || key.KeyError)!State {
    return State.init(try sim.nodeIdFor(index), null, config, .init(seed));
}

// The deviation, first half: a `ForwardJoin` that has run out of walk sends a
// `Neighbor` and inserts nothing.
//
// Eager insertion is the bug. A node that puts a peer in its active view on
// the strength of a message from a walk spends a slot on a peer it may not be
// able to reach, drops an honest neighbour to make room, and ends up holding
// a view the other end does not share. Every byte-level test still passes.
test "a forward join at the end of its walk asks and does not insert" {
    const walker = try sim.nodeIdFor(1);
    const target = try sim.nodeIdFor(3);
    var state: State = try newMembership(2, .{ .active_view_capacity = 2 }, 7);
    var out: Actions(SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    try prime(&state, &out);

    try state.handle(.{ .recv_message = .{ .from = walker, .message = .{ .forward_join = .{
        .peer = .{ .id = target, .data = null },
        .ttl = .{ .value = 0 },
    } } } }, &out);

    // One Neighbor went to the target, and the walker is cut loose because it
    // is not a neighbour: that teardown is upstream's own "I am not sure this
    // is correct" rule, kept because the simulator is compared against it.
    try t.expectEqual(@as(usize, 2), out.count());
    try t.expect(out.at(0) == .send_message);
    try t.expect(sameNode(out.at(0).send_message.to, target));
    try t.expect(out.at(0).send_message.message == .neighbor);
    try t.expectEqual(Priority.high, out.at(0).send_message.message.neighbor.priority);
    try t.expect(out.at(1) == .disconnect_peer);
    try t.expect(sameNode(out.at(1).disconnect_peer, walker));

    // Nothing was inserted, nothing was reported to the application, and the
    // peer is on the pending list: asked, not answered.
    try t.expectEqual(@as(usize, 0), state.activeView().len);
    try t.expect(state.pending_neighbor_requests.contains(target));
    for (out.slice()) |produced| try t.expect(produced != .emit_event);
}

// The deviation, second half: the peer enters the active view only when it
// answers, and answering is not answered again.
test "a neighbor enters the active view when it replies, and a reply is not a request" {
    const peer = try sim.nodeIdFor(3);
    var state: State = try newMembership(2, .{}, 11);
    var out: Actions(SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    try prime(&state, &out);

    const walker = try sim.nodeIdFor(1);
    try state.handle(.{ .recv_message = .{ .from = walker, .message = .{ .forward_join = .{
        .peer = .{ .id = peer, .data = null },
        .ttl = .{ .value = 0 },
    } } } }, &out);
    try t.expectEqual(@as(usize, 0), state.activeView().len);
    try t.expectEqual(@as(usize, 1), state.pending_neighbor_requests.count());

    // The peer answers with a Neighbor of its own.
    out.clear();
    try state.handle(.{ .recv_message = .{ .from = peer, .message = .{ .neighbor = .{
        .priority = .high,
        .data = null,
    } } } }, &out);

    // Now it is a neighbour, the request is spent, and nothing is sent back:
    // a reply that were treated as a request would ping-pong forever.
    try t.expectEqual(@as(usize, 1), state.activeView().len);
    try t.expect(sameNode(state.activeView()[0], peer));
    try t.expectEqual(@as(usize, 0), state.pending_neighbor_requests.count());
    try t.expectEqual(@as(usize, 1), out.count());
    try t.expect(out.at(0) == .emit_event);
    try t.expect(out.at(0).emit_event == .neighbor_up);
}

// The whole exchange between two nodes, and the shape it leaves behind.
test "the active view is bidirectional once the neighbor exchange finishes" {
    const left_index: u8 = 2;
    const right_index: u8 = 3;
    const left_id = try sim.nodeIdFor(left_index);
    const right_id = try sim.nodeIdFor(right_index);
    var left: State = try newMembership(left_index, .{}, 1);
    var right: State = try newMembership(right_index, .{}, 2);
    var out: Actions(SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();

    // Left asks right. Left's view is empty, right's too, and neither knows
    // the other is a neighbour yet.
    try prime(&left, &out);
    try stateNeighborRequest(&left, right_id, &out);
    try t.expectEqual(@as(usize, 0), left.activeView().len);
    try t.expectEqual(@as(usize, 0), right.activeView().len);

    // Right receives it, cannot know it is a reply, so it accepts and answers.
    try prime(&right, &out);
    const ask: Neighbor = .{ .priority = .high, .data = null };
    try right.handle(.{ .recv_message = .{
        .from = left_id,
        .message = .{ .neighbor = ask },
    } }, &out);
    try t.expectEqual(@as(usize, 1), right.activeView().len);
    try t.expect(sameNode(right.activeView()[0], left_id));
    // The neighbour is reported, and the request is answered.
    try t.expectEqual(@as(usize, 2), out.count());
    try t.expect(out.at(0) == .emit_event);
    try t.expect(out.at(0).emit_event == .neighbor_up);
    try t.expect(sameNode(out.at(0).emit_event.neighbor_up, left_id));
    try t.expect(out.at(1) == .send_message);
    try t.expect(out.at(1).send_message.message == .neighbor);
    try t.expect(sameNode(out.at(1).send_message.to, left_id));

    // The asymmetry exists only between the two events. Left takes the reply
    // as the answer to its own request and both views agree.
    out.clear();
    const reply: Neighbor = .{ .priority = .high, .data = null };
    try left.handle(.{ .recv_message = .{
        .from = right_id,
        .message = .{ .neighbor = reply },
    } }, &out);
    try t.expectEqual(@as(usize, 1), left.activeView().len);
    try t.expect(sameNode(left.activeView()[0], right_id));
    try t.expectEqual(@as(usize, 1), right.activeView().len);
    try t.expectEqual(@as(usize, 0), left.pending_neighbor_requests.count());
    // The only thing left is the report: a reply is not answered, or the two
    // would trade `Neighbor` messages for as long as both were alive.
    try t.expectEqual(@as(usize, 1), out.count());
    try t.expect(out.at(0) == .emit_event);
    try t.expect(out.at(0).emit_event == .neighbor_up);
    try t.expect(sameNode(out.at(0).emit_event.neighbor_up, right_id));

    // Upstream leaves the *asker's* own request outstanding on the other side:
    // the reply satisfies the pending set of whoever sent the Neighbor, and
    // nothing ever tells the sender that its request landed. The pending timer
    // is what clears it, and clearing it must not drop a working neighbour.
    try t.expectEqual(@as(usize, 1), right.pending_neighbor_requests.count());
    out.clear();
    try right.handle(.{ .timer_expired = .{ .pending_neighbor_request = left_id } }, &out);
    try t.expectEqual(@as(usize, 0), right.pending_neighbor_requests.count());
    try t.expectEqual(@as(usize, 1), right.activeView().len);
    try t.expect(sameNode(right.activeView()[0], left_id));
}

/// Put the membership state in the position the deviation creates: a peer it
/// wants as a neighbour, and no evidence it can be reached.
fn stateNeighborRequest(
    state: *State,
    peer: NodeId,
    out: *Actions(SwarmOutEvent),
) !void {
    const walker = try sim.nodeIdFor(1);
    try state.handle(.{ .recv_message = .{ .from = walker, .message = .{ .forward_join = .{
        .peer = .{ .id = peer, .data = null },
        .ttl = .{ .value = 0 },
    } } } }, out);
    try t.expectEqual(@as(usize, 0), state.activeView().len);
}

// A `Neighbor` nobody asked for is answered, because the other end has no way
// to know it is a reply.
test "a neighbor we did not ask for is answered" {
    const peer = try sim.nodeIdFor(3);
    var state: State = try newMembership(2, .{}, 13);
    var out: Actions(SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    try prime(&state, &out);

    try state.handle(.{ .recv_message = .{ .from = peer, .message = .{ .neighbor = .{
        .priority = .high,
        .data = null,
    } } } }, &out);

    try t.expectEqual(@as(usize, 1), state.activeView().len);
    try t.expectEqual(@as(usize, 2), out.count());
    try t.expect(out.at(0) == .emit_event);
    try t.expect(out.at(0).emit_event == .neighbor_up);
    try t.expect(out.at(1) == .send_message);
    try t.expect(out.at(1).send_message.message == .neighbor);
    try t.expect(sameNode(out.at(1).send_message.to, peer));
    try t.expect(state.pending_neighbor_requests.contains(peer));
}

// A low-priority request into a full view is refused, and refused *properly*:
// a `Disconnect` and a link teardown, not silence.
test "a low-priority neighbor is refused when the view is full" {
    const first = try sim.nodeIdFor(2);
    const second = try sim.nodeIdFor(3);
    var state: State = try newMembership(1, .{ .active_view_capacity = 1 }, 17);
    var out: Actions(SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    try prime(&state, &out);

    try state.handle(.{ .recv_message = .{ .from = first, .message = .{ .neighbor = .{
        .priority = .high,
        .data = null,
    } } } }, &out);
    out.clear();
    try t.expectEqual(@as(usize, 1), state.activeView().len);

    try state.handle(.{ .recv_message = .{ .from = second, .message = .{ .neighbor = .{
        .priority = .low,
        .data = null,
    } } } }, &out);

    // A ShuffleReply so the refused node does not lose its own contacts, the
    // Disconnect, and the teardown — and then the teardown the "not an active
    // view member" rule asks for as well, because a refused peer was never
    // going to be one. Four actions, in that order.
    try t.expectEqual(@as(usize, 4), out.count());
    try t.expect(out.at(0) == .send_message);
    try t.expect(out.at(0).send_message.message == .shuffle_reply);
    try t.expect(sameNode(out.at(0).send_message.to, second));
    try t.expect(out.at(1) == .send_message);
    try t.expect(out.at(1).send_message.message == .disconnect);
    try t.expect(out.at(1).send_message.message.disconnect.alive);
    try t.expect(out.at(2) == .disconnect_peer);
    try t.expect(sameNode(out.at(2).disconnect_peer, second));
    try t.expect(out.at(3) == .disconnect_peer);
    try t.expect(sameNode(out.at(3).disconnect_peer, second));

    // The view is untouched: a refused peer is not a neighbour.
    try t.expectEqual(@as(usize, 1), state.activeView().len);
    try t.expect(sameNode(state.activeView()[0], first));
}

// A high-priority request into a full view evicts somebody, and the evicted
// peer is told with a `Disconnect` and kept in the passive view.
test "a high-priority neighbor evicts and the evicted peer is told" {
    const first = try sim.nodeIdFor(2);
    const second = try sim.nodeIdFor(3);
    var state: State = try newMembership(1, .{ .active_view_capacity = 1 }, 19);
    var out: Actions(SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    try prime(&state, &out);

    try state.handle(.{ .recv_message = .{ .from = first, .message = .{ .neighbor = .{
        .priority = .high,
        .data = null,
    } } } }, &out);
    out.clear();
    try state.handle(.{ .recv_message = .{ .from = second, .message = .{ .neighbor = .{
        .priority = .high,
        .data = null,
    } } } }, &out);

    // NeighborDown for the evicted peer, a shuffle reply and a disconnect to
    // it, a NeighborUp for the new one, and a Neighbor back to it.
    var saw_down = false;
    var saw_disconnect_to_first = false;
    var saw_up = false;
    for (out.slice()) |produced| switch (produced) {
        .emit_event => |change| switch (change) {
            .neighbor_down => |gone| saw_down = sameNode(gone, first),
            .neighbor_up => |arrived| saw_up = sameNode(arrived, second),
        },
        .send_message => |send| {
            if (send.message == .disconnect and sameNode(send.to, first)) {
                saw_disconnect_to_first = true;
            }
        },
        else => {},
    };
    try t.expect(saw_down);
    try t.expect(saw_up);
    try t.expect(saw_disconnect_to_first);
    try t.expectEqual(@as(usize, 1), state.activeView().len);
    try t.expect(sameNode(state.activeView()[0], second));
    // Kept, because the peer is alive and we only dropped it for room.
    try t.expect(state.passiveView().len >= 1);
}

// A `Neighbor` that is never answered times out, and the peer it was aimed at
// is dropped from the passive view.
test "a neighbor request that is never answered gives the peer up" {
    const reachable = try sim.nodeIdFor(2);
    const stale = try sim.nodeIdFor(3);
    var state: State = try newMembership(1, .{}, 23);
    var out: Actions(SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    try prime(&state, &out);

    // A shuffle reply hands us two passive peers and nothing else, so the
    // refill has somewhere to aim.
    const gifter = try sim.nodeIdFor(9);
    try state.handle(.{ .recv_message = .{ .from = gifter, .message = .{ .shuffle_reply = .{
        .nodes = try PeerInfos.init(&.{
            .{ .id = reachable, .data = null },
            .{ .id = stale, .data = null },
        }),
    } } } }, &out);
    out.clear();
    try t.expectEqual(@as(usize, 2), state.passiveView().len);
    try state.handle(.{ .timer_expired = .do_shuffle }, &out);
    out.clear();

    // The shuffle timer found an active peer to aim at only if the view was
    // non-empty; force the situation by asking for a neighbour directly.
    const walker = try sim.nodeIdFor(8);
    try state.handle(.{ .recv_message = .{ .from = walker, .message = .{ .forward_join = .{
        .peer = .{ .id = reachable, .data = null },
        .ttl = .{ .value = 0 },
    } } } }, &out);
    out.clear();
    try t.expect(state.pending_neighbor_requests.contains(reachable));
    try t.expectEqual(@as(usize, 0), state.activeView().len);

    // The timer fires and the peer is given up, without any evidence it was
    // ever a neighbour.
    try state.handle(.{ .timer_expired = .{ .pending_neighbor_request = reachable } }, &out);
    try t.expect(!state.pending_neighbor_requests.contains(reachable));
    try t.expectEqual(@as(usize, 0), state.activeView().len);
    try t.expect(!containsNode(state.passiveView(), reachable));
}

// A direct `Join` is the paper's rule and is inserted eagerly: the peer
// reached us over a connection it already has, so there is nothing to prove.
test "a direct join is inserted, and the walk it starts is forwarded" {
    const contact = try sim.nodeIdFor(2);
    const already = try sim.nodeIdFor(3);
    var state: State = try newMembership(1, .{}, 29);
    var out: Actions(SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    try prime(&state, &out);

    try state.handle(.{ .recv_message = .{ .from = already, .message = .{ .neighbor = .{
        .priority = .high,
        .data = null,
    } } } }, &out);
    out.clear();
    try state.handle(.{ .recv_message = .{ .from = contact, .message = .{ .join = null } } }, &out);

    // The new node is in the active view, and every *other* active node is
    // told about it, which is rule 7 and the start of the walk.
    var saw_up = false;
    var forwarded: usize = 0;
    for (out.slice()) |produced| switch (produced) {
        .emit_event => |change| {
            if (change == .neighbor_up and sameNode(change.neighbor_up, contact)) saw_up = true;
        },
        .send_message => |send| {
            if (send.message == .forward_join and sameNode(send.to, already)) {
                forwarded += 1;
                try t.expect(sameNode(send.message.forward_join.peer.id, contact));
                try t.expectEqual(
                    state.config.active_random_walk_length.value,
                    send.message.forward_join.ttl.value,
                );
            }
        },
        else => {},
    };
    try t.expect(saw_up);
    try t.expectEqual(@as(usize, 1), forwarded);
    try t.expectEqual(@as(usize, 2), state.activeView().len);
}

// A message from a peer that is not in the active view is followed by a
// teardown, which is upstream's own "I am not sure this is correct" comment
// kept as behaviour because the simulator is compared against it.
test "a message from a passive peer ends with a teardown" {
    const stranger = try sim.nodeIdFor(4);
    var state: State = try newMembership(1, .{}, 31);
    var out: Actions(SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    try prime(&state, &out);

    // A `Shuffle` rather than a `Join`: a join is answered by inserting, and
    // an inserted sender is not torn down.
    try state.handle(.{ .recv_message = .{ .from = stranger, .message = .{ .shuffle = .{
        .origin = stranger,
        .nodes = try PeerInfos.init(&.{}),
        .ttl = .{ .value = 0 },
    } } } }, &out);
    var tore_down = false;
    for (out.slice()) |produced| {
        if (produced == .disconnect_peer and sameNode(produced.disconnect_peer, stranger)) {
            tore_down = true;
        }
    }
    try t.expect(tore_down);
}

// The shuffle timer is armed on the first call whatever that call was, and
// only once. It is in `handle` rather than the constructor in upstream, and
// moving it changes when a node with no traffic ever shuffles.
test "the shuffle timer is armed once, on the first call" {
    var state: State = try newMembership(1, .{}, 37);
    var out: Actions(SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();

    try state.handle(.{ .update_peer_data = PeerData{} }, &out);
    try t.expectEqual(@as(usize, 1), out.count());
    try t.expect(out.at(0) == .schedule_timer);
    try t.expect(out.at(0).schedule_timer.timer == .do_shuffle);
    try t.expectEqual(state.config.shuffle_interval, out.at(0).schedule_timer.after);

    out.clear();
    try state.handle(.{ .update_peer_data = PeerData{} }, &out);
    try t.expectEqual(@as(usize, 0), out.count());
}

// A `Quit` disconnects every neighbour and leaves the view empty.
test "a quit disconnects every neighbour" {
    const first = try sim.nodeIdFor(2);
    const second = try sim.nodeIdFor(3);
    var state: State = try newMembership(1, .{}, 41);
    var out: Actions(SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    try prime(&state, &out);

    try state.handle(.{ .recv_message = .{ .from = first, .message = .{ .neighbor = .{
        .priority = .high,
        .data = null,
    } } } }, &out);
    try state.handle(.{ .recv_message = .{ .from = second, .message = .{ .neighbor = .{
        .priority = .high,
        .data = null,
    } } } }, &out);
    out.clear();
    try state.handle(.quit, &out);

    try t.expectEqual(@as(usize, 0), state.activeView().len);
    var disconnects: usize = 0;
    for (out.slice()) |produced| switch (produced) {
        .send_message => |send| {
            if (send.message == .disconnect) {
                disconnects += 1;
                // A quit is not an eviction: we are leaving, not staying
                // without them.
                try t.expect(!send.message.disconnect.alive);
            }
        },
        else => {},
    };
    try t.expectEqual(@as(usize, 2), disconnects);
}

// A `TopicId` is 32 bytes the application chose. There is no derivation and no
// scope, and a test that pinned a derived one would be pinning a scheme this
// module deliberately does not have.
test "a topic id is 32 opaque bytes and nothing more" {
    try t.expectEqual(@as(usize, 32), topic_id_length);
    try t.expectEqual(@as(usize, 32), @sizeOf(TopicId));
    const zero = [_]u8{0} ** topic_id_length;
    var one = [_]u8{0} ** topic_id_length;
    one[0] = 1;
    const left = TopicId.fromBytes(one);
    const right = TopicId.fromBytes(zero);
    try t.expect(left.eql(TopicId.fromBytes(one)));
    try t.expect(!left.eql(right));
    try t.expectEqual(std.math.Order.gt, left.order(right));
    try t.expectEqualStrings("0100000000", &left.shortHex());
}

// Contact data is bounded, and the bound is reported rather than truncated.
test "contact data over the bound is refused" {
    const long = try t.allocator.alloc(u8, peer_data_max + 1);
    defer t.allocator.free(long);
    @memset(long, 0x11);
    try t.expectError(error.PeerDataTooLong, PeerData.fromBytes(long));
    // A length the length field cannot spell is refused the same way, by the
    // narrowing rather than by a trap in it.
    const unspellable = try t.allocator.alloc(u8, std.math.maxInt(u16) + 1);
    defer t.allocator.free(unspellable);
    @memset(unspellable, 0x33);
    try t.expectError(error.PeerDataTooLong, PeerData.fromBytes(unspellable));
    const exact = try t.allocator.alloc(u8, peer_data_max);
    defer t.allocator.free(exact);
    @memset(exact, 0x22);
    const data = try PeerData.fromBytes(exact);
    try t.expectEqual(peer_data_max, data.slice().len);
    try t.expectEqual(@as(usize, 0), (try PeerData.fromBytes(&.{})).slice().len);
}

// The contact table proves the same bound at the copy, where nothing above it
// has: the slice is a peer's claim about itself, and a message is not obliged
// to be short.
test "the contact table refuses what a record cannot spell" {
    var map: PeerDataMap = .{};
    const peer = try sim.nodeIdFor(2);
    // One byte over the ceiling, and still a length a `u16` spells: only the
    // comparison refuses this one, so only the comparison keeps the copy in
    // bounds.
    const over = try t.allocator.alloc(u8, peer_data_max + 1);
    defer t.allocator.free(over);
    @memset(over, 0x44);
    try t.expectError(error.PeerDataTooLong, map.put(peer, over));
    // A length the length field cannot spell is refused by the narrowing, and
    // not by a trap in it.
    const unspellable = try t.allocator.alloc(u8, std.math.maxInt(u16) + 1);
    defer t.allocator.free(unspellable);
    @memset(unspellable, 0x55);
    try t.expectError(error.PeerDataTooLong, map.put(peer, unspellable));
    // Nothing refused left a half-written entry behind, and the ceiling is a
    // length rather than a hint.
    try t.expectEqual(@as(usize, 0), map.count());
    const exact = try t.allocator.alloc(u8, peer_data_max);
    defer t.allocator.free(exact);
    @memset(exact, 0x66);
    try map.put(peer, exact);
    try t.expectEqualSlices(u8, exact, map.get(peer).?.slice());
}

/// Fill a frame big enough to cover whatever the reader below unwound, so a
/// slice into a dead frame reads back as poison instead of as the bytes it
/// happened to leave behind. `never_inline` is load-bearing: an inlined
/// helper would poison the caller's own live locals rather than the dead
/// region.
fn clobberStack() void {
    var poison: [2048]u8 = undefined;
    @memset(&poison, 0xcd);
    std.mem.doNotOptimizeAway(&poison);
}

// The contact data a node advertises is read into a frame, and the messages it
// goes into outlive that frame. Reading it back with nothing in between finds
// the right bytes either way, which is why this needs a frame in between to
// tell the two apart.
test "a node's own contact data outlives the frame it was read in" {
    var state = try State.init(
        try sim.nodeIdFor(0),
        try PeerData.fromBytes("41234"),
        .{},
        Rng.init(1),
    );
    // `never_inline` on the read as well as the clobber: inlined, the frame
    // this test is about would be this test's own and the poison would miss
    // it. The same shape as `CustomAddr` in `src/base/addr.zig`.
    const seen = @call(.never_inline, State.myData, .{&state});
    @call(.never_inline, clobberStack, .{});

    // Snapshot with no call in between: the assertion is a call, and its frame
    // lands on the region this test exists to inspect. `orelse` is a branch and
    // not a call, so capturing the optional here costs the read nothing.
    const borrowed = seen orelse return error.TestUnexpectedResult;
    const held = [_]u8{ borrowed[0], borrowed[1], borrowed[2], borrowed[3], borrowed[4] };
    try t.expectEqualSlices(u8, "41234", &held);

    // A node with no contact data says so, and says it from the address rather
    // than from a copy that happens to be empty.
    var bare = try State.init(try sim.nodeIdFor(1), null, .{}, Rng.init(2));
    try t.expectEqual(@as(?[]const u8, null), @call(.never_inline, State.myData, .{&bare}));
}

// A bootstrap list is bounded twice: by what a `u8` can count, and by
// `max_bootstrap`. Either half on its own would let the other one past.
test "a bootstrap list is refused by its count and by its length" {
    const peer = try sim.nodeIdFor(2);
    const over = [_]NodeId{peer} ** (max_bootstrap + 1);
    const unspellable = [_]NodeId{peer} ** (std.math.maxInt(u8) + 1);
    try t.expectError(error.BootstrapListTooLong, Peers.init(over[0..]));
    try t.expectError(error.BootstrapListTooLong, Peers.init(unspellable[0..]));
    const list = try Peers.init(over[0..max_bootstrap]);
    try t.expectEqual(max_bootstrap, list.slice().len);
}

// A config the fixed-capacity sets cannot hold is refused up front.
test "a config beyond the fixed views is refused" {
    try t.expectError(
        error.ActiveViewFull,
        (Config{ .active_view_capacity = max_active + 1 }).validate(),
    );
    try t.expectError(
        error.PassiveViewFull,
        (Config{ .passive_view_capacity = max_passive + 1 }).validate(),
    );
    try t.expectError(
        error.ShuffleNodeListTooLong,
        (Config{ .shuffle_active_view_count = max_shuffle_nodes }).validate(),
    );
    try (Config{}).validate();
}

// ---------------------------------------------------------------------------
// The simulator
// ---------------------------------------------------------------------------

/// Feed one byte to a running digest, so a run can be fingerprinted without
/// being printed.
fn fold(hasher: anytype, value: u8) void {
    var one = [_]u8{value};
    hasher.update(&one);
}

/// A whole run, reduced to a digest: every neighbour change in order, then
/// every node's active view. Two runs agree exactly when these agree.
fn runDigest(seed: u64, peers: u8) sim.HarnessError![32]u8 {
    var simulator: sim.Simulator = try sim.Simulator.init(t.allocator, .{
        .rng_seed = seed,
        .peers = peers,
    }, .{
        .latency = .default_fixed,
        .membership = .{ .active_view_capacity = 3 },
    });
    defer simulator.deinit();
    try simulator.bootstrap(.single);
    var buffer: [sim.max_neighbour_events]sim.NeighbourEvent = undefined;
    var hasher = std.crypto.hash.Blake3.init(.{});
    for (simulator.network.neighbourEvents(&buffer)) |event| {
        fold(&hasher, event.a);
        fold(&hasher, event.b);
        fold(&hasher, @intFromBool(event.up));
    }
    var found: [sim.max_peers]u8 = undefined;
    var index: u8 = 0;
    while (index < peers) : (index += 1) {
        const count = simulator.network.neighborIndices(index, &found);
        fold(&hasher, @intCast(count));
        for (found[0..count]) |neighbour| fold(&hasher, neighbour);
    }
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

fn sameEvents(got: []const sim.NeighbourEvent, want: []const sim.NeighbourEvent) bool {
    if (got.len != want.len) return false;
    for (got, want) |a, b| {
        if (a.a != b.a or a.b != b.b or a.up != b.up) return false;
    }
    return true;
}

fn countReceived(events: []const sim.SimEvent) usize {
    var count: usize = 0;
    for (events) |event| {
        if (event.event == .received) count += 1;
    }
    return count;
}

fn joinOf(peers: []const NodeId) sim.HarnessError!Command {
    return .{ .join = try Peers.init(peers) };
}

// Upstream `proto::test::hyparview_smoke`: four nodes, an active view of two,
// a fixed latency, and three join commands. The expected neighbour events and
// the three surviving links are upstream's own assertions, captured from
// `proto.rs` at the commit named at the top of this file.
test "four nodes converge on the three links upstream does" {
    var simulator: sim.Simulator = try sim.Simulator.init(t.allocator, .{
        .rng_seed = 0,
        .peers = 4,
    }, .{
        .latency = .default_fixed,
        .membership = .{ .active_view_capacity = 2 },
    });
    defer simulator.deinit();
    const network = &simulator.network;
    var index: u8 = 0;
    while (index < 4) : (index += 1) try network.insert(index);

    try network.command(0, try joinOf(&.{ try sim.nodeIdFor(1), try sim.nodeIdFor(2) }));
    try network.command(1, try joinOf(&.{try sim.nodeIdFor(2)}));
    try network.command(2, try joinOf(&.{}));
    try network.runTrips(3);

    var buffer: [sim.max_neighbour_events]sim.NeighbourEvent = undefined;
    const expected = [_]sim.NeighbourEvent{
        .{ .up = true, .a = 0, .b = 1 },
        .{ .up = true, .a = 0, .b = 2 },
        .{ .up = true, .a = 1, .b = 0 },
        .{ .up = true, .a = 1, .b = 2 },
        .{ .up = true, .a = 2, .b = 0 },
        .{ .up = true, .a = 2, .b = 1 },
    };
    try t.expect(sameEvents(network.neighbourEvents(&buffer), &expected));
    try t.expectEqual(@as(usize, 3), network.conns().len);
    try t.expect(network.checkSynchronicity());
    // Node 3 was inserted but never asked to join, so it is in no view.
    try t.expectEqual(@as(usize, 0), network.neighborCount(3));
}

// The rest of upstream's `hyparview_smoke`: a fourth node joins a full view.
// Upstream accepts either outcome, because which peer node 0 drops is a
// random choice, and asserts the connections and the synchrony either way.
test "a node joining a full view evicts one peer, either one, and stays synchronous" {
    var simulator: sim.Simulator = try sim.Simulator.init(t.allocator, .{
        .rng_seed = 0,
        .peers = 4,
    }, .{
        .latency = .default_fixed,
        .membership = .{ .active_view_capacity = 2 },
    });
    defer simulator.deinit();
    const network = &simulator.network;
    var index: u8 = 0;
    while (index < 4) : (index += 1) try network.insert(index);
    try network.command(0, try joinOf(&.{ try sim.nodeIdFor(1), try sim.nodeIdFor(2) }));
    try network.command(1, try joinOf(&.{try sim.nodeIdFor(2)}));
    try network.command(2, try joinOf(&.{}));
    try network.runTrips(3);

    network.events.clearRetainingCapacity();
    try network.command(3, try joinOf(&.{try sim.nodeIdFor(0)}));
    try network.runTrips(2);

    // The two possible neighbour-event lists, as upstream writes them. The
    // eviction is random; the shape is not.
    const kept_one = [_]sim.NeighbourEvent{
        .{ .up = false, .a = 0, .b = 1 },
        .{ .up = true, .a = 0, .b = 3 },
        .{ .up = false, .a = 1, .b = 0 },
        .{ .up = true, .a = 3, .b = 0 },
    };
    const kept_two = [_]sim.NeighbourEvent{
        .{ .up = false, .a = 0, .b = 2 },
        .{ .up = true, .a = 0, .b = 3 },
        .{ .up = false, .a = 2, .b = 0 },
        .{ .up = true, .a = 3, .b = 0 },
    };
    var buffer: [sim.max_neighbour_events]sim.NeighbourEvent = undefined;
    const events = network.neighbourEvents(&buffer);
    try t.expect(sameEvents(events, &kept_one) or sameEvents(events, &kept_two));

    try t.expect(network.hasNeighbor(0, 3));
    try t.expect(network.hasNeighbor(3, 0));
    try t.expectEqual(@as(usize, 3), network.conns().len);
    try t.expect(network.checkSynchronicity());
}

// Upstream `proto::test::quit`: a chain of four joins, then the last one
// leaves, and everybody else is still connected to somebody.
test "a node that quits leaves the swarm and the rest stay connected" {
    var simulator: sim.Simulator = try sim.Simulator.init(t.allocator, .{
        .rng_seed = 0,
        .peers = 4,
    }, .{
        .latency = .default_fixed,
        .membership = .{ .active_view_capacity = 2 },
    });
    defer simulator.deinit();
    const network = &simulator.network;
    var index: u8 = 0;
    while (index < 4) : (index += 1) try network.insert(index);
    try network.command(0, try joinOf(&.{}));
    try network.command(1, try joinOf(&.{try sim.nodeIdFor(0)}));
    try network.command(2, try joinOf(&.{try sim.nodeIdFor(1)}));
    try network.command(3, try joinOf(&.{try sim.nodeIdFor(2)}));
    try network.runTrips(2);

    var seen = [_]bool{false} ** sim.max_peers;
    index = 0;
    while (index < 4) : (index += 1) {
        for (network.neighbors(index)) |neighbour| {
            const found = network.peerIndexOf(neighbour) orelse return error.TestUnexpectedResult;
            seen[found] = true;
        }
    }
    for (seen[0..4]) |present| try t.expect(present);
    try t.expect(network.checkSynchronicity());

    try network.command(3, .quit);
    try network.runTrips(4);

    // Upstream asserts the topic state is gone, which here is the node no
    // longer counting as joined and no longer holding a link.
    try t.expect(!network.hasJoined(3));
    try t.expectEqual(@as(usize, 0), network.neighborCount(3));
    var after = [_]bool{false} ** sim.max_peers;
    index = 0;
    while (index < 3) : (index += 1) {
        for (network.neighbors(index)) |neighbour| {
            const found = network.peerIndexOf(neighbour) orelse return error.TestUnexpectedResult;
            after[found] = true;
        }
    }
    try t.expect(after[0]);
    try t.expect(after[1]);
    try t.expect(after[2]);
    try t.expect(!after[3]);
    try t.expect(network.checkSynchronicity());
}

// Upstream `proto::test::plumtree_smoke`: six nodes in two components, a
// broadcast that reaches two nodes, the components joined, and a broadcast
// that then reaches all five others.
test "a broadcast reaches the whole swarm, once the halves are joined" {
    var simulator: sim.Simulator = try sim.Simulator.init(t.allocator, .{
        .rng_seed = 0,
        .peers = 6,
    }, .{
        .latency = .default_fixed,
        .membership = .{ .active_view_capacity = 3 },
    });
    defer simulator.deinit();
    const network = &simulator.network;
    var index: u8 = 0;
    while (index < 6) : (index += 1) try network.insert(index);

    try network.command(0, try joinOf(&.{}));
    try network.command(1, try joinOf(&.{try sim.nodeIdFor(0)}));
    try network.command(2, try joinOf(&.{try sim.nodeIdFor(0)}));
    try network.command(3, try joinOf(&.{}));
    try network.command(4, try joinOf(&.{try sim.nodeIdFor(3)}));
    try network.command(5, try joinOf(&.{try sim.nodeIdFor(3)}));
    try network.runTrips(4);
    network.events.clearRetainingCapacity();
    try t.expect(network.checkSynchronicity());

    // In the half node 1 is in, two others.
    try network.command(1, .{ .broadcast = .{ .content = "hi1", .scope = .swarm } });
    try network.runTrips(4);
    try t.expectEqual(@as(usize, 2), countReceived(network.events.items));
    try t.expect(network.checkSynchronicity());

    // Join the two halves and broadcast again.
    network.events.clearRetainingCapacity();
    try network.command(2, try joinOf(&.{try sim.nodeIdFor(5)}));
    try network.runTrips(3);
    network.events.clearRetainingCapacity();
    try network.command(1, .{ .broadcast = .{ .content = "hi2", .scope = .swarm } });
    try network.runTrips(5);
    try t.expectEqual(@as(usize, 5), countReceived(network.events.items));
    try t.expect(network.checkSynchronicity());
}

// The plan's bar: two or more nodes agree on membership, which is a property
// of a network and not of any one state machine. Every node is connected, and
// every link is held by both ends.
test "a bootstrapped swarm converges: nobody is alone, and the disagreement stops" {
    var simulator: sim.Simulator = try sim.Simulator.init(t.allocator, .{
        .rng_seed = 7,
        .peers = 8,
    }, .{
        .latency = .default_drawn,
        .membership = .{ .active_view_capacity = 3 },
    });
    defer simulator.deinit();
    try simulator.bootstrap(.single);

    // Upstream's own bar for a bootstrapped swarm: nobody is left with no
    // neighbours at all. That is the assertion `big_hyparview` makes, and it
    // is the one a node that never joined would fail.
    try t.expectEqual(@as(usize, 0), simulator.network.peersWithoutNeighbors());
    const extent = simulator.network.activeExtent();
    try t.expect(extent.max <= 3);
    try t.expect(extent.min >= 1);

    // Convergence, as opposed to merely being non-empty: the run keeps going
    // with nothing left to join, and the disagreement count does not grow. A
    // swarm that kept acquiring one-sided links would be failing, and one
    // that had acquired some and stopped would be merely unlucky — which is
    // upstream's position and is written down in `asymmetricLinks`.
    const early = simulator.network.asymmetricLinks();
    try simulator.network.runTrips(40);
    try t.expectEqual(@as(usize, 0), simulator.network.peersWithoutNeighbors());
    try t.expectEqual(early, simulator.network.asymmetricLinks());

    // And the broadcast built on top of that membership reaches every other
    // node exactly once, without disturbing the membership it was built on.
    const settled = simulator.network.asymmetricLinks();
    const stats = try simulator.gossipRound(0, "hello");
    try t.expectEqual(stats.expected, stats.delivered);
    try t.expectEqual(@as(usize, 0), stats.duplicated);
    try t.expectEqual(settled, simulator.network.asymmetricLinks());
}

// The same run twice, from the same seed, is the same run. Upstream's
// simulator cannot say this: its pending-request and alive-disconnect sets
// are hash sets on a per-process seed, and it iterates one of them.
test "the same seed gives the same run, byte for byte" {
    const first = try runDigest(0x5eed, 8);
    const second = try runDigest(0x5eed, 8);
    try t.expectEqualSlices(u8, &first, &second);
}

// And the seed is what makes it so: a different seed is a different run, and
// an unseeded one would be a different run every time.
test "a different seed is a different run" {
    const first = try runDigest(1, 8);
    const second = try runDigest(2, 8);
    try t.expect(!std.mem.eql(u8, &first, &second));
}

// The second bootstrap mode: a core forms first, then everybody else joins a
// random core member. Same convergence, different topology.
test "a core bootstrap converges the same way" {
    var simulator: sim.Simulator = try sim.Simulator.init(t.allocator, .{
        .rng_seed = 3,
        .peers = 8,
    }, .{
        .latency = .default_drawn,
        .membership = .{ .active_view_capacity = 3 },
    });
    defer simulator.deinit();
    try simulator.bootstrap(.{ .core = 3 });
    try t.expectEqual(@as(usize, 0), simulator.network.peersWithoutNeighbors());
    const early = simulator.network.asymmetricLinks();
    try simulator.network.runTrips(40);
    try t.expectEqual(@as(usize, 0), simulator.network.peersWithoutNeighbors());
    try t.expectEqual(early, simulator.network.asymmetricLinks());
}

// The harness refuses what it cannot hold, rather than quietly truncating.
test "the simulator refuses a thirteenth node and a duplicate" {
    var simulator: sim.Simulator = try sim.Simulator.init(t.allocator, .{
        .rng_seed = 0,
        .peers = 2,
    }, .{ .latency = .default_fixed });
    defer simulator.deinit();
    try simulator.network.insert(0);
    try t.expectError(error.DuplicatePeer, simulator.network.insert(0));
    try t.expectError(error.PeerIndexOutOfRange, simulator.network.insert(sim.max_peers));
}

// The simulator's identities are a fixture, and a fixture that quietly
// produced the same node twice would turn every convergence assertion into a
// tautology. This walks the whole index range, so a degenerate seed panics
// here rather than passing.
test "every simulated node has its own identity" {
    var index: u8 = 0;
    while (index < sim.max_peers) : (index += 1) {
        const mine = try sim.nodeIdFor(index);
        try t.expect(sameNode(mine, try sim.nodeIdFor(index)));
        var other: u8 = 0;
        while (other < sim.max_peers) : (other += 1) {
            if (other == index) continue;
            try t.expect(!sameNode(mine, try sim.nodeIdFor(other)));
        }
    }
}
