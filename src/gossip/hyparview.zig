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
//! Two layers, in dependency order:
//!
//! 1. `State`, the membership state machine. Two views, a pending-request set,
//!    a table of peers' contact data, and a caller-seeded generator.
//! 2. `TopicState`, the composition: HyParView for membership and
//!    `plumtree.State` for broadcast, with the event ordering that couples
//!    them. This is upstream's `proto/topic.rs`.
//!
//! The third layer is gone from here. `sim` — upstream's `proto/sim.rs`, a
//! discrete-event in-process network that runs both layers — and the
//! whole-swarm runs that decide whether this module agrees with the reference
//! now live in `hyparview_sim_tests.zig`, with the state machines' own tests
//! in `hyparview_tests.zig`. It left because it allocates: a harness holding
//! `std.ArrayList`s, an arena and a link table would make the promise below a
//! claim about most of this file rather than about all of it, and a promise a
//! reader has to check line by line is not a promise.
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
//! container the caller hands in. That holds for every declaration in this
//! file, which is why the simulator that does allocate is a sibling rather
//! than a namespace here: a reader of this file is reading two state
//! machines, and `hyparview_sim_tests.zig` is where the harness lives.

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
///
/// Named rather than private because `State.peer_data` is a public field, and a
/// field whose type cannot be spelled from another file is a field a caller
/// cannot read, build or hand back. The claim that needs that — that the copy
/// bound is enforced at the table and not only in the codec — is proved by a
/// test that constructs the table itself, in `hyparview_tests.zig`. `Entry`
/// stays private: the bound is what a caller needs, not the slot layout.
pub const PeerDataMap = struct {
    const Entry = struct { peer: NodeId, data: PeerData };

    entries: [max_known_peers]Entry = undefined,
    len: usize = 0,

    pub fn count(self: *const PeerDataMap) usize {
        return self.len;
    }

    /// Forget every peer's contact data. The `PeerData` values in the slots
    /// past `len` are copies this table took, and `get` reads only the live
    /// prefix, so forgetting the entry is what stops this state from offering
    /// that data again.
    pub fn clear(self: *PeerDataMap) void {
        self.len = 0;
    }

    pub fn get(self: *const PeerDataMap, peer: NodeId) ?*const PeerData {
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
    pub fn put(self: *PeerDataMap, peer: NodeId, data: []const u8) Error!void {
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

        /// Forget every peer. Slots past `len` keep their ids and are never
        /// read again.
        pub fn clear(self: *Self) void {
            self.len = 0;
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
    /// This node's identity, fixed by `init`. A `Join` naming it is refused and
    /// an active view holding it is impossible, so writing it after `init`
    /// changes which peers this node will connect to. Zig fields are not
    /// private — this one is fixed by convention and by `init`, not by the
    /// language.
    me: NodeId,
    /// This node's own contact data, fixed by `init`; `null` and an empty
    /// `PeerData` both mean *advertise nothing*, and `myData` sends no slice
    /// either way. The bytes are stored by value in this `PeerData` — a
    /// `PeerData.fromBytes` copied them on the way in — so the caller keeps no
    /// claim on them and need not keep its own copy alive.
    ///
    /// A `Neighbor`, `Join` or `Shuffle` this state sends borrows these bytes,
    /// so the one call that invalidates an `out` entry holding such a slice is
    /// the next `.update_peer_data` event: it writes this record in place. No
    /// other event touches it, and `left` keeps it.
    me_data: ?PeerData,
    /// Peers we are connected to. Insertion-ordered, as upstream's.
    active_view: IndexSet(max_active) = .{},
    /// Peers we know about and are not connected to.
    passive_view: IndexSet(max_passive) = .{},
    /// View capacities, shuffle and walk sizes and every timeout, fixed by
    /// `init`, which validates them once and does not validate them again. It
    /// is read per event — every view insertion, every timer arming and every
    /// shuffle — so writing it after `init` changes the behaviour of views
    /// that were already built under the old values; nothing rewrites them.
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

    /// Whether this state has left the topic. Upstream drops the whole
    /// per-peer state on `Quit` and then ignores every later event for it, so
    /// a state that has quit answers nothing and produces nothing.
    ///
    /// Terminal, and there is no way back from here: rejoining means a new
    /// `State` from `init`. A join offered to a state that has quit would be
    /// answered by machinery whose passive view, claims and contact data no
    /// longer describe anything, which is the situation upstream avoids by
    /// dropping the actor rather than emptying it.
    left: bool = false,

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
    /// **A state that has quit is inert.** Upstream drops the per-peer state on
    /// `Quit` and ignores every later event for it; the `left` flag is how that
    /// is expressed here. An inert `handle` succeeds, appends nothing and
    /// changes nothing, so a driver that keeps feeding a node it has stopped
    /// driving gets silence rather than an error it cannot act on.
    ///
    /// The shuffle timer is armed on the first call whatever that call was,
    /// which is upstream's `handle`: the tail of the function, after the
    /// dispatch, not a constructor side effect. It matters because a node that
    /// only ever received messages still has to shuffle, and one that armed the
    /// timer in its constructor would arm it at a different moment in the run.
    /// It is *queued before the latch is set*, because a latch set first is a
    /// claim that a timer exists which the caller never received: an allocator
    /// refusing that one append would leave the node believing it had a shuffle
    /// scheduled, and no shuffle would ever happen again. The same rule runs
    /// the other way: a `.do_shuffle` event is delivered because the caller
    /// took that timer out of its queue, so `handleShuffleTimer` releases the
    /// latch before its fallible work and this tail re-arms on any later turn.
    /// Neither half alone would do — a latch that is only ever set survives a
    /// refusal to publish, and a timer queued with the latch already set is a
    /// claim the caller never received.
    ///
    /// **Not transactional, and the residue is named rather than hidden.** An
    /// event advances `self` and appends to `out` as it goes, so an
    /// `error.OutOfMemory` out of an append leaves the state advanced as far as
    /// that event got and leaves the appends that succeeded in `out`. The state
    /// is still a valid `State` — every mutation here is checked, so nothing is
    /// left half-written — but it is not the state the caller handed in.
    ///
    /// The recovery is the caller's, and `plumtree.State.handle` states it in
    /// full because it is the same recovery: snapshot the value before the call
    /// and restore it on error, which works because `State` is a plain value
    /// holding no slice of its own storage. The copy is `@sizeOf(State)` and no
    /// allocation. The bounds stated there apply here. It restores `self` and
    /// nothing else, so a caller that acts on `out` as it drains it has already
    /// sent what it read; it restores `out` only when `out` was empty when the
    /// call started, because `Actions` cannot truncate to a saved length; and it
    /// does not restore the caller's timers — a `.do_shuffle` event is
    /// delivered because the caller removed that timer to fire it, so a restored
    /// copy carries `shuffle_scheduled` with no timer behind it and the caller
    /// must re-queue the shuffle itself. A caller that accumulates output across
    /// events, or that cannot keep a copy, must abandon instead: treat the
    /// failed `handle` as the end of this peer's run. Replaying the event is not
    /// promised to be idempotent.
    ///
    /// **What the entries in `out` borrow.** `Actions` owns the list and not the
    /// bytes its entries name, and those bytes live in three places. An emitted
    /// `peer_data` entry names the slice the event carried, which is the
    /// caller's own buffer. A `Shuffle` or `ShuffleReply` node list names a
    /// `peer_data` slot, and a `Join`'s, a `Neighbor`'s and a `Shuffle`'s own
    /// data names a `me_data` slot. Both of those are stored inline by value —
    /// `PeerDataMap.put` and `PeerData.fromBytes` each copied on the way in —
    /// so nothing is borrowed from the message that filled them. Appending
    /// copies the event value and no bytes, so an entry lives exactly as long
    /// as those places.
    ///
    /// Two calls end the claim on a `peer_data` slot: the next `handle` that
    /// writes one, and a quit, whose `peer_data.clear()` forgets them all. One
    /// call ends the claim on a `me_data` slot: a `.update_peer_data` event,
    /// which is the only thing that writes the field. A caller that keeps an
    /// output list across any of them must copy.
    pub fn handle(
        self: *State,
        event: SwarmInEvent,
        out: *Actions(SwarmOutEvent),
    ) (Error || Allocator.Error)!void {
        if (self.left) return;
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
        // A node that has just quit does not shuffle: there is no view left to
        // shuffle, and a timer armed after the quit is exactly the stale timer
        // the drop exists to prevent.
        if (self.left or self.shuffle_scheduled) return;
        try out.push(.{ .schedule_timer = .{
            .after = self.config.shuffle_interval,
            .timer = .do_shuffle,
        } });
        self.shuffle_scheduled = true;
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

    /// Upstream `handle_quit`, and all of what a quit drops.
    ///
    /// The active view goes first and noisily: every peer in it owes a
    /// `ShuffleReply` and a `Disconnect` so it is not left holding a half-open
    /// belief about a neighbour that has gone. That output is the one part of
    /// leaving a caller can observe, and it is why the loop drains the view
    /// rather than clearing it.
    ///
    /// Everything else is dropped in silence, and all of it is state about the
    /// topic rather than about this node: the passive view, the unanswered
    /// neighbour requests, the peers that said they were still alive as they
    /// disconnected, and the contact data. `peer_data` is the one that matters
    /// beyond tidiness: those are the bytes this node would offer those peers
    /// to somebody else, and clearing the table is what stops it.
    ///
    /// `me_data` survives, because it is this node's own contact data and not
    /// the topic's; so does `stats`, which reports what the node did while it
    /// was here. `shuffle_scheduled` goes, because `left` has taken over the
    /// question of whether any timer is still wanted.
    ///
    /// **A failure part way leaves a partial drain, not a partial quit.** A peer
    /// leaves the active view only once its whole `sendDisconnect` has been
    /// appended, so at every refusal the peer being told is still in the view
    /// and `left` is not yet set — a caller that retries gets the same peer
    /// again, and the drain can finish.
    /// That is deliberate: a peer forgotten without a `Disconnect` leaves the
    /// other side holding a neighbour belief nothing will correct, and no
    /// retry can reach it.
    ///
    /// What a refusal does leave is a published prefix. `sendDisconnect`
    /// appends a `ShuffleReply`, then the `Disconnect`, then the
    /// `disconnect_peer`, so a refusal at the second or third append leaves the
    /// reply on the wire with the peer still in the view, and the retry sends a
    /// second one before the `Disconnect`. That is the residue; no retry is
    /// promised to be free of it, and the price is a duplicate node list rather
    /// than anything the other node has to reconcile. Nothing else has moved:
    /// the tables dropped below are untouched until the drain finishes.
    fn handleQuit(self: *State, out: *Actions(SwarmOutEvent)) (Error || Allocator.Error)!void {
        while (self.active_view.count() > 0) {
            const peer = self.active_view.at(0);
            // Told first, forgotten second, for the reason the failure paragraph
            // gives: a peer taken out of the view before its `Disconnect` was
            // published is one no retry can reach. `sendDisconnect` reads the
            // views and the contact table and writes none of them, so the peer
            // is still in the view while its farewell is built — which is why
            // the farewell excludes it by name.
            try self.sendDisconnect(peer, false, out);
            _ = self.active_view.removeAt(0);
        }
        self.passive_view.clear();
        self.pending_neighbor_requests.clear();
        self.alive_disconnect_peers.clear();
        self.peer_data.clear();
        self.shuffle_scheduled = false;
        self.left = true;
    }

    /// Upstream `send_disconnect`. A `ShuffleReply` goes out first, with
    /// enough of our view to keep the other node connected: it is about to
    /// lose us, and if it has just joined the swarm it may have nobody else.
    /// How much of the view is still standing is the caller's business, not
    /// this one's: on the quit path the drain empties it as it goes, so the
    /// peer told last is offered whatever is left, which is nothing once it is
    /// alone. The peer is excluded from whatever that list turned out to be,
    /// so it is never recommended to itself, which is what keeps the quit path
    /// honest while the peer is still in the active view when this runs.
    fn sendDisconnect(
        self: *State,
        peer: NodeId,
        alive: bool,
        out: *Actions(SwarmOutEvent),
    ) (Error || Allocator.Error)!void {
        const offered =
            self.config.shuffle_active_view_count + self.config.shuffle_passive_view_count;
        try self.sendShuffleReply(peer, &.{peer}, offered, out);
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
        // `sim.Network.asymmetricLinks` in `hyparview_sim_tests.zig` measures
        // that, and says the same.
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
            try self.sendShuffleReply(message.origin, &.{}, len, out);
            return;
        }
        const excluded = [_]NodeId{ message.origin, from };
        const next = self.active_view.pickRandomWithout(&excluded, &self.rng) orelse {
            // Nothing to forward to: answer instead of dropping the shuffle,
            // which is what upstream's `else` arm does by falling through to
            // the end of the function and losing the message.
            const len = message.nodes.count;
            for (message.nodes.slice()) |node| try self.addPassive(node.id, node.data, out);
            try self.sendShuffleReply(message.origin, &.{}, len, out);
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
    /// `without` names the peers neither half may offer.
    fn sendShuffleReply(
        self: *State,
        to: NodeId,
        without: []const NodeId,
        len: usize,
        out: *Actions(SwarmOutEvent),
    ) (Error || Allocator.Error)!void {
        var chosen: [max_shuffle_nodes]NodeId = undefined;
        const wanted = @min(len, max_shuffle_nodes);
        var count = self.passive_view.shuffledWithoutAndCapped(without, wanted, &self.rng, &chosen);
        if (count < wanted) {
            count += self.active_view.shuffledWithoutAndCapped(
                without,
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
    /// peer, carrying part of both views and ourselves. The walk after this one
    /// is armed by the tail of `handle`, which is the only thing that arms one.
    fn handleShuffleTimer(
        self: *State,
        out: *Actions(SwarmOutEvent),
    ) (Error || Allocator.Error)!void {
        // The timer this call answers has already left the caller's queue, so
        // the latch is released before any append below can be refused. Held
        // across them it would be a claim that a timer exists which nothing
        // will ever fire: `handle` arms the next one only while this is clear,
        // so releasing it here is what lets the next event arm one.
        self.shuffle_scheduled = false;
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

    /// Upstream `send_neighbor`: one `Neighbor` per request, no more. The
    /// pending entry is the claim that the request was made, so it is withdrawn
    /// with the request rather than left standing on a refused append.
    fn sendNeighbor(
        self: *State,
        peer: NodeId,
        priority: Priority,
        out: *Actions(SwarmOutEvent),
    ) (Error || Allocator.Error)!void {
        if (!try self.pending_neighbor_requests.insert(peer)) return;
        // The timer that clears this entry is queued by the caller after this
        // returns, so a claim left behind by a refused append is one nothing
        // owns: every later refill skips the peer and counts it against the
        // active-view capacity, and nothing ever times it out.
        errdefer std.debug.assert(self.pending_neighbor_requests.remove(peer));
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
            try appendMembership(out, produced);
            self.stats.messages_sent += @intFromBool(produced == .send_message);
        }
        for ([_][]const plumtree.OutEvent{ payload.slice(), topology.slice() }) |list| {
            for (list) |produced| {
                try appendPayload(out, produced);
                self.stats.messages_sent += @intFromBool(produced == .send_message);
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
