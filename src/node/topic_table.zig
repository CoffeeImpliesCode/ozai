//! Which peers a topic reaches.
//!
//! HyParView keeps its own views (`gossip/hyparview/topic.zig`); this is the
//! node's routing side of the same question, asked the other way round: given a
//! topic, which peers does this node write it to. It holds no view, applies no
//! membership rule, and learns that a topic exists only because a peer joined
//! it — which is what makes it a table rather than a subscription list the
//! gossip layer has to keep in step with.
//!
//! Nothing here is reproduced from the Rust tree beyond the key, for the
//! reason `conn_index.zig` gives: no upstream line is cited and no
//! interoperability claim is made. The key is upstream's
//! `TopicId([u8; 32])` (`proto/state.rs:21`), and its opacity — no derivation,
//! no scope, nothing encrypted under it, as `gossip/hyparview.zig` records —
//! is why the key is compared here and never interpreted.
//!
//! **It allocates nothing, so there is no allocator to pass.** A topic's peers
//! are a fixed array sized by a named constant and the topics are a fixed
//! array sized by another, so the whole routing table is a value: no
//! allocation to inject a failure into, and none to forget releasing.

const std = @import("std");
const base_key = @import("../base/key.zig");
const gossip = @import("../gossip/hyparview.zig");

const NodeId = base_key.NodeId;
const TopicId = gossip.TopicId;

/// How many topics this node routes at once.
///
/// **A bound is a refusal, and an unbounded route table is a table whose size a
/// remote peer picks.** Any peer may name a topic this node has never heard of,
/// so every new name would be a new slot. Eight is the number of swarms the
/// operator is willing to route for at once — one per application
/// subscription — and `error.NoFreeTopic` is what a node past it sees.
pub const max_topics = 8;

/// How many peers one topic's route may hold.
///
/// **A fan-out and not a swarm size.** A topic this node has heard of can have
/// far more members than this node writes to, and which of them those are is
/// the routing decision this module deliberately does not make — it stores
/// what it is given and refuses the rest. Sixteen is well past the five
/// neighbours a HyParView node keeps by default (`gossip/hyparview/bounds.zig`,
/// `max_active`), so a full route is already a wide send.
pub const topic_members = 16;

/// Every way the table refuses a join.
pub const JoinError = error{
    /// The table holds its topic bound already and `topic` is not one of the
    /// topics it holds.
    ///
    /// **Nothing is evicted.** A topic that is routed is dropped only by
    /// `leave` or `removePeer`, and both name what went. Evicting here would
    /// unsubscribe the node from a swarm it is still a member of, and nothing
    /// anywhere would report the loss — so the caller gets an error it can
    /// count and decide against instead.
    NoFreeTopic,
    /// `topic` is at `topic_members` and `peer` is not one of its peers.
    ///
    /// **The table is unchanged**: the topic keeps every peer it had and keeps
    /// its slot, and the caller decides which route to shed. A join refused
    /// here has cost the topic nothing and the peer nothing but its join.
    TopicFull,
};

/// What a join did.
pub const Join = union(enum) {
    /// The peer is in the topic's route now and was not before.
    joined,
    /// It already was, and the table is exactly as it was. A join that
    /// repeats a peer cannot grow the route, which is the duplicate delivery
    /// on every later round that a set has to refuse.
    already,
};

/// One topic's peers, in no order this module promises.
pub const Members = struct {
    /// The peers. Only `[0..len]` is ever read, so the tail is `undefined`
    /// rather than empty and nothing walks past `len` to find it.
    ids: [topic_members]NodeId = undefined,
    /// How many of them are in use, never a capacity: a route of two holding
    /// one is `len == 1`.
    len: usize = 0,
};

/// One topic and the route to the peers this node writes it to.
pub const Entry = struct {
    /// The topic, which is also the key.
    topic: TopicId,
    /// The peers it is written to.
    members: Members,
};

/// A bounded map from topic to the peers this node sends it to.
///
/// `topics` is how many topics this table holds and `TopicTable(max_topics)` is
/// the one a node builds. Nothing grows: `join` past the bound is
/// `error.NoFreeTopic`, and a topic leaves only through `leave` or
/// `removePeer`.
///
/// **A topic with no peers has no route, and no slot.** `leave` and
/// `removePeer` free the slot when the last peer goes, so a node is never
/// holding a topic it routes nothing to — and never answers `NoFreeTopic`
/// because of a topic with nobody in it.
///
/// **A peer's route into every topic leaves in one call.** `removePeer` is
/// what a disconnect uses, and the reason it is one call rather than one call
/// per topic the caller knows of: a peer left in a single route is a node that
/// still writes to a connection it has closed, and a caller that has to
/// remember which topics a peer was in is a caller that will forget one.
///
/// **The order of a route is not part of the contract.** Removal closes the
/// gap with the last peer, so two nodes holding the same peers in different
/// orders hand them back in different orders and that is not a difference.
pub fn TopicTable(comptime topics: usize) type {
    return struct {
        const Self = @This();

        // Zero topics is a node that routes nothing, which is what
        // `Node.config`'s role switch expresses and not something a table
        // should be able to be built as.
        comptime {
            std.debug.assert(topics > 0);
        }

        /// The topics held. Only `[0..len]` is ever read.
        entries: [topics]Entry = undefined,
        /// How many of `entries` are in use, never a capacity.
        len: usize = 0,

        /// An empty table. Nothing to release — see the module doc — so there
        /// is no `deinit` and no allocator to hand one.
        pub fn init() Self {
            return .{};
        }

        /// How many topics are routed.
        pub fn count(self: *const Self) usize {
            return self.len;
        }

        /// The peers `topic` is written to, borrowed, or null for a topic this
        /// table does not hold.
        ///
        /// Borrowed from the table and no longer than it: the caller reads the
        /// route before the next `join` or `leave`, and the table owns the
        /// bytes. It is a slice rather than a copy because a route is read on
        /// every send and copying sixteen node ids per send to answer "who do I
        /// write this to" is work nobody asked for.
        pub fn members(self: *const Self, topic: TopicId) ?[]const NodeId {
            const index = self.indexOf(topic) orelse return null;
            const route = &self.entries[index].members;
            return route.ids[0..route.len];
        }

        /// Put `peer` in `topic`'s route, opening the topic if it is not held.
        ///
        /// A refused join leaves the table exactly as it was: a topic opened by
        /// this call and then refused is not one this table holds.
        pub fn join(self: *Self, topic: TopicId, peer: NodeId) JoinError!Join {
            const index = self.indexOf(topic) orelse return self.open(topic, peer);
            const route = &self.entries[index].members;
            if (memberAt(route, peer) != null) return Join.already;
            if (route.len == topic_members) return error.TopicFull;
            route.ids[route.len] = peer;
            route.len += 1;
            return Join.joined;
        }

        /// Take `peer` out of `topic`'s route. Whether it was there.
        ///
        /// A peer that was not in the topic leaves nothing and frees nothing:
        /// the removal that matters is the one across every topic, which is
        /// `removePeer`.
        pub fn leave(self: *Self, topic: TopicId, peer: NodeId) bool {
            const index = self.indexOf(topic) orelse return false;
            if (!takePeer(&self.entries[index].members, peer)) return false;
            _ = self.dropEmpty(index);
            return true;
        }

        /// Take `peer` out of every topic it was in, and answer with how many
        /// routes it left.
        ///
        /// The cost is a scan of every topic, which at `max_topics` is a
        /// handful of 32-byte comparisons each. A peer-to-topics index would
        /// answer it without the scan, and would have to be kept in step with
        /// this table on every join and every leave: the two disagreeing is a
        /// peer routed to nothing, or one that was never routed at all. One
        /// bounded table and one way to be wrong beats two tables and two.
        pub fn removePeer(self: *Self, peer: NodeId) usize {
            var removed: usize = 0;
            var index: usize = 0;
            while (index < self.len) {
                if (takePeer(&self.entries[index].members, peer)) removed += 1;
                // A topic that just emptied had the last entry moved into its
                // slot, so this index holds a topic nobody has looked at yet
                // and is still the one to look at. Otherwise it is a topic
                // that kept its peers, and this peer is out of it.
                if (self.dropEmpty(index)) continue;
                index += 1;
            }
            return removed;
        }

        /// Where `topic` is, or null for a topic this table does not hold.
        ///
        /// A scan and not a hash, for `conn_index.zig`'s reason: the whole
        /// table is `topics` entries and a topic is 32 bytes, so a lookup
        /// costs less than the message it is about to route. The loop is
        /// bounded by the storage it walks.
        fn indexOf(self: *const Self, topic: TopicId) ?usize {
            for (self.entries[0..self.len], 0..) |entry, index| {
                if (entry.topic.eql(topic)) return index;
            }
            return null;
        }

        /// Give a peer the one route that is not taken, opening the topic.
        fn open(self: *Self, topic: TopicId, peer: NodeId) JoinError!Join {
            if (self.len == topics) return error.NoFreeTopic;
            var fresh: Entry = .{
                .topic = topic,
                .members = .{ .ids = undefined, .len = 1 },
            };
            fresh.members.ids[0] = peer;
            self.entries[self.len] = fresh;
            self.len += 1;
            return Join.joined;
        }

        /// Free the slot at `index` when its topic has no peers left. Whether
        /// the slot was freed, which is the one fact the caller's loop needs:
        /// a freed slot holds a different topic than it did.
        fn dropEmpty(self: *Self, index: usize) bool {
            if (self.entries[index].members.len != 0) return false;
            // ZBC cannot combine the callers' proofs that this table has a live entry.
            // zbc-disable-next-line: index-minus-one-without-zero-guard
            self.entries[index] = self.entries[self.len - 1];
            self.len -= 1;
            return true;
        }
    };
}

/// Where `peer` is in `members`, or null for a peer the route does not hold.
fn memberAt(members: *const Members, peer: NodeId) ?usize {
    for (members.ids[0..members.len], 0..) |member, index| {
        if (member.order(peer) == .eq) return index;
    }
    return null;
}

/// Take `peer` out of `members`, closing the gap with the last peer. Whether
/// it was there.
fn takePeer(members: *Members, peer: NodeId) bool {
    const index = memberAt(members, peer) orelse return false;
    // ZBC cannot carry `memberAt`'s successful scan of the nonempty prefix into this subtraction.
    // zbc-disable-next-line: index-minus-one-without-zero-guard
    members.ids[index] = members.ids[members.len - 1];
    members.len -= 1;
    return true;
}

// --- tests

const t = std.testing;
const topic_id_length = gossip.topic_id_length;
const node_test_ids = @import("node_test_ids.zig");

/// A topic named by one byte. A `TopicId` is 32 bytes an application chose
/// and every one of them is as good as any other, so the bytes only have to
/// differ.
fn testTopic(tag: u8) TopicId {
    var bytes = [_]u8{0} ** topic_id_length;
    bytes[0] = tag;
    return TopicId.fromBytes(bytes);
}

/// Whether `route` holds `peer`.
fn holdsPeer(route: []const NodeId, peer: NodeId) bool {
    for (route) |member| {
        if (member.order(peer) == .eq) return true;
    }
    return false;
}

test "a joined peer is in that topic's route and an unjoined topic has none" {
    // `TopicTable` is a generic factory: the binding holds the struct type it
    // returns, and a type binding is PascalCase rather than a value.
    // zwanzig-disable-next-line: identifier-style
    const Table = TopicTable(2);
    var table = Table.init();

    // An empty table holds no topics, and says so for every one of them rather
    // than with an empty route: a caller must not be able to mistake "no such
    // topic" for "a topic nobody is in".
    try t.expectEqual(@as(usize, 0), table.count());
    try t.expectEqual(@as(?[]const NodeId, null), table.members(testTopic(1)));

    const room = testTopic(1);
    const peer = try node_test_ids.testNodeId(41);
    try t.expectEqual(Join.joined, try table.join(room, peer));
    try t.expectEqual(@as(usize, 1), table.count());
    const route = table.members(room) orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(usize, 1), route.len);
    try t.expect(holdsPeer(route, peer));

    // A second topic is a second route and not a longer one: the members of
    // one topic are not the members of the other.
    const other = testTopic(2);
    const second = try node_test_ids.testNodeId(42);
    try t.expectEqual(Join.joined, try table.join(other, second));
    try t.expectEqual(@as(usize, 2), table.count());
    const other_route = table.members(other) orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(usize, 1), other_route.len);
    try t.expect(holdsPeer(other_route, second));
    try t.expect(!holdsPeer(other_route, peer));
}

test "a peer that joins a topic twice is in it once" {
    // zwanzig-disable-next-line: identifier-style
    const Table = TopicTable(1);
    var table = Table.init();
    const room = testTopic(1);
    const peer = try node_test_ids.testNodeId(43);

    try t.expectEqual(Join.joined, try table.join(room, peer));
    try t.expectEqual(Join.already, try table.join(room, peer));
    // A third time is the same answer. A route that grew on a repeat is a
    // peer written to twice on every send, and no caller would see it.
    try t.expectEqual(Join.already, try table.join(room, peer));

    const route = table.members(room) orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(usize, 1), route.len);
    try t.expect(holdsPeer(route, peer));
    try t.expectEqual(@as(usize, 1), table.count());
}

test "iterating a route yields every peer in it once and nobody else" {
    // zwanzig-disable-next-line: identifier-style
    const Table = TopicTable(2);
    var table = Table.init();
    const room = testTopic(1);
    const first = try node_test_ids.testNodeId(51);
    const second = try node_test_ids.testNodeId(52);
    const third = try node_test_ids.testNodeId(53);
    const elsewhere = try node_test_ids.testNodeId(54);
    _ = try table.join(room, first);
    _ = try table.join(room, second);
    _ = try table.join(room, third);
    _ = try table.join(testTopic(2), elsewhere);

    // Three peers joined, three peers handed back, no repeats: a route with a
    // peer in it twice sends that peer the topic twice, and a route missing
    // one is a peer that never hears about a swarm it joined.
    const route = table.members(room) orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(usize, 3), route.len);
    for (route, 0..) |member, index| {
        try t.expect(holdsPeer(route, member));
        try t.expect(!holdsPeer(route[0..index], member));
        // The other topic's peer is not in this one: routes do not leak.
        try t.expect(member.order(elsewhere) != .eq);
    }
    for ([_]NodeId{ first, second, third }) |peer| {
        try t.expect(holdsPeer(route, peer));
    }

    // The other topic's route is the same shape over its own single peer.
    const other = table.members(testTopic(2)) orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(usize, 1), other.len);
    try t.expect(holdsPeer(other, elsewhere));
}

test "a peer that leaves one topic leaves the rest of the table alone" {
    // zwanzig-disable-next-line: identifier-style
    const Table = TopicTable(2);
    var table = Table.init();
    const room = testTopic(1);
    const next_room = testTopic(2);
    const leaving = try node_test_ids.testNodeId(61);
    const staying = try node_test_ids.testNodeId(62);
    _ = try table.join(room, leaving);
    _ = try table.join(room, staying);
    _ = try table.join(next_room, staying);

    try t.expect(table.leave(room, leaving));
    const route = table.members(room) orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(usize, 1), route.len);
    try t.expect(holdsPeer(route, staying));
    try t.expect(!holdsPeer(route, leaving));

    // A peer that is not in the topic, and a topic this table does not hold,
    // both leave nothing: a removal that failed must not free a slot.
    try t.expect(!table.leave(room, leaving));
    try t.expect(!table.leave(testTopic(3), staying));
    try t.expectEqual(@as(usize, 2), table.count());

    // The last peer out frees the slot, because a topic this node routes
    // nobody is not a topic this node holds.
    try t.expect(table.leave(next_room, staying));
    try t.expectEqual(@as(usize, 1), table.count());
    try t.expectEqual(@as(?[]const NodeId, null), table.members(next_room));
    // And the route it could not take with it is untouched: freeing one
    // topic's slot moved the last topic into the gap and dropped no route.
    const kept = table.members(room) orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(usize, 1), kept.len);
    try t.expect(holdsPeer(kept, staying));
}

test "a table full of topics refuses a topic it has never routed" {
    // The production bound, so the number the operator picks is the one under
    // test and not a smaller one that behaves the same way. The number itself
    // is pinned because it is the answer to "how many swarms does this node
    // route for", and that answer must not drift silently.
    // zwanzig-disable-next-line: identifier-style
    const Table = TopicTable(max_topics);
    var table = Table.init();
    try t.expectEqual(@as(usize, 8), max_topics);

    const peer = try node_test_ids.testNodeId(71);
    for (0..max_topics) |offset| {
        const topic = testTopic(@intCast(offset + 1));
        try t.expectEqual(Join.joined, try table.join(topic, peer));
    }
    try t.expectEqual(@as(usize, max_topics), table.count());

    // One topic past the bound is refused, and it is refused rather than
    // admitted by dropping one of the eight.
    const stranger = testTopic(200);
    try t.expectError(error.NoFreeTopic, table.join(stranger, peer));
    try t.expectEqual(@as(usize, max_topics), table.count());
    try t.expectEqual(@as(?[]const NodeId, null), table.members(stranger));

    // Every topic the table routed still routes the peer it was given: the
    // refusal cost the table nothing, and it did not unsubscribe the node
    // from a swarm it is still a member of.
    for (0..max_topics) |offset| {
        const topic = testTopic(@intCast(offset + 1));
        const route = table.members(topic) orelse return error.TestUnexpectedResult;
        try t.expectEqual(@as(usize, 1), route.len);
        try t.expect(holdsPeer(route, peer));
    }

    // One departure frees exactly one slot, for exactly one arrival.
    try t.expect(table.leave(testTopic(1), peer));
    try t.expectEqual(@as(usize, max_topics) - 1, table.count());
    try t.expectEqual(Join.joined, try table.join(stranger, peer));
    try t.expectEqual(@as(usize, max_topics), table.count());
}

test "a topic at its peer bound refuses one more and keeps the peers it had" {
    // The production fan-out, filled, so the refusal is proved at the number a
    // node actually routes with rather than at a small one.
    // zwanzig-disable-next-line: identifier-style
    const Table = TopicTable(max_topics);
    var table = Table.init();
    try t.expectEqual(@as(usize, 16), topic_members);

    const room = testTopic(1);
    for (0..topic_members) |offset| {
        const seed: u8 = @intCast(offset + 1);
        try t.expectEqual(Join.joined, try table.join(room, try node_test_ids.testNodeId(seed)));
    }
    const full = table.members(room) orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(usize, topic_members), full.len);

    // One peer past the fan-out is refused, and the topic keeps every peer it
    // had: a table that shed a route to admit a peer would drop a peer that is
    // still there with nobody to say it went.
    const stranger = try node_test_ids.testNodeId(200);
    try t.expectError(error.TopicFull, table.join(room, stranger));

    const after = table.members(room) orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(usize, topic_members), after.len);
    for (after) |member| try t.expect(member.order(stranger) != .eq);
    for (0..topic_members) |offset| {
        const seed: u8 = @intCast(offset + 1);
        try t.expect(holdsPeer(after, try node_test_ids.testNodeId(seed)));
    }

    // One departure makes room for exactly one arrival, and the topic is full
    // again afterwards rather than one over.
    try t.expect(table.leave(room, try node_test_ids.testNodeId(1)));
    try t.expectEqual(Join.joined, try table.join(room, stranger));
    const refilled = table.members(room) orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(usize, topic_members), refilled.len);
    try t.expect(holdsPeer(refilled, stranger));
    try t.expectError(
        error.TopicFull,
        table.join(room, try node_test_ids.testNodeId(201)),
    );
}

test "a peer that leaves takes its route out of every topic it was in" {
    // zwanzig-disable-next-line: identifier-style
    const Table = TopicTable(4);
    var table = Table.init();
    const first = testTopic(1);
    const second = testTopic(2);
    const third = testTopic(3);
    const fourth = testTopic(4);
    const gone = try node_test_ids.testNodeId(81);
    const staying = try node_test_ids.testNodeId(82);

    // The departing peer is in three of the four topics and the one that
    // stays is in three of them too, so a removal that swept every topic is
    // proved on routes that are shared and on one that empties entirely.
    _ = try table.join(first, gone);
    _ = try table.join(first, staying);
    _ = try table.join(second, gone);
    _ = try table.join(second, staying);
    _ = try table.join(third, gone);
    _ = try table.join(fourth, staying);
    try t.expectEqual(@as(usize, 4), table.count());

    // Three routes, three removals: the count is what lets a caller notice a
    // disconnect for a peer it thought was nowhere.
    try t.expectEqual(@as(usize, 3), table.removePeer(gone));

    // Gone from every topic it was in, and still in none of the four.
    for ([_]TopicId{ first, second, third, fourth }) |topic| {
        const route = table.members(topic) orelse continue;
        for (route) |member| try t.expect(member.order(gone) != .eq);
    }
    // The three topics that had another peer keep their route and lose only
    // this peer; the one that had only this peer is gone, because a topic this
    // node routes nobody is not a topic this node holds.
    try t.expectEqual(@as(usize, 3), table.count());
    try t.expectEqual(@as(?[]const NodeId, null), table.members(third));
    const first_route = table.members(first) orelse return error.TestUnexpectedResult;
    const second_route = table.members(second) orelse return error.TestUnexpectedResult;
    const fourth_route = table.members(fourth) orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(usize, 1), first_route.len);
    try t.expectEqual(@as(usize, 1), second_route.len);
    try t.expectEqual(@as(usize, 1), fourth_route.len);
    try t.expect(holdsPeer(first_route, staying));
    try t.expect(holdsPeer(second_route, staying));
    try t.expect(holdsPeer(fourth_route, staying));

    // A peer that was never routed leaves nothing, twice over: a disconnect
    // path that runs again is not allowed to free somebody else's slot.
    try t.expectEqual(@as(usize, 0), table.removePeer(gone));
    try t.expectEqual(@as(usize, 3), table.count());

    // And the peer that stayed is routed in three topics, and going takes all
    // three with it.
    try t.expectEqual(@as(usize, 3), table.removePeer(staying));
    try t.expectEqual(@as(usize, 0), table.count());
    for ([_]TopicId{ first, second, third, fourth }) |topic| {
        try t.expectEqual(@as(?[]const NodeId, null), table.members(topic));
    }
    try t.expectEqual(@as(usize, 0), table.removePeer(staying));
    try t.expectEqual(@as(usize, 0), table.count());
}
