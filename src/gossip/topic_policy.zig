//! Which topics this node is in, and what it tells each of them about itself.
//!
//! `node/topic_table.zig` answers "given a topic, which peers does this node
//! write it to", and it says why it holds no view and applies no membership
//! rule: a topic exists there because a peer joined it. This is the other
//! half. A topic exists here because **this node chose it**, and the choice
//! carries three things the routing table has no room for — the topic, the
//! contact bytes this node advertises in it, and the peers it asks to be
//! introduced to. None of them is learned from a message, and all three are
//! refused rather than evicted when the bound is reached.
//!
//! **It allocates nothing, so there is no allocator to pass.** Every record is
//! inline: the topics are a fixed array sized by `max_topics`, and a topic's
//! contact bytes and introduction list are the protocol's own `PeerData` and
//! `Peers`, which are values. So the whole policy is a value a caller holds
//! beside its `TopicState`s, with no allocation to inject a failure into and
//! none to forget releasing.
//!
//! **Nothing here is reproduced from the Rust tree, so no upstream line is
//! cited and no interoperability claim is made.** `PeerData` and `Peers` are
//! `gossip/hyparview.zig`'s own types rather than copies of them, and the wire
//! questions — what a `TopicId` is, and that nothing encrypts under one — are
//! answered in that module's doc and not repeated here.
//!
//! # What a join is, and what leaving costs
//!
//! **`forget` is the only door out, and it names the topic it dropped.**
//! Nothing else frees a slot. That is the permanence decision, and it is the
//! opposite of the one a subscription API would make, so the reasons are worth
//! stating in full:
//!
//! 1. **The layer underneath has no way back, so a policy promising one would
//!    be lying.** `hyparview/topic.zig`'s `TopicState.left` is terminal: after
//!    `Command.quit` the state "succeeds, appends nothing and changes
//!    nothing", and rejoining means building a new `TopicState`. A policy that
//!    let this node re-admit a topic and carry on would be promising
//!    reversibility the membership machine does not have, and the caller would
//!    find out when the inert layer silently dropped a broadcast.
//! 2. **A leave on a whim is a flap, and a flap is what the active view is
//!    sized against.** Every join is answered by `Neighbor` exchanges and
//!    forwarded walks; a node that left because it was bored would spend a
//!    second `max_active` full of handshakes twice per change of mind. Refusing
//!    to leave is not a restriction on the operator — it is the ordinary case:
//!    an application drops a subscription when the user asks, not on a timer.
//! 3. **The obligations are nameable, so they can be given up one at a time.**
//!    The two things a topic holds this node to — the contact bytes it
//!    advertises and the peers it will dial — are not the membership itself.
//!    `forget` ends both and answers that it did; `forgetPeer` gives up one
//!    peer's introductions across every topic that named it, and costs no
//!    slot. So "a node that cannot leave accumulates obligations to peers it
//!    no longer wants to gossip with" is answered by the narrow door, not by
//!    the wide one.
//!
//! **A second `admit` of a topic this node already holds is `already`, and
//! changes nothing.** It cannot widen the introduction list and cannot replace
//! the advertised bytes, because a join is permanent: the only way to change
//! what this node tells a topic is `forget` and then `admit`, which is one
//! call that names the loss and one that names the gain.
//!
//! **A topic whose introduction list has emptied keeps its slot.** The list is
//! the bootstrap peers, and a node that has finished dialling is still a member
//! of the swarm; `Command.join` with an empty list is upstream's own way to
//! start a node that is "ready to be asked". Only `forget` ends membership, and
//! that is where `node/topic_table.zig` differs: it frees a topic whose route
//! emptied, because a route with no peers reaches nobody, whereas a membership
//! with no bootstrap peers reaches a swarm this node is already in.
//!
//! # Two topics may share peers
//!
//! **Overlapping membership is allowed, and the ceiling it implies is
//! published rather than discovered.** Three reasons:
//!
//! 1. **Nothing on the wire forbids it, because the topic is not in the
//!    message.** `gossip/codec/frame.zig` writes it once per stream, in
//!    `StreamHeader`, and no arm of `SwarmMessage` carries one. A peer in two
//!    topics is one peer on one socket with two streams, so the ordinary
//!    multi-topic node is the normal case and exclusivity would forbid it.
//! 2. **Exclusivity could not be enforced anyway.** `TopicState.handle`
//!    dispatches on the message alone and holds no registry of the other
//!    topics; a policy that refused the overlap locally would only be able to
//!    refuse *its own* half of it. Two nodes that disagreed would each believe
//!    the other had left, and nothing would say so.
//! 3. **The cost is arithmetic, and it is `max_outbound`.** A topic at its
//!    width writes to `hyparview.max_active` peers, so a node in every topic
//!    it holds can name `max_outbound` peers — and a peer in two topics is
//!    named twice, which is precisely why the outbound set is larger than the
//!    sum of the topics'. Note what that number is against: `max_outbound` is
//!    256 and `node/conn_index.zig`'s `max_peers` is 32. A node that
//!    participates in every topic at full width cannot be routed by the
//!    directory this tree builds. That is the operator's decision to make, and
//!    this module's job is to have already named it rather than to hide it.

const std = @import("std");
const gossip = @import("hyparview.zig");

const NodeId = gossip.NodeId;
const PeerData = gossip.PeerData;
const Peers = gossip.Peers;
const TopicId = gossip.TopicId;

/// How many topics this node is in at once.
///
/// **A bound is a refusal, and an unbounded participation table is a table
/// whose size the operator's own configuration picks.** Eight is the number of
/// swarms one node serves at once, and it is the same number
/// `node/topic_table.zig` routes for: the two tables answer different
/// questions about the same operator decision, so they are held to one number
/// and each states the other's.
pub const max_topics = 8;

/// The most peers one topic's introduction list may name.
///
/// `gossip/hyparview/bounds.zig`'s `max_bootstrap`, read rather than written:
/// a `Command.join` carrying more peers than that is refused by `Peers.init`
/// before it reaches this table, and a second ceiling here would be a number
/// that can disagree with the one the wire type already enforces.
pub const max_peers = gossip.max_bootstrap;

/// The most peers a node in every topic it holds can be named towards, and the
/// number a caller sizing a connection directory needs.
///
/// `max_topics` times `hyparview.max_active`, because each topic's active view
/// is that wide and the topics do not share their membership. It exceeds
/// `node/conn_index.zig`'s `max_peers`, and the module doc says what follows
/// from that rather than leaving a caller to multiply two numbers and find it
/// out.
pub const max_outbound = max_topics * gossip.max_active;

/// Every way the policy refuses a topic.
pub const PolicyError = error{
    /// The policy holds `max_topics` topics and this is not one of them.
    ///
    /// **Nothing is evicted.** A topic is dropped only by `forget`, which
    /// names it. Evicting here would silently unsubscribe this node from a
    /// swarm its `TopicState` is still running, and the membership machine
    /// would keep the views, the timers and the caches for a topic nobody
    /// believes in any more — a refusal the caller can count beats that.
    TopicsFull,
};

/// What an `admit` did.
pub const Admission = union(enum) {
    /// The topic is in the policy now and was not before.
    admitted,
    /// It already was, and the policy is exactly as it was: the contact bytes
    /// and the introduction list on offer were not taken, so a repeated join
    /// cannot widen what this node will dial.
    already,
};

/// One topic and everything this node tells it about itself.
pub const Entry = struct {
    /// The topic, which is also the key.
    topic: TopicId,
    /// The contact bytes this node advertises in this topic, and null for a
    /// topic it advertises nothing in. `PeerData` is held by value because
    /// `PeerData.fromBytes` copied it on the way in, so nothing here borrows
    /// the caller's buffer and no admission leaves a claim on it.
    data: ?PeerData,
    /// The peers this node asks to be introduced to. Empty is a legitimate
    /// value and not a missing one — see the module doc on `forgetPeer`.
    peers: Peers,
};

/// Which topics this node is in, and what it tells each of them.
///
/// A fixed bound and no allocator: `max_topics` inline entries, so this is a
/// value. `admit` past the bound is `error.TopicsFull` and a topic leaves only
/// through `forget`.
///
/// **The order of the topics is not part of the contract.** `forget` closes
/// the gap with the last topic, so two policies holding the same topics need
/// not list them the same way and that is not a difference.
pub const TopicPolicy = struct {
    /// The topics held, first admitted first. Only `[0..len]` is ever read, so
    /// an entry past `len` is `undefined` rather than empty: nothing walks
    /// past `len` to find it.
    entries: [max_topics]Entry = undefined,
    /// How many of `entries` are in use, never a capacity.
    len: usize = 0,

    /// An empty policy. Nothing to release — see the module doc — so there is
    /// no `deinit` and no allocator to hand one.
    pub fn init() TopicPolicy {
        return .{};
    }

    /// How many topics this node is in.
    pub fn count(self: *const TopicPolicy) usize {
        return self.len;
    }

    /// Whether this node is in `topic`.
    pub fn holds(self: *const TopicPolicy, topic: TopicId) bool {
        return self.indexOf(topic) != null;
    }

    /// The contact bytes this node advertises in `topic`, or null for a topic
    /// it does not hold and for one it advertises nothing in.
    ///
    /// **Empty and absent are the same answer**, because `State.myData` already
    /// makes them the same answer on the wire: a zero-length `PeerData` sends
    /// no slice. A per-topic record that could tell the two apart would be a
    /// second spelling of one fact, and a caller would eventually act on the
    /// difference.
    ///
    /// The bytes are borrowed from the policy and valid until the next `admit`
    /// or `forget`: `advertised` hands back a slice into the entry, which is
    /// exactly the borrow `node/topic_table.zig`'s `members` documents.
    pub fn advertised(self: *const TopicPolicy, topic: TopicId) ?[]const u8 {
        const index = self.indexOf(topic) orelse return null;
        const data = &self.entries[index].data orelse return null;
        if (data.isEmpty()) return null;
        return data.slice();
    }

    /// The peers `topic` is introduced to, borrowed, or null for a topic this
    /// policy does not hold.
    ///
    /// Borrowed on the same terms as `advertised`, and empty rather than null
    /// for a topic this node is in and has nobody to be introduced to.
    pub fn introductions(self: *const TopicPolicy, topic: TopicId) ?[]const NodeId {
        const index = self.indexOf(topic) orelse return null;
        return self.entries[index].peers.slice();
    }

    /// Put `topic` in the policy, with what this node tells it about itself.
    ///
    /// A refused admission leaves the policy exactly as it was, and a topic
    /// already held keeps the bytes and the list it had. The bounds on those
    /// two values are the protocol's own and were proved where they were built
    /// — `PeerData.fromBytes` and `Peers.init` — so they are taken here as
    /// given rather than checked twice.
    pub fn admit(
        self: *TopicPolicy,
        topic: TopicId,
        data: ?PeerData,
        peers: Peers,
    ) PolicyError!Admission {
        if (self.indexOf(topic) != null) return Admission.already;
        if (self.len == max_topics) return error.TopicsFull;
        self.entries[self.len] = .{ .topic = topic, .data = data, .peers = peers };
        self.len += 1;
        return Admission.admitted;
    }

    /// Take `topic` out of the policy. Whether it was there.
    ///
    /// **The only door out**, and the whole of the permanence decision — see
    /// the module doc. It answers whether it dropped anything rather than
    /// failing, so a caller that meant to leave and did not is told, and a
    /// caller that meant to leave twice evicts nobody, which is what makes a
    /// shutdown path that runs twice harmless.
    pub fn forget(self: *TopicPolicy, topic: TopicId) bool {
        const index = self.indexOf(topic) orelse return false;
        self.entries[index] = self.entries[self.len - 1];
        self.len -= 1;
        return true;
    }

    /// Take `peer` out of every introduction list it was named in, and answer
    /// with how many it left.
    ///
    /// **It frees no slot.** A topic that had nobody left to be introduced to
    /// is still a topic this node is in — the list is the bootstrap peers, not
    /// the membership — so `forget` and not this call is what ends a topic.
    ///
    /// The cost is a scan of every topic, which at `max_topics` is a handful of
    /// 32-byte comparisons per peer. A peer-to-topics index would answer it
    /// without the scan and would have to be kept in step with every `admit`
    /// and every `forget`; the two disagreeing is a peer this node will still
    /// dial after it decided not to. One table and one way to be wrong beats
    /// two tables and two.
    pub fn forgetPeer(self: *TopicPolicy, peer: NodeId) usize {
        var removed: usize = 0;
        for (self.entries[0..self.len]) |*entry| {
            if (takeIntro(&entry.peers, peer)) removed += 1;
        }
        return removed;
    }

    /// Where `topic` is, or null for a topic this policy does not hold.
    ///
    /// A scan and not a hash, for `conn_index.zig`'s reason: the whole policy
    /// is `max_topics` entries and a topic is 32 bytes, so a lookup costs less
    /// than the frame it is about to be asked about. The loop is bounded by the
    /// storage it walks.
    fn indexOf(self: *const TopicPolicy, topic: TopicId) ?usize {
        for (self.entries[0..self.len], 0..) |entry, index| {
            if (entry.topic.eql(topic)) return index;
        }
        return null;
    }
};

/// Take `peer` out of one topic's introduction list, closing the gap with the
/// last peer. Whether it was there.
fn takeIntro(list: *Peers, peer: NodeId) bool {
    for (list.items[0..list.count], 0..) |held, index| {
        if (held.order(peer) != .eq) continue;
        list.items[index] = list.items[list.count - 1];
        list.count -= 1;
        return true;
    }
    return false;
}

// --- tests

const t = std.testing;
const test_node_id = @import("plumtree/test_node_id.zig");

/// A topic named by one byte. A `TopicId` is 32 bytes an application chose and
/// every one of them is as good as any other, so the bytes only have to differ.
fn testTopic(tag: u8) TopicId {
    var bytes = [_]u8{0} ** gossip.topic_id_length;
    bytes[0] = tag;
    return TopicId.fromBytes(bytes);
}

/// An introduction list with nobody in it, which upstream's own `Command.join`
/// says is a node "ready to be asked" rather than a missing value.
fn none() Peers {
    return .{ .count = 0, .items = undefined };
}

test "an admitted topic is held and tells this node's own words and peers" {
    var policy = TopicPolicy.init();
    try t.expectEqual(@as(usize, 0), policy.count());
    try t.expect(!policy.holds(testTopic(1)));
    // A topic this node is not in has no words and no introductions, and says
    // so with null rather than with an empty answer: a caller must not be able
    // to mistake "no such topic" for "a topic I say nothing in".
    try t.expectEqual(@as(?[]const u8, null), policy.advertised(testTopic(1)));
    try t.expectEqual(@as(?[]const NodeId, null), policy.introductions(testTopic(1)));

    const room = testTopic(1);
    const first = try test_node_id.testNodeId(1);
    const second = try test_node_id.testNodeId(2);
    try t.expectEqual(Admission.admitted, try policy.admit(
        room,
        try PeerData.fromBytes("alpha"),
        try Peers.init(&.{ first, second }),
    ));

    try t.expectEqual(@as(usize, 1), policy.count());
    try t.expect(policy.holds(room));
    // The advertised bytes are the ones that were offered, which is the whole
    // of "what this node tells each topic about itself".
    try t.expectEqualStrings("alpha", policy.advertised(room).?);
    try t.expectEqual(@as(usize, 2), policy.introductions(room).?.len);
    // Each peer is found by the id it is known by and not by its slot, which
    // is what proves the list holds identities rather than positions.
    try t.expect(inList(policy.introductions(room).?, first));
    try t.expect(inList(policy.introductions(room).?, second));
}

test "a refused topic leaves the policy exactly as it was" {
    // The production bound, so the number an operator picks is the one under
    // test. The number itself is pinned because it is the answer to "how many
    // topics does this node be in", and that answer must not drift silently.
    var policy = TopicPolicy.init();
    try t.expectEqual(@as(usize, 8), max_topics);
    var filled: u8 = 1;
    while (filled <= max_topics) : (filled += 1) {
        _ = try policy.admit(testTopic(filled), try PeerData.fromBytes("a"), none());
    }
    try t.expectEqual(@as(usize, max_topics), policy.count());

    // The refusal, and nothing evicted: the topics are all still here, still
    // saying what they said, and the one that would not fit is not held.
    try t.expectError(error.TopicsFull, policy.admit(
        testTopic(0xfe),
        try PeerData.fromBytes("b"),
        none(),
    ));
    try t.expectEqual(@as(usize, max_topics), policy.count());
    try t.expect(!policy.holds(testTopic(0xfe)));
    for (policy.entries[0..max_topics], 1..) |entry, position| {
        try t.expect(entry.topic.eql(testTopic(@intCast(position))));
        try t.expectEqualStrings("a", policy.advertised(entry.topic).?);
    }
}

test "admitting a topic a second time changes nothing" {
    var policy = TopicPolicy.init();
    const room = testTopic(7);
    const first = try test_node_id.testNodeId(3);
    const second = try test_node_id.testNodeId(4);
    _ = try policy.admit(room, try PeerData.fromBytes("first"), try Peers.init(&.{first}));

    // A repeated join is `already`, and the bytes and the list on offer the
    // second time are not taken: a join is permanent, so it cannot widen what
    // this node will dial behind the caller's back.
    try t.expectEqual(Admission.already, try policy.admit(
        room,
        try PeerData.fromBytes("second"),
        try Peers.init(&.{ first, second }),
    ));
    try t.expectEqual(@as(usize, 1), policy.count());
    try t.expectEqualStrings("first", policy.advertised(room).?);
    try t.expectEqual(@as(usize, 1), policy.introductions(room).?.len);
    try t.expect(inList(policy.introductions(room).?, first));
    try t.expect(!inList(policy.introductions(room).?, second));
}

test "forget drops the one topic it names and frees its slot" {
    var policy = TopicPolicy.init();
    const kept = testTopic(1);
    const dropped = testTopic(2);
    _ = try policy.admit(kept, null, none());
    _ = try policy.admit(dropped, null, none());
    try t.expectEqual(@as(usize, 2), policy.count());

    try t.expect(policy.forget(dropped));
    try t.expectEqual(@as(usize, 1), policy.count());
    try t.expect(!policy.holds(dropped));
    try t.expect(policy.holds(kept));
    // The slot was really freed, not just hidden: the topic comes back.
    try t.expectEqual(Admission.admitted, try policy.admit(
        testTopic(3),
        null,
        none(),
    ));
    try t.expectEqual(@as(usize, 2), policy.count());

    // A topic nobody held is a null forget and evicts nobody, which is what
    // makes a shutdown that runs twice harmless.
    try t.expect(!policy.forget(dropped));
    try t.expectEqual(@as(usize, 2), policy.count());
    try t.expect(policy.holds(kept));
}

test "one peer leaving takes it out of every topic that named it" {
    var policy = TopicPolicy.init();
    const gone = try test_node_id.testNodeId(5);
    const staying = try test_node_id.testNodeId(6);
    const room_a = testTopic(1);
    const room_b = testTopic(2);
    _ = try policy.admit(room_a, null, try Peers.init(&.{ gone, staying }));
    _ = try policy.admit(room_b, null, try Peers.init(&.{ gone }));

    // Two lists named it and both lost it, which is the answer to "does a peer
    // this node has decided against still get dialled somewhere".
    try t.expectEqual(@as(usize, 2), policy.forgetPeer(gone));
    try t.expect(!inList(policy.introductions(room_a).?, gone));
    try t.expect(!inList(policy.introductions(room_b).?, gone));
    // The peer that stayed is untouched in the list it was in, and the topic
    // whose list is now empty is still a topic this node is in: the list is
    // the bootstrap, not the membership, so forgetting a peer frees no slot.
    try t.expect(inList(policy.introductions(room_a).?, staying));
    try t.expectEqual(@as(usize, 0), policy.introductions(room_b).?.len);
    try t.expectEqual(@as(usize, 2), policy.count());
    try t.expect(policy.holds(room_b));

    // A peer no list ever named changes nothing.
    try t.expectEqual(@as(usize, 0), policy.forgetPeer(try test_node_id.testNodeId(7)));
    try t.expectEqual(@as(usize, 2), policy.count());
}

test "one peer can be in two topics and the outbound ceiling says what that costs" {
    var policy = TopicPolicy.init();
    const shared = try test_node_id.testNodeId(8);
    const only_a = try test_node_id.testNodeId(9);
    const room_a = testTopic(1);
    const room_b = testTopic(2);
    _ = try policy.admit(room_a, try PeerData.fromBytes("first"), try Peers.init(&.{ shared }));
    _ = try policy.admit(room_b, try PeerData.fromBytes("second"), try Peers.init(
        &.{ shared, only_a },
    ));

    // Overlapping membership is allowed and each topic keeps its own words: a
    // peer in two topics is one peer, and the two topics say different things
    // to it.
    try t.expectEqual(@as(usize, 2), policy.count());
    try t.expectEqualStrings("first", policy.advertised(room_a).?);
    try t.expectEqualStrings("second", policy.advertised(room_b).?);
    try t.expectEqual(@as(usize, 1), policy.introductions(room_a).?.len);
    try t.expectEqual(@as(usize, 2), policy.introductions(room_b).?.len);

    // And the ceiling is arithmetic over the topics, not over their peers: two
    // topics three peers wide can name up to `max_active` each, and the node's
    // outbound set is the sum because the memberships do not overlap. The peer
    // above is named in both lists and is counted twice, which is exactly why
    // the sum is larger than the union.
    try t.expectEqual(@as(usize, 8 * gossip.max_active), max_outbound);
    try t.expect(max_outbound > gossip.max_active);
}

/// Whether `peers` holds `peer`.
fn inList(peers: []const NodeId, peer: NodeId) bool {
    for (peers) |held| {
        if (held.order(peer) == .eq) return true;
    }
    return false;
}
