//! Which topics this node is in, and what it tells each of them about itself.
//!
//! The membership half of the layer `topic_policy.zig` is the face of. That
//! file holds the module doc, and it holds the reasons: what a join is, why
//! `forget` is the only door out, why two topics may share a peer, and what the
//! bound costs. They are the layer's decisions and none of them is this file's
//! to restate, so what is here is the storage and the transitions.
//!
//! **The bounds and the refusal are `topic_bounds.zig`'s**, and are read from
//! it rather than repeated: `max_topics` sizes the array below, and `admit`
//! refuses with `error.TopicsFull` because the ceiling is one number the caller
//! can read before it builds any of this.
//!
//! **It allocates nothing, so there is no allocator to pass.** Every record is
//! inline: the topics are a fixed array sized by `topic_bounds.max_topics`,
//! and a topic's contact bytes and introduction list are the protocol's own
//! `PeerData` and `Peers`, which are values. So the whole policy is a value a
//! caller holds beside its `TopicState`s, with no allocation to inject a
//! failure into and none to forget releasing.
//!
//! **`NodeId` comes from `base/key.zig` rather than from `gossip`,** because
//! `hyparview.zig` does not re-export it and a `NodeId` is one type across the
//! tree — the same spelling `node/topic_table.zig` uses for the peers it
//! routes to the same topics.

const base_key = @import("../base/key.zig");
const bounds = @import("topic_bounds.zig");
const gossip = @import("hyparview.zig");

const NodeId = base_key.NodeId;
const PeerData = gossip.PeerData;
const Peers = gossip.Peers;
const TopicId = gossip.TopicId;

const max_topics = bounds.max_topics;

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
        const held = if (self.entries[index].data) |*data| data else return null;
        if (held.isEmpty()) return null;
        return held.slice();
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
    ) bounds.PolicyError!Admission {
        if (self.indexOf(topic) != null) return .already;
        if (self.len == max_topics) return error.TopicsFull;
        self.entries[self.len] = .{ .topic = topic, .data = data, .peers = peers };
        self.len += 1;
        return .admitted;
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
        // ZBC cannot infer that indexOf returns only a live-prefix index, so self.len is positive.
        // zbc-disable-next-line: index-minus-one-without-zero-guard
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
        // ZBC cannot infer that entering this live-prefix loop proves list.count is positive.
        // zbc-disable-next-line: index-minus-one-without-zero-guard
        list.items[index] = list.items[list.count - 1];
        list.count -= 1;
        return true;
    }
    return false;
}
