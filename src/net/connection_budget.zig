//! Whether this node takes one more peer, and what it says when it does not.
//!
//! `node/conn_index.zig` owns the directory and already refuses a bind past its
//! bound with `error.NoFreeSlot`. This file is the decision **in front of** it:
//! it turns one arriving attempt plus what the node already holds into one
//! answer, and it keeps apart what the **peer** learns from what the
//! **operator** learns, because those are two different facts and one counter
//! cannot hold both.
//!
//! **Pure: the attempt and the count are the caller's.** Nothing here opens a
//! socket, reads a clock, or allocates. The arriving attempt is already a value
//! (`endpoint/incoming_filter.zig:238-255`) and the occupancy is a count the
//! directory already keeps (`node/conn_index.zig:140-142`).
//!
//! **It holds no peers, so its bound is a refusal and not a capacity.** The
//! storage is `ConnIndex`'s `[max_peers]Entry`. A second directory here would
//! be a second answer to "which peers does this node speak to", and
//! `transport/bridge_config.zig:152-156` refuses exactly that shape for the
//! ALPN: one number, held in one place, read by everyone.
//!
//! # At the bound: refuse, and do not evict
//!
//! **Refusing is right here, but the tree's reasons do not transfer, so they
//! are not the argument.** `node/topic_table.zig:52-58` refuses because a topic
//! entry is this node's own bookkeeping: evicting one unsubscribes it from a
//! swarm whose `TopicState` is still running, and nothing reports the loss. A
//! connection is none of those things, so the case is made again from the
//! connection's own side:
//!
//! 1. **The trade is not symmetric.** The peer that would be evicted is one this
//!    node finished a handshake with, holds streams on, and has already counted
//!    in its gossip views — `gossip/topic_bounds.zig:41-49` names
//!    `max_topics * max_active` outbound peers, and every one of them is a
//!    socket. The peer that would take its place has presented a certificate
//!    and nothing else. Shedding the first for the second is a downgrade
//!    dressed as an admission.
//! 2. **Nothing here could choose honestly.** The only rules available are
//!    oldest-first and arbitrary, and oldest-first needs a clock. This module
//!    has none (`AGENTS.md` §2), and `ConnIndex` says outright that its entry
//!    order is first-bound order and not a property
//!    (`node/conn_index.zig:108-110`). A policy that reads that order is not a
//!    policy; it is a preference invented here and never defended.
//! 3. **Eviction is silent to the peer and counted nowhere.** The far end sees
//!    a transport close with no cause, and this node drops a per-connection
//!    state the `Conn` and the session store own. A refusal costs the
//!    directory nothing and the peer one attempt it is free to make again.
//!
//! So `at_bound` is a refusal — and a peer this node **already holds** is not
//! refused at the bound at all: a rebind needs no slot
//! (`node/conn_index.zig:97-106`), so a full directory is a node that cannot
//! widen, not a node that cannot reconnect.
//!
//! # What a refusal says, and to whom
//!
//! **To the peer: `.reject`, and never `.ignore` or `.retry`.**
//! `incoming_filter.Answer` has four answers and the other three are wrong for
//! reasons this module owns:
//!
//! - `.ignore` sends nothing, and upstream does not even log it
//!   (`incoming_filter.zig:107-109`). To the peer that is indistinguishable
//!   from a lost packet: it waits out the handshake timeout and reports a
//!   timeout. A peer that cannot tell a full node from a dead one cannot go and
//!   find another, which is the only thing it could usefully do.
//! - `.retry` is worse, and here it is not even available. A Retry token is
//!   address validation (`incoming_filter.zig:94-98`), so spending this node's
//!   one permitted Retry per flow on a capacity answer asks the peer to prove
//!   what it has already proved; and `incoming_filter.admit` already rewrites
//!   `.retry` into `.reject` on a flow that has proved its address
//!   (`incoming_filter.zig:270-284`). One decision would then reach the wire as
//!   a token on one attempt and a close on the next, chosen by a fact about the
//!   peer rather than about this node's capacity.
//! - `.reject` says it once, inside the handshake, and it is the one ending
//!   `incoming_filter` documents as the one the peer is told about.
//!
//! **To the operator: a named reason, counted apart.** `node/node_stats.zig:32`
//! carries one `refusals` counter, and one counter cannot answer the question
//! an operator actually has, because the two reasons have different fixes:
//!
//! - `at_bound` says the operator's own number is too low for the traffic this
//!   node is being offered. The fix is `max_peers`.
//! - `no_identity` says an attempt completed with no node id, so there is
//!   nothing to route and nothing to answer later — `node/node_accept.zig:79`
//!   drops exactly these with a bare `continue` today, which is a refusal with
//!   no count at all. The fix is not a larger bound; the other end is not a
//!   node.
//!
//! Counted together, a port scanner and a busy node produce one number and the
//! operator cannot tell which they are looking at. So `reason` travels with the
//! answer and is null only when the peer was admitted: an admitted peer needs
//! no accounting, and a reason that could be null for that reason is a reason
//! an operator learns to ignore.

const std = @import("std");

const base_key = @import("../base/key.zig");
const conn_index = @import("../node/conn_index.zig");
const incoming_filter = @import("../endpoint/incoming_filter.zig");

const NodeId = base_key.NodeId;

/// How many peers this node speaks to at once.
///
/// **Read from the directory rather than written here.** `ConnIndex`'s storage is
/// `[max_peers]Entry`, so a second number would be a second place for the
/// node's peer width and the table that holds it to disagree. The tree holds one
/// peer limit and this is that one, named so a caller in this layer can ask the
/// question without importing the node's directory.
pub const max_peers: usize = conn_index.max_peers;

/// Why one arriving attempt was refused.
pub const Reason = enum {
    /// The attempt named no node id, so it cannot be routed to and cannot be
    /// answered on a stream later.
    ///
    /// **Refused below the bound, and never queued.** There is no peer here for
    /// a later message to be about, so waiting would hold a handshake open on
    /// behalf of nobody — and the handshake is the resource `max_peers` exists
    /// to bound.
    no_identity,
    /// The directory holds `max_peers` peers and this is not one of them.
    ///
    /// **Nothing is given up to make room.** See the module doc for why the
    /// tree's refuse-not-evict reasons do not transfer here and what does.
    at_bound,
};

/// One arriving attempt, as this decision is asked about it.
pub const Attempt = struct {
    /// The peer on the other end, or null for an attempt that named none.
    ///
    /// Read only for whether it is there. *Which* peer arrived is not an input
    /// to this decision: nothing in the tree's position makes one peer more
    /// admissible than another, and a rule that ranked them would be a
    /// preference invented here rather than a bound anybody chose.
    peer: ?NodeId,
    /// Whether the directory already routes `peer`.
    ///
    /// The caller's answer, not this module's: `ConnIndex` holds the peers and
    /// this module holds none, so a second copy of that lookup would be a
    /// second answer to "does this node speak to that peer already".
    returning: bool,
    /// How many peers the directory holds.
    ///
    /// The caller's count for the same reason. `ConnIndex.count()` already
    /// answers it, and a caller passing anything else is a caller this module
    /// cannot rescue.
    held: usize,
};

/// One decision, in both the forms it is delivered in.
///
/// **The two fields are not the same fact.** `answer` is what crosses the wire
/// to a peer; `reason` is what an operator reads. They are carried together so
/// that a caller cannot tell the peer one thing and count another.
pub const Admission = struct {
    /// What the peer is told, in the four answers the accept filter already has.
    /// Never `.retry`: see the module doc.
    answer: incoming_filter.Answer,
    /// Why the peer was refused, and null when it was admitted.
    reason: ?Reason,
};

/// Whether this node takes `attempt`, and what it says either way.
///
/// Total, allocation-free, and a function of its argument alone: calling it
/// twice with the same attempt gives the same answer and reserves nothing on
/// the second call, which is what "a refusal and not a queue" means when there
/// is no state here to grow.
pub fn decide(attempt: Attempt) Admission {
    // A count above the bound cannot be a state to decide about: the
    // directory's storage is `[max_peers]Entry` and cannot hold more, so an
    // answer computed on such a count would be answering a question nobody
    // asked. Caught where the mistake is rather than turned into a refusal the
    // caller would have to interpret.
    std.debug.assert(attempt.held <= max_peers);

    // Identity first, because no bound can make room for it: this peer does not
    // exist as far as the directory is concerned, so the count is beside the
    // point. Reporting `at_bound` for an attempt that named nobody would send
    // an operator to raise a bound that was never the problem.
    if (attempt.peer == null) {
        return .{ .answer = .reject, .reason = .no_identity };
    }
    // A peer the directory already routes needs no slot, so the bound does not
    // apply to it. This is `ConnIndex`'s own position — a rebind replaces rather
    // than refuses (`node/conn_index.zig:97-106`) — and it is why a full
    // directory is a node that cannot widen rather than one that cannot
    // reconnect.
    if (attempt.returning) {
        return .{ .answer = .accept, .reason = null };
    }
    if (attempt.held == max_peers) {
        return .{ .answer = .reject, .reason = .at_bound };
    }
    return .{ .answer = .accept, .reason = null };
}

// --- tests

const t = std.testing;
const test_ids = @import("../node/node_test_ids.zig");
const Answer = incoming_filter.Answer;

test "an attempt below the bound is admitted and one past it is refused as at_bound" {
    // The production bound, so the number an operator picks is the one under
    // test. It is read rather than written, so pinning it also pins the claim
    // that this module and the directory are held to one peer limit.
    try t.expectEqual(@as(usize, 32), max_peers);
    try t.expectEqual(max_peers, conn_index.max_peers);

    const peer = try test_ids.testNodeId(1);
    const stranger = try test_ids.testNodeId(2);

    // An empty directory admits anything that names a peer, and an admitted
    // peer needs no accounting — the reason is null rather than some "none"
    // variant, so a caller cannot count it.
    const first = decide(.{ .peer = peer, .returning = false, .held = 0 });
    try t.expectEqual(Answer.accept, first.answer);
    try t.expect(first.reason == null);

    // One slot short of the bound is still admitted: the refusal is at the
    // bound and not one past it, which is the whole content of the number.
    const last = decide(.{ .peer = stranger, .returning = false, .held = max_peers - 1 });
    try t.expectEqual(Answer.accept, last.answer);
    try t.expect(last.reason == null);

    // At the bound it is refused, and refused with the reason that names the
    // operator's own number rather than with a bare "full".
    const refused = decide(.{ .peer = stranger, .returning = false, .held = max_peers });
    try t.expectEqual(Answer.reject, refused.answer);
    try t.expectEqual(Reason.at_bound, refused.reason.?);
}

test "a peer this node already holds is admitted at the bound" {
    // The one case the bound does not apply to. A directory at `max_peers`
    // holds every peer it will hold, and the peer that is already one of them
    // costs no slot to keep — so refusing it here would refuse a reconnect at
    // a full node, which is the failure `ConnIndex.remove` exists to make
    // impossible.
    const peer = try test_ids.testNodeId(3);
    const admitted = decide(.{ .peer = peer, .returning = true, .held = max_peers });
    try t.expectEqual(Answer.accept, admitted.answer);
    try t.expect(admitted.reason == null);

    // The same peer against a directory that is not full is admitted the same
    // way: the bound is not what made the difference, and a caller must not be
    // able to read "returning" as a special case of an admission that only
    // holds at one occupancy.
    const roomy = decide(.{ .peer = peer, .returning = true, .held = 0 });
    try t.expectEqual(Answer.accept, roomy.answer);
    try t.expect(roomy.reason == null);
}

test "an attempt that named no peer is refused below the bound" {
    // Below the bound, so the refusal cannot be the count: there is room here
    // and the answer is still a refusal. This is the attempt
    // `node/node_accept.zig:79` drops with a bare `continue` today.
    const nameless = decide(.{ .peer = null, .returning = false, .held = 0 });
    try t.expectEqual(Answer.reject, nameless.answer);
    try t.expectEqual(Reason.no_identity, nameless.reason.?);

    // And it keeps its own name at the bound rather than reporting the count,
    // which is the ordering the module doc argues for: an operator sent to
    // raise `max_peers` because a scanner turned up would raise it for nothing.
    const full = decide(.{ .peer = null, .returning = false, .held = max_peers });
    try t.expectEqual(Reason.no_identity, full.reason.?);

    // A caller that claims such an attempt is a peer it already holds has
    // contradicted itself, and the identity is the fact that decides first.
    const claimed = decide(.{ .peer = null, .returning = true, .held = 0 });
    try t.expectEqual(Reason.no_identity, claimed.reason.?);
}

/// The attempt each refusal is reached from, so the sweep below asks about
/// every one of them without a hand-written list that could fall behind. The
/// switch is exhaustive over `Reason`, so a refusal added later has no attempt
/// to be swept with until one is written here — at compile time.
fn attemptFor(reason: Reason, peer: NodeId) Attempt {
    return switch (reason) {
        .no_identity => .{ .peer = null, .returning = false, .held = 0 },
        .at_bound => .{ .peer = peer, .returning = false, .held = max_peers },
    };
}

test "every refusal reaches the peer as a rejection and never as a silence" {
    const peer = try test_ids.testNodeId(4);

    // Swept at comptime over the whole reason set rather than case by case: the
    // two refusals are the two a peer must be able to tell from a lost packet,
    // and a refusal added later without an answer here would ship a silent one.
    inline for (@typeInfo(Reason).@"enum".fields) |field| {
        const reason: Reason = @enumFromInt(field.value);
        const admission = decide(attemptFor(reason, peer));
        // `reject`, and neither of the two answers a peer cannot act on:
        // `ignore` sends nothing, and `retry` would spend the flow's one
        // address validation on a fact about this node's capacity.
        try t.expectEqual(Answer.reject, admission.answer);
        // The operator's half is the same reason, named and never dropped on
        // the way to the peer.
        try t.expectEqual(reason, admission.reason.?);
    }
}

test "a refusal reserves nothing, and a departure is what frees the slot" {
    const stranger = try test_ids.testNodeId(5);
    const attempt: Attempt = .{ .peer = stranger, .returning = false, .held = max_peers };

    // Asked twice at the same count, refused twice: the first refusal queued
    // nothing, so the second is the same question with the same answer rather
    // than a second peer waiting behind the first.
    const first = decide(attempt);
    const second = decide(attempt);
    try t.expectEqual(first.answer, second.answer);
    try t.expectEqual(first.reason, second.reason);

    // The count is the caller's and is untouched — there is no field here for
    // a refusal to have grown, which is the structural half of "not a queue".
    try t.expectEqual(max_peers, attempt.held);

    // One departure is the only thing that frees the slot, and it frees it for
    // exactly this peer. That is the difference from a queue, which would have
    // made room on its own at some point this module decided on.
    const after = decide(.{ .peer = stranger, .returning = false, .held = max_peers - 1 });
    try t.expectEqual(Answer.accept, after.answer);
    try t.expect(after.reason == null);
}
