//! How much of the swarm this node takes part in, and the one answer a caller
//! gets for asking past it.
//!
//! **It is separate from the membership because a caller may read these and
//! hold no membership at all.** Sizing a connection directory is
//! `max_outbound`, and a caller that has not decided which topics to join reads
//! that number first — so the ceilings are a thing in their own right rather
//! than a detail of a table it has not built.
//!
//! **Nothing here grows and nothing here is a cache.** Each number is the size
//! of the refusal that guards it: `max_topics` is how many topics exist, and
//! the ninth is refused rather than admitted by dropping a live one. That is
//! `node/topic_table.zig`'s position for the routing half of the same operator
//! decision, and it is why the refusal is a named error and not a replacement.
//!
//! **The reasons live in `topic_policy.zig` and are not repeated here.** What a
//! join is, why `forget` is the only door out, why two topics may share a peer
//! and what that costs are the layer's decisions; this file holds the numbers
//! and the error they refuse with.

const gossip = @import("hyparview.zig");

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
