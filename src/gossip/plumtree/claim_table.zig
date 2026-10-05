//! One missing-message entry's shape: who claimed it, how far they claimed to
//! be, and whether a `Graft` timer is already running for it.
//!
//! Upstream's `HashMap<MessageId, VecDeque<(PI, Round)>>` plus
//! `graft_timer_scheduled: HashSet<MessageId>`, with the two merged. The merge
//! is not a simplification, it is a bound: the flag is only ever set on an id
//! that has an entry, so the number of outstanding graft timers cannot exceed
//! `max_missing` and needs no second table.
//!
//! The protocol-wide story — the `MessageId` rule, re-validation, the iTree,
//! purity, bounds and divergences — is in `../plumtree.zig`, which is the module
//! callers import. This file is one piece of it.

const key = @import("../../base/key.zig");
const limits = @import("limits.zig");
const message = @import("message.zig");
const message_id = @import("message_id.zig");

const NodeId = key.NodeId;
const MessageId = message_id.MessageId;
const Round = message.Round;
const max_claims = limits.max_claims;

/// One "peer X claims message M, Y hops from the origin" claim.
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
pub const MissingEntry = struct {
    id: MessageId,
    count: u16,
    graft_timer_scheduled: bool,
    peers: [max_claims]NodeId,
    rounds: [max_claims]Round,
};
