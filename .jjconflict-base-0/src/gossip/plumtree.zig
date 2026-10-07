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
//! # What is in `plumtree/`, and why
//!
//! This file is the module callers import and the only public surface: every
//! name below is re-exported from the file that owns it, so nothing outside
//! `src/gossip/` changes. The split is by responsibility, and each piece is
//! here for one reason:
//!
//! - `limits.zig` — the unit, every fixed capacity, and the one error set.
//!   They are the same contract: what the machine can hold, and what it says
//!   when it cannot.
//! - `message_id.zig` — `MessageId` and `domainSeparatedId`. The rule the
//!   whole protocol rests on, and the one way to compute a wrong id.
//! - `message.zig` — rounds, scopes and the wire vocabulary.
//! - `config.zig` — the settings `State` reads per event, and the counters.
//! - `actions.zig` — the caller-owned output list, which is why no protocol
//!   function takes an allocator.
//! - `node_id.zig` — `sameNode`, the one identity comparison every
//!   peer-keyed structure below is built on.
//! - `peer_set.zig`, `id_cache.zig`, `message_cache.zig` — the three bounded
//!   containers, each with its own eviction rule.
//! - `claim_table.zig` — the missing-message entry shape and why the graft
//!   timer flag is merged into it.
//! - `state.zig` — the state machine itself.
//! - `blake3_vectors.zig` — BLAKE3's published vectors. **Wire contract, not
//!   a fixture**: the `hash` column is what a `MessageId` is, and a peer on
//!   the reference computes the same value for the same content. It is kept in
//!   one file, unmoved and in published order.
//! - `*_test.zig` — the tests, beside the code they exercise.

const actions = @import("plumtree/actions.zig");
const config = @import("plumtree/config.zig");
const limits = @import("plumtree/limits.zig");
const message = @import("plumtree/message.zig");
const message_id = @import("plumtree/message_id.zig");
const state = @import("plumtree/state.zig");

pub const Nanos = limits.Nanos;
pub const nanos_per_milli = limits.nanos_per_milli;
pub const nanos_per_second = limits.nanos_per_second;

pub const id_length = limits.id_length;
pub const max_content = limits.max_content;
pub const cache_slots = limits.cache_slots;
pub const max_received_ids = limits.max_received_ids;
pub const max_peers = limits.max_peers;
pub const max_missing = limits.max_missing;
pub const max_claims = limits.max_claims;
pub const max_queued_ihaves = limits.max_queued_ihaves;
pub const max_ihaves_per_message = limits.max_ihaves_per_message;
pub const max_queue_peers = limits.max_queue_peers;

pub const Error = limits.Error;

pub const Actions = actions.Actions;

pub const MessageId = message_id.MessageId;
pub const domainSeparatedId = message_id.domainSeparatedId;

pub const Round = message.Round;
pub const DeliveryScope = message.DeliveryScope;
pub const Scope = message.Scope;
pub const deliveryScope = message.deliveryScope;
pub const Gossip = message.Gossip;
pub const IHave = message.IHave;
pub const IHaves = message.IHaves;
pub const Graft = message.Graft;
pub const Message = message.Message;
pub const Timer = message.Timer;
pub const GossipEvent = message.GossipEvent;
pub const OutEvent = message.OutEvent;
pub const InEvent = message.InEvent;

pub const Config = config.Config;
pub const Stats = config.Stats;

pub const State = state.State;

test {
    _ = @import("plumtree/blake3_test.zig");
    _ = @import("plumtree/state_test.zig");
    _ = @import("plumtree/recovery_test.zig");
    _ = @import("plumtree/cache_test.zig");
}
