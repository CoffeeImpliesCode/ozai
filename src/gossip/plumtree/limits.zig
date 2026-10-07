//! The value domain and the bounds of the PlumTree state machine.
//!
//! Time is an integer count of nanoseconds handed in by the caller, every
//! collection has a fixed capacity, and every refusal is one of the errors in
//! `Error`. They live together because they are the same contract stated three
//! ways: what the machine can hold, and what it says when it cannot.
//!
//! `hyparview.zig` and the simulator both read their durations from here, so a
//! number written once is a number written once.
//!
//! The protocol-wide story — the `MessageId` rule, re-validation, the iTree,
//! purity, bounds and divergences — is in `../plumtree.zig`, which is the module
//! callers import. This file is one piece of it.

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

/// The largest content fitting a 4096-byte received neighbor Gossip:
/// two tags, 32 hash bytes, two length bytes, and one scope tag.
pub const max_content = 4096 - 37;

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

/// The largest frame-fitting IHave vector: two tags, one count, and at least
/// 32 hash bytes plus one round byte per record.
pub const max_ihaves_per_message = @divFloor(4096 - 3, 33);

/// How many peers may have a lazy-push queue at once.
pub const max_queue_peers = 32;

/// Every way this state machine can refuse to do what it was asked.
pub const Error = error{
    /// An iTree peer set would have grown past `max_peers`.
    PeerSetFull,
    /// A payload exceeds storage capacity or its broadcast reaches the strict wire-body limit.
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
