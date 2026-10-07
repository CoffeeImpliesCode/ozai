//! The settings `State` reads per event, and the counters it reports.
//!
//! Upstream `plumtree::Config`, with durations as integer nanoseconds because
//! nothing here may read a clock. `Stats` is what a caller reads to say what
//! the node did while it was on the topic.
//!
//! The protocol-wide story — the `MessageId` rule, re-validation, the iTree,
//! purity, bounds and divergences — is in `../plumtree.zig`, which is the module
//! callers import. This file is one piece of it.

const limits = @import("limits.zig");
const message = @import("message.zig");

const Nanos = limits.Nanos;
const nanos_per_milli = limits.nanos_per_milli;
const nanos_per_second = limits.nanos_per_second;
const Round = message.Round;

/// Upstream `plumtree::Config`, with durations as integer nanoseconds because
/// nothing here may read a clock.
pub const Config = struct {
    /// How long to wait for an eager push after an `IHave` before grafting.
    /// Paper p8: a function of the overlay diameter and the application's
    /// recovery-latency target. Upstream default 80 ms.
    graft_timeout_1: Nanos = 80 * nanos_per_milli,
    /// How long to wait for the payload after a `Graft` before grafting
    /// somebody else. Paper p9: smaller than the first, about one round trip.
    /// Upstream default 40 ms.
    graft_timeout_2: Nanos = 40 * nanos_per_milli,
    /// How long `IHave`s are batched before being sent. Upstream default 5 ms.
    dispatch_timeout: Nanos = 5 * nanos_per_milli,
    /// How many rounds closer a lazy peer must claim to be before the tree is
    /// optimised. Paper p12. Upstream default 7.
    optimization_threshold: Round = .{ .value = 7 },
    /// How long a payload stays available to answer a late `Graft`. Upstream
    /// default 30 s.
    message_cache_retention: Nanos = 30 * nanos_per_second,
    /// How long a message id is remembered, which is what makes a duplicate a
    /// duplicate. Upstream default 90 s.
    message_id_retention: Nanos = 90 * nanos_per_second,
    /// How often the caches are swept. Upstream default 1 s.
    cache_evict_interval: Nanos = nanos_per_second,
};

/// Counters, upstream `plumtree::Stats`. `payload_messages_received` counts
/// payloads that arrived, including ones re-validation then dropped; see the
/// module doc.
pub const Stats = struct {
    payload_messages_received: u64 = 0,
    control_messages_received: u64 = 0,
    max_last_delivery_hop: u16 = 0,
};
