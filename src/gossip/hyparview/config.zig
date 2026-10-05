//! What a caller configures membership with, what membership reports, and the
//! short peer list a join carries.
//!
//! Upstream `hyparview::Config`, whose defaults are the paper's where it has any
//! and a labelled guess where it does not. `Config.validate` is the one place a
//! capacity that the fixed sets cannot hold is refused.
//! The protocol-wide story — the `Neighbor` deviation, the `TopicId` privacy
//! note and the purity rules — is in `../hyparview.zig`, which is the module
//! callers import. This file is one piece of it.

const std = @import("std");

const key = @import("../../base/key.zig");
const plumtree = @import("../plumtree.zig");
const bounds = @import("bounds.zig");
const wire = @import("message.zig");

const NodeId = key.NodeId;
const Nanos = plumtree.Nanos;
const nanos_per_milli = plumtree.nanos_per_milli;
const nanos_per_second = plumtree.nanos_per_second;
const Ttl = wire.Ttl;
const Error = bounds.Error;
const max_active = bounds.max_active;
const max_bootstrap = bounds.max_bootstrap;
const max_passive = bounds.max_passive;
const max_shuffle_nodes = bounds.max_shuffle_nodes;

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
