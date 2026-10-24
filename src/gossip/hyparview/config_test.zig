//! The bootstrap list and the configuration, both bounded before a run
//! rather than twenty messages into one.

const std = @import("std");
const key = @import("../../base/key.zig");
const bounds = @import("bounds.zig");
const settings = @import("config.zig");
const sim = @import("sim.zig");

const t = std.testing;

const NodeId = key.NodeId;
const max_shuffle_nodes = bounds.max_shuffle_nodes;
const max_active = bounds.max_active;
const max_passive = bounds.max_passive;
const max_bootstrap = bounds.max_bootstrap;
const Peers = settings.Peers;
const Config = settings.Config;

// A bootstrap list is bounded twice: by what a `u8` can count, and by
// `max_bootstrap`. Either half on its own would let the other one past.
test "a bootstrap list is refused by its count and by its length" {
    const peer = try sim.nodeIdFor(2);
    const over = @as([(max_bootstrap + 1)]NodeId, @splat(peer));
    const unspellable = @as([(std.math.maxInt(u8) + 1)]NodeId, @splat(peer));
    try t.expectError(error.BootstrapListTooLong, Peers.init(over[0..]));
    try t.expectError(error.BootstrapListTooLong, Peers.init(unspellable[0..]));
    const list = try Peers.init(over[0..max_bootstrap]);
    try t.expectEqual(max_bootstrap, list.slice().len);
}

// A config the fixed-capacity sets cannot hold is refused up front.
test "a config beyond the fixed views is refused" {
    try t.expectError(
        error.ActiveViewFull,
        (Config{ .active_view_capacity = max_active + 1 }).validate(),
    );
    try t.expectError(
        error.PassiveViewFull,
        (Config{ .passive_view_capacity = max_passive + 1 }).validate(),
    );
    try t.expectError(
        error.ShuffleNodeListTooLong,
        (Config{ .shuffle_active_view_count = max_shuffle_nodes }).validate(),
    );
    try (Config{}).validate();
}
