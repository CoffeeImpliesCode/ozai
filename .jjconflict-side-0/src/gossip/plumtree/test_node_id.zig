//! Node ids for the tests, from fixed seeds.
//!
//! A `NodeId` cannot be built from arbitrary bytes, so a test pool draws from
//! seeds, as `discovery/item.zig` does. This lives beside the tests rather than
//! in `../plumtree.zig` because it is the only thing in the protocol that needs
//! no production caller.

const key = @import("../../base/key.zig");

const NodeId = key.NodeId;

/// Node ids from fixed seeds, as `discovery/item.zig` does them. A `NodeId`
/// cannot be built from arbitrary bytes — `fromBytes` rejects a non-point — so
/// a test pool draws from seeds.
///
/// Fallible, because a seed that derives the identity point is a `u8` value
/// away and nothing about `0xa5` rules it out. A test that hit one says
/// `error.DegenerateSeed` and names its seed; a `unreachable` here would take
/// the whole test binary down and say nothing.
pub fn testNodeId(index: u8) key.KeyError!NodeId {
    var seed: [key.SecretKey.seed_length]u8 = undefined;
    @memset(&seed, 0xa5);
    seed[0] = index;
    return (try key.SecretKey.fromSeed(seed)).nodeId();
}
