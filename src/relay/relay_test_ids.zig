//! The node ids the relay's own tests name, derived from a seed so that the same
//! node is the same node on every run.
//!
//! **Test support, and nothing else.** The three modules under test in
//! `relay/` — `server_handshake.zig`, `server_queue.zig` and
//! `server_registry.zig` — all need a deterministic node id and all need it to
//! come out of `base/key.zig` the same way, so the derivation lives here rather
//! than written three times. `relay/server.zig` re-exports none of it.
//!
//! It is not a general factory: the seed is a byte and the value is an ed25519
//! node id, and there is no other fixture in the relay that a test needs.

const key = @import("../base/key.zig");

const NodeId = key.NodeId;

/// A key from a fixed seed, so the node ids derived from it name the same nodes
/// on every run.
///
/// `fromSeed` fails only on a degenerate seed, which a uniform fill is not.
///
/// The error is propagated rather than asserted away anyway: a seed that was
/// somehow not accepted fails the test that named it, not the whole run.
pub fn testSecret(seed: u8) !key.SecretKey {
    return key.SecretKey.fromSeed(@as([key.SecretKey.seed_length]u8, @splat(seed)));
}

/// The node id that key claims.
pub fn testNodeId(seed: u8) !NodeId {
    return (try testSecret(seed)).nodeId();
}
