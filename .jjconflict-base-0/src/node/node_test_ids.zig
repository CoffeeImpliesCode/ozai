//! The peers the node layer's own tables name in tests, derived from a seed so
//! that the same seed is the same peer on every run.
//!
//! **Test support, and nothing else.** `conn_index.zig` and `topic_table.zig`
//! both need several distinct peers, and both need them to come out of
//! `base/key.zig` the same way, so the derivation lives here rather than
//! written twice. `relay/relay_test_ids.zig` is the same fixture for the
//! relay's three modules and is not exported by anything.
//!
//! It is not a general factory: the seed is a byte and the value is an ed25519
//! node id, and there is no other peer a test in this directory needs.

const key = @import("../base/key.zig");

const NodeId = key.NodeId;

/// The peer that seed names.
///
/// **Real ids, and not 32 bytes that were never a point.** `NodeId`'s own
/// documentation says its `key` field is a precondition rather than an
/// invariant, so a struct literal would make a table under test hold a value
/// the identity type does not promise is an identity. Deriving one from a seed
/// costs a key generation and cannot produce a peer that `fromBytes` would
/// have refused.
///
/// `fromSeed` fails only on a degenerate seed, which a uniform fill is not,
/// and the error is propagated rather than asserted away: a seed that was
/// somehow not accepted fails the test that named it, not the whole run.
///
/// The secret is wiped before the id leaves, so a peer named in a test leaves
/// no key material on the stack behind it.
pub fn testNodeId(seed: u8) !NodeId {
    var secret = try key.SecretKey.fromSeed([_]u8{seed} ** key.SecretKey.seed_length);
    defer secret.deinit();
    return secret.nodeId();
}
