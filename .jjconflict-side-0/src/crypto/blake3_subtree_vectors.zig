//! BLAKE3's published root hashes for the inputs a tree walk needs that
//! `../gossip/plumtree/blake3_vectors.zig` does not carry.
//!
//! That table stops at 1024 bytes — one chunk — because a `MessageId` is a
//! whole message and nothing in PlumTree is longer than that. A tree's claims
//! start where a message ends: the root of a two-, four-, eight- or
//! sixteen-chunk input is what shows that a subtree's chaining value and a
//! merge of two chaining values are the tree's own values and not just some
//! value this code can reproduce. The same JSON file, at the same commit,
//! carries those digests.
//!
//! They are kept in their own file rather than appended to the PlumTree table
//! because the two tables are different contracts with disjoint lengths: one
//! is a protocol's wire type, this one is a tree walk's root, and a reader
//! asking "is this length a `MessageId` or a tree?" should be able to tell
//! from the file it came out of.

/// One published case: the input's length in bytes, and the first 32 bytes of
/// its `hash` as 64 hex characters.
pub const SubtreeVector = struct {
    len: usize,
    /// The 32-byte digest, as hex.
    hash: []const u8,
};

/// From `BLAKE3-team/BLAKE3`, `test_vectors/test_vectors.json`, commit
/// `6aab490a26124663329dfd3961b8469f8fdb158b` — the commit
/// `../gossip/plumtree/blake3_vectors.zig` already cites, read 2026-10-05.
/// That file's `hash` column is extended output; a digest is its first 32
/// bytes. The input is the 251-byte repeating sequence 0, 1, ... 250 that
/// `../gossip/plumtree/blake3_vectors.zig` defines, per the `_comment` in the
/// same JSON.
pub const subtree_vectors = [_]SubtreeVector{
    .{
        .len = 2048,
        .hash = "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a",
    },
    .{
        .len = 4096,
        .hash = "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969",
    },
    .{
        .len = 8192,
        .hash = "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a63",
    },
    .{
        .len = 16384,
        .hash = "f875d6646de28985646f34ee13be9a576fd515f76b5b0a26bb324735041ddde4",
    },
};
