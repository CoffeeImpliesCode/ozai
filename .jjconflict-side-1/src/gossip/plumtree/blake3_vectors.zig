//! BLAKE3's own published vectors, and the two helpers that turn them into a
//! `MessageId`.
//!
//! These bytes are a wire contract, not a fixture for this implementation: the
//! `hash` column is what a `MessageId` is, and a peer on the reference
//! computes the same value for the same content. They are kept in one file,
//! unmoved and in their published order, so that "did the table change?" is a
//! question with one answer.
//!
//! `derive_key` is the same input under key derivation and the published
//! context string. It is here so the rejection test can use a real
//! domain-separated digest rather than a made-up one.

const std = @import("std");
const limits = @import("limits.zig");
const message_id = @import("message_id.zig");

const t = std.testing;

const MessageId = message_id.MessageId;
const id_length = limits.id_length;

/// The input of a BLAKE3 test-vector case: 0, 1, ... 250 repeating.
///
/// Fallible for the ordinary reason: the testing allocator runs out like any
/// other, and a test that cannot say so is a test that reports a crash.
pub fn blake3Input(len: usize) ![]u8 {
    const input = try t.allocator.alloc(u8, len);
    for (input, 0..) |*byte, index| byte.* = @intCast(index % 251);
    return input;
}

/// BLAKE3 test vectors from `BLAKE3-team/BLAKE3`,
/// `test_vectors/test_vectors.json`, commit
/// `6aab490a26124663329dfd3961b8469f8fdb158b`, fetched 2026-09-30. The input of
/// each case is the 251-byte sequence 0, 1, ... 250 repeating, per the
/// `COMMENT` in `test_vectors/src/lib.rs` at the same commit.
///
/// `hash` is the plain hash, which is what a `MessageId` is. `derive_key` is
/// the same input under the key-derivation mode and the context string
/// `BLAKE3 2019-12-27 16:29:52 test vectors context`; it is here so the
/// rejection test can use a real domain-separated digest.
/// The 32 bytes behind a 64-character hex digest, decoded at run time.
/// A `MessageId` is a byte array, so a table of published digests has to be
/// decoded before it can be compared with one, and a comptime decode of two
/// dozen literals costs more compile time than the whole rest of the module.
pub fn messageIdFromHex(hex: []const u8) MessageId {
    if (hex.len != id_length * 2) @panic("a digest literal must be 64 hex characters");
    var bytes: [id_length]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, hex) catch @panic("a digest literal must be hex");
    return MessageId.fromBytes(bytes);
}

pub const Blake3Vector = struct {
    len: usize,
    /// The plain hash: this is what a `MessageId` is.
    hash: []const u8,
    /// The same input under key derivation and the published context string.
    derive_key: []const u8,
};

pub const blake3_vectors = [_]Blake3Vector{
    .{
        .len = 0,
        .hash = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        .derive_key = "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d",
    },
    .{
        .len = 1,
        .hash = "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
        .derive_key = "b3e2e340a117a499c6cf2398a19ee0d29cca2bb7404c73063382693bf66cb06c",
    },
    .{
        .len = 2,
        .hash = "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63",
        .derive_key = "1f166565a7df0098ee65922d7fea425fb18b9943f19d6161e2d17939356168e6",
    },
    .{
        .len = 3,
        .hash = "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f",
        .derive_key = "440aba35cb006b61fc17c0529255de438efc06a8c9ebf3f2ddac3b5a86705797",
    },
    .{
        .len = 8,
        .hash = "2351207d04fc16ade43ccab08600939c7c1fa70a5c0aaca76063d04c3228eaeb",
        .derive_key = "2b166978cef14d9d438046c720519d8b1cad707e199746f1562d0c87fbd32940",
    },
    .{
        .len = 63,
        .hash = "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b",
        .derive_key = "b6451e30b953c206e34644c6803724e9d2725e0893039cfc49584f991f451af3",
    },
    .{
        .len = 64,
        .hash = "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98",
        .derive_key = "a5c4a7053fa86b64746d4bb688d06ad1f02a18fce9afd3e818fefaa7126bf73e",
    },
    .{
        .len = 127,
        .hash = "d81293fda863f008c09e92fc382a81f5a0b4a1251cba1634016a0f86a6bd640d",
        .derive_key = "c91c090ceee3a3ac81902da31838012625bbcd73fcb92e7d7e56f78deba4f0c3",
    },
    .{
        .len = 128,
        .hash = "f17e570564b26578c33bb7f44643f539624b05df1a76c81f30acd548c44b45ef",
        .derive_key = "81720f34452f58a0120a58b6b4608384b5c51d11f39ce97161a0c0e442ca0225",
    },
    .{
        .len = 1023,
        .hash = "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11",
        .derive_key = "74a16c1c3d44368a86e1ca6df64be6a2f64cce8f09220787450722d85725dea5",
    },
    .{
        .len = 1024,
        .hash = "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
        .derive_key = "7356cd7720d5b66b6d0697eb3177d9f8d73a4a5c5e968896eb6a689684302706",
    },
};
