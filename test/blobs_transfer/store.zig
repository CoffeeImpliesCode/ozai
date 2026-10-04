//! What the provider holds: one blob, its hash, and the bao data a `push`
//! carries behind its request.
//!
//! Support for `test/blobs_transfer_test.zig`, split out of it so that the
//! bytes under test and the transport they cross are two files rather than
//! one. There is no protocol state here and none is wanted: `Store` is a
//! value the link owns, and the two halves of that test want different state
//! on top of exactly the same bytes.
//!
//! The one thing this file adds to the protocol is nothing — every step is the
//! protocol's own. `chunkCount` is `chunkAfterByte`, which is the first chunk
//! at or past a byte offset and, for a blob's own length, is its chunk count.

const std = @import("std");
const ozai = @import("ozai");

const blobs = ozai.blobs_protocol;

/// The provider's blob: 256 whole chunks and 700 bytes of a short one.
///
/// The size is chosen, not picked. Larger than one packet by three orders of
/// magnitude, and larger than `batch.max_segments_linux` datagrams, so the send
/// seam's segmentation is on the path rather than merely configured. The
/// remainder is 700 rather than 1024 so the last chunk is short, which is the
/// case `chunksToBytes` cannot answer exactly.
pub const blob_length: usize = 256 * 1024 + 700;

/// The blob's hash, and a request's hash is 32 raw bytes.
///
/// The first byte matters to one assertion in the test: overwriting a `get`
/// frame's discriminant with `push`'s makes that byte the declared body
/// length, and 0x5a is a one-byte varint for ninety — more than the frame has
/// left. See the framing test.
pub const blob_hash: [32]u8 = @splat(0x5a);

/// The seeds of the blob's bytes and the payload's. Two, so a payload cannot
/// be mistaken for a stretch of the blob.
pub const blob_seed: u32 = 0x243f_6a88;
pub const payload_seed: u32 = 0xb7e1_5162;

/// The bao data a `push` writes after its request, on the same stream. Big
/// enough that a reader which swallowed it into the request would hold more
/// bytes than the request declares.
pub const payload_length: usize = 1024;

pub const Store = struct {
    bytes: []u8,
    payload: []u8,
    hash: [32]u8 = blob_hash,

    pub fn init(alloc: std.mem.Allocator) !Store {
        const bytes = try alloc.alloc(u8, blob_length);
        errdefer alloc.free(bytes);
        const payload = try alloc.alloc(u8, payload_length);
        errdefer alloc.free(payload);
        fill(bytes, blob_seed);
        fill(payload, payload_seed);
        return .{ .bytes = bytes, .payload = payload };
    }

    pub fn deinit(store: Store, alloc: std.mem.Allocator) void {
        alloc.free(store.payload);
        alloc.free(store.bytes);
    }

    /// How many chunks the blob has: the input every range walk is read
    /// against, and the protocol's own rounding rather than a ceiling written
    /// out here. `chunkAfterByte` is the first chunk at or past a byte offset,
    /// which for a blob's own length is its chunk count.
    pub fn chunkCount(store: Store) u64 {
        return blobs.chunkAfterByte(store.bytes.len);
    }
};

/// The bytes of `out`, from a xorshift32 rather than a repeated byte.
///
/// A transfer test that moved `0x5a` from one buffer to another would pass
/// against a send path that duplicated one byte 256 times, and against one
/// that wrote the first quarter over the last. The period here is 2^32 - 1,
/// so no alignment repeats inside a blob of this size.
fn fill(out: []u8, seed: u32) void {
    var state: u32 = seed;
    for (out) |*byte| {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        byte.* = @truncate(state);
    }
}