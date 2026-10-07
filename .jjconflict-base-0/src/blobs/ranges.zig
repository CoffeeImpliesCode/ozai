//! The two units a range in this protocol is counted in, the conversions
//! between them, and the boundary list one of them is on the wire.
//!
//! Nothing here knows what a request is. A request that needs a chunk
//! arithmetic names this file and this file names no request, which is the
//! whole boundary and the reason it is worth having: the four roundings below
//! are arithmetic, so the tests that pin them are tests of arithmetic and
//! need no frame, no storage and no reader. `blobs/protocol.zig` is the facade
//! this file sits behind.
//!
//! # Chunks, and the block above them
//!
//! Every range in this protocol — in a request and in an `ObserveItem` alike —
//! is a count of 1024-byte BLAKE3 chunks. `chunk_size` is bao-tree's
//! `BLAKE3_CHUNK_SIZE` (`src/tree.rs:119`, at commit
//! `2be9abd144783455606424424c29bd3a57f926f8`), and `ChunkNum`'s own doc says
//! "The blake3 chunk size is 1024 bytes" (`src/tree.rs:14`). Upstream says the
//! same in prose at `src/protocol.rs:98`: ranges are "always given in terms of
//! 1024 byte blake3 chunks, *not* in terms of bytes or chunk groups", because
//! a chunk is the unit BLAKE3 hashes and combining chunks is "merely an
//! optimization to reduce metadata overhead".
//!
//! `block_size` is the same crate's default, 16384 bytes: `BlockSize`'s
//! `bytes()` is `BLAKE3_CHUNK_SIZE << chunk_log` (`src/tree.rs:159`) and the
//! crate's two worked examples both say "Use a block size of 16 KiB, a good
//! default for most cases" (`src/lib.rs:88` and `src/lib.rs:152`), which is
//! `from_chunk_log(4)`.
//!
//! The ratio is the point, and `chunks_per_block` is derived from the two
//! constants rather than written beside them: sixteen chunks to a block, so
//! one round of the bao tree carries 16384 bytes and a block boundary lands
//! every sixteen chunks. Upstream states the trade at `src/protocol.rs:26`:
//! the "minimum granularity is a chunk group of 16KiB or 16 blake3 chunks",
//! and "the worst case overhead when doing range requests is about two chunk
//! groups per range". A request is therefore answered in blocks even though it
//! is asked for in chunks, and that gap — up to two blocks per requested range
//! — is the price of a range request at all.
//!
//! The conversion between the two units is a named function and not an
//! arithmetic expression at a call site: `bytesToChunks` rounds a byte range
//! *outward* (the start down to the chunk that contains it, the end up to the
//! first chunk past it) because that is `bao_tree::io::round_up_to_chunks`
//! (`src/io/mod.rs:135`), and it rounds the two ends in opposite directions on
//! purpose — its comment says "full_chunks() rounds down, chunks() rounds up".
//! `chunksToBytes` is the other direction and is exact only for a whole
//! number of chunks; a blob whose length is not a multiple of 1024 has a short
//! last chunk, so the byte count it returns is the first byte *past* that
//! chunk.

const std = @import("std");
const postcard = @import("../wire/postcard.zig");

/// The BLAKE3 chunk size in bytes: the unit every range in this protocol is
/// counted in. See the module comment for where the number comes from.
pub const chunk_size: u64 = 1024;

/// The bao tree's block size in bytes: the unit an answer is actually sent in,
/// sixteen chunks to a block. See the module comment.
pub const block_size: u64 = 16384;

/// Chunks to a block, derived so it cannot drift from the two constants above.
pub const chunks_per_block: u64 = @divExact(block_size, chunk_size);

/// A byte range, half-open, in the unit the protocol does not use on the wire.
///
/// `end` is the first byte *past* the range, so `end <= start` is an empty or
/// inverted range and `len` is not derivable from these fields without that
/// case being handled. `bytesToChunks` is the conversion that keeps the two
/// cases apart.
pub const ByteRange = struct {
    /// The first byte of the range.
    start: u64,
    /// One past the last byte. Nothing keeps it above `start`: a value built
    /// by the caller may be empty or inverted, and `chunksToBytes` saturates
    /// rather than wrapping.
    end: u64,
};

/// A chunk range, half-open. This *is* the wire unit: see the module comment.
pub const ChunkRange = struct {
    /// The first chunk of the range.
    start: u64,
    /// One past the last chunk. A `ChunkRange` off a peer's wire can be
    /// `u64.max`, and `start > end` is possible in a hand-built value, which
    /// is why `len` saturates rather than the type promising an order.
    end: u64,

    /// Chunks this range covers, zero when it is empty or inverted.
    pub fn len(self: ChunkRange) u64 {
        return self.end -| self.start;
    }
};

/// The chunk that contains byte `offset`: `offset / 1024`, rounded down.
///
/// This is upstream's `ChunkNum::full_chunks` (`src/tree.rs:209`), and it is
/// the start half of a byte-to-chunk rounding. The rounding is not symmetric
/// and must not be: a request for byte 1 is a request for the chunk byte 1 is
/// inside, not for the chunk after it. `byte 0` and `byte 1023` are both chunk
/// 0, and only the far end of the same request rounds up.
pub fn chunkOfByte(offset: u64) u64 {
    return @divFloor(offset, chunk_size);
}

/// The first chunk at or past byte `end`: `end / 1024`, rounded up.
///
/// Upstream's `ChunkNum::chunks` (`src/tree.rs:199`), whose doc gives the two
/// cases this has to keep apart: "1024 bytes is 1 chunk, 1025 bytes is 2
/// chunks". The partial chunk is added as one rather than computed as
/// `ceil((end + 1023) / 1024)`, which would overflow at `u64.max` — and an end
/// of `u64.max` is a legal byte offset off a peer's wire.
pub fn chunkAfterByte(end: u64) u64 {
    const whole = @divFloor(end, chunk_size);
    return whole + @intFromBool(end % chunk_size != 0);
}

/// The chunk range that covers `range`, rounded outward at both ends.
///
/// `bao_tree::io::round_up_to_chunks` (`src/io/mod.rs:135`) with upstream's
/// `ChunkRanges::bytes` (`src/protocol.rs:745`), which is the only direction a
/// byte range reaches a request through. Two roundings, in opposite
/// directions: the start goes *down* to the chunk that contains the first byte
/// and the end goes *up* to the first chunk past the last one.
///
/// A byte range whose end is not past its start covers no byte and so covers
/// no chunk: it returns the empty range at the chunk holding `start`, and
/// never the one-chunk range the outward rounding would otherwise name. That
/// is what keeps `start <= end` on every result, so `ChunkRange.len` reads the
/// count off a range a peer can be sent without the answer covering data the
/// request never asked for.
pub fn bytesToChunks(range: ByteRange) ChunkRange {
    const start = chunkOfByte(range.start);
    if (range.end <= range.start) return .{ .start = start, .end = start };
    return .{ .start = start, .end = chunkAfterByte(range.end) };
}

/// The bytes a chunk range covers.
///
/// The other direction, and the only one with an exact answer. A blob whose
/// length is not a multiple of 1024 has a last chunk that is short, so the byte
/// count for a range ending at that chunk is the first byte *past* it rather
/// than its end; `fullChunks` of the blob's size is what recovers the real
/// length. The multiply saturates because a chunk number off a peer's wire can
/// be `u64.max`, where upstream's `self.0 << 10` would not be a value at all.
pub fn chunksToBytes(range: ChunkRange) ByteRange {
    return .{
        .start = range.start *| chunk_size,
        .end = range.end *| chunk_size,
    };
}

/// A set of chunk ranges, as the boundary list `range_collections` stores.
///
/// The wire form is a count and then that many `u64` boundaries: the
/// `Serialize` impl at `range_collections` 0.4.6 `src/range_set.rs:975` is a
/// `serialize_seq` of the boundaries, and with postcard that is a length and
/// the values. A boundary at an even position *starts* a range and one at an
/// odd position *ends* it, because "Start boundaries are always inclusive,
/// end boundaries are exclusive" is the type's own rule (`src/range_set.rs:124`).
/// So the empty set has no boundaries, the set of every chunk is the single
/// boundary zero (`RangeSet::all`, `src/range_set.rs:641`), and a set is
/// `is_all` exactly when it is `[0]` (`src/range_set.rs:343`).
///
/// This is **not** `RangeSpec`, and the two are one byte apart on a wire.
///
///     ChunkRangeSet{ .boundaries = &.{ 1, 2 } }  //  "020102": chunks 1 and 2
///     RangeSpec{ .widths = &.{ 1, 2 } }           //  "020102": 1 gap, 2 from there
///
/// Both spellings are a count and that many `varint(u64)`s, they are both
/// drawn from the same pool of small numbers, and they mean opposite things:
/// a boundary list starts *inside*, a width list starts with a gap. A
/// decoder that read one as the other would request the wrong bytes and
/// would not be able to tell from the result, which is why they are separate
/// types with separate `parse`s rather than one range type with a flag.
///
/// What is not here is the algebra. `RangeSpec`'s module comment declines
/// `RangeSet2`'s union, intersection and negation for the same reason this
/// does: a request is only ever *read* against a blob, and building a set from
/// arbitrary unions is a port of another crate. A peer sends a set already
/// unioned, so a decode that normalises is the whole of what is needed.
pub const ChunkRangeSet = struct {
    /// Boundaries, borrowed. See the type comment for the parity rule.
    boundaries: []const u64,

    /// The set of no chunks at all.
    pub const empty: ChunkRangeSet = .{ .boundaries = &.{} };

    /// Every chunk, whatever the blob's size. The single boundary zero.
    pub const all: ChunkRangeSet = .{ .boundaries = &.{0} };

    /// The last chunk of any blob, and nothing before it. Upstream's
    /// `ChunkRanges::last_chunk`, which is `from_range_from(u64::MAX)`: the
    /// start rounds down to zero, so the boundaries are `[0, u64.max]` and the
    /// range runs to the end of whatever blob is read against.
    pub const last_chunk: ChunkRangeSet = .{ .boundaries = &.{ 0, std.math.maxInt(u64) } };

    /// The set naming no chunks at all, which is an empty boundary list.
    pub fn isEmpty(self: ChunkRangeSet) bool {
        return self.boundaries.len == 0;
    }

    /// The single-boundary-zero test, which is how `range_collections` decides
    /// a set is everything (`src/range_set.rs:343`).
    pub fn isAll(self: ChunkRangeSet) bool {
        return self.boundaries.len == 1 and self.boundaries[0] == 0;
    }

    /// Equality of the boundary lists. Two sets a peer spelled differently
    /// compare equal when they name the same ranges, because a decode sorts
    /// and deduplicates before this sees them.
    pub fn eql(a: ChunkRangeSet, b: ChunkRangeSet) bool {
        return std.mem.eql(u64, a.boundaries, b.boundaries);
    }

    /// The wire form: a length, then each boundary as `varint(u64)`.
    pub fn write(self: ChunkRangeSet, writer: *postcard.Writer) postcard.Error!void {
        try writer.writeLen(self.boundaries.len);
        for (self.boundaries) |boundary| try writer.writeU64(boundary);
    }

    /// Read the wire form into `boundaries`, which the result then borrows.
    ///
    /// A boundary list that is unsorted or repeats is a *value*, not an error:
    /// upstream's `RangeSetVisitor` (`src/range_set.rs:1000`) reads whatever
    /// the frame names, `sort()`s it and `dedup()`s it, and checks nothing
    /// else — not the parity, not the order. Normalising here is what keeps
    /// this total over arbitrary bytes, and it is also what makes the boundary
    /// parity of the result mean anything.
    ///
    /// On error the reader may have advanced and a prefix of `boundaries` may
    /// already hold the boundaries read so far — in wire order, unsorted and
    /// undeduplicated, because the two steps below run only on success — while
    /// the rest of the slice keeps what the caller had. `error.BufferFull` is
    /// the one failure that writes nothing: the declared count is checked
    /// against `boundaries.len` before the first boundary is read.
    pub fn parse(
        reader: *postcard.Reader,
        boundaries: []u64,
    ) postcard.Error!ChunkRangeSet {
        const count = try reader.readLen();
        if (count > boundaries.len) return error.BufferFull;
        const filled = boundaries[0..count];
        for (filled) |*boundary| boundary.* = try reader.readU64();
        std.sort.heap(u64, filled, {}, ascending);
        return .{ .boundaries = dedup(filled) };
    }
};

fn ascending(_: void, lhs: u64, rhs: u64) bool {
    return lhs < rhs;
}

/// The sorted, duplicate-free form of `sorted`, in place and in the same
/// storage. A duplicate boundary is a range that starts and ends in the same
/// place, and `range_collections` drops it at decode, so dropping it here is
/// what the frame means.
fn dedup(sorted: []u64) []u64 {
    var kept: usize = 0;
    // The write index never passes the read index, so the walk is over `sorted`
    // as it was when it started.
    for (sorted) |value| {
        if (kept == 0 or sorted[kept - 1] != value) {
            sorted[kept] = value;
            kept += 1;
        }
    }
    return sorted[0..kept];
}
