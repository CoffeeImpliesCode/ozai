//! The unit every range in the blobs protocol is counted in, the conversions
//! between that unit and bytes, and the boundary list a provider's availability
//! arrives as.
//!
//! One of the four modules `protocol.zig` is split into. The identity of the
//! protocol — its ALPN, its message cap, its error set and the caller-owned
//! scratch a decode fills — stays in `protocol.zig`, and this file is the
//! arithmetic below it: what a chunk is, how a byte range becomes a chunk
//! range, and what an `ObserveItem`'s ranges mean.
//!
//! The conversions are here rather than beside the requests that carry them
//! because two of the three request types never use them: only the plan that
//! answers an `observe` and the caller that walks a spec back to bytes go
//! through `bytesToChunks` and `chunksToBytes`, and both are chunk arithmetic
//! rather than framing. `protocol.zig`'s module comment is where the derivation
//! of `chunk_size`, `block_size` and `chunks_per_block` from bao-tree's own
//! constants is written down.
//!
//! What is *not* here is the algebra of a set of chunk ranges. A peer sends a
//! set already unioned, and upstream's `RangeSet` union, intersection and
//! negation are a port of another crate this build does not carry. What is
//! here is the decode, which is what the peer actually needs: `parse` reads
//! whatever the frame names, sorts it and deduplicates it, exactly as
//! upstream's `RangeSetVisitor` (`src/range_set.rs:1000`) does.

const std = @import("std");
const postcard = @import("../wire/postcard.zig");
/// The module's shared vocabulary and its shared test scaffolding. Imported
/// for `parseHex` and `expectHex`, which three of the four modules' golden
/// vectors need and which are the hex dumper `range_spec.zig` carries a fourth
/// copy of.
const protocol = @import("protocol.zig");

/// The BLAKE3 chunk size in bytes: the unit every range in this protocol is
/// counted in. See the protocol module comment for where the number comes from.
pub const chunk_size: u64 = 1024;

/// The bao tree's block size in bytes: the unit an answer is actually sent in,
/// sixteen chunks to a block. See the protocol module comment.
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

/// A chunk range, half-open. This *is* the wire unit: see the protocol module
/// comment.
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

const testing = std.testing;

/// Write `set` and expect exactly `hex`, and read it back.
fn expectSetHex(set: ChunkRangeSet, hex: []const u8) !void {
    var scratch: [64]u8 = undefined;
    const expected = try protocol.parseHex(&scratch, hex);
    var buffer: [64]u8 = undefined;
    var writer = postcard.Writer.init(&buffer);
    try set.write(&writer);
    try protocol.expectHex(expected, writer.finish());

    var boundaries: [16]u64 = undefined;
    var reader = postcard.Reader.init(expected);
    const decoded = try ChunkRangeSet.parse(&reader, &boundaries);
    try reader.finish();
    try testing.expect(set.eql(decoded));
}

test "bytes to chunks: the four roundings upstream's tests pin" {
    // Captured, from upstream's `chunk_ranges_ext` test at
    // `src/protocol.rs:943` and its `get_request_builder` test at
    // `src/protocol.rs:960`, which state these as equalities:
    //
    //   ChunkRanges::bytes(1..2)     == ChunkNum(0)..ChunkNum(1)
    //   ChunkRanges::offset(1024*10) == ChunkNum(10)..ChunkNum(11)
    //   ChunkRanges::bytes(0..100)   == ..ChunkNum(1)
    //
    // The first is the non-integral case, and it is the reason the two ends
    // round in opposite directions: byte 1 is inside chunk 0 and byte 2 is the
    // first byte of the chunk after it, so the range is exactly one chunk.
    try testing.expectEqual(
        ChunkRange{ .start = 0, .end = 1 },
        bytesToChunks(.{ .start = 1, .end = 2 }),
    );
    try testing.expectEqual(
        ChunkRange{ .start = 10, .end = 11 },
        bytesToChunks(.{ .start = 10240, .end = 10241 }),
    );
    try testing.expectEqual(
        ChunkRange{ .start = 0, .end = 1 },
        bytesToChunks(.{ .start = 0, .end = 100 }),
    );
    // Upstream's own worked example, `ChunkRanges::bytes(10000..11000)`, from
    // the module prose at `src/protocol.rs:161`.
    try testing.expectEqual(
        ChunkRange{ .start = 9, .end = 11 },
        bytesToChunks(.{ .start = 10000, .end = 11000 }),
    );

    // `ChunkNum::chunks`'s doc gives the two cases this has to keep apart:
    // "1024 bytes is 1 chunk, 1025 bytes is 2 chunks". One byte over a boundary
    // is the whole of the non-integral case, and 100000 bytes is 97 and a bit.
    try testing.expectEqual(@as(u64, 0), chunkAfterByte(0));
    try testing.expectEqual(@as(u64, 1), chunkAfterByte(1024));
    try testing.expectEqual(@as(u64, 2), chunkAfterByte(1025));
    try testing.expectEqual(@as(u64, 98), chunkAfterByte(100000));
    // The start rounds the other way, and byte 1023 is still in chunk 0.
    try testing.expectEqual(@as(u64, 0), chunkOfByte(0));
    try testing.expectEqual(@as(u64, 0), chunkOfByte(1023));
    try testing.expectEqual(@as(u64, 1), chunkOfByte(1024));

    // The other direction, exact only for whole chunks.
    try testing.expectEqual(
        ByteRange{ .start = 0, .end = 1024 },
        chunksToBytes(.{ .start = 0, .end = 1 }),
    );
    try testing.expectEqual(
        ByteRange{ .start = 10240, .end = 11264 },
        chunksToBytes(.{ .start = 10, .end = 11 }),
    );
    // A chunk number off a peer's wire can be `u64.max`, where upstream's
    // `self.0 << 10` would not be a value at all.
    try testing.expectEqual(
        std.math.maxInt(u64),
        chunksToBytes(.{ .start = 0, .end = std.math.maxInt(u64) }).end,
    );
    // An inverted range covers no chunks rather than wrapping to a huge one.
    try testing.expectEqual(@as(u64, 0), (ChunkRange{ .start = 5, .end = 3 }).len());
}

test "an empty or inverted byte range covers no chunk" {
    // The audit case: bytes 5 through 5 is no bytes, so it is no chunks. The
    // outward rounding alone named chunk 0 through 1 and the answer covered a
    // chunk the request never asked for.
    const empty = bytesToChunks(.{ .start = 5, .end = 5 });
    try testing.expectEqual(@as(u64, 0), empty.len());
    try testing.expectEqual(ChunkRange{ .start = 0, .end = 0 }, empty);

    // The empty range at zero, and one straddling a chunk boundary, so the
    // answer is at the chunk the start byte is in rather than at zero.
    try testing.expectEqual(
        ChunkRange{ .start = 0, .end = 0 },
        bytesToChunks(.{ .start = 0, .end = 0 }),
    );
    const straddling = bytesToChunks(.{ .start = 1024, .end = 1024 });
    try testing.expectEqual(ChunkRange{ .start = 1, .end = 1 }, straddling);
    try testing.expectEqual(@as(u64, 0), straddling.len());
    try testing.expectEqual(
        ChunkRange{ .start = 4, .end = 4 },
        bytesToChunks(.{ .start = 4096, .end = 4096 }),
    );

    // Inverted is the same answer: end before start names no bytes, and
    // rounding its end up would name chunks past the ones a caller asked
    // about. `start <= end` holds on every result, so the count reads zero
    // rather than wrapping.
    for ([_]ByteRange{
        .{ .start = 5, .end = 3 },
        .{ .start = 2048, .end = 1024 },
        .{ .start = 1024, .end = 1 },
    }) |range| {
        const chunks = bytesToChunks(range);
        try testing.expect(chunks.start <= chunks.end);
        try testing.expectEqual(@as(u64, 0), chunks.len());
        try testing.expectEqual(chunkOfByte(range.start), chunks.start);
    }

    // The one-byte range is the boundary this fix must not move: it is the
    // smallest range that covers a byte, and it still rounds outward to a
    // whole chunk.
    try testing.expectEqual(
        ChunkRange{ .start = 0, .end = 1 },
        bytesToChunks(.{ .start = 5, .end = 6 }),
    );
    try testing.expectEqual(
        ChunkRange{ .start = 1, .end = 2 },
        bytesToChunks(.{ .start = 1024, .end = 1025 }),
    );

    // And the other direction agrees: an empty chunk range is an empty byte
    // range, so a round trip through both conversions cannot widen one.
    for ([_]ChunkRange{
        .{ .start = 0, .end = 0 },
        .{ .start = 1, .end = 1 },
        .{ .start = 4, .end = 4 },
    }) |chunks| {
        try testing.expectEqual(@as(u64, 0), chunksToBytes(chunks).end -| chunksToBytes(chunks).start);
    }
}

test "ChunkRangeSet: a boundary list, and not a width list" {
    // The empty set is a count of nothing, and the whole set is a single
    // boundary zero: `RangeSet::empty` and `RangeSet::all`
    // (`src/range_set.rs:637` and `:641`).
    try expectSetHex(.empty, "00");
    try expectSetHex(.all, "0100");
    // Chunks 1 and 2 is the two boundaries 1 and 2. Read as a `RangeSpec` those
    // same bytes mean one gap chunk and two selected from there — which is why
    // the two are separate types rather than one range with a flag.
    try expectSetHex(.{ .boundaries = &.{ 1, 2 } }, "020102");
    // `last_chunk` is upstream's `ChunkRanges::last_chunk`, which is
    // `from_range_from(u64::MAX)`: the start rounds down to zero, so the range
    // runs to the end of whatever blob it is read against.
    try expectSetHex(.last_chunk, "02" ++ "00" ++ "ff" ** 9 ++ "01");
    try testing.expect(ChunkRangeSet.empty.isEmpty());
    try testing.expect(!ChunkRangeSet.empty.isAll());
    try testing.expect(ChunkRangeSet.all.isAll());
    try testing.expect(!ChunkRangeSet.last_chunk.isAll());

    // A decode sorts and dedups, because that is what upstream's
    // `RangeSetVisitor` does (`src/range_set.rs:1000`): it reads what the frame
    // names, sorts it, dedups it, and checks nothing else — not the parity, not
    // the order. So an unsorted list with a repeat is a *value*.
    {
        var boundaries: [16]u64 = undefined;
        var reader = postcard.Reader.init(&[_]u8{ 0x04, 0x05, 0x01, 0x05, 0x09 });
        const set = try ChunkRangeSet.parse(&reader, &boundaries);
        try reader.finish();
        try testing.expectEqualSlices(u64, &.{ 1, 5, 9 }, set.boundaries);
        // And the normalised set has its own canonical form, which is not the
        // one that arrived. The parity still holds: 1 and 5 start ranges, 9
        // ends one.
        var buffer: [32]u8 = undefined;
        var writer = postcard.Writer.init(&buffer);
        try set.write(&writer);
        try protocol.expectHex(&[_]u8{ 0x03, 0x01, 0x05, 0x09 }, writer.finish());
    }
    // A count the caller's boundaries could not hold.
    {
        var boundaries: [1]u64 = undefined;
        var reader = postcard.Reader.init(&[_]u8{ 0x04, 0x01, 0x02, 0x03, 0x04 });
        try testing.expectError(error.BufferFull, ChunkRangeSet.parse(&reader, &boundaries));
    }
}
