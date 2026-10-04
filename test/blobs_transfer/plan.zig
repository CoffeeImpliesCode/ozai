//! The byte ranges one answer covers, and the chunk boundaries they came from.
//!
//! Support for `test/blobs_transfer_test.zig`, split out of it so that the
//! arithmetic under test and the sockets it crosses are two files. Every step
//! here is the protocol's own: `RangeSpec.resolve` is upstream's
//! `to_chunk_ranges` read against a blob, the sequence walk is
//! `RangeSpecSeq.iter`, and the bytes are `chunksToBytes`.
//!
//! The one thing this file adds is the clip at the blob's real length, because
//! `chunksToBytes` is only exact for a whole number of chunks and the blob's
//! last chunk is short. It is required rather than tidy: a range ending in
//! that chunk gets back the first byte *past* it, and an answer that covered
//! those bytes would be reading past the end of the blob.
//!
//! The two directions are kept together for a reason: the plan goes chunks to
//! bytes, and an `observe` reports the same spans as a `ChunkRangeSet` for the
//! getter to go the other way. `planSpec` and `planFromBoundaries` are that
//! pair, and a test that asserted only one of them would pass against a
//! conversion that inverted on the way back.

const std = @import("std");
const ozai = @import("ozai");
const store_mod = @import("store.zig");

const blobs = ozai.blobs_protocol;
const range_spec = ozai.range_spec;
const Store = store_mod.Store;

/// The most byte ranges one answer may cover. A `RangeSpec` of a few widths
/// yields a few spans, and a bound keeps the plan a value rather than an
/// allocation.
pub const max_spans = 8;

pub const Plan = struct {
    ranges: [max_spans]blobs.ByteRange = @splat(.{ .start = 0, .end = 0 }),
    len: usize = 0,
    boundaries: [max_spans * 2]u64 = @splat(0),
    boundary_len: usize = 0,

    /// How many bytes the plan covers in total.
    pub fn total(plan: Plan) usize {
        var sum: usize = 0;
        for (plan.ranges[0..plan.len]) |range| sum += @intCast(range.end - range.start);
        return sum;
    }

    pub fn boundariesSlice(plan: *const Plan) []const u64 {
        return plan.boundaries[0..plan.boundary_len];
    }
};

/// Walk a spec against the store and fill `plan`.
///
/// Every step is the protocol's own: `RangeSpec.resolve` is upstream's
/// `to_chunk_ranges` read against a blob, and `chunksToBytes` is the other
/// direction of the conversion. The clip at the end is this file's, and it is
/// required rather than tidy: a blob whose length is not a multiple of 1024
/// has a short last chunk, so the byte count the chunk arithmetic returns for
/// a range ending in it is the first byte *past* that chunk.
pub fn planSpec(plan: *Plan, spec: range_spec.RangeSpec, store: Store) error{TooManySpans}!void {
    plan.* = .{};
    var spans = spec.resolve(store.chunkCount());
    while (spans.next()) |span| {
        if (plan.len == max_spans) return error.TooManySpans;
        const end = span.offset +| span.size;
        const bytes = blobs.chunksToBytes(.{ .start = span.offset, .end = end });
        plan.ranges[plan.len] = .{
            .start = @min(bytes.start, store.bytes.len),
            .end = @min(bytes.end, store.bytes.len),
        };
        plan.len += 1;
        // The parity `ChunkRangeSet` documents: an even position starts a
        // range and an odd one ends it.
        plan.boundaries[plan.boundary_len] = span.offset;
        plan.boundary_len += 1;
        plan.boundaries[plan.boundary_len] = end;
        plan.boundary_len += 1;
    }
}

/// The byte ranges a boundary list names, read against the size it arrived
/// with.
///
/// The direction `planSpec` did not take, and the one a getter has to take to
/// know what an answer will cover. The clip is the same rule: the last chunk
/// of a blob is short and the boundary list does not know that.
pub fn planFromBoundaries(boundaries: []const u64, size: u64) Plan {
    var plan: Plan = .{};
    var slot: usize = 0;
    while (slot + 1 < boundaries.len) : (slot += 2) {
        if (plan.len == max_spans) break;
        const bytes = blobs.chunksToBytes(.{
            .start = boundaries[slot],
            .end = boundaries[slot + 1],
        });
        plan.ranges[plan.len] = .{
            .start = @min(bytes.start, size),
            .end = @min(bytes.end, size),
        };
        plan.len += 1;
    }
    return plan;
}

/// The spec a decoded `get`'s sequence puts on the store's one blob.
///
/// The walk is `RangeSpecSeq.iter`, upstream's `ChunkRangesSeqIter`: one spec
/// per blob, and a pair the walk has not reached yet leaves the current spec in
/// place. The store holds one blob, so the first pair is the whole of it — and
/// for a whole-blob request that first pair is followed by the terminator
/// naming a blob that is not here.
pub fn specOf(request: blobs.GetRequest) range_spec.RangeSpec {
    var walk = request.ranges.iter();
    return walk.next() orelse range_spec.RangeSpec.empty;
}
