//! The provider's half: what it holds, and what it answers with.
//!
//! `Store` is the one blob and the bao data a `push` carries behind its
//! request. `Plan` is the byte ranges one answer covers and the chunk boundaries
//! they came from — both kept together because the two directions of that
//! conversion are the property: the plan goes chunks to bytes, and an `observe`
//! reports the same spans as a `ChunkRangeSet` for the getter to go the other
//! way.
//!
//! `serve`, `writeAnswer` and `writeObserve` are here rather than in the link
//! because they are the half of the exchange that answers: what they do is read
//! the request the getter put on the wire and derive bytes from the store. They
//! were `Link` methods whose bodies never touch a field of the link itself, so
//! they are top-level functions over `*Link` now and no statement in them
//! changed.

const std = @import("std");
const ozai = @import("ozai");

const blobs = ozai.blobs_protocol;
const range_spec = ozai.range_spec;
const postcard = ozai.postcard;

const jobs = @import("transfer_jobs.zig");
const link_ns = @import("transfer_link.zig");

/// The most byte ranges one answer may cover. A `RangeSpec` of a few widths
/// yields a few spans, and a bound keeps the plan a value rather than an
/// allocation.
pub const max_spans = 8;

/// Room for one encoded `ObserveItem` and for the length in front of it.
const observe_room = 256;

/// The provider's blob: 256 whole chunks and 700 bytes of a short one.
///
/// The size is chosen, not picked. Larger than one packet by three orders of
/// magnitude, and larger than `batch.max_segments_linux` datagrams, so the send
/// seam's segmentation is on the path rather than merely configured. The
/// remainder is 700 rather than 1024 so the last chunk is short, which is the
/// case `chunksToBytes` cannot answer exactly.
const blob_length: usize = 256 * 1024 + 700;

/// The blob's hash, and a request's hash is 32 raw bytes.
///
/// The first byte matters to one assertion in this file: overwriting a `get`
/// frame's discriminant with `push`'s makes that byte the declared body
/// length, and 0x5a is a one-byte varint for ninety — more than the frame has
/// left. See the framing test.
pub const blob_hash: [32]u8 = @splat(0x5a);

/// The seeds of the blob's bytes and the payload's. Two, so a payload cannot
/// be mistaken for a stretch of the blob.
const blob_seed: u32 = 0x243f_6a88;
const payload_seed: u32 = 0xb7e1_5162;

/// The bao data a `push` writes after its request, on the same stream. Big
/// enough that a reader which swallowed it into the request would hold more
/// bytes than the request declares.
pub const payload_length: usize = 1024;

// ---------------------------------------------------------------------------
// The provider's half
// ---------------------------------------------------------------------------

/// What the provider holds: one blob, its hash, and the bao data a `push`
/// carries behind its request.
pub const Store = struct {
    bytes: []u8,
    payload: []u8,
    hash: [32]u8 = blob_hash,

    /// Fill the store: the blob, its hash, and the bao data behind a `push`.
    ///
    /// `pub` because `transfer_link.zig` calls it across the file boundary the
    /// split that gave this module its own name introduced.
    pub fn init(alloc: std.mem.Allocator) !Store {
        const bytes = try alloc.alloc(u8, blob_length);
        errdefer alloc.free(bytes);
        const payload = try alloc.alloc(u8, payload_length);
        errdefer alloc.free(payload);
        fill(bytes, blob_seed);
        fill(payload, payload_seed);
        return .{ .bytes = bytes, .payload = payload };
    }

    /// Free the blob and the bao data behind it.
    ///
    /// `pub` because `transfer_link.zig` calls it across the file boundary the
    /// split that gave this module its own name introduced.
    pub fn deinit(store: Store, alloc: std.mem.Allocator) void {
        alloc.free(store.payload);
        alloc.free(store.bytes);
    }

    /// How many chunks the blob has: the input every range walk is read
    /// against, and the protocol's own rounding rather than a ceiling written
    /// out here. `chunkAfterByte` is the first chunk at or past a byte offset,
    /// which for a blob's own length is its chunk count.
    ///
    /// `pub` because `blobs_transfer_test.zig` calls it across the file
    /// boundary the split that gave this module its own name introduced.
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

/// The byte ranges one answer covers, and the chunk boundaries they came from.
///
/// The boundaries are kept beside the byte ranges because the two directions of
/// the conversion are the property: the plan goes chunks to bytes, and an
/// `observe` reports the same spans as a `ChunkRangeSet` for the getter to go
/// the other way.
pub const Plan = struct {
    ranges: [max_spans]blobs.ByteRange = @splat(.{ .start = 0, .end = 0 }),
    len: usize = 0,
    boundaries: [max_spans * 2]u64 = @splat(0),
    boundary_len: usize = 0,

    /// How many bytes the plan covers in total.
    /// `pub` because `blobs_transfer_test.zig` calls it across the file
    /// boundary the split that gave this module its own name introduced.
    pub fn total(plan: Plan) usize {
        var sum: usize = 0;
        for (plan.ranges[0..plan.len]) |range| sum += @intCast(range.end - range.start);
        return sum;
    }

    fn boundariesSlice(plan: *const Plan) []const u64 {
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
fn planSpec(plan: *Plan, spec: range_spec.RangeSpec, store: Store) error{TooManySpans}!void {
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
fn specOf(request: blobs.GetRequest) range_spec.RangeSpec {
    var walk = request.ranges.iter();
    return walk.next() orelse range_spec.RangeSpec.empty;
}

/// The spec a decoded request carries for the store's one blob, whatever
/// framing it arrived in. A `push` is a newtype over a `GetRequest`, so its
/// body is the same shape and its first pair is the same pair.
pub fn requestSpec(
    job: *const jobs.Job,
) error{ GetManyUnsupported, NoRequestSeen }!range_spec.RangeSpec {
    return switch (job.seen orelse return error.NoRequestSeen) {
        .to_eof => |request| switch (request) {
            .get => |value| specOf(value),
            .observe => |value| value.ranges,
            .get_many => return error.GetManyUnsupported,
        },
        .length_prefixed => |framed| framed.request.get.ranges.items[0].spec,
    };
}

// -- the provider's half ------------------------------------------------

/// Answer every job whose request has arrived whole and has not been
/// answered yet.
pub fn serve(link: *link_ns.Link) !bool {
    var moved = false;
    for (&link.jobs) |*job| {
        if (job.served or !job.asked) continue;
        if (!link.finished(&link.provider_fin, job.stream)) continue;
        const conn = link.provider.bridge.connectionAt(0) orelse continue;
        // The request as it came off the socket, decoded by the one reader
        // `Request.read` dispatches to.
        var reader = postcard.Reader.init(jobs.received(&link.provider_bytes, job.stream));
        const seen = try blobs.Request.read(&reader, &job.storage.inner);
        job.seen = seen;
        const stream = conn.entry.conn.streams.getStream(job.stream) orelse
            return error.NoStream;
        job.served = true;
        moved = true;
        switch (seen) {
            .to_eof => |request| {
                // The `to_eof` rule, and it applies to that arm alone: the
                // request is the whole stream, so a byte after it is a
                // stream that carried something else.
                try reader.finish();
                switch (request) {
                    .get => |get| {
                        try planSpec(&job.plan, specOf(get), link.store);
                        try writeAnswer(link, job, stream);
                    },
                    .observe => |observe| {
                        try planSpec(&job.plan, observe.ranges, link.store);
                        try writeObserve(link, job, stream);
                    },
                    .get_many => return error.GetManyUnsupported,
                }
            },
            .length_prefixed => |framed| {
                // No `finish` here, and that is the whole difference
                // between the two framings: the reader is left on the
                // payload, and that is where the bao data starts.
                job.payload_offset = framed.payload_offset;
                stream.send.close();
            },
        }
    }
    return moved;
}

/// The bao data of a `get`: the planned ranges, in order, and nothing else.
pub fn writeAnswer(link: *link_ns.Link, job: *jobs.Job, stream: anytype) !void {
    if (!job.empty) {
        var budget = job.truncate_to orelse std.math.maxInt(usize);
        for (job.plan.ranges[0..job.plan.len]) |range| {
            if (budget == 0) break;
            const start: usize = @intCast(range.start);
            const take: usize = @intCast(@min(budget, range.end - range.start));
            try stream.send.writeData(link.store.bytes[start .. start + take]);
            budget -= take;
        }
    }
    stream.send.close();
}

/// A run of `ObserveItem`s: what the provider has, as a `ChunkRangeSet`.
///
/// Length-prefixed, because a run has no other boundary — the same
/// `write_length_prefixed` a `push` request is written with, and for the
/// same reason. The body goes into its own buffer rather than being built
/// inside the frame, because the two must not be the same bytes.
pub fn writeObserve(link: *link_ns.Link, job: *jobs.Job, stream: anytype) !void {
    var body_room: [observe_room]u8 = undefined;
    var framed_room: [observe_room]u8 = undefined;
    var body = postcard.Writer.init(&body_room);
    const item: blobs.ObserveItem = .{
        .size = link.store.bytes.len,
        .ranges = .{ .boundaries = job.plan.boundariesSlice() },
    };
    try item.write(&body);
    const framed = body.finish();
    var writer = postcard.Writer.init(&framed_room);
    try writer.writeU64(framed.len);
    @memcpy(writer.buffer[writer.length..][0..framed.len], framed);
    writer.length += framed.len;
    try stream.send.writeData(writer.finish());
    stream.send.close();
}
