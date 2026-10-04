//! BLAKE3 subtree hashing: the root hash of a subtree at a given input offset,
//! its chaining value, and the two merges that combine sibling subtrees.
//!
//! A Bao tree is not one hash of a whole input. It is a tree over 1024-byte
//! chunks whose interior nodes are named by chaining values and whose root is
//! named by a hash, and every proof a peer sends is a slice of that tree. Two
//! of the things such a tree needs are not reachable through
//! `std.crypto.hash.Blake3` — `blake3_core.zig`'s module comment says which and
//! why: a node's *chaining value* rather than its hash, and a subtree that
//! *starts* at an offset rather than at byte zero.
//!
//! So the walk is here and the compression is in `blake3_core.zig`. The shape
//! it maintains is BLAKE3's own: a left-to-right stack of the chaining values
//! of the subtrees already finished, folded down whenever the chunk count says
//! one of them has just been completed, and read back out by folding the stack
//! right to left onto the chunk in hand. What it does not carry over is the
//! reference implementation's fast path over bulk input, which exists to save
//! tree compressions and not block compressions — a chunk is compressed a
//! block at a time either way.
//!
//! Every digest here is checked against the published BLAKE3 vectors, and
//! every subtree against a whole-input digest of the same bytes, so the
//! offset and the two merges cannot agree with each other while disagreeing
//! with BLAKE3.

const std = @import("std");
const core = @import("blake3_core.zig");

/// A digest is 32 bytes, and so is a chaining value.
pub const digest_length = core.digest_length;

/// The compression block, re-exported so a caller sizing a buffer for a
/// subtree does not have to know that the compression is in another file.
pub const block_length = core.block_length;

/// The chunk: 1024 bytes, the unit a subtree is a whole number of.
pub const chunk_length = core.chunk_length;

/// A root hash: the 32 bytes that name a subtree of some input.
pub const Hash = [digest_length]u8;

/// A chaining value: the 32 bytes that name a node's *parent*. The same width
/// as a hash and never the same value for the same bytes, which is why it does
/// not carry that name.
pub const ChainingValue = [digest_length]u8;

/// The deepest a tree over a `u64` byte offset can get: a subtree of `2^n`
/// chunks is `2^n * 1024` bytes and no offset names more than that. The stack
/// is one entry per level plus the chunk in hand, the bound std keeps for the
/// same reason (`lib/std/crypto/blake3.zig:15`).
const max_depth = 54;

/// The last chunk a `u64` byte offset can name, which is what `fromChunks`
/// clamps to.
const max_chunk = std.math.maxInt(u64) / chunk_length;

/// Where a subtree starts in the input.
///
/// The tree is defined on chunks, so an offset names a whole chunk. One that
/// began inside a chunk would need the rest of that chunk, which a subtree
/// hash is never handed: `blobs/chunk.zig` is where byte ranges are rounded
/// out to chunk ranges on their way here.
pub const InputOffset = struct {
    byte_offset: u64,

    pub const Error = error{UnalignedOffset};

    /// The offset of `byte_offset`, which must name a whole chunk.
    pub fn init(byte_offset: u64) Error!InputOffset {
        if (!isAligned(byte_offset)) return error.UnalignedOffset;
        return .{ .byte_offset = byte_offset };
    }

    /// The offset of chunk `chunk`.
    ///
    /// The chunk is clamped rather than multiplied: a chunk index past the
    /// last one a `u64` byte offset could name has no input behind it at all,
    /// and a wrapped product would name a real offset in the wrong place.
    pub fn fromChunks(chunk: u64) InputOffset {
        return .{ .byte_offset = @min(chunk, max_chunk) * chunk_length };
    }

    /// Whether `byte_offset` names a whole chunk.
    pub fn isAligned(byte_offset: u64) bool {
        return byte_offset % chunk_length == 0;
    }

    /// The first byte of the subtree.
    pub fn bytes(self: InputOffset) u64 {
        return self.byte_offset;
    }

    /// The index of the subtree's first chunk, which is the counter every
    /// compression underneath it reads.
    pub fn chunkIndex(self: InputOffset) u64 {
        return @divExact(self.byte_offset, chunk_length);
    }
};

/// The walk over one subtree: the chunk being filled, and the chaining values
/// of the subtrees already finished underneath it.
pub const SubtreeHasher = struct {
    chunk: core.ChunkState,
    /// The finished subtrees of this subtree, left to right and deepest last:
    /// the maximal complete nodes of the chunks read so far, because a node
    /// is only merged into its parent once its right sibling has arrived.
    stack: [max_depth + 1][8]u32,
    stack_len: u8,
    /// The chunk index this subtree starts at, so the stack is counted from
    /// the subtree's own first chunk and not from the input's.
    start_chunk: u64,

    /// The subtree that starts at `offset`. Nothing is hashed until `update`.
    pub fn init(offset: InputOffset) SubtreeHasher {
        return .{
            .chunk = core.ChunkState.init(offset.chunkIndex(), .{}),
            .stack = undefined,
            .stack_len = 0,
            .start_chunk = offset.chunkIndex(),
        };
    }

    /// Feed the subtree's bytes, in as many pieces as the caller likes.
    pub fn update(self: *SubtreeHasher, input: []const u8) void {
        var remaining = input;
        while (remaining.len > 0) {
            // A chunk is completed only where there are bytes behind it. A
            // chunk that fills on the last byte of the input is not completed
            // at all: it is this subtree's own output, and compressing it now
            // would leave nothing but its chaining value, which cannot produce
            // a root hash because the ROOT flag belongs to the block it was
            // compressed from.
            if (self.chunk.len() == chunk_length) self.completeChunk();
            const take = @min(chunk_length - self.chunk.len(), remaining.len);
            self.chunk.update(remaining[0..take]);
            remaining = remaining[take..];
        }
    }

    /// The subtree's root hash: the ROOT flag set on this subtree's own node.
    ///
    /// Only for a subtree that *is* the input asked about. Set on a subtree
    /// that is part of a larger input, the value is one nothing else computes
    /// and no peer can arrive at.
    pub fn finalizeRoot(self: *const SubtreeHasher) Hash {
        return self.output().rootHash();
    }

    /// The subtree's chaining value: what its parent merges, and what a proof
    /// names when the subtree is not the whole. The ROOT flag is absent, so
    /// this is not a hash of these bytes and must not be stored where a hash
    /// is expected.
    pub fn finalizeNonRoot(self: *const SubtreeHasher) ChainingValue {
        return core.storeCvWords(self.output().chainingValue());
    }

    /// The chunk that has just filled, as a chaining value on the stack, and
    /// the empty chunk the next one starts from.
    fn completeChunk(self: *SubtreeHasher) void {
        self.mergeCvStack();
        self.stack[self.stack_len] = self.chunk.output().chainingValue();
        self.stack_len += 1;
        self.chunk.reset(self.chunk.chunk_counter + 1);
    }

    /// Fold the stack down to one entry per set bit of the chunks completed
    /// before this one, which is the left-to-right shape of the tree over
    /// them: a subtree is complete exactly when its right sibling arrives, and
    /// each set bit of the count is such an arrival.
    fn mergeCvStack(self: *SubtreeHasher) void {
        const chunks_before = self.chunk.chunk_counter - self.start_chunk;
        const post_merge_len: u8 = @intCast(@popCount(chunks_before));
        while (self.stack_len > post_merge_len) {
            const top = self.stack_len - 1;
            self.stack[top - 1] =
                core.parentOutput(self.stack[top - 1], self.stack[top]).chainingValue();
            self.stack_len -= 1;
        }
    }

    /// The node this subtree's root is read from: the stack's rightmost
    /// subtree merged up its left-hand side onto the chunk in hand. The chunk
    /// state is never empty once anything has been completed, because
    /// `completeChunk` only runs where bytes follow it.
    fn output(self: *const SubtreeHasher) core.Output {
        // Nothing underneath the chunk means this subtree is at most one
        // chunk, and the chunk's own flags already say whether it starts and
        // ends there.
        if (self.stack_len == 0) return self.chunk.output();
        var out = self.chunk.output();
        var remaining = self.stack_len;
        while (remaining > 0) {
            remaining -= 1;
            out = core.parentOutput(self.stack[remaining], out.chainingValue());
        }
        return out;
    }
};

/// The parent of two sibling subtrees, as a chaining value: what a grandparent
/// merges. The ROOT flag is absent, so this is not a hash of the two together.
pub fn mergeSubtreesNonRoot(left: ChainingValue, right: ChainingValue) ChainingValue {
    return core.storeCvWords(
        core.parentOutput(core.loadCvWords(left), core.loadCvWords(right)).chainingValue(),
    );
}

/// The root hash of the tree whose two top subtrees are `left` and `right`.
///
/// The same merge as `mergeSubtreesNonRoot` with the ROOT flag set, and the
/// flag is the whole difference: a proof that verifies against a hash and
/// against a chaining value would verify against neither.
pub fn mergeSubtreesRoot(left: ChainingValue, right: ChainingValue) Hash {
    return core.parentOutput(core.loadCvWords(left), core.loadCvWords(right)).rootHash();
}

const testing = std.testing;

/// BLAKE3 test vectors from `BLAKE3-team/BLAKE3`,
/// `test_vectors/test_vectors.json`, commit
/// `6aab490a26124663329dfd3961b8469f8fdb158b`, fetched 2026-09-30 — the same
/// table `src/gossip/plumtree.zig:1561` mirrors, and the same source, so a
/// tree root here is checked against a published digest and not against this
/// implementation's own output. The input of each case is the 251-byte
/// sequence 0, 1, ... 250 repeating, and the lengths run up to and across a
/// chunk boundary so that the chunk flags, the stack fold and the single-chunk
/// case are all covered.
const vectors = [_]struct { len: usize, hash: []const u8 }{
    .{
        .len = 0,
        .hash = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
    },
    .{
        .len = 1,
        .hash = "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
    },
    .{
        .len = 2,
        .hash = "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63",
    },
    .{
        .len = 3,
        .hash = "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f",
    },
    .{
        .len = 8,
        .hash = "2351207d04fc16ade43ccab08600939c7c1fa70a5c0aaca76063d04c3228eaeb",
    },
    .{
        .len = 63,
        .hash = "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b",
    },
    .{
        .len = 64,
        .hash = "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98",
    },
    .{
        .len = 127,
        .hash = "d81293fda863f008c09e92fc382a81f5a0b4a1251cba1634016a0f86a6bd640d",
    },
    .{
        .len = 128,
        .hash = "f17e570564b26578c33bb7f44643f539624b05df1a76c81f30acd548c44b45ef",
    },
    .{
        .len = 1023,
        .hash = "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11",
    },
    .{
        .len = 1024,
        .hash = "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
    },
};

/// The input of a vector case: 0, 1, ... 250 repeating.
fn fillVectorInput(buffer: []u8) void {
    for (buffer, 0..) |*byte, index| byte.* = @intCast(index % 251);
}

test "subtree roots are the published blake3 digests" {
    for (vectors) |vector| {
        var input: [1024]u8 = undefined;
        fillVectorInput(input[0..vector.len]);
        var hasher = SubtreeHasher.init(try InputOffset.init(0));
        hasher.update(input[0..vector.len]);
        try testing.expectEqualStrings(
            vector.hash,
            &std.fmt.bytesToHex(hasher.finalizeRoot(), .lower),
        );
    }
}

test "a subtree root is not a digest under a context string" {
    // The failure this module could most plausibly suffer is a tree hashed
    // under a context: a different value for the same bytes, which verifies
    // against nothing. plumtree keeps the same check for `MessageId`, with the
    // published context string.
    const context = "BLAKE3 2019-12-27 16:29:52 test vectors context";
    for (vectors) |vector| {
        var input: [1024]u8 = undefined;
        fillVectorInput(input[0..vector.len]);
        var hasher = SubtreeHasher.init(try InputOffset.init(0));
        hasher.update(input[0..vector.len]);

        var separated = std.crypto.hash.Blake3.initKdf(context, .{});
        separated.update(input[0..vector.len]);
        var under_context: [digest_length]u8 = undefined;
        separated.final(&under_context);
        try testing.expect(!std.mem.eql(u8, &hasher.finalizeRoot(), &under_context));
    }
}

test "merging siblings is hashing the whole" {
    // The two merges are one compression, so each has to agree with a subtree
    // hashed as a single node, and the flag has to make them disagree.
    for ([_]usize{ 2, 4, 8, 16 }) |chunks| {
        const len = chunks * chunk_length;
        var input: [16 * chunk_length]u8 = undefined;
        fillVectorInput(input[0..len]);

        var whole = SubtreeHasher.init(try InputOffset.init(0));
        whole.update(input[0..len]);

        var left = SubtreeHasher.init(try InputOffset.init(0));
        left.update(input[0 .. len / 2]);
        var right = SubtreeHasher.init(try InputOffset.init(len / 2));
        right.update(input[len / 2 ..]);
        const left_cv = left.finalizeNonRoot();
        const right_cv = right.finalizeNonRoot();

        try testing.expectEqualSlices(
            u8,
            &whole.finalizeRoot(),
            &mergeSubtreesRoot(left_cv, right_cv),
        );
        try testing.expectEqualSlices(
            u8,
            &whole.finalizeNonRoot(),
            &mergeSubtreesNonRoot(left_cv, right_cv),
        );
        // The ROOT flag is the only difference between the two merges, so it
        // cannot be the difference between neither of them.
        try testing.expect(!std.mem.eql(u8, &whole.finalizeRoot(), &whole.finalizeNonRoot()));
        // And the halves are in tree order: the left subtree is the first
        // half of the input, so swapping them is a different tree.
        try testing.expect(!std.mem.eql(
            u8,
            &mergeSubtreesRoot(left_cv, right_cv),
            &mergeSubtreesRoot(right_cv, left_cv),
        ));
    }
}

test "the input offset is part of the value" {
    // A subtree is a range of one input, so its digest has to be the digest
    // that same range has inside the whole input's tree. `Blake3` is the
    // oracle for the whole here: a whole-input digest from byte zero is the
    // one thing it can be asked for.
    for ([_]struct { left: usize, right: usize }{
        .{ .left = 1, .right = 1 },
        .{ .left = 1, .right = 3 },
        .{ .left = 2, .right = 1 },
        .{ .left = 2, .right = 5 },
        .{ .left = 4, .right = 4 },
    }) |split| {
        const left_len = split.left * chunk_length;
        const len = left_len + split.right * chunk_length;
        var input: [16 * chunk_length]u8 = undefined;
        fillVectorInput(input[0..len]);

        var whole = std.crypto.hash.Blake3.init(.{});
        whole.update(input[0..len]);
        var expected: [digest_length]u8 = undefined;
        whole.final(&expected);

        var left = SubtreeHasher.init(try InputOffset.init(0));
        left.update(input[0..left_len]);
        var right = SubtreeHasher.init(try InputOffset.init(left_len));
        right.update(input[left_len..]);
        try testing.expectEqualSlices(u8, &expected, &mergeSubtreesRoot(
            left.finalizeNonRoot(),
            right.finalizeNonRoot(),
        ));
    }
    // The offset is not decoration: one chunk of input as two different
    // chunks are two different nodes, which is what makes a range hash a
    // range and not the bytes it holds.
    var input: [2 * chunk_length]u8 = undefined;
    fillVectorInput(&input);
    var at_zero = SubtreeHasher.init(try InputOffset.init(0));
    at_zero.update(input[0..chunk_length]);
    var at_one = SubtreeHasher.init(try InputOffset.init(chunk_length));
    at_one.update(input[chunk_length..]);
    try testing.expect(!std.mem.eql(
        u8,
        &at_zero.finalizeNonRoot(),
        &at_one.finalizeNonRoot(),
    ));
}

test "a subtree is the same streamed or whole" {
    // The completion rule in `update` is where a byte-at-a-time caller and a
    // whole-slice caller could come apart: a chunk that fills on the last
    // byte is completed by neither, and one that fills mid-stream by both.
    for ([_]usize{ 0, 1, 1023, 1024, 1025, 2048, 3072, 5000 }) |len| {
        var input: [5000]u8 = undefined;
        fillVectorInput(input[0..len]);
        var whole = SubtreeHasher.init(try InputOffset.init(0));
        whole.update(input[0..len]);
        const expected_root = whole.finalizeRoot();
        const expected_cv = whole.finalizeNonRoot();

        var streamed = SubtreeHasher.init(try InputOffset.init(0));
        for (input[0..len]) |byte| {
            const piece = [_]u8{byte};
            streamed.update(&piece);
            // An empty piece is not input, and must not complete a chunk.
            streamed.update(&[_]u8{});
        }
        try testing.expectEqualSlices(u8, &expected_root, &streamed.finalizeRoot());
        try testing.expectEqualSlices(u8, &expected_cv, &streamed.finalizeNonRoot());
    }
}

test "an offset names a whole chunk" {
    try testing.expect(InputOffset.isAligned(0));
    try testing.expect(InputOffset.isAligned(4 * chunk_length));
    try testing.expect(!InputOffset.isAligned(chunk_length - 1));
    // A range that starts inside a chunk cannot be hashed as a subtree, and
    // says so rather than rounding itself into a different range.
    try testing.expectError(error.UnalignedOffset, InputOffset.init(1));
    try testing.expectError(
        error.UnalignedOffset,
        InputOffset.init(chunk_length * 3 + 1),
    );
    const offset = try InputOffset.init(3 * chunk_length);
    try testing.expectEqual(@as(u64, 3 * chunk_length), offset.bytes());
    try testing.expectEqual(@as(u64, 3), offset.chunkIndex());
    try testing.expectEqual(
        @as(u64, 3),
        InputOffset.fromChunks(3).chunkIndex(),
    );
    // A chunk index past the last one a byte offset could name is clamped
    // rather than wrapped: it names no input, and a wrapped product would name
    // a real offset at the wrong place.
    try testing.expectEqual(
        @as(u64, max_chunk),
        InputOffset.fromChunks(std.math.maxInt(u64)).chunkIndex(),
    );
    try testing.expectEqual(
        max_chunk * chunk_length,
        InputOffset.fromChunks(std.math.maxInt(u64)).bytes(),
    );
}