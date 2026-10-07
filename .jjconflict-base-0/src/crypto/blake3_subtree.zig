//! A Bao tree's walk over BLAKE3: an input offset, a chaining value that is
//! not the root, and the merge of two chaining values.
//!
//! A Bao tree is the BLAKE3 tree under another name. Its nodes are that tree's
//! nodes and its root hash is that function's hash, so the only thing this
//! layer adds is a place to start: `Hasher` opens at an offset into a larger
//! input and returns the chaining value the whole tree holds for the same
//! range. It reads no socket, no clock and no allocator. It is a function of
//! bytes, an offset and the state the walk has built, which is what
//! `AGENTS.md` §2 asks of anything that looks like a protocol.
//!
//! What is pinned to published bytes, and what is not, is the subject of the
//! test blocks below. The root path is pinned, at every length both vector
//! tables carry. A non-root chaining value is not published by anyone, so it
//! is proved the only way it can be here — by the tree's defining property,
//! that its root is the merge of its two halves — and that gap is stated in
//! the module's own test names rather than left to a reader to discover.
//!
//! This is the third file in the walk: `blake3_core.zig` is the compression,
//! `blake3_nodes.zig` is a node's shape over it, and this one decides which
//! node is which.

const std = @import("std");
const core = @import("blake3_core.zig");
const nodes = @import("blake3_nodes.zig");

/// Every way this walk can refuse to hash what it was handed.
pub const Error = error{
    /// The byte offset does not land on a chunk boundary. The tree's nodes
    /// begin and end on chunk boundaries, so an offset inside a chunk names no
    /// subtree at all, and rounding it would hash bytes the caller did not
    /// name while reporting a range they did ask for.
    OffsetNotChunkAligned,
};

/// A walk over one range of one input, from an offset measured in chunks.
pub const Hasher = struct {
    chunk: nodes.ChunkState,
    cv_stack: [core.max_depth + 1]core.ChainingValue = undefined,
    cv_stack_len: u8 = 0,
    /// The range's first chunk, and the offset in bytes it came from. This is
    /// why a value computed over a range equals the whole tree's value for
    /// that range: the offset is in the chunk counter, which the compression
    /// reads.
    start_chunk: u64,

    /// Open a range beginning `start_byte` into the input. `start_byte` must
    /// land on a chunk boundary; `Error.OffsetNotChunkAligned` is what says so.
    pub fn init(start_byte: u64) Error!Hasher {
        if (start_byte % core.chunk_length != 0) return error.OffsetNotChunkAligned;
        const start_chunk = start_byte / core.chunk_length;
        return .{
            .chunk = nodes.ChunkState.init(start_chunk),
            .start_chunk = start_chunk,
        };
    }

    /// The chunk being filled. Absolute: `start_chunk` plus the chunks this
    /// range has completed.
    pub fn chunkIndex(self: *const Hasher) u64 {
        return self.chunk.chunk_counter;
    }

    /// The chunks this range has completed. This is the count the stack is
    /// trimmed against, and it is the range's own count rather than the
    /// absolute one: the tree the stack describes starts at `start_chunk`, so
    /// trimming against the absolute counter would describe a tree with a
    /// different shape and every value above it would be wrong.
    fn subtreeChunks(self: *const Hasher) u64 {
        return self.chunk.chunk_counter - self.start_chunk;
    }

    /// Fold the stack down to the nodes a tree of this range's completed
    /// chunks has open. A node merges only when its right sibling arrives, so
    /// the number of entries that survive is the population count of the
    /// chunk count: one entry per unfinished level, and no more.
    fn mergeCvStack(self: *Hasher) void {
        const keep: u8 = @intCast(@popCount(self.subtreeChunks()));
        while (self.cv_stack_len > keep) {
            const top = self.cv_stack_len;
            self.cv_stack[top - 2] = nodes.parentChainingValue(
                self.cv_stack[top - 2],
                self.cv_stack[top - 1],
                .{},
            );
            self.cv_stack_len -= 1;
        }
    }

    /// Add a finished chunk as the right-most node of the range.
    fn pushCv(self: *Hasher, new_cv: core.ChainingValue) void {
        self.mergeCvStack();
        std.debug.assert(self.cv_stack_len < self.cv_stack.len);
        self.cv_stack[self.cv_stack_len] = new_cv;
        self.cv_stack_len += 1;
    }

    /// The chunk in `chunk` is full and more bytes follow it, so its value is
    /// final and it becomes a node of the tree.
    fn completeChunk(self: *Hasher) void {
        self.pushCv(self.chunk.output().chainingValue(.{}));
        self.chunk.reset(self.chunk.chunk_counter + 1);
    }

    /// Take bytes of this range. A chunk is completed only where bytes follow
    /// it, so the range's last chunk stays open in `chunk` and CHUNK_END, and
    /// ROOT where it applies, still have the block they name.
    pub fn update(self: *Hasher, input: []const u8) void {
        if (input.len == 0) return;
        var inp = input;

        if (self.chunk.len() > 0) {
            const take = @min(core.chunk_length - self.chunk.len(), inp.len);
            self.chunk.update(inp[0..take]);
            inp = inp[take..];
            if (inp.len == 0) return;
            self.completeChunk();
        }

        // `>`, not `>=`: a full chunk with nothing after it is still the last
        // chunk, and leaving it open is what gives the final compression its
        // block rather than an empty one.
        while (inp.len > core.chunk_length) {
            self.chunk.update(inp[0..core.chunk_length]);
            inp = inp[core.chunk_length..];
            self.completeChunk();
        }

        if (inp.len > 0) {
            self.chunk.update(inp);
            self.mergeCvStack();
        }
    }

    /// The compression this range ends on, with `extra` set on it and nothing
    /// recomputed: ROOT is added here, at the one compression that is the
    /// root, and adding it earlier would change the node above it.
    fn finalOutput(self: *const Hasher, extra: core.Flags) nodes.Output {
        // A chunk is completed only where bytes follow it, so any node on the
        // stack is waiting for the open chunk that follows it, and the open
        // chunk is always there. A range that is one chunk has an empty stack
        // and nothing to merge.
        std.debug.assert(self.cv_stack_len == 0 or self.chunk.len() > 0);
        if (self.cv_stack_len == 0) return self.chunk.output().withFlags(extra);

        var remaining: usize = self.cv_stack_len;
        var output: nodes.Output = self.chunk.output();
        while (remaining > 0) {
            remaining -= 1;
            const right_cv = output.chainingValue(.{});
            output = nodes.parentOutput(self.cv_stack[remaining], right_cv, .{});
        }
        return output.withFlags(extra);
    }

    /// This range's chaining value: its root node with ROOT clear. This is
    /// what a tree stores for a range that is not its own root, and what
    /// `merge` takes.
    pub fn finalChainingValue(self: *const Hasher) core.CvBytes {
        return core.cvBytes(self.finalOutput(.{}).chainingValue(.{}));
    }

    /// The 32-byte root hash of this range: the same node with ROOT set. Over a
    /// whole input at offset zero this is the plain BLAKE3 hash.
    pub fn final(self: *const Hasher) core.CvBytes {
        return core.cvBytes(self.finalOutput(.{ .root = true }).chainingValue(.{}));
    }
};

/// The chaining value of the node over `left` and `right`, ROOT clear: an
/// interior node, and the value a tree stores for a subtree that is not its
/// root.
pub fn merge(left: core.CvBytes, right: core.CvBytes) core.CvBytes {
    return core.cvBytes(
        nodes.parentChainingValue(core.cvFromBytes(left), core.cvFromBytes(right), .{}),
    );
}

/// The same node with ROOT set: the root hash of a tree whose two top halves
/// are `left` and `right`.
pub fn mergeRoot(left: core.CvBytes, right: core.CvBytes) core.CvBytes {
    const root: core.Flags = .{ .root = true };
    return core.cvBytes(
        nodes.parentChainingValue(core.cvFromBytes(left), core.cvFromBytes(right), root),
    );
}

const t = std.testing;
const published = @import("../gossip/plumtree/blake3_vectors.zig");
const subtree_published = @import("blake3_subtree_vectors.zig");

// The root of a tree at offset zero is the plain BLAKE3 hash of the whole
// input. Pinned to published bytes: all eleven of
// `../gossip/plumtree/blake3_vectors.zig`, through the walk and not around
// it.
test "a tree at offset zero hashes the whole input" {
    for (published.blake3_vectors) |vector| {
        const input = try published.blake3Input(vector.len);
        defer t.allocator.free(input);

        var hasher = try Hasher.init(0);
        hasher.update(input);
        try t.expectEqualStrings(vector.hash, &std.fmt.bytesToHex(&hasher.final(), .lower));
    }
}

// The tree's defining property, checked against published bytes: the root of
// a two-, four-, eight- or sixteen-chunk input is the merge of the two
// halves' chaining values with ROOT set, and each published digest is the
// answer.
//
// This is where the non-root values stop being untested. They are not
// published anywhere, but a merge that is wrong in either argument, in
// either order, or in its flags cannot come out equal to a digest nobody
// predicted.
test "a tree's root is the merge of its two halves" {
    for (subtree_published.subtree_vectors) |vector| {
        const input = try published.blake3Input(vector.len);
        defer t.allocator.free(input);

        var whole = try Hasher.init(0);
        whole.update(input);
        try t.expectEqualStrings(vector.hash, &std.fmt.bytesToHex(&whole.final(), .lower));

        const half: u64 = @intCast(vector.len / 2);
        var left = try Hasher.init(0);
        left.update(input[0 .. vector.len / 2]);
        var right = try Hasher.init(half);
        right.update(input[vector.len / 2 ..]);

        const merged = mergeRoot(left.finalChainingValue(), right.finalChainingValue());
        try t.expectEqualStrings(vector.hash, &std.fmt.bytesToHex(&merged, .lower));
    }
}

// A range's own value is its root node with ROOT clear, and it is not that
// range's root hash. A tree that stored the root hash where the chaining
// value belongs would still pass the test above and would be wrong at every
// level below the root, because a parent compresses its children's ROOT-free
// values.
test "a subtree's chaining value is not its root hash" {
    for (subtree_published.subtree_vectors) |vector| {
        const input = try published.blake3Input(vector.len);
        defer t.allocator.free(input);

        var hasher = try Hasher.init(0);
        hasher.update(input[0 .. vector.len / 2]);
        try t.expect(!std.meta.eql(hasher.final(), hasher.finalChainingValue()));
    }
}

// The offset is in the chunk counter, which is the only reason a subtree's
// value is the whole tree's value for the same range. A walk that ignored its
// offset would hand back a range's value at the wrong place in the tree, and
// the merge above would fail.
test "the same bytes at offset zero and at one chunk are different values" {
    const input = try published.blake3Input(core.chunk_length);
    defer t.allocator.free(input);

    var at_zero = try Hasher.init(0);
    at_zero.update(input);
    var at_one = try Hasher.init(core.chunk_length);
    at_one.update(input);

    try t.expect(!std.meta.eql(at_zero.finalChainingValue(), at_one.finalChainingValue()));
    try t.expectEqual(@as(u64, 1), at_one.chunkIndex());
}

// An offset inside a chunk names no subtree, so it is refused rather than
// rounded. Rounding would hash a range the caller did not name and report it
// as one they did.
test "an offset inside a chunk is refused" {
    // `64` is here and not below: a BLAKE3 chunk is `chunk_length` bytes and
    // not one compression block, so an offset one block in is still inside
    // chunk zero.
    for ([_]u64{ 1, 2, 63, 64, 1023, 1025, 2047, 2049 }) |start_byte| {
        try t.expectError(error.OffsetNotChunkAligned, Hasher.init(start_byte));
    }
    for ([_]u64{ 0, 1024, 2048, 4096, 16384 }) |start_byte| {
        const hasher = try Hasher.init(start_byte);
        try t.expectEqual(start_byte / core.chunk_length, hasher.chunkIndex());
    }
}

// How the bytes are cut up cannot be part of the value, and an empty piece in
// the middle of them cannot be part of it either: `update` is a function of
// the bytes handed to it so far and of nothing else. Checked for both the
// root hash and the chaining value, because they take different paths out of
// the same walk.
test "a byte at a time, with empty pieces, is the whole slice" {
    const lengths = [_]usize{ 0, 1, 1023, 1024, 1025, 2048, 3072, 4096 };
    for (lengths) |len| {
        const input = try published.blake3Input(len);
        defer t.allocator.free(input);

        var whole = try Hasher.init(0);
        whole.update(input);

        var streamed = try Hasher.init(0);
        streamed.update(input[0..0]);
        for (input) |byte| {
            streamed.update(&[_]u8{byte});
            streamed.update(input[0..0]);
        }

        try t.expectEqual(whole.final(), streamed.final());
        try t.expectEqual(whole.finalChainingValue(), streamed.finalChainingValue());
    }
}

// Left and right are different children of an ordered tree, not a pair. Both
// orderings, and ROOT against no ROOT, give four different values here.
test "a merge is over an ordered pair and one flag" {
    const input = try published.blake3Input(2048);
    defer t.allocator.free(input);

    var left = try Hasher.init(0);
    left.update(input[0..core.chunk_length]);
    var right = try Hasher.init(core.chunk_length);
    right.update(input[core.chunk_length..]);

    const left_cv = left.finalChainingValue();
    const right_cv = right.finalChainingValue();
    try t.expect(!std.meta.eql(merge(left_cv, right_cv), merge(right_cv, left_cv)));
    try t.expect(!std.meta.eql(merge(left_cv, right_cv), mergeRoot(left_cv, right_cv)));
}

// A cross-check against `std.crypto.hash.Blake3`, not a wire claim: the
// published tables skip these lengths, and a walk that got the tree's shape
// wrong at, say, 5000 bytes would pass every digest above. `std` is a second
// implementation, not captured bytes, so this says the walk agrees with it
// and nothing about any peer.
test "the walk agrees with std at lengths no vector covers" {
    const lengths = [_]usize{ 1025, 3072, 5000, 12000 };
    for (lengths) |len| {
        const input = try published.blake3Input(len);
        defer t.allocator.free(input);

        var hasher = try Hasher.init(0);
        hasher.update(input);

        var out: [core.digest_length]u8 = undefined;
        std.crypto.hash.Blake3.hash(input, &out, .{});
        try t.expectEqual(out, hasher.final());
    }
}
