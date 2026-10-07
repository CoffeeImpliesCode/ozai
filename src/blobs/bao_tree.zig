//! The shape of a Bao tree over one blob: how many chunk groups it has, where
//! each one's bytes are, how a node splits, and what its root block is.
//!
//! # The size is a claim, never a check
//!
//! Every number in this file is a function of one `u64`: the declared size. A
//! declared size is a *claim* about the bytes, and nothing here compares it
//! against anything else — not the length of the bytes handed over, not a
//! header, not a length a peer's frame repeats. What makes a size true is the
//! proof path: the bytes beside the proof must hash node by node to a root the
//! caller already held out of band, and a tree cut to a size the bytes do not
//! fill cannot reach that root. `BaoTree` is that arithmetic and nothing else.
//!
//! # What is pinned, and what is not
//!
//! Pinned to published bytes: the split rule, through
//! `crypto/blake3_subtree.zig`'s reproduction of every published BLAKE3 digest
//! it carries. A node whose children were not the two halves BLAKE3 itself
//! would use changes the root at every length both tables reach, so a tree
//! that split "evenly" instead would miss all of them. Pinned to this repo's
//! own captures: the two roundings, which are borrowed from `blobs/ranges.zig`
//! rather than rewritten, and the widths, which come from
//! `crypto/blake3_core.zig`.
//!
//! The split rule is the largest power of two strictly below the chunk count.
//! `oracle_test.zig` compares roots, outboards and responses with captures
//! emitted by the pinned upstream Store, including a partial final group.
//!
//! The parent-pair layout is pinned by `crypto/blake3_nodes.zig` rather than by
//! any capture: it is the same left word then right word that file compresses
//! into a parent block, read back out of it.

const std = @import("std");

const core = @import("../crypto/blake3_core.zig");
const subtree = @import("../crypto/blake3_subtree.zig");
const ranges = @import("ranges.zig");

/// The BLAKE3 chunk size: the unit every node and every range here is counted
/// in. Borrowed from `blobs/ranges.zig` rather than restated, because a second
/// literal is a second chance to disagree with the request layer.
pub const chunk_size: u64 = ranges.chunk_size;

/// The default chunk-group size, sixteen chunks: the unit this tree's top
/// level is counted in. Borrowed for the same reason as `chunk_size`.
pub const block_size: u64 = ranges.block_size;

/// Chunks to a group, derived from the two above so it cannot drift.
pub const chunks_per_block: u64 = ranges.chunks_per_block;

/// A chaining value's width, which is BLAKE3's output width.
pub const cv_length: usize = core.digest_length;

/// A parent pair's width on a wire and in an outboard: two chaining values.
pub const pair_length: usize = 2 * cv_length;

/// Every way reading a tree's own arithmetic over a blob can fail.
pub const HashError = error{
    /// The bytes handed over are not the length the tree was cut for. Every
    /// node's byte range is clipped to the declared size, so a blob of another
    /// length names ranges these bytes do not hold.
    SizeMismatch,
    /// A node does not begin on a chunk boundary. Every node this file names
    /// does, so this is the walk refusing to round rather than hashing bytes
    /// the caller did not name.
    OffsetNotChunkAligned,
};

/// One parent pair: a node's left chaining value and then its right.
pub const Pair = struct {
    left: core.CvBytes,
    right: core.CvBytes,
};

/// Write `pair` into the first `pair_length` bytes of `out`.
pub fn writePair(out: []u8, pair: Pair) void {
    @memcpy(out[0..cv_length], &pair.left);
    @memcpy(out[cv_length..pair_length], &pair.right);
}

/// Read a parent pair out of the first `pair_length` bytes of `bytes`.
pub fn readPair(bytes: []const u8) Pair {
    var pair: Pair = undefined;
    @memcpy(&pair.left, bytes[0..cv_length]);
    @memcpy(&pair.right, bytes[cv_length..pair_length]);
    return pair;
}

/// The left half of a node: where a split puts `left_span` chunks. A
/// two-chunk node splits one and one, which is the smallest case there is.
pub const Children = struct {
    left: Node,
    right: Node,
};

/// A node of the tree: a half-open span of chunks.
///
/// Both fields count 1024-byte chunks and nothing else. Every node a walk over
/// this tree names satisfies `start_chunk + span <= BaoTree.chunks()`, the last
/// one included: a blob whose length is not a multiple of 1024 has a short last
/// chunk and the node holding it holds the short span, never a rounded-up one.
pub const Node = struct {
    start_chunk: u64,
    span: u64,

    /// One past this node's last chunk, saturating.
    ///
    /// A walk over this tree never gets near the ceiling, because every node
    /// it names is bounded by `BaoTree.chunks()`. A `Node` handed in from
    /// outside can be, and saturating keeps that a range that reads as empty
    /// rather than an overflow a caller has to predict.
    pub fn endChunk(self: Node) u64 {
        return self.start_chunk +| self.span;
    }

    /// The chunks this node covers, which is the unit the wire is counted in.
    pub fn chunks(self: Node) ranges.ChunkRange {
        return .{ .start = self.start_chunk, .end = self.endChunk() };
    }

    /// The bytes this node covers, with the end clipped to the blob's own
    /// length, so a node never names a byte the blob does not hold.
    pub fn bytes(self: Node, tree: BaoTree) ranges.ByteRange {
        return .{
            .start = self.start_chunk * chunk_size,
            .end = @min(self.endChunk() *| chunk_size, tree.size),
        };
    }

    /// Whether `sel` holds every chunk of this node. A node the request takes
    /// whole is answered with its bytes and no pair of its own.
    pub fn covers(self: Node, sel: ranges.ChunkRange) bool {
        return self.start_chunk >= sel.start and self.endChunk() <= sel.end;
    }

    /// Whether this node and `sel` share a chunk. An empty node intersects
    /// nothing, which is what makes a zero-byte blob's root unreachable by any
    /// range request, and neither does a `sel` that names no chunk: a
    /// zero-width request has no chunks to share, so the walk below answers it
    /// with nothing rather than with the whole tree. Without this a request
    /// of zero width inside a blob would read as selecting the one chunk
    /// whose boundary it sits on, and `bao_plan` would build a plan for a
    /// range that was asked for nothing.
    pub fn intersects(self: Node, sel: ranges.ChunkRange) bool {
        if (self.span == 0 or sel.start >= sel.end) return false;
        return self.start_chunk < sel.end and sel.start < self.endChunk();
    }

    /// This node's two children, by the split rule below.
    pub fn children(self: Node) Children {
        const left_span = splitAt(self.span);
        return .{
            .left = .{ .start_chunk = self.start_chunk, .span = left_span },
            .right = .{
                .start_chunk = self.start_chunk + left_span,
                .span = self.span - left_span,
            },
        };
    }

    /// Whether this node is one whole chunk group: it begins on a group
    /// boundary and holds that group entire, the last group of a blob being
    /// the short one.
    pub fn isGroupLeaf(self: Node, tree: BaoTree) bool {
        if (self.start_chunk % chunks_per_block != 0) return false;
        return self.span == @min(chunks_per_block, tree.chunks() -| self.start_chunk);
    }

    /// Whether this node is one of the `blocks - 1` parents an outboard holds
    /// a pair for: it begins on a group boundary and spans more than one
    /// group. Every node below that line is inside a group and is not stored.
    pub fn isOutboardParent(self: Node) bool {
        return self.start_chunk % chunks_per_block == 0 and self.span > chunks_per_block;
    }

    /// Whether two nodes name the same span. The walk compares nodes rather
    /// than positions, so this is how a plan is checked against a tree.
    pub fn eql(a: Node, b: Node) bool {
        return a.start_chunk == b.start_chunk and a.span == b.span;
    }
};

/// The left half's length when a node of `span` chunks splits: the largest
/// power of two strictly below `span`.
///
/// This is BLAKE3's rule and not "half". Forty-seven chunks split thirty-two
/// and fifteen, not twenty-four and twenty-three, and a tree that split evenly
/// would be a different hash wearing the same name. `span` must be at least
/// two: a node of one chunk has nothing below it.
pub fn splitAt(span: u64) u64 {
    std.debug.assert(span >= 2);
    return @as(u64, 1) << @intCast(63 - @clz(span - 1));
}

/// The tree over a blob of `size` bytes.
pub const BaoTree = struct {
    /// The declared size. A claim; see the module comment.
    size: u64,

    pub fn init(size: u64) BaoTree {
        return .{ .size = size };
    }

    /// The chunks the blob has: its length rounded up to a chunk, which is
    /// zero for a blob of no bytes. A blob of no bytes has no last chunk, so
    /// no range request can name one.
    pub fn chunks(self: BaoTree) u64 {
        return ranges.chunkAfterByte(self.size);
    }

    /// The chunk groups the blob has: its chunks rounded up to a group. The
    /// last group is short rather than rounded up.
    pub fn blocks(self: BaoTree) u64 {
        return divCeil(self.chunks(), chunks_per_block);
    }

    /// The bytes of chunk group `index`, with the last group clamped to the
    /// blob's own end. `index` below `blocks()`; nothing keeps it there.
    pub fn blockBytes(self: BaoTree, index: u64) ranges.ByteRange {
        const start = index * block_size;
        return .{ .start = start, .end = @min(start +| block_size, self.size) };
    }

    /// The chunks of chunk group `index`.
    pub fn blockChunks(self: BaoTree, index: u64) ranges.ChunkRange {
        const bytes = self.blockBytes(index);
        return .{
            .start = ranges.chunkOfByte(bytes.start),
            .end = ranges.chunkAfterByte(bytes.end),
        };
    }

    /// The tree's root: every chunk the blob has and no more.
    pub fn root(self: BaoTree) Node {
        return .{ .start_chunk = 0, .span = self.chunks() };
    }

    /// The root block's shape: this many parent pairs, which is one fewer
    /// than there are groups, because a tree with `n` leaves has `n - 1`
    /// parents however unevenly it splits.
    pub fn rootBlockPairs(self: BaoTree) u64 {
        return self.blocks() -| 1;
    }

    /// The root block's length in bytes.
    pub fn rootBlockBytes(self: BaoTree) u64 {
        return self.rootBlockPairs() * @as(u64, pair_length);
    }

    /// Whether the root is one whole chunk group rather than a parent of them.
    pub fn rootIsLeaf(self: BaoTree) bool {
        return self.root().isGroupLeaf(self);
    }

    /// The chaining value the tree holds for `node`: ROOT clear, because every
    /// parent compresses its children's ROOT-free values.
    pub fn nodeCv(self: BaoTree, node: Node, data: []const u8) HashError!core.CvBytes {
        const range = node.bytes(self);
        if (data.len != self.size) return error.SizeMismatch;
        var hasher = try subtree.Hasher.init(range.start);
        hasher.update(data[@intCast(range.start)..@intCast(range.end)]);
        return hasher.finalChainingValue();
    }

    /// The blob's root hash: the same walk with ROOT set. This is the value a
    /// caller holds out of band and the last node of a proof has to reach.
    pub fn rootHash(self: BaoTree, data: []const u8) HashError!core.CvBytes {
        const range = self.root().bytes(self);
        if (data.len != self.size) return error.SizeMismatch;
        var hasher = try subtree.Hasher.init(0);
        hasher.update(data[@intCast(range.start)..@intCast(range.end)]);
        return hasher.final();
    }
};

/// The chunk group that holds `chunk`. A group number is a chunk number over
/// the group size, so it is a division and not a lookup: nothing about it
/// depends on the blob.
pub fn blockOfChunk(chunk: u64) u64 {
    return @divFloor(chunk, chunks_per_block);
}

/// `a` over `b`, rounded up. `b` is a named constant here and never zero.
fn divCeil(a: u64, b: u64) u64 {
    return a / b + @intFromBool(a % b != 0);
}

const t = std.testing;
const published = @import("../gossip/plumtree/blake3_vectors.zig");

// The four sizes the brief names, each counted out by hand from the two
// constants rather than read back out of the code.
//
//   16383 B -> 16 chunks (chunk 15 is 1023 bytes), 1 group, 1 group is a
//              leaf, 1 - 1 = 0 parents, so 0 outboard bytes.
//   16384 B -> 16 chunks, 1 group of 16, still a leaf, still 0 parents. One
//              byte more and the last chunk is full; it does not add a group.
//   32768 B -> 32 chunks, 2 groups, 2 - 1 = 1 parent, one 64-byte pair.
//   49153 B -> 49 chunks (chunk 48 is 1 byte), ceil(49/16) = 4 groups, of
//              which the last holds a single chunk, so 4 - 1 = 3 parents and
//              three 64-byte pairs.
//
// The first two are the sharp pair: they straddle the group size exactly and
// must both be an empty outboard, because a group is a leaf and the boundary
// adds no group. The last is the one that could be got wrong by rounding the
// last group up: 49153 bytes is three groups and a single byte, so four
// groups, not five.
test "the block count and the outboard length, hand-computed" {
    const cases = [_]struct { size: u64, chunks: u64, blocks: u64, pairs: u64 }{
        .{ .size = 16383, .chunks = 16, .blocks = 1, .pairs = 0 },
        .{ .size = 16384, .chunks = 16, .blocks = 1, .pairs = 0 },
        .{ .size = 32768, .chunks = 32, .blocks = 2, .pairs = 1 },
        .{ .size = 49153, .chunks = 49, .blocks = 4, .pairs = 3 },
    };
    for (cases) |case| {
        const tree = BaoTree.init(case.size);
        try t.expectEqual(case.chunks, tree.chunks());
        try t.expectEqual(case.blocks, tree.blocks());
        try t.expectEqual(case.pairs, tree.rootBlockPairs());
        try t.expectEqual(case.pairs * @as(u64, pair_length), tree.rootBlockBytes());
    }
}

// A short last group is short, and the byte range of every group lands inside
// the blob. The 49153 case is the one that matters: group 3 is one byte, and a
// group that rounded up would name 16385 bytes of a 49153-byte blob.
test "the last group is clamped to the blob and the others tile it" {
    const tree = BaoTree.init(49153);
    try t.expectEqual(ranges.ByteRange{ .start = 0, .end = 16384 }, tree.blockBytes(0));
    try t.expectEqual(ranges.ByteRange{ .start = 16384, .end = 32768 }, tree.blockBytes(1));
    try t.expectEqual(ranges.ByteRange{ .start = 32768, .end = 49152 }, tree.blockBytes(2));
    try t.expectEqual(ranges.ByteRange{ .start = 49152, .end = 49153 }, tree.blockBytes(3));

    try t.expectEqual(ranges.ChunkRange{ .start = 0, .end = 16 }, tree.blockChunks(0));
    try t.expectEqual(ranges.ChunkRange{ .start = 32, .end = 48 }, tree.blockChunks(2));
    try t.expectEqual(ranges.ChunkRange{ .start = 48, .end = 49 }, tree.blockChunks(3));

    var index: u64 = 0;
    while (index < tree.blocks()) : (index += 1) {
        const bytes = tree.blockBytes(index);
        const chunks = tree.blockChunks(index);
        try t.expectEqual(bytes.start, chunks.start * chunk_size);
        try t.expect(bytes.end <= tree.size);
        try t.expectEqual(blockOfChunk(chunks.start), index);
    }
}

// The split is BLAKE3's, and the boundaries in this table are where "half" and
// "the largest power of two below" disagree most: 47 is 32 + 15 and not
// 24 + 23, 63 is 32 + 31, 65 is 64 + 1. A tree that halved would still be a
// tree and would still be self-consistent, and would be a different hash.
test "a node splits at the largest power of two below its span" {
    const cases = [_]struct { span: u64, left: u64 }{
        .{ .span = 2, .left = 1 },
        .{ .span = 3, .left = 2 },
        .{ .span = 4, .left = 2 },
        .{ .span = 5, .left = 4 },
        .{ .span = 15, .left = 8 },
        .{ .span = 16, .left = 8 },
        .{ .span = 17, .left = 16 },
        .{ .span = 31, .left = 16 },
        .{ .span = 32, .left = 16 },
        .{ .span = 33, .left = 32 },
        .{ .span = 47, .left = 32 },
        .{ .span = 48, .left = 32 },
        .{ .span = 63, .left = 32 },
        .{ .span = 64, .left = 32 },
        .{ .span = 65, .left = 64 },
    };
    for (cases) |case| {
        try t.expectEqual(case.left, splitAt(case.span));
        const node = Node{ .start_chunk = 0, .span = case.span };
        const children = node.children();
        try t.expectEqual(case.left, children.left.span);
        try t.expectEqual(case.span - case.left, children.right.span);
        try t.expectEqual(case.left, children.right.start_chunk);
    }
}

// The tree is BLAKE3's tree: the root is the merge of its two halves' values,
// ROOT set, at every length. This is what a blob's trusted root is, and it is
// why the split above is not a choice. `std` is a second implementation, not
// captured bytes, so this says the walk agrees with it and nothing about any
// peer.
test "the tree's root is the plain BLAKE3 hash of the blob" {
    const sizes = [_]u64{ 0, 1, 1023, 1024, 1025, 4096, 16384, 16385, 47000, 49153 };
    for (sizes) |size| {
        const data = try published.blake3Input(@intCast(size));
        defer t.allocator.free(data);

        const tree = BaoTree.init(size);
        const root = tree.root();
        try t.expectEqual(@as(u64, 0), root.start_chunk);
        try t.expectEqual(tree.chunks(), root.span);
        try t.expectEqual(ranges.ByteRange{ .start = 0, .end = size }, root.bytes(tree));

        var reference: [core.digest_length]u8 = undefined;
        std.crypto.hash.Blake3.hash(data, &reference, .{});
        try t.expectEqual(reference, try tree.rootHash(data));

        if (root.span >= 2) {
            const children = root.children();
            const merged = subtree.mergeRoot(
                try tree.nodeCv(children.left, data),
                try tree.nodeCv(children.right, data),
            );
            try t.expectEqual(merged, try tree.rootHash(data));
        }
    }
}

// The number of nodes an outboard stores is `blocks - 1`, and the ones it
// stores are exactly those that begin on a group boundary and span more than
// one group. Counted here by walking the tree over a spread of sizes, because
// "one parent fewer than leaves" is the arithmetic the size claim rests on and
// it has to hold for a blob whose groups do not divide evenly.
test "an outboard holds one parent fewer than there are groups" {
    const sizes = [_]u64{ 0, 1, 1024, 16384, 16385, 32768, 32769, 47000, 49152, 49153, 65536 };
    for (sizes) |size| {
        const tree = BaoTree.init(size);
        const found = countParents(tree.root());
        try t.expectEqual(tree.blocks() -| 1, found);
        try t.expectEqual(found * @as(u64, pair_length), tree.rootBlockBytes());
    }
}

fn countParents(node: Node) u64 {
    if (!node.isOutboardParent()) return 0;
    const children = node.children();
    return 1 + countParents(children.left) + countParents(children.right);
}

// A node of one group is a leaf and a node of two groups is not, and the line
// between them is where an outboard stops. 49152 bytes is the sharp case, and
// it is sharp because 48 chunks is *not* a power of two: BLAKE3 splits it
// 32 + 16, so the root's left child is two whole groups — itself an outboard
// parent — and only its right child is one whole group. A tree that split 48
// as 16 + 32 would put the leaf on the other side of the root, and a tree
// that split it into three equal groups would not be BLAKE3 at all. This is
// the size that separates the two shapes: a blob of one, two or four groups
// cannot, because each of those is a power of two and splits down to whole
// groups on its own.
test "the leaf line falls between one group and two" {
    const one_group = BaoTree.init(16384);
    try t.expect(one_group.rootIsLeaf());
    try t.expect(one_group.root().isGroupLeaf(one_group));
    try t.expect(!one_group.root().isOutboardParent());

    const three_groups = BaoTree.init(49152);
    try t.expectEqual(@as(u64, 3), three_groups.blocks());
    try t.expectEqual(@as(u64, 2), three_groups.rootBlockPairs());
    try t.expect(!three_groups.rootIsLeaf());
    try t.expect(three_groups.root().isOutboardParent());
    const children = three_groups.root().children();
    try t.expectEqual(@as(u64, 32), children.left.span);
    try t.expect(!children.left.isGroupLeaf(three_groups));
    try t.expect(children.left.isOutboardParent());
    try t.expectEqual(@as(u64, 16), children.right.span);
    try t.expect(children.right.isGroupLeaf(three_groups));

    // The short last group is a leaf too, and at 49153 bytes it is one level
    // further down again: 49 chunks split 32 + 17, so the root's right child
    // is group 2 and the short group 3 together rather than either of them
    // alone. Group 3 holds chunk 48 and nothing else.
    const short = BaoTree.init(49153);
    const wide = short.root().children();
    try t.expectEqual(@as(u64, 17), wide.right.span);
    try t.expect(!wide.right.isGroupLeaf(short));
    const groups = wide.right.children();
    try t.expect(groups.left.isGroupLeaf(short));
    const last = groups.right;
    try t.expect(last.isGroupLeaf(short));
    try t.expectEqual(@as(u64, 1), last.span);
    try t.expect(!last.isOutboardParent());
}

// Every node the tree names is inside the blob, and every node's bytes start
// on a chunk boundary. A node that ran past the blob would name bytes the
// bytes do not hold, and one that started mid-chunk would be refused by the
// walk that hashes it.
test "every node is inside the blob and starts on a chunk boundary" {
    const sizes = [_]u64{ 0, 1025, 16385, 32769, 47000, 49153 };
    for (sizes) |size| {
        const tree = BaoTree.init(size);
        try checkNodes(tree, tree.root());
    }
}

fn checkNodes(tree: BaoTree, node: Node) !void {
    try t.expect(node.endChunk() <= tree.chunks());
    try t.expectEqual(node.start_chunk * chunk_size, node.bytes(tree).start);
    try t.expectEqual(@as(u64, 0), node.bytes(tree).start % chunk_size);
    try t.expect(node.bytes(tree).end <= tree.size);
    if (node.span < 2) return;
    const children = node.children();
    try checkNodes(tree, children.left);
    try checkNodes(tree, children.right);
}

// The pair layout is the parent block's own word order, read back out of it.
test "a parent pair is the left chaining value and then the right" {
    const data = try published.blake3Input(2048);
    defer t.allocator.free(data);

    const tree = BaoTree.init(2048);
    const children = tree.root().children();
    const pair = Pair{
        .left = try tree.nodeCv(children.left, data),
        .right = try tree.nodeCv(children.right, data),
    };

    var bytes: [pair_length]u8 = undefined;
    writePair(&bytes, pair);
    const read = readPair(&bytes);
    try t.expectEqual(pair.left, read.left);
    try t.expectEqual(pair.right, read.right);
    try t.expect(!std.meta.eql(pair.left, pair.right));

    // The two halves are in that order and not the other way round: the left
    // value is the first 32 bytes and the right value is the last 32. A pair
    // written the other way round would still be 64 bytes and would merge
    // every node in the tree to something else.
    try t.expectEqualSlices(u8, &pair.left, bytes[0..cv_length]);
    try t.expectEqualSlices(u8, &pair.right, bytes[cv_length..pair_length]);

    var swapped: [pair_length]u8 = undefined;
    writePair(&swapped, .{ .left = pair.right, .right = pair.left });
    try t.expect(!std.meta.eql(swapped, bytes));
}

// The declared size is a claim and the length of the bytes is a fact, and the
// two are compared. Bytes of exactly the declared length are read; bytes of
// any other length are refused rather than read at the edges, because every
// node's byte range is clipped to the declared size and a longer blob would
// name bytes past it.
test "a tree refuses bytes that are not its declared length" {
    const data = try published.blake3Input(1024);
    defer t.allocator.free(data);
    const longer = try published.blake3Input(1025);
    defer t.allocator.free(longer);

    const tree = BaoTree.init(1024);
    try t.expectEqual(@as(u64, 1024), tree.size);
    try t.expectEqual(@as(u64, 1), tree.chunks());
    try t.expectEqual(@as(usize, core.digest_length), (try tree.nodeCv(tree.root(), data)).len);
    try t.expectEqualSlices(u8, &try tree.rootHash(data), &try tree.rootHash(data));

    try t.expectError(error.SizeMismatch, tree.nodeCv(tree.root(), data[0..1023]));
    try t.expectError(error.SizeMismatch, tree.nodeCv(tree.root(), longer));
    try t.expectError(error.SizeMismatch, tree.rootHash(longer));
    try t.expectError(error.SizeMismatch, tree.rootHash(data[0..0]));
    try t.expectError(error.SizeMismatch, tree.nodeCv(tree.root(), data[0..0]));
}

test "last byte range at maximum declared size does not overflow" {
    const tree = BaoTree.init(std.math.maxInt(u64));
    const node = Node{ .start_chunk = tree.chunks() - 1, .span = 1 };
    try t.expectEqual(tree.size, node.bytes(tree).end);
    try t.expectEqual(@as(u64, 1023), node.bytes(tree).end - node.bytes(tree).start);
}
