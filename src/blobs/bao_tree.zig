//! The shape of a bao tree: which blocks a blob hashes into, where every node
//! of that tree sits, and how a tree is walked.
//!
//! This is geometry and nothing else. It holds no digest and reads no bytes:
//! BLAKE3's chaining and the outboard's bytes are the encoder's, and the proofs
//! are the verifier's. What is here is the shape those two agree on, so that a
//! request can be answered in blocks and a proof can name a node.
//!
//! # The units, which are upstream's
//!
//! A *chunk* is 1024 bytes and a *block* is sixteen chunks, 16 KiB. Both come
//! from `n0-computer/bao-tree` at commit
//! `2be9abd144783455606424424c29bd3a57f926f8`, cited where the numbers are
//! used in `protocol.zig`'s module comment: `BLAKE3_CHUNK_SIZE` at
//! `src/tree.rs:119`, `BlockSize::bytes()` at `src/tree.rs:159`, and the
//! crate's own default of `from_chunk_log(4)`. `chunk.zig` is this build's one
//! definition of the chunk arithmetic, so the two roundings below are its and
//! not copies of it.
//!
//! # What the tree is
//!
//! Blocks are the leaves, one node per block. A node at level `1 + k` covers
//! `2^k` blocks, and a node's children are its first and second halves, split
//! at its midpoint. A child that would start past the blob's last block does
//! not exist, which is the rule upstream's `split_inner` walks with when it
//! sends "a range that starts at or past a node's mid to the right" — the
//! quotation is `range_spec.zig`'s, and it is the same rule.
//!
//! The blob's blocks are covered by a *stack of complete subtrees*: the binary
//! decomposition of the block count, laid out from the blob's left, and the
//! **root is the largest one, at the blob's right end**. So a blob of five
//! blocks is the block 0 on its own, then a subtree of four blocks, and the
//! root covers blocks 1 to 4. The tree is right aligned, `shifted()` is how
//! far the root sits from block 0, and the nodes that reach the blob's last
//! block without passing through the root are the left spine.
//!
//! The rule that forces the root to the right end is the root's own: a root
//! digest covers the whole blob, so the root must be a subtree that reaches the
//! blob's last block, and the largest complete subtree that does is the one at
//! that end. A blob of no bytes is the same rule degenerate: no blocks, and a
//! tree of one node covering no block and no byte. Its root is that leaf, so
//! `blocks` is zero while a walk still hands out one node.
//!
//! # The order of a walk
//!
//! Both walks go through the stack from the left: the smallest subtree first,
//! the root last. Within a subtree, pre-order is a node and then its left and
//! right subtrees, and post-order is its left and right subtrees and then the
//! node. A walk holds no stack — see `preOrderStep` for why the path needs
//! none — and it runs out of subtrees after at most `max_level` steps, because
//! the level it resumes the stack at only ever rises.
//!
//! # What the tests check this against
//!
//! A reference recursion, written over runs of blocks and midpoints, which
//! splits a block count at its highest power of two where this module masks
//! one. It shares none of the arithmetic that finds a node's parent or its
//! successor in a walk, so its agreement is evidence about the shape rather
//! than one piece of arithmetic checked against itself.

const std = @import("std");
const chunk = @import("chunk.zig");

/// The BLAKE3 digest a node is summarised by, in bytes: the same 32 bytes
/// `ticket/blob_ticket.zig` calls its `Hash`.
pub const hash_size: u64 = 32;

/// The most levels a tree can have. A node's span doubles per level and a
/// block count is a `u64`, so level 64 is the first level no node reaches and
/// every walk up the levels below is bounded by it.
pub const max_level: u8 = 64;

/// A chunk number: the unit every range in this protocol is counted in.
///
/// A chunk is 1024 bytes, and both roundings are `chunk.zig`'s because they
/// are the protocol's: a byte range becomes a chunk range by rounding the start
/// *down* to the chunk that holds it and the end *up* to the first chunk past
/// it, and the two must not round the same way.
pub const ChunkNum = struct {
    /// The chunk, counted from the start of the blob.
    index: u64,

    /// The chunk that holds byte `offset`, rounded down.
    pub fn fromBytes(offset: u64) ChunkNum {
        return .{ .index = chunk.chunkOfByte(offset) };
    }

    /// The first chunk at or past byte `end`, rounded up.
    pub fn fromBytesCeil(end: u64) ChunkNum {
        return .{ .index = chunk.chunkAfterByte(end) };
    }

    /// The first byte of the chunk.
    ///
    /// Saturating, because a `ChunkNum` a caller built by hand can be
    /// `u64.max`, where upstream's `self.0 << 10` would not be a value at all.
    pub fn toBytes(self: ChunkNum) u64 {
        return self.index *| chunk.chunk_size;
    }

    /// The first byte past the chunk.
    pub fn endBytes(self: ChunkNum) u64 {
        return (self.index +| 1) *| chunk.chunk_size;
    }
};

/// The unit a tree's nodes cover: a block, counted in chunks.
///
/// The log is the whole of the type, and it is bounded because an unbounded one
/// would make a block larger than the blob it describes.
pub const BlockSize = struct {
    /// The log2 of the block size in chunks.
    chunk_log: u8,

    /// The largest log a block size may carry: 256 chunks, 256 KiB.
    pub const max_chunk_log: u8 = 8;

    /// The size the protocol answers in: sixteen chunks, 16 KiB.
    pub const default: BlockSize = .{ .chunk_log = 4 };

    /// The block size for `chunk_log`, or null when the log is out of range.
    pub fn init(chunk_log: u8) ?BlockSize {
        if (chunk_log > max_chunk_log) return null;
        return .{ .chunk_log = chunk_log };
    }

    /// Chunks to a block, `1 << chunk_log`.
    pub fn chunks(self: BlockSize) u64 {
        return @as(u64, 1) << @intCast(self.chunk_log);
    }

    /// Bytes to a block, `chunk_size << chunk_log`, which is upstream's
    /// `BlockSize::bytes` at `src/tree.rs:159`.
    pub fn bytes(self: BlockSize) u64 {
        return chunk.chunk_size * self.chunks();
    }
};

comptime {
    // The default has to be the block size the rest of the protocol calls a
    // block, or the tree would answer a request in a unit nothing asked in.
    std.debug.assert(BlockSize.default.bytes() == chunk.block_size);
    std.debug.assert(BlockSize.default.chunks() == chunk.chunks_per_block);
}

/// A half-open byte range, the unit an outboard is measured in.
pub const OutboardRanges = struct {
    /// Every node's digest but the root's: the tree section, which is the
    /// outboard's first `tree.end` bytes.
    tree: chunk.ByteRange,
    /// The root's digest, the outboard's last `hash_size` bytes.
    root: chunk.ByteRange,
};

/// The tree a blob of a known size has: its blocks, its nodes, and where they
/// sit. The root is the largest complete subtree at the blob's right end, so
/// `shifted` is how far the root is from the blob's first block.
pub const BaoTree = struct {
    /// The blob's length, in bytes.
    size: u64,
    /// The unit a node covers.
    block_size: BlockSize,
    /// The root's level: one is a leaf, so the root covers `2^(level-1)`
    /// blocks.
    root_level: u8,
    /// The root's first block, which is `shifted` and is not block 0 unless the
    /// block count is a power of two.
    root_offset: u64,

    /// The tree of a blob of `size` bytes.
    ///
    /// Total, and it cannot fail: every size has a tree, and the block size is
    /// already a `BlockSize`, which is the only thing upstream's `new` has a
    /// precondition about.
    pub fn init(size: u64, block_size: BlockSize) BaoTree {
        const shape = shapeBlocks(size, block_size);
        const depth: u6 = @intCast(63 - @clz(shape));
        return .{
            .size = size,
            .block_size = block_size,
            .root_level = depth + 1,
            .root_offset = shape - (@as(u64, 1) << depth),
        };
    }

    /// The blob's length, in bytes.
    pub fn size(self: BaoTree) u64 {
        return self.size;
    }

    /// The unit a node covers.
    pub fn blockSize(self: BaoTree) BlockSize {
        return self.block_size;
    }

    /// Blocks of data: `size` rounded up to a whole block.
    ///
    /// Zero for a blob of no bytes, whose tree is the one empty leaf above and
    /// so has a node without a block.
    pub fn blocks(self: BaoTree) u64 {
        const block_chunks = self.block_size.chunks();
        const chunks = ChunkNum.fromBytes(self.size).index;
        return chunks / block_chunks + @intFromBool(chunks % block_chunks != 0);
    }

    /// Chunks of data: `size` rounded up to a whole chunk.
    pub fn chunks(self: BaoTree) u64 {
        return ChunkNum.fromBytesCeil(self.size).index;
    }

    /// Blocks before the root's first block.
    ///
    /// Zero when the block count is a power of two, and otherwise the length
    /// of the left spine: the subtrees the root does not cover.
    pub fn shifted(self: BaoTree) u64 {
        return self.root_offset;
    }

    /// The root node, covering the blob's last `2^maxDepth` blocks.
    pub fn root(self: BaoTree) TreeNode {
        return .{ .tree = self, .level = self.root_level, .block_offset = self.root_offset };
    }

    /// Levels between the root and a leaf, so the root's span is `2^maxDepth`
    /// blocks.
    pub fn maxDepth(self: BaoTree) u8 {
        return self.root_level - 1;
    }

    /// Nodes in the tree, the root included: a subtree of `2^k` blocks holds
    /// `2^(k+1) - 1` nodes, and the stack's subtrees cover every block.
    pub fn nodeCount(self: BaoTree) u64 {
        const shape = shapeBlocks(self.size, self.block_size);
        return 2 * shape - @popCount(shape);
    }

    /// Bytes an outboard of this tree is: one digest per node.
    pub fn outboardSize(self: BaoTree) u64 {
        return hash_size * self.nodeCount();
    }

    /// The two sections an outboard is cut into: every node's digest but the
    /// root's, then the root's.
    pub fn outboardRanges(self: BaoTree) OutboardRanges {
        const tree_end = self.outboardSize() - hash_size;
        return .{
            .tree = .{ .start = 0, .end = tree_end },
            .root = .{ .start = tree_end, .end = self.outboardSize() },
        };
    }

    /// Every node of the tree in pre-order: the stack's smallest subtree
    /// first, the root last.
    pub fn preOrder(self: BaoTree) PreOrder {
        return .{ .tree = self };
    }

    /// Every node of the tree in post-order, over the same subtrees.
    pub fn postOrder(self: BaoTree) PostOrder {
        return .{ .tree = self };
    }
};

/// One node of a tree: a run of blocks at a level, and the tree it is in.
///
/// A node is named by its level and its first block, and the two together say
/// which node it is — every other thing about it is arithmetic on those, which
/// is why the node carries no index of its own and no bounds to check.
pub const TreeNode = struct {
    /// The tree the node is in.
    tree: BaoTree,
    /// The node's level: one is a leaf, so it covers one block, and every level
    /// up doubles the blocks a node covers.
    level: u8,
    /// The node's first block, counted from the start of the blob.
    block_offset: u64,

    /// The node at `level` covering the blocks from `block_offset` onwards.
    pub fn init(tree: BaoTree, level: u8, block_offset: u64) TreeNode {
        return .{ .tree = tree, .level = level, .block_offset = block_offset };
    }

    /// The node's level: one is a leaf.
    pub fn treeLevel(self: TreeNode) u8 {
        return self.level;
    }

    /// Levels between the node and a leaf. The root's is `BaoTree.maxDepth`.
    pub fn subtreeDepth(self: TreeNode) u8 {
        return self.level - 1;
    }

    /// Whether the node is the tree's root.
    pub fn isRoot(self: TreeNode) bool {
        return self.level == self.tree.root_level;
    }

    /// Whether the node is a leaf, and so covers exactly one block.
    pub fn isLeaf(self: TreeNode) bool {
        return self.level == 1;
    }

    /// Blocks the node covers, its span: one for a leaf, doubling per level.
    pub fn blockCount(self: TreeNode) u64 {
        return @as(u64, 1) << @intCast(self.level - 1);
    }

    /// Whether the node's last block is the blob's last block.
    ///
    /// The tree is right aligned, so this is the right spine: the root, and
    /// everything reached from it by right children. A node on the left spine
    /// covers a run of blocks that ends inside the blob, so it is not aligned,
    /// and a node that is a left child is not either.
    pub fn isRightAligned(self: TreeNode) bool {
        const shape = shapeBlocks(self.tree.size, self.tree.block_size);
        return self.block_offset + self.blockCount() == shape;
    }

    /// The node's first chunk.
    pub fn chunkGroup(self: TreeNode) ChunkNum {
        return .{ .index = self.block_offset * self.tree.blockSize().chunks() };
    }

    /// The node's bytes, cut at the blob's end: the last block of a blob that
    /// is not a whole number of blocks long is short, and its node's nominal
    /// span reaches past the bytes that exist.
    pub fn byteRange(self: TreeNode) chunk.ByteRange {
        const block_chunks = self.tree.blockSize().chunks();
        const first = ChunkNum{ .index = self.block_offset * block_chunks };
        const past = ChunkNum{ .index = (self.block_offset + self.blockCount()) * block_chunks };
        return .{ .start = first.toBytes(), .end = @min(past.endBytes(), self.tree.size()) };
    }

    /// The node's chunks, cut at the blob's last chunk. The two ends round the
    /// two ways they round everywhere else: a node starts on a chunk boundary,
    /// and a node that reaches the blob's end stops on its last chunk.
    pub fn chunkRange(self: TreeNode) chunk.ChunkRange {
        const bytes = self.byteRange();
        return .{
            .start = ChunkNum.fromBytes(bytes.start).index,
            .end = ChunkNum.fromBytesCeil(bytes.end).index,
        };
    }

    /// The node's parent, or null when the node is the root or the top of one
    /// of the stack's subtrees, which is every node with no node above it.
    pub fn parent(self: TreeNode) ?TreeNode {
        const subtree = subtreeOf(self.tree, self.block_offset);
        if (self.level == subtree.level) return null;
        const span = blockSpan(self.level + 1);
        const offset = subtree.top + @divFloor(self.block_offset - subtree.top, span) * span;
        return TreeNode.init(self.tree, self.level + 1, offset);
    }

    /// The node's left child, which exists whenever the node is not a leaf: the
    /// left child is the node's own first blocks, and the node is in the blob.
    pub fn left(self: TreeNode) ?TreeNode {
        if (self.isLeaf()) return null;
        return TreeNode.init(self.tree, self.level - 1, self.block_offset);
    }

    /// The node's right child, or null when the node's second half starts past
    /// the blob's last block.
    pub fn right(self: TreeNode) ?TreeNode {
        if (self.isLeaf()) return null;
        const subtree = subtreeOf(self.tree, self.block_offset);
        const offset = self.block_offset + blockSpan(self.level - 1);
        if (offset >= subtree.top + subtree.span) return null;
        return TreeNode.init(self.tree, self.level - 1, offset);
    }

    /// The node's left sibling, or null when the node is its subtree's leftmost
    /// node at its level and so has nothing to its left.
    pub fn leftSibling(self: TreeNode) ?TreeNode {
        const subtree = subtreeOf(self.tree, self.block_offset);
        const offset = self.block_offset - blockSpan(self.level);
        if (offset < subtree.top) return null;
        return TreeNode.init(self.tree, self.level, offset);
    }

    /// The node's right sibling, or null when the node's subtree ends at the
    /// node's right edge.
    pub fn rightSibling(self: TreeNode) ?TreeNode {
        const subtree = subtreeOf(self.tree, self.block_offset);
        const offset = self.block_offset + blockSpan(self.level);
        if (offset >= subtree.top + subtree.span) return null;
        return TreeNode.init(self.tree, self.level, offset);
    }

    /// Whether the node is inside `other`'s run of blocks, which is what a
    /// proof naming `other` is checked against. The two nodes must be of the
    /// same tree, and `other` must not be below the node: a subtree holds its
    /// own descendants and nothing else.
    pub fn isSubtree(self: TreeNode, other: TreeNode) bool {
        if (self.tree.size != other.tree.size) return false;
        if (self.tree.root_level != other.tree.root_level) return false;
        if (self.tree.root_offset != other.tree.root_offset) return false;
        if (other.level > self.level) return false;
        return other.block_offset <= self.block_offset and
            self.block_offset + self.blockCount() <= other.block_offset + other.blockCount();
    }

    /// The node's own stack subtree, for a caller walking one subtree.
    pub fn subtree(self: TreeNode) Subtree {
        return subtreeOf(self.tree, self.block_offset);
    }
};

/// The tree's nodes in one of the two depth-first orders.
///
/// The walk goes through the stack from the left — the smallest subtree first,
/// the root last — which is the order the blob's blocks are read in. `order` is
/// a comptime parameter because the two walks differ only in which node
/// follows which, and a flag a walk cannot change would put a branch in every
/// step of both of them.
pub fn Walk(comptime order: enum { pre, post }) type {
    return struct {
        const Self = @This();

        /// The tree being walked.
        tree: BaoTree,
        /// The level the walk resumes the stack at. It only ever rises, so a
        /// walk cannot come back to a subtree it has finished, and it runs out
        /// after at most `max_level` subtrees.
        resume_level: u8 = 1,
        /// The subtree being walked, zeroed once it is finished.
        subtree: Subtree = .{},
        /// The node last handed out, and zero when the subtree is finished.
        level: u8 = 0,
        /// The last node's first block.
        block_offset: u64 = 0,

        /// The next node, or null once the tree is walked.
        ///
        /// Every step is either the next node or a strictly higher
        /// `resume_level`, so the walk ends.
        pub fn next(self: *Self) ?TreeNode {
            while (true) {
                if (self.level != 0) {
                    const node = self.node();
                    const step = switch (order) {
                        .pre => preOrderStep(self.tree, self.subtree, node),
                        .post => postOrderStep(self.tree, self.subtree, node),
                    };
                    if (step) |next_node| {
                        self.level = next_node.level;
                        self.block_offset = next_node.block_offset;
                        return next_node;
                    }
                    self.level = 0;
                }
                const subtree = subtreeAt(self.tree, self.resume_level) orelse return null;
                self.resume_level = subtree.level + 1;
                self.subtree = subtree;
                self.block_offset = subtree.top;
                // Pre-order opens a subtree at its root and post-order at its
                // leftmost leaf, because that is the first node of each order.
                self.level = switch (order) {
                    .pre => subtree.level,
                    .post => 1,
                };
                return self.node();
            }
        }

        /// The node the walk is on.
        fn node(self: Self) TreeNode {
            return .{
                .tree = self.tree,
                .level = self.level,
                .block_offset = self.block_offset,
            };
        }
    };
}

/// The tree's nodes in pre-order: a node, then its left subtree, then its
/// right one.
pub const PreOrder = Walk(.pre);

/// The tree's nodes in post-order: its left subtree, then its right one, then
/// the node.
pub const PostOrder = Walk(.post);

/// One subtree of the stack: the run of blocks its root covers.
const Subtree = struct {
    /// The subtree's first block.
    top: u64,
    /// Blocks its root covers, `2^(level-1)`.
    span: u64,
    /// Its root's level: one is a leaf.
    level: u8,
};

/// Blocks a node at `level` covers, `2^(level-1)`, for `level` in
/// `1..max_level`.
fn blockSpan(level: u8) u64 {
    return @as(u64, 1) << @intCast(level - 1);
}

/// The block count a tree's shape is built from: `BaoTree.blocks`, or one for a
/// blob of no bytes, whose tree is a single leaf covering nothing.
///
/// Derived from the size and the block size on every call rather than carried
/// beside them, so it cannot drift from the two it comes from.
fn shapeBlocks(size: u64, block_size: BlockSize) u64 {
    const block_chunks = block_size.chunks();
    const chunks = ChunkNum.fromBytes(size).index;
    const blocks = chunks / block_chunks + @intFromBool(chunks % block_chunks != 0);
    return @max(blocks, 1);
}

/// The node's index inside its own subtree: zero is the leftmost node at that
/// level, and the span divides the difference exactly.
fn subtreeIndex(subtree: Subtree, node: TreeNode) u64 {
    return (node.block_offset - subtree.top) / blockSpan(node.level);
}

/// The stack subtree holding `block_offset`: the last one that starts at or
/// before it.
///
/// The subtrees tile the blob's blocks from the left, smallest first, and the
/// one covering `2^k` blocks starts at `blocks mod 2^k`. Those starts do not
/// fall as the level rises, so the walk up the levels stops at the first start
/// past the block, and what it stopped at is the subtree holding it.
fn subtreeOf(tree: BaoTree, block_offset: u64) Subtree {
    const shape = shapeBlocks(tree.size, tree.block_size);
    var found: Subtree = .{ .top = 0, .span = 1, .level = 1 };
    var level: u8 = 1;
    while (level <= max_level) : (level += 1) {
        const span = blockSpan(level);
        const top = shape & (span - 1);
        if (top > block_offset) break;
        found = .{ .top = top, .span = span, .level = level };
    }
    return found;
}

/// The next stack subtree at or above `level`, which is where a walk through
/// the stack resumes: the levels the shape has a subtree at.
fn subtreeAt(tree: BaoTree, level: u8) ?Subtree {
    const shape = shapeBlocks(tree.size, tree.block_size);
    var at: u8 = @max(level, 1);
    while (at <= max_level) : (at += 1) {
        const span = blockSpan(at);
        if (shape & span != 0) return .{ .top = shape & (span - 1), .span = span, .level = at };
    }
    return null;
}

/// The node after `node` in pre-order inside `subtree`, or null once the
/// subtree is walked out.
///
/// A walk needs no stack for this. Inside its own subtree a node's ancestor at
/// any level is its first block rounded down to that level's span, and the
/// node's position in that ancestor's pair is one bit of the node's own index.
/// So the ancestor nearest with an unvisited right child is the lowest level
/// whose bit is clear, which is arithmetic on the node rather than a history.
fn preOrderStep(tree: BaoTree, subtree: Subtree, node: TreeNode) ?TreeNode {
    if (node.treeLevel() > 1) {
        return TreeNode.init(tree, node.level - 1, node.block_offset);
    }
    const index = subtreeIndex(subtree, node);
    var level: u8 = node.level + 1;
    while (level <= subtree.level) : (level += 1) {
        const side = index >> @intCast(level - node.level - 1);
        if (side & 1 != 0) continue;
        const parent_index = index >> @intCast(level - node.level);
        const offset = subtree.top + (2 * parent_index + 1) * blockSpan(level - 1);
        if (offset >= subtree.top + subtree.span) continue;
        return TreeNode.init(tree, level - 1, offset);
    }
    return null;
}

/// The node after `node` in post-order inside `subtree`, or null once the
/// subtree is walked out.
///
/// Every node is followed by its parent unless it is a left child with a right
/// sibling, and then it is followed by that sibling's subtree — which a
/// post-order walk enters at its leftmost leaf. So a post-order step is one of
/// two things and never a climb.
fn postOrderStep(tree: BaoTree, subtree: Subtree, node: TreeNode) ?TreeNode {
    const index = subtreeIndex(subtree, node);
    if (index & 1 == 0) {
        const sibling = subtree.top + (index + 1) * blockSpan(node.level);
        if (sibling < subtree.top + subtree.span) {
            return TreeNode.init(tree, 1, sibling);
        }
    }
    if (node.level == subtree.level) return null;
    const parent_index = index >> 1;
    return TreeNode.init(
        tree,
        node.level + 1,
        subtree.top + parent_index * blockSpan(node.level + 1),
    );
}

const t = std.testing;

test "the block size is the one the rest of the protocol answers in" {
    // The tree has to meet the protocol in the protocol's unit: a block is
    // 16 KiB of sixteen chunks, and a chunk is 1024 bytes.
    try t.expectEqual(@as(u64, 1024), chunk.chunk_size);
    try t.expectEqual(@as(u64, 16384), BlockSize.default.bytes());
    try t.expectEqual(@as(u64, 16), BlockSize.default.chunks());
    try t.expectEqual(BlockSize.default.bytes(), chunk.block_size);
    try t.expectEqual(BlockSize.default.chunks(), chunk.chunks_per_block);
    // The log is the type, and it is bounded: 256 chunks is the largest block,
    // and nine would be a block of 512 KiB, which nothing asked for.
    try t.expectEqual(@as(u64, 256), BlockSize{ .chunk_log = 8 }.chunks());
    try t.expectEqual(@as(u64, 262144), BlockSize{ .chunk_log = 8 }.bytes());
    try t.expectEqual(@as(u64, 1), BlockSize{ .chunk_log = 0 }.chunks());
    try t.expectEqual(@as(u64, 1024), BlockSize{ .chunk_log = 0 }.bytes());
    try t.expectEqual(@as(?BlockSize, null), BlockSize.init(9));
    try t.expectEqual(@as(?BlockSize, null), BlockSize.init(255));
    try t.expectEqual(BlockSize{ .chunk_log = 4 }, BlockSize.init(4).?);
    // A level is a span, and a span is a power of two of at most 2^63, which
    // is what `max_level` promises the walks that go up the levels.
    try t.expectEqual(@as(u64, 1), blockSpan(1));
    try t.expectEqual(@as(u64, 16), blockSpan(5));
    try t.expectEqual(@as(u64, 1) << 63, blockSpan(max_level));
}

test "a chunk number rounds the two ways the protocol rounds them" {
    // Start down to the chunk that holds the byte, end up to the first chunk
    // past it: byte 0 and byte 1023 are both chunk 0, and 1024 bytes is one
    // chunk while 1025 is two.
    try t.expectEqual(@as(u64, 0), ChunkNum.fromBytes(0).index);
    try t.expectEqual(@as(u64, 0), ChunkNum.fromBytes(1023).index);
    try t.expectEqual(@as(u64, 1), ChunkNum.fromBytes(1024).index);
    try t.expectEqual(@as(u64, 1), ChunkNum.fromBytesCeil(1024).index);
    try t.expectEqual(@as(u64, 2), ChunkNum.fromBytesCeil(1025).index);
    try t.expectEqual(@as(u64, 0), ChunkNum.fromBytesCeil(0).index);
    // And back out, saturating rather than wrapping, because a caller can hold
    // a chunk number no blob reaches.
    try t.expectEqual(@as(u64, 0), ChunkNum{ .index = 0 }.toBytes());
    try t.expectEqual(@as(u64, 1024), ChunkNum{ .index = 1 }.toBytes());
    try t.expectEqual(@as(u64, 1024), ChunkNum{ .index = 0 }.endBytes());
    try t.expectEqual(@as(u64, 2048), ChunkNum{ .index = 1 }.endBytes());
    try t.expectEqual(std.math.maxInt(u64), ChunkNum{ .index = std.math.maxInt(u64) }.toBytes());
    try t.expectEqual(std.math.maxInt(u64), ChunkNum{ .index = std.math.maxInt(u64) }.endBytes());
}

const SizeCase = struct {
    size: u64,
    blocks: u64,
    chunks: u64,
};

test "a blob's blocks and chunks round the way chunk.zig rounds them" {
    const cases = [_]SizeCase{
        .{ .size = 0, .blocks = 0, .chunks = 0 },
        .{ .size = 1, .blocks = 1, .chunks = 1 },
        .{ .size = 1023, .blocks = 1, .chunks = 1 },
        .{ .size = 1024, .blocks = 1, .chunks = 1 },
        .{ .size = 1025, .blocks = 1, .chunks = 2 },
        .{ .size = 16383, .blocks = 1, .chunks = 16 },
        .{ .size = 16384, .blocks = 1, .chunks = 16 },
        .{ .size = 16385, .blocks = 2, .chunks = 17 },
        .{ .size = 32768, .blocks = 2, .chunks = 32 },
        .{ .size = 100000, .blocks = 7, .chunks = 98 },
        .{ .size = 1048576, .blocks = 64, .chunks = 1024 },
    };
    for (cases) |case| {
        const tree = BaoTree.init(case.size, BlockSize.default);
        try t.expectEqual(case.size, tree.size());
        try t.expectEqual(BlockSize.default, tree.blockSize());
        try t.expectEqual(case.blocks, tree.blocks());
        try t.expectEqual(case.chunks, tree.chunks());
    }
}

const ShapeCase = struct {
    blocks: u64,
    shifted: u64,
    root_level: u8,
    nodes: u64,
};

test "the root is the largest complete subtree at the blob's right end" {
    // The shift is the whole of "right aligned": zero when the blocks are a
    // whole number of complete subtrees and the number of blocks on the left
    // spine when they are not. The node count is one per node, the root
    // included, which is what an outboard is sized by.
    const cases = [_]ShapeCase{
        .{ .blocks = 0, .shifted = 0, .root_level = 1, .nodes = 1 },
        .{ .blocks = 1, .shifted = 0, .root_level = 1, .nodes = 1 },
        .{ .blocks = 2, .shifted = 0, .root_level = 2, .nodes = 3 },
        .{ .blocks = 3, .shifted = 1, .root_level = 2, .nodes = 4 },
        .{ .blocks = 4, .shifted = 0, .root_level = 3, .nodes = 7 },
        .{ .blocks = 5, .shifted = 1, .root_level = 3, .nodes = 8 },
        .{ .blocks = 6, .shifted = 2, .root_level = 3, .nodes = 10 },
        .{ .blocks = 7, .shifted = 3, .root_level = 3, .nodes = 11 },
        .{ .blocks = 8, .shifted = 0, .root_level = 4, .nodes = 15 },
        .{ .blocks = 9, .shifted = 1, .root_level = 4, .nodes = 16 },
        .{ .blocks = 10, .shifted = 2, .root_level = 4, .nodes = 18 },
        .{ .blocks = 13, .shifted = 5, .root_level = 4, .nodes = 23 },
        .{ .blocks = 16, .shifted = 0, .root_level = 5, .nodes = 31 },
    };
    for (cases) |case| {
        const tree = treeOfBlocks(case.blocks);
        try t.expectEqual(case.blocks, tree.blocks());
        try t.expectEqual(case.shifted, tree.shifted());
        try t.expectEqual(case.root_level, tree.root().treeLevel());
        try t.expectEqual(case.root_level - 1, tree.maxDepth());
        try t.expectEqual(case.nodes, tree.nodeCount());
        try t.expectEqual(hash_size * case.nodes, tree.outboardSize());
    }
}

test "an outboard is the tree's nodes and then the root" {
    // One digest per node, the root's last, and the two sections together are
    // the whole outboard — which is the only thing a reader of an outboard
    // needs to know before it starts checking the root.
    const tree = treeOfBlocks(5);
    const ranges = tree.outboardRanges();
    try t.expectEqual(@as(u64, 0), ranges.tree.start);
    try t.expectEqual(hash_size * 7, ranges.tree.end);
    try t.expectEqual(ranges.tree.end, ranges.root.start);
    try t.expectEqual(tree.outboardSize(), ranges.root.end);
    try t.expectEqual(ranges.root.end - ranges.root.start, hash_size);
    // And the empty blob is the one case with nothing but a root to check.
    const empty = BaoTree.init(0, BlockSize.default);
    try t.expectEqual(@as(u64, 0), empty.blocks());
    try t.expectEqual(@as(u64, 1), empty.nodeCount());
    try t.expectEqual(hash_size, empty.outboardSize());
    try t.expectEqual(@as(u64, 0), empty.outboardRanges().tree.end);
    try t.expectEqual(@as(u64, 1), empty.root().isRightAligned());
}

test "pre-order and post-order agree with the reference recursion" {
    // The oracle is a definition, not an implementation: nodes are runs of
    // blocks, children are the halves split at the midpoint, and a blob's tree
    // is the block count split at its highest power of two, over and over. It
    // shares no masks or offsets with the walks above, so both orders coming
    // out of the two the same is evidence about the shape.
    for (0..13) |index| {
        try expectWalksMatch(treeOfBlocks(index));
    }
    for ([_]u64{ 16, 17, 31, 33, 64, 100 }) |blocks| {
        try expectWalksMatch(treeOfBlocks(blocks));
    }
    // The block size is not part of the shape, so five 1 KiB blocks and five
    // 16 KiB blocks walk the same way, and both have five blocks.
    const fine = BaoTree.init(5 * 1024, BlockSize.init(0).?);
    try t.expectEqual(@as(u64, 5), fine.blocks());
    try expectWalksMatch(fine);
    try expectWalksMatch(treeOfBlocks(5));
}

test "the walk holds every node once, and the leaves are the blocks in order" {
    // A leaf is a block, so the leaves in walk order are the block numbers in
    // order, and there are as many of them as the blob has blocks.
    for ([_]u64{ 0, 1, 2, 3, 7, 8, 9, 13, 21, 64 }) |blocks| {
        const tree = treeOfBlocks(blocks);
        var walk = tree.preOrder();
        var leaf_index: u64 = 0;
        while (walk.next()) |node| {
            if (!node.isLeaf()) continue;
            try t.expectEqual(leaf_index, node.block_offset);
            try t.expectEqual(@as(u8, 1), node.treeLevel());
            leaf_index += 1;
        }
        try t.expectEqual(@max(blocks, 1), leaf_index);
        // And the walk hands out every node the count says there are, which is
        // what makes "the walk terminates" checkable rather than a hope.
        try t.expectEqual(tree.nodeCount(), count(tree.preOrder()));
        try t.expectEqual(tree.nodeCount(), count(tree.postOrder()));
    }
}

test "every node's parent, children and siblings are the tree's own" {
    // Each node is a child of the node above it and of nothing else. The nodes
    // with no parent are the stack's tops, one per set bit of the block count.
    // And a node is right aligned exactly when its right edge is its parent's,
    // which makes the right spine the nodes that reach the blob's last block.
    for ([_]u64{ 0, 1, 2, 3, 5, 7, 8, 9, 13, 17, 33 }) |blocks| {
        const tree = treeOfBlocks(blocks);
        var with_parent: u64 = 0;
        var tops: u64 = 0;
        var walk = tree.preOrder();
        while (walk.next()) |node| {
            const parent = node.parent() orelse {
                // No parent means the node is the top of its own subtree, so it
                // starts where that subtree starts: at block 0, or at the root.
                const subtree = node.subtree();
                try t.expectEqual(subtree.level, node.treeLevel());
                try t.expectEqual(subtree.top, node.block_offset);
                try t.expect(node.isRoot() or subtree.top == 0);
                tops += 1;
                continue;
            };
            with_parent += 1;
            try t.expectEqual(node.treeLevel() + 1, parent.treeLevel());
            const left = parent.left().?;
            const right = parent.right();
            // The node is one of its parent's two children, and the child
            // names the parent back, so the relation is the tree's own.
            try t.expect(sameNode(node, left) or (right != null and sameNode(node, right.?)));
            try t.expect(sameNode(parent, left.parent().?));
            if (right) |right_child| try t.expect(sameNode(parent, right_child.parent().?));
            // Alignment is a property of the right edge and not of the level: a
            // right child is aligned exactly as its parent is, and a left child
            // stops at the midpoint and so never is.
            try t.expectEqual(blockEnd(node) == blockEnd(parent), node.isRightAligned());
            // A sibling, when there is one, is the same level one span away.
            if (node.leftSibling()) |sibling| {
                try t.expectEqual(node.treeLevel(), sibling.treeLevel());
                try t.expectEqual(node.block_offset - blockSpan(node.treeLevel()), sibling.block_offset);
            }
            if (node.rightSibling()) |sibling| {
                try t.expectEqual(node.treeLevel(), sibling.treeLevel());
                try t.expectEqual(node.block_offset + blockSpan(node.treeLevel()), sibling.block_offset);
            }
        }
        try t.expectEqual(@popCount(@max(blocks, 1)), tops);
        try t.expectEqual(tree.nodeCount() - tops, with_parent);
        try t.expect(tree.root().isRoot());
        try t.expect(tree.root().parent() == null);
        // Right children from the root reach the blob's last block, and only
        // the root itself is aligned without a parent to be aligned with.
        var spine = tree.root();
        while (spine.right()) |right| spine = right;
        try t.expectEqual(@max(tree.blocks(), 1), blockEnd(spine));
        try t.expect(spine.isRightAligned());
    }
}

test "a node's bytes and chunks stop at the blob's end" {
    // The last block of a blob that is not a whole number of blocks long is
    // short, so the nodes that reach it are cut, and the cut is at the blob's
    // last chunk rather than at a round chunk boundary.
    const cases = [_]u64{ 1, 1023, 16384, 16385, 100000, 1048576 };
    for (cases) |size| {
        const tree = BaoTree.init(size, BlockSize.default);
        var walk = tree.preOrder();
        while (walk.next()) |node| {
            const bytes = node.byteRange();
            const ranges = node.chunkRange();
            try t.expect(bytes.start <= bytes.end);
            try t.expect(bytes.end <= size);
            try t.expectEqual(chunk.chunkOfByte(bytes.start), ranges.start);
            try t.expectEqual(chunk.chunkAfterByte(bytes.end), ranges.end);
            try t.expect(ranges.end <= tree.chunks());
            // A node's nominal span is a whole number of blocks, and only the
            // ones that reach the end are cut.
            const nominal = node.blockCount() * BlockSize.default.bytes();
            try t.expect(node.block_offset + node.blockCount() == tree.blocks() or
                bytes.end - bytes.start == nominal);
        }
        // The leaf covering the blob's last block ends on the blob's last byte.
        const last = nodeAtLastBlock(tree);
        try t.expectEqual(size, last.byteRange().end);
        try t.expectEqual(tree.chunks(), last.chunkRange().end);
    }
}

test "a node is inside the subtree it names and no other" {
    const tree = treeOfBlocks(13);
    const root = tree.root();
    const spine_leaf = TreeNode.init(tree, 1, 0);
    const spine_subtree = TreeNode.init(tree, 2, 1);
    const left_edge = TreeNode.init(tree, 1, 5);
    const right_edge = TreeNode.init(tree, 1, 12);
    // A node holds itself and its own descendants: the root holds every node
    // of the blob, and the left spine's own subtree holds its own leaves.
    try t.expect(root.isSubtree(root));
    try t.expect(left_edge.isSubtree(root));
    try t.expect(right_edge.isSubtree(root));
    try t.expect(TreeNode.init(tree, 1, 2).isSubtree(spine_subtree));
    // It holds nothing above it and nothing of its own level but itself, so
    // the root is inside nothing and the left spine's top is inside no root.
    try t.expect(!root.isSubtree(left_edge));
    try t.expect(!root.isSubtree(right_edge));
    try t.expect(!root.isSubtree(spine_subtree));
    try t.expect(!spine_subtree.isSubtree(root));
    try t.expect(!spine_subtree.isSubtree(spine_leaf));
    try t.expect(!spine_leaf.isSubtree(spine_subtree));
    // Neither edge is inside the other, they are siblings.
    try t.expect(!left_edge.isSubtree(right_edge));
    try t.expect(!right_edge.isSubtree(left_edge));
    // And a node of another blob is nobody's subtree, in either direction.
    const other = treeOfBlocks(14);
    try t.expect(!root.isSubtree(other.root()));
    try t.expect(!other.root().isSubtree(root));
}

/// The tree of `blocks` whole 16 KiB blocks, so the block count of the result
/// is `blocks` and the size is whatever the test table means by it.
fn treeOfBlocks(blocks: u64) BaoTree {
    return BaoTree.init(blocks * BlockSize.default.bytes(), BlockSize.default);
}

/// One past the node's last block: its nominal span counted from its first,
/// which is the edge the tree's alignment is read off.
fn blockEnd(node: TreeNode) u64 {
    return node.block_offset + node.blockCount();
}

/// Whether two nodes are the same node.
fn sameNode(a: TreeNode, b: TreeNode) bool {
    return a.treeLevel() == b.treeLevel() and a.block_offset == b.block_offset;
}

/// The leaf covering the blob's last block, or the root's own leaf for a blob
/// of no bytes.
fn nodeAtLastBlock(tree: BaoTree) TreeNode {
    return TreeNode.init(tree, 1, if (tree.blocks() == 0) 0 else tree.blocks() - 1);
}

/// How many nodes a walk hands out, and no more: the count is what the tree
/// says there are, so a walk that went on past them would be caught here
/// rather than run until something else stopped it.
fn count(walk: anytype) u64 {
    var seen: u64 = 0;
    while (walk.next() != null) {
        seen += 1;
        if (seen > (1 << 20)) return seen;
    }
    return seen;
}

/// Check that both walks of `tree` hand out the nodes the reference recursion
/// says, in the reference's order.
fn expectWalksMatch(tree: BaoTree) !void {
    var pre: std.ArrayList(TreeNode) = .empty;
    defer pre.deinit(t.allocator);
    var post: std.ArrayList(TreeNode) = .empty;
    defer post.deinit(t.allocator);
    try referenceTree(tree, &pre, &post);

    var pre_walk = tree.preOrder();
    var index: usize = 0;
    while (pre_walk.next()) |node| {
        if (index >= pre.items.len) return error.WalkRanLong;
        if (!sameNode(pre.items[index], node)) return error.WalkOrderMismatch;
        index += 1;
    }
    if (index != pre.items.len) return error.WalkShort;

    var post_walk = tree.postOrder();
    index = 0;
    while (post_walk.next()) |node| {
        if (index >= post.items.len) return error.WalkRanLong;
        if (!sameNode(post.items[index], node)) return error.WalkOrderMismatch;
        index += 1;
    }
    if (index != post.items.len) return error.WalkShort;

    // The two orders hold the same nodes, and the count is the tree's.
    if (pre.items.len != tree.nodeCount()) return error.NodeCountMismatch;
    if (post.items.len != tree.nodeCount()) return error.NodeCountMismatch;
    for (pre.items, post.items) |a, b| {
        if (!sameNode(a, b)) return error.OrdersHoldDifferentNodes;
    }
}

/// The nodes of `tree`, in pre-order and in post-order, by the reference
/// recursion the module comment describes.
///
/// Recurses where `BaoTree` computes: a subtree is halved and both halves are
/// walked, and a blob's stack is its block count split at the highest power of
/// two with the smaller part off the left.
fn referenceTree(
    tree: BaoTree,
    pre: *std.ArrayList(TreeNode),
    post: *std.ArrayList(TreeNode),
) !void {
    var spans: std.ArrayList(u64) = .empty;
    defer spans.deinit(t.allocator);
    try referenceSubtrees(referenceBlocks(tree), &spans);
    var top: u64 = 0;
    for (spans.items) |span| {
        try referenceSubtree(tree, span, top, pre, post);
        top += span;
    }
}

/// The spans of the subtrees covering `shape` blocks, smallest first.
fn referenceSubtrees(shape: u64, spans: *std.ArrayList(u64)) !void {
    if (shape <= 1) {
        if (shape == 1) try spans.append(t.allocator, 1);
        return;
    }
    var span: u64 = 1;
    while (span <= @divFloor(shape, 2)) span *= 2;
    if (shape - span != 0) try referenceSubtrees(shape - span, spans);
    try spans.append(t.allocator, span);
}

/// The nodes of one subtree of `span` blocks from `top`, pre-order and
/// post-order, by recursion.
fn referenceSubtree(
    tree: BaoTree,
    span: u64,
    top: u64,
    pre: *std.ArrayList(TreeNode),
    post: *std.ArrayList(TreeNode),
) !void {
    const node = TreeNode.init(tree, levelOfSpan(span), top);
    try pre.append(t.allocator, node);
    if (span > 1) {
        const half = span / 2;
        try referenceSubtree(tree, half, top, pre, post);
        // The right child exists only where there is a block past the midpoint,
        // which is the rule `BaoTree` applies without a recursion to find.
        if (top + half < referenceBlocks(tree)) {
            try referenceSubtree(tree, half, top + half, pre, post);
        }
    }
    try post.append(t.allocator, node);
}

/// The level of a node covering `span` blocks: a leaf is level one.
fn levelOfSpan(span: u64) u8 {
    return @intCast(63 - @clz(span) + 1);
}

/// The block count the reference tree is built over: the blob's blocks, or one
/// for a blob of no bytes, whose tree is the single leaf above. Spelled out
/// rather than reusing `shapeBlocks`, because an oracle that calls the
/// implementation's own arithmetic cannot disagree with it.
fn referenceBlocks(tree: BaoTree) u64 {
    return @max(tree.blocks(), 1);
}
