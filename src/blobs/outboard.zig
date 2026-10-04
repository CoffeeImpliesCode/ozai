//! The outboard of a blob: the hashes a verifier needs and the data does not
//! carry, laid out in either of the two orders bao-tree stores it in, plus the
//! geometry that decides which slot a hash belongs in.
//!
//! Upstream is `n0-computer/bao-tree` commit
//! `2be9abd144783455606424424c29bd3a57f926f8` (crate 0.16.1), the crate
//! `n0-computer/iroh-blobs` builds its blob answers with. Every rule below is a
//! port of a named function there, cited at the port, because the offsets are a
//! wire format: an outboard this build writes has to be one upstream reads.
//!
//! # What an outboard holds
//!
//! One *pair* per node: the hash of the node's left child, then the hash of its
//! right child, 32 bytes each. Combining the two is what produces the node's own
//! hash, so a verifier that has the data for one side needs only the pair of
//! the lowest node that has data on the other side, and repeats upwards. The
//! pairs are for every node from the block level up, minus the one node at the
//! end whose right child starts past the end of the blob — that node's right
//! child is empty and its hash comes from the empty input rather than from the
//! outboard. Upstream calls that rule `is_relevant_for_outboard`
//! (`src/lib.rs:544`), and the count that falls out of it is
//! `blocks - 1` (`outboard_hash_pairs`, `src/lib.rs:504`), so an outboard is
//! `64 * (blocks - 1)` bytes whatever the blob's size is.
//!
//! # Two orders, one set of bytes
//!
//! The same set of pairs can be written two ways. In **pre-order** the pairs
//! come root first, level by level, so a verifier seeking one node reads its
//! ancestors' slots from the front of the file. In **post-order** they come
//! left subtree, right subtree, node, so a verifier streaming the blob forward
//! reads each slot once, in order. Both orders hold the same pairs for the same
//! nodes and are the same length; only the slot of a node differs, which is
//! what `preOrderOffset` and `postOrderOffset` are for.
//!
//! # Framing: a little-endian u64 size
//!
//! An outboard on its own does not say what blob it belongs to, so upstream
//! frames it with the blob size as a little-endian `u64` — the `bao` crate
//! compatibility note at `src/lib.rs:238` is the statement of it, and the two
//! mem outboards put it at the two ends of the file:
//! `PostOrderMemOutboard::into_inner_with_suffix` (`src/io/outboard.rs:213`)
//! writes it after the pairs and `PreOrderMemOutboard::into_inner_with_prefix`
//! (`src/io/outboard.rs:360`) before them. The suffix is what this module
//! names: `sizeSuffixOffset` is the outboard size, so `framedSize` is the
//! length of the whole thing, and the prefix layout is the same bytes moved
//! down by `size_suffix_len`.
//!
//! # Nothing here reads, writes or hashes
//!
//! This module is arithmetic over a size and a block size: no allocator, no
//! globals, no I/O, no BLAKE3. It answers "how long is an outboard", "is this
//! node in it", "where does this node's pair go" and "what blob does this
//! suffix name", and every answer is a value rather than a side effect. The
//! hashing is `crypto/blake3_subtree.zig`, the walking and the proof encoding
//! is `blobs/proof.zig`, and the bytes are whatever storage the caller owns.

const std = @import("std");

/// The BLAKE3 chunk size in bytes. `protocol.zig`'s module comment carries the
/// derivation from bao-tree's `BLAKE3_CHUNK_SIZE`; the value is stated here
/// rather than imported so that the outboard geometry stands on its own.
pub const chunk_size: u64 = 1024;

/// The block size a tree is built with when a caller names none: sixteen
/// chunks to a block, which is `BlockSize::from_chunk_log(4)` upstream
/// (`src/tree.rs:159`) and the default iroh-blobs asks for.
pub const default_block_size: u64 = 16384;

/// The size of one BLAKE3 hash in bytes.
pub const hash_size: usize = 32;

/// One outboard slot: a node's left child hash followed by its right child
/// hash, in that order. A pair is the unit of storage because the unit of
/// verification is a parent, which is a combine of exactly two hashes.
pub const HashPair = [hash_size * 2]u8;

/// The width of the blob size an outboard is framed with, in bytes.
pub const size_suffix_len: usize = 8;

/// A node of the tree, named by its position in an in-order traversal.
///
/// Upstream's `TreeNode` newtype (`src/lib.rs:616`) is the same `u64` with the
/// same meaning, so the arithmetic below is a port of its methods rather than a
/// second convention: a node index computed here indexes the same tree there.
pub const Node = u64;

/// `HashPair.len` in the unit the geometry counts bytes in.
const pair_size: u64 = HashPair.len;

/// `HashPair.len` in the unit a buffer is sliced with.
const pair_len: usize = HashPair.len;

/// The block size a `Tree` could not be built with.
///
/// A block size is a power of two of at least one chunk, so a value that is
/// neither has no tree above it and is refused at construction rather than
/// turned into a division by zero later. Upstream checks the same two
/// conditions in `BlockSize::from_bytes` (`src/tree.rs:183`).
pub const InitError = error{InvalidBlockSize};

/// The ways a load or a save can refuse.
///
/// Both are refusals rather than repairs: a node with no slot is a node the
/// outboard does not hold, and a buffer that cannot hold a slot is a truncated
/// read. Upstream returns `io::ErrorKind::InvalidInput` for the first and
/// indexes the buffer for the second (`src/io/outboard.rs:275`); a truncation
/// that indexes instead is how an outboard file that is short reads as hashes.
pub const SlotError = error{IrrelevantNode, OutOfBounds};

/// The geometry of one blob's tree: how big the blob is and how big a block of
/// it is. Everything an outboard needs to know about a blob is in here, which
/// is why it is two integers and no state.
pub const Tree = struct {
    /// The blob's size in bytes. Any `u64`: a size off a peer's wire is not
    /// checked against anything here, it only decides the shape of the tree.
    size: u64,
    /// The block size in bytes: a power of two of at least `chunk_size`.
    block_size: u64,

    /// The tree for a blob of `size` bytes in `block_size` blocks. Use
    /// `Tree.init` rather than the literal, which is why this is the only
    /// checked way in: a block size that is not a power of two has no block
    /// boundary to divide at.
    pub fn init(size: u64, block_size: u64) InitError!Tree {
        if (block_size < chunk_size or (block_size & (block_size - 1)) != 0) {
            return error.InvalidBlockSize;
        }
        return .{ .size = size, .block_size = block_size };
    }

    /// The log2 of the chunks to a block, which is the level of the tree's
    /// leaves: level zero is a chunk, level `chunk_log` is a block.
    pub fn chunkLog(self: Tree) u32 {
        return @intCast(@ctz(self.block_size) - 10);
    }

    /// The chunks the blob occupies, with the last one short when the size is
    /// not a multiple of the chunk size. Zero for an empty blob, which is why
    /// `root` and the relevance rule below clamp it themselves.
    pub fn chunks(self: Tree) u64 {
        const whole = self.size / chunk_size;
        return whole + @intFromBool(self.size % chunk_size != 0);
    }

    /// The blocks the blob occupies. Upstream's `blocks` (`src/lib.rs:493`),
    /// including its clamp: an empty blob is one block, not zero, because the
    /// root hash of nothing is a hash and not an absence.
    pub fn blocks(self: Tree) u64 {
        const whole = self.size / self.block_size;
        return @max(whole + @intFromBool(self.size % self.block_size != 0), 1);
    }

    /// The pairs the outboard holds: `outboard_hash_pairs`
    /// (`src/lib.rs:504`). One fewer than the block count for every size,
    /// including zero.
    pub fn pairCount(self: Tree) u64 {
        return self.blocks() - 1;
    }

    /// The bytes the pairs occupy, without the size suffix:
    /// `BaoTree::outboard_size` (`src/lib.rs:512`). It is this number and not
    /// a walk of the tree, which is the point: an outboard is sized before it
    /// is written.
    pub fn outboardSize(self: Tree) u64 {
        return self.pairCount() * pair_size;
    }

    /// Where the size suffix sits in the framed outboard: one past the last
    /// pair, which is what upstream's post-order mem outboard appends
    /// (`src/io/outboard.rs:213`).
    pub fn sizeSuffixOffset(self: Tree) u64 {
        return self.outboardSize();
    }

    /// The length of a framed outboard, suffix included. The prefix layout of
    /// upstream's pre-order mem outboard is the same bytes, so its length is
    /// this one too.
    pub fn framedSize(self: Tree) u64 {
        return self.sizeSuffixOffset() + @as(u64, size_suffix_len);
    }

    /// The root of the tree, in chunk-level node numbering. Upstream's
    /// `BaoTree::root` (`src/lib.rs:479`), which clamps an empty blob to one
    /// chunk before rounding up to a power of two.
    pub fn root(self: Tree) Node {
        const count = @max(self.chunks(), 1);
        return nextPowerOfTwo((count + 1) / 2) - 1;
    }

    /// True when the outboard holds a pair for `node`:
    /// `is_relevant_for_outboard` (`src/lib.rs:544`).
    ///
    /// Below the block level the answer is false because the hash is computed
    /// from the data every time it is needed and storing it would be storing
    /// the data. Above it the answer is true. At exactly the block level it is
    /// true only when the node's right child starts inside the blob, which is
    /// what leaves the one half-empty node at the end of a blob that does not
    /// end on a block boundary out of the outboard.
    pub fn isRelevant(self: Tree, node: Node) bool {
        const level = nodeLevel(node);
        if (level < self.chunkLog()) return false;
        if (level > self.chunkLog()) return true;
        return midChunks(node) < self.chunks();
    }

    /// The slot `node`'s pair is in a pre-order outboard, or null when the
    /// outboard holds no pair for it. Upstream's `pre_order_offset`
    /// (`src/lib.rs:558`).
    pub fn preOrderOffset(self: Tree, node: Node) ?u64 {
        const shifted = shiftUp(node, self.chunkLog()) orelse return null;
        const filled = self.shiftedFilled();
        if (shifted >= filled) return null;
        if (isLeaf(shifted) and midChunks(node) >= self.chunks()) return null;
        return preOrderSlot(shifted, filled);
    }

    /// The slot `node`'s pair is in a post-order outboard, or null when the
    /// outboard holds no pair for it. Upstream's `post_order_offset`
    /// (`src/lib.rs:571`).
    ///
    /// A node whose nominal range reaches past the end of the blob is
    /// *unstable*: appending data to the blob moves it, so its slot is counted
    /// from the end of the outboard rather than from the start. A node that
    /// cannot, because it has no right child to skip, has no slot at all.
    pub fn postOrderOffset(self: Tree, node: Node) ?u64 {
        const shifted = shiftUp(node, self.chunkLog()) orelse return null;
        if (shifted >= self.shiftedFilled()) return null;
        if (midChunks(node) + (@as(u64, 1) << nodeLevel(node)) <= self.chunks()) {
            return treePostOrderSlot(shifted);
        }
        if (isLeaf(shifted) and midChunks(node) >= self.chunks()) return null;
        const from_end = @as(u64, @popCount(node + 1));
        if (from_end > self.pairCount()) return null;
        return self.pairCount() - from_end;
    }

    /// The pair a pre-order outboard holds for `node`: the mem outboard's
    /// `load` (`src/io/outboard.rs:439`), with the buffer indexing upstream
    /// does at `src/io/outboard.rs:513` made a refusal.
    pub fn loadPre(self: Tree, data: []const u8, node: Node) SlotError!HashPair {
        const slot = self.preOrderOffset(node) orelse return error.IrrelevantNode;
        const range = slotRange(data.len, slot) orelse return error.OutOfBounds;
        return data[range[0]..range[1]].*;
    }

    /// Store `pair` as the pre-order pair for `node`:
    /// `PreOrderMemOutboard`'s `save` (`src/io/outboard.rs:445`).
    pub fn savePre(self: Tree, data: []u8, node: Node, pair: *const HashPair) SlotError!void {
        const slot = self.preOrderOffset(node) orelse return error.IrrelevantNode;
        const range = slotRange(data.len, slot) orelse return error.OutOfBounds;
        @memcpy(data[range[0]..range[1]], pair[0..]);
    }

    /// The pair a post-order outboard holds for `node`:
    /// `PostOrderMemOutboard`'s `load` (`src/io/outboard.rs:256`).
    pub fn loadPost(self: Tree, data: []const u8, node: Node) SlotError!HashPair {
        const slot = self.postOrderOffset(node) orelse return error.IrrelevantNode;
        const range = slotRange(data.len, slot) orelse return error.OutOfBounds;
        return data[range[0]..range[1]].*;
    }

    /// Store `pair` as the post-order pair for `node`:
    /// `PostOrderMemOutboard`'s `save` (`src/io/outboard.rs:275`).
    pub fn savePost(self: Tree, data: []u8, node: Node, pair: *const HashPair) SlotError!void {
        const slot = self.postOrderOffset(node) orelse return error.IrrelevantNode;
        const range = slotRange(data.len, slot) orelse return error.OutOfBounds;
        @memcpy(data[range[0]..range[1]], pair[0..]);
    }

    /// The number of nodes in the tree that outboard offsets are counted in.
    ///
    /// Upstream's `shifted` (`src/lib.rs:384`): the tree as it is seen with
    /// the block size applied, whose leaves are the ones the outboard is built
    /// from. `filled` is the count of nodes, and it is the bound a shifted node
    /// index is checked against before its slot arithmetic runs, which is what
    /// keeps a node that is not in this tree from naming a slot in it.
    fn shiftedFilled(self: Tree) Node {
        const leaves = (self.blocks() + 1) / 2;
        return leaves + (leaves - 1);
    }
};

/// The level of a node: its trailing one bits, 0 for a leaf. Upstream
/// `TreeNode::level` (`src/lib.rs:707`), which is `self.0.trailing_ones()`.
/// A node of `u64.max` would carry 64 of them and no tree has one, so the count
/// is returned rather than the shift it would be used for.
pub fn nodeLevel(node: Node) u32 {
    const next = node +% 1;
    return if (next == 0) 64 else @ctz(next);
}

/// True when a node has no children in the tree it is counted in. Upstream
/// `TreeNode::is_leaf` (`src/lib.rs:683`): leaves are the even indices,
/// branches are the odd ones.
pub fn isLeaf(node: Node) bool {
    return (node & 1) == 0;
}

/// Write a blob's size as the little-endian `u64` that frames an outboard.
pub fn writeSizeSuffix(buf: *[size_suffix_len]u8, size: u64) void {
    std.mem.writeInt(u64, buf, size, .little);
}

/// Read the blob size out of the suffix that frames an outboard.
pub fn readSizeSuffix(buf: *const [size_suffix_len]u8) u64 {
    return std.mem.readInt(u64, buf, .little);
}

/// The tree an outboard's suffix names, at `block_size`.
///
/// The suffix is the whole of what an outboard says about its blob, so this is
/// the one way a tree is recovered from bytes rather than given: the pairs are
/// then placed by this geometry and nowhere else.
pub fn treeFromSizeSuffix(suffix: *const [size_suffix_len]u8, block_size: u64) InitError!Tree {
    return Tree.init(readSizeSuffix(suffix), block_size);
}

/// The chunk a node splits at, one past its index: `TreeNode::mid`
/// (`src/lib.rs:666`), which is in chunks rather than bytes so that the
/// comparisons below cannot overflow a byte range on a large node index.
fn midChunks(node: Node) u64 {
    return node + 1;
}

/// A chunk-level node as a node of the tree with the block size applied:
/// `TreeNode::add_block_size` (`src/lib.rs:702`), which is null for a node
/// smaller than a block, since such a node is not in the outboard's tree at
/// all.
fn shiftUp(node: Node, chunk_log: u32) ?Node {
    const mask = (@as(u64, 1) << chunk_log) - 1;
    if (node & mask != mask) return null;
    return node >> chunk_log;
}

/// The slot of a shifted node in a pre-order outboard, counting from the root.
/// `pre_order_offset_loop` (`src/lib.rs:861`), which walks up to count the
/// ancestors of the node that are inside the tree.
fn preOrderSlot(shifted: Node, filled: Node) u64 {
    const span = @as(u64, 1) << @intCast(nodeLevel(shifted));
    const left = shifted + 1 - span;
    var parent_count: u64 = 0;
    var offset = shifted;
    var current = span;
    while (true) {
        const pspan = current * 2;
        offset = if (offset & pspan == 0) offset + current else offset - current;
        if (offset < filled) parent_count += 1;
        if (pspan >= filled) break;
        current = pspan;
    }
    return left - @as(u64, @popCount(left)) + parent_count;
}

/// The slot of a shifted node in a post-order outboard, counting from the
/// leftmost leaf. `TreeNode::post_order_offset` (`src/lib.rs:821`): the slots
/// its own subtree takes, plus the slots before the next ancestor to its left.
fn treePostOrderSlot(node: Node) u64 {
    const below = countBelow(node);
    const ancestor = nextLeftAncestor(node) orelse return below;
    return below + ancestor + 1 - @as(u64, @popCount(ancestor + 1));
}

/// The nodes strictly below a node in its own subtree: `TreeNode::count_below`
/// (`src/lib.rs:759`).
fn countBelow(node: Node) u64 {
    const next = node + 1;
    return (next & (~next +% 1)) * 2 - 2;
}

/// The next ancestor of a node that lies to its left, if there is one:
/// `TreeNode::next_left_ancestor0` (`src/lib.rs:845`).
fn nextLeftAncestor(node: Node) ?Node {
    const next = node + 1;
    const without = next & (next -% 1);
    return if (without == 0) null else without - 1;
}

/// The smallest power of two that is not below `n`, with `n <= 1` giving one,
/// as `u64::next_power_of_two` does. The shift stays inside 63 because only a
/// block count reaches this, and a block count is a count of blocks.
fn nextPowerOfTwo(n: u64) u64 {
    if (n <= 1) return 1;
    return @as(u64, 1) << @intCast(64 - @clz(n - 1));
}

/// The bytes of `slot` in a buffer of `data_len` bytes, or null when the buffer
/// cannot hold them.
///
/// Every load and save goes through here, because an outboard file that is
/// shorter than its own geometry says is a truncated read and has to be one.
fn slotRange(data_len: usize, slot: u64) ?[2]usize {
    const start = slot * pair_size;
    if (start > @as(u64, data_len)) return null;
    const at: usize = @intCast(start);
    if (data_len - at < pair_len) return null;
    return .{ at, at + pair_len };
}

const testing = std.testing;

test "an outboard holds one pair per branch node, and an empty blob none" {
    // 4096 bytes of 1 KiB blocks is four blocks, so three pairs.
    const tree = try Tree.init(4096, chunk_size);
    try testing.expectEqual(@as(u64, 4), tree.blocks());
    try testing.expectEqual(@as(u64, 3), tree.pairCount());
    try testing.expectEqual(@as(u64, 3 * 64), tree.outboardSize());

    // An empty blob is one block and no pairs, so its outboard is the suffix.
    const empty = try Tree.init(0, chunk_size);
    try testing.expectEqual(@as(u64, 1), empty.blocks());
    try testing.expectEqual(@as(u64, 0), empty.outboardSize());
    try testing.expectEqual(@as(u64, 8), empty.framedSize());

    // A blob of exactly one block is the other end of the same rule: its block
    // hash is its root hash, so there is nothing left to store.
    const one_block = try Tree.init(default_block_size, default_block_size);
    try testing.expectEqual(@as(u64, 1), one_block.blocks());
    try testing.expectEqual(@as(u64, 0), one_block.pairCount());

    // A block size that is not a power of two has no boundary to divide at.
    try testing.expectError(error.InvalidBlockSize, Tree.init(1, 1500));
    try testing.expectError(error.InvalidBlockSize, Tree.init(1, 512));
}

test "the two orders hold the same pairs and put them in different slots" {
    const tree = try Tree.init(4096, chunk_size);
    // Pre-order is root 1, then left 0, then right 2; post-order is 0, 2, 1.
    try testing.expectEqual(@as(?u64, 0), tree.preOrderOffset(1));
    try testing.expectEqual(@as(?u64, 1), tree.preOrderOffset(0));
    try testing.expectEqual(@as(?u64, 2), tree.preOrderOffset(2));
    try testing.expectEqual(@as(?u64, 0), tree.postOrderOffset(0));
    try testing.expectEqual(@as(?u64, 1), tree.postOrderOffset(2));
    try testing.expectEqual(@as(?u64, 2), tree.postOrderOffset(1));

    // 65537 bytes of 16 KiB blocks is five blocks: four pairs, and the block
    // left over at the end has no right child to hold a hash for.
    const big = try Tree.init(65537, default_block_size);
    try testing.expectEqual(@as(u64, 5), big.blocks());
    try testing.expectEqual(@as(u64, 4), big.pairCount());
    try testing.expectEqual(@as(?u64, 0), big.preOrderOffset(63));
    try testing.expectEqual(@as(?u64, 1), big.preOrderOffset(31));
    try testing.expectEqual(@as(?u64, 2), big.preOrderOffset(15));
    try testing.expectEqual(@as(?u64, 3), big.preOrderOffset(47));
    try testing.expectEqual(@as(?u64, 0), big.postOrderOffset(15));
    try testing.expectEqual(@as(?u64, 1), big.postOrderOffset(47));
    try testing.expectEqual(@as(?u64, 2), big.postOrderOffset(31));
    try testing.expectEqual(@as(?u64, 3), big.postOrderOffset(63));
    try testing.expect(!big.isRelevant(79));
    try testing.expectEqual(@as(?u64, null), big.preOrderOffset(79));
    try testing.expectEqual(@as(?u64, null), big.postOrderOffset(79));

    // A node below the block level is computed from the data every time, so it
    // is not in the outboard at all.
    try testing.expect(!big.isRelevant(7));
    try testing.expectEqual(@as(?u64, null), big.preOrderOffset(7));

    // 3072 bytes of 1 KiB blocks is three blocks and two pairs: the third
    // block is the short one and node 2 is where its hash would have gone.
    const three = try Tree.init(3072, chunk_size);
    try testing.expectEqual(@as(u64, 2), three.pairCount());
    try testing.expect(!three.isRelevant(2));
    try testing.expectEqual(@as(?u64, null), three.preOrderOffset(2));
    try testing.expectEqual(@as(?u64, 1), three.preOrderOffset(0));
}

test "load and save agree on a node's slot and refuse the ones that have none" {
    const tree = try Tree.init(4096, chunk_size);
    var data: [3 * 64]u8 = [_]u8{0} ** (3 * 64);
    const pair: HashPair = @splat(0xab);

    try tree.savePre(&data, 2, &pair);
    try testing.expectEqualSlices(u8, &pair, &data[128..192]);
    const first = try tree.loadPre(&data, 2);
    try testing.expectEqualSlices(u8, &pair, &first);

    // The post-order slot of the same node is a different place in the same
    // bytes, which is the whole difference between the two orders.
    try tree.savePost(&data, 2, &pair);
    try testing.expectEqualSlices(u8, &pair, &data[64..128]);
    const second = try tree.loadPost(&data, 2);
    try testing.expectEqualSlices(u8, &pair, &second);

    // A node that is not in this tree has no slot to read or write.
    try testing.expectError(error.IrrelevantNode, tree.savePre(&data, 9, &pair));
    try testing.expectError(error.IrrelevantNode, tree.loadPost(&data, 9));

    // A buffer too short for the slot is a truncated outboard, not an overread.
    var short: [64]u8 = [_]u8{0} ** 64;
    try testing.expectError(error.OutOfBounds, tree.loadPre(&short, 2));
    try testing.expectError(error.OutOfBounds, tree.savePost(&short, 2, &pair));
}

test "the size suffix names the blob, little endian, and it is the framing" {
    var suffix: [size_suffix_len]u8 = undefined;
    writeSizeSuffix(&suffix, 0x0102030405060708);
    try testing.expectEqualSlices(u8, &[_]u8{ 8, 7, 6, 5, 4, 3, 2, 1 }, &suffix);
    try testing.expectEqual(@as(u64, 0x0102030405060708), readSizeSuffix(&suffix));

    const tree = try treeFromSizeSuffix(&suffix, default_block_size);
    try testing.expectEqual(@as(u64, 0x0102030405060708), tree.size);
    try testing.expectEqual(tree.outboardSize() + @as(u64, size_suffix_len), tree.framedSize());
    try testing.expectEqual(tree.outboardSize(), tree.sizeSuffixOffset());
}