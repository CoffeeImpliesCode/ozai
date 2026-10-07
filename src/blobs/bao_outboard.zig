//! The outboard: the `(blocks - 1) * 64` bytes that sit beside a blob and
//! stand for every parent in its tree.
//!
//! An outboard holds one 64-byte parent pair per parent the tree has, and a
//! tree with `n` leaves has `n - 1` parents however unevenly it splits, so the
//! length follows from the blob's length and nothing else is in it. The pairs
//! come out in preorder — a node's pair, then its left child's, then its
//! right's — because that is the order a range proof consumes them in and
//! because a tree that stored them in any other order would need an index to
//! find them again.
//!
//! A parent below the chunk-group line is not stored. A group is a leaf, and a
//! group is the smallest thing a range request is ever answered in, so the
//! whole of the group-level structure is exactly the pairs a group-aligned
//! proof walks past before it reaches data. That claim is byte-checked, not
//! argued, in `bao_proof_encode.zig`: for a request that lands on group lines
//! every pair the proof carries is the outboard's own 64 bytes, at the
//! outboard's own offset for that node. It is *not* a prefix, and the tests
//! say so: a proof walks only the parents its range touches, so it skips
//! whole subtrees the outboard still stores, and the pairs it carries are a
//! run of the outboard's pairs in the outboard's own order with gaps between
//! them.
//!
//! # What is pinned, and what is not
//!
//! Pinned: the length, through the four hand-computed sizes below and the count
//! of parents the writer walks. The preorder, through `pairIndex` and the
//! order check below — a proof walks a parent before its children, and it can
//! only find a node's pair in the outboard at all if the outboard is in the
//! same order. The pair layout, through `crypto/blake3_nodes.zig`, which
//! compresses the same two words in the same order.
//!
//! Not pinned: that this is the *whole* of an upstream outboard, or that a
//! peer's pairs mean what these do. `oracle_test.zig` checks this representation
//! against actual pinned upstream Store exports, loaded from capture files.

const std = @import("std");

const tree_mod = @import("bao_tree.zig");

pub const BaoTree = tree_mod.BaoTree;
pub const Node = tree_mod.Node;
pub const HashError = tree_mod.HashError;
pub const pair_length = tree_mod.pair_length;

/// Everything that can stop an outboard being written.
pub const Error = HashError || error{
    /// The destination is shorter than `(blocks - 1) * 64` bytes. A short
    /// destination is an error and not a truncation: every pair here is named
    /// by a claimed size, and an outboard that stops half a pair in is not one.
    BufferTooSmall,
};

/// How many bytes an outboard for this tree is.
pub fn bytes(tree: BaoTree) u64 {
    return tree.rootBlockBytes();
}

/// The outboard for `tree`, written into `out`, returning its length.
///
/// `data` must be the blob the tree was cut for. A blob of another length is
/// refused rather than read at the edges, because every pair here is computed
/// over bytes a claimed size named.
pub fn encode(tree: BaoTree, data: []const u8, out: []u8) Error!usize {
    var writer: Writer = .{ .tree = tree, .data = data, .out = out };
    try writer.walk(tree.root());
    return writer.len;
}

const Writer = struct {
    tree: BaoTree,
    data: []const u8,
    out: []u8,
    len: usize = 0,

    /// Only the parents above the group line are stored, so the walk stops as
    /// soon as it is inside one: the children of a group are sub-block pairs,
    /// and no outboard holds those.
    fn walk(self: *Writer, node: Node) Error!void {
        if (!node.isOutboardParent()) return;
        const children = node.children();
        const pair: tree_mod.Pair = .{
            .left = try self.tree.nodeCv(children.left, self.data),
            .right = try self.tree.nodeCv(children.right, self.data),
        };
        const at = try self.reserve();
        tree_mod.writePair(self.out[at..][0..pair_length], pair);
        try self.walk(children.left);
        try self.walk(children.right);
    }

    fn reserve(self: *Writer) Error!usize {
        if (pair_length > self.out.len -| self.len) return error.BufferTooSmall;
        const at = self.len;
        self.len += pair_length;
        return at;
    }
};

/// The index of `node`'s pair in this tree's outboard, or null when `node` is
/// not one of the parents an outboard stores.
///
/// The pairs are written in preorder and the outboard holds every one of them,
/// so this is where a reader looks a node up rather than counting its way down
/// the tree. It is the same walk `encode` takes, and that is what makes "the
/// pairs a proof carries are the outboard's own bytes" a statement about
/// bytes at a named offset rather than an argument about two walks.
pub fn pairIndex(tree: BaoTree, node: Node) ?usize {
    if (!node.isOutboardParent()) return null;
    var at = tree.root();
    var index: u64 = 0;
    for (0..64) |_| {
        if (!at.isOutboardParent()) return null;
        if (at.eql(node)) return @intCast(index);
        const children = at.children();
        if (node.start_chunk >= children.left.start_chunk and
            node.endChunk() <= children.left.endChunk())
        {
            at = children.left;
            index += 1;
        } else if (node.start_chunk >= children.right.start_chunk and
            node.endChunk() <= children.right.endChunk())
        {
            // Every left group contributes one leaf; leaves minus one parents
            // occupy the skipped preorder subtree.
            const left_parents = (children.left.span - 1) / tree_mod.chunks_per_block;
            index += 1 + left_parents;
            at = children.right;
        } else {
            return null;
        }
    }
    return null;
}

const t = std.testing;
const ranges = @import("ranges.zig");
const plan_mod = @import("bao_plan.zig");
const published = @import("../gossip/plumtree/blake3_vectors.zig");

// The four sizes from the brief, through the writer rather than through the
// arithmetic. 16383 and 16384 write nothing at all; 32768 writes one pair;
// 49153 writes three, because 49 chunks is four groups and four groups have
// three parents.
test "the outboard is blocks minus one pairs at four hand-computed sizes" {
    const cases = [_]struct { size: u64, pairs: usize }{
        .{ .size = 16383, .pairs = 0 },
        .{ .size = 16384, .pairs = 0 },
        .{ .size = 32768, .pairs = 1 },
        .{ .size = 49153, .pairs = 3 },
    };
    for (cases) |case| {
        const data = try published.blake3Input(@intCast(case.size));
        defer t.allocator.free(data);

        const tree = BaoTree.init(data.len);
        var out: [4 * pair_length]u8 = @splat(0);
        const written = try encode(tree, data, &out);
        try t.expectEqual(case.pairs * pair_length, written);
        try t.expectEqual(bytes(tree), @as(u64, written));
    }
}

// Preorder, not any other order: the root's pair comes first, then the whole
// of its left subtree, then the right's. 49153 bytes is 49 chunks, which
// split 32 + 17, so the three parents are the root itself and its two
// children, and nothing below either of them spans more than one group. The
// second and third pairs are those two children, in that order. Swapping them,
// or writing the root last, would leave an outboard that is self-consistent
// and unreadable by the walk that has to consume it in order.
test "the pairs come out in preorder" {
    const data = try published.blake3Input(49153);
    defer t.allocator.free(data);

    const tree = BaoTree.init(data.len);
    var out: [3 * pair_length]u8 = @splat(0);
    try t.expectEqual(@as(usize, 3 * pair_length), try encode(tree, data, &out));

    const children = tree.root().children();
    const wanted = [_]tree_mod.Node{ tree.root(), children.left, children.right };
    for (wanted, 0..) |node, index| {
        try t.expectEqual(index, pairIndex(tree, node).?);
        const grand = node.children();
        try t.expectEqual(
            tree_mod.Pair{
                .left = try tree.nodeCv(grand.left, data),
                .right = try tree.nodeCv(grand.right, data),
            },
            tree_mod.readPair(out[index * pair_length ..][0..pair_length]),
        );
    }
    try t.expectEqual(@as(?usize, null), pairIndex(tree, children.left.children().left));
}

// The claim the pair order rests on, taken at the level of plans: for a
// request that lands on group lines, every data item begins on a group
// boundary and covers whole groups, and there are no pairs below the group
// line, so every pair the proof carries is a pair the outboard stores — and
// the outboard's own order, so the indices a plan's pairs sit at go up and
// never back down. `bao_proof_encode.zig` checks the matching bytes.
test "a group-aligned proof's pairs are pairs the outboard stores, in order" {
    const data = try published.blake3Input(49153);
    defer t.allocator.free(data);

    const tree = BaoTree.init(data.len);
    var outboard: [3 * pair_length]u8 = @splat(0);
    const outboard_len = try encode(tree, data, &outboard);

    const requests = [_]ranges.ChunkRange{
        .{ .start = 0, .end = 16 },
        .{ .start = 16, .end = 32 },
        .{ .start = 32, .end = 48 },
        .{ .start = 48, .end = 49 },
        .{ .start = 0, .end = 49 },
    };
    for (requests) |request| {
        const plan = plan_mod.planOf(tree, request);
        var pair_bytes: usize = 0;
        var last: ?usize = null;
        for (plan.items[0..plan.len]) |item| {
            switch (item) {
                .pair => |node| {
                    pair_bytes += pair_length;
                    const index = pairIndex(tree, node) orelse return error.TestUnexpectedResult;
                    try t.expect(last == null or index > last.?);
                    last = index;
                },
                .skip => continue,
                .data => |node| {
                    const whole = node.span % tree_mod.chunks_per_block == 0;
                    try t.expectEqual(@as(u64, 0), node.start_chunk % tree_mod.chunks_per_block);
                    try t.expect(node.endChunk() == tree.chunks() or whole);
                },
            }
        }
        try t.expect(pair_bytes <= outboard_len);
    }
}

// A blob of one group has no parent at all, so its outboard is empty and
// writing it needs no destination at all. The 16384 case is the boundary: one
// byte more and there is a parent, so a single 64-byte pair.
test "a blob of one group has an empty outboard" {
    const data = try published.blake3Input(16385);
    defer t.allocator.free(data);

    const one = BaoTree.init(16384);
    try t.expectEqual(@as(u64, 0), bytes(one));
    var out: [pair_length]u8 = @splat(0);
    try t.expectEqual(@as(usize, 0), try encode(one, data[0..16384], out[0..0]));
    try t.expect(one.rootIsLeaf());

    const two = BaoTree.init(16385);
    try t.expectEqual(@as(u64, pair_length), bytes(two));
    try t.expectEqual(pair_length, try encode(two, data, &out));
}

// A destination one byte short is an error and not a short outboard, and a
// blob that is not the tree's declared size is refused before anything is
// written.
test "a destination shorter than the outboard is refused" {
    const data = try published.blake3Input(49153);
    defer t.allocator.free(data);

    const tree = BaoTree.init(data.len);
    var out: [3 * pair_length]u8 = @splat(0);
    try t.expectError(error.BufferTooSmall, encode(tree, data, out[0 .. 3 * pair_length - 1]));
    try t.expectError(error.BufferTooSmall, encode(tree, data, out[0..0]));
    try t.expectError(error.SizeMismatch, encode(tree, data[0..1024], &out));
}
