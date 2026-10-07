//! The bytes of a proof: the plan of `bao_plan.zig`, walked over a blob.
//!
//! This is the answering half. It reads the whole blob — including the groups
//! the request did not name, because a parent pair states what those are worth
//! — and writes the plan's items into a destination the caller sized from the
//! plan. It is pure over `(plan, tree, data, out)`: no socket, no clock, no
//! allocator, and no hidden state.
//!
//! Two things are written in an order that needs saying. A pair is written
//! *before* the children's bytes but its two values are only known *after* they
//! have been walked, so the writer reserves the 64 bytes, walks the children,
//! and fills the reservation in. A node the request takes whole is written as
//! its own bytes and not as a pair, because its value is then computed by
//! hashing exactly the bytes the verifier will hash.
//!
//! Nothing here verifies anything. An encoder handed a blob that does not fill
//! the claimed size is refused, and one handed a plan that does not describe
//! the walk is refused, but neither is a check on the *proof*: the only thing
//! that settles whether these bytes prove this blob is the walk in
//! `bao_proof_verify.zig` against a root the caller already trusted.

const std = @import("std");

const core = @import("../crypto/blake3_core.zig");
const subtree = @import("../crypto/blake3_subtree.zig");
const tree_mod = @import("bao_tree.zig");
const plan_mod = @import("bao_plan.zig");
const outboard_mod = @import("bao_outboard.zig");

pub const BaoTree = tree_mod.BaoTree;
pub const Node = tree_mod.Node;
pub const Plan = plan_mod.Plan;
pub const pair_length = tree_mod.pair_length;

/// Everything that can stop a proof being written.
pub const Error = tree_mod.HashError || error{
    /// The destination is shorter than the plan says the proof is. A short
    /// destination is an error and not a truncation, for the reason
    /// `bao_outboard.zig` gives.
    BufferTooSmall,
    /// The plan does not describe the walk the tree takes. This is the guard
    /// that keeps a hand-built plan from being encoded into bytes no verifier
    /// would accept: every item must name the node the walk is on, and the
    /// walk must consume the whole plan and write exactly its length.
    PlanMismatch,
};

/// Write the proof `plan` describes for `data` into `out`, returning its
/// length.
///
/// `data` must be the blob the tree was cut for and `out` must be at least
/// `plan.bytes` long. Both are checked rather than assumed.
pub fn encode(plan: Plan, tree: BaoTree, data: []const u8, out: []u8) Error!usize {
    if (plan.isEmpty()) return 0;
    var writer: Writer = .{ .tree = tree, .data = data, .out = out, .plan = plan };
    _ = try writer.walk(tree.root(), true);
    if (writer.next != plan.len or writer.len != plan.bytes) return error.PlanMismatch;
    return writer.len;
}

const Writer = struct {
    tree: BaoTree,
    data: []const u8,
    out: []u8,
    plan: Plan,
    /// How many plan items have been consumed.
    next: usize = 0,
    /// How many bytes have been written.
    len: usize = 0,

    /// The item the plan holds for the node the walk is on. The plan is the
    /// only thing that says which node each item is about, so an item naming a
    /// different node is a plan that does not describe this walk. A pair at a
    /// node of one chunk is refused for the same reason: there is nothing
    /// below a leaf to pair, and splitting one would be reading past it.
    fn expect(self: *const Writer, node: Node) Error!plan_mod.Item {
        if (self.next >= self.plan.len) return error.PlanMismatch;
        const held = self.plan.items[self.next];
        if (!held.node().eql(node)) return error.PlanMismatch;
        if (held == .pair and node.span < 2) return error.PlanMismatch;
        return held;
    }

    fn reserve(self: *Writer, count: usize) Error!usize {
        if (count > self.out.len -| self.len) return error.BufferTooSmall;
        const at = self.len;
        self.len += count;
        return at;
    }

    /// The value of `node`: the root's own hash with ROOT set, and every other
    /// node's chaining value with ROOT clear. That distinction is the whole
    /// difference between a blob's root and the value its parent would
    /// compress, and getting it backwards fails at the root of every proof.
    fn hash(self: *const Writer, node: Node, is_root: bool) Error!core.CvBytes {
        return if (is_root)
            self.tree.rootHash(self.data)
        else
            self.tree.nodeCv(node, self.data);
    }

    fn walk(self: *Writer, node: Node, is_root: bool) Error!core.CvBytes {
        const item = try self.expect(node);
        self.next += 1;
        switch (item) {
            .pair => {
                const at = try self.reserve(pair_length);
                const children = node.children();
                const left = try self.walk(children.left, false);
                const right = try self.walk(children.right, false);
                tree_mod.writePair(
                    self.out[at..][0..pair_length],
                    .{ .left = left, .right = right },
                );
                return if (is_root)
                    subtree.mergeRoot(left, right)
                else
                    subtree.merge(left, right);
            },
            .skip => return self.hash(node, is_root),
            .data => |covered| {
                // Hash first: that is what checks the blob against the claimed
                // size, and the copy below indexes the same range.
                const cv = try self.hash(covered, is_root);
                const range = covered.bytes(self.tree);
                const count: usize = @intCast(range.end - range.start);
                const at = try self.reserve(count);
                @memcpy(
                    self.out[at..][0..count],
                    self.data[@intCast(range.start)..@intCast(range.end)],
                );
                return cv;
            },
        }
    }
};

const t = std.testing;
const ranges = @import("ranges.zig");
const published = @import("../gossip/plumtree/blake3_vectors.zig");

const block_size: usize = @intCast(tree_mod.block_size);

// A whole-blob proof is the blob. Nothing else is written, so the proof of the
// whole blob and the blob itself are the same bytes, and there is no pair in it
// to check: every byte is bound by the one root hash at the end.
test "a whole-blob proof is the blob" {
    const data = try published.blake3Input(49153);
    defer t.allocator.free(data);

    const tree = BaoTree.init(data.len);
    const plan = plan_mod.planOf(tree, .{ .start = 0, .end = tree.chunks() });

    var out: [49153]u8 = @splat(0);
    const written = try encode(plan, tree, data, &out);
    try t.expectEqual(data.len, written);
    try t.expectEqualSlices(u8, data, out[0..written]);
}

// The pairs a proof carries are the outboard's own bytes, and the data follows
// them. Chunks 32 to 48 of a 49153-byte blob is group 2 whole, and the walk to
// it passes the root and the pair over groups 2 and 3: two pairs, which are
// the outboard's pairs number 0 and number 2.
//
// Not the outboard's first two. The proof skips the parent over groups 0 and 1
// without naming it, so its second pair is the outboard's *third*. A proof is
// the outboard's pairs in the outboard's order with gaps left for the
// subtrees the request never reaches, and this checks that byte for byte
// rather than by position: each pair is compared against the outboard's own
// 64 bytes at the offset the outboard stores that node's pair.
test "the pairs of a group-aligned proof are the outboard's own bytes" {
    const data = try published.blake3Input(49153);
    defer t.allocator.free(data);

    const tree = BaoTree.init(data.len);
    var outboard: [3 * pair_length]u8 = @splat(0);
    const outboard_len = try outboard_mod.encode(tree, data, &outboard);

    const request = ranges.ChunkRange{ .start = 32, .end = 48 };
    const plan = plan_mod.planOf(tree, request);
    var proof: [3 * pair_length + block_size]u8 = @splat(0);
    const written = try encode(plan, tree, data, &proof);

    var pairs: usize = 0;
    var at: usize = 0;
    var last: ?usize = null;
    for (plan.items[0..plan.len]) |item| {
        if (item != .pair) continue;
        const index = outboard_mod.pairIndex(tree, item.pair) orelse
            return error.TestUnexpectedResult;
        try t.expect(last == null or index > last.?);
        last = index;
        try t.expectEqualSlices(
            u8,
            outboard[index * pair_length ..][0..pair_length],
            proof[at..][0..pair_length],
        );
        pairs += 1;
        at += pair_length;
    }
    try t.expectEqual(@as(usize, 2), pairs);
    try t.expectEqual(@as(usize, 2), last.?);
    try t.expect(pairs * pair_length < outboard_len);
    try t.expectEqual(written, pairs * pair_length + block_size);
    try t.expectEqualSlices(
        u8,
        data[32 * 1024 .. 48 * 1024],
        proof[at..written],
    );
}

// A pair's two halves are the two children's own values and not the node's
// value and not the children's root hashes. A writer that put the node's own
// value on both sides would still write 64 bytes and would fail at the first
// parent above it.
test "a written pair holds the two children's values, not the parent's" {
    const data = try published.blake3Input(49153);
    defer t.allocator.free(data);

    const tree = BaoTree.init(data.len);
    const children = tree.root().children();
    const plan = plan_mod.planOf(tree, .{ .start = 0, .end = 16 });

    var proof: [3 * pair_length + block_size]u8 = @splat(0);
    const written = try encode(plan, tree, data, &proof);
    const pair = tree_mod.readPair(proof[0..][0..pair_length]);

    const left = try tree.nodeCv(children.left, data);
    const right = try tree.nodeCv(children.right, data);
    try t.expectEqual(left, pair.left);
    try t.expectEqual(right, pair.right);
    try t.expect(!std.meta.eql(left, right));
    try t.expect(!std.meta.eql(subtree.merge(left, right), pair.left));
    try t.expect(written > pair_length);
}

// Only the root carries ROOT, and a one-group blob is the sharp case: its root
// is also a chunk group, so a walk that keyed "root" off the tree's shape
// would set the flag twice or not at all. The merge of the written pair is the
// blob's own root hash.
test "one blob of one group is answered with the blob's own root hash" {
    const data = try published.blake3Input(16384);
    defer t.allocator.free(data);

    const tree = BaoTree.init(data.len);
    const plan = plan_mod.planOf(tree, .{ .start = 4, .end = 9 });

    var proof: [16 * pair_length + 8 * core.chunk_length]u8 = @splat(0);
    const written = try encode(plan, tree, data, &proof);
    const children = tree.root().children();
    const pair = tree_mod.readPair(proof[0..][0..pair_length]);

    try t.expectEqual(try tree.nodeCv(children.left, data), pair.left);
    try t.expectEqual(try tree.nodeCv(children.right, data), pair.right);
    try t.expectEqual(
        subtree.mergeRoot(pair.left, pair.right),
        try tree.rootHash(data),
    );
    try t.expect(written > pair_length);
}

// A destination one byte short is refused rather than truncated, and a blob
// that is not the tree's declared size is refused before anything is written.
test "a short destination or the wrong blob is refused" {
    const data = try published.blake3Input(49153);
    defer t.allocator.free(data);

    const tree = BaoTree.init(data.len);
    const plan = plan_mod.planOf(tree, .{ .start = 0, .end = 16 });

    var out: [3 * pair_length + block_size]u8 = @splat(0);
    try t.expectError(error.BufferTooSmall, encode(plan, tree, data, out[0 .. plan.bytes - 1]));
    try t.expectError(error.BufferTooSmall, encode(plan, tree, data, out[0..0]));
    try t.expectError(error.SizeMismatch, encode(plan, tree, data[0..1024], &out));
}

// A plan that does not describe the tree's walk is refused, not encoded. Each
// mutation below breaks one of the three ways a plan can disagree — the node
// an item names, the number of items the walk consumes, and the length the
// plan promised — and all three would otherwise be written as bytes no
// verifier would accept.
test "a plan that does not match the walk is refused" {
    const data = try published.blake3Input(49153);
    defer t.allocator.free(data);

    const tree = BaoTree.init(data.len);
    var out: [3 * pair_length + block_size]u8 = @splat(0);
    const real = plan_mod.planOf(tree, .{ .start = 0, .end = 16 });

    // The first item names a node the walk is not on.
    var node_mismatch = real;
    node_mismatch.items[0] = .{ .pair = tree.root().children().right };
    try t.expectError(error.PlanMismatch, encode(node_mismatch, tree, data, &out));

    // The plan promises more items than the walk consumes.
    var long = real;
    long.len += 1;
    long.bytes += pair_length;
    try t.expectError(error.PlanMismatch, encode(long, tree, data, &out));

    // The plan promises more bytes than the walk writes.
    var count_mismatch = real;
    count_mismatch.bytes += 1;
    try t.expectError(error.PlanMismatch, encode(count_mismatch, tree, data, &out));

    // A plan that runs out before the walk does.
    var short = real;
    short.len = 0;
    short.bytes = 0;
    try t.expectEqual(@as(usize, 0), try encode(short, tree, data, &out));

    // A pair at a node of one chunk, on the one blob whose root is a single
    // chunk: there is nothing below a leaf to pair, and splitting one would
    // read past it.
    const one = try published.blake3Input(1);
    defer t.allocator.free(one);
    var leaf: plan_mod.Plan = .{};
    leaf.items[0] = .{ .pair = BaoTree.init(1).root() };
    leaf.len = 1;
    leaf.bytes = pair_length;
    var small: [pair_length]u8 = @splat(0);
    try t.expectError(error.PlanMismatch, encode(leaf, BaoTree.init(1), one, &small));
}
