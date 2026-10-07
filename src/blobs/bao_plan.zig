//! What a proof for one requested range has to carry, and in what order.
//!
//! The plan is a function of the tree and the request and of nothing else. It
//! is never a function of the bytes that arrive, and that is the whole
//! fail-closed property of this layer: what the verifier will expect is fixed
//! before the first byte is read, so a peer cannot choose the shape of the
//! walk by sending something different. A verifier that derived its plan from
//! the response would be checking the response against itself.
//!
//! # The shape of the walk
//!
//! One rule, applied at every level of the tree:
//!
//! - a wholly selected node below the persisted group line carries its data;
//! - every touched persisted parent carries its pair, even for a whole blob;
//! - a partially selected group descends to the requested chunks;
//! - a child the request does not touch is a **skip**: no bytes at all. Its
//!   value comes from the pair above it, and the item exists only so the walk's
//!   shape is written down in one place instead of in a reader's head.
//!
//! The three kinds do not stop at the group line. A request that takes part of
//! a chunk group descends inside it and emits that group's sub-block pairs, and
//! a request that takes several whole groups still answers each with its bytes.
//! The outboard below the group line is the *whole* of the group-level pairs,
//! and a proof for a group-aligned request carries a run of them: the pairs of
//! the parents its range touches, at the outboard's own offsets, in the
//! outboard's own order. It is not a prefix, because the proof skips whole
//! subtrees the outboard still stores.
//!
//! # The size is never checked here
//!
//! Nothing below compares a declared size against a header or against the
//! length of the bytes it was handed, and nothing below could. A size is a
//! claim about bytes, and the only thing that settles it is the path from those
//! bytes to a root the caller already held out of band — `bao_proof_verify.zig`
//! and no other file. A plan for a size the bytes do not fill is a perfectly
//! ordinary plan; it just will not verify.

const std = @import("std");

const core = @import("../crypto/blake3_core.zig");
const ranges = @import("ranges.zig");
const range_spec = @import("range_spec.zig");
const tree_mod = @import("bao_tree.zig");

pub const BaoTree = tree_mod.BaoTree;
pub const Node = tree_mod.Node;
pub const pair_length = tree_mod.pair_length;

/// One thing in a proof, and the node it is about.
pub const Item = union(enum) {
    /// A parent pair: `pair_length` bytes, the left chaining value and then
    /// the right. The pair is about `node`; which node is in the plan and
    /// never in the bytes.
    pair: Node,
    /// A child with nothing beside it: no bytes. The verifier takes this
    /// child's value from the pair above it and has nothing to compare it
    /// against here.
    skip: Node,
    /// The bytes of `node`, hashed by the verifier as one BLAKE3 subtree from
    /// the node's first chunk.
    data: Node,

    /// The node this item is about. An encoder compares it against the node
    /// its own walk is on, which is how a plan that does not describe the
    /// walk is caught rather than encoded.
    pub fn node(self: Item) Node {
        return switch (self) {
            .pair => |held| held,
            .skip => |held| held,
            .data => |held| held,
        };
    }
};

/// Caller-bounded storage for a proof walk. A whole-blob proof includes every
/// group parent, so unlike a boundary-only walk it can exceed this capacity.
/// Such plans fail closed with `overflow`, never truncate a successful proof.
pub const max_items = 4 * (core.max_depth + 1);

/// A walk over the tree, written down before any byte is read.
pub const Plan = struct {
    items: [max_items]Item = undefined,
    len: usize = 0,
    /// How many bytes the whole proof is. The destination must be at least
    /// this long, and a proof that ends anywhere else is not this proof.
    bytes: usize = 0,
    overflow: bool = false,

    pub fn isEmpty(self: *const Plan) bool {
        return self.len == 0;
    }

    /// How many bytes `index`'s item carries: the pair's 64, nothing for a
    /// skip, and the node's own range for data.
    pub fn itemBytes(self: *const Plan, tree: BaoTree, index: usize) usize {
        return switch (self.items[index]) {
            .pair => pair_length,
            .skip => 0,
            .data => |node| blk: {
                const range = node.bytes(tree);
                break :blk @as(usize, @intCast(range.end - range.start));
            },
        };
    }
};

/// The walk a proof for `request` takes.
///
/// The request is clipped to the blob first — see `clip` — and the walk is over
/// the clipped range, so an encoder and a verifier given the same request walk
/// the same path even where the request asked for more than the blob holds.
pub fn planOf(tree: BaoTree, request: ranges.ChunkRange) Plan {
    var builder: Builder = .{ .sel = clip(tree, request) };
    const root = tree.root();
    if (root.intersects(builder.sel)) builder.walk(tree, root);
    return builder.plan;
}

/// The request as the range layer reads it against this blob: a span running
/// past the blob's last chunk is cut at it, and a span that selects nothing
/// selects nothing.
///
/// The rule is `range_spec.zig`'s and not a copy of it. A request is spelled as
/// the spec it is — one deselected gap, then one selection — and read with
/// `resolve` against the blob's chunk count, which is the only way any request
/// in this protocol is ever read against a blob. `RangeSpec.verified_size` is a
/// one-width spec read the same way, so the same call answers it.
///
/// One rule comes along with it and is not this file's to change: a span that
/// starts *at or past* the blob's last chunk is answered with the last chunk.
/// That is what makes `verified_size` — one round for a blob's size and a proof
/// of it — mean what its name says. It is also the one place where a request
/// is answered with something other than what it named, so `clip` *returns*
/// what it will cover rather than applying it, and both sides of a proof plan
/// from the returned value.
pub fn clip(tree: BaoTree, request: ranges.ChunkRange) ranges.ChunkRange {
    const widths = [2]u64{ request.start, request.len() };
    var walk = (range_spec.RangeSpec{ .widths = &widths }).resolve(tree.chunks());
    const span = walk.next() orelse return .{ .start = request.start, .end = request.start };
    return .{ .start = span.offset, .end = span.offset + span.size };
}

const Builder = struct {
    plan: Plan = .{},
    /// The request as it will be answered: the clip above, not the request.
    sel: ranges.ChunkRange,

    fn push(self: *Builder, tree: BaoTree, item: Item) void {
        if (self.plan.len == self.plan.items.len) {
            self.plan.overflow = true;
            return;
        }
        self.plan.items[self.plan.len] = item;
        self.plan.len += 1;
        self.plan.bytes += switch (item) {
            .pair => pair_length,
            .skip => 0,
            .data => |node| blk: {
                const range = node.bytes(tree);
                break :blk @as(usize, @intCast(range.end - range.start));
            },
        };
    }

    /// The node is touched by the request and not taken whole: it is a parent
    /// and the walk goes on below it. A node that intersects and is not taken
    /// whole spans at least two chunks, because the request is counted in
    /// chunks, so it always has children to walk into.
    fn walk(self: *Builder, tree: BaoTree, node: Node) void {
        if (self.plan.overflow) return;
        if (node.span <= tree_mod.chunks_per_block and node.covers(self.sel)) {
            self.push(tree, .{ .data = node });
            return;
        }
        const children = node.children();
        self.push(tree, .{ .pair = node });
        self.descend(tree, children.left);
        self.descend(tree, children.right);
    }

    fn descend(self: *Builder, tree: BaoTree, node: Node) void {
        if (node.intersects(self.sel)) {
            self.walk(tree, node);
        } else {
            self.push(tree, .{ .skip = node });
        }
    }
};

const t = std.testing;
const published = @import("../gossip/plumtree/blake3_vectors.zig");

// Upstream always emits persisted parents, including a whole-blob request.
test "whole multigroup proofs retain every persisted parent" {
    const tree = BaoTree.init(49189);
    const plan = planOf(tree, .{ .start = 0, .end = tree.chunks() });
    try t.expectEqual(@as(usize, 7), plan.len);
    try t.expect(plan.items[0] == .pair);
    try t.expectEqual(@as(usize, 49189 + 3 * pair_length), plan.bytes);
}

// A request for one chunk group. The group's bytes are hashed whole and a
// group is a leaf, so nothing is written below the root and the pair over the
// first two groups. The two groups the request did not take are skips, and
// they still take their place in the plan: the walk's shape is written down
// here rather than left to whoever walks it later.
test "a request for one group is two pairs, the group's bytes, and two skips" {
    const tree = BaoTree.init(49152);
    const plan = planOf(tree, .{ .start = 16, .end = 32 });

    try t.expectEqual(@as(usize, 5), plan.len);
    try t.expect(plan.items[0] == .pair);
    try t.expect(tree.root().eql(plan.items[0].pair));
    try t.expect(tree.root().children().left.eql(plan.items[1].pair));
    try t.expect(tree.root().children().right.eql(plan.items[4].skip));
    try t.expect(plan.items[2] == .skip);
    try t.expect(plan.items[3] == .data);
    try t.expectEqual(
        ranges.ByteRange{ .start = 16384, .end = 32768 },
        plan.items[3].data.bytes(tree),
    );
    try t.expectEqual(@as(usize, 2 * pair_length + 16384), plan.bytes);
}

// A request that starts inside one group and stops inside the next. The walk
// goes below the group line on both sides, so the plan carries sub-block pairs
// that no outboard stores, and only the chunks it was asked for. This is the
// case a group-aligned request never reaches, and it is why a plan is not a
// prefix of the outboard in general.
test "a range straddling two groups carries the sub-block pairs too" {
    const tree = BaoTree.init(49152);
    const plan = planOf(tree, .{ .start = 8, .end = 20 });

    // Root pair, then the pair over the first two groups, then inside group 0 a
    // pair, a skip and the selected chunk, then inside group 1 a pair, a pair,
    // the selected chunk, a skip and a skip, and a skip for group 2. That is
    // five pairs, not four: the walk crosses the group line on both sides, so
    // it crosses it twice on the way down and twice on the way back up, and
    // every crossing is a parent that emits its own pair.
    try t.expectEqual(@as(usize, 11), plan.len);
    try t.expect(plan.items[0] == .pair);
    try t.expect(tree.root().eql(plan.items[0].pair));
    try t.expect(tree.root().children().left.eql(plan.items[1].pair));
    try t.expect(plan.items[4] == .data);
    try t.expectEqual(
        ranges.ByteRange{ .start = 8 * 1024, .end = 16 * 1024 },
        plan.items[4].data.bytes(tree),
    );
    try t.expect(plan.items[7] == .data);
    try t.expectEqual(
        ranges.ByteRange{ .start = 16 * 1024, .end = 20 * 1024 },
        plan.items[7].data.bytes(tree),
    );
    try t.expect(plan.items[10] == .skip);

    var pairs: usize = 0;
    var bytes: usize = 0;
    for (plan.items[0..plan.len], 0..) |item, index| {
        if (item == .pair) pairs += 1;
        bytes += plan.itemBytes(tree, index);
    }
    try t.expectEqual(@as(usize, 5), pairs);
    try t.expectEqual(@as(usize, 2 * pairs + 1), plan.len);
    try t.expectEqual(@as(usize, 5 * pair_length + 12 * 1024), plan.bytes);
    try t.expectEqual(plan.bytes, bytes);
}

// The clip is `range_spec.resolve` and nothing else, which the test below
// pins twice: against a plain `min` for every request that starts inside the
// blob, and against the last-chunk rule for the one request shape that does
// not. Both are the range layer's rule; neither is re-derived here.
test "the clip is the range layer's own reading of the request" {
    const sizes = [_]u64{ 1, 1024, 1025, 16384, 16385, 49152, 49153 };
    for (sizes) |size| {
        const tree = BaoTree.init(size);
        for (0..@as(usize, @intCast(tree.chunks() + 3))) |start| {
            for ([_]u64{ 0, 1, 5, 16, 17, 1000 }) |length| {
                const request: ranges.ChunkRange = .{ .start = start, .end = start + length };
                const got = clip(tree, request);
                if (start >= tree.chunks()) {
                    // Upstream's rule, inherited: a span at or past the end is
                    // the last chunk, which is what `verified_size` relies on.
                    try t.expectEqual(tree.chunks() - 1, got.start);
                    try t.expectEqual(tree.chunks(), got.end);
                } else if (length == 0) {
                    try t.expectEqual(@as(u64, 0), got.len());
                } else {
                    try t.expectEqual(@as(u64, start), got.start);
                    try t.expectEqual(@min(start + length, tree.chunks()), got.end);
                }
            }
        }
    }
}

// A span running past the blob is cut at the blob, and the plan is the plan of
// what will actually be answered rather than of what was asked. 49153 bytes is
// 49 chunks; chunks 40 to 900 is 40 to 49, and the out-of-range half of the
// request costs the requester nothing but its own length.
test "a range running past the end is cut at the last chunk" {
    const tree = BaoTree.init(49153);
    const plan = planOf(tree, .{ .start = 40, .end = 900 });
    const covered = clip(tree, .{ .start = 40, .end = 900 });

    try t.expectEqual(ranges.ChunkRange{ .start = 40, .end = 49 }, covered);
    try t.expect(plan.len > 0);
    for (plan.items[0..plan.len]) |item| {
        switch (item) {
            .pair, .skip => continue,
            .data => |node| try t.expect(node.endChunk() <= 49),
        }
    }
}

// A request that selects nothing has no proof. That is not a hole in the
// walk: a zero-width request names no chunk, so there is nothing to answer and
// nothing that could reach a root, which is why `bao_proof_verify.zig` refuses
// it by name instead of accepting an empty proof.
test "an empty request has an empty plan" {
    const data = try published.blake3Input(49153);
    defer t.allocator.free(data);

    const tree = BaoTree.init(data.len);
    for ([_]ranges.ChunkRange{
        .{ .start = 0, .end = 0 },
        .{ .start = 17, .end = 17 },
        .{ .start = 48, .end = 48 },
    }) |request| {
        const plan = planOf(tree, request);
        try t.expect(plan.isEmpty());
        try t.expectEqual(@as(usize, 0), plan.bytes);
    }
}

// A blob of no bytes has no last chunk, so no request names one and no proof
// reaches its root. The root of an empty blob is still well defined — it is
// the published digest of the empty input — and it has to come from somewhere
// other than a range request.
test "a blob of no bytes has an unreachable root" {
    const tree = BaoTree.init(0);
    try t.expectEqual(@as(u64, 0), tree.chunks());
    try t.expectEqual(@as(u64, 0), tree.blocks());
    try t.expectEqual(@as(u64, 0), tree.rootBlockBytes());
    try t.expect(tree.rootIsLeaf());

    const all = planOf(tree, .{ .start = 0, .end = tree.chunks() });
    try t.expect(all.isEmpty());

    const data = try published.blake3Input(0);
    defer t.allocator.free(data);
    try t.expectEqualStrings(
        published.blake3_vectors[0].hash,
        &std.fmt.bytesToHex(&try tree.rootHash(data), .lower),
    );
}

// A plan never asks for more than `max_items` items and never names a node
// the blob does not hold, and its item count is exactly twice its pair count
// plus one — the shape `max_items`' own comment argues for, checked here over
// every request of blobs whose group count does not divide evenly.
test "a plan stays inside its bound and inside the blob" {
    const sizes = [_]u64{ 16385, 32769, 47000, 49153, 65537 };
    for (sizes) |size| {
        const tree = BaoTree.init(size);
        for (0..@as(usize, @intCast(tree.chunks() + 1))) |start| {
            for ([_]u64{ 0, 1, 3, 16, 17, 33, 47 }) |length| {
                const plan = planOf(tree, .{ .start = start, .end = start + length });
                try t.expect(plan.len <= max_items);

                var pairs: usize = 0;
                var bytes: usize = 0;
                for (plan.items[0..plan.len], 0..) |item, index| {
                    if (item == .pair) pairs += 1;
                    bytes += plan.itemBytes(tree, index);
                    try t.expect(item.node().endChunk() <= tree.chunks());
                }
                try t.expectEqual(plan.bytes, bytes);
                if (plan.isEmpty()) {
                    try t.expectEqual(@as(usize, 0), pairs);
                } else {
                    try t.expectEqual(2 * pairs + 1, plan.len);
                }
            }
        }
    }
}

test "oversized whole proof plans fail closed without walking unbounded groups" {
    const tree = BaoTree.init(std.math.maxInt(u64));
    const plan = planOf(tree, .{ .start = 0, .end = tree.chunks() });
    try t.expect(plan.overflow);
}
