//! Walking a proof against a root the caller already trusted.
//!
//! The verifier is a state machine over bytes and over nothing else. `want`
//! says how many bytes the next item needs, `take` consumes exactly that many,
//! and `finish` is the only way to succeed. It reads no socket, no clock and
//! no environment; `trusted_root` is a parameter, not something it fetches.
//!
//! # Why the plan comes from the request and not from the bytes
//!
//! Every item the verifier expects is derived from the tree and the request
//! before the first byte arrives. A peer therefore cannot choose the shape of
//! the walk by sending something different: extra bytes are `TrailingBytes`,
//! short ones are `ResponseTruncated`, and a well-formed response that stops
//! early is `ProofIncomplete` at `finish`. A verifier that derived its
//! expectations from the response would be checking the response against
//! itself.
//!
//! # What `finish` guarantees
//!
//! Success needs three things, and all three are checked there, after the
//! whole plan has been consumed and every parent has closed:
//!
//! 1. **Every owed child arrived.** The plan is spent and the parent stack is
//!    empty. Anything left over is `ProofIncomplete`, and an early end of the
//!    response is that error and never a success.
//! 2. **A root was computed.** `RootNotVerified` when there is none to
//!    compare. A plan `planOf` built cannot reach it — the stack empties only
//!    through the node whose value is the root — and it is here because "the
//!    root has been compared" is a property worth stating rather than
//!    inferring from the shape of the walk.
//! 3. **The root is the trusted root.** `RootMismatch` when it is not, which
//!    is the only failure here that is not an attack: everything the peer sent
//!    agreed with itself and does not belong to this blob.
//!
//! # A declared size is never checked against a header
//!
//! Nothing here reads a length off a frame and calls it a size, and no step
//! compares two size fields. The tree is cut to a claimed size, the plan is
//! cut to the same one, and the claim is settled only by this walk: bytes that
//! do not fill the tree cannot reach the root the caller trusted, and a proof
//! that stops short of that root is refused.

const std = @import("std");

const core = @import("../crypto/blake3_core.zig");
const subtree = @import("../crypto/blake3_subtree.zig");
const ranges = @import("ranges.zig");
const tree_mod = @import("bao_tree.zig");
const plan_mod = @import("bao_plan.zig");

pub const BaoTree = tree_mod.BaoTree;
pub const Node = tree_mod.Node;
pub const Plan = plan_mod.Plan;
pub const pair_length = tree_mod.pair_length;

comptime {
    // Node byte offsets are multiples of the BLAKE3 chunk length.
    std.debug.assert(ranges.chunk_size == core.chunk_length);
}

/// Every way a proof can be refused. Each is a decision and not a crash: a
/// peer that sends any of these is refused with the one that says why.
pub const Error = error{
    /// The request selects nothing, so there is no proof to check. A
    /// zero-width request names no chunk, and a request for a blob's size is
    /// `RangeSpec.verified_size`, which names the last chunk.
    NoRangeRequested,
    /// The plan names a node the tree does not have, so it cannot be walked.
    /// `planOf` cannot build one; a plan handed in can.
    MalformedPlan,
    /// The response ended inside an item: fewer bytes arrived than the item
    /// needs. Never a success and never a partial comparison.
    ResponseTruncated,
    /// The response carried more bytes than the plan can use. Extra bytes are
    /// not ignored, because a peer that appends whatever it likes is a peer
    /// this walk has no reading for.
    TrailingBytes,
    /// `finish` was called with the plan unspent, or with a parent still open.
    /// This is what a response that stops before the tree is spanned gets.
    ProofIncomplete,
    /// `finish` was called and no root was computed, so nothing was compared
    /// against the trusted root.
    RootNotVerified,
    /// The root this proof reaches is not the root the caller trusted.
    RootMismatch,
    /// A value computed from the bytes beside it is not the value the proof
    /// claimed for it. A flipped data byte and a flipped byte in a parent pair
    /// are the same event here and are named the same way on purpose: at the
    /// moment of comparison there is one disagreement between one computed
    /// value and one claimed value, and saying which was wrong would be a
    /// claim the walk cannot support.
    ChildMismatch,
};

/// One open parent: the two values the proof claimed for its children, and
/// which child the next value closes.
const Frame = struct {
    left: core.CvBytes,
    right: core.CvBytes,
    /// Zero while the left child is outstanding.
    side: u1,
};

/// The walk, one item at a time.
pub const Verifier = struct {
    tree: BaoTree,
    plan: Plan,
    /// The root the caller already held. It never comes from the response.
    trusted_root: core.CvBytes,
    stack: [core.max_depth + 1]Frame = undefined,
    /// How many parents are open. Zero means the root has closed.
    depth: usize = 0,
    /// How many plan items have been consumed.
    next: usize = 0,
    /// The root's value, once the walk has computed it.
    root: ?core.CvBytes = null,
    /// Set by `finish` and nowhere else, so a caller can ask whether the walk
    /// reached the trusted root rather than assuming it did.
    root_verified: bool = false,

    /// The plan is taken as a parameter, so it is checked before it is walked.
    /// Every node must lie inside the tree: that is what makes a node's byte
    /// range in bounds, and it is what makes `start_chunk * 1024` overflow
    /// impossible, since a tree's chunk count is at most 2^54. A node of one
    /// chunk is a leaf and cannot be the parent a pair claims to be.
    pub fn init(tree: BaoTree, plan: Plan, trusted_root: core.CvBytes) Error!Verifier {
        if (plan.overflow) return error.MalformedPlan;
        if (plan.isEmpty()) return error.NoRangeRequested;
        for (plan.items[0..plan.len]) |item| {
            const node = item.node();
            if (node.endChunk() > tree.chunks()) return error.MalformedPlan;
            if (item == .pair and node.span < 2) return error.MalformedPlan;
        }
        return .{ .tree = tree, .plan = plan, .trusted_root = trusted_root };
    }

    /// How many bytes the next item needs, or null once the plan is spent. A
    /// skip needs none, so a caller that reads this before every read handles
    /// the zero-length items without a special case.
    pub fn want(self: *const Verifier) ?usize {
        if (self.next >= self.plan.len) return null;
        return self.plan.itemBytes(self.tree, self.next);
    }

    /// Consume exactly `want()` bytes. Fewer is `ResponseTruncated` and more
    /// is `TrailingBytes`; neither is padded and neither is ignored.
    pub fn take(self: *Verifier, bytes: []const u8) Error!void {
        const needed = self.want() orelse return error.TrailingBytes;
        if (bytes.len < needed) return error.ResponseTruncated;
        if (bytes.len > needed) return error.TrailingBytes;

        const item = self.plan.items[self.next];
        self.next += 1;
        switch (item) {
            .pair => {
                if (self.depth >= self.stack.len) return error.MalformedPlan;
                const pair = tree_mod.readPair(bytes);
                self.stack[self.depth] = .{ .left = pair.left, .right = pair.right, .side = 0 };
                self.depth += 1;
            },
            .skip => try self.closeChild(null),
            .data => |node| try self.closeChild(self.hash(node, bytes)),
        }
    }

    /// Accept a caller-streamed data item's hash without buffering its bytes.
    pub fn takeDataHash(self: *Verifier, cv: core.CvBytes) Error!void {
        if (self.next >= self.plan.len) return error.MalformedPlan;
        if (self.plan.items[self.next] != .data) return error.MalformedPlan;
        self.next += 1;
        try self.closeChild(cv);
    }

    /// The value of `node` from the bytes that just arrived. With no parent
    /// open this is the tree's own root and it is the one node whose value
    /// carries ROOT; every other node's value is what its parent would
    /// compress, ROOT clear.
    fn hash(self: *const Verifier, node: Node, bytes: []const u8) core.CvBytes {
        const range = node.bytes(self.tree);
        // Alignment follows from Node.bytes and the chunk-size assertion above.
        var hasher = subtree.Hasher.init(range.start) catch
            @panic("Bao node offset must be chunk-aligned");
        hasher.update(bytes[0..@intCast(range.end - range.start)]);
        return if (self.depth == 0) hasher.final() else hasher.finalChainingValue();
    }

    /// Close the child the walk is on. `computed` is null for a skip, where the
    /// value comes from the parent pair and there is nothing to compare.
    fn closeChild(self: *Verifier, computed: ?core.CvBytes) Error!void {
        if (self.depth == 0) {
            // Nothing is open, so this value is the tree's own root, and it
            // closes only once the plan is spent: either the plan was the
            // root's own bytes and nothing else, or the root's pair has just
            // closed over the last of its children. A value closing with plan
            // items still to come is a plan with more above the root than the
            // tree has, and a null one is a plan that never claimed a value
            // for it.
            if (self.next != self.plan.len) return error.MalformedPlan;
            self.root = computed orelse return error.MalformedPlan;
            return;
        }
        const frame = &self.stack[self.depth - 1];
        const claimed = if (frame.side == 0) frame.left else frame.right;
        if (computed) |value| {
            if (!std.meta.eql(value, claimed)) return error.ChildMismatch;
        }
        if (frame.side == 0) {
            frame.side = 1;
            return;
        }
        const left = frame.left;
        const right = frame.right;
        const is_root = self.depth == 1;
        self.depth -= 1;
        try self.closeChild(if (is_root)
            subtree.mergeRoot(left, right)
        else
            subtree.merge(left, right));
    }

    /// The only way to succeed. See the module comment for the three
    /// guarantees this makes.
    pub fn finish(self: *Verifier) Error!void {
        if (self.next != self.plan.len or self.depth != 0) return error.ProofIncomplete;
        const root = self.root orelse return error.RootNotVerified;
        if (!std.meta.eql(root, self.trusted_root)) return error.RootMismatch;
        self.root_verified = true;
    }
};

/// Check `response` as a proof that the requested range of `tree` reaches
/// `trusted_root`.
///
/// This is the machine above driven over one buffer, and it reads no length off
/// the response: the plan fixes every item's length before a byte is looked at.
/// An end of response that falls on an item boundary is left to `finish` to
/// name, so "the response stopped" and "the response stopped mid-item" are two
/// errors and not one.
pub fn verify(
    tree: BaoTree,
    request: ranges.ChunkRange,
    trusted_root: core.CvBytes,
    response: []const u8,
) Error!void {
    var machine = try Verifier.init(tree, plan_mod.planOf(tree, request), trusted_root);
    var rest = response;
    while (machine.want()) |needed| {
        // A skip carries no bytes, so an exhausted response still has those
        // items to consume: stopping on an empty buffer would leave the plan
        // unspent and turn a complete proof into `ProofIncomplete`. Stopping
        // on an item that *does* need bytes is left to `finish`, which is
        // what keeps "stopped here" apart from "stopped inside an item".
        if (rest.len < needed) {
            if (rest.len == 0) break;
            return error.ResponseTruncated;
        }
        try machine.take(rest[0..needed]);
        rest = rest[needed..];
    }
    if (rest.len != 0) return error.TrailingBytes;
    try machine.finish();
}

const t = std.testing;
const encode_mod = @import("bao_proof_encode.zig");
const published = @import("../gossip/plumtree/blake3_vectors.zig");

const none: []const u8 = &.{};

/// A blob, its root, and the proof of one request over it, built through the
/// real encoder so the round trips below go over the real walk.
const Proof = struct {
    data: []u8,
    root: core.CvBytes,
    tree: BaoTree,
    plan: Plan,
    bytes: []u8,

    fn make(size: usize, request: ranges.ChunkRange) !Proof {
        const data = try published.blake3Input(size);
        const tree = BaoTree.init(data.len);
        const plan = plan_mod.planOf(tree, request);
        const bytes = try t.allocator.alloc(u8, plan.bytes);
        _ = try encode_mod.encode(plan, tree, data, bytes);
        return .{
            .data = data,
            .root = try tree.rootHash(data),
            .tree = tree,
            .plan = plan,
            .bytes = bytes,
        };
    }

    fn free(self: Proof) void {
        t.allocator.free(self.bytes);
        t.allocator.free(self.data);
    }

    fn verifySelf(self: Proof, request: ranges.ChunkRange) !void {
        try verify(self.tree, request, self.root, self.bytes);
    }
};

/// Where item `index` of `plan` starts in the proof it describes.
fn offsetOf(tree: BaoTree, plan: Plan, index: usize) usize {
    var at: usize = 0;
    for (plan.items[0..index], 0..) |_, i| at += plan.itemBytes(tree, i);
    return at;
}

/// How many bytes the plan's data items carry in all.
fn dataBytes(tree: BaoTree, plan: Plan) usize {
    var total: usize = 0;
    for (plan.items[0..plan.len], 0..) |item, index| {
        if (item == .data) total += plan.itemBytes(tree, index);
    }
    return total;
}

/// Where the plan's first data item starts. Every pair before it is 64 bytes
/// and every skip is none, so the answer is a whole number of pairs.
fn dataOffset(tree: BaoTree, plan: Plan) usize {
    var at: usize = 0;
    for (plan.items[0..plan.len], 0..) |item, index| {
        if (item == .data) return at;
        at += plan.itemBytes(tree, index);
    }
    return at;
}

/// The 64 bytes of the root's own pair, for the malformed-plan tests.
fn rootPair(tree: BaoTree, data: []const u8) ![pair_length]u8 {
    const children = tree.root().children();
    var out: [pair_length]u8 = undefined;
    tree_mod.writePair(&out, .{
        .left = try tree.nodeCv(children.left, data),
        .right = try tree.nodeCv(children.right, data),
    });
    return out;
}

// The five requests the walk has to answer, each round-tripped through the
// real encoder and the real `crypto/blake3_subtree.zig` layer over synthetic
// data: the whole blob, one chunk, a range that starts in one group and stops
// in the next, the last chunk alone, and a range running past the end.
test "the five requests round trip through the encoder and the walk" {
    const cases = [_]struct { size: usize, request: ranges.ChunkRange }{
        .{ .size = 49153, .request = .{ .start = 0, .end = 49 } },
        .{ .size = 49153, .request = .{ .start = 20, .end = 21 } },
        .{ .size = 49153, .request = .{ .start = 8, .end = 20 } },
        .{ .size = 49153, .request = .{ .start = 48, .end = 49 } },
        .{ .size = 49153, .request = .{ .start = 40, .end = 900 } },
    };
    for (cases) |case| {
        const built = try Proof.make(case.size, case.request);
        defer built.free();
        try built.verifySelf(case.request);
    }
}

// One group and one chunk. A blob of one group has its root inside a group, so
// the walk sets ROOT on a group's own value; a blob of one chunk is the same
// walk one level down, and a blob of 1025 bytes has a short last chunk.
test "one group, one chunk and one short chunk verify too" {
    const cases = [_]struct { size: usize, request: ranges.ChunkRange }{
        .{ .size = 16384, .request = .{ .start = 0, .end = 16 } },
        .{ .size = 16384, .request = .{ .start = 4, .end = 9 } },
        .{ .size = 1, .request = .{ .start = 0, .end = 1 } },
        .{ .size = 1025, .request = .{ .start = 1, .end = 2 } },
    };
    for (cases) |case| {
        const built = try Proof.make(case.size, case.request);
        defer built.free();
        try built.verifySelf(case.request);
    }
}

// Every request of these blobs, not just the five above: the plan is derived
// from the request, the response from the plan, and the walk has to survive
// every shape in between, including a blob whose groups do not divide evenly.
test "every request of an uneven blob verifies" {
    const sizes = [_]usize{ 16385, 49153 };
    for (sizes) |size| {
        const tree = BaoTree.init(size);
        var start: u64 = 0;
        while (start < tree.chunks()) : (start += 1) {
            for ([_]u64{ 1, 16, 17 }) |length| {
                const request: ranges.ChunkRange = .{ .start = start, .end = start + length };
                const built = try Proof.make(size, request);
                defer built.free();
                try built.verifySelf(request);
            }
        }
    }
}

// A flipped byte in the data is caught where the data is hashed: the value the
// walk computes is not the value the parent pair claimed for that child. The
// request is one chunk at 20 of a 49153-byte blob: the walk to it crosses six
// parents and the chunk is the seventh item.
test "a flipped byte in the data is a child mismatch" {
    const request: ranges.ChunkRange = .{ .start = 20, .end = 21 };
    var built = try Proof.make(49153, request);
    defer built.free();

    const at = dataOffset(built.tree, built.plan);
    try t.expect(at > 0);
    try t.expectEqual(@as(usize, 0), at % pair_length);
    try t.expectEqual(6 * pair_length, at);
    try t.expect(at + core.chunk_length <= built.bytes.len);
    built.bytes[at] ^= 0x01;

    try t.expectError(error.ChildMismatch, verify(built.tree, request, built.root, built.bytes));
}

// The same flip in the parent pair's left half, the half whose child is proved
// beside it, is caught by the same comparison and named the same way. At the
// moment of comparison a wrong claimed value and a wrong computed value are one
// disagreement, and the walk cannot honestly tell which is which.
test "a flipped byte in a proved half of a pair is a child mismatch" {
    const request: ranges.ChunkRange = .{ .start = 20, .end = 21 };
    var built = try Proof.make(49153, request);
    defer built.free();

    // The root's left child is the half of the blob the request reaches, so
    // the root pair's left half is the one the walk will check against data.
    built.bytes[0] ^= 0x01;

    try t.expectError(error.ChildMismatch, verify(built.tree, request, built.root, built.bytes));
}

// The same flip in the half nothing proved is caught one level up, as a root
// that does not match. Two errors for one corruption is the honest outcome: the
// walk reports where it found out, not where the byte was.
test "a flipped byte in a skipped half of a pair is a root mismatch" {
    const request: ranges.ChunkRange = .{ .start = 20, .end = 21 };
    var built = try Proof.make(49153, request);
    defer built.free();

    // The root's right child is past the request, so the right half of the
    // root pair is taken on trust and only the merge can catch a flip in it.
    built.bytes[pair_length - 1] ^= 0x01;

    try t.expectError(error.RootMismatch, verify(built.tree, request, built.root, built.bytes));
}

// A response that stops inside an item is `ResponseTruncated`, refused while
// the walk is still on that item: never finished, never compared.
test "a truncated response is refused" {
    const request: ranges.ChunkRange = .{ .start = 20, .end = 21 };
    const built = try Proof.make(49153, request);
    defer built.free();

    try t.expectError(
        error.ResponseTruncated,
        verify(built.tree, request, built.root, built.bytes[0..1]),
    );
    const at = dataOffset(built.tree, built.plan);
    try t.expectError(
        error.ResponseTruncated,
        verify(built.tree, request, built.root, built.bytes[0 .. at - 1]),
    );
}

// A response that stops on an item boundary is well formed and still short.
// `finish` refuses it as incomplete, and it is the case that must never be a
// success: it is the one an "end of response is end of proof" reader gets
// wrong.
test "a response that stops before the tree is spanned is refused" {
    const request: ranges.ChunkRange = .{ .start = 20, .end = 21 };
    const built = try Proof.make(49153, request);
    defer built.free();

    const data_bytes = dataBytes(built.tree, built.plan);
    try t.expectEqual(@as(usize, core.chunk_length), data_bytes);
    try t.expectError(
        error.ProofIncomplete,
        verify(built.tree, request, built.root, built.bytes[0 .. built.bytes.len - data_bytes]),
    );
}

// A root the caller does not trust is a mismatch, and the proof is otherwise
// perfect. Driven a step at a time as well as in one call, so the flag the
// caller can ask about is shown to be false.
test "a wrong trusted root is a root mismatch" {
    const request: ranges.ChunkRange = .{ .start = 20, .end = 21 };
    const built = try Proof.make(49153, request);
    defer built.free();

    var wrong = built.root;
    wrong[0] ^= 0x01;
    try t.expectError(error.RootMismatch, verify(built.tree, request, wrong, built.bytes));

    var machine = try Verifier.init(built.tree, built.plan, wrong);
    try t.expect(built.tree.root().eql(built.plan.items[0].node()));
    while (machine.next < built.plan.len) {
        const at = offsetOf(built.tree, built.plan, machine.next);
        const needed = machine.want() orelse return error.TestUnexpectedResult;
        try machine.take(built.bytes[at..][0..needed]);
    }
    try t.expect(!machine.root_verified);
    try t.expectError(error.RootMismatch, machine.finish());
    try t.expect(!machine.root_verified);
}

// A root the caller trusts, driven a step at a time, ends with the flag set:
// `root_verified` is a statement about the walk rather than about the absence
// of an error.
test "a walk that reaches the trusted root says so" {
    const request: ranges.ChunkRange = .{ .start = 20, .end = 21 };
    const built = try Proof.make(49153, request);
    defer built.free();

    var machine = try Verifier.init(built.tree, built.plan, built.root);
    while (machine.next < built.plan.len) {
        const at = offsetOf(built.tree, built.plan, machine.next);
        const needed = machine.want() orelse return error.TestUnexpectedResult;
        try machine.take(built.bytes[at..][0..needed]);
    }
    try t.expectEqual(@as(?usize, null), machine.want());
    try machine.finish();
    try t.expect(machine.root_verified);
}

// Bytes the plan cannot use are refused rather than ignored. A peer that
// appends whatever it likes has a reading this walk does not have.
test "a response longer than the plan is refused" {
    const request: ranges.ChunkRange = .{ .start = 0, .end = 49 };
    const built = try Proof.make(49153, request);
    defer built.free();

    const longer = try t.allocator.alloc(u8, built.bytes.len + 1);
    defer t.allocator.free(longer);
    @memcpy(longer[0..built.bytes.len], built.bytes);
    longer[built.bytes.len] = 0;

    try t.expectError(error.TrailingBytes, verify(built.tree, request, built.root, longer));
}

// A request that selects nothing has no proof to check, and the walk says so
// by name rather than accepting an empty response as a proof of nothing.
test "an empty request is refused by name" {
    const data = try published.blake3Input(49153);
    defer t.allocator.free(data);

    const tree = BaoTree.init(data.len);
    const root = try tree.rootHash(data);
    for ([_]ranges.ChunkRange{
        .{ .start = 0, .end = 0 },
        .{ .start = 17, .end = 17 },
    }) |request| {
        try t.expectError(error.NoRangeRequested, verify(tree, request, root, none));
    }
}

// A plan that names a node outside the tree, a plan with a parent and no child
// to close it, and a plan that skips the root are all refused rather than
// walked. `planOf` builds none of these; a plan handed in as a parameter can,
// and a parameter the walk cannot follow is a refusal and not an assertion.
test "a plan that cannot be walked is refused" {
    const data = try published.blake3Input(49153);
    defer t.allocator.free(data);

    const tree = BaoTree.init(data.len);
    const root = try tree.rootHash(data);
    const request: ranges.ChunkRange = .{ .start = 0, .end = 16 };

    var outside: plan_mod.Plan = plan_mod.planOf(tree, request);
    outside.items[0] = .{ .pair = .{ .start_chunk = tree.chunks(), .span = 2 } };
    try t.expectError(error.MalformedPlan, Verifier.init(tree, outside, root));

    var unclosed: plan_mod.Plan = plan_mod.planOf(tree, request);
    unclosed.items[0] = .{ .pair = tree.root() };
    unclosed.len = 1;
    unclosed.bytes = pair_length;
    var stalled = try Verifier.init(tree, unclosed, root);
    const pair_bytes = try rootPair(tree, data);
    try stalled.take(&pair_bytes);
    try t.expectError(error.ProofIncomplete, stalled.finish());

    var skipped: plan_mod.Plan = .{};
    skipped.items[0] = .{ .skip = tree.root() };
    skipped.len = 1;
    var machine = try Verifier.init(tree, skipped, root);
    try t.expectError(error.MalformedPlan, machine.take(none));

    // A pair at a node of one chunk: a leaf has nothing below it to pair.
    var leaf: plan_mod.Plan = .{};
    leaf.items[0] = .{ .pair = .{ .start_chunk = 0, .span = 1 } };
    leaf.len = 1;
    try t.expectError(error.MalformedPlan, Verifier.init(tree, leaf, root));
}
