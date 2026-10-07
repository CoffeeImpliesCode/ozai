//! Answering a decoded `GetRequest` out of the store.
//!
//! A response starts with the actual blob size as u64 little-endian, followed
//! by validated Bao preorder pairs and data. Persisted parents are loaded by
//! their tree index, not by the number of parents selected by the request.
//!
//! # Why an empty answer is the only refusal
//!
//! A provider that does not have the blob writes nothing and closes. It writes
//! no error frame, because there is no such frame: `BaoResponse` has no error
//! arm, and upstream's `# Responses` section says the provider "will close just
//! the stream used to send the response", with the reason recovered from the
//! resulting error on the getter's side.
//!
//! Anything else this module could write would be worse, not merely different.
//! A getter cannot tell an error notice from a short proof — it hands both to
//! the same verifier — so a provider that wrote one would turn "I do not have
//! this blob" into a child mismatch, and a provider that wrote a partial blob
//! would turn it into a hash mismatch on bytes nobody asked for. Zero bytes
//! carry exactly one meaning, and it is the one the getter already knows how to
//! read: ask someone else. Every other answer is bytes a verifier has to treat
//! as a claim about the blob.
//!
//! # What this store cannot answer
//!
//! One blob. A `GetRequest` naming a hash sequence — `GetRequest.all`, whose
//! walk has no terminator — needs a collection index this store does not have,
//! and a spec resolving to two or more disjoint spans needs a plan
//! `bao_plan.planOf` cannot build, because it takes one `ChunkRange`. Both
//! return `.absent`, which is the refusal above, and both are refusals rather
//! than partial answers: half a collection's bytes would be a stream no
//! verifier accepts, and on the wire it is indistinguishable from a truncated
//! answer — which is the failure mode that costs a peer its time twice.

const std = @import("std");

const core = @import("../crypto/blake3_core.zig");
const subtree = @import("../crypto/blake3_subtree.zig");
const ranges = @import("ranges.zig");
const range_spec = @import("range_spec.zig");
const tree_mod = @import("bao_tree.zig");
const plan_mod = @import("bao_plan.zig");
const outboard_mod = @import("bao_outboard.zig");
const requests = @import("requests.zig");
const store = @import("store.zig");

/// A decoded `get`, as `blobs/protocol.zig` hands one over.
pub const GetRequest = requests.GetRequest;

/// The tree over one blob.
pub const BaoTree = tree_mod.BaoTree;

/// A parent pair's width, which is also the outboard's stride.
const pair_length = tree_mod.pair_length;

/// Everything that can stop an answer being written.
pub const Error = std.Io.File.OpenError ||
    std.Io.File.LengthError ||
    std.Io.File.ReadPositionalError ||
    std.Io.Writer.Error ||
    subtree.Error ||
    error{
        /// The data file is shorter than the tree the request resolves
        /// against, so an item of the plan names bytes the store does not
        /// hold. Only a store written behind this module's back, or one whose
        /// data was truncated under an open reader, can produce one.
        ShortData,
        ShortOutboard,
        InvalidOutboard,
        PlanTooLarge,
        /// `init` was handed no scratch to stream through, and streaming needs
        /// at least one byte. A programmer error, refused rather than looped on.
        NoScratch,
    };

/// What a `get` produced.
pub const Outcome = enum {
    /// The whole answer is in the writer. Its end is the answer's only
    /// boundary.
    answered,
    /// Nothing was written, and the caller reads that as "ask someone else"
    /// rather than as anything about the blob.
    absent,
};

/// One blob in a store, ready to answer requests about it.
pub const Provider = struct {
    dir: std.Io.Dir,
    hash: store.Hash,
    paths: store.Names,
    /// Caller-owned scratch every streamed range passes through. Its length is
    /// a throughput knob and nothing else: one byte is correct, and the loop
    /// never needs more than it was given.
    scratch: []u8,

    /// A provider over the blob named by `hash` in `dir`. `name_storage` and
    /// `scratch` belong to the caller and must outlive the provider.
    pub fn init(
        dir: std.Io.Dir,
        name_storage: *store.NameStorage,
        hash: store.Hash,
        scratch: []u8,
    ) Error!Provider {
        if (scratch.len == 0) return error.NoScratch;
        return .{
            .dir = dir,
            .hash = hash,
            .paths = store.names(name_storage, hash),
            .scratch = scratch,
        };
    }

    /// Write the answer to `request` into `writer`.
    ///
    /// A request for another blob is `.absent` and not an error: a provider is
    /// one blob, and a peer may ask it about anything.
    pub fn answer(
        self: *const Provider,
        io: std.Io,
        writer: *std.Io.Writer,
        request: GetRequest,
    ) Error!Outcome {
        if (!std.meta.eql(self.hash, request.hash)) return .absent;
        const handles = store.openComplete(io, self.dir, self.paths) catch |err| switch (err) {
            // Both absences are one answer, and it is the same answer the
            // torn-pair window produces.
            error.FileNotFound => return .absent,
            else => return err,
        };
        defer handles.close(io);

        const tree = BaoTree.init(try handles.data.length(io));
        const selected = request.selectedRange(tree.chunks()) orelse return .absent;
        const plan = plan_mod.planOf(tree, selected);
        if (plan.overflow) return error.PlanTooLarge;
        if (plan.isEmpty()) return .absent;
        var size_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &size_bytes, tree.size, .little);
        try writer.writeAll(&size_bytes);
        try writePlan(self, io, writer, &handles, tree, plan);
        return .answered;
    }
};

/// Write every item of `plan`, in plan order.
fn writePlan(
    provider: *const Provider,
    io: std.Io,
    writer: *std.Io.Writer,
    handles: *const store.Handles,
    tree: BaoTree,
    plan: plan_mod.Plan,
) Error!void {
    var verifier = @import("bao_proof_verify.zig").Verifier.init(
        tree, plan, provider.hash,
    ) catch return error.InvalidOutboard;
    var pair: [pair_length]u8 = undefined;
    for (plan.items[0..plan.len]) |item| switch (item) {
        .skip => verifier.take(&.{}) catch return error.InvalidOutboard,
        .data => |node| {
            var hasher = try subtree.Hasher.init(node.bytes(tree).start);
            try runRange(io, handles.data, node.bytes(tree), provider.scratch, &.{
                .both = .{ .answer = writer, .hasher = &hasher },
            });
            const cv = if (verifier.depth == 0)
                hasher.final()
            else
                hasher.finalChainingValue();
            verifier.takeDataHash(cv) catch return error.InvalidOutboard;
        },
        .pair => |node| {
            if (node.isOutboardParent()) {
                const index = outboard_mod.pairIndex(tree, node) orelse
                    return error.InvalidOutboard;
                const read = try handles.outboard.readPositionalAll(
                    io, &pair, @as(u64, @intCast(index)) * pair_length,
                );
                if (read != pair_length) return error.ShortOutboard;
            } else {
                try computePair(io, handles.data, tree, node, provider.scratch, &pair);
            }
            const values = tree_mod.readPair(&pair);
            const computed = if (verifier.depth == 0)
                subtree.mergeRoot(values.left, values.right)
            else
                subtree.merge(values.left, values.right);
            const expected = if (verifier.depth == 0)
                provider.hash
            else if (verifier.stack[verifier.depth - 1].side == 0)
                verifier.stack[verifier.depth - 1].left
            else
                verifier.stack[verifier.depth - 1].right;
            if (!std.meta.eql(computed, expected)) return error.InvalidOutboard;
            try writer.writeAll(&pair);
            verifier.take(&pair) catch return error.InvalidOutboard;
        },
    };
    verifier.finish() catch return error.InvalidOutboard;
}

/// The `pair_length` bytes of the pair about `node`, computed from the data.
///
/// This is `bao_proof_encode`'s own arithmetic over a node, run a range at a
/// time because the data is a file and not a slice: the same `Hasher.init`,
/// the same `update`, the same `finalChainingValue`, so the value is the one
/// `BaoTree.nodeCv` returns for the whole blob held in memory.
fn computePair(
    io: std.Io,
    data: std.Io.File,
    tree: BaoTree,
    node: tree_mod.Node,
    scratch: []u8,
    out: *[pair_length]u8,
) Error!void {
    const children = node.children();
    const left = try childValue(io, data, tree, children.left, scratch);
    const right = try childValue(io, data, tree, children.right, scratch);
    tree_mod.writePair(out, .{ .left = left, .right = right });
}

fn childValue(
    io: std.Io,
    data: std.Io.File,
    tree: BaoTree,
    node: tree_mod.Node,
    scratch: []u8,
) Error!core.CvBytes {
    const range = node.bytes(tree);
    var hasher = try subtree.Hasher.init(range.start);
    try runRange(io, data, range, scratch, &.{ .hasher = &hasher });
    return hasher.finalChainingValue();
}

/// Where `runRange` puts the bytes it reads. Two consumers with one loop, so
/// the two cannot drift on the one thing they must agree about: the order the
/// bytes arrive in.
const Sink = union(enum) {
    /// Into the answer, in the order they were read.
    answer: *std.Io.Writer,
    /// Into a subtree hasher, which is the same walk over a narrower range.
    hasher: *subtree.Hasher,
    both: struct { answer: *std.Io.Writer, hasher: *subtree.Hasher },
};

/// Read `range` of `data` in pieces no larger than `scratch`, in order.
fn runRange(
    io: std.Io,
    data: std.Io.File,
    range: ranges.ByteRange,
    scratch: []u8,
    sink: *const Sink,
) Error!void {
    var at = range.start;
    while (at < range.end) {
        const want: usize = @intCast(@min(scratch.len, range.end - at));
        const read = try data.readPositional(io, &.{scratch[0..want]}, at);
        if (read == 0) return error.ShortData;
        switch (sink.*) {
            .answer => |answer| try answer.writeAll(scratch[0..read]),
            .hasher => |hasher| hasher.update(scratch[0..read]),
            .both => |both| {
                both.hasher.update(scratch[0..read]);
                try both.answer.writeAll(scratch[0..read]);
            },
        }
        at += read;
    }
}

const t = std.testing;
const encode_mod = @import("bao_proof_encode.zig");
const published = @import("../gossip/plumtree/blake3_vectors.zig");

/// Chunks 20 through 21 of a 49153-byte blob. The range is not group-aligned,
/// so its plan needs both halves of the store: two pairs the outboard holds
/// and five below a group it does not.
const off_group = ranges.ChunkRange{ .start = 20, .end = 21 };

/// `off_group` as a request's ranges, over storage that outlives the call.
///
/// `GetRequest` borrows its items and the items borrow their widths, so a
/// helper that built either would hand back a pointer to a frame that is gone
/// before the caller reads it. These two arrays are comptime, so they are in
/// the binary and a request built over them is a request anyone may hold.
const off_group_widths = [_]u64{ off_group.start, off_group.len() };
const off_group_items = [_]range_spec.Item{
    .{ .delta = 0, .spec = .{ .widths = &off_group_widths } },
    .{ .delta = 1, .spec = range_spec.RangeSpec.empty },
};

// Whole responses include a size and persisted pairs; a missing hash is EOF.
test "a whole blob is answered with size and Bao, and a miss with none" {
    const data = try published.blake3Input(49153);
    defer t.allocator.free(data);
    const tree = BaoTree.init(data.len);
    const hash: store.Hash = try tree.rootHash(data);

    var tmp = try @import("test_scratch").tmpDir(.{});
    defer tmp.cleanup();
    try putBlob(tmp.dir, hash, data);

    var name_storage: store.NameStorage = undefined;
    var scratch: [1024]u8 = undefined;
    const provider = try Provider.init(tmp.dir, &name_storage, hash, &scratch);

    const answer = try t.allocator.alloc(u8, data.len + 8 + 3 * pair_length);
    defer t.allocator.free(answer);
    var writer = std.Io.Writer.fixed(answer);
    try t.expectEqual(.answered, try provider.answer(t.io, &writer, GetRequest.blob(hash)));
    try t.expectEqual(tree.size, std.mem.readInt(u64, writer.buffered()[0..8], .little));
    const payload = try t.allocator.alloc(u8, data.len);
    defer t.allocator.free(payload);
    const decoded = try @import("getter.zig").decode(
        GetRequest.blob(hash), tree.size, hash, writer.buffered(), payload,
    );
    try t.expectEqualSlices(u8, data, payload[0..decoded.written]);

    // A hash nobody stored: the writer is untouched, which is what "closes
    // just that stream with nothing written" means at this layer.
    var missed: [64]u8 = undefined;
    var miss_writer = std.Io.Writer.fixed(&missed);
    const absent = try provider.answer(t.io, &miss_writer, GetRequest.blob(@splat(0x99)));
    try t.expectEqual(.absent, absent);
    try t.expectEqual(@as(usize, 0), miss_writer.buffered().len);
}

// The answer for a partial request is byte for byte the plan's own encoding
// over the same range. That is the pin on both paths this file takes at once:
// the outboard parents read out of the file, the pairs below a group recomputed
// from the data, and the data item between them, all in plan order.
test "a partial range is the plan's own encoding, pairs in preorder" {
    const data = try published.blake3Input(49153);
    defer t.allocator.free(data);
    const tree = BaoTree.init(data.len);
    const hash: store.Hash = try tree.rootHash(data);

    var tmp = try @import("test_scratch").tmpDir(.{});
    defer tmp.cleanup();
    try putBlob(tmp.dir, hash, data);

    const plan = plan_mod.planOf(tree, off_group);
    const expected = try t.allocator.alloc(u8, plan.bytes);
    defer t.allocator.free(expected);
    const expected_len = try encode_mod.encode(plan, tree, data, expected);

    var name_storage: store.NameStorage = undefined;
    var scratch: [1024]u8 = undefined;
    const provider = try Provider.init(tmp.dir, &name_storage, hash, &scratch);

    const answer = try t.allocator.alloc(u8, expected.len + 8);
    defer t.allocator.free(answer);
    var writer = std.Io.Writer.fixed(answer);
    const request = off_groupFor(hash);
    try t.expectEqual(.answered, try provider.answer(t.io, &writer, request));
    try t.expectEqualSlices(u8, expected[0..expected_len], writer.buffered()[8..]);
}

// Corrupt persisted pairs cannot produce a successfully completed response.
test "an invalid outboard parent aborts the provider response" {
    const data = try published.blake3Input(49153);
    defer t.allocator.free(data);
    const tree = BaoTree.init(data.len);
    const hash: store.Hash = try tree.rootHash(data);

    var tmp = try @import("test_scratch").tmpDir(.{});
    defer tmp.cleanup();
    try putBlob(tmp.dir, hash, data);

    // Damage the committed outboard under the provider's feet. A bit in the
    // first pair, which the off-group plan asks for first.
    var name_storage: store.NameStorage = undefined;
    const paths = store.names(&name_storage, hash);
    var damaged = try readAll(t.io, tmp.dir, paths.outboard);
    defer t.allocator.free(damaged);
    damaged[0] ^= 0x01;
    var outboard = try tmp.dir.createFile(t.io, paths.outboard, .{ .truncate = true });
    try outboard.writeStreamingAll(t.io, damaged);
    outboard.close(t.io);

    var scratch: [1024]u8 = undefined;
    const provider = try Provider.init(tmp.dir, &name_storage, hash, &scratch);
    var answer: [1024 * 3]u8 = undefined;
    var writer = std.Io.Writer.fixed(&answer);
    try t.expectError(error.InvalidOutboard, provider.answer(t.io, &writer, off_groupFor(hash)));
}

// Both refusals the store's shape forces: an unbounded hash sequence, and a
// spec with two disjoint selected spans. Neither is an error, and neither
// writes a byte — a partial answer here would be bytes on the wire with no
// meaning a getter could act on.
test "a walk this store cannot take is refused, not half-answered" {
    const data = try published.blake3Input(49153);
    defer t.allocator.free(data);
    const tree = BaoTree.init(data.len);
    const hash: store.Hash = try tree.rootHash(data);

    var tmp = try @import("test_scratch").tmpDir(.{});
    defer tmp.cleanup();
    try putBlob(tmp.dir, hash, data);

    var name_storage: store.NameStorage = undefined;
    var scratch: [1024]u8 = undefined;
    const provider = try Provider.init(tmp.dir, &name_storage, hash, &scratch);

    // `GetRequest.all`: one spec and no terminator, so the walk never ends.
    try t.expectEqual(.absent, try expectNothingWritten(provider, GetRequest.all(hash)));

    // Two selected runs with a gap between them: skip two, take four, skip
    // three, take one. The spans resolve to `[2, 6)` and `[9, 10)`, and one
    // `ChunkRange` cannot name both without also naming the gap.
    const gapped = [_]range_spec.Item{
        .{ .delta = 0, .spec = .{ .widths = &.{ 2, 4, 3, 1 } } },
        .{ .delta = 1, .spec = range_spec.RangeSpec.empty },
    };
    try t.expectEqual(.absent, try expectNothingWritten(provider, .{
        .hash = hash,
        .ranges = .{ .items = &gapped },
    }));
}

// A request for another blob is a miss, not a failure: one provider is one
// blob and a peer may ask it about anything. Both refusals must leave the
// writer exactly as they found it.
fn expectNothingWritten(provider: Provider, request: GetRequest) !Outcome {
    var answer: [64]u8 = undefined;
    var writer = std.Io.Writer.fixed(&answer);
    const outcome = try provider.answer(t.io, &writer, request);
    try t.expectEqual(@as(usize, 0), writer.buffered().len);
    return outcome;
}

/// The request that names `off_group` and nothing else, for the blob `hash`.
fn off_groupFor(hash: store.Hash) GetRequest {
    return .{ .hash = hash, .ranges = .{ .items = &off_group_items } };
}

/// A blob written the way a store is written: into the partials, then promoted.
fn putBlob(dir: std.Io.Dir, hash: store.Hash, data: []const u8) !void {
    var name_storage: store.NameStorage = undefined;
    const paths = store.names(&name_storage, hash);
    const tree = BaoTree.init(data.len);
    const outboard = try t.allocator.alloc(u8, outboard_length(tree));
    defer t.allocator.free(outboard);
    const outboard_len = try outboard_mod.encode(tree, data, outboard);
    const partial = try store.createPartial(t.io, dir, paths);
    try partial.data.writeStreamingAll(t.io, data);
    try partial.outboard.writeStreamingAll(t.io, outboard[0..outboard_len]);
    partial.close(t.io);
    try store.commit(t.io, dir, paths);
}

/// A buffer exactly the outboard's own length, so a test never has to guess
/// how big one is.
fn outboard_length(tree: BaoTree) usize {
    return @intCast(outboard_mod.bytes(tree));
}

fn readAll(io: std.Io, dir: std.Io.Dir, path: []const u8) ![]u8 {
    const file = try dir.openFile(io, path, .{});
    defer file.close(io);
    const length: usize = @intCast(try file.length(io));
    const bytes = try t.allocator.alloc(u8, length);
    errdefer t.allocator.free(bytes);
    _ = try file.readPositionalAll(io, bytes, 0);
    return bytes;
}
