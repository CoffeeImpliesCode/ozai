//! Answering a decoded `GetRequest` out of the store.
//!
//! The answer to a `get` is bao data and nothing else: no length prefix, no
//! size prefix, no error frame. `framing.zig` argues that at length and
//! `responses.zig` applies it, so what is left for this file is the bytes
//! themselves and the one way to refuse.
//!
//! # What the answer is
//!
//! Preorder. `bao_plan.planOf` fixes the walk before a byte is read, and every
//! item of that plan contributes its bytes in plan order: a `.pair` item
//! contributes `pair_length` bytes of its children's values, a `.data` item
//! contributes the node's own bytes, and a `.skip` item contributes none. A
//! request for every chunk of a blob therefore has a one-item plan and its
//! answer is the blob — which is why a whole-blob answer needs no header to be
//! read, and why nothing here writes one.
//!
//! A pair comes out of the outboard when its node is an outboard parent, and is
//! computed from the data when it is not. That split is the whole reason a
//! store holds two files: `bao_outboard.encode` writes the pairs of the
//! outboard parents and no others, and a plan that is not group-aligned asks
//! for pairs below a group as well. The outboard index advances only on an
//! outboard parent, which is what keeps it the index into the file `encode`
//! wrote.
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

        const tree = BaoTree.init(try handles.data.length(t.io));
        const selected = selectedRange(request, tree.chunks()) orelse return .absent;
        const plan = plan_mod.planOf(tree, selected);
        if (plan.isEmpty()) return .absent;
        try writePlan(self, io, writer, &handles, tree, plan);
        return .answered;
    }
};

/// The one contiguous chunk range `request` names, or null when it does not
/// name exactly one.
///
/// `GetRequest.blob`'s sequence is one selected spec at delta zero and an
/// empty spec at delta one, and that terminator is what ends the walk. Two
/// spans resolve to a range with a gap in it, which is not what the spec
/// asked for, so they are refused rather than closed up.
///
/// `getter.zig` resolves the same range through this function, because a
/// getter that resolved it differently would build a different plan and
/// refuse an answer the provider meant.
pub fn selectedRange(request: GetRequest, total_chunks: u64) ?ranges.ChunkRange {
    const items = request.ranges.items;
    if (items.len != 2) return null;
    if (items[0].delta != 0) return null;
    if (items[1].delta != 1 or !items[1].spec.isEmpty()) return null;

    var walk = items[0].spec.resolve(total_chunks);
    const first = walk.next() orelse return null;
    const second = walk.next() orelse return .{
        .start = first.offset,
        .end = first.offset + first.size,
    };
    // Two spans that do not touch are two selected runs with a deselected gap
    // between them, and closing that gap up would answer for chunks the spec
    // refused. A third span is refused for the same reason.
    if (second.offset != first.offset + first.size) return null;
    if (walk.next() != null) return null;
    return .{ .start = first.offset, .end = second.offset + second.size };
}

/// Write every item of `plan`, in plan order.
fn writePlan(
    provider: *const Provider,
    io: std.Io,
    writer: *std.Io.Writer,
    handles: *const store.Handles,
    tree: BaoTree,
    plan: plan_mod.Plan,
) Error!void {
    var outboard_index: u64 = 0;
    var pair: [pair_length]u8 = undefined;
    for (plan.items[0..plan.len]) |item| switch (item) {
        .skip => {},
        .data => |node| try runRange(
            io,
            handles.data,
            node.bytes(tree),
            provider.scratch,
            &.{ .answer = writer },
        ),
        .pair => |node| {
            if (node.isOutboardParent()) {
                _ = try handles.outboard.readPositionalAll(
                    io,
                    &pair,
                    outboard_index * pair_length,
                );
                outboard_index += 1;
            } else {
                try computePair(io, handles.data, tree, node, provider.scratch, &pair);
            }
            try writer.writeAll(&pair);
        },
    };
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

// A whole-blob answer is the blob. Nothing is prepended, because the plan of
// every chunk is the root and the root's own bytes are the answer; and a blob
// the store does not have is answered with nothing, which is the one refusal a
// getter can read without hashing anything.
test "a whole blob is answered with its own bytes, and a miss with none" {
    const data = try published.blake3Input(49153);
    defer t.allocator.free(data);
    const tree = BaoTree.init(data.len);
    const hash: store.Hash = try tree.rootHash(data);

    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    try putBlob(tmp.dir, hash, data);

    var name_storage: store.NameStorage = undefined;
    var scratch: [1024]u8 = undefined;
    const provider = try Provider.init(tmp.dir, &name_storage, hash, &scratch);

    const answer = try t.allocator.alloc(u8, data.len);
    defer t.allocator.free(answer);
    var writer = std.Io.Writer.fixed(answer);
    try t.expectEqual(.answered, try provider.answer(t.io, &writer, GetRequest.blob(hash)));
    try t.expectEqualSlices(u8, data, writer.buffered());

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

    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    try putBlob(tmp.dir, hash, data);

    const plan = plan_mod.planOf(tree, off_group);
    const expected = try t.allocator.alloc(u8, plan.bytes);
    defer t.allocator.free(expected);
    const expected_len = try encode_mod.encode(plan, tree, data, expected);

    var name_storage: store.NameStorage = undefined;
    var scratch: [1024]u8 = undefined;
    const provider = try Provider.init(tmp.dir, &name_storage, hash, &scratch);

    const answer = try t.allocator.alloc(u8, expected.len);
    defer t.allocator.free(answer);
    var writer = std.Io.Writer.fixed(answer);
    const request = off_groupFor(hash);
    try t.expectEqual(.answered, try provider.answer(t.io, &writer, request));
    try t.expectEqualSlices(u8, expected[0..expected_len], writer.buffered());
}

// The pairs come out of the outboard file and not out of a recomputation of the
// data. A flipped byte in the stored outboard therefore reaches the answer,
// which is the observable half of that claim: recomputation would have
// answered the truth and hidden the damage.
test "an outboard parent is read from the file, not recomputed" {
    const data = try published.blake3Input(49153);
    defer t.allocator.free(data);
    const tree = BaoTree.init(data.len);
    const hash: store.Hash = try tree.rootHash(data);

    var tmp = t.tmpDir(.{});
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
    try t.expectEqual(.answered, try provider.answer(t.io, &writer, off_groupFor(hash)));
    try t.expectEqualSlices(u8, damaged[0..pair_length], writer.buffered()[0..pair_length]);
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

    var tmp = t.tmpDir(.{});
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
