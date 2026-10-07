//! Interrupted transfers: what a `.partial` on disk is, and whether it may be
//! written to again.
//!
//! `store.zig` owns the four names and the one commit point, and its module doc
//! says the last line of it: "Every byte written through this module lands
//! under `.partial`, which is a name on disk, and `resume.zig` finds it there."
//! This file is that half. It opens what a dead writer left, decides whether the
//! bytes in it may be written to again, and leaves the store in exactly one of
//! two states: a prefix that has been **verified** and is safe to append to, or
//! no partial at all.
//!
//! # The decision: verified, or discarded
//!
//! **A partial is resumed only where it has been verified against a value the
//! caller holds out of band. Everywhere else it is discarded, and the blob is
//! written again from the beginning.** There is no third answer, and there is
//! no case where a stored number is believed.
//!
//! Three facts force that, and each one is a corruption path if it is ignored.
//!
//! 1. **A file's length is not a claim about which bytes are in it.** It is a
//!    claim about how many were written, by a writer that may have died between
//!    the write and the length becoming durable. Resuming at `length` means
//!    asserting that the first `length` bytes are the blob's first `length`
//!    bytes, and nothing on disk says so.
//! 2. **The two halves do not advance together.** `store.createPartial` opens
//!    both and `store.commit` renames the outboard first, so a writer that died
//!    can leave a data partial and an outboard partial describing different
//!    amounts of the same transfer. The outboard's length is therefore not a
//!    second opinion about the data's, and this file reads only the data.
//! 3. **The root hash authenticates the whole blob and nothing below it.**
//!    `BaoTree.rootHash` walks the whole range with ROOT set. There is no
//!    shorter input a caller can be handed that says "these first `n` bytes are
//!    this blob's first `n` bytes".
//!
//! So the resume point is not a length. It is a `Checkpoint`: an offset, the
//! declared size it means, and the subtree chaining value of the bytes below
//! that offset. All three come from outside the store — the caller already held
//! them, or got them from the peer in the exchange that carried those bytes.
//!
//! ## What must be persisted, and what must be verified
//!
//! * **The offset.** Chunk-aligned, because `subtree.Hasher.init` refuses an
//!   offset that names no subtree (`Error.OffsetNotChunkAligned`). A
//!   non-aligned offset is `.unaligned` and the partial is discarded.
//! * **The chaining value of the prefix.** This is the check. The bytes on disk
//!   are re-hashed as a subtree and compared; a single flipped byte anywhere
//!   below the offset changes that value and the resume is refused.
//! * **The declared size.** The offset means nothing without it: a tree is cut
//!   for one size, so the same byte count is a different node in a tree of
//!   another size. This is the size-disagreement case, below.
//! * **Durability, which is the caller's.** A checkpoint is worth exactly as
//!    much as the bytes were synced before it was written down. This file reads
//!    no clock and calls no `sync`; `File.sync` is the writer's, and a record
//!    kept beside unsynced bytes names bytes that may never have reached the
//!    disk.
//!
//! ## What happens when the sizes disagree
//!
//! **The partial is discarded, both halves, and the fault is
//! `.size_disagreement`.** `Checkpoint.size` is not the size the blob is being
//! resumed at, so the offset in the checkpoint names a node of a tree that is
//! not this one, and the chaining value beside it was taken against a different
//! set of byte ranges.
//!
//! The tempting alternative is to trust whichever number is larger, or to
//! resume at `min(recorded, actual)`. Both are worse than starting over. The
//! bytes are refetchable and a wrong blob is not, and the record is the only
//! thing anywhere that says which size these bytes were taken at — so a record
//! that disagrees with the blob is a record about nothing, and the bytes it
//! describes cannot be attributed to any tree. Leaving them in place would
//! mean the next caller has to make that same judgement about a file whose only
//! description is the caller's own.
//!
//! # The outboard is emptied, never resumed
//!
//! Nothing above says where in the transfer the outboard had got to. A resume
//! therefore truncates the outboard partial to nothing and the caller writes
//! it whole beside the data it appends. The provider validates stored pairs
//! before completing a response, but rebuilding here avoids committing a stale
//! outboard that would abort every later transfer.
//!
//! # Purity
//!
//! `io: std.Io` is a parameter of every call and is stored nowhere; `alloc` is
//! not taken because nothing here allocates; no clock, no environment and no
//! global. Every buffer is the caller's, and the two descriptors `Outcome`
//! hands back are the pair `store.Handles` already defines.

const std = @import("std");
const core = @import("../crypto/blake3_core.zig");
const subtree = @import("../crypto/blake3_subtree.zig");
const tree_mod = @import("bao_tree.zig");
const store = @import("store.zig");

/// The tree a partial is cut for. `bao_tree.zig` owns it; this file only spells
/// it, for the reason `store.zig` gives for spelling `Hash`.
pub const BaoTree = tree_mod.BaoTree;

/// The blob's root hash, which is what a prefix is checked against.
pub const Hash = store.Hash;

const chunk_size = tree_mod.chunk_size;

/// Everything that can stop a resume being decided.
pub const Error = std.Io.File.OpenError ||
    std.Io.Dir.DeleteFileError ||
    std.Io.File.LengthError ||
    std.Io.File.SetLengthError ||
    std.Io.File.ReadPositionalError ||
    subtree.Error ||
    error{
        /// `scratch` was empty. Streaming needs at least one byte, and
        /// `provider.zig` refuses the same thing under the same name.
        NoScratch,
    };

/// What the two partials held when they were looked at, in bytes.
///
/// A half that is not there is zero, so the pair reads as "how far this
/// transfer had got" without a second optional.
pub const Found = struct {
    data_bytes: u64 = 0,
    outboard_bytes: u64 = 0,
};

/// Why a partial is not resumable.
///
/// One arm per fact, because a caller that logs one wants to know which of them
/// it was: the first three say a record and a file disagree, and the last says
/// the bytes are not the blob's.
pub const Fault = enum {
    /// The offset is not on a chunk boundary, so it names no subtree and the
    /// chaining value beside it is a hash of nothing.
    unaligned,
    /// The checkpoint's declared size is not the size the blob is being resumed
    /// at. See the module doc.
    size_disagreement,
    /// The partial holds fewer bytes than the checkpoint's offset, so the
    /// record is ahead of the bytes it describes.
    short,
    /// The bytes on disk do not hash to the checkpoint's chaining value: they
    /// are not the blob's prefix, whatever their length says.
    unverified,
};

/// A resume point, held outside the store.
///
/// The value a writer keeps beside a transfer it is part way through. It is not
/// produced here and it is not read from the store: the store holds no record
/// of one, which is the whole of the module doc's decision.
pub const Checkpoint = struct {
    /// The size the tree was cut for. Disagreeing with the blob being resumed
    /// discards the partial; see `Fault.size_disagreement`.
    size: u64,
    /// Where the bytes stop. Chunk-aligned, and the prefix's length.
    at: u64,
    /// The subtree chaining value of `[0, at)`, which is what makes `at`
    /// checkable.
    cv: core.CvBytes,
};

/// What a resume decided, and what the caller may now write through.
///
/// Both partials are open read/write whatever the answer is, so the caller's
/// shape is one `defer handles.close(io)` and one loop.
pub const Outcome = struct {
    /// The pair, open for writing. `at` is zero when nothing was resumed.
    handles: store.Handles,
    /// The verified prefix's length: where the caller appends. Zero means the
    /// whole blob is written, which is the answer when the store was empty and
    /// the answer when a partial was refused.
    at: u64,
    /// Why nothing is resumable, when a partial was there and could not be
    /// used. Null when the store held no partial, which is not a failure: a
    /// first write is `at == 0` and no fault.
    fault: ?Fault,
    /// What the partials held when they were looked at. Kept so a caller can
    /// tell "there was nothing" from "there was something and it was refused"
    /// without reading `at`.
    found: Found,
};

/// Look at the two partials and say how many bytes each holds.
///
/// Changes nothing. Both halves are stat'd through an open and a close, so a
/// store with no partial costs one failed open per half and no descriptors are
/// held when this returns.
pub fn inspect(io: std.Io, dir: std.Io.Dir, paths: store.Names) Error!Found {
    return .{
        .data_bytes = try lengthOf(io, dir, paths.data_partial),
        .outboard_bytes = try lengthOf(io, dir, paths.outboard_partial),
    };
}

/// Settle an interrupted transfer: decide what the bytes on disk are, and
/// leave the store ready to be written to.
///
/// The store comes out in exactly one of two states: `at` is the verified
/// prefix and the caller appends to it, or `at` is zero, both partials are
/// empty, and the caller writes the blob again. There is no path that leaves an
/// unverified partial behind, and none that leaves a caller without the
/// descriptors to write through.
///
/// `scratch` is the caller's and only has to be one byte long; it is a
/// throughput knob. Both it and the descriptors in `Outcome` must outlive the
/// writes the caller makes.
pub fn settle(
    io: std.Io,
    dir: std.Io.Dir,
    paths: store.Names,
    tree: BaoTree,
    checkpoint: Checkpoint,
    scratch: []u8,
) Error!Outcome {
    const found = try inspect(io, dir, paths);
    if (found.data_bytes == 0) return fresh(io, dir, paths, found);
    if (scratch.len == 0) return error.NoScratch;
    if (checkpoint.size != tree.size) return restart(io, dir, paths, found, .size_disagreement);
    if (checkpoint.at % chunk_size != 0) return restart(io, dir, paths, found, .unaligned);
    if (checkpoint.at > found.data_bytes) return restart(io, dir, paths, found, .short);
    const matched = try prefixMatches(io, dir, paths, checkpoint, scratch);
    if (!matched) return restart(io, dir, paths, found, .unverified);
    return adopt(io, dir, paths, found, checkpoint.at);
}

/// Nothing was started, so there is nothing to verify and nothing to throw
/// away. A first write is not a fault.
fn fresh(
    io: std.Io,
    dir: std.Io.Dir,
    paths: store.Names,
    found: Found,
) Error!Outcome {
    return .{
        .handles = try store.createPartial(io, dir, paths),
        .at = 0,
        .fault = null,
        .found = found,
    };
}

/// Fail closed: the partial goes, and the caller writes the blob again.
///
/// `store.discardPartials` is idempotent, so this is the same two unlinks a
/// caller would have made, and `store.createPartial` truncates, so the files
/// that come back are empty rather than absent.
fn restart(
    io: std.Io,
    dir: std.Io.Dir,
    paths: store.Names,
    found: Found,
    fault: Fault,
) Error!Outcome {
    try store.discardPartials(io, dir, paths);
    return .{
        .handles = try store.createPartial(io, dir, paths),
        .at = 0,
        .fault = fault,
        .found = found,
    };
}

/// Keep the verified prefix, empty the outboard, and hand both back open.
///
/// Data first and on purpose, for `store.openComplete`'s reason: the two halves
/// of a pair are opened under an `errdefer` so a failure on the second releases
/// the first, and which half is the one that can fail first is decided once, in
/// `store.zig`, rather than twice.
fn adopt(
    io: std.Io,
    dir: std.Io.Dir,
    paths: store.Names,
    found: Found,
    at: u64,
) Error!Outcome {
    const data = try dir.openFile(io, paths.data_partial, .{ .mode = .read_write });
    errdefer data.close(io);
    const outboard = try dir.openFile(io, paths.outboard_partial, .{ .mode = .read_write });
    errdefer outboard.close(io);
    // The data is cut back to the verified offset: the file may be longer, and
    // everything past the last byte anybody checked is bytes nobody checked.
    try data.setLength(io, at);
    // The outboard goes to nothing at all, for the module doc's reason.
    try outboard.setLength(io, 0);
    return .{
        .handles = .{ .data = data, .outboard = outboard },
        .at = at,
        .fault = null,
        .found = found,
    };
}

/// Whether `[0, checkpoint.at)` of the data partial hashes to `checkpoint.cv`.
///
/// One pass, and it re-hashes rather than comparing lengths: a length is what
/// a dead writer left behind, and a chaining value is what the caller was told.
/// A zero-length read is a refusal and not a hash of nothing, because the file
/// was stat'd above and a zero here means it was truncated underneath.
fn prefixMatches(
    io: std.Io,
    dir: std.Io.Dir,
    paths: store.Names,
    checkpoint: Checkpoint,
    scratch: []u8,
) Error!bool {
    const data = try dir.openFile(io, paths.data_partial, .{});
    defer data.close(io);
    var hasher = try subtree.Hasher.init(0);
    var at: u64 = 0;
    while (at < checkpoint.at) {
        const want: u64 = @min(scratch.len, checkpoint.at - at);
        const read = try data.readPositional(io, &.{scratch[0..@intCast(want)]}, at);
        if (read == 0) return false;
        hasher.update(scratch[0..read]);
        at += read;
    }
    return std.mem.eql(u8, &hasher.finalChainingValue(), &checkpoint.cv);
}

fn lengthOf(io: std.Io, dir: std.Io.Dir, path: []const u8) Error!u64 {
    const file = dir.openFile(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return 0,
        else => return err,
    };
    defer file.close(io);
    return file.length(io);
}

const t = std.testing;
const outboard_mod = @import("bao_outboard.zig");
const published = @import("../gossip/plumtree/blake3_vectors.zig");

/// A blob of `size` bytes over published BLAKE3 input, with the tree cut for
/// it and the root hash a caller could already have held out of band.
///
/// The size is 49153 because it is a boundary the other modules in this
/// directory test at: 49 chunks, four groups, and therefore an outboard of
/// three pairs — so a partial with both halves written is a real pair rather
/// than a data file beside an empty one.
fn blob(size: usize) !struct { data: []u8, tree: BaoTree, root: Hash } {
    const data = try published.blake3Input(size);
    const tree = BaoTree.init(data.len);

    return .{ .data = data, .tree = tree, .root = try tree.rootHash(data) };
}

/// Forty-eight chunks: a whole number of them, so a blob of that size has a
/// length that is itself a legal resume offset. See the test that uses it.
const whole_chunks = 48;

/// The chaining value of `data[0..at]`: what a checkpoint holds beside its
/// offset, and what `settle` re-derives from the file.
fn prefixCv(data: []const u8, at: usize) !core.CvBytes {
    var hasher = try subtree.Hasher.init(0);
    hasher.update(data[0..at]);
    return hasher.finalChainingValue();
}

/// A checkpoint that authorises nothing, for the cases where the store is
/// empty and the record is never read.
const nothing: Checkpoint = .{ .size = 0, .at = 0, .cv = @splat(0) };

// Nothing was started, so there is nothing to verify and nothing to throw
// away. A first write reports no offset and no fault, and the two files it
// leaves behind are the two `store.createPartial` names.
test "a store with no partial is a fresh write and not a fault" {
    const b = try blob(49153);
    defer t.allocator.free(b.data);
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var storage: store.NameStorage = undefined;
    const paths = store.names(&storage, b.root);

    try t.expectEqual(Found{}, try inspect(t.io, tmp.dir, paths));
    var scratch: [4096]u8 = undefined;
    var out = try settle(t.io, tmp.dir, paths, b.tree, nothing, &scratch);
    defer out.handles.close(t.io);

    try t.expectEqual(@as(u64, 0), out.at);
    try t.expectEqual(null, out.fault);
    try t.expectEqual(Found{}, out.found);
    try t.expectEqual(@as(u64, 0), try out.handles.data.length(t.io));
    try t.expectEqual(@as(u64, 0), try out.handles.outboard.length(t.io));
}

// The honest resume: a writer that died with the whole blob down and an
// outboard beside it. The offset is verified against the chaining value and
// the file is cut back to it, so the bytes above the last byte anybody checked
// are gone even though nobody asked for them to be. And the outboard goes to
// nothing: it was written in the same breath and nothing here checked it.
test "a verified prefix is kept and cut back to the offset that was checked" {
    const b = try blob(49153);
    defer t.allocator.free(b.data);
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var storage: store.NameStorage = undefined;
    const paths = store.names(&storage, b.root);

    const at: usize = 20 * 1024;
    const partial = try store.createPartial(t.io, tmp.dir, paths);
    try partial.data.writeStreamingAll(t.io, b.data);
    var outboard: [3 * tree_mod.pair_length]u8 = undefined;
    const outboard_len = try outboard_mod.encode(b.tree, b.data, &outboard);
    try partial.outboard.writeStreamingAll(t.io, outboard[0..outboard_len]);
    partial.close(t.io);

    var scratch: [4096]u8 = undefined;
    var out = try settle(t.io, tmp.dir, paths, b.tree, .{
        .size = b.tree.size,
        .at = at,
        .cv = try prefixCv(b.data, at),
    }, &scratch);
    defer out.handles.close(t.io);

    try t.expectEqual(@as(u64, at), out.at);
    try t.expectEqual(null, out.fault);
    try t.expectEqual(@as(u64, b.data.len), out.found.data_bytes);
    try t.expectEqual(@as(u64, outboard_len), out.found.outboard_bytes);
    // The prefix survives byte for byte, and nothing past it does.
    try t.expectEqual(@as(u64, at), try out.handles.data.length(t.io));
    var back: [at]u8 = undefined;
    const got = try out.handles.data.readPositionalAll(t.io, &back, 0);
    try t.expectEqual(@as(usize, at), got);
    try t.expectEqualSlices(u8, b.data[0..at], &back);
    try t.expectEqual(@as(u64, 0), try out.handles.outboard.length(t.io));
}

// The case the brief names. The checkpoint's size is not the blob's, so its
// offset names a node of a tree that is not this one and its chaining value
// was taken against a different set of ranges. Neither half survives: the
// bytes are refetchable and a wrong blob is not, and the record was the only
// description of which size these bytes were taken at.
test "a checkpoint for another size discards both halves" {
    const b = try blob(49153);
    defer t.allocator.free(b.data);
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var storage: store.NameStorage = undefined;
    const paths = store.names(&storage, b.root);

    const partial = try store.createPartial(t.io, tmp.dir, paths);
    try partial.data.writeStreamingAll(t.io, b.data);
    try partial.outboard.writeStreamingAll(t.io, b.data[0..32]);
    partial.close(t.io);

    var scratch: [4096]u8 = undefined;
    var out = try settle(t.io, tmp.dir, paths, b.tree, .{
        .size = b.tree.size + 1,
        .at = 1024,
        .cv = try prefixCv(b.data, 1024),
    }, &scratch);
    defer out.handles.close(t.io);

    try t.expectEqual(Fault.size_disagreement, out.fault.?);
    try t.expectEqual(@as(u64, 0), out.at);
    // Refused, not ignored: the bytes that were there are gone and the files
    // that come back are empty.
    try t.expectEqual(@as(u64, b.data.len), out.found.data_bytes);
    try t.expectEqual(@as(u64, 0), try out.handles.data.length(t.io));
    try t.expectEqual(@as(u64, 0), try out.handles.outboard.length(t.io));
}

// Three more refusals, one fact each. An offset off a chunk boundary names no
// subtree, so the chaining value beside it is a hash of nothing and there is
// nothing to compare; a record ahead of the bytes it describes is a record
// that outlived its file; and a flipped byte is the case the whole decision
// exists for, because its length is exactly right.
test "an unaligned offset, a record ahead of the bytes, and a flipped byte" {
    const b = try blob(49153);
    defer t.allocator.free(b.data);
    var scratch: [4096]u8 = undefined;

    const cases = [_]struct {
        name: []const u8,
        at: u64,
        cv: core.CvBytes,
        want: Fault,
    }{
        .{
            .name = "unaligned",
            .at = 1000,
            .cv = @splat(0),
            .want = .unaligned,
        },
        .{
            .name = "short",
            .at = 60 * 1024,
            .cv = @splat(0),
            .want = .short,
        },
        .{
            .name = "unverified",
            .at = 20480,
            .cv = try prefixCv(b.data, 20480),
            .want = .unverified,
        },
    };
    for (cases) |case| {
        var tmp = t.tmpDir(.{});
        defer tmp.cleanup();
        var storage: store.NameStorage = undefined;
        const paths = store.names(&storage, b.root);
        const partial = try store.createPartial(t.io, tmp.dir, paths);
        // One byte short of the blob's own, flipped in the middle of the range
        // the checkpoint claims: the length is right and the bytes are not.
        var damaged = try t.allocator.dupe(u8, b.data);
        defer t.allocator.free(damaged);
        damaged[100] ^= 0x01;
        try partial.data.writeStreamingAll(t.io, damaged);
        partial.close(t.io);

        var out = try settle(t.io, tmp.dir, paths, b.tree, .{
            .size = b.tree.size,
            .at = case.at,
            .cv = case.cv,
        }, &scratch);
        defer out.handles.close(t.io);
        try t.expectEqual(case.want, out.fault.?);
        try t.expectEqual(@as(u64, 0), out.at);
        try t.expectEqual(@as(u64, 0), try out.handles.data.length(t.io));
    }
}

// Streaming needs a byte to read into, and a caller that hands over none gets
// told rather than looped on. Refused only when there is a partial: the empty
// store never hashes anything, so an empty scratch is harmless there.
test "an empty scratch is refused only where a prefix would be hashed" {
    const b = try blob(49153);
    defer t.allocator.free(b.data);
    var storage: store.NameStorage = undefined;

    var empty = t.tmpDir(.{});
    defer empty.cleanup();
    const empty_paths = store.names(&storage, b.root);
    var out = try settle(t.io, empty.dir, empty_paths, b.tree, nothing, &.{});
    out.handles.close(t.io);

    var held = t.tmpDir(.{});
    defer held.cleanup();
    const held_paths = store.names(&storage, b.root);
    const partial = try store.createPartial(t.io, held.dir, held_paths);
    try partial.data.writeStreamingAll(t.io, b.data);
    partial.close(t.io);
    try t.expectError(
        error.NoScratch,
        settle(t.io, held.dir, held_paths, b.tree, .{
            .size = b.tree.size,
            .at = 1024,
            .cv = try prefixCv(b.data, 1024),
        }, &.{}),
    );
}

// A transfer that finished and died before the rename is the case worth
// keeping: the blob is whole, the checkpoint authorises every byte of it, and
// the store promotes it instead of asking a peer for bytes it already has. The
// outboard is emptied on the way, because nothing in this file verified it.
//
// Forty-eight chunks, so the blob's own length is a resume offset: an offset
// has to be chunk aligned, so a 49153-byte blob is *not* resumable at its end
// and would be written again from the start. The checkpoint's `cv` is the
// ROOT-clear subtree value of `[0, at)`, which `prefixCv` computes; `b.root` is
// the ROOT-set hash of the same bytes and is what the committed file is
// checked against at the end.
test "a whole blob verifies and promotes without a refetch" {
    const b = try blob(whole_chunks * chunk_size);
    defer t.allocator.free(b.data);
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var storage: store.NameStorage = undefined;
    const paths = store.names(&storage, b.root);

    const partial = try store.createPartial(t.io, tmp.dir, paths);
    try partial.data.writeStreamingAll(t.io, b.data);
    var outboard: [3 * tree_mod.pair_length]u8 = undefined;
    try partial.outboard.writeStreamingAll(t.io, outboard[0..try outboard_mod.encode(
        b.tree,
        b.data,
        &outboard,
    )]);
    partial.close(t.io);

    var scratch: [4096]u8 = undefined;
    var out = try settle(t.io, tmp.dir, paths, b.tree, .{
        .size = b.tree.size,
        .at = b.data.len,
        .cv = try prefixCv(b.data, b.data.len),
    }, &scratch);
    try t.expectEqual(@as(u64, b.data.len), out.at);
    try t.expectEqual(null, out.fault);
    try t.expectEqual(@as(u64, 0), try out.handles.outboard.length(t.io));
    out.handles.close(t.io);

    try store.commit(t.io, tmp.dir, paths);
    const handles = try store.openComplete(t.io, tmp.dir, paths);
    defer handles.close(t.io);
    try t.expectEqual(@as(u64, b.data.len), try handles.data.length(t.io));
    // And the promoted data is the blob: the trusted root is the one the
    // committed file reaches, hashed over the bytes that were read back.
    var back: [whole_chunks * chunk_size]u8 = undefined;
    const read = try handles.data.readPositionalAll(t.io, &back, 0);
    try t.expectEqual(@as(usize, back.len), read);
    try t.expectEqual(b.root, try b.tree.rootHash(back[0..read]));
}

// The two name sets never overlap, so settling a committed blob touches
// nothing: the partial names are absent, the committed pair is still whole,
// and settling again reports what an untouched store reports.
test "a committed blob is never touched by a settle" {
    const b = try blob(49153);
    defer t.allocator.free(b.data);
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var storage: store.NameStorage = undefined;
    const paths = store.names(&storage, b.root);

    const partial = try store.createPartial(t.io, tmp.dir, paths);
    try partial.data.writeStreamingAll(t.io, b.data);
    partial.close(t.io);
    try store.commit(t.io, tmp.dir, paths);

    var scratch: [4096]u8 = undefined;
    var out = try settle(t.io, tmp.dir, paths, b.tree, nothing, &scratch);
    try t.expectEqual(@as(u64, 0), out.at);
    try t.expectEqual(null, out.fault);
    out.handles.close(t.io);

    // The commit's names are untouched, and a second settle is the first one.
    const handles = try store.openComplete(t.io, tmp.dir, paths);
    defer handles.close(t.io);
    try t.expectEqual(@as(u64, b.data.len), try handles.data.length(t.io));
    var again = try settle(t.io, tmp.dir, paths, b.tree, nothing, &scratch);
    try t.expectEqual(out.at, again.at);
    try t.expectEqual(out.fault, again.fault);
    try t.expectEqual(out.found, again.found);
    again.handles.close(t.io);
}
