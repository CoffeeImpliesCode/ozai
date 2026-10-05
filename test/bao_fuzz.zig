//! Fuzz target for the Bao proof walk: `bao_proof_verify.zig` against
//! `bao_proof_encode.zig`, over a plan from `bao_plan.zig`.
//!
//! One target file and one corpus directory per decoder: `zig build fuzz`
//! replays the corpus, and `zig build fuzz --fuzz=<N>` hands the same corpus
//! to Zig's coverage-guided fuzzer and lets it mutate for N iterations.
//!
//! **The decoders are the production ones, reached through the `ozai` module
//! and not re-derived here.** A fuzz target carrying its own copy of the walk
//! would prove something about the copy: the property this file exists to
//! establish is that `verify` answers every byte a peer sends with a decision,
//! and only the production `verify` is the thing a peer will meet. So the four
//! imports below are the four facades and every call below is a call into one
//! of them.
//!
//! # What is checked, and why there are two halves
//!
//! A proof is a walk of the tree over one blob, and every item the verifier
//! expects is fixed by the tree and the request before the first byte arrives.
//! So a peer controls the bytes and nothing else, and there are two things to
//! say about that:
//!
//! 1. **Arbitrary bytes are refused, by name.** A response that is not exactly
//!    the length the plan promised cannot be a proof of anything, so the walk
//!    must reach a decision, and must reach it with one of the eight names
//!    below. A panic, a read past the end of the response, or a walk that does
//!    not terminate is the finding this target exists for, and every oracle is
//!    written so that one of those three shows up as a failed run.
//! 2. **A real proof verifies, and a real round trip is a fixed point.** The
//!    bytes in this half are not literals: they are written by the production
//!    encoder, over a plan the production `planOf` built, for a request the
//!    fuzz bytes chose.
//!
//! # What is not pinned
//!
//! No byte of any Bao proof has been captured from the Rust `bao-tree` crate,
//! and `bao_tree.zig` says so in its own module comment. What these oracles
//! establish is that the walk is total and self-consistent: an encoder and a
//! verifier that agree, a plan that is a function of the request, and a named
//! refusal for everything else. Interoperability with that crate is unverified
//! here and is not claimed.

const std = @import("std");
const ozai = @import("ozai");
const bao_encode = ozai.bao_proof_encode;
const bao_plan = ozai.bao_plan;
const bao_verify = ozai.bao_proof_verify;
const blobs = ozai.blobs_protocol;
const t = std.testing;

const BaoTree = bao_plan.BaoTree;
const Plan = bao_plan.Plan;
const VerifyError = bao_verify.Error;
const ChunkRange = blobs.ChunkRange;
const pair_length = bao_plan.pair_length;

/// Seeds are the bytes a peer would send as a proof response.
///
/// The first four are shapes `bao_proof_verify.zig` has a rule for and which no
/// valid proof has: nothing at all, one byte, and a whole parent pair with
/// nothing under it and then one byte short. The rest are the interior of a
/// proof — a run of data bytes, a pair with a byte behind it, a non-zero pair —
/// so a mutation starts from something that reaches the comparison half of the
/// walk rather than only its length checks.
///
/// They are held inline rather than as `@embedFile`s under `test/corpus/bao/`,
/// because this slice was given exactly three files and a corpus directory
/// would be a fourth. The names in the comments on each line are the file names
/// a `test/corpus/bao/` carries for them.
const corpus = [_][]const u8{
    repeated(0x00, 0), // empty: no response at all
    &.{0x00}, // one_byte: a length no item of any plan has
    &.{0xff}, // one_byte_high: the other end of the same range
    repeated(0x00, pair_length), // bare_pair: a parent pair and nothing under it
    repeated(0x00, pair_length - 1), // short_pair: the same pair, one byte short
    repeated(0x5a, 32), // data_run: what a data node's own bytes look like
    repeated(0x00, pair_length + 1), // pair_trailing_byte: a pair and one byte after
    repeated(0x11, 16), // data_run_nonzero: a run no all-zero fill would produce
};

/// Long enough for a seed and for a mutated input to still reach a check it was
/// not grown for, and short enough that one run is bounded by the window rather
/// than by the fuzzer.
const input_buffer_len = 128;

/// The blob sizes a run walks, ascending.
///
/// Every shape `bao_tree.zig` has a rule for is here: no bytes at all, a blob
/// shorter than one chunk, one chunk exactly, a blob one byte into its second
/// chunk so the last chunk is short, and blobs either side of the sixteen-chunk
/// group line — sixteen chunks exactly (one group, so the root is a leaf), one
/// byte past it (two groups, the second short), and a fifth of a group again.
/// The last is the largest and it is what bounds every buffer below.
const sizes = [_]u64{ 0, 1, 1023, 1024, 1025, 16383, 16384, 16385, 20480 };

/// `sizes` at its widest, as a count.
const max_blob_size: usize = 20480;

/// The margin a proof buffer carries over the widest blob: a pair for every
/// partial node above it.
///
/// Sixteen pairs rather than the exact number, because the exact number is a
/// property of the tree and this buffer is a property of the fuzzer. A request
/// that needed more would be refused by `encode` as `error.BufferTooSmall`, a
/// declared error, so it reads as a finding rather than as an overflow.
const pair_margin = 16 * pair_length;

/// A buffer for the widest proof above, used for the encoded proof and for the
/// one written again beside it.
const proof_len = max_blob_size + pair_margin;

/// The names `bao_verify.Error` refuses with, in the order
/// `bao_proof_verify.zig` declares them. This is the record of what a peer may
/// be told, and `expectNamed` fails the run on anything outside it.
const refusal_names = [_][]const u8{
    "NoRangeRequested",
    "MalformedPlan",
    "ResponseTruncated",
    "TrailingBytes",
    "ProofIncomplete",
    "RootNotVerified",
    "RootMismatch",
    "ChildMismatch",
};

comptime {
    // A seed longer than the window the fuzzer reads into would be cut short on
    // its way to the oracle, and the length checks would never see the rest.
    for (corpus) |seed| std.debug.assert(seed.len <= input_buffer_len);

    // The list above is the error set, member for member and in order. A
    // refusal added there without a line here is a name a peer can be given that
    // this file has no record of, so it stops the build instead; a rename or a
    // reorder stops it too, which is the point of holding both.
    const fields = @typeInfo(VerifyError).error_set.fields;
    if (fields.len != refusal_names.len) {
        @compileError("the proof verifier gained or lost a refusal");
    }
    for (fields, 0..) |field, index| {
        if (!std.mem.eql(u8, field.name, refusal_names[index])) {
            @compileError("a proof refusal was renamed, moved, or is not listed");
        }
    }
}

/// The fuzzer keeps one of these by pointer for the whole run, so it is empty by
/// design: everything the oracle needs is comptime.
const Context = struct {};

test "bao proof decode" {
    // A fuzz test is a plain test to a plain build. Without `-ffuzz` the runner
    // walks the corpus instead of handing it to the fuzzer, which is what makes
    // a bare `zig build fuzz` a bounded gate rather than an empty step.
    try t.fuzz(Context{}, testOne, .{ .corpus = &corpus });
}

fn testOne(_: Context, smith: *t.Smith) anyerror!void {
    var buffer: [input_buffer_len]u8 = undefined;
    // `in` is the corpus entry verbatim while the corpus is replayed, and null
    // when the fuzzer drives, in which case `slice` consumes its input.
    const bytes = if (smith.in) |replay| replay else buffer[0..smith.slice(&buffer)];
    var blob: [max_blob_size]u8 = undefined;
    var proof: [proof_len]u8 = undefined;
    var again: [proof_len]u8 = undefined;
    try check(bytes, &blob, &proof, &again);
}

/// One walk, over a tree and a request the fuzz bytes chose.
fn check(
    bytes: []const u8,
    blob: *[max_blob_size]u8,
    proof: *[proof_len]u8,
    again: *[proof_len]u8,
) !void {
    // `tree.size` is a `u64` claim and a slice index is a count, so the length
    // the blob is cut to is narrowed here once rather than at each use.
    const size = sizes[byteAt(bytes, 0) % sizes.len];
    const tree = BaoTree.init(size);
    const blob_len: usize = @intCast(size);
    // The request runs one or two chunks past the blob on purpose: `planOf`
    // clips it, and that clip is the rule which makes
    // `RangeSpec.verified_size` mean what its name says, so a run that never
    // asked for more than it could get would never reach it.
    const start = byteAt(bytes, 1) % (tree.chunks() + 2);
    const request = ChunkRange{ .start = start, .end = start + byteAt(bytes, 2) % 40 };

    // A blob of the size the tree was cut for and of no other length, because
    // `rootHash` refuses any other and the walk hashes slices of this.
    fillBlob(blob[0..blob_len], byteAt(bytes, 3));
    const data = blob[0..blob_len];
    const root = try tree.rootHash(data);

    const plan = bao_plan.planOf(tree, request);
    if (plan.isEmpty()) {
        // Oracle: nothing asked for. A zero-width request names no chunk, so
        // `planOf` builds no walk for it and there is no proof to check. The
        // verifier says so before it looks at the response at all, which is why
        // the same bytes are refused here whatever they hold.
        try t.expectError(
            error.NoRangeRequested,
            bao_verify.verify(tree, request, root, bytes),
        );
        return;
    }

    const written = try bao_encode.encode(plan, tree, data, proof);
    try checkPlan(tree, plan, written);
    try checkWalk(tree, plan, root, proof[0..written]);
    try checkFixedPoint(plan, tree, data, proof[0..written], again);
    try checkTruncation(tree, plan, request, root, proof[0..written], byteAt(bytes, 4));
    try checkFlip(tree, request, root, proof[0..written], byteAt(bytes, 5));
    try checkWrongRoot(tree, request, root, proof[0..written], blob, data);
    try checkArbitrary(tree, request, root, proof[0..written], bytes);
}

/// The plan is a function of the tree and the request, and this is that rule as
/// a value: every node it names is inside the tree, and its item lengths add up
/// to the proof it promised.
fn checkPlan(tree: BaoTree, plan: Plan, written: usize) !void {
    // Oracle: capacity. A plan is at most `max_items`, which is a depth bound
    // above it and not a number any request can push past.
    try t.expect(plan.len <= bao_plan.max_items);
    var total: usize = 0;
    for (plan.items[0..plan.len], 0..) |item, index| {
        // Oracle: bounds. Every node the plan names lies inside the tree, and
        // that is what makes `start_chunk * 1024` unable to overflow and a
        // node's byte range in bounds. `Verifier.init` checks the same thing of
        // a plan handed to it, and a `planOf` plan cannot fail it.
        try t.expect(item.node().endChunk() <= tree.chunks());
        total += plan.itemBytes(tree, index);
    }
    // Oracle: size. `plan.bytes` is the length the proof is, for every request
    // and every tree above, so a mismatch is either a walk that consumed a
    // different number of items than it wrote or a buffer that was too small.
    try t.expectEqual(plan.bytes, total);
    try t.expectEqual(plan.bytes, written);
}

/// The state machine under `verify`, walked the way a streaming caller walks it:
/// one item at a time, each length asked of `want` rather than taken on trust.
///
/// `root` is `anytype` because it is the chaining value `tree.rootHash`
/// returns, and naming that type here would restate a width this file does not
/// otherwise need; the call into `verify` is what binds it.
fn checkWalk(tree: BaoTree, plan: Plan, root: anytype, proof: []const u8) !void {
    var machine = try bao_verify.Verifier.init(tree, plan, root);
    var at: usize = 0;
    while (machine.want()) |needed| {
        // Oracle: the walk reads the response at the offset it left behind. A
        // machine wanting more than the response holds would read past it, so
        // the bound is stated here as well as relied on.
        try t.expect(at + needed <= proof.len);
        try machine.take(proof[at..][0..needed]);
        at += needed;
    }
    try t.expectEqual(proof.len, at);
    // Oracle: extent, in both directions. The plan is spent and the response is
    // used up, so `take` has nothing left to ask for and every byte it is given
    // is one too many. A skip carries no bytes, so this is reachable on a plan
    // ending in a skip as well as on one ending in data.
    try t.expectError(error.TrailingBytes, machine.take(&.{}));
    try t.expectError(error.TrailingBytes, machine.take(&.{0x00}));
    try machine.finish();
    // Oracle: the root was compared. `finish` is the only thing that sets this,
    // so a value that is true here says the walk settled the question rather
    // than running out of plan.
    try t.expect(machine.root_verified);
}

/// The encoder written twice out of two buffers: the same plan over the same
/// tree and the same blob must produce the same bytes.
fn checkFixedPoint(
    plan: Plan,
    tree: BaoTree,
    data: []const u8,
    proof: []const u8,
    again: *[proof_len]u8,
) !void {
    const rewritten = try bao_encode.encode(plan, tree, data, again);
    try t.expectEqualSlices(u8, proof, again[0..rewritten]);
}

/// Every prefix of a real proof is refused, and which refusal it is depends on
/// where the prefix stopped.
fn checkTruncation(
    tree: BaoTree,
    plan: Plan,
    request: ChunkRange,
    root: anytype,
    proof: []const u8,
    seed: u8,
) !void {
    // A plan for a request that selects a chunk always carries at least one byte
    // of data: a skip is only ever pushed for a node the request does not
    // touch, so a walk that selects something pushes data for it.
    std.debug.assert(proof.len > 0);
    const cut = atOffset(proof.len, seed);
    const err = bao_verify.verify(tree, request, root, proof[0..cut]) catch |failure| failure;
    // Oracle: stopped inside an item, or stopped on one. The two are different
    // errors on purpose — "the response stopped" and "the response stopped
    // mid-item" are two facts and one of them being lost would be a bug — and
    // this is what says which of the two a given cut is answered with.
    if (isItemBoundary(tree, plan, cut)) {
        try t.expectEqual(error.ProofIncomplete, err);
    } else {
        try t.expectEqual(error.ResponseTruncated, err);
    }
}

/// One flipped byte in a real proof. Every refusal here is a disagreement
/// between one computed value and one claimed value, so the answer is one of
/// two names whatever byte the flip landed in.
fn checkFlip(
    tree: BaoTree,
    request: ChunkRange,
    root: anytype,
    proof: []u8,
    seed: u8,
) !void {
    const at = atOffset(proof.len, seed);
    proof[at] ^= 0x80;
    const err = bao_verify.verify(tree, request, root, proof) catch |failure| failure;
    proof[at] ^= 0x80;
    // Oracle: one disagreement, one answer. A flipped data byte and a flipped
    // byte inside a parent pair are the same event at the moment of comparison,
    // which is why `bao_proof_verify.zig` names them the same way. A third
    // answer would mean the walk stopped for some reason other than the
    // comparison, which is the bug this oracle exists to catch.
    try t.expect(err == error.ChildMismatch or err == error.RootMismatch);
}

/// The same proof against a root that is not this blob's.
fn checkWrongRoot(
    tree: BaoTree,
    request: ChunkRange,
    root: anytype,
    proof: []const u8,
    blob: *[max_blob_size]u8,
    data: []const u8,
) !void {
    // A plan is only built for a size the tree holds, so a non-empty plan means
    // at least one byte of data and there is a byte to change.
    std.debug.assert(data.len > 0);
    blob[0] ^= 0x01;
    const other = try tree.rootHash(data);
    blob[0] ^= 0x01;
    // Oracle: which blob. Everything the peer sent agreed with itself and the
    // root it reaches belongs to somebody else, which is the one failure here
    // that is not an attack. It is a different answer from every refusal a
    // fuzzer reaches by mutating the proof, and it is what a caller is told for
    // a proof of the wrong blob rather than a broken one.
    try t.expectError(error.RootMismatch, bao_verify.verify(tree, request, other, proof));
    // And the trust did not move: the same bytes against the root the caller
    // already held still verify.
    try bao_verify.verify(tree, request, root, proof);
}

/// The fuzz bytes offered as a whole response.
fn checkArbitrary(
    tree: BaoTree,
    request: ChunkRange,
    root: anytype,
    proof: []const u8,
    bytes: []const u8,
) !void {
    if (bytes.len == proof.len) return;
    // Oracle: a decision, and a named one. The plan fixes every item's length
    // before the first byte is looked at, so a response of another length cannot
    // be a proof of this request whatever it holds, and the walk must refuse it.
    // `verify` is typed `Error!void` with the eight names above, so this catch
    // binds a member of that set and nothing else — an undeclared error, a
    // silent default and a fault cannot reach here — and `expectNamed` is what
    // holds the refusal to the list the module documents.
    if (bao_verify.verify(tree, request, root, bytes)) |_| {
        return error.FaultyProofVerified;
    } else |err| {
        try expectNamed(err);
    }
}

/// Whether `at` is where an item of the plan ends, which is where "the response
/// stopped" is not the same claim as "the response stopped inside an item".
fn isItemBoundary(tree: BaoTree, plan: Plan, at: usize) bool {
    if (at == 0) return true;
    var walked: usize = 0;
    for (plan.items[0..plan.len], 0..) |_, index| {
        walked += plan.itemBytes(tree, index);
        if (walked == at) return true;
    }
    return false;
}

/// That `err` is one of the names `bao_proof_verify.zig` documents.
fn expectNamed(err: VerifyError) !void {
    for (refusal_names) |name| {
        if (std.mem.eql(u8, name, @errorName(err))) return;
    }
    std.debug.print("bao fuzz: a refusal the list does not name: {s}\n", .{
        @errorName(err),
    });
    return error.UnnamedRefusal;
}

/// `count` copies of `byte`. A run longer than a line or two is a run, and
/// writing it out as a list would say nothing the name does not.
fn repeated(comptime byte: u8, comptime count: usize) []const u8 {
    comptime var out: [count]u8 = undefined;
    for (&out) |*slot| slot.* = byte;
    return &out;
}

/// An offset into a buffer of `len` bytes, chosen by a seed byte. The
/// conversion is spelled out because the seed is a `u8` and an offset is a
/// count, and the two meeting in a `%` is where the widths would otherwise be
/// left to a peer type resolution.
fn atOffset(len: usize, seed: u8) usize {
    return @as(usize, seed) % len;
}

/// `bytes` at `index`, or zero past its end. A seed shorter than a table index
/// is a case and not a fault, and zero is a value every table here has an entry
/// for.
fn byteAt(bytes: []const u8, index: usize) u8 {
    return if (index < bytes.len) bytes[index] else 0;
}

/// `out` filled with a repeating pattern seeded by `tag`, so two blobs of one
/// size that differ anywhere differ in their root — which is what the
/// wrong-root oracle needs and what a constant fill would not give it.
fn fillBlob(out: []u8, tag: u8) void {
    // `@truncate` needs a result type of its own, and this is the only place in
    // the file that needs a step at all: two blobs of one size differ in their
    // root because of this pattern and because of nothing else.
    for (out, 0..) |*byte, index| byte.* = tag ^ @as(u8, @truncate(index *% 7 +% 3));
}