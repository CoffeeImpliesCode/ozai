//! Driving a `GetRequest` and judging the answer.
//!
//! The getter's whole job is to hand the answer to `bao_proof_verify` and
//! report what came back. It adds no rule of its own about what an answer may
//! contain, because a rule here would be a second opinion about bytes the
//! verifier has already decided how to read.
//!
//! # An empty answer is never judged here
//!
//! Zero bytes arriving is a fact about the stream, and this module carries it
//! as `Outcome.empty` so a caller can go and ask a different provider. It is
//! not an input to the verdict, and it is not the verdict.
//!
//! It cannot be the verdict, because it means two things. A provider that does
//! not have the blob writes nothing, and a blob of zero bytes is answered with
//! nothing — those are the same bytes, and `BaoResponse.isEof` exists to say
//! so rather than to resolve it. A getter that called an empty answer complete
//! would be claiming a blob on the strength of no bytes, and one that called it
//! incomplete would be reporting a missing blob that the store may well have.
//!
//! The verifier never needs that choice, because its verdict is derived from
//! the tree and the request and never from the arrival. For any request that
//! selects a chunk the plan is non-empty, so zero bytes can only be a refusal —
//! `ResponseTruncated` when the plan wanted bytes, `ProofIncomplete` when
//! `finish` finds the plan unspent. For a request that selects nothing,
//! `Verifier.init` refuses with `NoRangeRequested` before a byte is looked at.
//! So the verdict for an empty answer is always a refusal, and it is always the
//! verifier's own; this module's job is to say so rather than to derive it.
//!
//! That is why `check` passes the bytes through unchanged and reports both
//! facts side by side. A caller that wants "is this blob mine" reads
//! `refused`. A caller that wants "should I ask someone else" reads `empty`.
//! Reading `empty` as a completion is the one mistake the shape above is built
//! to prevent: `refused` is null only when the walk reached the trusted root.
//!
//! # Why the range is not resolved here
//!
//! The chunk range a request selects is `provider.selectedRange`, and this
//! module calls it rather than repeating it. A getter that resolved the range
//! its own way would build a plan the provider did not answer, and would
//! refuse a correct answer for the crime of disagreeing about which chunks it
//! covered.

const std = @import("std");

const core = @import("../crypto/blake3_core.zig");
const ranges = @import("ranges.zig");
const plan_mod = @import("bao_plan.zig");
const verify_mod = @import("bao_proof_verify.zig");
const provider_mod = @import("provider.zig");
const requests = @import("requests.zig");

/// A decoded `get`, as the transport hands one over.
pub const GetRequest = requests.GetRequest;

/// The tree the answer is judged against.
pub const BaoTree = verify_mod.BaoTree;

/// A refusal, which is every way an answer can fail to be a blob.
pub const Refused = verify_mod.Error;

/// What one answer turned out to be.
pub const Outcome = struct {
    /// The provider ended the stream without writing a byte. A fact about the
    /// wire, and the same fact for a blob the store does not have and for a
    /// blob of no bytes at all. Never a verdict: see the module comment.
    empty: bool,
    /// The verifier's own verdict. `null` means the walk reached the trusted
    /// root, and it is the only thing in this type that means the answer is
    /// complete.
    refused: ?Refused,

    /// Whether the answer is this blob. Deliberately `refused == null` and
    /// nothing else: the emptiness of an answer is not evidence either way.
    pub fn isComplete(self: Outcome) bool {
        return self.refused == null;
    }
};

/// Judge `answer` as the answer to `request` for the blob `tree` and
/// `trusted_root` name.
///
/// `trusted_root` is what the caller already held out of band; nothing here
/// reads it off the answer, which is what makes the check a check.
///
/// A request that names no single contiguous range is `error.NoRangeRequested`
/// under `.refused`, which is the same refusal `Verifier.init` makes for a plan
/// with nothing in it: the two are the same failure and get the same name.
pub fn check(
    request: GetRequest,
    tree: BaoTree,
    trusted_root: core.CvBytes,
    answer: []const u8,
) Outcome {
    const selected = provider_mod.selectedRange(request, tree.chunks()) orelse
        return .{ .empty = answer.len == 0, .refused = error.NoRangeRequested };
    verify_mod.verify(tree, selected, trusted_root, answer) catch |err| {
        return .{ .empty = answer.len == 0, .refused = err };
    };
    return .{ .empty = answer.len == 0, .refused = null };
}

/// The bytes a provider would send for `request` over `tree`, which is what
/// `check` is judged against.
///
/// The answer is the plan's own encoding, so a caller that has the blob in
/// memory does not need a provider to learn whether an answer is right.
pub fn expectedAnswer(
    request: GetRequest,
    tree: BaoTree,
    data: []const u8,
    out: []u8,
) plan_mod.BuilderError!usize {
    const selected = provider_mod.selectedRange(request, tree.chunks()) orelse
        return error.NoRangeRequested;
    const plan = plan_mod.planOf(tree, selected);
    return @import("bao_proof_encode.zig").encode(plan, tree, data, out);
}

const t = std.testing;
const encode_mod = @import("bao_proof_encode.zig");
const published = @import("../gossip/plumtree/blake3_vectors.zig");

const whole_blob = 49153;

// The honest case: a provider that has the blob, and an answer the walk accepts.
// `isComplete` is true and `empty` is false, and both come from the verifier
// rather than from a length.
test "a whole-blob answer is the blob, and the walk accepts it" {
    const data = try published.blake3Input(whole_blob);
    defer t.allocator.free(data);
    const tree = BaoTree.init(data.len);
    const hash: store_mod_placeholder = try tree.rootHash(data);
    var scratch: [whole_blob]u8 = undefined;
    const request = .blob(hash);
    const written = try encode_mod.encode(
        plan_mod.planOf(tree, .{ .start = 0, .end = tree.chunks() }),
        tree,
        data,
        &scratch,
    );

    const outcome = check(request, tree, hash, scratch[0..written]);
    try t.expectEqual(false, outcome.empty);
    try t.expect(outcome.isComplete());
    try t.expectEqual(null, outcome.refused);
}

// The rule this module exists to state, swept over the shapes a `get` can take.
// For every one of them an empty answer is refused, and the refusal is the
// verifier's: no request in the sweep has an empty plan and a zero-length
// answer, so "empty" never reaches a place where it could be called complete.
test "an empty answer is refused for every request that selects chunks" {
    const data = try published.blake3Input(whole_blob);
    defer t.allocator.free(data);
    const tree = BaoTree.init(data.len);
    const hash: store_mod_placeholder = try tree.rootHash(data);

    const cases = [_]ranges.ChunkRange{
        .{ .start = 0, .end = tree.chunks() },
        .{ .start = 0, .end = 1 },
        .{ .start = 20, .end = 21 },
        .{ .start = 47, .end = 48 },
        // Past the end: `planOf` clips it, so the plan is non-empty and the
        // answer is still short.
        .{ .start = 48, .end = 60 },
    };
    for (cases) |selected| {
        const request = requestFor(hash, selected);
        const outcome = check(request, tree, hash, &.{});
        try t.expect(outcome.empty);
        try t.expect(!outcome.isComplete());
        try t.expect(outcome.refused != null);
        // The same bytes, the same request, straight into the verifier: the
        // getter reported that verdict rather than making one up.
        try t.expectError(
            outcome.refused.?,
            verify_mod.verify(tree, selected, hash, &.{}),
        );
    }
}

// A zero-length blob is answered with zero bytes, and its plan is empty, so the
// verifier refuses it by name rather than by shortness. The two are the same
// wire shape and stay two refusals here.
test "a zero-length blob is refused by name, and refused as incomplete" {
    const data = try published.blake3Input(whole_blob);
    defer t.allocator.free(data);
    const hash: store_mod_placeholder = try tree_zero().rootHash(data);

    // A tree over no bytes has no chunks, so no plan selects anything.
    const empty_tree = BaoTree.init(0);
    try t.expectEqual(@as(u64, 0), empty_tree.chunks());
    const outcome = check(.blob(hash), empty_tree, hash, &.{});
    try t.expect(outcome.empty);
    try t.expectEqual(error.NoRangeRequested, outcome.refused.?);

    // And the empty answer for a blob that *does* have bytes is a different
    // refusal, so "empty" cannot be one verdict either way.
    const tree = BaoTree.init(data.len);
    try t.expectEqual(
        error.ProofIncomplete,
        check(.blob(hash), tree, hash, &.{}).refused.?,
    );
}

// A damaged answer is refused by the verifier and named by it. The getter adds
// no error of its own, so every `refused` a caller sees is one a peer can be
// shown.
test "a flipped byte and a truncated answer are the verifier's refusals" {
    const data = try published.blake3Input(whole_blob);
    defer t.allocator.free(data);
    const tree = BaoTree.init(data.len);
    const hash: store_mod_placeholder = try tree.rootHash(data);
    const selected = ranges.ChunkRange{ .start = 20, .end = 21 };

    var scratch: [plan_mod.planOf(tree, selected).bytes]u8 = undefined;
    const written = try encode_mod.encode(
        plan_mod.planOf(tree, selected),
        tree,
        data,
        &scratch,
    );
    const answer = scratch[0..written];

    var damaged = try t.allocator.dupe(u8, answer);
    defer t.allocator.free(damaged);
    damaged[damaged.len - 1] ^= 0x01;
    const flipped = check(requestFor(hash, selected), tree, hash, damaged);
    try t.expect(!flipped.empty);
    try t.expectEqual(error.ChildMismatch, flipped.refused.?);

    // Cut in the middle of the answer: bytes arrived, and not enough of them.
    const truncated = check(requestFor(hash, selected), tree, hash, answer[0 .. answer.len / 2]);
    try t.expect(!truncated.empty);
    try t.expect(truncated.refused.? == error.ResponseTruncated or
        truncated.refused.? == error.ProofIncomplete);
}

// A request this store's shape cannot walk gets the verifier's own name for it,
// not a getter-invented one: the plan is empty, and that is what
// `NoRangeRequested` says.
test "a request naming no single range is refused by the verifier's name" {
    const data = try published.blake3Input(whole_blob);
    defer t.allocator.free(data);
    const tree = BaoTree.init(data.len);
    const hash: store_mod_placeholder = try tree.rootHash(data);

    var scratch: [whole_blob]u8 = undefined;
    const written = try encode_mod.encode(
        plan_mod.planOf(tree, .{ .start = 0, .end = tree.chunks() }),
        tree,
        data,
        &scratch,
    );
    for ([_]GetRequest{ .all(hash), .blob(hash).* }) |request| {
        if (std.meta.activeTag(request) == .ranges and request.ranges.isEmpty()) continue;
        const outcome = check(request, tree, hash, scratch[0..written]);
        try t.expectEqual(error.NoRangeRequested, outcome.refused.?);
        try t.expect(!outcome.empty);
    }
}

fn requestFor(hash: core.CvBytes, selected: ranges.ChunkRange) GetRequest {
    return .{
        .hash = hash,
        .ranges = .{ .items = &.{
            .{ .delta = 0, .spec = .{ .widths = &.{ selected.start, selected.len() } } },
            .{ .delta = 1, .spec = @import("range_spec.zig").RangeSpec.empty },
        } },
    };
}

fn tree_zero() BaoTree {
    return BaoTree.init(1);
}