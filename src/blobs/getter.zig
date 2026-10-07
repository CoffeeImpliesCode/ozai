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
const range_spec = @import("range_spec.zig");
const plan_mod = @import("bao_plan.zig");
const verify_mod = @import("bao_proof_verify.zig");
const encode_mod = @import("bao_proof_encode.zig");
const provider_mod = @import("provider.zig");
const requests = @import("requests.zig");

const tree_mod_pair_length = @import("bao_tree.zig").pair_length;
/// A decoded `get`, as the transport hands one over.
pub const GetRequest = requests.GetRequest;

/// The tree the answer is judged against.
pub const BaoTree = verify_mod.BaoTree;

/// A refusal, which is every way an answer can fail to be a blob.
pub const Refused = verify_mod.Error;

/// Everything `expectedAnswer` can fail with: the encoder's own failures, plus
/// the one refusal this module names for a request that selects nothing.
pub const EncodeError = encode_mod.Error || error{
    /// The request names no single contiguous range, so there is no answer to
    /// encode. `check` reports the same refusal under `.refused`, and it is
    /// `Refused`'s arm of the same name.
    NoRangeRequested,
};

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
) EncodeError!usize {
    const selected = provider_mod.selectedRange(request, tree.chunks()) orelse
        return error.NoRangeRequested;
    const plan = plan_mod.planOf(tree, selected);
    return encode_mod.encode(plan, tree, data, out);
}

pub const Decoded = struct { size: u64, written: usize };
pub const DecodeError = Refused || error{
    SizeMismatch,
    HashMismatch,
    BufferTooSmall,
};

/// Verify a complete `/iroh-bytes/4` response before exposing requested data.
/// The wire size is untrusted until the Bao walk reaches the requested hash.
pub fn decode(
    request: GetRequest,
    expected_size: ?u64,
    trusted_root: core.CvBytes,
    wire: []const u8,
    out: []u8,
) DecodeError!Decoded {
    if (!std.meta.eql(request.hash, trusted_root)) return error.HashMismatch;
    if (wire.len < 8) return error.ResponseTruncated;
    const size = std.mem.readInt(u64, wire[0..8], .little);
    if (expected_size) |expected| {
        if (size != expected) return error.SizeMismatch;
    }
    const tree = BaoTree.init(size);
    const selected = provider_mod.selectedRange(request, tree.chunks()) orelse
        return error.NoRangeRequested;
    const proof = wire[8..];
    try verify_mod.verify(tree, selected, trusted_root, proof);
    const start = selected.start * ranges.chunk_size;
    const end = @min(selected.end *| ranges.chunk_size, size);
    const length: usize = @intCast(end - start);
    if (length > out.len) return error.BufferTooSmall;
    const plan = plan_mod.planOf(tree, selected);
    var at: usize = 0;
    var written: usize = 0;
    for (plan.items[0..plan.len], 0..) |item, index| {
        const count = plan.itemBytes(tree, index);
        if (item == .data) {
            const bytes = item.data.bytes(tree);
            const left = @max(start, bytes.start);
            const right = @min(end, bytes.end);
            if (left < right) {
                const offset: usize = @intCast(left - bytes.start);
                const take: usize = @intCast(right - left);
                @memcpy(out[written..][0..take], proof[at + offset ..][0..take]);
                written += take;
            }
        }
        at += count;
    }
    std.debug.assert(written == length);
    return .{ .size = size, .written = written };
}

const t = std.testing;
const published = @import("../gossip/plumtree/blake3_vectors.zig");

const whole_blob = 49153;

// The honest case: a provider that has the blob, and an answer the walk accepts.
// `isComplete` is true and `empty` is false, and both come from the verifier
// rather than from a length.
test "a whole-blob answer is the blob, and the walk accepts it" {
    const data = try published.blake3Input(whole_blob);
    defer t.allocator.free(data);
    const tree = BaoTree.init(data.len);
    const hash: core.CvBytes = try tree.rootHash(data);
    var scratch: [whole_blob + 3 * tree_mod_pair_length]u8 = undefined;
    const request = GetRequest.blob(hash);
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
    const hash: core.CvBytes = try tree.rootHash(data);

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
        // A request borrows its items and the items borrow their widths, so the
        // two arrays are the caller's and outlive the request.
        const widths = [_]u64{ selected.start, selected.len() };
        const items = [_]range_spec.Item{
            .{ .delta = 0, .spec = .{ .widths = &widths } },
            .{ .delta = 1, .spec = range_spec.RangeSpec.empty },
        };
        const request: GetRequest = .{ .hash = hash, .ranges = .{ .items = &items } };
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
    // A tree over no bytes has no chunks, so no plan selects anything, and its
    // root is the published digest of the empty input. That hash comes from the
    // tree, not from a range request, which is why it is taken over no bytes.
    const empty_data = try published.blake3Input(0);
    defer t.allocator.free(empty_data);
    const empty_tree = BaoTree.init(0);
    const hash: core.CvBytes = try empty_tree.rootHash(empty_data);
    try t.expectEqual(@as(u64, 0), empty_tree.chunks());
    const outcome = check(GetRequest.blob(hash), empty_tree, hash, &.{});
    try t.expect(outcome.empty);
    try t.expectEqual(error.NoRangeRequested, outcome.refused.?);

    // And the empty answer for a blob that *does* have bytes is a different
    // refusal, so "empty" cannot be one verdict either way.
    const tree = BaoTree.init(data.len);
    try t.expectEqual(
        error.ProofIncomplete,
        check(GetRequest.blob(hash), tree, hash, &.{}).refused.?,
    );
}

// A damaged answer is refused by the verifier and named by it. The getter adds
// no error of its own, so every `refused` a caller sees is one a peer can be
// shown.
test "a flipped byte and a truncated answer are the verifier's refusals" {
    const data = try published.blake3Input(whole_blob);
    defer t.allocator.free(data);
    const tree = BaoTree.init(data.len);
    const hash: core.CvBytes = try tree.rootHash(data);
    const selected = ranges.ChunkRange{ .start = 20, .end = 21 };

    const plan = plan_mod.planOf(tree, selected);
    const scratch = try t.allocator.alloc(u8, plan.bytes);
    defer t.allocator.free(scratch);
    const written = try encode_mod.encode(plan, tree, data, scratch);
    const answer = scratch[0..written];

    var damaged = try t.allocator.dupe(u8, answer);
    defer t.allocator.free(damaged);
    damaged[damaged.len - 1] ^= 0x01;
    const widths = [_]u64{ selected.start, selected.len() };
    const items = [_]range_spec.Item{
        .{ .delta = 0, .spec = .{ .widths = &widths } },
        .{ .delta = 1, .spec = range_spec.RangeSpec.empty },
    };
    const request: GetRequest = .{ .hash = hash, .ranges = .{ .items = &items } };
    const flipped = check(request, tree, hash, damaged);
    try t.expect(!flipped.empty);
    try t.expectEqual(error.ChildMismatch, flipped.refused.?);

    // Cut in the middle of the answer: bytes arrived, and not enough of them.
    const truncated = check(request, tree, hash, answer[0 .. answer.len / 2]);
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
    const hash: core.CvBytes = try tree.rootHash(data);

    var scratch: [whole_blob + 3 * tree_mod_pair_length]u8 = undefined;
    const written = try encode_mod.encode(
        plan_mod.planOf(tree, .{ .start = 0, .end = tree.chunks() }),
        tree,
        data,
        &scratch,
    );
    // An unbounded sequence, a sequence with no ranges at all, and a spec with
    // two selected runs and a gap between them. `GetRequest.blob` is not one of
    // them: it names the whole blob, which is one range, and the complete
    // answer above is exactly the answer to it.
    const gapped = [_]range_spec.Item{
        .{ .delta = 0, .spec = .{ .widths = &.{ 2, 4, 3, 1 } } },
        .{ .delta = 1, .spec = range_spec.RangeSpec.empty },
    };
    const cases = [_]GetRequest{
        GetRequest.all(hash),
        .{ .hash = hash, .ranges = .empty },
        .{ .hash = hash, .ranges = .{ .items = &gapped } },
    };
    for (cases) |request| {
        const outcome = check(request, tree, hash, scratch[0..written]);
        try t.expectEqual(error.NoRangeRequested, outcome.refused.?);
        try t.expect(!outcome.empty);
    }
}

// A real response is size + Bao, and consumers get only requested bytes.
test "decode verifies wire size and clips partial final chunk payload" {
    const data = try published.blake3Input(49189);
    defer t.allocator.free(data);
    const tree = BaoTree.init(data.len);
    const root = try tree.rootHash(data);
    const items = [_]range_spec.Item{
        .{ .delta = 0, .spec = .{ .widths = &.{ 47, 2 } } },
        .{ .delta = 1, .spec = range_spec.RangeSpec.empty },
    };
    const request = GetRequest{ .hash = root, .ranges = .{ .items = &items } };
    var wire: [49189 + 1024]u8 = undefined;
    std.mem.writeInt(u64, wire[0..8], tree.size, .little);
    const proof_len = try expectedAnswer(request, tree, data, wire[8..]);
    var payload: [2048]u8 = undefined;
    const decoded = try decode(request, tree.size, root, wire[0 .. 8 + proof_len], &payload);
    try t.expectEqual(@as(u64, 49189), decoded.size);
    try t.expectEqualSlices(u8, data[47 * 1024 ..], payload[0..decoded.written]);
    try t.expectError(error.SizeMismatch, decode(
        request, tree.size + 1, root, wire[0 .. 8 + proof_len], &payload,
    ));
    wire[8 + proof_len - 1] ^= 1;
    try t.expectError(error.ChildMismatch, decode(
        request, tree.size, root, wire[0 .. 8 + proof_len], &payload,
    ));
}
