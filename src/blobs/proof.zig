//! What a bao proof has to look like before any of it means anything: the
//! chunk ranges a proof covers, the codec that carries them, and the
//! structural rule that no proof is finished without its root compared.
//!
//! # Why shape is its own module
//!
//! A bao proof answers two questions at once — what are the bytes, and how do
//! they hash to the root the request named — and answering the second needs
//! BLAKE3 subtree hashing, which is another module's job. Neither question
//! needs it *structurally*. Which nodes a proof must carry, in which order,
//! and when it may claim to be finished are decisions about shape, and they are
//! the first ones a peer reaches. A structurally wrong proof is rejected before
//! a single hash is computed, and a decoder that could report success on a
//! structurally incomplete proof would report success on a truncation that
//! happens to end on a node boundary — which is the whole attack.
//!
//! So this module holds shape and nothing else: it computes no hash, reads no
//! clock, allocates nothing, and every value it hands back is borrowed from a
//! caller-owned buffer or written into one.
//!
//! # The ranges
//!
//! `encode_ranges_validated` and `decode_ranges` carry the spans a proof covers
//! in the same `range_spec.Span` a spec walk yields, so a range a getter asked
//! for and a range a proof claims to answer are one value type and cannot drift
//! apart in meaning. Three rules, and `checkRanges` is the only place that
//! states them:
//!
//! - No span is empty. `SpanIter.span` never hands out a zero-width span, so
//!   one on the wire is a peer that did not read a spec.
//! - No span's end wraps. Offsets and sizes are `u64`s a peer chose.
//! - No span starts before the one before it ends. A proof's ranges are walked
//!   in the order they are listed, and two that overlap ask the tree for one
//!   chunk twice, which is not a range set any more.
//!
//! `truncate_ranges` is the size rule, and it is `SpanIter.span`'s rule read
//! against a blob: a span that starts inside the blob is cut at its end, one
//! that starts at or past it is the blob's last chunk, and only the first such
//! span is kept, because the walk hands that chunk out once however many spans
//! reach for it. `u64.max` is why the rule has a case at all: `verified_size`
//! selects nothing until the blob's last chunk, and a truncation that cut it to
//! nothing would make a size proof impossible to answer.
//!
//! # Failing closed
//!
//! `Completion` is the whole of the completion rule and it is structural on
//! purpose. A proof is finished when the node carrying the expected root hash
//! has been compared against it — `root_compared`, which `push` sets on no
//! other node and only after the hashes match — and the walk owes no subtree,
//! which `owed` counts. `finish` is the only thing here that can report a
//! proof complete, and it reports it on those two conditions alone.
//!
//! Every other ending of a stream is a named failure, and none of them is
//! success:
//!
//! - The stream ends before the node carrying the root hash arrives, so nothing
//!   was ever compared against the hash the request named:
//!   `error.ParentNotFound`.
//! - The stream ends with a subtree's contents still owed, which is what a
//!   truncated answer looks like: `error.LeafNotFound`.
//!
//! Missing data is the end of the stream rather than an error frame — that is
//! `protocol.zig`'s rule and this module does not restate it — so these two
//! are what a short answer turns into here, and neither is a value a caller
//! could mistake for a finished proof.

const std = @import("std");
const postcard = @import("../wire/postcard.zig");
const range_spec = @import("range_spec.zig");

/// The BLAKE3 hash a proof's root is.
///
/// `protocol.zig` puts these same 32 bytes on the wire under a private alias of
/// the same shape. This is that type under the name the tree gives it, so the
/// root a request named and the root a proof carries compare as values rather
/// than through a conversion.
const Hash = [32]u8;

/// Every way a range list can fail to encode.
///
/// The postcard members are the codec's, repeated rather than wrapped: a caller
/// writing a proof wants to tell a writer with no room from a list whose ranges
/// cannot be walked, and a nested error would make it unwrap a type that does
/// not depend on the list it was in. The three added members are the three
/// rules `checkRanges` states, one arm each.
pub const EncodeError = postcard.Error || error{
    /// A span that covers no chunks. `SpanIter.span` never hands one out, so
    /// this is a caller that built a list the walk would not produce.
    EmptyRange,
    /// A span whose end does not fit the counter: the sum saturates at the
    /// largest offset there is rather than naming a span.
    /// A span that starts before the one before it ends: overlapping or
    /// descending, where a proof's ranges are walked in the order they are
    /// listed.
    RangesUnsorted,
};

/// Every way a proof stream can fail to decode, or to be believed.
///
/// The encode members are repeated rather than wrapped, for the reason
/// `EncodeError` gives, and the six added members are the structural rules of a
/// proof stream. A list a peer sent is rejected for a broken rule rather than
/// sorted into shape, because a proof's ranges are read in the order they
/// arrive and a reordered list is a different proof.
pub const DecodeError = EncodeError || error{
    /// The first node of a stream is not the root, or does not start at chunk
    /// 0. A proof opens with the subtree it is a proof of.
    NotRoot,
    /// A node more than one level away from the node before it, or a second
    /// node at level 0. A pre-order walk steps into a child and back out to the
    /// next unvisited sibling, so the level changes by one step at a time in
    /// either direction — it never skips a level — and the root is the only
    /// node at level 0.
    LevelOutOfOrder,
    /// A node after the tree the stream covered was already complete. Nothing
    /// asked for it, so nothing checked it either.
    UnexpectedNode,
    /// The node carrying the root hash does not carry the expected one: a proof
    /// of a different blob.
    RootMismatch,
    /// The stream ended with a subtree's contents still owed. This is what a
    /// short answer is: the walk descended and the data never arrived.
    LeafNotFound,
    /// The stream ended before the node carrying the root hash arrived, so
    /// nothing was ever compared against the hash the request named.
    ParentNotFound,
};

/// Write `spans` as a proof's range list, having first checked every rule a
/// range list has to satisfy.
///
/// The wire form is an element count and then each span as its offset and its
/// size, so the list is what a peer reads back with `decode_ranges` and hands
/// to the tree walk.
///
/// Checking before writing is what the name is for: a list that breaks a rule
/// writes nothing at all, so a rejected list cannot leave a partial one on the
/// wire for the reader below to decode as a shorter answer. `error.BufferFull`
/// is the exception the writer owns — it can leave a committed prefix, exactly
/// as `postcard.Writer` documents.
pub fn encode_ranges_validated(
    spans: []const range_spec.Span,
    writer: *postcard.Writer,
) EncodeError!void {
    try checkRanges(spans);
    try writer.writeLen(spans.len);
    for (spans) |span| {
        try writer.writeU64(span.offset);
        try writer.writeU64(span.size);
    }
}

/// Read a proof's range list into `out`, and check it with the same rules.
///
/// The result borrows `out`, which is the caller's, so it must not outlive it.
/// On error the reader may have advanced and a prefix of `out` may already hold
/// the spans read so far — unvalidated, because the three rules are checked
/// after the last one is read — while the rest keeps what the caller had.
/// `error.BufferFull` is the one failure that writes nothing: the declared
/// count is checked against `out.len` before the first span is read.
///
/// The spans are returned as they arrived rather than sorted into shape, which
/// is what separates this from `ChunkRangeSet.parse` upstream's own visitor
/// does. That one normalises because a peer sends a unioned set and every union
/// names the same chunks; a proof is a walk, and a list whose spans overlap is
/// a request for a chunk twice, which no tree walk can answer.
pub fn decode_ranges(
    reader: *postcard.Reader,
    out: []range_spec.Span,
) DecodeError![]range_spec.Span {
    const count = try reader.readLen();
    if (count > out.len) return error.BufferFull;
    const filled = out[0..count];
    for (filled) |*span| {
        span.offset = try reader.readU64();
        span.size = try reader.readU64();
    }
    try checkRanges(filled);
    return filled;
}

/// The rules a range list has to satisfy, checked once for both directions.
///
/// Both sides call this rather than one calling the other, so that the encode
/// path cannot inherit the decode path's error set and neither depends on the
/// other's direction of travel.
fn checkRanges(spans: []const range_spec.Span) EncodeError!void {
    for (spans, 0..) |span, index| {
        if (span.size == 0) return error.EmptyRange;
        // Saturating, then compared against the start: `size` is nonzero here,
        // so a sum that fits is always above the start and a sum that does not
        // is either clamped back to it or wrapped below it. Both are this one
        // arm, and a wrapping add would make the second case an earlier span
        // reading as a huge offset.
        const end = span.offset +| span.size;
        if (end <= span.offset) return error.RangeOverflow;
        // Adjacent spans are allowed and overlapping ones are not, which is
        // `span.offset < end of the previous span` rather than `<=`.
        if (index != 0 and span.offset < spans[index - 1].offset +| spans[index - 1].size) {
            return error.RangesUnsorted;
        }
    }
}

/// The spans `spans` covers against a blob of `total_chunks` chunks, truncated
/// in place and returned.
///
/// `spans` must be in ascending offset order — the order `checkRanges` requires
/// and the order `SpanIter` hands out — because the last-chunk rule below
/// stops the walk and a list read in another order would stop it elsewhere.
/// This is `SpanIter.span`'s rule and not a paraphrase of it: a span starting
/// inside the blob is cut at its end, one starting at or past it is the blob's
/// last chunk, that chunk is handed out once however many spans reach for it,
/// and a blob of no chunks covers nothing at all. A zero-width span selects
/// nothing and is dropped, which is the `size == 0` return in `SpanIter.span`.
pub fn truncate_ranges(spans: []range_spec.Span, total_chunks: u64) []range_spec.Span {
    // The walk's first rule, before any span is looked at: a blob with no
    // chunks has no last chunk, so nothing resolves against it.
    if (total_chunks == 0) return spans[0..0];
    var kept: usize = 0;
    for (spans) |span| {
        if (span.offset >= total_chunks) {
            // `last_given`: this and every span after it name the same chunk,
            // and the walk hands it out once and then stops.
            spans[kept] = .{ .offset = total_chunks - 1, .size = 1 };
            return spans[0 .. kept + 1];
        }
        const size = @min(span.offset +| span.size, total_chunks) - span.offset;
        if (size == 0) continue;
        spans[kept] = .{ .offset = span.offset, .size = size };
        kept += 1;
    }
    return spans[0..kept];
}

/// One node of a proof stream, as the tree walk delivers it.
///
/// Upstream's `PrefixNode` (`n0-computer/bao-tree` `src/proofs.rs`, commit
/// 2be9abd144783455606424424c29bd3a57f926f8), reduced to the shape `Completion`
/// checks. The node's own data — a leaf's bytes — is the transfer payload and
/// is not a field here: the walk owns those bytes and hands them to the hasher,
/// and a proof is structurally complete when the tree says so rather than when
/// this struct has been filled.
pub const Node = struct {
    /// The level this node's subtree starts at, counted from the node the
    /// stream opens with. The root is level 0 and its children are level 1.
    level: u8,
    /// The chunk offset this node's subtree starts at. Only the root's is 0.
    offset: u64,
    /// How many chunks the subtree covers. A leaf that carries its data covers
    /// one block of them; a parent covers the two subtrees below it.
    size: u64,
    /// Whether the stream carries this node's data, which only a leaf does: a
    /// parent carries its children's hashes in its place, which is what makes
    /// a proof a proof.
    is_leaf: bool,
    /// The node's hash: combined into its parent when it is a parent, and the
    /// subtree's own hash when it is a leaf.
    hash: Hash,
};

/// The structural end of a proof stream: whether the root was compared, and
/// what the walk still owes.
///
/// Nothing here computes a hash or looks at data. `push` takes the node the
/// walk decoded and checks that the stream is a pre-order walk of one tree
/// opening at its root, comparing the root's hash once and only once; `finish`
/// reports the stream finished and refuses to report it finished without that
/// comparison having happened. The two are separate calls because the tree walk
/// is the thing that knows a stream has ended, and it ends at the root's own
/// node as often as at a leaf — the caller says so, and `finish` is where the
/// saying is checked.
pub const Completion = struct {
    /// The root hash the request named. The first node of the stream has to
    /// carry exactly these bytes, or the proof is of something else.
    root: Hash,
    /// Whether the node carrying `root` has been compared. Set by `push` on the
    /// root and by nothing else, so a stream that never carried one cannot
    /// finish.
    root_compared: bool = false,
    /// How many nodes have been pushed, which is what "the root has not arrived
    /// yet" is stated in terms of.
    nodes: usize = 0,
    /// The level of the node just pushed, and 0 before the first.
    level: u8 = 0,
    /// Subtrees the walk still owes. The root's own subtree is owed before
    /// anything is read; a node settles the subtree it is the root of and a
    /// parent owes its two children in its place, so a fully walked tree owes
    /// nothing at the end.
    owed: usize = 1,

    /// Take one node of the stream, and check that the stream may carry it.
    ///
    /// A caller that decodes a node from the wire, checks its hash against the
    /// tree it is walking, and then pushes it here gets the structural check as
    /// a separate refusal: a node the walk never asked for cannot pass, so
    /// bytes appended to an already-complete proof fail instead of extending
    /// it.
    ///
    /// On `error.RootMismatch` the node is not taken: nothing was compared, so
    /// the state is the one before the call and a caller that keeps going has
    /// not advanced a walk.
    pub fn push(self: *Completion, node: Node) DecodeError!void {
        // A node that covers no chunks cannot be descended into, and one whose
        // end does not fit the counter names no subtree at all. Same saturation
        // rule as `checkRanges`, and for the same reason: `size` is nonzero, so
        // a sum that fits lands strictly above the start.
        if (node.size == 0) return error.EmptyRange;
        const end = node.offset +| node.size;
        if (end <= node.offset) return error.RangeOverflow;
        // Settling a subtree that is not owed is what appending bytes to a
        // finished proof looks like. Checked before the level rules because it
        // is the one a stream can reach by being longer rather than by being
        // wrong.
        if (self.owed == 0) return error.UnexpectedNode;
        if (self.nodes == 0) {
            if (node.level != 0 or node.offset != 0) return error.NotRoot;
        } else if (node.level == 0 or
            node.level > self.level +| 1 or node.level < self.level -| 1)
        {
            return error.LevelOutOfOrder;
        }
        if (node.level == 0) {
            // Only the root is at level 0 — the rule above refuses a second
            // one — so this is the one comparison a whole proof gets. It is
            // made before any state moves, so a mismatch leaves the walk
            // exactly where it was rather than half-advanced.
            if (!std.mem.eql(u8, &node.hash, &self.root)) return error.RootMismatch;
            self.root_compared = true;
        }
        self.nodes += 1;
        self.level = node.level;
        self.owed -= 1;
        // Pre-order: reading a node settles the subtree it roots, and a parent
        // puts its two children's subtrees in that place. A leaf roots the only
        // subtree it has, so it owes nothing. This is what makes a tree of `n`
        // nodes end at zero owed rather than at one.
        if (!node.is_leaf) self.owed += 2;
    }

    /// The stream ended. Succeeds only when the root was compared and the walk
    /// owes nothing; every other ending is `error.ParentNotFound` or
    /// `error.LeafNotFound`, never success.
    ///
    /// The root check comes first even though `owed` is the cheaper one to
    /// read: a stream that never carried the root is missing the root's hash,
    /// and that is the failure a caller has to see whatever else it also owes.
    pub fn finish(self: Completion) DecodeError!void {
        if (!self.root_compared) return error.ParentNotFound;
        if (self.owed != 0) return error.LeafNotFound;
    }
};

const std_testing = std.testing;

/// The spans a spec selects before it is read against any blob: the widths at
/// odd positions, with the open-ended tail running to the end of the counter.
///
/// `SpanIter` cuts these against a blob's length and `truncate_ranges` has to
/// cut the same list the same way, so this is what the truncation test compares
/// two answers. Written rather than reused because the point of the comparison
/// is that the two sides start from the same untruncated list.
fn selectedSpans(spec: range_spec.RangeSpec, out: []range_spec.Span) []range_spec.Span {
    var used: usize = 0;
    var start: u64 = 0;
    for (spec.widths, 0..) |width, index| {
        const end = start +| width;
        if (index % 2 == 1) {
            out[used] = .{ .offset = start, .size = end - start };
            used += 1;
        }
        start = end;
    }
    // An odd element count leaves the walk inside a selected span, which runs
    // past the list rather than ending at a width in it.
    if (spec.widths.len % 2 == 1) {
        out[used] = .{ .offset = start, .size = std.math.maxInt(u64) - start };
        used += 1;
    }
    return out[0..used];
}

/// Drain a walk into `storage` and hand back just the spans that came out.
fn collect(storage: []range_spec.Span, walk: range_spec.SpanIter) []range_spec.Span {
    var iterator = walk;
    var count: usize = 0;
    while (iterator.next()) |span| {
        std.debug.assert(count < storage.len);
        storage[count] = span;
        count += 1;
    }
    return storage[0..count];
}

fn expectDecodeError(hex: []const u8, expected: DecodeError) !void {
    var scratch: [64]u8 = undefined;
    const bytes = try std.fmt.hexToBytes(&scratch, hex);
    var spans: [8]range_spec.Span = undefined;
    var reader = postcard.Reader.init(bytes);
    try std_testing.expectError(expected, decode_ranges(&reader, &spans));
}

fn expectHex(expected: []const u8, actual: []const u8) !void {
    if (std.mem.eql(u8, expected, actual)) return;
    std.debug.print("expected {s}\n     got {s}\n", .{ expected, actual });
    return error.WireFormatMismatch;
}

/// A node whose hash is `byte` repeated, so a test can name one root and any
/// other.
fn nodeHash(byte: u8) Hash {
    return @splat(byte);
}

/// A node that carries its children's hashes, at the subtree it roots.
fn parentNode(level: u8, offset: u64, size: u64, hash: u8) Node {
    return .{
        .level = level,
        .offset = offset,
        .size = size,
        .is_leaf = false,
        .hash = nodeHash(hash),
    };
}

/// A node that carries its own data, at the subtree it roots.
fn leafNode(level: u8, offset: u64, size: u64, hash: u8) Node {
    return .{
        .level = level,
        .offset = offset,
        .size = size,
        .is_leaf = true,
        .hash = nodeHash(hash),
    };
}

test "golden: a proof's range list, one count then offset and size per span" {
    const spans = [_]range_spec.Span{
        .{ .offset = 1, .size = 2 },
        .{ .offset = 9, .size = 4 },
        .{ .offset = 10000, .size = 1 },
    };
    var buffer: [32]u8 = undefined;
    var writer = postcard.Writer.init(&buffer);
    try encode_ranges_validated(&spans, &writer);
    // 10000 is 0x2710, and postcard varint is 0x90 0x4e — the same encoding
    // `range_spec.zig`'s own vectors carry for a width of 10000.
    try expectHex("0301020904904e01", writer.finish());

    var out: [3]range_spec.Span = undefined;
    var reader = postcard.Reader.init(writer.finish());
    try std_testing.expectEqualSlices(
        range_spec.Span,
        &spans,
        try decode_ranges(&reader, &out),
    );
    try reader.finish();
}

test "encode: a list that breaks a rule writes nothing at all" {
    const cases = [_]struct { spans: []const range_spec.Span, expected: EncodeError }{
        .{
            .spans = &.{.{ .offset = 0, .size = 0 }},
            .expected = error.EmptyRange,
        },
        .{
            // The largest offset, and a size that carries it past the counter.
            .spans = &.{.{ .offset = std.math.maxInt(u64), .size = 1 }},
            .expected = error.RangeOverflow,
        },
        .{
            // The second span starts inside the first.
            .spans = &.{
                .{ .offset = 0, .size = 4 },
                .{ .offset = 2, .size = 1 },
            },
            .expected = error.RangesUnsorted,
        },
        .{
            // Descending is the same refusal: the walk reads them in order.
            .spans = &.{
                .{ .offset = 8, .size = 1 },
                .{ .offset = 0, .size = 1 },
            },
            .expected = error.RangesUnsorted,
        },
    };
    for (cases) |case| {
        var buffer: [32]u8 = undefined;
        var writer = postcard.Writer.init(&buffer);
        try std_testing.expectError(
            case.expected,
            encode_ranges_validated(case.spans, &writer),
        );
        // Nothing was committed, so the writer is still at its first byte: a
        // partial list would decode as a shorter one.
        try std_testing.expectEqual(@as(usize, 0), writer.finish().len);
    }
}

test "encode: adjacent spans are one list, not an overlap" {
    const spans = [_]range_spec.Span{
        .{ .offset = 0, .size = 4 },
        .{ .offset = 4, .size = 4 },
    };
    var buffer: [32]u8 = undefined;
    var writer = postcard.Writer.init(&buffer);
    try encode_ranges_validated(&spans, &writer);
    try expectHex("020000040404", writer.finish());
}

test "codec: a range list off a peer's wire is a named error" {
    // One span of no chunks.
    try expectDecodeError("010100", error.EmptyRange);
    // Two spans where the second starts inside the first: 0..4 and 2..3.
    try expectDecodeError("0200040203", error.RangesUnsorted);
    // The largest offset, and a size that carries it past the counter. The
    // offset is `u64.max`, which is nine continuation bytes and a `01`.
    try expectDecodeError("01" ++ "ffffffffffffffffff" ++ "01" ++ "01", error.RangeOverflow);
    // A count of three spans against two spans' bytes: the count cannot be
    // true, which is `BadLength` rather than a short buffer. A count of two
    // against one span's bytes leaves the second one off the end of the input.
    try expectDecodeError("030001", error.BadLength);
    try expectDecodeError("020001", error.UnexpectedEnd);
    // A varint that keeps its continuation bit set for every byte a `u64` has
    // room for, and one that terminates on the last of those bytes carrying
    // more value bits than a `u64` has left.
    try expectDecodeError("01" ++ "80808080808080808080", error.BadVarint);
    try expectDecodeError("01" ++ "808080808080808080" ++ "02", error.ValueOutOfRange);
    // More names than the caller's scratch holds.
    {
        var scratch: [8]u8 = undefined;
        const bytes = try std.fmt.hexToBytes(&scratch, "020001010100");
        // Filled with a value no frame in this file carries, so "was not
        // written" is observable rather than a read of undefined memory.
        var one = [_]range_spec.Span{.{ .offset = 0xff, .size = 0xff }};
        var reader = postcard.Reader.init(bytes);
        try std_testing.expectError(error.BufferFull, decode_ranges(&reader, &one));
        // The declared count is checked against the caller's buffer before the
        // first span is read, so this failure wrote nothing into it.
        try std_testing.expectEqual(
            range_spec.Span{ .offset = 0xff, .size = 0xff },
            one[0],
        );
    }
    // Bytes after the list: a value decoder consumes everything it was given.
    {
        var scratch: [8]u8 = undefined;
        const bytes = try std.fmt.hexToBytes(&scratch, "01010101");
        var spans: [2]range_spec.Span = undefined;
        var reader = postcard.Reader.init(bytes);
        _ = try decode_ranges(&reader, &spans);
        try std_testing.expectError(error.TrailingBytes, reader.finish());
    }
}

test "truncate_ranges: the size rule is the spec walk's, span for span" {
    const cases = [_]struct { spec: range_spec.RangeSpec, total: u64 }{
        // The whole blob.
        .{ .spec = range_spec.all, .total = 64 },
        // The size proof: a deselected gap that swallows the blob, then the
        // last chunk. The gap is `u64.max` wide and must not survive.
        .{ .spec = range_spec.verified_size, .total = 64 },
        .{ .spec = range_spec.verified_size, .total = 1 },
        // Upstream's worked example: 0..2 off, 2..7 on, 7..10 off, 10..11 on.
        .{ .spec = .{ .widths = &.{ 2, 5, 3, 1 } }, .total = 64 },
        // The same list against a blob that ends inside the second span.
        .{ .spec = .{ .widths = &.{ 2, 5, 3, 1 } }, .total = 8 },
        // A selected span that starts past the end is the last chunk, and only
        // the first such span is kept however many reach for it.
        .{ .spec = .{ .widths = &.{ 70, 5 } }, .total = 64 },
        .{ .spec = .{ .widths = &.{ 70, 5, 3 } }, .total = 64 },
        // An empty spec selects nothing whatever the blob's length.
        .{ .spec = range_spec.empty, .total = 64 },
        // A blob of no chunks has no last chunk, so it selects nothing.
        .{ .spec = range_spec.all, .total = 0 },
        .{ .spec = range_spec.verified_size, .total = 0 },
    };
    for (cases) |case| {
        var raw: [8]range_spec.Span = undefined;
        var expected: [8]range_spec.Span = undefined;
        try std_testing.expectEqualSlices(
            range_spec.Span,
            collect(&expected, case.spec.resolve(case.total)),
            truncate_ranges(selectedSpans(case.spec, &raw), case.total),
        );
    }
}

test "truncate_ranges: the last chunk is handed out once" {
    // Three spans that all start past the end of a two-chunk blob: one chunk
    // out of all three, which is the `last_given` rule rather than a merge.
    var spans = [_]range_spec.Span{
        .{ .offset = 5, .size = 1 },
        .{ .offset = 9, .size = 2 },
        .{ .offset = std.math.maxInt(u64), .size = 1 },
    };
    try std_testing.expectEqualSlices(
        range_spec.Span,
        &.{.{ .offset = 1, .size = 1 }},
        truncate_ranges(&spans, 2),
    );
}

test "truncate_ranges: a span cut at the blob's end is the walk's span" {
    var spans = [_]range_spec.Span{
        .{ .offset = 4, .size = 8 },
        .{ .offset = 12, .size = 4 },
    };
    try std_testing.expectEqualSlices(
        range_spec.Span,
        &.{
            .{ .offset = 4, .size = 6 },
            .{ .offset = 12, .size = 2 },
        },
        truncate_ranges(&spans, 10),
    );
}

test "root check: a proof with no root is never finished" {
    var completion = Completion{ .root = nodeHash(0xaa) };
    // Nothing was compared, so nothing can be finished, whatever the walk owes.
    try std_testing.expectError(error.ParentNotFound, completion.finish());

    // A stream that opens on something other than the root is refused before
    // the comparison happens, so the state is untouched and still unfinished:
    // neither a level below the root nor a root that starts past chunk 0 is
    // the subtree the request named.
    try std_testing.expectError(error.NotRoot, completion.push(leafNode(1, 0, 1, 0xaa)));
    try std_testing.expectError(error.NotRoot, completion.push(leafNode(0, 16, 1, 0xaa)));
    try std_testing.expectError(error.ParentNotFound, completion.finish());
}

test "root check: the root is compared once, and a proof of another blob fails" {
    // The right hash, on a leaf: the whole blob in one node, so this finishes.
    {
        var completion = Completion{ .root = nodeHash(0xaa) };
        try completion.push(leafNode(0, 0, 1, 0xaa));
        try completion.finish();
        // A node after the tree was complete is not a longer proof: nothing
        // asked for it, so nothing checked it.
        try std_testing.expectError(error.UnexpectedNode, completion.push(leafNode(1, 0, 1, 0xbb)));
    }
    // The wrong hash is the refusal, and nothing else about the stream is.
    {
        var completion = Completion{ .root = nodeHash(0xaa) };
        try std_testing.expectError(
            error.RootMismatch,
            completion.push(parentNode(0, 0, 16, 0xbb)),
        );
        // The push took nothing, so the refusal left the walk where it was.
        try std_testing.expectError(error.ParentNotFound, completion.finish());
    }
}

test "root check: a stream that ends mid-tree is LeafNotFound" {
    var completion = Completion{ .root = nodeHash(0xaa) };
    // A parent at the root and two parents below it, each with two leaves:
    // seven nodes in all. Every ending before the seventh leaves a subtree
    // owed, which is what a truncated answer is, and none of them is finished.
    try completion.push(parentNode(0, 0, 16, 0xaa));
    try std_testing.expectError(error.LeafNotFound, completion.finish());
    try completion.push(parentNode(1, 0, 8, 0xbb));
    try std_testing.expectError(error.LeafNotFound, completion.finish());
    try completion.push(leafNode(2, 0, 4, 0xcc));
    try std_testing.expectError(error.LeafNotFound, completion.finish());
    try completion.push(leafNode(2, 4, 4, 0xdd));
    try std_testing.expectError(error.LeafNotFound, completion.finish());
    // The walk steps back up to the root's other child, which arrives with its
    // own two halves still owed, so nothing is finished yet.
    try completion.push(parentNode(1, 8, 8, 0xee));
    try std_testing.expectError(error.LeafNotFound, completion.finish());
    try completion.push(leafNode(2, 8, 4, 0xff));
    try std_testing.expectError(error.LeafNotFound, completion.finish());
    try completion.push(leafNode(2, 12, 4, 0x11));
    try completion.finish();
}

test "root check: a walk steps one level at a time, in either direction" {
    var completion = Completion{ .root = nodeHash(0xaa) };
    try completion.push(parentNode(0, 0, 16, 0xaa));
    // Level 2 straight after level 0: the level 1 parent was never sent, so the
    // walk owes a subtree that no node in the stream could settle.
    try std_testing.expectError(
        error.LevelOutOfOrder,
        completion.push(leafNode(2, 0, 4, 0xbb)),
    );
    try completion.push(parentNode(1, 0, 8, 0xcc));
    // A sibling at the same level is what a walk does after a node's subtree.
    try completion.push(parentNode(1, 8, 8, 0xdd));
    // Two levels down is a step and three is not.
    try completion.push(parentNode(2, 0, 4, 0xee));
    try std_testing.expectError(
        error.LevelOutOfOrder,
        completion.push(leafNode(4, 0, 1, 0xff)),
    );
    try completion.push(leafNode(3, 0, 2, 0x11));
    // Back up two levels at once is the same refusal as down two: the walk
    // steps out of a subtree one level at a time.
    try std_testing.expectError(
        error.LevelOutOfOrder,
        completion.push(parentNode(1, 0, 8, 0x22)),
    );
    // And a second root is not a walk either, whatever it claims to cover.
    try std_testing.expectError(
        error.LevelOutOfOrder,
        completion.push(leafNode(0, 0, 1, 0xaa)),
    );
    // One level out, at the same level this node came in at, is the sibling the
    // walk owed — and the rest of the tree is still owed with it.
    try completion.push(leafNode(3, 2, 2, 0x33));
    try std_testing.expectError(error.LeafNotFound, completion.finish());
}

test "root check: a node that covers nothing cannot be descended into" {
    var completion = Completion{ .root = nodeHash(0xaa) };
    try std_testing.expectError(error.EmptyRange, completion.push(parentNode(0, 0, 0, 0xaa)));
    try std_testing.expectError(
        error.RangeOverflow,
        completion.push(parentNode(0, std.math.maxInt(u64), 2, 0xaa)),
    );
    // Neither refusal advanced the walk, so nothing is finished.
    try std_testing.expectError(error.ParentNotFound, completion.finish());
}