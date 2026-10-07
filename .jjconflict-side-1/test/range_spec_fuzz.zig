//! Fuzz target for the `RangeSpec` and `RangeSpecSeq` decoders.
//!
//! One target file and one corpus directory per decoder: `zig build fuzz`
//! replays the corpus, and `zig build fuzz --fuzz=<N>` hands the same corpus to
//! Zig's coverage-guided fuzzer and lets it mutate for N iterations. A decoder
//! is only worth this once the same bytes have been shown not to panic, and a
//! range spec is the first type in the transfer path whose every field comes
//! straight off a peer's wire.

const std = @import("std");
const ozai = @import("ozai");
const range_spec = ozai.range_spec;
const postcard = ozai.postcard;
const t = std.testing;

/// Seeds are the raw bytes a peer would send for a range specification. The
/// first four are the hexdumps in iroh-blobs `src/protocol/range_spec.rs` at
/// commit e82cbdcbdac9a78033174aad55e3199b2cf4c0dc, so a mutation starts from
/// something upstream actually wrote; the rest are the shapes the algebra has a
/// rule for, the one failure every varint decoder has, and the two the fuzzer
/// found: two pairs at the same start, which a canonical sequence never
/// produces, and a walk exactly as long as the limit below. `test/corpus/
/// range_spec/` is the record, and a file there is live only once it is named
/// here.
const corpus = [_][]const u8{
    @embedFile("corpus/range_spec/empty"), // 0 bytes: no length prefix at all
    @embedFile("corpus/range_spec/all"), // upstream: RangeSpec::all()
    @embedFile("corpus/range_spec/single_element"), // upstream: chunks(64..)
    @embedFile("corpus/range_spec/even_widths"), // upstream: two disjoint ranges
    @embedFile("corpus/range_spec/odd_widths"), // three widths: an open-ended span
    @embedFile("corpus/range_spec/exceeds_total"), // wider than the blob it is read against
    @embedFile("corpus/range_spec/saturating"), // widths summing past u64.max
    @embedFile("corpus/range_spec/seq_from_ranges"), // upstream: from_ranges
    @embedFile("corpus/range_spec/seq_infinite"), // upstream: from_ranges_infinite
    @embedFile("corpus/range_spec/shared_start"), // two pairs at one start
    @embedFile("corpus/range_spec/trailing_byte"), // a whole spec and one byte after it
    @embedFile("corpus/range_spec/bad_varint"), // a varint with no room to stop
    @embedFile("corpus/range_spec/walk_at_limit"), // one pair, a walk of exactly the fuzzer's limit
};

/// Long enough to overrun every encoding below, so a mutated input can still
/// reach a length check it was not grown for, and short enough that a decoded
/// spec fits the walk limit below.
const input_buffer_len = 64;

/// A decoded spec is at most `input_buffer_len` widths of at most ten bytes
/// each, plus a length prefix. The re-encode is what the fixed-point oracle
/// compares, so it has to be able to hold the widest legal one.
const reencode_len = postcard.varintMax(u64) * (input_buffer_len + 1);

/// Every byte of input becomes at most one pair — twenty bytes out, a delta
/// and a spec length — or one width, ten bytes out, never both.
const reencode_seq_len = 2 * reencode_len;

/// A decoded spec names at most `input_buffer_len` widths, and half of any
/// list are deselected gaps, so this cannot be reached.
const max_spans = input_buffer_len / 2 + 2;

/// Blob sizes a spec is read against, ascending. Zero and one are blobs a
/// width can be wider than; the last is the largest a `u64` can name.
const totals = [_]u64{ 0, 1, 2, 7, 64, 1 << 20, std.math.maxInt(u64) };

/// How many blobs a sequence walk the fuzzer can afford to run. A delta of
/// `u64.max` names more blobs than that, and the oracle says so rather than
/// waiting for it.
const walk_limit = 64;

comptime {
    // A seed longer than the window the fuzzer reads into would be cut short on
    // its way to the oracle, and the length check would never see the rest.
    for (corpus) |seed| std.debug.assert(seed.len <= input_buffer_len);
}

/// The fuzzer keeps one of these by pointer for the whole run, so it is empty
/// by design: everything the oracle needs is comptime.
const Context = struct {};

test "range spec decode" {
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
    try checkSpec(bytes);
    try checkSeq(bytes);
}

/// One spec, from the bytes alone.
fn checkSpec(bytes: []const u8) !void {
    var widths: [input_buffer_len]u64 = undefined;
    var reader = postcard.Reader.init(bytes);
    const spec = range_spec.RangeSpec.parse(&reader, &widths) catch |err| {
        // Oracle: capacity. A count is a `varint(u64)` a peer can name, but
        // every element it names is at least one byte, so a frame of
        // `bytes.len` bytes can never declare more widths than the window
        // holds. A decoder that did not bound the count would be the one that
        // reaches this.
        try t.expect(err != error.BufferFull);
        return;
    };
    // Whatever the reader has left is a second message rather than a failure
    // of this one: the decoder reads the fields the length prefixes name and
    // stops there, and `Reader.finish` is how a caller that wants a whole frame
    // asserts it. This oracle is not that caller, so a seed carrying a trailing
    // byte is a case rather than a failure.
    try t.expect(spec.widths.len <= widths.len);

    // Oracle: fidelity. The re-encoding of a decoded spec is postcard's
    // canonical spelling, not the one that was sent — postcard accepts a
    // non-canonical varint — so the fixed point is taken from the second
    // decode, not the first.
    var encoded: [reencode_len]u8 = undefined;
    var writer = postcard.Writer.init(&encoded);
    try spec.write(&writer);
    const canonical = writer.finish();

    var recoded_widths: [input_buffer_len]u64 = undefined;
    var recoder = postcard.Reader.init(canonical);
    const recoded = try range_spec.RangeSpec.parse(&recoder, &recoded_widths);
    try recoder.finish();
    try t.expect(spec.eql(recoded));

    var again: [reencode_len]u8 = undefined;
    var rewriter = postcard.Writer.init(&again);
    try recoded.write(&rewriter);
    try t.expectEqualSlices(u8, canonical, rewriter.finish());

    try checkCounts(spec);
    try checkTotals(spec);
}

/// The count a spec reports is a sum over the widths at odd positions, and the
/// ceiling exists exactly when the walk ends on a deselected span. Both are
/// recomputed here in a `u128`, which cannot saturate, so a `u64` that
/// overflowed in the sum is caught rather than agreed with.
fn checkCounts(spec: range_spec.RangeSpec) !void {
    var expected: u128 = 0;
    var index: usize = 0;
    while (index < spec.widths.len) : (index += 1) {
        if (index % 2 == 1) expected += spec.widths[index];
    }

    const count = spec.chunks();
    try t.expectEqual(@min(expected, std.math.maxInt(u64)), @as(u128, count.min));
    if (spec.widths.len % 2 == 0) {
        try t.expect(count.max != null);
        try t.expectEqual(count.min, count.max.?);
    } else {
        try t.expect(count.max == null);
    }
}

/// Every span the walk yields is inside the blob, in increasing offset order.
///
/// The size of a span is not checked against the width it came from, and the
/// spans of one spec are not checked against each other for overlap: upstream
/// returns a *range set*, which merges two runs that touch, and merging is
/// range-set algebra that this module does not do. What the contract is here
/// is that the spans are inside the blob, and the last chunk of a blob is
/// named by every run that reaches or passes it.
fn checkTotals(spec: range_spec.RangeSpec) !void {
    var spans: [max_spans]range_spec.Span = undefined;
    for (totals) |total| {
        const len = drain(spec.resolve(total), &spans);
        for (spans[0..len], 0..) |span, index| {
            // Oracle: clip. A selected span is never empty, and never reaches
            // past the blob, whatever the widths said.
            try t.expect(span.size > 0);
            try t.expect(span.size <= total -| span.offset);
            if (index != 0) try t.expect(spans[index - 1].offset <= span.offset);
        }
    }
}

/// One sequence, from the bytes alone.
fn checkSeq(bytes: []const u8) !void {
    var items: [input_buffer_len]range_spec.Item = undefined;
    var widths: [input_buffer_len]u64 = undefined;
    var reader = postcard.Reader.init(bytes);
    const seq = range_spec.RangeSpecSeq.parse(&reader, &items, &widths) catch |err| {
        // Same capacity rule as a bare spec, and one more: a pair costs a
        // byte for its delta, so the widths of every pair together still fit
        // the window.
        try t.expect(err != error.BufferFull);
        return;
    };
    // A trailing byte is a second message, for the reason given in `checkSpec`.
    try t.expect(seq.items.len <= items.len);

    var encoded: [reencode_seq_len]u8 = undefined;
    var writer = postcard.Writer.init(&encoded);
    try seq.write(&writer);
    const canonical = writer.finish();

    var recoded_items: [input_buffer_len]range_spec.Item = undefined;
    var recoded_widths: [input_buffer_len]u64 = undefined;
    var recoder = postcard.Reader.init(canonical);
    const recoded = try range_spec.RangeSpecSeq.parse(&recoder, &recoded_items, &recoded_widths);
    try recoder.finish();
    try t.expect(seq.eql(recoded));

    try checkWalk(seq);
}

/// The two walks are the same walk, and both have to match the deltas.
fn checkWalk(seq: range_spec.RangeSpecSeq) !void {
    var finite = seq.iter();
    var infinite = seq.iterInfinite();
    var count: usize = 0;
    while (count < walk_limit) {
        const got = finite.next() orelse break;
        // Oracle: agreement. The finite walk is a prefix of the infinite one,
        // so a delta that moves a pair backwards shows up here as a pair whose
        // spec the two walks disagree about.
        try t.expect(got.eql(infinite.next()));
        count += 1;
    }

    // A walk of exactly `walk_limit` blobs leaves the loop with the same count
    // as one that is longer than that, so ask for one more blob before deciding
    // which of the two it was. The fuzzer found this: one pair with a delta of
    // 63 is a walk of exactly 64 blobs.
    if (count == walk_limit and finite.next() != null) {
        // Too long to run, which is only true when the deltas really do name
        // more blobs than the fuzzer can afford.
        try t.expect(coveredBlobs(seq) > walk_limit);
        return;
    }

    // Oracle: extent. The finite walk covers exactly one more blob than the
    // pair that ends it starts at.
    try t.expectEqual(coveredBlobs(seq), @as(u64, count));
    try t.expect(infinite.isAtEnd());

    // Oracle: repetition. A sequence that ends on a selected spec is
    // "this for every later blob", and the walk says so forever; one that
    // ends on an empty spec is exhausted and repeats the empty spec.
    const last = infinite.next();
    try t.expect(seq.isInfinite() == !last.isEmpty());
    for (0..4) |_| try t.expect(last.eql(infinite.next()));
}

/// The blobs a sequence's finite walk covers.
///
/// A pair is taken at the first blob the walk reaches that is at or past the
/// pair's start, and the walk is by then one blob past the pair before it. So
/// the count is a running maximum of the two, not the sum of the deltas: a
/// peer is free to send a zero delta, and then two pairs share a start and
/// the second is taken the blob *after* it rather than at it. Upstream's walk
/// lands in the same place, because its `offset < start` guard is the same
/// one, and upstream adds its deltas without a check.
fn coveredBlobs(seq: range_spec.RangeSpecSeq) u64 {
    if (seq.items.len == 0) return 0;
    var start: u128 = 0;
    var at: u128 = 0;
    for (seq.items, 0..) |item, index| {
        start += item.delta;
        // The first pair has no blob before it, so it is taken at its start.
        at = if (index == 0) start else @max(start, at + 1);
    }
    const blobs = at + 1;
    if (blobs >= std.math.maxInt(u64)) return std.math.maxInt(u64);
    return @intCast(blobs);
}

/// Drain a walk into `out`, which is sized past any spec the window admits.
/// The sum is the caller's: a spec whose widths overflow must not be able to
/// overflow the check on it either.
fn drain(walk: range_spec.SpanIter, out: []range_spec.Span) usize {
    var it = walk;
    var count: usize = 0;
    while (it.next()) |span| {
        std.debug.assert(count < out.len);
        out[count] = span;
        count += 1;
    }
    return count;
}
