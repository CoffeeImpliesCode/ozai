//! Which chunks of a blob a peer is being asked for, and how that question is
//! asked of a whole collection at once.
//!
//! Captured from n0-computer/iroh-blobs, `src/protocol/range_spec.rs`, commit
//! e82cbdcbdac9a78033174aad55e3199b2cf4c0dc, fetched 2026-09-30. The captured
//! proptest cases are from `proptest-regressions/protocol/range_spec.txt` at
//! the same commit.
//!
//! # The unit is a chunk, not a byte
//!
//! A width is a count of 1024-byte BLAKE3 chunks, never a count of bytes and
//! never a count of chunk groups. That is the whole reason the type exists:
//! chunks are the unit BLAKE3 hashes, so nothing below a chunk can be
//! addressed, and combining chunks is only an optimisation that shrinks
//! metadata. `iroh-blobs/src/protocol.rs` says so in the prose above
//! `ChunkRangesExt`, and a spec that counted anything else could not be checked
//! against a peer's tree.
//!
//! # The algebra
//!
//! `RangeSpec` is a list of *widths*, alternating deselected and selected,
//! starting deselected at chunk 0. A list of `n` widths describes `n` spans;
//! spans at even positions are deselected, spans at odd positions are selected.
//!
//! - Even element count: the last span is deselected, and the selection is
//!   bounded. `[2, 5, 3, 1]` is upstream's worked example — five spans, two of
//!   them selected: `[0, 2)` off, `[2, 7)` on, `[7, 10)` off, `[10, 11)` on,
//!   and deselected from 11 on.
//! - Odd element count: the walk ends inside a selected span, which runs to the
//!   end of the blob. `[0]` is therefore "the whole blob" and `[64]` is "the
//!   tail from chunk 64".
//! - No elements: nothing is selected. Upstream calls this "empty" because the
//!   representation is the empty set, not because the blob is.
//!
//! Read against a blob of `n` chunks, a selected span that starts inside the
//! blob is cut at the blob's end, and one that starts at or past the end is
//! the blob's last chunk. `resolve` says why that second rule is upstream's
//! and not a guess, and it is what makes a spec of `[u64.max]` mean "the last
//! chunk" rather than "nothing at all".
//!
//! `RangeSpecSeq` is one level up: a list of `(delta, RangeSpec)` pairs, one
//! per blob in a collection, where `delta` is how many blobs after the previous
//! pair this one starts at, so a sequence of `(0, a), (5, b)` puts `a` on blobs
//! 0 through 4 and `b` on blob 5. A pair is taken at the first blob the walk
//! reaches that is at or past its start, and the walk is by then one blob past
//! the pair before it, so a peer that sends a zero delta gets a second pair on
//! the blob *after* the first rather than on top of it. A walk that reaches
//! the end of the list *terminates*; a walk that is allowed to continue
//! *repeats the last spec forever*, which is what makes a request for an
//! unknown-length collection expressible. `isInfinite` is that distinction,
//! and it is one line.
//!
//! # Two things deliberately not ported
//!
//! Upstream's `to_chunk_ranges` returns a `ChunkRanges`, which is
//! `range_collections::RangeSet2<ChunkNum>`: a set algebra with union,
//! intersection and negation. Nothing in the request path needs it — a spec is
//! only ever read against a blob, and reading it against a blob is the clip
//! `resolve` performs. Porting the set algebra is a port of another crate, and
//! it would be a different ticket.
//!
//! So this module keeps the direction upstream reads a spec *into* the set and
//! drops the direction that builds a set from arbitrary unions, which is
//! `RangeSpec::new`. The other gap that leaves is the sequence constructors
//! `ChunkRangesSeq::from_ranges` and `from_ranges_infinite`: both take a
//! `ChunkRanges` per blob, so they arrive with the set algebra. What they did
//! is remembered where it matters — the canonicalisation they perform, that two
//! adjacent identical specs collapse into one run, is asserted against the
//! captured proptest case that found it.
//!
//! # Purity
//!
//! `widths` and `items` borrow storage the caller owns, and a decode fills
//! storage the caller hands it. Neither type allocates, reads a clock, or
//! reads the environment, for the reasons `docs/ARCHITECTURE.md` gives under
//! "Wire codecs are pure and separate from the transport". Every width that
//! arrives from a peer is a `u64` that may be `u64.max`, so every sum in the
//! walk saturates: a decoder that overflowed would be a crash a peer can
//! reach, and this module is the first thing in the transfer path that reads
//! bytes it did not choose.

const std = @import("std");
const postcard = @import("../wire/postcard.zig");

const no_widths: [0]u64 = .{};
const all_widths = [_]u64{0};
const last_chunk_widths = [_]u64{std.math.maxInt(u64)};

/// A chunk range specification: alternating span widths in chunk units.
///
/// See the module comment for the parity rule and for why a width is a count of
/// chunks. `widths` borrows; a value that outlives the buffer it was read from
/// has to copy it first, for the reason `CustomAddr.parse` gives.
pub const RangeSpec = struct {
    /// The widths, borrowed from wherever the spec came. Nothing here
    /// allocates, and a spec decoded through `parse` borrows the caller's
    /// buffer, so it must not outlive that buffer.
    widths: []const u64,

    /// Selects nothing. `isEmpty` is true, and `resolve` yields no spans.
    pub const empty: RangeSpec = .{ .widths = &no_widths };

    /// Selects every chunk, whatever the blob's size.
    pub const all: RangeSpec = .{ .widths = &all_widths };

    /// Selects the last chunk, and nothing before it.
    ///
    /// Upstream's `verified_size`, which is how a peer asks for a blob's size
    /// and a proof of it in one round. `u64.max` is not a position any blob
    /// reaches, so the one-element list is a deselected gap that swallows
    /// whatever the blob holds and then a selected span that starts past its
    /// end — which `resolve` reads as the last chunk. See `resolve` for where
    /// that rule comes from; it is the reason this is a spec and not a special
    /// case in the decoder.
    pub const verified_size: RangeSpec = .{ .widths = &last_chunk_widths };

    /// Whether the spec selects nothing at all, which is a spec with no
    /// widths — not `all`, which has one width of zero.
    pub fn isEmpty(self: RangeSpec) bool {
        return self.widths.len == 0;
    }

    /// One width of zero: the selected span starts at chunk 0 and the list
    /// ends inside it, so nothing is ever deselected.
    pub fn isAll(self: RangeSpec) bool {
        return self.widths.len == 1 and self.widths[0] == 0;
    }

    /// The same widths in the same order. A decoded spec and one a caller
    /// built over the same numbers are equal; two specs that select the same
    /// chunks by different widths are not, because the widths are the wire
    /// form.
    pub fn eql(a: RangeSpec, b: RangeSpec) bool {
        return std.mem.eql(u64, a.widths, b.widths);
    }

    /// How many chunks this spec selects, as a floor and a ceiling.
    ///
    /// The floor sums the closed selected spans, which is exact for an even
    /// element count. The ceiling is the same number, or null when the walk
    /// ends inside a selected span and the total therefore depends on the blob.
    pub fn chunks(self: RangeSpec) ChunkCount {
        var min: u64 = 0;
        var index: usize = 1;
        while (index < self.widths.len) : (index += 2) {
            // Saturating: the widths come off a peer's wire, and this sum is
            // exactly the number a peer can make largest.
            min +|= self.widths[index];
        }
        return .{
            .min = min,
            .max = if (self.widths.len % 2 == 1) null else min,
        };
    }

    /// The selected chunk spans of a blob of `total_chunks` chunks, in order.
    ///
    /// This is upstream's `to_chunk_ranges` read against a blob, which is the
    /// only way a peer ever reads one: upstream's set is open at the top and
    /// the blob's length is not in the request. Three rules, and the third is
    /// the one that is not obvious.
    ///
    /// A selected span that starts inside the blob is cut at the blob's end.
    /// A selected span that starts *at or past* the end of the blob is the
    /// blob's last chunk. That is where upstream's tree descent lands, not
    /// nowhere: `PreOrderPartialChunkIterRef::new` at
    /// `n0-computer/bao-tree` `src/iter.rs`, commit
    /// 2be9abd144783455606424424c29bd3a57f926f8, pushes the range set onto the
    /// stack unexamined, and every `split_inner` sends a range that starts at
    /// or past a node's mid to the right. A range past the whole tree is
    /// therefore taken right at every level and is answered by the rightmost
    /// leaf. It is what makes `verified_size` mean what its name says.
    ///
    /// And a blob of no chunks has no last chunk, so it selects nothing at
    /// all however the spec reads.
    pub fn resolve(self: RangeSpec, total_chunks: u64) SpanIter {
        return .{ .spec = self, .total = total_chunks };
    }

    /// Write the postcard form: an element count, then each width as
    /// `varint(u64)`.
    pub fn write(self: RangeSpec, writer: *postcard.Writer) postcard.Error!void {
        try writer.writeLen(self.widths.len);
        for (self.widths) |width| try writer.writeU64(width);
    }

    /// Read the postcard form into `widths`, which the result then borrows.
    ///
    /// Success fills exactly the encoded count of widths, without defaults or
    /// clamping. On error, the reader may have advanced and a prefix of `widths`
    /// may already be written; no usable spec is returned. `BufferFull` means
    /// the encoded count exceeds the caller's destination.
    pub fn parse(reader: *postcard.Reader, widths: []u64) postcard.Error!RangeSpec {
        const count = try reader.readLen();
        if (count > widths.len) return error.BufferFull;
        for (widths[0..count]) |*width| width.* = try reader.readU64();
        return .{ .widths = widths[0..count] };
    }

    /// The widths in braces, for a log line and for the failing-decoder
    /// messages in this file's tests. Not the wire form: see `write`.
    pub fn format(self: RangeSpec, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.writeAll("RangeSpec{");
        for (self.widths, 0..) |width, index| {
            if (index != 0) try writer.writeAll(", ");
            try writer.print("{d}", .{width});
        }
        try writer.writeAll("}");
    }
};

/// The chunk count a spec selects: a floor, and a ceiling that is null when
/// the walk ends inside a selected span.
pub const ChunkCount = struct {
    /// Chunks selected at least. Exact when `max` is not null; otherwise the
    /// closed selected spans alone.
    min: u64,
    /// Chunks selected at most, or null when the open-ended tail means the
    /// total depends on the blob the spec is read against.
    max: ?u64,
};

/// One selected span: `size` chunks starting at chunk `offset`.
///
/// Both fields count chunks, not bytes, and `offset + size` may be one past
/// the blob's last chunk: `resolve` cuts a span at the blob's end.
pub const Span = struct {
    /// The first chunk of the span, counted from the start of the blob.
    offset: u64,
    /// How many chunks the span covers. Never zero: a zero-width span is not
    /// handed out at all.
    size: u64,
};

/// The spans `RangeSpec.resolve` yields, in increasing offset order.
///
/// Upstream's `to_chunk_ranges` loop with `resolve`'s three read-against-a-blob
/// rules folded in, and with every addition saturating: the widths came off a
/// peer's wire and `u64.max` is a legal one, where upstream panics on it in
/// debug. The rules are `resolve`'s because they are the reader's and not the
/// walk's.
pub const SpanIter = struct {
    /// The spec being read. Borrowed for as long as the walk is used.
    spec: RangeSpec,
    /// The width the walk is on, and past the end once the list is spent.
    index: usize = 0,
    /// The chunk offset the span being built starts at.
    start: u64 = 0,
    /// The blob this spec is read against.
    total: u64,
    /// Set once the blob's last chunk has been handed out. Every span that
    /// starts past the end of the blob resolves to it, so it is handed out
    /// once however many such spans there are.
    last_given: bool = false,
    /// Set once the open-ended tail has been handed out. The tail is the last
    /// span the walk has, so a second `next` must not hand it out again — which
    /// is the whole difference between the tail and the spans inside it.
    tail_given: bool = false,

    /// The next selected span, or null once the walk is spent.
    ///
    /// `null` is the end, and it stays the end: a second call after it
    /// returns null again. The spans come out in increasing offset order, and
    /// a span that starts past the end of the blob is the blob's last chunk
    /// however many such spans the spec has.
    pub fn next(self: *SpanIter) ?Span {
        if (self.total == 0) return null;
        while (self.index < self.spec.widths.len) {
            const position = self.index;
            self.index = position + 1;
            const start = self.start;
            const end = start +| self.spec.widths[position];
            self.start = end;
            // Widths at even positions are deselected gaps.
            if (position % 2 == 1) {
                if (self.span(start, end)) |out| return out;
            }
        }
        // An odd element count leaves the walk inside a selected span, which
        // runs past the list rather than ending at a width in it.
        if (!self.tail_given and self.spec.widths.len % 2 == 1) {
            self.tail_given = true;
            if (self.span(self.start, std.math.maxInt(u64))) |out| return out;
        }
        return null;
    }

    /// The span `[start, end)` selects of the blob, or null when it selects
    /// nothing: a zero width, or the last chunk already handed out.
    fn span(self: *SpanIter, start: u64, end: u64) ?Span {
        if (self.last_given) return null;
        if (start >= self.total) {
            self.last_given = true;
            return .{ .offset = self.total - 1, .size = 1 };
        }
        const size = @min(end, self.total) - start;
        if (size == 0) return null;
        return .{ .offset = start, .size = size };
    }
};

/// One pair of a `RangeSpecSeq`: how far past the previous pair's start this
/// one begins, and the spec for the blobs in between.
pub const Item = struct {
    /// How many blobs after the previous pair's start this one begins at. A
    /// zero delta puts the pair on the blob *after* the one before it; a
    /// `u64.max` is legal off a peer's wire, and the walk saturates rather
    /// than wrapping behind itself.
    delta: u64,
    /// The spec for the blobs this pair covers. Its `widths` are borrowed,
    /// and after a decode they share one buffer across every item.
    spec: RangeSpec,
};

/// A range specification for a collection of blobs, run-length encoded.
///
/// The wire form, which is what upstream's private `wire::RangeSpecSeq` is and
/// what a `GetRequest` carries. The decoded form upstream works with holds
/// absolute offsets and a `ChunkRanges` per blob; the two differ only in that
/// the offsets are a running sum here and in that a spec is a width list rather
/// than a range set, so the walk below reproduces upstream's two iterators
/// unchanged.
///
/// `items` borrows, and a decode fills a `[]Item` the caller owns plus one
/// `[]u64` the specs in it share. See `RangeSpec` for why neither type
/// allocates.
pub const RangeSpecSeq = struct {
    /// The pairs, one per run of blobs. Borrowed, and after a decode each
    /// item's `spec.widths` is borrowed from the same buffer, so the whole
    /// sequence must not outlive it.
    items: []const Item,

    /// No pairs at all: a legal decode of the one-byte frame `00`, and a walk
    /// that ends immediately.
    pub const empty: RangeSpecSeq = .{ .items = &.{} };

    /// Whether the sequence names no blobs. Distinct from a one-item sequence
    /// whose spec is `RangeSpec.empty`, which still walks one blob.
    pub fn isEmpty(self: RangeSpecSeq) bool {
        return self.items.len == 0;
    }

    /// Whether a walk that is allowed to continue repeats the last spec
    /// forever, which upstream's `is_infinite` asks the same way.
    ///
    /// A zero-length sequence is a legal decode — `00` — so the last-spec read
    /// is reachable with no pairs at all. Upstream's `unwrap_or_default` is
    /// what makes that case false rather than a question.
    pub fn isInfinite(self: RangeSpecSeq) bool {
        const len = self.items.len;
        return len > 0 and !self.items[len - 1].spec.isEmpty();
    }

    /// The same pairs, same order, same deltas and same widths. This compares
    /// the encoding as it stands rather than the chunks the two would select,
    /// so two sequences that cover a collection identically can still differ.
    ///
    /// The specs' borrowed widths are compared by value, so two sequences over
    /// different buffers holding the same numbers are equal.
    pub fn eql(a: RangeSpecSeq, b: RangeSpecSeq) bool {
        if (a.items.len != b.items.len) return false;
        for (a.items, b.items) |left, right| {
            if (left.delta != right.delta or !left.spec.eql(right.spec)) return false;
        }
        return true;
    }

    /// The specs of the blobs this sequence covers, one per blob, ending when
    /// the sequence does.
    pub fn iter(self: RangeSpecSeq) Iter {
        return .{ .seq = self };
    }

    /// The same walk, allowed to continue: once the sequence is spent the last
    /// spec repeats forever.
    ///
    /// Upstream's `iter_infinite`. The caller bounds it, and `isAtEnd` is how
    /// it knows how much of the walk is real.
    pub fn iterInfinite(self: RangeSpecSeq) InfiniteIter {
        return .{ .seq = self };
    }

    /// Write the postcard form: an element count, then per pair the delta and
    /// the spec, in that order. Upstream's pair is a tuple, and postcard
    /// writes a tuple in declaration order.
    pub fn write(self: RangeSpecSeq, writer: *postcard.Writer) postcard.Error!void {
        try writer.writeLen(self.items.len);
        for (self.items) |item| {
            try writer.writeU64(item.delta);
            try item.spec.write(writer);
        }
    }

    /// Read the postcard form into `items`, whose specs share `widths`.
    ///
    /// The two buffers are separate because the encoding nests: a pair holds a
    /// spec, and a spec holds widths. One `[]u64` for the whole message is
    /// enough — every width is at least one byte on the wire, so the declared
    /// counts can never ask for more slots than the frame could have carried —
    /// but a flat run of `u64` has nowhere to put the deltas.
    pub fn parse(
        reader: *postcard.Reader,
        items: []Item,
        widths: []u64,
    ) postcard.Error!RangeSpecSeq {
        const count = try reader.readLen();
        if (count > items.len) return error.BufferFull;
        var used: usize = 0;
        for (items[0..count]) |*item| {
            const delta = try reader.readU64();
            const spec = try RangeSpec.parse(reader, widths[used..]);
            used += spec.widths.len;
            item.* = .{ .delta = delta, .spec = spec };
        }
        return .{ .items = items[0..count] };
    }

    /// The pairs as `(delta, RangeSpec{…})` in braces, for a log line and for
    /// this file's failing-decoder messages. Not the wire form: see `write`.
    pub fn format(self: RangeSpecSeq, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.writeAll("RangeSpecSeq{");
        for (self.items, 0..) |item, index| {
            if (index != 0) try writer.writeAll(", ");
            try writer.print("({d}, ", .{item.delta});
            try item.spec.format(writer);
            try writer.writeAll(")");
        }
        try writer.writeAll("}");
    }
};

/// The finite walk: one spec per blob, ending with the sequence.
///
/// Upstream's `ChunkRangesSeqIter`, whose loop is reproduced rather than
/// paraphrased: a pair whose start the walk has not reached yet leaves the
/// current spec in place, which is how a delta larger than one repeats a spec
/// across the blobs in between.
pub const Iter = struct {
    /// The sequence being walked. Borrowed for as long as the walk is used, and
    /// its items' `spec.widths` must outlive the walk as well.
    seq: RangeSpecSeq,
    /// The pair being considered, and `items.len` once the walk is spent.
    index: usize = 0,
    /// The start of the pair at `index`, as the running sum of the deltas of
    /// the pairs already taken. A pair's own delta is added when it is taken,
    /// so a first delta of three leaves blobs 0, 1 and 2 empty.
    consumed: u64 = 0,
    /// The blob the walk is at.
    offset: u64 = 0,
    /// The spec blobs before the first pair get.
    current: RangeSpec = .empty,

    /// The spec for the next blob, or null once the sequence is spent.
    ///
    /// The value borrows the sequence's widths, so it stays valid only as long
    /// as the sequence does. Blobs before the first pair get `RangeSpec.empty`,
    /// and a pair whose start the walk has not reached leaves the current spec
    /// in place — that is how a delta larger than one repeats a spec.
    pub fn next(self: *Iter) ?RangeSpec {
        if (self.index >= self.seq.items.len) return null;
        const item = self.seq.items[self.index];
        // Saturating for the same reason the span walk saturates: a delta of
        // `u64.max` would otherwise wrap into a start behind the walk, and
        // every later blob would then be handed the wrong spec.
        const start = self.consumed +| item.delta;
        if (self.offset < start) {
            self.offset += 1;
            return self.current;
        }
        self.current = item.spec;
        self.consumed = start;
        self.index += 1;
        self.offset += 1;
        return self.current;
    }
};

/// The unbounded walk: the same, with the last spec repeated forever.
pub const InfiniteIter = struct {
    /// The sequence being walked, borrowed for as long as the walk is used.
    /// The fields below advance as `next` is called; a caller reads them to
    /// tell how much of the walk is real and how far along it is.
    seq: RangeSpecSeq,
    /// The pair being taken next, and `items.len` once the sequence is spent
    /// and the walk is repeating.
    index: usize = 0,
    /// The start of the pair at `index`, as the running sum of the deltas
    /// already taken.
    consumed: u64 = 0,
    /// The blob the walk is at, counting from zero.
    offset: u64 = 0,
    /// The spec handed out for the blob the walk is at. Before the first pair
    /// this is `RangeSpec.empty`.
    current: RangeSpec = .empty,

    /// Whether the walk is past the sequence and now repeating.
    pub fn isAtEnd(self: InfiniteIter) bool {
        return self.index >= self.seq.items.len;
    }

    /// The spec for the next blob. Never null: once the sequence is spent the
    /// last spec repeats forever, and the caller bounds the walk with
    /// `isAtEnd` to tell the real blobs from the repeated ones.
    ///
    /// The value borrows the sequence's widths, so it stays valid only as long
    /// as the sequence does.
    pub fn next(self: *InfiniteIter) RangeSpec {
        if (self.index < self.seq.items.len) {
            const item = self.seq.items[self.index];
            const start = self.consumed +| item.delta;
            if (self.offset < start) {
                self.offset += 1;
                return self.current;
            }
            self.current = item.spec;
            self.consumed = start;
            self.index += 1;
            self.offset += 1;
            return self.current;
        }
        self.offset += 1;
        return self.current;
    }
};

const std_testing = std.testing;

// Golden vectors below: n0-computer/iroh-blobs, `src/protocol/range_spec.rs`,
// commit e82cbdcbdac9a78033174aad55e3199b2cf4c0dc, fetched 2026-09-30. The
// hexdumps are the ones upstream's `range_spec_wire_format` and
// `range_spec_seq_wire_format` tests hold, byte for byte.

/// Upstream `test "range_spec_wire_format"`, at the commit above.
const spec_vectors = [_]struct { spec: RangeSpec, hex: []const u8 }{
    // RangeSpec::EMPTY
    .{ .spec = .empty, .hex = "00" },
    // RangeSpec::all()
    .{ .spec = .all, .hex = "0100" },
    // RangeSpec::new(ChunkRanges::chunks(64..))
    .{ .spec = .{ .widths = &.{64} }, .hex = "0140" },
    // RangeSpec::new(ChunkRanges::chunks(10000..)). 10000 is 0x2710, and
    // postcard varint is 10000 = 0x90 0x4e.
    .{ .spec = .{ .widths = &.{10000} }, .hex = "01904e" },
    // RangeSpec::new(ChunkRanges::chunks(..64))
    .{ .spec = .{ .widths = &.{ 0, 64 } }, .hex = "020040" },
    // RangeSpec::new(&ChunkRanges::chunks(1..3) | &ChunkRanges::chunks(9..13))
    .{ .spec = .{ .widths = &.{ 1, 2, 6, 4 } }, .hex = "0401020604" },
};

/// Upstream `test "range_spec_seq_wire_format"`, at the commit above.
const seq_vectors = [_]struct { seq: RangeSpecSeq, hex: []const u8 }{
    // ChunkRangesSeq::empty()
    .{ .seq = .empty, .hex = "00" },
    // ChunkRangesSeq::all()
    .{ .seq = .{ .items = &.{.{ .delta = 0, .spec = .all }} }, .hex = "01000100" },
    // ChunkRangesSeq::from_ranges([chunks(1..3), chunks(7..13)])
    .{
        .seq = .{ .items = &.{
            .{ .delta = 0, .spec = .{ .widths = &.{ 1, 2 } } },
            .{ .delta = 1, .spec = .{ .widths = &.{ 7, 6 } } },
            .{ .delta = 1, .spec = .empty },
        } },
        .hex = "0300020102010207060100",
    },
    // ChunkRangesSeq::from_ranges_infinite([empty, empty, empty, chunks(7..),
    // all()]). The three leading empty specs collapse, so the first pair
    // starts three blobs in.
    .{
        .seq = .{ .items = &.{
            .{ .delta = 3, .spec = .{ .widths = &.{7} } },
            .{ .delta = 1, .spec = .all },
        } },
        .hex = "02030107010100",
    },
};

test "golden: RangeSpec wire format, iroh-blobs range_spec.rs" {
    for (spec_vectors) |vector| {
        var scratch: [64]u8 = undefined;
        const expected = try parseHex(&scratch, vector.hex);

        var buffer: [64]u8 = undefined;
        var writer = postcard.Writer.init(&buffer);
        try vector.spec.write(&writer);
        try expectHex(expected, writer.finish());

        // A decode of the captured bytes is the same spec, and the whole
        // message is the whole message.
        var widths: [16]u64 = undefined;
        var reader = postcard.Reader.init(expected);
        const decoded = try RangeSpec.parse(&reader, &widths);
        try reader.finish();
        try std_testing.expect(vector.spec.eql(decoded));
    }
}

test "golden: RangeSpecSeq wire format, iroh-blobs range_spec.rs" {
    for (seq_vectors) |vector| {
        var scratch: [64]u8 = undefined;
        const expected = try parseHex(&scratch, vector.hex);

        var buffer: [64]u8 = undefined;
        var writer = postcard.Writer.init(&buffer);
        try vector.seq.write(&writer);
        try expectHex(expected, writer.finish());

        var items: [8]Item = undefined;
        var widths: [32]u64 = undefined;
        var reader = postcard.Reader.init(expected);
        const decoded = try RangeSpecSeq.parse(&reader, &items, &widths);
        try reader.finish();
        try std_testing.expect(vector.seq.eql(decoded));
    }
}

test "golden: proptest-regressions/protocol/range_spec.txt, case 1" {
    // cc 5ff4de8531a81c637b4d202c97b724a41a989bc6894464e84db5ac2a519c08a9
    // shrinks to ranges = [RangeSet{1..2}]
    //
    // `RangeSet{1..2}` is the boundary list [1, 2]: one chunk of gap and one
    // selected chunk.
    const spec: RangeSpec = .{ .widths = &.{ 1, 1 } };
    try std_testing.expectEqual(ChunkCount{ .min = 1, .max = 1 }, spec.chunks());

    var spans: [8]Span = undefined;
    const got = collect(&spans, spec.resolve(8));
    try std_testing.expectEqual(@as(usize, 1), got.len);
    try std_testing.expectEqual(Span{ .offset = 1, .size = 1 }, got[0]);

    // As a sequence, upstream terminates the run: the blob after this one is
    // not requested.
    const seq: RangeSpecSeq = .{ .items = &.{
        .{ .delta = 0, .spec = spec },
        .{ .delta = 1, .spec = .empty },
    } };
    var scratch: [64]u8 = undefined;
    const expected = try parseHex(&scratch, "02000201010100");
    var buffer: [64]u8 = undefined;
    var writer = postcard.Writer.init(&buffer);
    try seq.write(&writer);
    try expectHex(expected, writer.finish());

    try expectWalk(seq, &[_]RangeSpec{ spec, .empty });
    try std_testing.expect(!seq.isInfinite());
}

test "golden: proptest-regressions/protocol/range_spec.txt, case 2" {
    // cc 50cb338763aa276705bb970d57d3d87e834f31a7e57bba810f46690c6d1e9955
    // shrinks to ranges = [RangeSet{7..98}, RangeSet{7..98}]
    //
    // `RangeSet{7..98}` is the boundary list [7, 98], so 7 chunks of gap and 91
    // selected. The duplication is the point: this is the case upstream's
    // canonicalisation exists for, and two identical adjacent specs are one
    // run, so the second delta is 2 rather than 1.
    const spec: RangeSpec = .{ .widths = &.{ 7, 91 } };
    try std_testing.expectEqual(ChunkCount{ .min = 91, .max = 91 }, spec.chunks());

    var spans: [8]Span = undefined;
    const got = collect(&spans, spec.resolve(1000));
    try std_testing.expectEqual(@as(usize, 1), got.len);
    try std_testing.expectEqual(Span{ .offset = 7, .size = 91 }, got[0]);

    const seq: RangeSpecSeq = .{ .items = &.{
        .{ .delta = 0, .spec = spec },
        .{ .delta = 2, .spec = .empty },
    } };
    var scratch: [64]u8 = undefined;
    const expected = try parseHex(&scratch, "020002075b0200");
    var buffer: [64]u8 = undefined;
    var writer = postcard.Writer.init(&buffer);
    try seq.write(&writer);
    try expectHex(expected, writer.finish());

    // Both blobs keep the spec, which is the property the shrinking found, and
    // the pair upstream appends to end the run is a third blob of nothing.
    try expectWalk(seq, &[_]RangeSpec{ spec, spec, .empty });
}

test "golden: proptest-regressions/protocol/range_spec.txt, case 3" {
    // cc 8579821a8bde7872fed2cfa38e8a5923706b9915f3920e9c2d101a06bc789309
    // shrinks to ranges = []
    try std_testing.expect(RangeSpec.empty.isEmpty());
    try std_testing.expect(!RangeSpec.empty.isAll());
    try std_testing.expectEqual(ChunkCount{ .min = 0, .max = 0 }, RangeSpec.empty.chunks());

    var spans: [8]Span = undefined;
    const none = collect(&spans, RangeSpec.empty.resolve(1000));
    try std_testing.expectEqual(@as(usize, 0), none.len);

    // As a sequence it is the empty collection: no pair, and a walk that ends
    // immediately.
    try std_testing.expect(RangeSpecSeq.empty.isEmpty());
    try std_testing.expect(!RangeSpecSeq.empty.isInfinite());
    try expectWalk(.empty, &[_]RangeSpec{});
    var walk = RangeSpecSeq.empty.iterInfinite();
    try std_testing.expect(walk.next().isEmpty());
}

test "RangeSpec: the three named specs" {
    try std_testing.expect(RangeSpec.empty.isEmpty());
    try std_testing.expect(!RangeSpec.empty.isAll());
    try std_testing.expect(!RangeSpec.all.isEmpty());
    try std_testing.expect(RangeSpec.all.isAll());
    try std_testing.expect(!RangeSpec.verified_size.isEmpty());
    try std_testing.expect(!RangeSpec.verified_size.isAll());

    var spans: [8]Span = undefined;

    // `all` selects the whole blob whatever its size.
    const every = collect(&spans, RangeSpec.all.resolve(64));
    try std_testing.expectEqual(@as(usize, 1), every.len);
    try std_testing.expectEqual(Span{ .offset = 0, .size = 64 }, every[0]);

    // `verified_size` asks for the last chunk, which is where a size proof
    // lives, and for nothing before it.
    const proof = collect(&spans, RangeSpec.verified_size.resolve(64));
    try std_testing.expectEqual(@as(usize, 1), proof.len);
    try std_testing.expectEqual(Span{ .offset = 63, .size = 1 }, proof[0]);

    const none = collect(&spans, RangeSpec.empty.resolve(64));
    try std_testing.expectEqual(@as(usize, 0), none.len);
}

test "RangeSpec: an even element count is bounded, an odd one is not" {
    // Upstream's worked example, at `src/protocol/range_spec.rs`,
    // `[2, 5, 3, 1]`: five spans, two of them selected.
    const spec: RangeSpec = .{ .widths = &.{ 2, 5, 3, 1 } };
    try std_testing.expectEqual(ChunkCount{ .min = 6, .max = 6 }, spec.chunks());

    var spans: [8]Span = undefined;
    const two = collect(&spans, spec.resolve(20));
    try std_testing.expectEqual(@as(usize, 2), two.len);
    try std_testing.expectEqual(Span{ .offset = 2, .size = 5 }, two[0]);
    try std_testing.expectEqual(Span{ .offset = 10, .size = 1 }, two[1]);

    // Three widths: the last span is deselected and the walk ends inside a
    // selected one, so the count has no ceiling.
    const open: RangeSpec = .{ .widths = &.{ 1, 2, 6 } };
    try std_testing.expectEqual(ChunkCount{ .min = 2, .max = null }, open.chunks());

    // A zero-width deselected span leaves two selected spans touching, and
    // neither is empty.
    const touching: RangeSpec = .{ .widths = &.{ 1, 2, 0, 3 } };
    try std_testing.expectEqual(ChunkCount{ .min = 5, .max = 5 }, touching.chunks());
    const pair = collect(&spans, touching.resolve(20));
    try std_testing.expectEqual(@as(usize, 2), pair.len);
    try std_testing.expectEqual(Span{ .offset = 1, .size = 2 }, pair[0]);
    try std_testing.expectEqual(Span{ .offset = 3, .size = 3 }, pair[1]);
}

test "RangeSpec.resolve: iteration order, and a spec past the end of the blob" {
    var spans: [8]Span = undefined;

    // The open-ended span runs to the end of the blob, and nothing more.
    const open: RangeSpec = .{ .widths = &.{ 1, 2, 6 } };
    const tail = collect(&spans, open.resolve(12));
    try std_testing.expectEqual(@as(usize, 2), tail.len);
    try std_testing.expectEqual(Span{ .offset = 1, .size = 2 }, tail[0]);
    try std_testing.expectEqual(Span{ .offset = 9, .size = 3 }, tail[1]);

    // A spec wider than the blob is clipped at the blob, not at the spec.
    const too_wide: RangeSpec = .{ .widths = &.{ 1, 100 } };
    const clipped = collect(&spans, too_wide.resolve(4));
    try std_testing.expectEqual(@as(usize, 1), clipped.len);
    try std_testing.expectEqual(Span{ .offset = 1, .size = 3 }, clipped[0]);

    // One whose selected span starts past the end of the blob is the blob's
    // last chunk, which is where the tree descent that reads a spec lands.
    const past = collect(&spans, too_wide.resolve(1));
    try std_testing.expectEqual(@as(usize, 1), past.len);
    try std_testing.expectEqual(Span{ .offset = 0, .size = 1 }, past[0]);

    // A blob of no chunks selects nothing, whatever the spec says.
    const no_blob = collect(&spans, RangeSpec.all.resolve(0));
    try std_testing.expectEqual(@as(usize, 0), no_blob.len);

    // Widths that sum past `u64.max` are the case the saturating walk exists
    // for. Upstream panics on this in debug; a peer must not be able to. The
    // first width is a deselected gap that swallows the whole blob, so the
    // selected span after it starts past the end and is the last chunk.
    const huge = std.math.maxInt(u64);
    const overflowing: RangeSpec = .{ .widths = &.{ huge, huge, huge } };
    try std_testing.expectEqual(ChunkCount{ .min = huge, .max = null }, overflowing.chunks());
    const saturated = collect(&spans, overflowing.resolve(16));
    try std_testing.expectEqual(@as(usize, 1), saturated.len);
    try std_testing.expectEqual(Span{ .offset = 15, .size = 1 }, saturated[0]);
}

test "RangeSpecSeq: a sequence is not one spec" {
    const a: RangeSpec = .{ .widths = &.{ 1, 2 } };
    const b: RangeSpec = .{ .widths = &.{ 7, 6 } };

    // Three pairs: blob 0 is `a`, blob 1 is `b`, blob 2 is nothing. The finite
    // walk covers exactly the three blobs the sequence names.
    const seq: RangeSpecSeq = .{ .items = &.{
        .{ .delta = 0, .spec = a },
        .{ .delta = 1, .spec = b },
        .{ .delta = 1, .spec = .empty },
    } };
    try expectWalk(seq, &[_]RangeSpec{ a, b, .empty });
    try std_testing.expect(!seq.isInfinite());
    try std_testing.expect(!seq.isEmpty());

    // A delta larger than one holds the current spec across the blobs in
    // between, and a first delta of three leaves the leading blobs empty.
    const spread: RangeSpecSeq = .{ .items = &.{
        .{ .delta = 3, .spec = a },
        .{ .delta = 2, .spec = b },
    } };
    try expectWalk(spread, &[_]RangeSpec{ .empty, .empty, .empty, a, a, b });
    try std_testing.expect(spread.isInfinite());

    // `iter` is a prefix of `iterInfinite`, which then repeats the last spec.
    var finite = spread.iter();
    var infinite = spread.iterInfinite();
    for (0..6) |_| {
        const got = try nextSpec(&finite);
        try std_testing.expect(got.eql(infinite.next()));
    }
    try std_testing.expect(finite.next() == null);
    try std_testing.expect(infinite.isAtEnd());
    for (0..4) |_| try std_testing.expect(b.eql(infinite.next()));

    // A sequence of one non-empty pair is the "whole collection, forever" form
    // upstream's `ChunkRangesSeq::all` is.
    const all: RangeSpecSeq = .{ .items = &.{.{ .delta = 0, .spec = .all }} };
    try expectWalk(all, &[_]RangeSpec{.all});
    try std_testing.expect(all.isInfinite());
    var all_walk = all.iterInfinite();
    for (0..3) |_| try std_testing.expect(RangeSpec.all.eql(all_walk.next()));
}

test "RangeSpecSeq: a saturating delta cannot rewind the walk" {
    // Upstream adds deltas unchecked, and a wrapped sum would put a later pair
    // behind the walk, handing every remaining blob the wrong spec.
    const late: RangeSpec = .{ .widths = &.{9} };
    const seq: RangeSpecSeq = .{ .items = &.{
        .{ .delta = 4, .spec = .all },
        .{ .delta = std.math.maxInt(u64), .spec = late },
    } };
    var walk = seq.iter();

    // Blobs 0 to 3 are before the first pair, and blob 4 is the first pair.
    for (0..4) |_| try std_testing.expect((try nextSpec(&walk)).isEmpty());
    // The sum of the deltas saturates at `u64.max`, so the second pair starts
    // past every blob there is. Unchecked addition would wrap it to 3, which
    // is behind the walk, and blob 5 would then be handed its spec instead.
    for (0..4) |_| try std_testing.expect(RangeSpec.all.eql(try nextSpec(&walk)));
}

test "RangeSpecSeq: a zero delta is a second pair, not a shared start" {
    // Two pairs with the same start is a legal encoding, and it is not the
    // same sequence as one pair. Upstream's walk emits a blob per pair once it
    // has passed a start, so the second pair lands on the blob *after* the
    // first, and the walk is one longer than the sum of the deltas. The
    // fuzzer found this: the seed is two pairs whose deltas are 2 and 0.
    const a: RangeSpec = .{ .widths = &.{ 1, 2 } };
    const b: RangeSpec = .{ .widths = &.{ 7, 6 } };
    const seq: RangeSpecSeq = .{ .items = &.{
        .{ .delta = 2, .spec = a },
        .{ .delta = 0, .spec = b },
    } };
    try expectWalk(seq, &[_]RangeSpec{ .empty, .empty, a, b });

    // A zero first delta is a different thing again: the first pair is taken
    // at blob 0, because nothing is before it.
    const head: RangeSpecSeq = .{ .items = &.{
        .{ .delta = 0, .spec = a },
        .{ .delta = 0, .spec = b },
    } };
    try expectWalk(head, &[_]RangeSpec{ a, b });
}

test "RangeSpecSeq: a decoded empty sequence has no last pair to read" {
    // One byte, a zero count, no pairs: a legal frame, and so a legal answer
    // from `parse`. Every last-element path below is reachable from it.
    var scratch: [8]u8 = undefined;
    const bytes = try parseHex(&scratch, "00");
    var items: [4]Item = undefined;
    var widths: [8]u64 = undefined;
    var reader = postcard.Reader.init(bytes);
    const decoded = try RangeSpecSeq.parse(&reader, &items, &widths);
    try reader.finish();

    try std_testing.expectEqual(@as(usize, 0), decoded.items.len);
    try std_testing.expect(decoded.isEmpty());
    try std_testing.expect(!decoded.isInfinite());
    try expectWalk(decoded, &[_]RangeSpec{});

    var walk = decoded.iterInfinite();
    try std_testing.expect(walk.isAtEnd());
    try std_testing.expect(walk.next().isEmpty());

    // The other polarity, from a decode rather than a literal: a sequence
    // whose last pair selects something repeats forever, and a sequence that
    // always answered false would pass everything above.
    const tail: RangeSpecSeq = .{ .items = &.{.{ .delta = 0, .spec = .all }} };
    var buffer: [8]u8 = undefined;
    var writer = postcard.Writer.init(&buffer);
    try tail.write(&writer);
    var tail_reader = postcard.Reader.init(writer.finish());
    const decoded_tail = try RangeSpecSeq.parse(&tail_reader, &items, &widths);
    try tail_reader.finish();
    try std_testing.expect(decoded_tail.isInfinite());
    try std_testing.expect(tail.eql(decoded_tail));
}

test "codec: every captured vector round trips as a fixed point" {
    for (spec_vectors) |vector| {
        var first: [64]u8 = undefined;
        var writer = postcard.Writer.init(&first);
        try vector.spec.write(&writer);
        const encoded = writer.finish();

        var widths: [16]u64 = undefined;
        var reader = postcard.Reader.init(encoded);
        const decoded = try RangeSpec.parse(&reader, &widths);
        try reader.finish();

        var second: [64]u8 = undefined;
        var rewriter = postcard.Writer.init(&second);
        try decoded.write(&rewriter);
        try expectHex(encoded, rewriter.finish());
        try std_testing.expect(vector.spec.eql(decoded));
    }

    for (seq_vectors) |vector| {
        var first: [64]u8 = undefined;
        var writer = postcard.Writer.init(&first);
        try vector.seq.write(&writer);
        const encoded = writer.finish();

        var items: [8]Item = undefined;
        var widths: [32]u64 = undefined;
        var reader = postcard.Reader.init(encoded);
        const decoded = try RangeSpecSeq.parse(&reader, &items, &widths);
        try reader.finish();

        var second: [64]u8 = undefined;
        var rewriter = postcard.Writer.init(&second);
        try decoded.write(&rewriter);
        try expectHex(encoded, rewriter.finish());
        try std_testing.expect(vector.seq.eql(decoded));
    }
}

test "codec: a writer with no room is BufferFull, never a resize" {
    var buffer: [3]u8 = undefined;
    var writer = postcard.Writer.init(&buffer);
    const spec: RangeSpec = .{ .widths = &.{ 1, 2, 6, 4 } };
    try std_testing.expectError(error.BufferFull, spec.write(&writer));

    const seq: RangeSpecSeq = .{ .items = &.{
        .{ .delta = 0, .spec = .{ .widths = &.{ 1, 2 } } },
        .{ .delta = 1, .spec = .{ .widths = &.{ 7, 6 } } },
    } };
    var small: [5]u8 = undefined;
    var seq_writer = postcard.Writer.init(&small);
    try std_testing.expectError(error.BufferFull, seq.write(&seq_writer));
}

test "codec: malformed spec encodings are named errors" {
    // No length prefix at all: the frame ends before the first field.
    try expectSpecError("", error.UnexpectedEnd);

    // A count the frame cannot possibly satisfy, twice: one with nothing after
    // it, one with less than it claims. The buffer is not short of bytes, the
    // frame claims to carry more than it holds.
    try expectSpecError("05", error.BadLength);
    try expectSpecError("0201", error.BadLength);

    // A varint that keeps its continuation bit set for every byte a u64 has
    // room for: no number of further bytes makes it fit.
    try expectSpecError("01" ++ "80" ** 10, error.BadVarint);

    // A varint that terminates inside the width but whose last byte carries
    // more value bits than a u64 has left: a number, not an encoding.
    try expectSpecError("01" ++ "80" ** 9 ++ "02", error.ValueOutOfRange);

    // A count that fits the bytes that follow, and elements that then run out
    // mid-varint.
    try expectSpecError("028080", error.UnexpectedEnd);

    // A valid spec with a byte after it. `finish` is the only thing that sees
    // it, which is why it is not automatic.
    try expectSpecErrorWithTrailer("010000", error.TrailingBytes);

    // A destination too small for the count the frame declared. The codec
    // names this `BufferFull` for a writer; a decode into a buffer the caller
    // sized is the same condition.
    var widths: [0]u64 = .{};
    var reader = postcard.Reader.init(&[_]u8{ 0x02, 0x00, 0x00 });
    try std_testing.expectError(error.BufferFull, RangeSpec.parse(&reader, &widths));
}

test "codec: malformed sequence encodings are named errors" {
    // An empty frame read as a sequence is a valid empty sequence, so the
    // first rejected byte has to be somewhere a peer can actually put one.
    try expectSeqError("", error.UnexpectedEnd);
    try expectSeqError("05", error.BadLength);
    // One pair whose spec claims nine widths and has none.
    try expectSeqError("02" ++ "00" ++ "09", error.BadLength);
    try expectSeqError("01" ++ "00" ++ "01" ++ "80" ** 10, error.BadVarint);
    try expectSeqError("01" ++ "00" ++ "01" ++ "80" ** 9 ++ "02", error.ValueOutOfRange);
    try expectSeqErrorWithTrailer("0000", error.TrailingBytes);

    // The specs of every pair share one width buffer, so a frame can name more
    // widths than the caller sized even when it names fewer than it holds.
    {
        var items: [1]Item = undefined;
        var widths: [1]u64 = undefined;
        var reader = postcard.Reader.init(&[_]u8{ 0x01, 0x00, 0x02, 0x05, 0x06 });
        try std_testing.expectError(
            error.BufferFull,
            RangeSpecSeq.parse(&reader, &items, &widths),
        );
    }
    {
        // Two pairs, and one width between them: the first spec takes the only
        // slot and the second finds none left.
        var items: [2]Item = undefined;
        var widths: [1]u64 = undefined;
        const bytes = [_]u8{ 0x02, 0x00, 0x01, 0x05, 0x00, 0x01, 0x06 };
        var reader = postcard.Reader.init(&bytes);
        try std_testing.expectError(
            error.BufferFull,
            RangeSpecSeq.parse(&reader, &items, &widths),
        );
    }
}

/// The bytes a hexdump above stands for, decoded into `out`. A hexdump needs
/// no allocator: every one of them lands in a scratch buffer the test already
/// has.
fn parseHex(out: []u8, hex: []const u8) ![]const u8 {
    if (hex.len % 2 != 0) return error.OddHexLength;
    return std.fmt.hexToBytes(out, hex);
}

fn expectSpecError(hex: []const u8, expected: postcard.Error) !void {
    var scratch: [64]u8 = undefined;
    const bytes = try parseHex(&scratch, hex);
    var widths: [64]u64 = undefined;
    var reader = postcard.Reader.init(bytes);
    try std_testing.expectError(expected, RangeSpec.parse(&reader, &widths));
}

fn expectSpecErrorWithTrailer(hex: []const u8, expected: postcard.Error) !void {
    var scratch: [64]u8 = undefined;
    const bytes = try parseHex(&scratch, hex);
    var widths: [64]u64 = undefined;
    var reader = postcard.Reader.init(bytes);
    _ = try RangeSpec.parse(&reader, &widths);
    try std_testing.expectError(expected, reader.finish());
}

fn expectSeqError(hex: []const u8, expected: postcard.Error) !void {
    var scratch: [64]u8 = undefined;
    const bytes = try parseHex(&scratch, hex);
    var items: [64]Item = undefined;
    var widths: [64]u64 = undefined;
    var reader = postcard.Reader.init(bytes);
    try std_testing.expectError(expected, RangeSpecSeq.parse(&reader, &items, &widths));
}

fn expectSeqErrorWithTrailer(hex: []const u8, expected: postcard.Error) !void {
    var scratch: [64]u8 = undefined;
    const bytes = try parseHex(&scratch, hex);
    var items: [64]Item = undefined;
    var widths: [64]u64 = undefined;
    var reader = postcard.Reader.init(bytes);
    _ = try RangeSpecSeq.parse(&reader, &items, &widths);
    try std_testing.expectError(expected, reader.finish());
}

/// Drain a walk into `storage`, which the tests size past any spec they build,
/// and hand back just the spans that came out.
fn collect(storage: []Span, walk: SpanIter) []Span {
    var it = walk;
    var count: usize = 0;
    while (it.next()) |span| {
        std.debug.assert(count < storage.len);
        storage[count] = span;
        count += 1;
    }
    return storage[0..count];
}

/// The specs the finite walk yields, in order, and nothing after.
fn expectWalk(seq: RangeSpecSeq, expected: []const RangeSpec) !void {
    var walk = seq.iter();
    for (expected) |want| {
        try std_testing.expect(want.eql(try nextSpec(&walk)));
    }
    try std_testing.expect(walk.next() == null);
}

/// The next spec of a finite walk, or a named failure rather than a panic: a
/// test that reaches this has already decided how long the walk is.
fn nextSpec(walk: anytype) !RangeSpec {
    return walk.next() orelse error.WalkEndedEarly;
}

/// Long enough for every hexdump above. This is a diagnostic, not a general
/// formatter: the bytes it prints are the ones written down in this file.
const max_dumped_bytes = 32;

fn expectHex(expected: []const u8, actual: []const u8) !void {
    if (std.mem.eql(u8, expected, actual)) return;
    std.debug.print("expected {d} bytes: {s}\n     got {d} bytes: {s}\n", .{
        expected.len, &hexdump(expected),
        actual.len,   &hexdump(actual),
    });
    return error.WireFormatMismatch;
}

fn hexdump(bytes: []const u8) [2 * max_dumped_bytes]u8 {
    var out: [2 * max_dumped_bytes]u8 = undefined;
    const digits = "0123456789abcdef";
    const shown = @min(bytes.len, max_dumped_bytes);
    for (bytes[0..shown], 0..) |byte, index| {
        out[index * 2] = digits[byte >> 4];
        out[index * 2 + 1] = digits[byte & 15];
    }
    @memset(out[shown * 2 ..], ' ');
    // ZBC cannot combine the loop's byte pairs with memset to prove the full array initialized.
    // zbc-disable-next-line: use-undefined
    return out;
}
