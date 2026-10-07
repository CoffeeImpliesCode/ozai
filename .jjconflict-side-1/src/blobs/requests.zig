//! The four request bodies, the item an observe answer is a run of, and the
//! caller-owned storage every decode in this protocol fills.
//!
//! `Storage` is why nothing here allocates: every slice a decoded message
//! points at lives in one the caller owns, and each field says exactly what its
//! own parse leaves behind on the failure paths, because a decode overwrites
//! the fields it uses and that is what invalidates an earlier result.
//!
//! These are bodies only. How one of them is framed on a stream belongs to
//! `framing.zig`, and that is what lets a `push` and a `get` be the same bytes
//! under a different rule rather than one request type with a flag.

const std = @import("std");
const postcard = @import("../wire/postcard.zig");
const range_spec = @import("range_spec.zig");
const ranges_mod = @import("ranges.zig");

const testing = std.testing;

// `ObserveItem`'s range set is a boundary list rather than a spec sequence, and
// the type that says so is the one that owns it.
const ChunkRangeSet = ranges_mod.ChunkRangeSet;

/// The BLAKE3 hash a request names.
///
/// `ticket/blob_ticket.zig` calls this same `[32]u8` its `Hash`, and both
/// modules put the same 32 bytes on the wire; it is one type under two names,
/// not two types. The name stops here: `blobs/protocol.zig` re-binds it
/// privately for its own tests and exports no third name for it.
pub const Hash = [32]u8;

const hash_length = @sizeOf(Hash);

/// Caller-owned scratch a decode fills.
///
/// Every slice a decoded message points at lives in one of these, which is why
/// nothing in this file allocates: a decoded `GetManyRequest` borrows `hashes`,
/// and a decoded `RangeSpecSeq` borrows `items` and `widths` together. The
/// defaults are empty, and an empty field is not a special case — a decode that
/// needs room it was not given is `error.BufferFull`, the same condition
/// `postcard.Writer` names for a writer, and it is checked against the count
/// the frame declared rather than against the bytes that remain.
///
/// **A decode overwrites the fields it uses, and that is what invalidates an
/// earlier result.** The exact operations, so a caller can say whether the
/// message it is still holding has been written over:
///
/// - `Request.read`, `EofFraming.read`, `LengthPrefixedFraming.read`,
///   `GetRequest.parse`, `GetManyRequest.parse` and `PushRequest.parse` all
///   write `items` and `widths` through `RangeSpecSeq.parse`. `GetRequest.parse`
///   and `PushRequest.parse` write nothing else; `GetManyRequest.parse` writes
///   `hashes` as well.
/// - `ObserveRequest.parse` writes `widths`.
/// - `ObserveItem.parse` writes `boundaries`, and so does every
///   `ObserveResponse.next` — the returned item of one call is overwritten by
///   the next.
///
/// A decode that does not reach a field leaves it alone, so two messages
/// decoded into *different* `Storage` values are independent, and one field
/// being invalidated does not invalidate the others.
///
/// A decode that fails part way leaves the fields it reached partly written,
/// and each field below says what its own parse leaves behind.
pub const Storage = struct {
    /// RangeSpecSeq pairs; returned ranges borrow them and specs borrow widths.
    /// A failed parse keeps completed pairs in the prefix and prior contents in
    /// the rest. A later decode overwrites the pairs it reaches.
    items: []range_spec.Item = &.{},
    /// Widths, shared by every spec in `items`. Overwritten by the next
    /// `RangeSpec.parse` or `RangeSpecSeq.parse` through this `Storage`.
    ///
    /// A parse that fails leaves them as `RangeSpec.parse` states:
    /// `error.BufferFull` writes nothing, and any other failure leaves the
    /// widths read so far in the leading slots, with the rest of the slice
    /// holding whatever it held before.
    widths: []u64 = &.{},
    /// GetManyRequest.hashes borrows this buffer. A failed parse keeps complete
    /// hashes in the prefix and prior contents in the rest; later parses overwrite it.
    hashes: []Hash = &.{},
    /// Boundaries for an `ObserveItem`'s chunk range set. Borrowed by that
    /// item's `ranges`, and overwritten by the next `ObserveItem.parse` or
    /// `ObserveResponse.next` through this `Storage`.
    ///
    /// A parse that fails leaves them as `ChunkRangeSet.parse` states: the
    /// boundaries read so far sit in the leading slots in wire order, neither
    /// sorted nor deduplicated, and the rest of the slice holds whatever it
    /// held before. `error.BufferFull` writes nothing.
    boundaries: []u64 = &.{},
};

/// A request for one blob, or for a collection and its children.
///
/// Upstream's `GetRequest` at `src/protocol.rs:498`, and the two constructors
/// are upstream's `GetRequest::blob` and `GetRequest::all`
/// (`src/protocol.rs:538`). `hash` and `ranges` are the two fields in that
/// order, and `ranges` borrows.
pub const GetRequest = struct {
    /// The BLAKE3 root hash of the blob or collection.
    hash: Hash,
    /// The ranges of data to request. The first element is the parent and all
    /// subsequent elements are its children, which is upstream's own comment
    /// on the field.
    ranges: range_spec.RangeSpecSeq,

    /// Every chunk of one blob. Upstream builds this from
    /// `ChunkRangesSeq::from_ranges([all])`, which is one selected spec at the
    /// blob and an empty spec one blob on to end the run; the wire form is in
    /// the golden vectors below.
    // `Hash` is a private alias of the public builtin `[32]u8]`, so a caller
    // passes those 32 bytes and names no private type.
    // ziglint-ignore: Z012
    pub fn blob(hash: Hash) GetRequest {
        return .{ .hash = hash, .ranges = .{ .items = &blob_ranges } };
    }

    /// A collection, every chunk of it, and every chunk of every child after
    /// it. Upstream's `ChunkRangesSeq::all()`, which is one selected spec and
    /// nothing after it, so the walk repeats it forever — the way a request
    /// asks for a hash sequence whose length neither side knows.
    // `Hash` is a private alias of the public builtin `[32]u8]`, so a caller
    // passes those 32 bytes and names no private type.
    // ziglint-ignore: Z012
    pub fn all(hash: Hash) GetRequest {
        return .{ .hash = hash, .ranges = .{ .items = &all_ranges } };
    }

    /// The same blob and the same ranges, comparing the borrowed widths by
    /// value.
    pub fn eql(a: GetRequest, b: GetRequest) bool {
        return std.mem.eql(u8, &a.hash, &b.hash) and a.ranges.eql(b.ranges);
    }

    /// Resolve one contiguous root-blob range, or null for collections and
    /// disjoint selections. Provider and getter share this pure interpretation
    /// so neither can answer or verify chunks the other did not select.
    pub fn selectedRange(self: GetRequest, total_chunks: u64) ?ranges_mod.ChunkRange {
        const items = self.ranges.items;
        if (items.len != 2) return null;
        if (items[0].delta != 0) return null;
        if (items[1].delta != 1 or !items[1].spec.isEmpty()) return null;

        var walk = items[0].spec.resolve(total_chunks);
        const first = walk.next() orelse return null;
        const second = walk.next() orelse return .{
            .start = first.offset,
            .end = first.offset + first.size,
        };
        // Closing a gap would transfer chunks the request explicitly omitted.
        if (second.offset != first.offset + first.size) return null;
        if (walk.next() != null) return null;
        return .{ .start = first.offset, .end = second.offset + second.size };
    }

    /// The wire form: 32 raw hash bytes, then a `RangeSpecSeq`. postcard does
    /// not length-prefix a fixed-size array, and a `Hash` is a newtype over
    /// `[u8; 32]`, so the hash is those 32 bytes and nothing else.
    pub fn write(self: GetRequest, writer: *postcard.Writer) postcard.Error!void {
        try writer.writeArray(hash_length, &self.hash);
        try self.ranges.write(writer);
    }

    /// The body of a `get`, which writes `storage.items` and `storage.widths`
    /// and returns a request borrowing them.
    ///
    /// `error.BufferFull` is `storage` being too small for a count the frame
    /// declared, and `storage` is left holding a prefix of what it did hold.
    pub fn parse(reader: *postcard.Reader, storage: *Storage) postcard.Error!GetRequest {
        return .{
            .hash = try reader.readArray(hash_length),
            .ranges = try range_spec.RangeSpecSeq.parse(reader, storage.items, storage.widths),
        };
    }
};

/// The sequence `GetRequest::blob` sends: all of one blob, and an empty spec
/// one blob on to end the run.
pub const blob_ranges = [_]range_spec.Item{
    .{ .delta = 0, .spec = range_spec.RangeSpec.all },
    .{ .delta = 1, .spec = range_spec.RangeSpec.empty },
};

/// The sequence `GetRequest::all` sends: all of the collection, and nothing
/// after it, so the walk repeats it for every child forever.
const all_ranges = [_]range_spec.Item{
    .{ .delta = 0, .spec = range_spec.RangeSpec.all },
};

/// A sequence for a request that asks for part of a blob: two chunks of gap and
/// four selected from there, and nothing after it. It is here so that a
/// `push` frame in the tests is not just a whole-blob request wearing a
/// different framing — a push carries any sequence a `get` can.
pub const push_ranges = [_]range_spec.Item{
    .{ .delta = 0, .spec = .{ .widths = &.{ 2, 4 } } },
};

/// A request for several unrelated blobs, from one provider.
///
/// Upstream's `GetManyRequest` at `src/protocol.rs:580`, and its own doc says
/// what makes it different from a `get` for a hash sequence: "the HashSeq is
/// provided by the requester". There is therefore no spec for a parent, and
/// the list of hashes *is* the list.
pub const GetManyRequest = struct {
    /// The hashes to get, borrowed. A decode fills `storage.hashes`.
    hashes: []const Hash,
    /// One spec per hash, in the same order as `hashes`.
    ranges: range_spec.RangeSpecSeq,

    /// The ranges that ask for every chunk of every one of `count` hashes.
    ///
    /// Upstream's `FromIterator` (`src/protocol.rs:590`) sorts and dedups the
    /// hashes and then writes exactly this: one selected spec at the first
    /// hash, and an empty spec `count` hashes on to end the run. The items go
    /// into `storage` because the count is not known until the caller's slice
    /// is, and nothing here allocates.
    ///
    /// Room for fewer than the two pairs this form writes is not a failure and
    /// writes nothing to `storage`. The answer is `RangeSpecSeq.empty`, the
    /// legal sequence that names no blob at all, so the request asks for
    /// nothing; a caller that must ask for every chunk of `count` hashes hands
    /// over the two slots the form needs.
    pub fn allRanges(
        storage: []range_spec.Item,
        count: u64,
    ) range_spec.RangeSpecSeq {
        if (storage.len < 2) return .empty;
        storage[0] = .{ .delta = 0, .spec = range_spec.RangeSpec.all };
        storage[1] = .{ .delta = count, .spec = range_spec.RangeSpec.empty };
        return .{ .items = storage[0..2] };
    }

    /// The same hashes in the same order and the same ranges. Order matters:
    /// one spec lines up with one hash.
    pub fn eql(a: GetManyRequest, b: GetManyRequest) bool {
        if (a.hashes.len != b.hashes.len) return false;
        for (a.hashes, b.hashes) |left, right| {
            if (!std.mem.eql(u8, &left, &right)) return false;
        }
        return a.ranges.eql(b.ranges);
    }

    /// The wire form: a count of hashes, the hashes, then a `RangeSpecSeq`. A
    /// postcard `Vec` is a length and that many elements, and a `Hash`
    /// element is 32 raw bytes.
    pub fn write(self: GetManyRequest, writer: *postcard.Writer) postcard.Error!void {
        try writer.writeLen(self.hashes.len);
        for (self.hashes) |hash| try writer.writeArray(hash_length, &hash);
        try self.ranges.write(writer);
    }

    /// The body of a `get_many`, which writes `storage.hashes`,
    /// `storage.items` and `storage.widths`, and returns a request borrowing
    /// all three.
    ///
    /// `error.BufferFull` is any of those buffers being too small for a count
    /// the frame declared; the buffers hold a prefix of what they did hold,
    /// and no part of the request is returned.
    pub fn parse(
        reader: *postcard.Reader,
        storage: *Storage,
    ) postcard.Error!GetManyRequest {
        const count = try reader.readLen();
        // Every hash is 32 bytes on the wire and `readLen` has already checked
        // the count against the bytes that remain, so this is only ever the
        // caller's buffer being too small for a count the frame could carry.
        if (count > storage.hashes.len) return error.BufferFull;
        for (storage.hashes[0..count]) |*hash| hash.* = try reader.readArray(hash_length);
        return .{
            .hashes = storage.hashes[0..count],
            .ranges = try range_spec.RangeSpecSeq.parse(reader, storage.items, storage.widths),
        };
    }
};

/// A request to watch one raw blob's availability.
///
/// Upstream's `ObserveRequest` at `src/protocol.rs:618`. `ranges` is a
/// `RangeSpec` and not a `RangeSpecSeq`, and that is upstream's own field type:
/// an observe is about one blob, so there is no per-child list to run-length
/// encode.
pub const ObserveRequest = struct {
    /// The BLAKE3 root hash of the blob to watch.
    hash: Hash,
    /// The chunks to observe. Upstream's `ObserveRequest::new` sends `all`.
    ranges: range_spec.RangeSpec,

    /// The same blob and the same chunks to watch.
    pub fn eql(a: ObserveRequest, b: ObserveRequest) bool {
        return std.mem.eql(u8, &a.hash, &b.hash) and a.ranges.eql(b.ranges);
    }

    /// The wire form: 32 raw hash bytes, then a `RangeSpec`.
    pub fn write(self: ObserveRequest, writer: *postcard.Writer) postcard.Error!void {
        try writer.writeArray(hash_length, &self.hash);
        try self.ranges.write(writer);
    }

    /// The body of an `observe`, which writes `storage.widths` and returns a
    /// request borrowing them.
    ///
    /// On error the reader may have advanced past the hash and into the range
    /// widths, and `storage.widths` may already hold the prefix
    /// `RangeSpec.parse` wrote; no request is returned. `error.BufferFull` is a
    /// declared width count larger than `storage.widths` and writes nothing.
    pub fn parse(reader: *postcard.Reader, storage: *Storage) postcard.Error!ObserveRequest {
        return .{
            .hash = try reader.readArray(hash_length),
            .ranges = try range_spec.RangeSpec.parse(reader, storage.widths),
        };
    }
};

/// A `Push` request, which is a `GetRequest` under a different discriminant.
///
/// Upstream's `PushRequest(GetRequest)` at `src/protocol.rs:567`, a newtype
/// over exactly one `GetRequest`, which is why the wire form is identical and
/// the only difference is the byte in front and the framing behind it.
pub const PushRequest = struct {
    /// The `get` this framing carries. After a decode its `ranges` borrow
    /// `storage.items` and `storage.widths`.
    get: GetRequest,

    // `Hash` is a private alias of the public builtin `[32]u8]`, so a caller
    // passes those 32 bytes and names no private type.
    // ziglint-ignore: Z012
    /// A `push` for `hash` over `ranges`. `ranges` is borrowed, and the
    /// discriminant and the framing around it are what make this a `push`
    /// rather than a `get`.
    pub fn new(hash: Hash, ranges: range_spec.RangeSpecSeq) PushRequest {
        return .{ .get = .{ .hash = hash, .ranges = ranges } };
    }

    /// Equality of the wrapped `get`.
    pub fn eql(a: PushRequest, b: PushRequest) bool {
        return a.get.eql(b.get);
    }

    /// The wire form, which is `GetRequest`'s: the discriminant in front of it
    /// is what makes this a `push`.
    pub fn write(self: PushRequest, writer: *postcard.Writer) postcard.Error!void {
        try self.get.write(writer);
    }

    /// The body of a `push`, which writes `storage.items` and
    /// `storage.widths` exactly as `GetRequest.parse` does.
    pub fn parse(reader: *postcard.Reader, storage: *Storage) postcard.Error!PushRequest {
        return .{ .get = try GetRequest.parse(reader, storage) };
    }
};

/// One update to an observed blob's availability.
///
/// Upstream's `ObserveItem` at `src/protocol.rs:635`. A provider sends the
/// whole bitfield first and then the *difference* from the last one
/// (`src/provider.rs:644`, `old.diff(&new)`), so an item is an update and not
/// a snapshot; `size` is the blob's size in bytes, which is how a getter
/// learns a size without asking for a `get`.
///
/// `ranges` is a `ChunkRangeSet` and not a `RangeSpec`, and the two are one
/// count and that many `varint(u64)`s apart. See `ChunkRangeSet` for the whole
/// of why that matters.
pub const ObserveItem = struct {
    /// The observed blob's size in bytes.
    size: u64,
    /// Which chunks the provider has, as a boundary list.
    ranges: ChunkRangeSet,

    /// The same size and the same chunk range set.
    pub fn eql(a: ObserveItem, b: ObserveItem) bool {
        return a.size == b.size and a.ranges.eql(b.ranges);
    }

    /// The wire form: the size as a `varint(u64)`, then the range set.
    pub fn write(self: ObserveItem, writer: *postcard.Writer) postcard.Error!void {
        try writer.writeU64(self.size);
        try self.ranges.write(writer);
    }

    /// One item, which writes `storage.boundaries` and returns an item
    /// borrowing them.
    ///
    /// The next item read through the same `Storage` overwrites those
    /// boundaries; see `ObserveResponse.next`.
    ///
    /// On error the reader may have advanced past the size and into the
    /// boundary list, and `storage.boundaries` may already hold the boundaries
    /// read so far, unsorted and undeduplicated; no item is returned.
    /// `error.BufferFull` is a declared boundary count larger than
    /// `storage.boundaries` and writes nothing.
    pub fn parse(reader: *postcard.Reader, storage: *Storage) postcard.Error!ObserveItem {
        return .{
            .size = try reader.readU64(),
            .ranges = try ChunkRangeSet.parse(reader, storage.boundaries),
        };
    }
};

test "GetManyRequest.allRanges is upstream's FromIterator" {
    // Upstream's `FromIterator` (`src/protocol.rs:590`) sorts and dedups the
    // hashes and then writes one selected spec at the first hash and an empty
    // spec `count` hashes on to end the run. Three cases, including the empty
    // one: a `get_many` for no hashes is a legal frame.
    // One buffer per case, because every one of these writes the same two slots
    // and a walk over a sequence whose storage has since been overwritten is a
    // walk over the wrong sequence.
    var none_items: [2]range_spec.Item = undefined;
    var one_items: [2]range_spec.Item = undefined;
    var three_items: [2]range_spec.Item = undefined;

    const none = GetManyRequest.allRanges(&none_items, 0);
    try testing.expectEqual(@as(usize, 2), none.items.len);
    try testing.expectEqual(@as(u64, 0), none.items[0].delta);
    try testing.expect(none.items[0].spec.isAll());
    try testing.expectEqual(@as(u64, 0), none.items[1].delta);
    try testing.expect(none.items[1].spec.isEmpty());

    // One hash: the selected spec is at it and the terminator is at the one
    // after, so the walk covers the hash and then stops.
    const one = GetManyRequest.allRanges(&one_items, 1);
    try testing.expectEqual(@as(u64, 1), one.items[1].delta);
    try testing.expect(!one.isInfinite());
    {
        var walk = one.iter();
        try testing.expect(walk.next().?.isAll());
        try testing.expect(walk.next().?.isEmpty());
        try testing.expect(walk.next() == null);
    }
    // With no hashes both pairs start at the same place, and the walk is one
    // blob past the pair before it, so the run covers two blobs and selects
    // nothing on the second. Upstream's builder drops a hash whose ranges are
    // empty, so a real `get_many` never sends this frame.
    {
        var walk = none.iter();
        try testing.expect(walk.next().?.isAll());
        try testing.expect(walk.next().?.isEmpty());
        try testing.expect(walk.next() == null);
    }

    const three = GetManyRequest.allRanges(&three_items, 3);
    try testing.expectEqual(@as(u64, 3), three.items[1].delta);
    try testing.expect(!three.isInfinite());
    // Room for fewer than the two pairs the form needs is the empty sequence
    // rather than a write past the caller's buffer.
    var tight: [1]range_spec.Item = undefined;
    try testing.expect(GetManyRequest.allRanges(&tight, 4).isEmpty());
    try testing.expect(GetManyRequest.allRanges(&.{}, 4).isEmpty());
}

test "single blob range resolution clips chunks and refuses disjoint or collection walks" {
    const hash: Hash = @splat(0);
    const whole = GetRequest.blob(hash).selectedRange(49).?;
    try testing.expectEqual(@as(u64, 0), whole.start);
    try testing.expectEqual(@as(u64, 49), whole.end);
    try testing.expectEqual(null, GetRequest.all(hash).selectedRange(49));
    const partial_items = [_]range_spec.Item{
        .{ .delta = 0, .spec = .{ .widths = &.{ 47, 10 } } },
        .{ .delta = 1, .spec = range_spec.RangeSpec.empty },
    };
    const partial: GetRequest = .{ .hash = hash, .ranges = .{ .items = &partial_items } };
    const clipped = partial.selectedRange(49).?;
    try testing.expectEqual(@as(u64, 47), clipped.start);
    try testing.expectEqual(@as(u64, 49), clipped.end);
    const gapped_items = [_]range_spec.Item{
        .{ .delta = 0, .spec = .{ .widths = &.{ 2, 4, 3, 1 } } },
        .{ .delta = 1, .spec = range_spec.RangeSpec.empty },
    };
    const gapped: GetRequest = .{ .hash = hash, .ranges = .{ .items = &gapped_items } };
    try testing.expectEqual(null, gapped.selectedRange(49));
}
