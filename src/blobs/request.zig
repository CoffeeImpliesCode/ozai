//! The four request bodies a getter sends, and nothing about how they are
//! framed.
//!
//! One of the four modules `protocol.zig` is split into. A request here is a
//! value: a hash, a `RangeSpec` or a `RangeSpecSeq`, and the two builders
//! upstream writes for a whole blob and for a collection. The discriminant
//! byte in front of it, the two ways the bytes can be framed on a stream and
//! the readers that decide between them are `framing.zig`'s, because that is
//! what makes a `push` and a `get` with the same body different frames rather
//! than the same frame read twice.
//!
//! The identity of the protocol — its ALPN, its message cap, its error set and
//! the caller-owned scratch every decode fills — stays in `protocol.zig`, and
//! `Error` and `Storage` are reached from there. They are aliased locally so
//! that a reader of this file sees the same names the declarations were written
//! with when they lived beside the framing.

const std = @import("std");
const postcard = @import("../wire/postcard.zig");
const range_spec = @import("range_spec.zig");
const protocol = @import("protocol.zig");

/// The protocol's error set and the caller-owned scratch a decode fills. Both
/// live in `protocol.zig`, which every one of the four modules imports.
const Error = protocol.Error;
const Storage = protocol.Storage;

/// The BLAKE3 hash a request names.
///
/// `ticket/blob_ticket.zig` calls this same `[32]u8` its `Hash`, and both
/// modules put the same 32 bytes on the wire; it is one type under two names,
/// not two types. This is a private alias so the name does not become a third.
/// `protocol.Storage`'s `hashes` buffer is the same `[32]u8` under its own
/// spelling, which is why it needs no name here.
const Hash = [32]u8;

const hash_length = @sizeOf(Hash);

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
    /// the golden vectors in `framing.zig`.
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
const blob_ranges = [_]range_spec.Item{
    .{ .delta = 0, .spec = range_spec.RangeSpec.all },
    .{ .delta = 1, .spec = range_spec.RangeSpec.empty },
};

/// The sequence `GetRequest::all` sends: all of the collection, and nothing
/// after it, so the walk repeats it for every child forever.
const all_ranges = [_]range_spec.Item{
    .{ .delta = 0, .spec = range_spec.RangeSpec.all },
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

const testing = std.testing;

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
