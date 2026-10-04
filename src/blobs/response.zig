//! What a provider sends back: bao-encoded data to the end of a stream, and a
//! run of availability updates for an `observe`.
//!
//! One of the four modules `protocol.zig` is split into. The framing a request
//! arrives in, and the discriminant that decides it, are `framing.zig`'s.
//! What is here is the other direction, and it has exactly two shapes because
//! upstream has exactly two (`src/protocol.rs:320` and `src/provider.rs:644`):
//! a whole bao stream that ends when the provider stops writing, and a run of
//! length-prefixed updates.
//!
//! # There is no error frame
//!
//! Nothing on this path has a wire form of its own. A `get` answer is bao data
//! until the provider stops writing, and a provider that does not have the
//! data stops writing: upstream's `# Responses` section
//! (`src/protocol.rs:320`) says the provider "will close just the stream used
//! to send the response", and the reason is recovered from the resulting
//! error on the getter's side rather than from anything in the bytes.
//!
//! So this type has no error arm and cannot be decoded from an error value. A
//! short answer is a short answer: `bytes` is what arrived, and whether that
//! covers the request is a question for the bao decoder and not for this one.
//! An empty answer and a zero-length blob are the same bytes, which is the
//! whole reason the decision cannot be made here.
//!
//! # Purity
//!
//! Nothing here reads a clock, the environment, a global or an allocator. Both
//! types borrow the caller's reader and the caller's `Storage`, and every slice
//! a decoded item points at lives in the latter; see `protocol.zig`'s module
//! comment for the argument this rests on, and for the rule about which decode
//! overwrites which field.

const std = @import("std");
const postcard = @import("../wire/postcard.zig");
const chunk = @import("chunk.zig");
/// The module's shared vocabulary and its shared test scaffolding, plus the
/// length-prefix rule both a `push` body and an observe item are written with.
const protocol = @import("protocol.zig");
const framing = @import("framing.zig");

/// The protocol's error set and the caller-owned scratch a decode fills. Both
/// live in `protocol.zig`, which every one of the four modules imports.
const Error = protocol.Error;
const Storage = protocol.Storage;

/// The boundary list an item's ranges are, and the length-prefix rule that
/// frames it.
const ChunkRangeSet = chunk.ChunkRangeSet;

/// A provider's answer to a `Get`, `GetMany` or `Push`: bao-encoded data, to
/// the end of the stream.
///
/// # There is no error frame
///
/// Nothing on this path has a wire form of its own. A `get` answer is bao data
/// until the provider stops writing, and a provider that does not have the
/// data stops writing: upstream's `# Responses` section
/// (`src/protocol.rs:320`) says the provider "will close just the stream used
/// to send the response", and the reason is recovered from the resulting
/// error on the getter's side rather than from anything in the bytes.
///
/// So this type has no error arm and cannot be decoded from an error value. A
/// short answer is a short answer: `bytes` is what arrived, and whether that
/// covers the request is a question for the bao decoder and not for this one.
/// An empty answer and a zero-length blob are the same bytes, which is the
/// whole reason the decision cannot be made here.
pub const BaoResponse = struct {
    /// Every byte the provider wrote, borrowed from the caller's buffer.
    bytes: []const u8,

    /// The rest of `reader`. Nothing is read, because there is nothing here to
    /// read: the answer is whatever remains.
    pub fn read(reader: *postcard.Reader) BaoResponse {
        return .{ .bytes = rest(reader) };
    }

    /// The provider ended the stream without writing anything.
    ///
    /// This is what a provider that does not have the requested data looks
    /// like from here, and also what an empty blob's answer looks like. The
    /// two are the same bytes and this type cannot tell them apart, which is
    /// the honest answer and the reason a missing range cannot be a decoded
    /// value.
    pub fn isEof(self: BaoResponse) bool {
        return self.bytes.len == 0;
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

/// A provider's running answer to an `Observe`: a run of `ObserveItem`s to the
/// end of the stream.
///
/// The items are length-prefixed, from upstream's `send_observe_item`
/// (`src/provider.rs:664`), which calls the same `write_length_prefixed` a
/// `push` request is written with. The prefix is here for the reason it is
/// there: a run has no other boundary, so without it a getter could not tell
/// one update from the next. That prefix is read by `framing.zig`'s
/// `readLengthPrefaced`, because it is the same rule and a second
/// implementation of the cap would be a second place for it to be wrong.
///
/// The response is a cursor, not a container: it holds the reader it consumes
/// and the storage its items are read into, and neither is copied. Both must
/// stay alive, and the reader must stay at the position `read` left it, for as
/// long as the response is used — `read` does not consume anything, and every
/// `next` advances the shared reader.
pub const ObserveResponse = struct {
    /// The reader the run is read from. `next` advances it; nothing else
    /// touches it, and a second reader over the same bytes reads the run from
    /// its own position.
    reader: *postcard.Reader,
    /// Where each item is decoded. Every `next` overwrites its `boundaries`.
    storage: *Storage,

    /// A response reading `reader` to its end, through `storage`.
    ///
    /// Nothing is consumed and nothing is decoded here, so the response is
    /// valid the moment it is returned and reads nothing until `next` is
    /// called.
    pub fn read(reader: *postcard.Reader, storage: *Storage) ObserveResponse {
        return .{ .reader = reader, .storage = storage };
    }

    /// The next item, or `null` at the end of the stream.
    ///
    /// `null` is EOF, and for an observe it is the ordinary end of a run and
    /// not a failure. A length prefix that promises more than the stream holds
    /// is `error.UnexpectedEnd`, which is a different thing: a stream that
    /// stopped *inside* an item has lost bytes, and one that stopped *between*
    /// two has not. Keeping them apart is the point — the first ends a
    /// transfer cleanly and the second means the answer is incomplete.
    ///
    /// **The item borrows `storage.boundaries`, and the next call overwrites
    /// them.** Only `ranges` is invalidated; `size` is a value in the returned
    /// item and stays readable. A caller that needs the boundaries of two items
    /// at once has to copy each one before asking for the next.
    ///
    /// On success the reader is past this item. On error it may have consumed
    /// a length prefix or body. Abandon this iteration; retry is not promised.
    pub fn next(self: *ObserveResponse) Error!?ObserveItem {
        if (self.reader.remaining() == 0) return null;
        var body = try framing.readLengthPrefaced(self.reader);
        const item = try ObserveItem.parse(&body, self.storage);
        try body.finish();
        return item;
    }
};

/// What `reader` has not read yet.
fn rest(reader: *postcard.Reader) []const u8 {
    return reader.buffer[reader.offset..];
}

const testing = std.testing;

test "missing data is EOF, not an error frame" {
    // A provider that does not have the data closes its side, so the answer is
    // the empty stream. It is not a value to decode, and this type has nowhere
    // to put one.
    {
        var reader = postcard.Reader.init("");
        try testing.expect(BaoResponse.read(&reader).isEof());
    }

    // A provider that stops part way through is the truncated case. It is a
    // short answer and not a failure, and the only things this type holds are
    // the bytes that arrived: whether they cover the request is a question for
    // the bao decoder, which is why nothing here can turn one into the other.
    const partial = [_]u8{ 0x00, 0x01, 0x02 };
    {
        var reader = postcard.Reader.init(&partial);
        const answer = BaoResponse.read(&reader);
        try testing.expect(!answer.isEof());
        try testing.expectEqualSlices(u8, &partial, answer.bytes);
    }

    var room: protocol.Room = .{};
    var storage = room.storage();

    // An observe run that ends between two items is EOF too, and it is a
    // `null` rather than an error: a provider sends the bitfield once and
    // then sends updates until the observer loses interest
    // (`src/provider.rs:644`), so the end of the stream is the ordinary end.
    // And a stream whose first byte is a length of zero is *not* that: there
    // are bytes here, and they do not decode, so the run is broken rather than
    // finished. `next` returns `null` only at a boundary.
    {
        var reader = postcard.Reader.init(&partial);
        var run = ObserveResponse.read(&reader, &storage);
        try testing.expectError(error.UnexpectedEnd, run.next());
    }
    {
        var reader = postcard.Reader.init("");
        var run = ObserveResponse.read(&reader, &storage);
        try testing.expect(try run.next() == null);
    }

    // A run that stops *inside* an item is a different thing and says so: a
    // length of five with three bytes behind it has lost bytes, and conflating
    // that with the end of a run is what would turn a broken stream into a
    // clean finish.
    {
        var reader = postcard.Reader.init(&[_]u8{ 0x05, 0x00, 0x00, 0x00 });
        var run = ObserveResponse.read(&reader, &storage);
        try testing.expectError(error.UnexpectedEnd, run.next());
    }

    // A well-formed item on a stream, and then the end of the run. The body is
    // 0x8008 — `varint(1024)`, the size — followed by a two-boundary set.
    {
        const item: ObserveItem = .{ .size = 1024, .ranges = .{ .boundaries = &.{ 1, 2 } } };
        // The body goes into its own buffer, because the frame below is built
        // by copying the body *into* it and the two must not be the same bytes.
        var body_buffer: [32]u8 = undefined;
        var body_writer = postcard.Writer.init(&body_buffer);
        try item.write(&body_writer);
        const body_bytes = body_writer.finish();
        try protocol.expectHex(&[_]u8{ 0x80, 0x08, 0x02, 0x01, 0x02 }, body_bytes);

        // The same bytes with a length in front, which is how a provider sends
        // them: `send_observe_item` at `src/provider.rs:664`.
        var frame: [64]u8 = undefined;
        var writer = postcard.Writer.init(&frame);
        try writer.writeU64(body_bytes.len);
        try appendFrameBytes(&writer, body_bytes);
        try protocol.expectHex(&[_]u8{ 0x05, 0x80, 0x08, 0x02, 0x01, 0x02 }, writer.finish());

        var reader = postcard.Reader.init(writer.finish());
        var run = ObserveResponse.read(&reader, &storage);
        const first = try run.next();
        try testing.expect(first != null);
        try testing.expect(item.eql(first.?));
        // And the run is over: the next read is at a boundary with nothing
        // behind it, which is EOF rather than a failure.
        try testing.expect(try run.next() == null);
    }
}

test "a response's length prefix is read as a varint, at every boundary" {
    // The observe item is one of the two length-prefixed shapes in this
    // protocol — the other is a `push` body, and `framing.zig` sweeps the same
    // four refusals against it — so the prefix is read by the same rule.
    var room: protocol.Room = .{};
    var storage = room.storage();
    var scratch: [64]u8 = undefined;

    // A length of one over the cap on an item.
    {
        const over = try protocol.parseHex(&scratch, "ffffffff01");
        var reader = postcard.Reader.init(over);
        var run = ObserveResponse.read(&reader, &storage);
        try testing.expectError(error.MessageTooLarge, run.next());
    }

    // An item whose length names more than the run holds, which is a stream
    // that stopped *inside* an item rather than between two.
    {
        const inside = try protocol.parseHex(&scratch, "05" ++ "00" ++ "00" ++ "00");
        var inside_reader = postcard.Reader.init(inside);
        var inside_run = ObserveResponse.read(&inside_reader, &storage);
        try testing.expectError(error.UnexpectedEnd, inside_run.next());
    }

    // And a run that ends between items is `null` rather than either error,
    // which is the distinction the module comment draws.
    {
        var empty_reader = postcard.Reader.init("");
        var empty_run = ObserveResponse.read(&empty_reader, &storage);
        try testing.expect(try empty_run.next() == null);
    }
}

/// Read `bytes` as an observe run, and assert that every item's set is sorted
/// and duplicate-free. Returns how many items came out.
///
/// `pub` because `framing.zig`'s mutation sweep drives it over the observe
/// seeds it shares with the request seeds: the sweep is one counter-based walk
/// over both halves, and splitting it would make its two halves disagree about
/// which inputs they saw.
pub fn expectTotalObserve(bytes: []const u8) !usize {
    var room: protocol.Room = .{};
    var storage = room.storage();
    var reader = postcard.Reader.init(bytes);
    var run = ObserveResponse.read(&reader, &storage);
    var items: usize = 0;
    drain: while (true) {
        const item = (run.next() catch break :drain) orelse break;
        items += 1;
        // A set that decoded has a sorted, duplicate-free boundary list, which
        // is what makes its even/odd parity mean anything.
        for (item.ranges.boundaries, 0..) |boundary, at| {
            if (at != 0) try testing.expect(item.ranges.boundaries[at - 1] < boundary);
        }
        if (items == 8) break;
    }
    return items;
}

/// Raw bytes into a postcard writer, with no length in front.
///
/// The mirror of `framing.zig`'s `take`, and the test's copy rather than a call
/// across: the one place this file needs it is building the frame above, and
/// `framing.zig`'s is private to the request writer that is its only
/// production caller.
fn appendFrameBytes(writer: *postcard.Writer, bytes: []const u8) !void {
    const room = writer.buffer[writer.length..];
    if (room.len < bytes.len) return error.BufferFull;
    @memcpy(room[0..bytes.len], bytes);
    writer.length += bytes.len;
}
