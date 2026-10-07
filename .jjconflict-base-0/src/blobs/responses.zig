//! What a provider answers with: the rest of a stream, and the run of
//! availability updates an observe produces.
//!
//! Neither type can hold an error frame, and that is the design rather than an
//! omission. The rule is argued at length in `framing.zig`'s module comment,
//! because it is a rule about streams; this file is where it is applied, and
//! the two places it shows as a value are `BaoResponse.isEof` and
//! `ObserveResponse.next` returning `null`.
//!
//! # Where these are tested
//!
//! The rule that missing data is the end of the stream is tested here, because
//! this is where it is applied and the two places it becomes a value —
//! `BaoResponse.isEof` and `ObserveResponse.next` returning `null` — are both
//! in this file.

const postcard = @import("../wire/postcard.zig");
const std = @import("std");
const framing = @import("framing.zig");
const requests = @import("requests.zig");
const test_support = @import("wire_test_support.zig");

// `framing.zig` owns the error set and the length-prefix rule; this module
// applies them. `requests.zig` owns the item an observe run is made of.
const Error = framing.Error;
const readLengthPrefaced = framing.readLengthPrefaced;
const ObserveItem = requests.ObserveItem;
const Storage = requests.Storage;

const appendBytes = framing.appendBytes;

// Test support, aliased so the test below reads as the protocol does and not as
// this file's import list does. A length prefix is written with the framing's
// own byte helper; the arena and the hex comparison are shared.
const testing = std.testing;
const Room = test_support.Room;
const expectHex = test_support.expectHex;

/// A provider's answer to a `Get`, `GetMany` or `Push`: bao-encoded data, to
/// the end of the stream.
///
/// # There is no error frame
///
/// A `get` answer contains a little-endian u64 size followed by Bao proof data
/// until the provider stops writing. A provider that does not have the
/// data stops writing: upstream's `# Responses` section
/// (`src/protocol.rs:320`) says the provider "will close just the stream used
/// to send the response", and the reason is recovered from the resulting
/// error on the getter's side rather than from anything in the bytes.
///
/// So this type has no error arm and cannot be decoded from an error value. A
/// short answer is a short answer: `bytes` is what arrived, and whether that
/// covers the request is a question for the bao decoder and not for this one.
/// A successful empty blob still has an eight-byte size header. Missing data
/// produces no response bytes.
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
    /// A provider that does not have the requested data writes no bytes.
    /// An empty blob has a size header and is therefore not EOF.
    pub fn isEof(self: BaoResponse) bool {
        return self.bytes.len == 0;
    }
};

/// A provider's running answer to an `Observe`: a run of `ObserveItem`s to the
/// end of the stream.
///
/// The items are length-prefixed, from upstream's `send_observe_item`
/// (`src/provider.rs:664`), which calls the same `write_length_prefixed` a
/// `push` request is written with. The prefix is here for the reason it is
/// there: a run has no other boundary, so without it a getter could not tell
/// one update from the next.
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
        var body = try readLengthPrefaced(self.reader);
        const item = try ObserveItem.parse(&body, self.storage);
        try body.finish();
        return item;
    }
};

/// What `reader` has not read yet.
fn rest(reader: *postcard.Reader) []const u8 {
    return reader.buffer[reader.offset..];
}

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

    var room: Room = .{};
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
        try expectHex(&[_]u8{ 0x80, 0x08, 0x02, 0x01, 0x02 }, body_bytes);

        // The same bytes with a length in front, which is how a provider sends
        // them: `send_observe_item` at `src/provider.rs:664`.
        var frame: [64]u8 = undefined;
        var writer = postcard.Writer.init(&frame);
        try writer.writeU64(body_bytes.len);
        try appendBytes(&writer, body_bytes);
        try expectHex(&[_]u8{ 0x05, 0x80, 0x08, 0x02, 0x01, 0x02 }, writer.finish());

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
