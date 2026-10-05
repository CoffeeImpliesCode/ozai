//! What a provider answers with: the rest of a stream, and the run of
//! availability updates an observe produces.
//!
//! Neither type can hold an error frame, and that is the design rather than an
//! omission. The rule is argued at length in `framing.zig`'s module comment,
//! because it is a rule about streams; this file is where it is applied, and
//! the two places it shows as a value are `BaoResponse.isEof` and
//! `ObserveResponse.next` returning `null`.

const postcard = @import("../wire/postcard.zig");
const framing = @import("framing.zig");
const requests = @import("requests.zig");

// `framing.zig` owns the error set and the length-prefix rule; this module
// applies them. `requests.zig` owns the item an observe run is made of.
const Error = framing.Error;
const readLengthPrefaced = framing.readLengthPrefaced;
const ObserveItem = requests.ObserveItem;
const Storage = requests.Storage;

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
