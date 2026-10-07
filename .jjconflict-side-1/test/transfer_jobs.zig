//! One request the getter makes, and everything that request carries with it.
//!
//! A `Job` is the request as the test states it, the request as the provider
//! decoded it off the socket, and the byte ranges each of them implies.
//! `DecodeStorage` is the scratch a blobs decode borrows into, and
//! `StreamBytes` is one stream's received bytes — a named type rather than a
//! bare `ArrayList` so the storage cannot escape and so the count a reader sees
//! is never the room behind it.
//!
//! `buildRequest` and `ask` are the getter's half: what it puts on the wire.
//! They were `Link` methods whose bodies never touch a field of the link, so
//! they are top-level functions over `*Link` now and no statement in them
//! changed.

const std = @import("std");
const ozai = @import("ozai");

const t = std.testing;

const blobs = ozai.blobs_protocol;
const range_spec = ozai.range_spec;
const postcard = ozai.postcard;

const ranges_mod = @import("transfer_ranges.zig");
const link_ns = @import("transfer_link.zig");

/// Room for one encoded request, and for the `push` arm's length-prefixed body
/// scratch. A `get` is 39 bytes and a `push` one varint more.
pub const request_room = 512;

/// Slots one blobs decode borrows into.
///
/// The counts are this file's own bounds, not the protocol's: a request longer
/// than any of them is a frame this artifact cannot hold, and
/// `RangeSpecSeq.parse` reports that as `error.BufferFull` rather than
/// pretending it read the request.
const decode_slots = 16;

// ---------------------------------------------------------------------------
// Jobs
// ---------------------------------------------------------------------------

/// Which of the four request types a job puts on the wire.
const Kind = enum {
    get,
    observe,
    push,

    /// `pub` because `blobs_transfer_test.zig` calls it across the file
    /// boundary the split that gave this module its own name introduced.
    pub fn discriminant(kind: Kind) blobs.RequestType {
        return switch (kind) {
            .get => .get,
            .observe => .observe,
            .push => .push,
        };
    }
};

/// One request the getter makes, what the provider made of it, and the
/// bookkeeping a stall report needs.
pub const Job = struct {
    /// Named in the stall report. A stall that does not say which request
    /// stalled is a stall that has to be reproduced before it can be read.
    name: []const u8,
    kind: Kind = .get,
    /// The widths of the range spec, in chunks. A `get` puts them in a
    /// sequence and an `observe` in a spec; both carry the same widths.
    widths: []const u64 = &.{},
    /// Write the module's own whole-blob sequence rather than a sequence of
    /// this file's, so the constructor upstream uses is on the path.
    whole: bool = false,
    /// How many bytes of the plan the provider writes, and null for all of
    /// them. A number below the total is the truncated case.
    truncate_to: ?usize = null,
    /// Write nothing at all, and close: the provider has nothing, which is EOF
    /// on the wire.
    empty: bool = false,

    /// The bytes the getter encoded, and the request the provider decoded off
    /// the socket from them.
    frame_len: usize = 0,
    frame: [request_room]u8 = undefined,
    seen: ?blobs.Request = null,
    /// Where the decode said the payload starts, for a `push`.
    payload_offset: usize = 0,
    /// The byte ranges the provider derived, and the ones the test expects.
    plan: ranges_mod.Plan = .{},
    expected: ranges_mod.Plan = .{},

    stream: u64 = 0,
    asked: bool = false,
    served: bool = false,
    storage: DecodeStorage = .{},

    /// The byte ranges this request must produce, as the test states them.
    /// `pub` because `blobs_transfer_test.zig` calls it across the file
    /// boundary the split that gave this module its own name introduced.
    pub fn expect(job: *Job, ranges: []const blobs.ByteRange) error{TooManySpans}!void {
        if (ranges.len > ranges_mod.max_spans) return error.TooManySpans;
        job.expected = .{};
        job.expected.len = ranges.len;
        for (ranges, 0..) |range, index| job.expected.ranges[index] = range;
    }

    /// `pub` because `blobs_transfer_test.zig` calls it across the file
    /// boundary the split that gave this module its own name introduced.
    pub fn spec(job: *const Job) range_spec.RangeSpec {
        return .{ .widths = job.widths };
    }
};

/// Scratch a blobs decode borrows into.
///
/// The arrays are fields rather than constants because a decode writes through
/// them, and `Storage`'s slices have to point at the same memory — so `init`
/// points them at `self` rather than returning one. A `DecodeStorage` that was
/// returned by value and had its slices cut from the local copy left every
/// later decode reading a frame that had already unwound, which a debug build
/// hides and a release build does not.
pub const DecodeStorage = struct {
    items: [decode_slots]range_spec.Item = @splat(.{ .delta = 0, .spec = .empty }),
    widths: [decode_slots]u64 = @splat(0),
    hashes: [decode_slots][32]u8 = @splat(@splat(0)),
    boundaries: [decode_slots]u64 = @splat(0),
    inner: blobs.Storage = undefined,

    /// Point `inner` at this value's own arrays, so a decode writes into the
    /// storage that outlives it rather than into a copy that has unwound.
    ///
    /// `pub` because `transfer_link.zig` calls it across the file boundary the
    /// split that gave this module its own name introduced.
    pub fn init(self: *DecodeStorage) void {
        self.inner = .{
            .items = self.items[0..],
            .widths = self.widths[0..],
            .hashes = self.hashes[0..],
            .boundaries = self.boundaries[0..],
        };
    }
};

/// One stream's received bytes, as a queue a caller may push to and read from
/// but never take the storage of.
///
/// A named type rather than a bare `ArrayList` so the storage cannot escape:
/// `push` and `slice` are the only ways in and out. `Link` used to answer a
/// reader with `list.items` and nothing else, which reads as a handover of the
/// list and is not one — and which is exactly the question `zbc` raised. The
/// answer is a borrow: the map owns the queue and `freeSides` frees it, so
/// `toOwnedSlice` would have been the bug rather than the fix, moving the
/// bytes out from under a map that still held the entry.
///
/// The count a reader sees is the count `push` advanced, never the room behind
/// it. `std.ArrayList` holds `items` as `ptr[0..len]` with `len` the written
/// count and keeps the allocation's length in a field of its own
/// (`lib/std/array_list.zig:31-35`); `allocatedSlice` at `:534` is what hands
/// back the room, and the comment above it says exactly that. So `room` and
/// `slice().len` are two different numbers and the test at the bottom of this
/// file is what holds them apart.
pub const StreamBytes = struct {
    queued: std.ArrayList(u8) = .empty,

    /// A queue holding nothing, which is what a `getOrPut` that missed leaves
    /// to be written to. Named so the two call sites say the same thing.
    pub const empty: StreamBytes = .{};

    fn deinit(self: *StreamBytes) void {
        self.queued.deinit(t.allocator);
        self.* = undefined;
    }

    /// Queue one chunk for a stream.
    ///
    /// `pub` because `blobs_transfer_test.zig` calls it across the file
    /// boundary the split that gave this module its own name introduced.
    pub fn push(self: *StreamBytes, chunk: []const u8) !void {
        try self.queued.appendSlice(t.allocator, chunk);
    }

    /// The bytes written so far.
    ///
    /// `pub` because `blobs_transfer_test.zig` calls it across the file
    /// boundary the split that gave this module its own name introduced.
    pub fn slice(self: *const StreamBytes) []const u8 {
        return self.queued.items;
    }

    /// How many more bytes fit without a reallocation. Never the count.
    ///
    /// `pub` because `blobs_transfer_test.zig` calls it across the file
    /// boundary the split that gave this module its own name introduced.
    pub fn room(self: *const StreamBytes) usize {
        return self.queued.capacity;
    }
};

/// The queue one side's copy of a stream sits in, or null for a stream that
/// has arrived nothing.
///
/// Null and an empty slice are two different answers and both are wanted: the
/// first says the stream is not in the map and the second says it is and
/// carried nothing, and a stall report that cannot tell them apart is a stall
/// report that has to be reproduced before it can be read.
pub fn queueOf(
    bytes: *const std.AutoHashMap(u64, StreamBytes),
    stream: u64,
) ?*const StreamBytes {
    return bytes.getPtr(stream);
}

/// The bytes a side has read off one stream, borrowed, or the empty slice.
pub fn received(
    bytes: *const std.AutoHashMap(u64, StreamBytes),
    stream: u64,
) []const u8 {
    const queued = queueOf(bytes, stream) orelse return &.{};
    return queued.slice();
}

/// Free every queue a side accumulated, before the map that holds them goes.
pub fn freeSides(map: *std.AutoHashMap(u64, StreamBytes)) void {
    var it = map.valueIterator();
    while (it.next()) |queued| queued.deinit();
}

// -- the getter's half --------------------------------------------------

/// The `Request` a job puts on the wire.
///
/// The `get` and `push` bodies carry a one-pair sequence, and it borrows an
/// array the caller owns, so it is built and encoded in the same call:
/// nothing that outlives the frame keeps a pointer into it.
fn buildRequest(
    job: *const Job,
    items: *[1]range_spec.Item,
    hash: [32]u8,
) blobs.Request {
    items[0] = .{ .delta = 0, .spec = job.spec() };
    return switch (job.kind) {
        .get => if (job.whole)
            .{ .to_eof = .{ .get = blobs.GetRequest.blob(hash) } }
        else
            .{ .to_eof = .{ .get = .{
                .hash = hash,
                .ranges = .{ .items = items[0..] },
            } } },
        .observe => .{ .to_eof = .{ .observe = .{
            .hash = hash,
            .ranges = job.spec(),
        } } },
        .push => .{ .length_prefixed = .{
            .request = blobs.PushRequest.new(hash, .{ .items = items[0..] }),
        } },
    };
}

/// Open a stream for `job`, write its request, and close the send side.
pub fn ask(link: *link_ns.Link, job: *Job) !void {
    const stream = try link.dialled.entry.conn.openStream();
    job.stream = stream.stream_id;
    var items: [1]range_spec.Item = undefined;
    var writer = postcard.Writer.init(&job.frame);
    try buildRequest(job, &items, link.store.hash).write(&writer, &link.body);
    job.frame_len = writer.finish().len;
    try stream.send.writeData(job.frame[0..job.frame_len]);
    // A `push` is the one request with bytes behind it, and they are on the
    // same stream: that is what `LengthPrefixedFraming` exists to make
    // unambiguous, and it is why the payload is written here rather than
    // after the provider has answered.
    if (job.kind == .push) try stream.send.writeData(link.store.payload);
    // The `to_eof` framing is the whole stream, and the `push` framing is
    // the stream minus its payload, so both are closed by a FIN and not by
    // a length.
    stream.send.close();
    job.asked = true;
}
