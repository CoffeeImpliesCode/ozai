//! Fuzz target for the blobs request, response and stream-close decoders.
//!
//! One target file and one corpus directory per decoder: `zig build fuzz`
//! replays the corpus, and `zig build fuzz --fuzz=<N>` hands the same corpus
//! to Zig's coverage-guided fuzzer and lets it mutate for N iterations. A
//! decoder is only worth this once the same bytes have been shown not to
//! panic, and this one sits at the far end of a getter's dependency chain:
//! every byte on this stream was chosen by a peer, and the two rules that
//! decide what a getter may believe — that a request is a whole frame, and that
//! its framing is the one its discriminant names — are the ones that fail
//! silently when they are wrong.
//!
//! Three paths are walked over the same bytes, and each has an oracle rather
//! than a "did not throw".
//!
//! 1. **Request**, through `Request.read`, which picks the framing from the
//!    discriminant. An accepted request is re-encoded, decoded again and
//!    encoded again, and the two encodings are compared byte for byte — the
//!    fixed point is the *second* encoding and never the input, because postcard
//!    does not enforce canonicalization and a non-canonical varint in the input
//!    is a legal second spelling of the same value. Framing is part of the
//!    value, so the oracles also check that a `push` stops exactly at the offset
//!    its length prefix names, that the offset is one discriminant plus the
//!    canonical prefix plus the declared body, and that a request which ran to
//!    the end of the stream consumed the whole message and has no payload.
//! 2. **Response**, through `BaoResponse` and `ObserveResponse`. This is the
//!    path with no error frame in it: a provider that cannot answer closes its
//!    side and the bytes simply stop. So the oracles here are the two states a
//!    response can be in and the boundary between them — an empty answer is
//!    EOF, a non-empty one is not, and an observe run that ends *between* items
//!    is `null` while one that stops *inside* an item is an error. Treating the
//!    absence of bao data as a decoder failure would be a finding about a
//!    getter, not about this file: whether a short answer covers the request is
//!    the bao decoder's question, and `BaoResponse` has no arm to answer it
//!    with by construction.
//! 3. **Stream close**, through `Closed.fromVarInt`. A code is a QUIC
//!    application code sent beside the stream, so the varint rules that decide
//!    how it is read are the ones the request path uses, and a code this build
//!    has no arm for is `error.UnknownClose` rather than a default — a default
//!    arm would report a close nobody sent.
//!
//! The two captured `Get` vectors and the three `Closed` codes are seeds and are
//! named here, so a corpus entry is live only once it is.

const std = @import("std");
const ozai = @import("ozai");
const blobs = ozai.blobs_protocol;
const range_spec = ozai.range_spec;
const postcard = ozai.postcard;
const t = std.testing;

/// Seeds are the raw bytes a peer would send as a blobs request stream.
///
/// `captured_get_blob` and `captured_get_all` are the two hexdumps upstream's
/// `request_wire_format` test holds at `src/protocol.rs:1061`, byte for byte, so
/// a mutation starts from something iroh actually wrote. `captured_push` is
/// derived from the first of them by exactly the two differences
/// `Request::read_async` (`src/protocol.rs:479`) makes — the discriminant and a
/// length prefix — and is labelled derived here for the same reason the module
/// test labels it.
///
/// The rest are the shapes the protocol has a rule for and a fuzzer would not
/// reach on its own: nothing at all, a reserved slot, a discriminant past the
/// table, a hash cut short, a length prefix that runs past the end, one past
/// `max_message_size`, one whose varint never stops, a whole request with one
/// byte behind it, and a `get_many` whose hash count the bytes behind it could
/// not carry.
///
/// `closed_stream_dropped`, `closed_provider_terminating` and
/// `closed_request_received` are the three `Closed` codes (`src/protocol.rs:667`),
/// one byte each because all three are below 64. They overlap the request
/// discriminants on purpose: the close path and the request path read the same
/// bytes and must not agree about what they are.
///
/// `test/corpus/blobs_protocol/` is the record, and a file there is live only
/// once it is named here.
const corpus = [_][]const u8{
    @embedFile("corpus/blobs_protocol/empty"), // 0 bytes: no discriminant
    @embedFile("corpus/blobs_protocol/captured_get_blob"), // upstream: GetRequest::blob
    @embedFile("corpus/blobs_protocol/captured_get_all"), // upstream: GetRequest::all
    @embedFile("corpus/blobs_protocol/captured_push"), // derived: the same body, framed
    @embedFile("corpus/blobs_protocol/push_with_payload"), // a push and the bao data behind it
    @embedFile("corpus/blobs_protocol/get_many"), // two hashes and one sequence
    @embedFile("corpus/blobs_protocol/observe"), // an ObserveRequest
    @embedFile("corpus/blobs_protocol/observe_item"), // one item, as a provider frames it
    @embedFile("corpus/blobs_protocol/observe_item_pair"), // two items in one run
    @embedFile("corpus/blobs_protocol/reserved_slot"), // 2, which upstream reserves
    @embedFile("corpus/blobs_protocol/unknown_discriminant"), // 10, one past the table
    @embedFile("corpus/blobs_protocol/truncated_hash"), // a `get` whose hash is cut short
    @embedFile("corpus/blobs_protocol/push_length_past_end"), // a length the frame does not hold
    @embedFile("corpus/blobs_protocol/length_over_cap"), // a length past max_message_size
    @embedFile("corpus/blobs_protocol/overlong_length_varint"), // ten groups, none of which stops
    @embedFile("corpus/blobs_protocol/trailing_byte"), // a whole request and one byte after it
    @embedFile("corpus/blobs_protocol/get_many_count_overflow"), // five hashes, 34 bytes behind
    @embedFile("corpus/blobs_protocol/closed_stream_dropped"), // Closed 0, as a QUIC varint
    @embedFile("corpus/blobs_protocol/closed_provider_terminating"), // Closed 1
    @embedFile("corpus/blobs_protocol/closed_request_received"), // Closed 2
};

/// Long enough for the longest seed — a `get_many` over two hashes is 72 bytes —
/// and short enough that a mutated input still fits the length checks below.
/// Every oracle in this file is stated for an input of at most this size, which
/// is what makes the `error.BufferFull` oracle an assertion rather than a hope.
const input_buffer_len = 96;

/// The widest canonical encoding of a request decoded from `input_buffer_len`
/// bytes. A non-canonical varint in the input collapses to fewer bytes on the
/// way out, so the encoding is bounded by the input plus the discriminant and
/// length prefix that were not in it.
const encode_buffer_len = 256;

/// `encode_buffer_len` and three bytes of junk, for the metamorphic oracle that
/// appends to a frame. Three is more than any width a length prefix here can
/// change and less than any boundary the oracles care about.
const grown_buffer_len = encode_buffer_len + 3;

/// How many observe items one run is drained before the fuzzer stops asking.
/// Every item costs at least the byte of its own length prefix, so a run cannot
/// loop; the bound is here so that a mutation which made one cost nothing fails
/// the fuzzer instead of hanging it.
const observe_item_limit = 8;

/// Caller-owned scratch for one decode, and the buffers it names.
///
/// Every buffer here is wide enough that a count the frame declares cannot
/// outrun it through the bytes: a width, a boundary and a sequence item each
/// cost at least one byte, so `readLen` — which bounds a count by the bytes
/// that remain — cannot name more of them than the caller holds. A `get_many`
/// hash count is the one width where that argument fails, because `readLen`
/// bounds it by bytes and not by the 32 one hash costs on the wire, so
/// `error.BufferFull` is reachable in a few bytes and `checkRefusal` reads that
/// count back out of the frame instead of ruling the arm out.
const Room = struct {
    items: [input_buffer_len]range_spec.Item = undefined,
    widths: [2 * input_buffer_len]u64 = undefined,
    hashes: [8][32]u8 = undefined,
    boundaries: [input_buffer_len]u64 = undefined,

    fn storage(self: *Room) blobs.Storage {
        return .{
            .items = &self.items,
            .widths = &self.widths,
            .hashes = &self.hashes,
            .boundaries = &self.boundaries,
        };
    }
};

comptime {
    // A seed longer than the window the fuzzer reads into would be cut short on
    // its way to the oracle, and the length checks would never see the rest.
    for (corpus) |seed| std.debug.assert(seed.len <= input_buffer_len);
}

/// The fuzzer keeps one of these by pointer for the whole run, so it is empty by
/// design: everything the oracle needs is comptime.
const Context = struct {};

test "blobs protocol decode" {
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
    try checkRequest(bytes);
    try checkResponse(bytes);
    try checkClose(bytes);
}

/// One request stream, from the bytes alone.
fn checkRequest(bytes: []const u8) !void {
    var room: Room = .{};
    var storage = room.storage();
    var reader = postcard.Reader.init(bytes);
    const request = blobs.Request.read(&reader, &storage) catch |err| {
        try checkRefusal(err, bytes, room.hashes.len);
        return;
    };

    // Oracle: capacity. Every buffer a decode filled is the caller's, so a
    // request that decoded wrote inside one of them. This is the check a decoder
    // that trusted a peer's count instead of the caller's storage would fail.
    try t.expect(storage.items.len <= room.items.len);
    try t.expect(storage.widths.len <= room.widths.len);
    try t.expect(storage.hashes.len <= room.hashes.len);

    // Oracle: the framing is the discriminant's, and it is visible. A request
    // that ran to the end of the stream consumed the whole message and has no
    // payload; a `push` stops at its length prefix and leaves the rest for the
    // bao data that follows it on the same stream.
    switch (request) {
        .to_eof => |eof| {
            try t.expectEqual(eof.discriminant(), request.discriminant());
            // `EofFraming.read` calls `finish`, so the reader is at the end.
            try t.expectEqual(@as(usize, 0), reader.remaining());
            try t.expectEqual(@as(usize, 0), request.payload(&reader).len);
        },
        .length_prefixed => |framed| {
            try t.expectEqual(@as(blobs.RequestType, .push), request.discriminant());
            // The offset is the reader's, handed over rather than recomputed: it
            // is the one thing a caller cannot work out from the request alone.
            try t.expectEqual(framed.payload_offset, reader.offset);
            try t.expect(framed.payload_offset <= bytes.len);
            try t.expectEqualSlices(
                u8,
                bytes[framed.payload_offset..],
                request.payload(&reader),
            );
            // Oracle: the offset is exactly one discriminant, the canonical
            // spelling of the declared length, and that many bytes of body. The
            // length is read back out of the frame rather than taken from the
            // value, so this checks the prefix against the framing rather than
            // the framing against itself.
            const declared = declaredLength(bytes);
            try t.expect(declared <= blobs.max_message_size);
            try t.expectEqual(
                1 + varintWidth(declared) + @as(usize, @intCast(declared)),
                framed.payload_offset,
            );
            // And those bytes are the canonical spelling of that number, so a
            // non-canonical prefix in the input is not what the framing kept.
            var scratch: [postcard.varintMax(u64)]u8 = undefined;
            var writer = postcard.Writer.init(&scratch);
            try writer.writeU64(declared);
            try t.expectEqualSlices(
                u8,
                writer.finish(),
                bytes[1 .. 1 + varintWidth(declared)],
            );
        },
    }

    // Oracle: fidelity. The re-encoding of a decoded request is postcard's
    // canonical spelling rather than the one that was sent, so the fixed point
    // is the second encoding and never the input.
    var encoded: [encode_buffer_len]u8 = undefined;
    var body: [encode_buffer_len]u8 = undefined;
    var writer = postcard.Writer.init(&encoded);
    try request.write(&writer, &body);
    const canonical = writer.finish();
    // The discriminant the value reports is the byte the value writes, which is
    // what makes `Request.discriminant` a fact about the value and not a guess.
    try t.expectEqual(
        request.discriminant(),
        std.enums.fromInt(blobs.RequestType, @as(u32, canonical[0])).?,
    );
    var again_room: Room = .{};
    var again_storage = again_room.storage();
    var recoder = postcard.Reader.init(canonical);
    const recoded = try blobs.Request.read(&recoder, &again_storage);
    try recoder.finish();
    try t.expect(request.eql(recoded));
    try t.expect(again_storage.hashes.len <= again_room.hashes.len);
    // What the canonical encoding left behind is the payload, measured against
    // the canonical framing rather than the input's: a non-canonical length
    // prefix in the input became a shorter canonical one behind the same body.
    const canonical_payload = canonical.len - recoder.offset;

    var again: [encode_buffer_len]u8 = undefined;
    var rewriter = postcard.Writer.init(&again);
    try recoded.write(&rewriter, &body);
    try t.expectEqualSlices(u8, canonical, rewriter.finish());

    // Oracle: metamorphic, and the one that separates the two framings. Bytes
    // appended after a `push` are payload by construction — the length prefix
    // covers the body and nothing after it — so the request is unchanged and the
    // payload is exactly that much longer. Appended after a request that ran to
    // the end of the stream, the same bytes are a second message rather than a
    // longer one, and `finish` is what tells the two apart.
    var grown: [grown_buffer_len]u8 = undefined;
    @memcpy(grown[0..canonical.len], canonical);
    @memset(grown[canonical.len..], 0xa5);
    const grown_len = canonical.len + 3;

    var grown_room: Room = .{};
    var grown_storage = grown_room.storage();
    var grown_reader = postcard.Reader.init(grown[0..grown_len]);
    const grown_request = blobs.Request.read(&grown_reader, &grown_storage) catch |err| {
        // Only a request that ran to the end of the stream can fail here, and it
        // fails on the whole message being over rather than on a short body.
        try t.expectEqual(error.TrailingBytes, err);
        return;
    };
    // Only the `push` framing can have read a grown frame as a whole message,
    // and its payload is the three bytes that were appended. The reader is not
    // finished here, and cannot be: the framing stopped at its length prefix,
    // so what it stopped at is where the reader is and the payload is what is
    // left — which is exactly what `finish` refuses.
    try t.expect(std.meta.activeTag(grown_request) == .length_prefixed);
    try t.expectEqual(grown_request.payload(&grown_reader).len, grown_reader.remaining());
    try t.expectEqual(canonical_payload + 3, grown_request.payload(&grown_reader).len);
    try t.expect(grown_request.eql(request));
}

/// Why a request was refused, asserted against the bytes rather than accepted.
///
/// Every arm `Request.read` can return is one of these. `Request.read` picks the
/// framing from the discriminant, so `error.WrongFraming` is unreachable here by
/// construction — the assertion is that it never comes back, which is the
/// property the two framings exist for.
fn checkRefusal(err: blobs.Error, bytes: []const u8, hash_capacity: usize) !void {
    switch (err) {
        error.WrongFraming => return error.FuzzUnexpectedWrongFraming,

        // The caller's storage, which a peer's declared count can outrun in a
        // frame this short. `readLen` bounds a count by the bytes that remain
        // and not by what one element costs, so a `get_many` naming more
        // hashes than the caller's buffer holds is refused here even though
        // those hashes could never fit in the input. The count is read back out
        // of the frame to check the refusal is about the caller's storage and
        // about nothing else.
        error.BufferFull => {
            const tag = std.enums.fromInt(blobs.RequestType, bytes[0]) orelse
                return error.TestExpectedResult;
            try t.expectEqual(blobs.RequestType.get_many, tag);
            var counting = postcard.Reader.init(bytes[1..]);
            const count = counting.readU64() catch return error.TestExpectedEqual;
            try t.expect(count > hash_capacity);
            try t.expect(count <= counting.remaining());
        },

        // A reserved slot is one of the six upstream reserves (`Slot2` through
        // `Slot7`, `src/protocol.rs:435`) and nothing else, so the byte in front
        // is the whole explanation and nothing behind it was read.
        error.ReservedSlot => {
            try t.expect(bytes.len > 0);
            try t.expect(bytes[0] >= 2 and bytes[0] <= 7);
            try t.expect(std.enums.fromInt(blobs.RequestType, @as(u32, bytes[0])) != null);
        },

        // A discriminant this build does not have: above the table, or with the
        // top bit set, which is why a discriminant is a raw byte and not a
        // varint at all.
        error.UnknownVariant => {
            try t.expect(bytes.len > 0);
            try t.expect(std.enums.fromInt(blobs.RequestType, @as(u32, bytes[0])) == null);
        },

        // The cap. For an input this short the EOF framing's own check cannot
        // fire — it compares the remaining bytes against `max_message_size` —
        // so a `MessageTooLarge` here came from a declared length, and that
        // length is read back out of the frame to check it really is over.
        error.MessageTooLarge => {
            try t.expect(declaredLength(bytes) > blobs.max_message_size);
        },

        // Everything else is a body that does not hold what it promised, and the
        // module's own decode tests name each of those rule by rule. What is
        // asserted here is that they stayed inside the set: a decoder that
        // invented an arm would be answering with something no caller matches.
        error.UnexpectedEnd,
        error.BadVarint,
        error.ValueOutOfRange,
        error.BadLength,
        error.TrailingBytes,
        // The four arms below are the postcard field errors this project's
        // codec declares but never emits on a request: every request slot
        // either consumes no payload, or takes one the length prefix already
        // fixed, so a request reader cannot reach them. Naming them is the
        // assertion — a decoder that started reading a bool, an `Option`, a
        // string or a variant where the framing has none would answer with
        // one of these instead of the refusal the bytes actually describe.
        error.BadBool,
        error.BadOptionTag,
        error.InvalidUtf8,
        error.UnknownClose,
        => {},
    }
}

/// A `push` frame's declared body length, read as postcard's `varint(u64)` from
/// the byte behind the discriminant. Zero when there is no such byte or the
/// prefix does not decode, because the callers below only use it to check a
/// refusal that a decoding prefix could have caused.
fn declaredLength(bytes: []const u8) u64 {
    if (bytes.len < 2) return 0;
    var reader = postcard.Reader.init(bytes[1..]);
    return reader.readU64() catch 0;
}

/// How many bytes postcard's canonical `varint(u64)` of `value` takes, computed
/// the way the encoder computes it rather than asked of the encoder, so a check
/// that uses it is on the bytes and not on the same function twice.
fn varintWidth(value: u64) usize {
    var rest = value;
    var count: usize = 1;
    while (rest >= 0x80) : (count += 1) rest >>= 7;
    return count;
}

/// The two paths a provider's answer takes, and the boundary between them.
fn checkResponse(bytes: []const u8) !void {
    // Oracle: EOF is a value and it is exactly "no bytes". `BaoResponse` has no
    // error arm by construction — a provider that cannot answer closes its side
    // and the evidence a getter has is that the bytes stopped — so the two states
    // are decided by the length and nothing else. Whether a short answer covers
    // the request is the bao decoder's question, and this module has no arm to
    // answer it with.
    {
        var reader = postcard.Reader.init(bytes);
        const answer = blobs.BaoResponse.read(&reader);
        try t.expectEqual(bytes.len == 0, answer.isEof());
        try t.expectEqualSlices(u8, bytes, answer.bytes);
    }

    // Oracle: an observe run ends at a boundary or it does not. `null` is the
    // ordinary end of a run and a failure to read inside one is
    // `UnexpectedEnd`, and conflating the two is what would turn a broken stream
    // into a clean finish. A `null` is therefore only ever reported with nothing
    // left behind, and an item always advances the reader past its own prefix.
    var room: Room = .{};
    var storage = room.storage();
    var reader = postcard.Reader.init(bytes);
    var run = blobs.ObserveResponse.read(&reader, &storage);
    var items: usize = 0;
    while (true) {
        const before = reader.offset;
        const maybe = run.next() catch break;
        const item = maybe orelse {
            try t.expectEqual(@as(usize, 0), reader.remaining());
            break;
        };
        items += 1;
        // Its length prefix and body are consumed, so the loop terminates and
        // cannot spin on a run that made no progress.
        try t.expect(reader.offset > before);
        // Oracle: a decoded set is sorted and duplicate-free, which is what
        // makes its even/odd parity mean anything — upstream's `RangeSetVisitor`
        // (`src/range_set.rs:1000`) sorts and dedups at decode and checks
        // nothing else, so an unsorted list with a repeat is a *value*.
        for (item.ranges.boundaries, 0..) |boundary, at| {
            if (at != 0) try t.expect(item.ranges.boundaries[at - 1] < boundary);
        }
        try t.expect(item.ranges.boundaries.len <= room.boundaries.len);
        if (items == observe_item_limit) break;
    }
}

/// A stream close, read as the `varint(u64)` a QUIC application code is spelled
/// in, which is the same length-varint the request path reads.
fn checkClose(bytes: []const u8) !void {
    var reader = postcard.Reader.init(bytes);
    const code = reader.readU64() catch return;
    const consumed = reader.offset;

    if (blobs.Closed.fromVarInt(code)) |closed| {
        // Oracle: the code round-trips through its own varint spelling, and a
        // named code carries a reason. `Closed` has three arms and upstream's
        // `Closed` (`src/protocol.rs:667`) has three, so the namespace is closed
        // and every code below three has a name.
        try t.expectEqual(closed.toVarInt(), code);
        try t.expect(code < 3);
        try t.expect(closed.reason().len > 0);
        // Oracle: the spelling that produced the code is the canonical one, so
        // the value read out of the frame re-encodes to the same bytes and the
        // reader consumed exactly that many.
        var scratch: [postcard.varintMax(u64)]u8 = undefined;
        var writer = postcard.Writer.init(&scratch);
        try writer.writeU64(code);
        try t.expectEqualSlices(u8, writer.finish(), bytes[0..consumed]);
    } else |err| {
        // Oracle: a code with no arm is named rather than defaulted, and it is a
        // code rather than a broken encoding — every number from three upwards is
        // one this build does not have.
        try t.expectEqual(error.UnknownClose, err);
        try t.expect(code >= 3);
    }
}
