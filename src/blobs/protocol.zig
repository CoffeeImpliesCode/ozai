//! The blobs wire protocol: the requests a getter may send, the two ways a
//! request is framed on a stream, and the rule that missing data is the end of
//! the stream rather than a message to decode.
//!
//! # What the protocol is
//!
//! A *provider* serves content-addressed blobs and a *getter* asks for them.
//! One request occupies one QUIC stream, and the bao-encoded answer is the
//! rest of that stream. The request set is upstream's, at `n0-computer/
//! iroh-blobs` `src/protocol.rs` commit
//! `e82cbdcbdac9a78033174aad55e3199b2cf4c0dc` (crate version 0.103.0, per
//! `Cargo.toml` at that commit), fetched 2026-09-30: `Get`, `GetMany`,
//! `Observe` and `Push` behind one discriminant byte, plus `ObserveItem`,
//! which is what the answer to an observe is a run of.
//!
//! # What lives where
//!
//! This file is a facade over four modules, and it holds the ALPN and the
//! re-exports. Every public name below is bound from exactly one of them, so a
//! caller that imports this file names none of them:
//!
//! * `blobs/ranges.zig` — the chunk unit and the block above it, the byte and
//!   chunk range types, the conversions between them, and `ChunkRangeSet`.
//! * `blobs/requests.zig` — the four request bodies, `ObserveItem`, and the
//!   caller-owned `Storage` every decode fills.
//! * `blobs/framing.zig` — the discriminant byte, the error set, the QUIC
//!   close codes, the two framings, and the length-prefix byte helpers.
//! * `blobs/responses.zig` — `BaoResponse` and `ObserveResponse`, which is
//!   where the rule that missing data is the end of the stream is applied.
//!
//! The citations for the framing rules and for the chunk arithmetic sit in
//! those two files' own module comments, next to the code they are about.
//! # Purity
//!
//! Nothing here reads a clock, the environment, a global or an allocator. A
//! decode fills `Storage`, which the caller owns, and every slice a decoded
//! message points at lives in it; `Request.write` borrows one caller-owned
//! scratch buffer for the `push` body, because a `varint` length cannot be
//! backpatched once its width is known. The reasons are the ones
//! `docs/ARCHITECTURE.md` gives under "Wire codecs are pure and separate from
//! the transport", and the one that bites hardest here is that every byte a
//! decoder below reads was chosen by a peer. Every decode path is total and
//! every error is named: there is no `unreachable` on any of them.

// -- The re-exports ----------------------------------------------------------
//
// Every decl below is bound, not defined: the four modules named at the top of
// this file own them and this file exists so that a caller names one import.
// The test blocks below are why the private names at the bottom are here.

const std = @import("std");
const postcard = @import("../wire/postcard.zig");
const range_spec = @import("range_spec.zig");

const framing_mod = @import("framing.zig");
const ranges_mod = @import("ranges.zig");
const requests_mod = @import("requests.zig");
const responses_mod = @import("responses.zig");

/// The ALPN this protocol is spoken on.
///
/// Upstream's `ALPN` at `src/protocol.rs:406`, `b"/iroh-bytes/4"`, at the
/// commit named in the module comment. `/4` is the protocol version and
/// changes with a wire change, which is why it is a value here rather than a
/// name someone has to remember.
pub const alpn = "/iroh-bytes/4";

// -- The units and the ranges ------------------------------------------------

pub const chunk_size = ranges_mod.chunk_size;
pub const block_size = ranges_mod.block_size;
pub const chunks_per_block = ranges_mod.chunks_per_block;
pub const ByteRange = ranges_mod.ByteRange;
pub const ChunkRange = ranges_mod.ChunkRange;
pub const chunkOfByte = ranges_mod.chunkOfByte;
pub const chunkAfterByte = ranges_mod.chunkAfterByte;
pub const bytesToChunks = ranges_mod.bytesToChunks;
pub const chunksToBytes = ranges_mod.chunksToBytes;
pub const ChunkRangeSet = ranges_mod.ChunkRangeSet;

// -- The request bodies ------------------------------------------------------

pub const Storage = requests_mod.Storage;
pub const GetRequest = requests_mod.GetRequest;
pub const GetManyRequest = requests_mod.GetManyRequest;
pub const ObserveRequest = requests_mod.ObserveRequest;
pub const PushRequest = requests_mod.PushRequest;
pub const ObserveItem = requests_mod.ObserveItem;

// -- The two framings and the codes around them ------------------------------

pub const max_message_size = framing_mod.max_message_size;
pub const Error = framing_mod.Error;
pub const RequestType = framing_mod.RequestType;
pub const Closed = framing_mod.Closed;
pub const EofRequest = framing_mod.EofRequest;
pub const PushFraming = framing_mod.PushFraming;
pub const Request = framing_mod.Request;
pub const EofFraming = framing_mod.EofFraming;
pub const LengthPrefixedFraming = framing_mod.LengthPrefixedFraming;

// -- The answers -------------------------------------------------------------

pub const BaoResponse = responses_mod.BaoResponse;
pub const ObserveResponse = responses_mod.ObserveResponse;

// -- Names only this file's own tests reach -----------------------------------
//
// Private on purpose. They are file-scope aliases and add no public name, so
// the tests below keep the spellings they were written with while the decls
// themselves stay where they are implemented.

const Hash = requests_mod.Hash;
const blob_ranges = requests_mod.blob_ranges;
const push_ranges = requests_mod.push_ranges;
const readLengthPrefaced = framing_mod.readLengthPrefaced;
const writeRequestType = framing_mod.writeRequestType;
const appendBytes = framing_mod.appendBytes;

const testing = std.testing;

// Golden vectors below: n0-computer/iroh-blobs, `src/protocol.rs`, commit
// e82cbdcbdac9a78033174aad55e3199b2cf4c0dc, fetched 2026-09-30. The two
// hexdumps are the ones upstream's `request_wire_format` test holds, byte for
// byte, and upstream's own comments name the fields. Everything else in this
// block is either derived from those and cited where it is derived, or a
// round trip — which asserts a property of the codec rather than a claim about
// what a peer sent.

/// The hash both upstream cases use: `let hash: Hash = [0xda; 32].into()`.
const da_hash: Hash = @splat(0xda);

const zero_hash: Hash = @splat(0);

const two_hashes = [_]Hash{ @splat(0), @splat(1) };

test "golden: Request wire format, iroh-blobs protocol.rs request_wire_format" {
    // 00                      # enum variant for GetRequest
    // dadadada…dadada (32)    # the hash
    // 020001000100            # the ChunkRangesSeq
    try expectRequestBytes(
        .{ .to_eof = .{ .get = GetRequest.blob(da_hash) } },
        "00" ++ "da" ** 32 ++ "020001000100",
    );
    try expectRequestFrom(
        "00" ++ "da" ** 32 ++ "020001000100",
        .{ .to_eof = .{ .get = GetRequest.blob(da_hash) } },
    );

    // 00                      # enum variant for GetRequest
    // dadadada…dadada (32)    # the hash
    // 01000100                # the ChunkRangesSeq
    try expectRequestBytes(
        .{ .to_eof = .{ .get = GetRequest.all(da_hash) } },
        "00" ++ "da" ** 32 ++ "01000100",
    );
    try expectRequestFrom(
        "00" ++ "da" ** 32 ++ "01000100",
        .{ .to_eof = .{ .get = GetRequest.all(da_hash) } },
    );

    // The second sequence is one pair and no terminator, so the walk repeats
    // it forever: that is what makes it a hash-sequence request rather than a
    // blob one, and it is a property of the sequence rather than of the frame.
    try testing.expect(GetRequest.all(da_hash).ranges.isInfinite());
    try testing.expect(!GetRequest.blob(da_hash).ranges.isInfinite());
}

test "golden: the push frame, derived from the captured get vector" {
    // Derived rather than captured, and derived from the two hexdumps above by
    // exactly the two differences `Request::read_async` (`src/protocol.rs:479`)
    // and `read_length_prefixed` (`src/util/stream.rs:381`) are: the
    // discriminant changes from `00` to `08`, and a `varint(u64)` length of
    // the body goes between the discriminant and the body. The body is
    // identical because `PushRequest` is a newtype over `GetRequest`
    // (`src/protocol.rs:567`) — the same hash and the same sequence, so the
    // same 38 bytes, and 38 is `0x26`.
    //
    // The length is the *body's* length and not the frame's, which is why it
    // covers the hash and the sequence and neither the discriminant in front
    // nor the payload behind: a `PushRequest` is decoded from exactly those
    // bytes, and the payload is outside the prefix by construction.
    const push: Request = .{
        .length_prefixed = .{ .request = .{ .get = GetRequest.blob(da_hash) } },
    };
    try expectRequestBytes(push, "08" ++ "26" ++ "da" ** 32 ++ "020001000100");
    try expectRequestFrom(
        "08" ++ "26" ++ "da" ** 32 ++ "020001000100",
        push,
    );
}

test "every request type round trips as a fixed point" {
    const requests = [_]Request{
        // A blob, and a collection, which is the same frame with a different
        // sequence.
        .{ .to_eof = .{ .get = GetRequest.blob(da_hash) } },
        .{ .to_eof = .{ .get = GetRequest.all(da_hash) } },
        // A `get` with an empty sequence: no ranges at all, which is a legal
        // frame and not a missing one.
        .{ .to_eof = .{ .get = .{ .hash = zero_hash, .ranges = .empty } } },
        // A `get_many` over two hashes, with the sequence a blob request uses.
        .{ .to_eof = .{ .get_many = .{
            .hashes = &two_hashes,
            .ranges = .{ .items = &blob_ranges },
        } } },
        // An observe, whose ranges are a spec and not a sequence.
        .{ .to_eof = .{ .observe = .{
            .hash = da_hash,
            .ranges = range_spec.RangeSpec.all,
        } } },
        // And a push, which is the same body under the other framing: once with
        // the sequence a whole-blob request sends, and once with a sequence of
        // its own, because a push is not restricted to a whole blob.
        .{ .length_prefixed = .{ .request = .{ .get = GetRequest.blob(da_hash) } } },
        .{ .length_prefixed = .{ .request = PushRequest.new(
            da_hash,
            .{ .items = &push_ranges },
        ) } },
    };
    for (requests) |request| try expectRequestFixedPoint(request);
}

test "framing: a push frame leaves the payload where it said it would" {
    const bao = [_]u8{ 0xde, 0xad, 0xbe, 0xef, 0x00, 0x11 };
    var frame: [64]u8 = undefined;
    var body: [2048]u8 = undefined;
    var writer = postcard.Writer.init(&frame);
    try (Request{ .length_prefixed = .{ .request = .{ .get = GetRequest.blob(da_hash) } } })
        .write(&writer, &body);

    // The request ends 40 bytes in: a discriminant, a one-byte length, 32 hash
    // bytes and a six-byte sequence. The payload starts there and is not
    // covered by the length.
    try testing.expectEqual(@as(usize, 40), writer.finish().len);
    @memcpy(frame[40 .. 40 + bao.len], &bao);

    var room: Room = .{};
    var storage = room.storage();
    var reader = postcard.Reader.init(frame[0 .. 40 + bao.len]);
    const decoded = try Request.read(&reader, &storage);
    const framed = switch (decoded) {
        .to_eof => return error.NotAPushFrame,
        .length_prefixed => |value| value,
    };
    try testing.expectEqual(@as(usize, 40), framed.payload_offset);
    try testing.expectEqualSlices(u8, &bao, decoded.payload(&reader));
    // The reader is left on the payload, not past it: the request is over and
    // the data has not started being consumed.
    try testing.expectEqual(@as(usize, 40), reader.offset);

    // And a request that ran to the end of the stream has no payload at all,
    // which the type says rather than leaving the caller to know which framing
    // it was handed.
    const get: Request = .{ .to_eof = .{ .get = GetRequest.blob(da_hash) } };
    try testing.expectEqualSlices(u8, "", get.payload(&reader));
}

test "framing: the two shapes are not interchangeable" {
    var get_frame: [64]u8 = undefined;
    var body: [2048]u8 = undefined;
    var writer = postcard.Writer.init(&get_frame);
    try (Request{ .to_eof = .{ .get = GetRequest.blob(da_hash) } }).write(&writer, &body);
    const get_bytes = writer.finish();

    // A `get` body read as a length prefix — the step a decoder that assumed
    // the other shape takes. The hash's first byte is the "length", and
    // thirty-two bytes of 0xda is a varint with the continuation bit set for
    // every byte a `u64` has room for. A named error, never a request.
    {
        var reader = postcard.Reader.init(get_bytes[1..]);
        try testing.expectError(error.BadVarint, readLengthPrefaced(&reader));
    }

    // A `push` body read as a `get` body is the dangerous one. The length byte
    // shifts the hash by one, and the sequence that follows is read from what
    // is left of the frame — so the result is not the request that was sent,
    // and it is either a named error or a *different* request depending on the
    // bytes. That is the whole reason the framing is a property of the type:
    // `Request.read` picks the framing from the discriminant, so no path in
    // this module can reach this, and a caller that reaches for the wrong
    // framing is told so instead. Here it is `BadLength`, because the shifted
    // hash leaves a 0xda where the sequence's element count is.
    {
        const push_body = "26" ++ "da" ** 32 ++ "020001000100";
        var reader = postcard.Reader.init(push_body);
        var room: Room = .{};
        var storage = room.storage();
        try testing.expectError(error.BadLength, GetRequest.parse(&reader, &storage));
    }

    // And each framing refuses a type it does not carry, before it reads a
    // byte of the body.
    {
        const push_frame = "08" ++ "26" ++ "da" ** 32 ++ "020001000100";
        var reader = postcard.Reader.init(push_frame[1..]);
        var room: Room = .{};
        var storage = room.storage();
        try testing.expectError(
            error.WrongFraming,
            EofFraming.read(.push, &reader, &storage),
        );
    }
    {
        var reader = postcard.Reader.init(get_bytes[1..]);
        var room: Room = .{};
        var storage = room.storage();
        try testing.expectError(
            error.WrongFraming,
            LengthPrefixedFraming.read(.get, &reader, &storage),
        );
    }
    // Every reserved arm is refused by the framing that would otherwise carry
    // it, and refused by name rather than read as a body.
    for (2..8) |slot| {
        const tag: RequestType = @enumFromInt(@as(u8, @intCast(slot)));
        var reader = postcard.Reader.init("");
        var room: Room = .{};
        var storage = room.storage();
        try testing.expectError(
            error.ReservedSlot,
            EofFraming.read(tag, &reader, &storage),
        );
    }
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

test "codec: malformed request encodings are named errors" {
    // A stream with no discriminant at all.
    try expectRequestErrorHex("", error.UnexpectedEnd);
    // 0x0a is one past the last arm, and 0x80 has the top bit set. Upstream
    // reads a discriminant as a raw byte, so neither is a truncated varint: both
    // are values this build does not have.
    try expectRequestErrorHex("0a", error.UnknownVariant);
    try expectRequestErrorHex("80", error.UnknownVariant);
    try expectRequestErrorHex("ff", error.UnknownVariant);
    // Every reserved arm, one through six, is refused.
    for (2..8) |slot| {
        const hex = [_]u8{ '0', '0' + @as(u8, @intCast(slot)) };
        try expectRequestErrorHex(&hex, error.ReservedSlot);
    }

    // A `get` whose sequence is a whole frame plus one byte. postcard 1.1.3's
    // `from_bytes` does not finalize its deserializer and would ignore that
    // byte; `finish` is what makes the two different frames.
    try expectRequestErrorHex(
        "00" ++ "da" ** 32 ++ "01000100" ++ "00",
        error.TrailingBytes,
    );
    // A `get` whose sequence declares a varint no `u64` can hold, and one
    // whose last byte carries more value bits than a `u64` has.
    try expectRequestErrorHex(
        "00" ++ "da" ** 32 ++ "01" ++ "00" ++ "80" ** 10,
        error.BadVarint,
    );
    try expectRequestErrorHex(
        "00" ++ "da" ** 32 ++ "01" ++ "00" ++ "80" ** 9 ++ "02",
        error.ValueOutOfRange,
    );
    // A `get` whose hash is cut short.
    try expectRequestErrorHex("00" ++ "da" ** 8, error.UnexpectedEnd);

    // A `push` whose declared length is past `max_message_size`, and one whose
    // length is inside the cap and not inside the stream.
    try expectRequestErrorHex("08" ++ "ffffffff01", error.MessageTooLarge);
    try expectRequestErrorHex("08" ++ "27" ++ "da" ** 8, error.UnexpectedEnd);
    // A `push` whose body decodes and then carries a byte the body did not
    // claim. The length is 39 and the body is 39: the 32 hash bytes, the
    // six-byte sequence, and one byte the `PushRequest` never asked for. The
    // payload sits outside the prefix, so this byte is not it either.
    try expectRequestErrorHex(
        "08" ++ "27" ++ "da" ** 32 ++ "020001000100" ++ "ff",
        error.TrailingBytes,
    );
    // A `push` with no length at all: the stream ends where the length is.
    try expectRequestErrorHex("08", error.UnexpectedEnd);

    // A `get_many` whose hash count is one the frame could carry and the
    // caller's storage could not. Every hash is 32 bytes, so a count of five
    // fits in the bytes that follow and not in `Room`'s four slots.
    try expectRequestErrorHex("09" ++ "05" ++ "da" ** 32 ++ "0000", error.BufferFull);

    // A `get` whose body is past `max_message_size`. This is the same cap the
    // `push` arm checks against a declared length, and it is the one rule in
    // the pair that a small frame cannot reach.
    {
        const big = try testing.allocator.alloc(u8, max_message_size + 2);
        defer testing.allocator.free(big);
        @memset(big, 0);
        var reader = postcard.Reader.init(big);
        var empty: Storage = .{};
        try testing.expectError(error.MessageTooLarge, Request.read(&reader, &empty));
    }
}

test "the protocol constants" {
    // Upstream's `ALPN` at `src/protocol.rs:406`, and `MAX_MESSAGE_SIZE` at
    // `src/protocol.rs:396` — whose comment says 100MiB for a value that is one
    // MiB. The value is what a peer enforces, so the value is what is here.
    try testing.expectEqualStrings("/iroh-bytes/4", alpn);
    try testing.expectEqual(@as(usize, 1024 * 1024), max_message_size);

    // BLAKE3's chunk size, and the bao tree's default block.
    try testing.expectEqual(@as(u64, 1024), chunk_size);
    try testing.expectEqual(@as(u64, 16384), block_size);
    // The ratio is why both are here: sixteen chunks to a block, so one round
    // of the tree carries 16384 bytes and a block boundary lands every
    // sixteenth chunk. `chunks_per_block` is derived from the two constants,
    // so it cannot drift from them.
    try testing.expectEqual(@as(u64, 16), chunks_per_block);
    try testing.expectEqual(@as(u64, 16), @divExact(block_size, chunk_size));
    try testing.expectEqual(block_size, chunk_size * chunks_per_block);
    // Upstream states the trade at `src/protocol.rs:26`: the minimum
    // granularity is "a chunk group of 16KiB or 16 blake3 chunks", and the
    // worst-case overhead of a range request is about two chunk groups. A
    // request is asked for in chunks and answered in blocks, and that gap is
    // the price of asking for a range at all.
    try testing.expectEqual(block_size, chunk_size * 16);
}

test "every request discriminant is one byte on the wire" {
    // Upstream reads the discriminant as a raw `u8` (`src/protocol.rs:449`) and
    // its `request_type_size` test pins the encoded size at one
    // (`RequestType::POSTCARD_MAX_SIZE == 1`, `src/protocol.rs:1068`). Every
    // arm is below 128, so postcard's `varint(u32)` for a discriminant and one
    // raw byte are the same bytes — which is what lets the reader be a byte.
    try testing.expectEqual(@as(usize, 10), std.enums.values(RequestType).len);
    for (std.enums.values(RequestType)) |arm| {
        var buffer: [1]u8 = undefined;
        var writer = postcard.Writer.init(&buffer);
        try writeRequestType(&writer, arm);
        try testing.expectEqualSlices(u8, &.{@intFromEnum(arm)}, writer.finish());
    }
    // The four arms that carry a request are the four upstream dispatches on,
    // and the order is the one `RequestType`'s own comment demands: it "must
    // contain the request types in the same order as the full requests".
    try testing.expectEqual(@as(u8, 0), @intFromEnum(RequestType.get));
    try testing.expectEqual(@as(u8, 1), @intFromEnum(RequestType.observe));
    try testing.expectEqual(@as(u8, 8), @intFromEnum(RequestType.push));
    try testing.expectEqual(@as(u8, 9), @intFromEnum(RequestType.get_many));
}

test "bytes to chunks: the four roundings upstream's tests pin" {
    // Captured, from upstream's `chunk_ranges_ext` test at
    // `src/protocol.rs:943` and its `get_request_builder` test at
    // `src/protocol.rs:960`, which state these as equalities:
    //
    //   ChunkRanges::bytes(1..2)     == ChunkNum(0)..ChunkNum(1)
    //   ChunkRanges::offset(1024*10) == ChunkNum(10)..ChunkNum(11)
    //   ChunkRanges::bytes(0..100)   == ..ChunkNum(1)
    //
    // The first is the non-integral case, and it is the reason the two ends
    // round in opposite directions: byte 1 is inside chunk 0 and byte 2 is the
    // first byte of the chunk after it, so the range is exactly one chunk.
    try testing.expectEqual(
        ChunkRange{ .start = 0, .end = 1 },
        bytesToChunks(.{ .start = 1, .end = 2 }),
    );
    try testing.expectEqual(
        ChunkRange{ .start = 10, .end = 11 },
        bytesToChunks(.{ .start = 10240, .end = 10241 }),
    );
    try testing.expectEqual(
        ChunkRange{ .start = 0, .end = 1 },
        bytesToChunks(.{ .start = 0, .end = 100 }),
    );
    // Upstream's own worked example, `ChunkRanges::bytes(10000..11000)`, from
    // the module prose at `src/protocol.rs:161`.
    try testing.expectEqual(
        ChunkRange{ .start = 9, .end = 11 },
        bytesToChunks(.{ .start = 10000, .end = 11000 }),
    );

    // `ChunkNum::chunks`'s doc gives the two cases this has to keep apart:
    // "1024 bytes is 1 chunk, 1025 bytes is 2 chunks". One byte over a boundary
    // is the whole of the non-integral case, and 100000 bytes is 97 and a bit.
    try testing.expectEqual(@as(u64, 0), chunkAfterByte(0));
    try testing.expectEqual(@as(u64, 1), chunkAfterByte(1024));
    try testing.expectEqual(@as(u64, 2), chunkAfterByte(1025));
    try testing.expectEqual(@as(u64, 98), chunkAfterByte(100000));
    // The start rounds the other way, and byte 1023 is still in chunk 0.
    try testing.expectEqual(@as(u64, 0), chunkOfByte(0));
    try testing.expectEqual(@as(u64, 0), chunkOfByte(1023));
    try testing.expectEqual(@as(u64, 1), chunkOfByte(1024));

    // The other direction, exact only for whole chunks.
    try testing.expectEqual(
        ByteRange{ .start = 0, .end = 1024 },
        chunksToBytes(.{ .start = 0, .end = 1 }),
    );
    try testing.expectEqual(
        ByteRange{ .start = 10240, .end = 11264 },
        chunksToBytes(.{ .start = 10, .end = 11 }),
    );
    // A chunk number off a peer's wire can be `u64.max`, where upstream's
    // `self.0 << 10` would not be a value at all.
    try testing.expectEqual(
        std.math.maxInt(u64),
        chunksToBytes(.{ .start = 0, .end = std.math.maxInt(u64) }).end,
    );
    // An inverted range covers no chunks rather than wrapping to a huge one.
    try testing.expectEqual(@as(u64, 0), (ChunkRange{ .start = 5, .end = 3 }).len());
}

test "an empty or inverted byte range covers no chunk" {
    // The audit case: bytes 5 through 5 is no bytes, so it is no chunks. The
    // outward rounding alone named chunk 0 through 1 and the answer covered a
    // chunk the request never asked for.
    const empty = bytesToChunks(.{ .start = 5, .end = 5 });
    try testing.expectEqual(@as(u64, 0), empty.len());
    try testing.expectEqual(ChunkRange{ .start = 0, .end = 0 }, empty);

    // The empty range at zero, and one straddling a chunk boundary, so the
    // answer is at the chunk the start byte is in rather than at zero.
    try testing.expectEqual(
        ChunkRange{ .start = 0, .end = 0 },
        bytesToChunks(.{ .start = 0, .end = 0 }),
    );
    const straddling = bytesToChunks(.{ .start = 1024, .end = 1024 });
    try testing.expectEqual(ChunkRange{ .start = 1, .end = 1 }, straddling);
    try testing.expectEqual(@as(u64, 0), straddling.len());
    try testing.expectEqual(
        ChunkRange{ .start = 4, .end = 4 },
        bytesToChunks(.{ .start = 4096, .end = 4096 }),
    );

    // Inverted is the same answer: end before start names no bytes, and
    // rounding its end up would name chunks past the ones a caller asked
    // about. `start <= end` holds on every result, so the count reads zero
    // rather than wrapping.
    for ([_]ByteRange{
        .{ .start = 5, .end = 3 },
        .{ .start = 2048, .end = 1024 },
        .{ .start = 1024, .end = 1 },
    }) |range| {
        const chunks = bytesToChunks(range);
        try testing.expect(chunks.start <= chunks.end);
        try testing.expectEqual(@as(u64, 0), chunks.len());
        try testing.expectEqual(chunkOfByte(range.start), chunks.start);
    }

    // The one-byte range is the boundary this fix must not move: it is the
    // smallest range that covers a byte, and it still rounds outward to a
    // whole chunk.
    try testing.expectEqual(
        ChunkRange{ .start = 0, .end = 1 },
        bytesToChunks(.{ .start = 5, .end = 6 }),
    );
    try testing.expectEqual(
        ChunkRange{ .start = 1, .end = 2 },
        bytesToChunks(.{ .start = 1024, .end = 1025 }),
    );

    // And the other direction agrees: an empty chunk range is an empty byte
    // range, so a round trip through both conversions cannot widen one.
    for ([_]ChunkRange{
        .{ .start = 0, .end = 0 },
        .{ .start = 1, .end = 1 },
        .{ .start = 4, .end = 4 },
    }) |chunks| {
        const bytes = chunksToBytes(chunks);
        try testing.expectEqual(@as(u64, 0), bytes.end -| bytes.start);
    }
}

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

test "ChunkRangeSet: a boundary list, and not a width list" {
    // The empty set is a count of nothing, and the whole set is a single
    // boundary zero: `RangeSet::empty` and `RangeSet::all`
    // (`src/range_set.rs:637` and `:641`).
    try expectSetHex(.empty, "00");
    try expectSetHex(.all, "0100");
    // Chunks 1 and 2 is the two boundaries 1 and 2. Read as a `RangeSpec` those
    // same bytes mean one gap chunk and two selected from there — which is why
    // the two are separate types rather than one range with a flag.
    try expectSetHex(.{ .boundaries = &.{ 1, 2 } }, "020102");
    // `last_chunk` is upstream's `ChunkRanges::last_chunk`, which is
    // `from_range_from(u64::MAX)`: the start rounds down to zero, so the range
    // runs to the end of whatever blob it is read against.
    try expectSetHex(.last_chunk, "02" ++ "00" ++ "ff" ** 9 ++ "01");
    try testing.expect(ChunkRangeSet.empty.isEmpty());
    try testing.expect(!ChunkRangeSet.empty.isAll());
    try testing.expect(ChunkRangeSet.all.isAll());
    try testing.expect(!ChunkRangeSet.last_chunk.isAll());

    // A decode sorts and dedups, because that is what upstream's
    // `RangeSetVisitor` does (`src/range_set.rs:1000`): it reads what the frame
    // names, sorts it, dedups it, and checks nothing else — not the parity, not
    // the order. So an unsorted list with a repeat is a *value*.
    {
        var boundaries: [16]u64 = undefined;
        var reader = postcard.Reader.init(&[_]u8{ 0x04, 0x05, 0x01, 0x05, 0x09 });
        const set = try ChunkRangeSet.parse(&reader, &boundaries);
        try reader.finish();
        try testing.expectEqualSlices(u64, &.{ 1, 5, 9 }, set.boundaries);
        // And the normalised set has its own canonical form, which is not the
        // one that arrived. The parity still holds: 1 and 5 start ranges, 9
        // ends one.
        var buffer: [32]u8 = undefined;
        var writer = postcard.Writer.init(&buffer);
        try set.write(&writer);
        try expectHex(&[_]u8{ 0x03, 0x01, 0x05, 0x09 }, writer.finish());
    }
    // A count the caller's boundaries could not hold.
    {
        var boundaries: [1]u64 = undefined;
        var reader = postcard.Reader.init(&[_]u8{ 0x04, 0x01, 0x02, 0x03, 0x04 });
        try testing.expectError(error.BufferFull, ChunkRangeSet.parse(&reader, &boundaries));
    }
}

test "Closed: a stream code, never a payload frame" {
    // Upstream's three codes and their reasons (`src/protocol.rs:676` and
    // `:690`).
    try testing.expectEqual(@as(u64, 0), Closed.stream_dropped.toVarInt());
    try testing.expectEqual(@as(u64, 1), Closed.provider_terminating.toVarInt());
    try testing.expectEqual(@as(u64, 2), Closed.request_received.toVarInt());
    try testing.expectEqualStrings("stream dropped", Closed.stream_dropped.reason());
    try testing.expectEqualStrings("provider terminating", Closed.provider_terminating.reason());
    try testing.expectEqualStrings("request received", Closed.request_received.reason());
    for (std.enums.values(Closed)) |arm| {
        try testing.expectEqual(arm, try Closed.fromVarInt(arm.toVarInt()));
        // All three are below 64, and a QUIC varint that small is a single
        // byte holding the value — which is why upstream's is a plain
        // `VarInt::from(self as u16)`.
        try testing.expect(arm.toVarInt() < 64);
    }
    // A code this build has no arm for is named, because a default arm would
    // report a close nobody sent.
    try testing.expectError(error.UnknownClose, Closed.fromVarInt(3));
    try testing.expectError(error.UnknownClose, Closed.fromVarInt(65_536));
    try testing.expectError(error.UnknownClose, Closed.fromVarInt(std.math.maxInt(u64)));

    // And they are a code beside the stream rather than bytes in it: an answer
    // is whatever the provider wrote, so a code is never in one.
    const code_bytes = [_]u8{@intCast(Closed.request_received.toVarInt())};
    var reader = postcard.Reader.init(&code_bytes);
    try testing.expectEqualSlices(u8, &code_bytes, BaoResponse.read(&reader).bytes);
}

test "decode is total: the real frames first, then a mutation sweep" {
    // The frames a peer actually sends, before anything else, so the shapes
    // above are exercised as themselves and the sweep has something
    // recognisable to mutate away from.
    const request_seeds = [_][]const u8{
        "00" ++ "da" ** 32 ++ "020001000100",
        "00" ++ "da" ** 32 ++ "01000100",
        "08" ++ "26" ++ "da" ** 32 ++ "020001000100",
    };
    // And one observe item, framed the way a provider frames it, so the
    // observe half of the sweep starts from a run that decodes rather than
    // from bytes that never could.
    const observe_seeds = [_][]const u8{
        "05" ++ "80" ++ "08" ++ "02" ++ "01" ++ "02",
    };
    const seeds = request_seeds ++ observe_seeds;

    var decoded_ok: usize = 0;
    for (request_seeds) |hex| {
        var scratch: [96]u8 = undefined;
        decoded_ok += try expectTotalRequest(try parseHex(&scratch, hex));
    }
    // Every captured frame decodes, and only those three are claimed to.
    try testing.expectEqual(request_seeds.len, decoded_ok);

    // A mutation sweep over those frames rather than a sweep of noise, and a
    // counter-based one rather than a random one, so a failure names its input
    // and the same inputs come out on every run and every machine. Noise
    // almost never decodes — a request has to consume itself exactly and a
    // random length prefix never does — so a sweep of noise would prove only
    // that the decoder rejects things. Growing a real frame with random bytes
    // is the shape a `push` payload is; overwriting a suffix of one is the
    // shape every truncation and every lying length is.
    //
    // Any error the sweep can raise is a member of `Error` by construction, so
    // the sweep fails by panicking and by nothing else — which is the point.
    var buffer: [96]u8 = undefined;
    for (seeds) |hex| {
        var scratch: [96]u8 = undefined;
        const seed = try parseHex(&scratch, hex);
        for (0..20_000) |n| {
            const grown = @min(seed.len + n % 33, buffer.len);
            @memcpy(buffer[0..seed.len], seed);
            for (buffer[seed.len..grown], 0..) |*byte, i| byte.* = mix(n, i);
            decoded_ok += try expectTotalRequest(buffer[0..grown]);

            const from = n % (seed.len + 1);
            @memcpy(buffer[0..seed.len], seed);
            for (buffer[from..seed.len], 0..) |*byte, i| byte.* = mix(n, from + i);
            decoded_ok += try expectTotalRequest(buffer[0..seed.len]);
        }
    }
    // The sweep has to have decoded a good number, or it proved nothing about
    // the happy path. Growing the `push` frame decodes every time, because what
    // follows a length prefix is payload and not part of the request.
    try testing.expect(decoded_ok > 5000);

    // The same sweep on the observe answer, whose items are length-prefixed and
    // whose ranges are a boundary list rather than a width list. A run ends
    // between items or on an error, never by looping: every item costs at
    // least the byte of its own length prefix.
    var items: usize = 0;
    for (seeds) |hex| {
        var scratch: [96]u8 = undefined;
        const seed = try parseHex(&scratch, hex);
        items += try expectTotalObserve(seed);
        for (0..20_000) |n| {
            const grown = @min(seed.len + n % 33, buffer.len);
            @memcpy(buffer[0..seed.len], seed);
            for (buffer[seed.len..grown], 0..) |*byte, i| byte.* = mix(n, i);
            items += try expectTotalObserve(buffer[0..grown]);
        }
    }
    try testing.expect(items > 0);
}

/// Decode `bytes` as a whole request, and if it decodes assert that it is a
/// fixed point. Returns whether it decoded.
fn expectTotalRequest(bytes: []const u8) !usize {
    var room: Room = .{};
    var storage = room.storage();
    var reader = postcard.Reader.init(bytes);
    const decoded = Request.read(&reader, &storage) catch return 0;

    // A request that decoded is a whole frame, and it re-encodes to bytes that
    // decode to the same request. The framing is a function of the type, so the
    // same bytes take the same branch twice — which is what makes the fixed
    // point worth asserting here and not only on hand-picked frames.
    var frame: [2048]u8 = undefined;
    var body: [2048]u8 = undefined;
    var writer = postcard.Writer.init(&frame);
    try decoded.write(&writer, &body);
    const written = writer.finish();

    var again_room: Room = .{};
    var again_storage = again_room.storage();
    var recoder = postcard.Reader.init(written);
    const recoded = try Request.read(&recoder, &again_storage);
    try recoder.finish();
    try testing.expect(decoded.eql(recoded));

    var again: [2048]u8 = undefined;
    var rewriter = postcard.Writer.init(&again);
    try recoded.write(&rewriter, &body);
    try testing.expectEqualSlices(u8, written, rewriter.finish());
    return 1;
}

/// Read `bytes` as an observe run, and assert that every item's set is sorted
/// and duplicate-free. Returns how many items came out.
fn expectTotalObserve(bytes: []const u8) !usize {
    var room: Room = .{};
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

/// Byte `i` of input `n` in a sweep that covers the space without a generator.
///
/// A splitmix finaliser over the two counters, so every byte of every input is
/// a pure function of where it sits. `std.RandomDefaultPrng` would need a seed
/// and a state, and a test whose inputs depend on a global is a test nobody can
/// reproduce.
fn mix(n: usize, i: usize) u8 {
    var z: u64 = @as(u64, @intCast(n)) *% 0x9e3779b97f4a7c15 +% @as(u64, @intCast(i));
    z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9;
    z = (z ^ (z >> 27)) *% 0x94d049bb133111eb;
    z = z ^ (z >> 31);
    return @truncate(z);
}

/// Storage for one decode, with the buffers it names beside it.
///
/// The slices in a `Storage` are the only place a decode writes, so they
/// cannot outlive the buffer they point into: a helper returning a `Storage`
/// alone would hand back a dangling one. `Room` and its buffers are a pair
/// because of that and not for tidiness.
const Room = struct {
    items: [16]range_spec.Item = undefined,
    widths: [64]u64 = undefined,
    hashes: [4]Hash = undefined,
    boundaries: [32]u64 = undefined,

    fn storage(self: *Room) Storage {
        return .{
            .items = &self.items,
            .widths = &self.widths,
            .hashes = &self.hashes,
            .boundaries = &self.boundaries,
        };
    }
};

/// Write `request` and expect exactly `hex`.
fn expectRequestBytes(request: Request, hex: []const u8) !void {
    var scratch: [256]u8 = undefined;
    const expected = try parseHex(&scratch, hex);
    var body: [2048]u8 = undefined;
    var buffer: [2048]u8 = undefined;
    var writer = postcard.Writer.init(&buffer);
    try request.write(&writer, &body);
    try expectHex(expected, writer.finish());
}

/// Read `hex` as a whole request and expect `expected`.
fn expectRequestFrom(hex: []const u8, expected: Request) !void {
    var scratch: [256]u8 = undefined;
    const bytes = try parseHex(&scratch, hex);
    var room: Room = .{};
    var storage = room.storage();
    var reader = postcard.Reader.init(bytes);
    const decoded = try Request.read(&reader, &storage);
    try reader.finish();
    try testing.expect(expected.eql(decoded));
}

/// Read `hex` as a whole request and expect a named error.
fn expectRequestErrorHex(hex: []const u8, expected: Error) !void {
    var scratch: [256]u8 = undefined;
    const bytes = try parseHex(&scratch, hex);
    var room: Room = .{};
    var storage = room.storage();
    var reader = postcard.Reader.init(bytes);
    try testing.expectError(expected, Request.read(&reader, &storage));
}

/// Encode `request`, read it back, and re-encode: a fixed point, both ways.
fn expectRequestFixedPoint(request: Request) !void {
    var body: [2048]u8 = undefined;
    var buffer: [2048]u8 = undefined;
    var writer = postcard.Writer.init(&buffer);
    try request.write(&writer, &body);
    const frame = writer.finish();

    var room: Room = .{};
    var storage = room.storage();
    var reader = postcard.Reader.init(frame);
    const decoded = try Request.read(&reader, &storage);
    try reader.finish();
    try testing.expect(request.eql(decoded));

    var again: [2048]u8 = undefined;
    var rewriter = postcard.Writer.init(&again);
    try decoded.write(&rewriter, &body);
    try testing.expectEqualSlices(u8, frame, rewriter.finish());
}

/// Write `set` and expect exactly `hex`, and read it back.
fn expectSetHex(set: ChunkRangeSet, hex: []const u8) !void {
    var scratch: [64]u8 = undefined;
    const expected = try parseHex(&scratch, hex);
    var buffer: [64]u8 = undefined;
    var writer = postcard.Writer.init(&buffer);
    try set.write(&writer);
    try expectHex(expected, writer.finish());

    var boundaries: [16]u64 = undefined;
    var reader = postcard.Reader.init(expected);
    const decoded = try ChunkRangeSet.parse(&reader, &boundaries);
    try reader.finish();
    try testing.expect(set.eql(decoded));
}

/// The bytes a hex string stands for, decoded into `out`. A hexdump needs no
/// allocator: every one of them lands in a scratch buffer a test already has.
fn parseHex(out: []u8, hex: []const u8) ![]const u8 {
    if (hex.len % 2 != 0) return error.OddHexLength;
    return std.fmt.hexToBytes(out, hex);
}

/// Long enough for every hexdump above. A diagnostic, not a general formatter:
/// the bytes it prints are the ones written down in this file.
const max_dumped_bytes = 64;

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
    return out;
}
