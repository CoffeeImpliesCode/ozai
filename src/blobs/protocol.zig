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
// The tests left below are the ones that need more than one of them: a test
// that asserts one module's own behaviour lives in that module.

const std = @import("std");
const postcard = @import("../wire/postcard.zig");

const framing_mod = @import("framing.zig");
const ranges_mod = @import("ranges.zig");
const requests_mod = @import("requests.zig");
const responses_mod = @import("responses.zig");
const test_support = @import("wire_test_support.zig");

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
// themselves stay where they are implemented. The decode arena and the two hex
// helpers are `wire_test_support.zig`'s, because three of this protocol's
// modules' tests want them.

const Room = test_support.Room;
const parseHex = test_support.parseHex;
const expectHex = test_support.expectHex;

const testing = std.testing;

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
    try expectSetHex(.last_chunk, "02" ++ "00" ++ "ffffffffffffffffff" ++ "01");
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
        "00" ++ "dadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadada" ++ "020001000100",
        "00" ++ "dadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadada" ++ "01000100",
        "08" ++ "26" ++ "dadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadada" ++ "020001000100",
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
