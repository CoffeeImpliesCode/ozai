//! The blobs wire protocol: the requests a getter may send, the two ways a
//! request is framed on a stream, and the rule that missing data is the end of
//! the stream rather than a message to decode.
//!
//! This file is the module's identity and its public surface. The four
//! declarations that are *about the protocol rather than about any one of its
//! parts* live here, and the four concerns are each their own file:
//!
//! - `chunk.zig` — the 1024-byte BLAKE3 chunk every range is counted in, the
//!   conversions to and from bytes, and `ChunkRangeSet`, the boundary list an
//!   `ObserveItem`'s ranges arrive as.
//! - `request.zig` — `GetRequest`, `GetManyRequest`, `ObserveRequest` and
//!   `PushRequest`: the four request bodies, as values.
//! - `framing.zig` — `RequestType`, `Request`, the two framings and their
//!   readers, the length-prefix rule, and the `Closed` stream codes.
//! - `response.zig` — `BaoResponse` and `ObserveResponse`: what a provider
//!   sends back.
//!
//! Everything a caller reached through `blobs_protocol` before the split is
//! re-exported below under the name it had, so `ozai.blobs_protocol.Request`
//! and `ozai.blobs_protocol.GetRequest` are the declarations they were. The
//! re-exports are the surface, not aliases for a second spelling of it: a
//! name exported from two places is one name with two owners, and the split is
//! only worth anything if it has exactly one.
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
//! # The framing depends on the request type, and that is the whole point
//!
//! Upstream reads `Get`, `GetMany` and `Observe` with `read_to_end_as`
//! (`src/util/stream.rs:370`): the request *is* the rest of the stream. It
//! reads `Push` with `read_length_prefixed` (`src/util/stream.rs:381`): a
//! `varint(u64)` length, then exactly that many bytes, and then the bao data
//! the getter is pushing, on the same stream.
//!
//! The difference is not a detail, because a `push` request and its payload
//! share a stream and the other three do not. A decoder that read a `push`
//! body to the end of the stream would swallow the payload into the request;
//! one that read a `get` with a length prefix would read the hash's first byte
//! as a length. So the framing is a property of the type and is carried as one:
//! `EofFraming` and `LengthPrefixedFraming` are separate types with separate
//! readers, and a value of one is not a value of the other. `Request.read`
//! reads the one discriminant byte and hands the request to exactly one of
//! them, and a type that is not the one a framing carries is
//! `error.WrongFraming` rather than a body decoded from the wrong bytes. The
//! whole of that argument is `framing.zig`'s module comment, and so is the code.
//!
//! # Missing data is EOF, not an error frame
//!
//! Upstream's `# Responses` section (`src/protocol.rs:320`) is explicit: for a
//! complete response the chunks "are guaranteed to completely cover the
//! requested ranges", and the reasons for an incomplete one are an interrupted
//! connection — which closes the whole connection — or that "the provider does
//! not have the requested data, or discovered on send that the requested data
//! is not valid", in which case "the provider will close just the stream used
//! to send the response".
//!
//! So there is no error value in a payload. A provider that cannot answer ends
//! the stream, and the evidence a getter has is that the bytes stopped. The
//! protocol has no type that can hold a decoded "missing data", and
//! `BaoResponse` has no error arm: a short answer is a short answer, and the
//! bao decoder — not this one — is what decides whether a transfer is
//! complete. The only error codes in the protocol are `Closed`, and they are a
//! QUIC STOP_STREAM code sent alongside the stream rather than bytes in it.
//!
//! That is why `BaoResponse.isEof` and `ObserveResponse.next` returning `null`
//! are the two places EOF is a value at all. Both are tested against bytes
//! that stop early, and neither is tested against an error.
//!
//! # Chunks, and the block above them
//!
//! Every range in this protocol — in a request and in an `ObserveItem` alike —
//! is a count of 1024-byte BLAKE3 chunks. `chunk_size` is bao-tree's
//! `BLAKE3_CHUNK_SIZE` (`src/tree.rs:119`, at commit
//! `2be9abd144783455606424424c29bd3a57f926f8`), and `ChunkNum`'s own doc says
//! "The blake3 chunk size is 1024 bytes" (`src/tree.rs:14`). Upstream says the
//! same in prose at `src/protocol.rs:98`: ranges are "always given in terms of
//! 1024 byte blake3 chunks, *not* in terms of bytes or chunk groups", because
//! a chunk is the unit BLAKE3 hashes and combining chunks is "merely an
//! optimization to reduce metadata overhead".
//!
//! `block_size` is the same crate's default, 16384 bytes: `BlockSize`'s
//! `bytes()` is `BLAKE3_CHUNK_SIZE << chunk_log` (`src/tree.rs:159`) and the
//! crate's two worked examples both say "Use a block size of 16 KiB, a good
//! default for most cases" (`src/lib.rs:88` and `src/lib.rs:152`), which is
//! `from_chunk_log(4)`.
//!
//! The ratio is the point, and `chunks_per_block` is derived from the two
//! constants rather than written beside them: sixteen chunks to a block, so
//! one round of the bao tree carries 16384 bytes and a block boundary lands
//! every sixteen chunks. Upstream states the trade at `src/protocol.rs:26`:
//! the "minimum granularity is a chunk group of 16KiB or 16 blake3 chunks",
//! and "the worst case overhead when doing range requests is about two chunk
//! groups per range". A request is therefore answered in blocks even though it
//! is asked for in chunks, and that gap — up to two blocks per requested range
//! — is the price of a range request at all. The three constants and the
//! arithmetic that derives the ratio from them are `chunk.zig`'s.
//!
//! The conversion between the two units is a named function and not an
//! arithmetic expression at a call site: `bytesToChunks` rounds a byte range
//! *outward* (the start down to the chunk that contains it, the end up to the
//! first chunk past it) because that is `bao_tree::io::round_up_to_chunks`
//! (`src/io/mod.rs:135`), and it rounds the two ends in opposite directions on
//! purpose — its comment says "full_chunks() rounds down, chunks() rounds up".
//! `chunksToBytes` is the other direction and is exact only for a whole
//! number of chunks; a blob whose length is not a multiple of 1024 has a short
//! last chunk, so the byte count it returns is the first byte *past* that
//! chunk.
//!
//! # Purity
//!
//! Nothing in any of the five files reads a clock, the environment, a global or
//! an allocator. A decode fills `Storage`, which the caller owns, and every
//! slice a decoded message points at lives in it; `Request.write` borrows one
//! caller-owned scratch buffer for the `push` body, because a `varint` length
//! cannot be backpatched once its width is known. The reasons are the ones
//! `docs/ARCHITECTURE.md` gives under "Wire codecs are pure and separate from
//! the transport", and the one that bites hardest here is that every byte a
//! decoder reads was chosen by a peer. Every decode path is total and every
//! error is named: there is no `unreachable` on any of them.

const std = @import("std");
const postcard = @import("../wire/postcard.zig");
const range_spec = @import("range_spec.zig");

const chunk = @import("chunk.zig");
const request = @import("request.zig");
const framing = @import("framing.zig");
const response = @import("response.zig");

/// The ALPN this protocol is spoken on.
///
/// Upstream's `ALPN` at `src/protocol.rs:406`, `b"/iroh-bytes/4"`, at the
/// commit named in the module comment. `/4` is the protocol version and
/// changes with a wire change, which is why it is a value here rather than a
/// name someone has to remember.
pub const alpn = "/iroh-bytes/4";

/// The most bytes a request body may occupy.
///
/// Upstream's `MAX_MESSAGE_SIZE` at `src/protocol.rs:396`, and its comment
/// says "100MiB" for a value that is one MiB. The value is what a peer
/// enforces, so this is the value; the comment is upstream's error and is noted
/// rather than followed.
///
/// It is the protocol's identity rather than one arm's rule: `EofFraming.read`
/// checks a body that ran to the end of the stream against it, and
/// `readLengthPrefaced` checks a declared length against it, and those are two
/// different arms of two different files.
pub const max_message_size: usize = 1024 * 1024;

/// Every way a blobs request can fail to encode or decode.
///
/// The postcard members are the codec's, and are repeated here rather than
/// wrapped: a caller that reads a request wants to tell a varint that cannot
/// fit from a length that cannot be true, and a nested error would make it
/// unwrap a type that does not depend on the frame it was in. The four added
/// members each name one rule of this protocol rather than one symptom.
pub const Error = postcard.Error || error{
    /// A body larger than `max_message_size`, named whether the length was
    /// declared in front of it or is implied by the rest of the stream.
    MessageTooLarge,
    /// A discriminant upstream reserves and its reader refuses. Upstream calls
    /// these `Slot2` through `Slot7` and rejects every one of them rather than
    /// skipping it, so a reserved slot is a request this build will not serve.
    ReservedSlot,
    /// A request type this framing does not carry. Only reachable by handing a
    /// request to the wrong of the two framings, which is the mistake the two
    /// types exist to make impossible.
    WrongFraming,
    /// A `Closed` code this build has no arm for.
    UnknownClose,
};

/// Caller-owned scratch a decode fills.
///
/// Every slice a decoded message points at lives in one of these, which is why
/// nothing in any of the five files allocates: a decoded `GetManyRequest`
/// borrows `hashes`, and a decoded `RangeSpecSeq` borrows `items` and `widths`
/// together. The defaults are empty, and an empty field is not a special case —
/// a decode that needs room it was not given is `error.BufferFull`, the same
/// condition `postcard.Writer` names for a writer, and it is checked against
/// the count the frame declared rather than against the bytes that remain.
///
/// `hashes` is `[][32]u8` and not `[]Hash` because `Hash` is `request.zig`'s
/// private alias of that builtin; the two are the same type, and a private
/// alias cannot be named from here.
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
    hashes: [][32]u8 = &.{},
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

// -- The unit every range is counted in, and the boundary list it arrives as.

pub const chunk_size = chunk.chunk_size;
pub const block_size = chunk.block_size;
pub const chunks_per_block = chunk.chunks_per_block;
pub const ByteRange = chunk.ByteRange;
pub const ChunkRange = chunk.ChunkRange;
pub const chunkOfByte = chunk.chunkOfByte;
pub const chunkAfterByte = chunk.chunkAfterByte;
pub const bytesToChunks = chunk.bytesToChunks;
pub const chunksToBytes = chunk.chunksToBytes;
pub const ChunkRangeSet = chunk.ChunkRangeSet;

// -- The four request bodies.

pub const GetRequest = request.GetRequest;
pub const GetManyRequest = request.GetManyRequest;
pub const ObserveRequest = request.ObserveRequest;
pub const PushRequest = request.PushRequest;

// -- The two framings, the discriminant that picks one, and the stream codes.

pub const RequestType = framing.RequestType;
pub const Closed = framing.Closed;
pub const EofRequest = framing.EofRequest;
pub const PushFraming = framing.PushFraming;
pub const Request = framing.Request;
pub const EofFraming = framing.EofFraming;
pub const LengthPrefixedFraming = framing.LengthPrefixedFraming;

// -- What a provider sends back.

pub const BaoResponse = response.BaoResponse;
pub const ObserveItem = response.ObserveItem;
pub const ObserveResponse = response.ObserveResponse;

const testing = std.testing;

// The test scaffolding the four modules share. It is `pub` because a golden
// vector is a claim about bytes, and the two halves of that claim — "these are
// the bytes" and "these are the bytes a decode gives back" — are asserted from
// three different files. `Room` is here for the same reason and for a second
// one: the slices in a `Storage` are the only place a decode writes, so a
// helper returning a `Storage` alone would hand back a dangling one, and `Room`
// and its buffers have to be a pair.

/// The bytes a hex string stands for, decoded into `out`. A hexdump needs no
/// allocator: every one of them lands in a scratch buffer a test already has.
pub fn parseHex(out: []u8, hex: []const u8) ![]const u8 {
    if (hex.len % 2 != 0) return error.OddHexLength;
    return std.fmt.hexToBytes(out, hex);
}

/// Long enough for every hexdump the four modules write down. A diagnostic,
/// not a general formatter: the bytes it prints are the ones written down in
/// those files.
pub const max_dumped_bytes = 64;

pub fn expectHex(expected: []const u8, actual: []const u8) !void {
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

/// Storage for one decode, with the buffers it names beside it.
///
/// The slices in a `Storage` are the only place a decode writes, so they
/// cannot outlive the buffer they point into: a helper returning a `Storage`
/// alone would hand back a dangling one. `Room` and its buffers are a pair
/// because of that and not for tidiness.
pub const Room = struct {
    items: [16]range_spec.Item = undefined,
    widths: [64]u64 = undefined,
    hashes: [4][32]u8 = undefined,
    boundaries: [32]u64 = undefined,

    pub fn storage(self: *Room) Storage {
        return .{
            .items = &self.items,
            .widths = &self.widths,
            .hashes = &self.hashes,
            .boundaries = &self.boundaries,
        };
    }
};

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
