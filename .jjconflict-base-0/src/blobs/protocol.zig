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
//! `error.WrongFraming` rather than a body decoded from the wrong bytes.
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
//! the stream, and the evidence a getter has is that the bytes stopped. This
//! module has no type that can hold a decoded "missing data", and `BaoResponse`
//! has no error arm: a short answer is a short answer, and the bao decoder —
//! not this one — is what decides whether a transfer is complete. The only
//! error codes in the protocol are `Closed`, and they are a QUIC STOP_STREAM
//! code sent alongside the stream rather than bytes in it.
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
//! — is the price of a range request at all.
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
//! Nothing here reads a clock, the environment, a global or an allocator. A
//! decode fills `Storage`, which the caller owns, and every slice a decoded
//! message points at lives in it; `Request.write` borrows one caller-owned
//! scratch buffer for the `push` body, because a `varint` length cannot be
//! backpatched once its width is known. The reasons are the ones
//! `docs/ARCHITECTURE.md` gives under "Wire codecs are pure and separate from
//! the transport", and the one that bites hardest here is that every byte a
//! decoder below reads was chosen by a peer. Every decode path is total and
//! every error is named: there is no `unreachable` on any of them.

const std = @import("std");
const postcard = @import("../wire/postcard.zig");
const range_spec = @import("range_spec.zig");

/// The ALPN this protocol is spoken on.
///
/// Upstream's `ALPN` at `src/protocol.rs:406`, `b"/iroh-bytes/4"`, at the
/// commit named in the module comment. `/4` is the protocol version and
/// changes with a wire change, which is why it is a value here rather than a
/// name someone has to remember.
pub const alpn = "/iroh-bytes/4";

/// The BLAKE3 chunk size in bytes: the unit every range in this protocol is
/// counted in. See the module comment for where the number comes from.
pub const chunk_size: u64 = 1024;

/// The bao tree's block size in bytes: the unit an answer is actually sent in,
/// sixteen chunks to a block. See the module comment.
pub const block_size: u64 = 16384;

/// Chunks to a block, derived so it cannot drift from the two constants above.
pub const chunks_per_block: u64 = @divExact(block_size, chunk_size);

/// The most bytes a request body may occupy.
///
/// Upstream's `MAX_MESSAGE_SIZE` at `src/protocol.rs:396`, and its comment
/// says "100MiB" for a value that is one MiB. The value is what a peer
/// enforces, so this is the value; the comment is upstream's error and is noted
/// rather than followed.
pub const max_message_size: usize = 1024 * 1024;

/// The BLAKE3 hash a request names.
///
/// `ticket/blob_ticket.zig` calls this same `[32]u8` its `Hash`, and both
/// modules put the same 32 bytes on the wire; it is one type under two names,
/// not two types. This is a private alias so the name does not become a third.
const Hash = [32]u8;

const hash_length = @sizeOf(Hash);

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

/// The ten discriminants a request stream can start with.
///
/// Upstream's `RequestType` at `src/protocol.rs:435`, whose doc says it "must
/// contain the request types in the same order as the full requests". Six arms
/// are reserved and carry nothing: they hold the positions of the four real
/// ones so that a later request type can be added without moving them, and
/// upstream's reader rejects every one rather than skipping it.
///
/// The type is a byte and not a `varint(u32)`, because that is how upstream
/// reads it — one raw `u8`, handed to postcard on its own
/// (`Request::read_async`, `src/protocol.rs:449`). Every discriminant here is
/// below 128, so the two spellings are the same bytes for every arm that
/// exists, which is also what upstream's own `request_type_size` test pins:
/// `RequestType::POSTCARD_MAX_SIZE == 1`. A byte with the top bit set is
/// therefore a discriminant this build does not have, and not a truncated
/// varint.
pub const RequestType = enum(u8) {
    /// `GetRequest`: one blob, or a collection and its children.
    get = 0,
    /// `ObserveRequest`: watch one blob's availability.
    observe = 1,
    /// Reserved, and refused.
    slot2 = 2,
    /// Reserved, and refused.
    slot3 = 3,
    /// Reserved, and refused.
    slot4 = 4,
    /// Reserved, and refused.
    slot5 = 5,
    /// Reserved, and refused.
    slot6 = 6,
    /// Reserved, and refused.
    slot7 = 7,
    /// `PushRequest`: send the provider data.
    push = 8,
    /// `GetManyRequest`: several unrelated blobs, one request.
    get_many = 9,
};

comptime {
    for (std.enums.values(RequestType)) |arm| {
        if (@intFromEnum(arm) > std.math.maxInt(u7)) {
            @compileError("a request discriminant has to be one byte on the wire");
        }
    }
}

/// The reasons a stream is closed or stopped, as one namespace of error codes.
///
/// Upstream's `Closed` at `src/protocol.rs:667`, `#[repr(u16)]`, and the reason
/// strings are its own at `src/protocol.rs:690`. These are QUIC codes, sent
/// next to the stream and never inside it — which is the whole reason a
/// provider that cannot answer a `get` has nothing to put in the payload. All
/// three are below 64, and a QUIC varint of that size is a single byte holding
/// the value (`toVarInt`).
pub const Closed = enum(u16) {
    /// The receive stream was dropped. Upstream keeps this as documentation of
    /// what happened to `0` and says it is not used explicitly.
    stream_dropped = 0,
    /// The provider is terminating, and every stream with it.
    provider_terminating = 1,
    /// The provider has the request. Only one request is allowed per stream, so
    /// more data after it is what this code is for.
    request_received = 2,

    /// The close reason as bytes, which upstream requires to be valid UTF-8.
    pub fn reason(self: Closed) []const u8 {
        return switch (self) {
            .stream_dropped => "stream dropped",
            .provider_terminating => "provider terminating",
            .request_received => "request received",
        };
    }

    /// The QUIC varint a STOP_STREAM carries for this reason.
    ///
    /// Upstream's `impl From<Closed> for VarInt` is `VarInt::from(self as
    /// u16)`, and every arm is below 64, so each is one byte. The
    /// compression is a QUIC varint's length prefix in its first two bits
    /// (`RFC 9000` section 16), where `00` means one byte and the low six bits
    /// are the value — which is why the value comes back unchanged.
    pub fn toVarInt(self: Closed) u64 {
        return @intFromEnum(self);
    }

    /// The reason a code names, or `error.UnknownClose` for a code this build
    /// has no arm for. A decoder that invented a default arm would report a
    /// close nobody sent.
    pub fn fromVarInt(code: u64) Error!Closed {
        if (code > std.math.maxInt(u16)) return error.UnknownClose;
        return std.enums.fromInt(Closed, @as(u16, @intCast(code))) orelse error.UnknownClose;
    }
};

/// A byte range, half-open, in the unit the protocol does not use on the wire.
///
/// `end` is the first byte *past* the range, so `end <= start` is an empty or
/// inverted range and `len` is not derivable from these fields without that
/// case being handled. `bytesToChunks` is the conversion that keeps the two
/// cases apart.
pub const ByteRange = struct {
    /// The first byte of the range.
    start: u64,
    /// One past the last byte. Nothing keeps it above `start`: a value built
    /// by the caller may be empty or inverted, and `chunksToBytes` saturates
    /// rather than wrapping.
    end: u64,
};

/// A chunk range, half-open. This *is* the wire unit: see the module comment.
pub const ChunkRange = struct {
    /// The first chunk of the range.
    start: u64,
    /// One past the last chunk. A `ChunkRange` off a peer's wire can be
    /// `u64.max`, and `start > end` is possible in a hand-built value, which
    /// is why `len` saturates rather than the type promising an order.
    end: u64,

    /// Chunks this range covers, zero when it is empty or inverted.
    pub fn len(self: ChunkRange) u64 {
        return self.end -| self.start;
    }
};

/// The chunk that contains byte `offset`: `offset / 1024`, rounded down.
///
/// This is upstream's `ChunkNum::full_chunks` (`src/tree.rs:209`), and it is
/// the start half of a byte-to-chunk rounding. The rounding is not symmetric
/// and must not be: a request for byte 1 is a request for the chunk byte 1 is
/// inside, not for the chunk after it. `byte 0` and `byte 1023` are both chunk
/// 0, and only the far end of the same request rounds up.
pub fn chunkOfByte(offset: u64) u64 {
    return @divFloor(offset, chunk_size);
}

/// The first chunk at or past byte `end`: `end / 1024`, rounded up.
///
/// Upstream's `ChunkNum::chunks` (`src/tree.rs:199`), whose doc gives the two
/// cases this has to keep apart: "1024 bytes is 1 chunk, 1025 bytes is 2
/// chunks". The partial chunk is added as one rather than computed as
/// `ceil((end + 1023) / 1024)`, which would overflow at `u64.max` — and an end
/// of `u64.max` is a legal byte offset off a peer's wire.
pub fn chunkAfterByte(end: u64) u64 {
    const whole = @divFloor(end, chunk_size);
    return whole + @intFromBool(end % chunk_size != 0);
}

/// The chunk range that covers `range`, rounded outward at both ends.
///
/// `bao_tree::io::round_up_to_chunks` (`src/io/mod.rs:135`) with upstream's
/// `ChunkRanges::bytes` (`src/protocol.rs:745`), which is the only direction a
/// byte range reaches a request through. Two roundings, in opposite
/// directions: the start goes *down* to the chunk that contains the first byte
/// and the end goes *up* to the first chunk past the last one.
///
/// A byte range whose end is not past its start covers no byte and so covers
/// no chunk: it returns the empty range at the chunk holding `start`, and
/// never the one-chunk range the outward rounding would otherwise name. That
/// is what keeps `start <= end` on every result, so `ChunkRange.len` reads the
/// count off a range a peer can be sent without the answer covering data the
/// request never asked for.
pub fn bytesToChunks(range: ByteRange) ChunkRange {
    const start = chunkOfByte(range.start);
    if (range.end <= range.start) return .{ .start = start, .end = start };
    return .{ .start = start, .end = chunkAfterByte(range.end) };
}

/// The bytes a chunk range covers.
///
/// The other direction, and the only one with an exact answer. A blob whose
/// length is not a multiple of 1024 has a last chunk that is short, so the byte
/// count for a range ending at that chunk is the first byte *past* it rather
/// than its end; `fullChunks` of the blob's size is what recovers the real
/// length. The multiply saturates because a chunk number off a peer's wire can
/// be `u64.max`, where upstream's `self.0 << 10` would not be a value at all.
pub fn chunksToBytes(range: ChunkRange) ByteRange {
    return .{
        .start = range.start *| chunk_size,
        .end = range.end *| chunk_size,
    };
}

/// A set of chunk ranges, as the boundary list `range_collections` stores.
///
/// The wire form is a count and then that many `u64` boundaries: the
/// `Serialize` impl at `range_collections` 0.4.6 `src/range_set.rs:975` is a
/// `serialize_seq` of the boundaries, and with postcard that is a length and
/// the values. A boundary at an even position *starts* a range and one at an
/// odd position *ends* it, because "Start boundaries are always inclusive,
/// end boundaries are exclusive" is the type's own rule (`src/range_set.rs:124`).
/// So the empty set has no boundaries, the set of every chunk is the single
/// boundary zero (`RangeSet::all`, `src/range_set.rs:641`), and a set is
/// `is_all` exactly when it is `[0]` (`src/range_set.rs:343`).
///
/// This is **not** `RangeSpec`, and the two are one byte apart on a wire.
///
///     ChunkRangeSet{ .boundaries = &.{ 1, 2 } }  //  "020102": chunks 1 and 2
///     RangeSpec{ .widths = &.{ 1, 2 } }           //  "020102": 1 gap, 2 from there
///
/// Both spellings are a count and that many `varint(u64)`s, they are both
/// drawn from the same pool of small numbers, and they mean opposite things:
/// a boundary list starts *inside*, a width list starts with a gap. A
/// decoder that read one as the other would request the wrong bytes and
/// would not be able to tell from the result, which is why they are separate
/// types with separate `parse`s rather than one range type with a flag.
///
/// What is not here is the algebra. `RangeSpec`'s module comment declines
/// `RangeSet2`'s union, intersection and negation for the same reason this
/// does: a request is only ever *read* against a blob, and building a set from
/// arbitrary unions is a port of another crate. A peer sends a set already
/// unioned, so a decode that normalises is the whole of what is needed.
pub const ChunkRangeSet = struct {
    /// Boundaries, borrowed. See the type comment for the parity rule.
    boundaries: []const u64,

    /// The set of no chunks at all.
    pub const empty: ChunkRangeSet = .{ .boundaries = &.{} };

    /// Every chunk, whatever the blob's size. The single boundary zero.
    pub const all: ChunkRangeSet = .{ .boundaries = &.{0} };

    /// The last chunk of any blob, and nothing before it. Upstream's
    /// `ChunkRanges::last_chunk`, which is `from_range_from(u64::MAX)`: the
    /// start rounds down to zero, so the boundaries are `[0, u64.max]` and the
    /// range runs to the end of whatever blob is read against.
    pub const last_chunk: ChunkRangeSet = .{ .boundaries = &.{ 0, std.math.maxInt(u64) } };

    /// The set naming no chunks at all, which is an empty boundary list.
    pub fn isEmpty(self: ChunkRangeSet) bool {
        return self.boundaries.len == 0;
    }

    /// The single-boundary-zero test, which is how `range_collections` decides
    /// a set is everything (`src/range_set.rs:343`).
    pub fn isAll(self: ChunkRangeSet) bool {
        return self.boundaries.len == 1 and self.boundaries[0] == 0;
    }

    /// Equality of the boundary lists. Two sets a peer spelled differently
    /// compare equal when they name the same ranges, because a decode sorts
    /// and deduplicates before this sees them.
    pub fn eql(a: ChunkRangeSet, b: ChunkRangeSet) bool {
        return std.mem.eql(u64, a.boundaries, b.boundaries);
    }

    /// The wire form: a length, then each boundary as `varint(u64)`.
    pub fn write(self: ChunkRangeSet, writer: *postcard.Writer) postcard.Error!void {
        try writer.writeLen(self.boundaries.len);
        for (self.boundaries) |boundary| try writer.writeU64(boundary);
    }

    /// Read the wire form into `boundaries`, which the result then borrows.
    ///
    /// A boundary list that is unsorted or repeats is a *value*, not an error:
    /// upstream's `RangeSetVisitor` (`src/range_set.rs:1000`) reads whatever
    /// the frame names, `sort()`s it and `dedup()`s it, and checks nothing
    /// else — not the parity, not the order. Normalising here is what keeps
    /// this total over arbitrary bytes, and it is also what makes the boundary
    /// parity of the result mean anything.
    ///
    /// On error the reader may have advanced and a prefix of `boundaries` may
    /// already hold the boundaries read so far — in wire order, unsorted and
    /// undeduplicated, because the two steps below run only on success — while
    /// the rest of the slice keeps what the caller had. `error.BufferFull` is
    /// the one failure that writes nothing: the declared count is checked
    /// against `boundaries.len` before the first boundary is read.
    pub fn parse(
        reader: *postcard.Reader,
        boundaries: []u64,
    ) postcard.Error!ChunkRangeSet {
        const count = try reader.readLen();
        if (count > boundaries.len) return error.BufferFull;
        const filled = boundaries[0..count];
        for (filled) |*boundary| boundary.* = try reader.readU64();
        std.sort.heap(u64, filled, {}, ascending);
        return .{ .boundaries = dedup(filled) };
    }
};

fn ascending(_: void, lhs: u64, rhs: u64) bool {
    return lhs < rhs;
}

/// The sorted, duplicate-free form of `sorted`, in place and in the same
/// storage. A duplicate boundary is a range that starts and ends in the same
/// place, and `range_collections` drops it at decode, so dropping it here is
/// what the frame means.
fn dedup(sorted: []u64) []u64 {
    var kept: usize = 0;
    // The write index never passes the read index, so the walk is over `sorted`
    // as it was when it started.
    for (sorted) |value| {
        if (kept == 0 or sorted[kept - 1] != value) {
            sorted[kept] = value;
            kept += 1;
        }
    }
    return sorted[0..kept];
}

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

/// A sequence for a request that asks for part of a blob: two chunks of gap and
/// four selected from there, and nothing after it. It is here so that a
/// `push` frame in the tests is not just a whole-blob request wearing a
/// different framing — a push carries any sequence a `get` can.
const push_ranges = [_]range_spec.Item{
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

/// A request whose bytes run to the end of the stream: `Get`, `GetMany` or
/// `Observe`.
///
/// Upstream reads all three with `read_to_end_as`
/// (`src/util/stream.rs:370`): it reads the stream to its end, asserts the
/// end, and decodes what it read. So the request is the whole stream and a
/// byte after it is a stream that carried something else — which is why this is
/// a separate type from `PushFraming` and not a flag on one request: the two
/// have different rules, and a value of one is not a value of the other.
pub const EofRequest = union(enum) {
    /// One blob, or a collection and its children. Its `ranges` borrow
    /// `storage.items` and `storage.widths` after a decode.
    get: GetRequest,
    /// Several unrelated blobs. Its `hashes` borrow `storage.hashes` after a
    /// decode.
    get_many: GetManyRequest,
    /// One blob's availability, whose `ranges` borrow `storage.widths`.
    observe: ObserveRequest,

    /// The discriminant this request is written under.
    pub fn discriminant(self: EofRequest) RequestType {
        return switch (self) {
            .get => .get,
            .get_many => .get_many,
            .observe => .observe,
        };
    }

    /// The same request, and only between arms that carry the same one: a `get`
    /// is never equal to an `observe`.
    pub fn eql(a: EofRequest, b: EofRequest) bool {
        return switch (a) {
            .get => |left| switch (b) {
                .get => |right| left.eql(right),
                .get_many, .observe => false,
            },
            .get_many => |left| switch (b) {
                .get_many => |right| left.eql(right),
                .get, .observe => false,
            },
            .observe => |left| switch (b) {
                .observe => |right| left.eql(right),
                .get, .get_many => false,
            },
        };
    }
};

/// A `Push` request, and the offset its payload starts at.
///
/// The payload is the bao data the getter is sending to the provider, on the
/// same stream, immediately after the request. `payload_offset` is where it
/// starts, and it is the reason the request carries a length at all: without
/// one, the payload would be indistinguishable from more of the request, and
/// a decoder reading the body to the end of the stream would swallow it.
pub const PushFraming = struct {
    /// The request.
    request: PushRequest,
    /// The first byte of the payload: the reader's offset after the request.
    ///
    /// Zero on a value built rather than read, and that is the only difference
    /// from one that was: `write` does not look at it, and the decode that
    /// produces a value sets it. See `eql` for why it is not compared.
    payload_offset: usize = 0,

    /// The bao data on the rest of the stream.
    ///
    /// This is the only framing in the protocol that leaves bytes after the
    /// request, so it is the only one where a caller has to be told where they
    /// start. A truncated stream is a short slice here and an error only in
    /// the request itself: see the module comment on missing data.
    pub fn payload(self: PushFraming, reader: *postcard.Reader) []const u8 {
        return reader.buffer[self.payload_offset..];
    }

    /// Whether two framings carry the same request.
    ///
    /// `payload_offset` is not compared: it is where a request happened to be
    /// *read*, and two reads of the same request from two different buffers are
    /// the same request. The offset is a fact about a decode, and the frame
    /// test above is what pins it.
    pub fn eql(a: PushFraming, b: PushFraming) bool {
        return a.request.eql(b.request);
    }
};

/// A request, and the framing it arrived in.
pub const Request = union(enum) {
    /// The request ran to the end of the stream.
    to_eof: EofRequest,
    /// The request was length-prefixed and the payload follows it.
    length_prefixed: PushFraming,

    /// The discriminant this request is written under.
    pub fn discriminant(self: Request) RequestType {
        return switch (self) {
            .to_eof => |request| request.discriminant(),
            .length_prefixed => .push,
        };
    }

    /// The bao data that follows this request on the same stream, or the empty
    /// slice for a request that has none.
    ///
    /// Empty for `to_eof` on purpose, and not as an oversight: those requests
    /// consumed the whole stream, so there is nothing after them by
    /// definition. A `push` payload starts at `payload_offset`.
    pub fn payload(self: Request, reader: *postcard.Reader) []const u8 {
        return switch (self) {
            .to_eof => "",
            .length_prefixed => |framed| framed.payload(reader),
        };
    }

    /// The same request in the same framing. A request read in one framing is
    /// never equal to one read in the other, whatever its body says.
    pub fn eql(a: Request, b: Request) bool {
        return switch (a) {
            .to_eof => |left| switch (b) {
                .to_eof => |right| left.eql(right),
                .length_prefixed => false,
            },
            .length_prefixed => |left| switch (b) {
                .to_eof => false,
                .length_prefixed => |right| left.eql(right),
            },
        };
    }

    /// Read the one discriminant byte and hand the request to the framing that
    /// carries its type.
    pub fn read(reader: *postcard.Reader, storage: *Storage) Error!Request {
        const tag = try readRequestType(reader);
        if (tag == .push) {
            return .{ .length_prefixed = try LengthPrefixedFraming.read(tag, reader, storage) };
        }
        return .{ .to_eof = try EofFraming.read(tag, reader, storage) };
    }

    /// Write the discriminant byte, then the body, in this request's framing.
    ///
    /// The discriminant comes first for every arm, and only then the length —
    /// which is the order `Request::read_async` reads them in
    /// (`src/protocol.rs:449`): the request type is a byte of its own, and a
    /// `push` body is length-prefixed *after* it.
    ///
    /// `body` is scratch for the `push` case and is untouched for the other
    /// three. It is the caller's because nothing here allocates, and a `varint`
    /// length cannot be backpatched once its width is known: the length is the
    /// body's length, so the body is built first and copied out. Upstream does
    /// the same with a `Vec` inside `write_length_prefixed`
    /// (`src/util/stream.rs:458`), reserving `size + 9` for the same reason.
    pub fn write(self: Request, writer: *postcard.Writer, body: []u8) Error!void {
        switch (self) {
            .to_eof => |request| {
                try writeRequestType(writer, request.discriminant());
                switch (request) {
                    .get => |value| try value.write(writer),
                    .get_many => |value| try value.write(writer),
                    .observe => |value| try value.write(writer),
                }
            },
            .length_prefixed => |framed| {
                try writeRequestType(writer, .push);
                var inner = postcard.Writer.init(body);
                try framed.request.write(&inner);
                const framed_bytes = inner.finish();
                try writer.writeU64(@intCast(framed_bytes.len));
                try appendBytes(writer, framed_bytes);
            },
        }
    }
};

/// Reading a request whose bytes run to the end of the stream.
///
/// A separate type from `LengthPrefixedFraming` on purpose. Upstream's two
/// readers are two functions with two different rules, and the difference is
/// what the two request families are: a `get` is the whole stream, a `push` is
/// a prefix of it. Making them one function with a flag would put the two rules
/// in one place and a decoder would pick between them by reading a byte off a
/// peer's wire.
pub const EofFraming = struct {
    /// Read the body of `tag`, which has to be a type this framing carries.
    ///
    /// The body runs to the end of `reader`, so the reader has to end at the
    /// end of it: a byte after a `get` is a stream that carried something else,
    /// and `postcard` 1.1.3's `from_bytes` (`source/postcard/src/de/mod.rs:12`)
    /// does not finalize its deserializer, so it would ignore that byte. ozai
    /// does not: `finish` is what makes a request and a request-plus-trailing-
    /// junk different frames rather than one frame read two ways.
    pub fn read(
        tag: RequestType,
        reader: *postcard.Reader,
        storage: *Storage,
    ) Error!EofRequest {
        if (reader.remaining() > max_message_size) return error.MessageTooLarge;
        const request: EofRequest = switch (tag) {
            .get => .{ .get = try GetRequest.parse(reader, storage) },
            .get_many => .{ .get_many = try GetManyRequest.parse(reader, storage) },
            .observe => .{ .observe = try ObserveRequest.parse(reader, storage) },
            // A `push` is not carried to the end of the stream: its payload is
            // there. Reading it this way would swallow the payload.
            .push => return error.WrongFraming,
            .slot2, .slot3, .slot4, .slot5, .slot6, .slot7 => return error.ReservedSlot,
        };
        try reader.finish();
        return request;
    }
};

/// Reading a request that is varint-length-prefixed, with a payload after it.
///
/// Upstream's `read_length_prefixed` at `src/util/stream.rs:381`, behind the
/// `Request::read_async` arm for `RequestType::Push` at
/// `src/protocol.rs:479`.
pub const LengthPrefixedFraming = struct {
    /// Read the body of `tag`, which has to be `push`.
    ///
    /// The reader is left on the first byte after the body, which is where
    /// the payload starts, and that offset is returned rather than recomputed
    /// by the caller: it is the one thing a caller cannot work out from the
    /// request alone.
    pub fn read(
        tag: RequestType,
        reader: *postcard.Reader,
        storage: *Storage,
    ) Error!PushFraming {
        if (tag != .push) return error.WrongFraming;
        var body = try readLengthPrefaced(reader);
        const request = try PushRequest.parse(&body, storage);
        try body.finish();
        return .{ .request = request, .payload_offset = reader.offset };
    }
};

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

/// A reader over exactly the `varint(u64)` bytes `reader` names next, with
/// `reader` left on the first byte after them.
///
/// This is the rule `read_length_prefixed` reads
/// (`src/util/stream.rs:381`) and `write_length_prefixed` writes
/// (`src/util/stream.rs:458`): a length, a cap at `max_message_size`, and a
/// body of exactly that many bytes. The cap is upstream's `max_size`
/// argument, and upstream's is the value in `MAX_MESSAGE_SIZE` rather than
/// the 100MiB its comment claims.
///
/// The length is read with postcard's `varint(u64)` and not with upstream's
/// hand-rolled `read_varint_u64` (`src/util/stream.rs:409`), which is looser
/// in two ways: it accepts a final byte carrying more value bits than a `u64`
/// has, where it silently shifts them out, and it never rejects an
/// over-long encoding. Upstream writes the canonical spelling, so every frame
/// it produces reads the same either way; ozai reads the canonical one and
/// names the other two, which is what `bad varint` and `value out of range`
/// are for.
fn readLengthPrefaced(reader: *postcard.Reader) Error!postcard.Reader {
    const length = try reader.readU64();
    if (length > @as(u64, max_message_size)) return error.MessageTooLarge;
    const narrow = std.math.cast(usize, length) orelse return error.MessageTooLarge;
    return postcard.Reader.init(try take(reader, narrow));
}

/// The one byte a request stream starts with.
///
/// Upstream reads it as a raw `u8` and hands that single byte to postcard on
/// its own (`src/protocol.rs:449`), so a discriminant is a byte and not a
/// `varint(u32)`. See `RequestType` for why the two spellings are the same
/// bytes for every arm that exists.
fn readRequestType(reader: *postcard.Reader) Error!RequestType {
    const raw = try reader.readU8();
    return std.enums.fromInt(RequestType, raw) orelse error.UnknownVariant;
}

fn writeRequestType(writer: *postcard.Writer, tag: RequestType) Error!void {
    // postcard writes an enum discriminant as `varint(u32)`, and every arm is
    // below 128, so the canonical spelling of each is the single raw byte that
    // upstream reads. The `comptime` block above `RequestType` is what keeps
    // that true if an arm is ever added.
    try writer.writeU8(@intFromEnum(tag));
}

/// `count` bytes of `reader`, and `reader` past them.
///
/// `postcard.Reader` keeps its buffer and offset public and has no method that
/// takes a bare count — every public one reads a *prefixed* value, and the
/// whole of a length prefix is that the value is not raw — so this is the one
/// place that reaches for the fields.
fn take(reader: *postcard.Reader, count: usize) Error![]const u8 {
    if (reader.remaining() < count) return error.UnexpectedEnd;
    const start = reader.offset;
    reader.offset += count;
    return reader.buffer[start..reader.offset];
}

/// What `reader` has not read yet.
fn rest(reader: *postcard.Reader) []const u8 {
    return reader.buffer[reader.offset..];
}

/// Raw bytes into a postcard writer, with no length in front.
///
/// The mirror of `take`, and for the same reason: `postcard.Writer` writes
/// prefixed values from its public surface, and a length prefix in front of
/// these bytes is exactly what is wanted — so writing one would be wrong.
fn appendBytes(writer: *postcard.Writer, bytes: []const u8) Error!void {
    const room = writer.buffer[writer.length..];
    if (room.len < bytes.len) return error.BufferFull;
    @memcpy(room[0..bytes.len], bytes);
    writer.length += bytes.len;
}

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
        try testing.expectEqual(@as(u64, 0), chunksToBytes(chunks).end -| chunksToBytes(chunks).start);
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
