//! The two ways a request can be framed on a stream, the discriminant that
//! decides which, and the readers that make the two rules impossible to
//! confuse.
//!
//! One of the four modules `protocol.zig` is split into. Upstream reads `Get`,
//! `GetMany` and `Observe` with `read_to_end_as`
//! (`src/util/stream.rs:370`): the request *is* the rest of the stream. It reads
//! `Push` with `read_length_prefixed` (`src/util/stream.rs:381`): a
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
//! The request *bodies* are `request.zig`'s, and the chunk arithmetic they are
//! read against is `chunk.zig`'s. What is here is the stream: the discriminant
//! namespace, the two request unions, the readers and the writers, the length
//! prefix both a `push` body and an `ObserveItem` are written with, and the
//! `Closed` codes sent *beside* a stream rather than inside it.

const std = @import("std");
const postcard = @import("../wire/postcard.zig");
const range_spec = @import("range_spec.zig");
/// The module's shared vocabulary and its shared test scaffolding.
const protocol = @import("protocol.zig");
/// Only the tests reach across: `Closed`'s two tests and the `BaoResponse`
/// block in the fixed-point test both assert that a stream code is beside the
/// stream rather than a byte in it, and that is a claim about the payload.
const response = @import("response.zig");

/// The protocol's error set, the caller-owned scratch a decode fills and the
/// message cap a framed body is checked against. All three live in
/// `protocol.zig`, which every one of the four modules imports.
const Error = protocol.Error;
const Storage = protocol.Storage;
const max_message_size = protocol.max_message_size;

/// The four request bodies `EofFraming.read` and `LengthPrefixedFraming.read`
/// dispatch to. Aliased under a name that is not `request`, because the readers
/// and the frame tests both hold a local `request` of their own.
const request_bodies = @import("request.zig");
const GetRequest = request_bodies.GetRequest;
const GetManyRequest = request_bodies.GetManyRequest;
const ObserveRequest = request_bodies.ObserveRequest;
const PushRequest = request_bodies.PushRequest;

/// A sequence for a request that asks for part of a blob: two chunks of gap and
/// four selected from there, and nothing after it. It is here so that a `push`
/// frame in the tests is not just a whole-blob request wearing a different
/// framing — a push carries any sequence a `get` can, and the sequences
/// `request.zig` holds are the two its own constructors send.
const push_ranges = [_]range_spec.Item{
    .{ .delta = 0, .spec = .{ .widths = &.{ 2, 4 } } },
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
                .observe => |right| right.eql(left) and right.eql(left),
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
    /// the request itself: see the protocol module comment on missing data.
    pub fn payload(self: PushFraming, reader: *postcard.Reader) []const u8 {
        return reader.buffer[self.payload_offset..];
    }

    /// Whether two framings carry the same request.
    ///
    /// `payload_offset` is not compared: it is where a request happened to be
    /// *read*, and two reads of the same request from two different buffers are
    /// the same request. The offset is a fact about a decode, and the frame
    /// test in this file is what pins it.
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
                .length_prefixed => |right| right.eql(left),
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
///
/// It is `pub` because `ObserveResponse.next` is the other reader of the same
/// rule: an observe item is written with the same `write_length_prefixed` a
/// `push` body is, and a second implementation of the cap would be a second
/// place for it to be wrong.
pub fn readLengthPrefaced(reader: *postcard.Reader) Error!postcard.Reader {
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
const da_hash: [32]u8 = @splat(0xda);

const zero_hash: [32]u8 = @splat(0);

const two_hashes = [_][32]u8{ @splat(0), @splat(1) };

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
    // covers the hash and the sequence and neither the discriminant in front of
    // it nor the payload behind: a `PushRequest` is decoded from exactly those
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
            .ranges = .{ .items = GetRequest.blob(da_hash).ranges.items },
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
    for (requests) |request_value| try expectRequestFixedPoint(request_value);
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

    var room: protocol.Room = .{};
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
        var room: protocol.Room = .{};
        var storage = room.storage();
        try testing.expectError(error.BadLength, GetRequest.parse(&reader, &storage));
    }

    // And each framing refuses a type it does not carry, before it reads a
    // byte of the body.
    {
        const push_frame = "08" ++ "26" ++ "da" ** 32 ++ "020001000100";
        var reader = postcard.Reader.init(push_frame[1..]);
        var room: protocol.Room = .{};
        var storage = room.storage();
        try testing.expectError(
            error.WrongFraming,
            EofFraming.read(.push, &reader, &storage),
        );
    }
    {
        var reader = postcard.Reader.init(get_bytes[1..]);
        var room: protocol.Room = .{};
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
        var room: protocol.Room = .{};
        var storage = room.storage();
        try testing.expectError(
            error.ReservedSlot,
            EofFraming.read(tag, &reader, &storage),
        );
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
        decoded_ok += try expectTotalRequest(try protocol.parseHex(&scratch, hex));
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
        const seed = try protocol.parseHex(&scratch, hex);
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
        const seed = try protocol.parseHex(&scratch, hex);
        items += try response.expectTotalObserve(seed);
        for (0..20_000) |n| {
            const grown = @min(seed.len + n % 33, buffer.len);
            @memcpy(buffer[0..seed.len], seed);
            for (buffer[seed.len..grown], 0..) |*byte, i| byte.* = mix(n, i);
            items += try response.expectTotalObserve(buffer[0..grown]);
        }
    }
    try testing.expect(items > 0);
}

test "domain sweep: every request discriminant decides its own framing" {
    // The ten arms of `RequestType` are a closed domain with two destinations:
    // four carry a request and six are reserved, and each of the ten reaches
    // `Request.read` with a different answer. Swept over
    // `std.enums.values(RequestType)` rather than over the numbers written here,
    // so an arm added upstream has to be placed in one of the two groups before
    // this test can pass: the `switch` below names all ten, so a new one fails
    // to compile rather than falling through to a default.
    inline for (std.enums.values(RequestType)) |arm| {
        // A one-byte stream never carries a whole request, so the refusal is
        // always about the body — or, for a reserved slot, about the tag alone.
        // The two groups are named rather than inferred from a range, so a
        // reserved slot cannot pass by accident: upstream rejects every one of
        // them by name, and a decoder that skipped one would answer a question
        // the peer never asked.
        const expected: Error = switch (arm) {
            .get, .observe, .push, .get_many => error.UnexpectedEnd,
            .slot2, .slot3, .slot4, .slot5, .slot6, .slot7 => error.ReservedSlot,
        };

        var buffer: [1]u8 = .{@intFromEnum(arm)};
        var reader = postcard.Reader.init(&buffer);
        var room: protocol.Room = .{};
        var storage = room.storage();
        try testing.expectError(expected, Request.read(&reader, &storage));

        // And the reader is left on the discriminant and nowhere past it, so a
        // refusal to serve a reserved slot never consumed the bytes behind it.
        try testing.expectEqual(@as(usize, 1), reader.offset);
    }

    // And the ten arms are exactly the ten numbers, in the order upstream
    // demands: "it must contain the request types in the same order as the full
    // requests" (`src/protocol.rs:435`).
    try testing.expectEqual(@as(usize, 10), std.enums.values(RequestType).len);
    const by_value = [_]RequestType{
        .get,   .observe, .slot2, .slot3, .slot4,
        .slot5, .slot6,   .slot7, .push,  .get_many,
    };
    for (by_value, 0..) |arm, index| {
        try testing.expectEqual(arm, @as(RequestType, @enumFromInt(@as(u8, @intCast(index)))));
    }
    // Every discriminant is below 128, so the raw byte upstream reads and
    // postcard's `varint(u32)` for a discriminant are the same bytes — which is
    // what lets the reader be a byte at all. A byte with the top bit set is
    // therefore a discriminant this build does not have and not a truncated
    // varint, and `readRequestType` answers `error.UnknownVariant` for it.
    inline for (std.enums.values(RequestType)) |arm| {
        try testing.expect(@intFromEnum(arm) < 0x80);
        var high: [1]u8 = .{@intFromEnum(arm) | 0x80};
        var high_reader = postcard.Reader.init(&high);
        var high_room: protocol.Room = .{};
        var high_storage = high_room.storage();
        try testing.expectError(
            error.UnknownVariant,
            Request.read(&high_reader, &high_storage),
        );
    }
}

test "domain sweep: the two framings carry exactly the request types they own" {
    // `EofFraming` carries three arms and `LengthPrefixedFraming` one, and the
    // two sets are disjoint. Asked of every arm of both, because a framing that
    // carried a type it does not own is how a `push` payload gets swallowed
    // into a request body.
    inline for (std.enums.values(RequestType)) |arm| {
        var room: protocol.Room = .{};
        var storage = room.storage();

        // A `push` is the only length-prefixed one, so it is the only arm the
        // EOF framing refuses with `WrongFraming`.
        const eof_expected: Error = if (arm == .push)
            error.WrongFraming
        else if (@intFromEnum(arm) >= 2 and @intFromEnum(arm) <= 7)
            error.ReservedSlot
        else
            // The three real EOF arms on an empty body, which is `UnexpectedEnd`
            // from the body and never from the discriminant.
            error.UnexpectedEnd;
        var eof_reader = postcard.Reader.init("");
        try testing.expectError(
            eof_expected,
            EofFraming.read(arm, &eof_reader, &storage),
        );

        // And everything but `push` is refused by the length-prefixed framing,
        // on the tag alone, before a byte of body is read.
        const framed_expected: Error = if (arm == .push)
            error.UnexpectedEnd // no length prefix at all
        else
            error.WrongFraming;
        var framed_reader = postcard.Reader.init("");
        try testing.expectError(
            framed_expected,
            LengthPrefixedFraming.read(arm, &framed_reader, &storage),
        );
    }
}

test "domain sweep: Closed is three codes, and a fourth is refused" {
    // `Closed` has three arms and upstream's `Closed` (`src/protocol.rs:667`)
    // has three, so the enum is the whole of the namespace rather than a
    // sample of it. `std.enums.values` is the table, which means a fourth arm
    // would have to be placed here rather than inherit an answer from a default.
    inline for (std.enums.values(Closed)) |arm| {
        // Each code is a QUIC varint beside the stream and never a byte in it,
        // so it round-trips through its own varint spelling.
        const code = arm.toVarInt();
        try testing.expectEqual(arm, try Closed.fromVarInt(code));
        // All three are below 64, and a QUIC varint that small is one raw byte
        // holding the value — which is why upstream's `toVarInt` is a cast and
        // not a length calculation.
        try testing.expect(code < 64);
        // And a reason, which is what a caller logs. Every arm names a
        // different one, so a reason cannot be mistaken for another's.
        try testing.expect(arm.reason().len > 0);
    }
    // The three reasons are distinct, checked as values rather than as
    // counts: a copy-paste that gave two codes one reason would pass a count.
    const reasons = [_][]const u8{
        Closed.stream_dropped.reason(),
        Closed.provider_terminating.reason(),
        Closed.request_received.reason(),
    };
    for (reasons, 0..) |reason, index| {
        for (reasons[index + 1 ..]) |other| {
            try testing.expect(!std.mem.eql(u8, reason, other));
        }
    }

    // A code this build has no arm for is named rather than defaulted, because
    // a default arm would report a close nobody sent. Three is the first gap,
    // and past `u16` is the other end of the same rule.
    for ([_]u64{ 3, 4, 255, 65_535, 65_536, std.math.maxInt(u64) }) |code| {
        try testing.expectError(error.UnknownClose, Closed.fromVarInt(code));
    }
    // And the code is never in the payload: a response is whatever the provider
    // wrote, so a stream code is not a byte of one.
    {
        const code_bytes = [_]u8{@intCast(Closed.request_received.toVarInt())};
        var reader = postcard.Reader.init(&code_bytes);
        const answer = response.BaoResponse.read(&reader);
        try testing.expectEqualSlices(u8, &code_bytes, answer.bytes);
        // That byte is a length prefix of one with nothing behind it, so a
        // provider that wrote it as a payload did not write a complete answer.
        try testing.expect(!answer.isEof());
    }
}

test "error inventory: every declared arm is refused by a concrete frame" {
    // `Error` is `postcard.Error` plus four arms of this module's own. The
    // postcard members are reached through the same request paths, so this
    // names all of them together rather than assuming another module's sweep
    // covers the ones a blobs frame can reach.
    //
    // The count is checked against the type rather than trusted, so an arm added
    // to `Error` without a case here fails the build rather than going quietly
    // untested.
    try testing.expectEqual(@typeInfo(Error).error_set.?.len, 14);

    var scratch: [256]u8 = undefined;

    // The module's own four. `ReservedSlot` and `MessageTooLarge` come through
    // `Request.read`; `WrongFraming` cannot, because `Request.read` picks the
    // framing from the tag and so never hands a request to the wrong one — it is
    // reachable only by a caller reaching for the wrong framing directly, which
    // is exactly what the two cases below are.
    try expectRequestErrorHex("02", error.ReservedSlot);
    try expectRequestErrorHex("08" ++ "ffffffff01", error.MessageTooLarge);
    {
        var reader = postcard.Reader.init("");
        var room: protocol.Room = .{};
        var storage = room.storage();
        try testing.expectError(
            error.WrongFraming,
            EofFraming.read(.push, &reader, &storage),
        );
    }
    {
        var reader = postcard.Reader.init("");
        var room: protocol.Room = .{};
        var storage = room.storage();
        try testing.expectError(
            error.WrongFraming,
            LengthPrefixedFraming.read(.get, &reader, &storage),
        );
    }
    try testing.expectError(error.UnknownClose, Closed.fromVarInt(3));

    // The postcard members a request can reach: a discriminant this build has
    // no arm for, a truncated frame, a varint too long and one too wide, a
    // length that cannot be true, bytes behind a whole message, and a count
    // the caller's storage could not hold.
    try expectRequestErrorHex("0a", error.UnknownVariant);
    try expectRequestErrorHex("00" ++ "da" ** 8, error.UnexpectedEnd);
    try expectRequestErrorHex(
        "00" ++ "da" ** 32 ++ "01" ++ "00" ++ "80" ** 10,
        error.BadVarint,
    );
    try expectRequestErrorHex(
        "00" ++ "da" ** 32 ++ "01" ++ "00" ++ "80" ** 9 ++ "02",
        error.ValueOutOfRange,
    );
    // A `get_many` naming five hashes behind four the caller's storage holds,
    // and a count the bytes could have carried: the buffer is big enough and
    // the storage is not, which is `BufferFull` and not `BadLength`.
    try expectRequestErrorHex("09" ++ "05" ++ "da" ** 32 ++ "0000", error.BufferFull);
    try expectRequestErrorHex(
        "00" ++ "da" ** 32 ++ "01000100" ++ "00",
        error.TrailingBytes,
    );
    // `BadLength` is a length the remaining input cannot satisfy, and a `push`
    // body read as a `get` body is the case that reaches it: the length byte
    // shifts the hash by one and the sequence's element count lands on a `0xda`.
    {
        const push_body = "26" ++ "da" ** 32 ++ "020001000100";
        var reader = postcard.Reader.init(try protocol.parseHex(&scratch, push_body));
        var room: protocol.Room = .{};
        var storage = room.storage();
        try testing.expectError(error.BadLength, GetRequest.parse(&reader, &storage));
    }

    // The three arms no blobs request can reach, and why each is here rather
    // than missing: `Error` is `postcard.Error` joined with this module's four,
    // so a caller matching on it sees all thirteen and two of the four real
    // requests it has never heard of. The join is deliberate — it lets a request
    // name "a varint that cannot fit" without a caller unwrapping a type that
    // does not depend on the frame it was in — and it means three arms are
    // unreachable from here.
    //
    // - `BadBool`: no request field is a `bool`. The request types are a hash
    //   (`[u8; 32]`), a count, a `RangeSpec`/`RangeSpecSeq` of `varint(u64)`
    //   widths and deltas, and a discriminant byte. Nothing calls `readBool`.
    // - `BadOptionTag`: no request field is an `Option`. Nothing calls
    //   `readOption`, and no request carries a presence flag.
    // - `InvalidUtf8`: no request field is a `String`. `GetRequest`'s only
    //   non-numeric field is the 32 raw hash bytes, which `readArray` copies
    //   without validating. Nothing calls `readStr`.
    //
    // Each is a precondition of the *format* rather than of this decoder: a
    // future request type with a string, a bool or an option in it would make
    // them reachable again, and the count above is what notices.
    //
    // The disposition is a claim about which reader this module calls, so what
    // is asserted here is the negative one that can be asserted without reading
    // the source: every request this module can express round-trips, so none of
    // the three ever fired on the path that would reach them.
    for ([_]Request{
        .{ .to_eof = .{ .get = GetRequest.blob(da_hash) } },
        .{ .to_eof = .{ .get_many = .{ .hashes = &two_hashes, .ranges = .empty } } },
        .{ .to_eof = .{ .observe = .{ .hash = da_hash, .ranges = .empty } } },
        .{ .length_prefixed = .{ .request = .{ .get = GetRequest.blob(da_hash) } } },
    }) |request_value| {
        var buffer: [256]u8 = undefined;
        var body: [2048]u8 = undefined;
        var writer = postcard.Writer.init(&buffer);
        try request_value.write(&writer, &body);
        var room: protocol.Room = .{};
        var storage = room.storage();
        var reader = postcard.Reader.init(writer.finish());
        const decoded = try Request.read(&reader, &storage);
        try reader.finish();
        try testing.expect(decoded.eql(request_value));
    }
}

test "accepted blobs re-encode the value and the framing that decoded them" {
    // A decode that succeeds has to be a fixed point of its own round trip, and
    // the framing is part of the value here rather than a detail of it: a
    // `push` and a `get` with the same body are different frames, and the
    // re-encode has to preserve which one it was. `BaoResponse` is the one half
    // that carries no error arm — missing data is the end of the stream, not a
    // value — so its re-encode is the bytes themselves.
    const requests = [_]Request{
        .{ .to_eof = .{ .get = GetRequest.blob(da_hash) } },
        .{ .to_eof = .{ .get = GetRequest.all(da_hash) } },
        .{ .to_eof = .{ .get = .{ .hash = zero_hash, .ranges = .empty } } },
        .{ .to_eof = .{ .get_many = .{
            .hashes = &two_hashes,
            .ranges = .{ .items = GetRequest.blob(da_hash).ranges.items },
        } } },
        .{ .to_eof = .{ .observe = .{
            .hash = da_hash,
            .ranges = range_spec.RangeSpec.all,
        } } },
        .{ .length_prefixed = .{ .request = .{ .get = GetRequest.blob(da_hash) } } },
        .{ .length_prefixed = .{ .request = PushRequest.new(
            da_hash,
            .{ .items = &push_ranges },
        ) } },
    };
    for (requests) |request_value| {
        try expectRequestFixedPoint(request_value);
    }

    // The framing is a function of the tag and not of the body, so the same
    // body under the other framing is a *different* frame rather than the same
    // frame read twice. `GetRequest.blob`'s bytes and `PushRequest`'s bytes
    // differ by the discriminant and the length prefix and nothing else.
    {
        var get_frame: [128]u8 = undefined;
        var push_frame: [128]u8 = undefined;
        var body: [2048]u8 = undefined;
        var get_writer = postcard.Writer.init(&get_frame);
        try (Request{ .to_eof = .{ .get = GetRequest.blob(da_hash) } }).write(&get_writer, &body);
        var push_writer = postcard.Writer.init(&push_frame);
        try (Request{ .length_prefixed = .{ .request = .{ .get = GetRequest.blob(da_hash) } } })
            .write(&push_writer, &body);

        // Same body, different discriminant and a length in front of it.
        const get_bytes = get_writer.finish();
        const push_bytes = push_writer.finish();
        try testing.expect(!std.mem.eql(u8, get_bytes, push_bytes));
        try testing.expectEqual(@as(u8, 0), get_bytes[0]);
        try testing.expectEqual(@as(u8, 8), push_bytes[0]);
        // The `push` body is the `get` body: the length covers the hash and the
        // sequence and neither the discriminant nor what follows.
        try testing.expectEqualSlices(u8, get_bytes[1..], push_bytes[2..]);

        // And the two decode to values that are not equal, because the framing
        // is part of what a `Request` is.
        var get_room: protocol.Room = .{};
        var get_storage = get_room.storage();
        var get_reader = postcard.Reader.init(get_bytes);
        const decoded_get = try Request.read(&get_reader, &get_storage);
        try get_reader.finish();

        var push_room: protocol.Room = .{};
        var push_storage = push_room.storage();
        var push_reader = postcard.Reader.init(push_bytes);
        const decoded_push = try Request.read(&push_reader, &push_storage);
        try push_reader.finish();

        // The framings are not interchangeable, so `Request.eql` says no in
        // both directions — the refusal is symmetric rather than a lookup that
        // happens to be false one way round.
        try testing.expect(!decoded_get.eql(decoded_push));
        try testing.expect(!decoded_push.eql(decoded_get));
        // The bodies are the same request and the inner values compare equal
        // by content — `GetRequest.eql` compares the borrowed ranges by value,
        // which is what makes this true across two different storages.
        try testing.expect(
            GetRequest.blob(da_hash).eql(decoded_get.to_eof.get),
        );
        try testing.expect(
            GetRequest.blob(da_hash).eql(decoded_push.length_prefixed.request.get),
        );
    }

    // `BaoResponse` has no decode to be a fixed point of, because there is
    // nothing in its bytes to decode. What it does have is two states, and they
    // are decided by the length and nothing else: a provider that ended the
    // stream without writing, and a provider that wrote something. Both are
    // ordinary values here, so the assertion is that the same bytes always give
    // the same answer and that only the empty one is EOF.
    {
        for ([_][]const u8{ "", "\x00", "\xde\xad", "\x00" ** 64 }) |bytes| {
            var reader = postcard.Reader.init(bytes);
            const answer = response.BaoResponse.read(&reader);
            try testing.expectEqual(bytes.len == 0, answer.isEof());
            try testing.expectEqualSlices(u8, bytes, answer.bytes);
            // Reading it twice gives the same answer, because `read` consumes
            // nothing: the response is a cursor over what is left.
            const again = response.BaoResponse.read(&reader);
            try testing.expectEqual(answer.isEof(), again.isEof());
        }
    }
}

test "a response's length prefix is read as a varint, at every boundary" {
    // The `push` body and each observe item are both length-prefixed, and the
    // prefix is postcard's `varint(u64)`. Its four refusals are four different
    // rules, and the boundary between them is what a peer is most likely to
    // land on: a length of exactly `max_message_size`, one over it, and the two
    // varint failures either side.
    {
        // A length one over the cap is `MessageTooLarge`, whatever is behind it.
        try expectRequestErrorHex("08" ++ "ffffffff01", error.MessageTooLarge);
        // Exactly the cap, with nothing behind it, is not the cap's refusal: the
        // frame is inside the cap and simply does not hold what it promised.
        try expectRequestErrorHex("08" ++ "808040", error.UnexpectedEnd);
        // A length whose last group carries more value bits than a `u64` has is
        // a number, not an encoding, so it is `ValueOutOfRange`.
        try expectRequestErrorHex("08" ++ "ffffffffffffffffff02", error.ValueOutOfRange);
        // Ten groups with nothing to terminate them cannot be fixed by more
        // bytes, so it is `BadVarint`.
        try expectRequestErrorHex("08" ++ "80808080808080808080", error.BadVarint);
    }
    // The same rules on an observe item, which is the other length-prefixed
    // shape in this protocol: the prefix is read the same way.
    {
        var room: protocol.Room = .{};
        var storage = room.storage();
        var scratch: [64]u8 = undefined;

        // A length of one over the cap on an item.
        const over = try protocol.parseHex(&scratch, "ffffffff01");
        var reader = postcard.Reader.init(over);
        var run = response.ObserveResponse.read(&reader, &storage);
        try testing.expectError(error.MessageTooLarge, run.next());

        // An item whose length names more than the run holds, which is a stream
        // that stopped *inside* an item rather than between two.
        const inside = try protocol.parseHex(&scratch, "05" ++ "00" ++ "00" ++ "00");
        var inside_reader = postcard.Reader.init(inside);
        var inside_run = response.ObserveResponse.read(&inside_reader, &storage);
        try testing.expectError(error.UnexpectedEnd, inside_run.next());

        // And a run that ends between items is `null` rather than either error,
        // which is the distinction the protocol module comment draws.
        var empty_reader = postcard.Reader.init("");
        var empty_run = response.ObserveResponse.read(&empty_reader, &storage);
        try testing.expect(try empty_run.next() == null);
    }
}

test "a reserved slot is a refusal, not a body decoded from the wrong bytes" {
    // Upstream calls these `Slot2` through `Slot7` and rejects every one rather
    // than skipping it, so a reserved slot is a request this build will not
    // serve. What it must not become is a *value*: a decoder that skipped a
    // reserved discriminant would read the bytes behind it as some other
    // request, and the peer would get an answer to a question it never asked.
    inline for (std.enums.values(RequestType)) |arm| {
        const reserved = @intFromEnum(arm) >= 2 and @intFromEnum(arm) <= 7;
        if (!reserved) continue;

        // With a well-formed body behind it, so the only thing that could be
        // read is the discriminant itself.
        const hex = switch (arm) {
            .slot2 => "02",
            .slot3 => "03",
            .slot4 => "04",
            .slot5 => "05",
            .slot6 => "06",
            .slot7 => "07",
            else => unreachable,
        };
        try expectRequestErrorHex(hex, error.ReservedSlot);

        // And with a whole `get` body behind it, which is the shape a peer would
        // send if it thought the slot were live.
        var scratch: [128]u8 = undefined;
        var reader = postcard.Reader.init(
            try protocol.parseHex(&scratch, hex ++ "00" ++ "da" ** 32 ++ "020001000100"),
        );
        var room: protocol.Room = .{};
        var storage = room.storage();
        try testing.expectError(error.ReservedSlot, Request.read(&reader, &storage));

        // The reserved arm is refused by the EOF framing directly too, on the
        // tag alone and before a byte of body is read.
        var direct = postcard.Reader.init(
            try protocol.parseHex(&scratch, "00" ++ "da" ** 32 ++ "020001000100"),
        );
        var direct_room: protocol.Room = .{};
        var direct_storage = direct_room.storage();
        try testing.expectError(
            error.ReservedSlot,
            EofFraming.read(arm, &direct, &direct_storage),
        );
    }
}

/// Decode `bytes` as a whole request, and if it decodes assert that it is a
/// fixed point. Returns whether it decoded.
fn expectTotalRequest(bytes: []const u8) !usize {
    var room: protocol.Room = .{};
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

    var again_room: protocol.Room = .{};
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

/// Write `request` and expect exactly `hex`.
fn expectRequestBytes(request_value: Request, hex: []const u8) !void {
    var scratch: [256]u8 = undefined;
    const expected = try protocol.parseHex(&scratch, hex);
    var body: [2048]u8 = undefined;
    var buffer: [2048]u8 = undefined;
    var writer = postcard.Writer.init(&buffer);
    try request_value.write(&writer, &body);
    try protocol.expectHex(expected, writer.finish());
}

/// Read `hex` as a whole request and expect `expected`.
fn expectRequestFrom(hex: []const u8, expected: Request) !void {
    var scratch: [256]u8 = undefined;
    const bytes = try protocol.parseHex(&scratch, hex);
    var room: protocol.Room = .{};
    var storage = room.storage();
    var reader = postcard.Reader.init(bytes);
    const decoded = try Request.read(&reader, &storage);
    try reader.finish();
    try testing.expect(expected.eql(decoded));
}

/// Read `hex` as a whole request and expect a named error.
fn expectRequestErrorHex(hex: []const u8, expected: Error) !void {
    var scratch: [256]u8 = undefined;
    const bytes = try protocol.parseHex(&scratch, hex);
    var room: protocol.Room = .{};
    var storage = room.storage();
    var reader = postcard.Reader.init(bytes);
    try testing.expectError(expected, Request.read(&reader, &storage));
}

/// Encode `request`, read it back, and re-encode: a fixed point, both ways.
fn expectRequestFixedPoint(request_value: Request) !void {
    var body: [2048]u8 = undefined;
    var buffer: [2048]u8 = undefined;
    var writer = postcard.Writer.init(&buffer);
    try request_value.write(&writer, &body);
    const frame = writer.finish();

    var room: protocol.Room = .{};
    var storage = room.storage();
    var reader = postcard.Reader.init(frame);
    const decoded = try Request.read(&reader, &storage);
    try reader.finish();
    try testing.expect(request_value.eql(decoded));

    var again: [2048]u8 = undefined;
    var rewriter = postcard.Writer.init(&again);
    try decoded.write(&rewriter, &body);
    try testing.expectEqualSlices(u8, frame, rewriter.finish());
}
