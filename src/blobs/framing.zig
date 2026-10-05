//! The discriminant byte, the two ways a request is framed on a stream, the
//! error set those two rules need, and the QUIC codes that end a stream.
//!
//! `EofFraming` and `LengthPrefixedFraming` are separate types because
//! upstream's two readers have two different rules, and a single reader with a
//! flag would put both rules in one place and let a decoder pick between them
//! by reading a byte off a peer's wire. `Request.read` reads the discriminant
//! byte first and hands the request to exactly one of them.
//!
//! `Error` and `Closed` are here rather than in the request bodies because
//! they name rules about frames and not about bodies: `WrongFraming` is what a
//! type carried by the wrong framing is, `ReservedSlot` is a discriminant
//! upstream reserves and refuses, and `Closed` is a STOP_STREAM code, which is
//! a fact about the stream rather than bytes in it. The byte helpers at the
//! bottom are here for the same reason the framings are: a length prefix is
//! part of how a frame is spelled, and `postcard` offers no method for a bare
//! count and none for unprefixed bytes.
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

const std = @import("std");
const postcard = @import("../wire/postcard.zig");
const requests = @import("requests.zig");

// The bodies this module frames, re-bound so the framing code below reads as
// framing code. `requests` is the owner; these are the same types, not copies.
const Storage = requests.Storage;
const GetRequest = requests.GetRequest;
const GetManyRequest = requests.GetManyRequest;
const ObserveRequest = requests.ObserveRequest;
const PushRequest = requests.PushRequest;

/// The most bytes a request body may occupy.
///
/// Upstream's `MAX_MESSAGE_SIZE` at `src/protocol.rs:396`, and its comment
/// says "100MiB" for a value that is one MiB. The value is what a peer
/// enforces, so this is the value; the comment is upstream's error and is noted
/// rather than followed.
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

pub fn writeRequestType(writer: *postcard.Writer, tag: RequestType) Error!void {
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
pub fn appendBytes(writer: *postcard.Writer, bytes: []const u8) Error!void {
    const room = writer.buffer[writer.length..];
    if (room.len < bytes.len) return error.BufferFull;
    @memcpy(room[0..bytes.len], bytes);
    writer.length += bytes.len;
}
