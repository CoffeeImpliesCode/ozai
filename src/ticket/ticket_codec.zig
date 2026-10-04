//! The framing every ticket kind shares: the canonical text form, the postcard
//! encoding of the address fields, and the error sets that name what each of
//! them refuses.
//!
//! # Why this is a module and not a trait
//!
//! Upstream puts the prefix, the base32 and the error set in the `Ticket`
//! trait and lets each kind supply only `KIND`, `encode_bytes` and
//! `decode_bytes`. Zig has no traits, so the trait's own half has to live
//! somewhere; it lived in `endpoint_ticket.zig`, which made one kind's module
//! answer for the other kind's fields. This is that half. The address kinds
//! both ticket layouts share — a relay URL, a socket address, a custom
//! transport — are written and read here, and nothing below knows which ticket
//! is on the wire.
//!
//! # The order the text form is built in
//!
//! `encodeText` is the kind prefix, then unpadded base32 of the bytes, and
//! the *whole string* is lower cased **after** the two are concatenated.
//! Upstream is `Self::KIND.to_string()`, then `encode_append`, then
//! `out.make_ascii_lowercase()`. The order is load bearing in one direction
//! only, and it is the direction that breaks: base32 emits upper case, so a
//! ticket whose body was left alone is a ticket whose body is upper case. A
//! peer still reads it — `decode_string` upper-cases before decoding — but it
//! is a second spelling of one value, which is the thing
//! `docs/ARCHITECTURE.md` invariant 2 exists to prevent. `encodeText` takes
//! the kind as a `comptime` parameter and refuses a prefix that is not lower
//! case, so the only lower casing that can happen is the one over the whole
//! string, and that is the one the tests pin.
//!
//! # Ownership
//!
//! Nothing here allocates beyond the caller's buffer and nothing here owns
//! anything. `readTransportAddr` hands back a custom payload that still
//! borrows the frame it was read out of, so what leaves this module is a
//! borrow: both decoders canonicalize their address list first and only then
//! copy the survivors, which is what makes a duplicate cost no allocation and
//! lets one payload be compared against another before either is copied.

const std = @import("std");
const addr = @import("../base/addr.zig");
const key = @import("../base/key.zig");
const postcard = @import("../wire/postcard.zig");
const relay_url = @import("../base/relay_url.zig");
const transport_addr = @import("../base/transport_addr.zig");

const Allocator = std.mem.Allocator;
const NodeId = key.NodeId;
const RelayUrl = relay_url.RelayUrl;
const SocketAddr = addr.SocketAddr;
const TransportAddr = transport_addr.TransportAddr;
const max_inline_length = addr.max_inline_length;
const orderTransport = transport_addr.orderTransport;

// -- The text form -----------------------------------------------------------

/// RFC 4648 base32, the alphabet `data_encoding::BASE32_NOPAD` emits.
///
/// Upper case, and *not* either of the alphabets in `base/base32.zig`: those
/// are sized at comptime, which a node id wants and a ticket cannot use, since
/// the body of a ticket is however many bytes the address list made it. This
/// is the same bit packer with the length as a value.
const rfc4648 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Everything the canonical text form refuses.
///
/// Named per rule rather than per symptom, the way `postcard.Error` is. A
/// caller needs to tell "this is not one of mine" from "this is one of mine
/// and I could not read the body", because those are different things to say
/// to a person who pasted the wrong string.
pub const TextError = error{
    /// The text does not begin with this kind's prefix. Upstream
    /// `ParseError::Kind`, and the one case where a ticket is simply not a
    /// ticket of this kind rather than a damaged one.
    UnknownKind,
    /// The base32 body is a symbol count no encoder produces: the text is
    /// complete, it just does not name a whole number of bytes. Upstream
    /// `data_encoding::DecodeKind::Length`, and deliberately not
    /// `UnexpectedEnd` — the input is not short.
    BadBase32Length,
    /// A byte in the body is not in the alphabet. Upstream
    /// `DecodeKind::Symbol`.
    BadBase32Symbol,
    /// The last symbol carried value below the byte boundary. `data-encoding`
    /// checks trailing bits, so an iroh peer rejects this too, and an encoder
    /// that emits it would be giving one ticket two spellings.
    NonZeroBase32Padding,
    /// The caller's buffer cannot hold what was asked for. `postcard.Writer`
    /// reports the same thing for the same reason, so the two are one word.
    BufferFull,
};

/// Everything a ticket body refuses, over and above `postcard.Error`.
pub const BodyError = error{
    /// The 32 bytes where an endpoint id belongs are not a canonical ed25519
    /// point. Upstream puts this in `ParseError::Verify`.
    NotANodeId,
    /// A relay URL the address layer will not accept. Upstream hands the same
    /// text to `url::Url::parse`, which is more permissive; see the
    /// divergence in the module report.
    BadRelayUrl,
    /// A custom transport payload longer than `addr.max_inline_length`.
    /// ozai's `CustomAddr` is a fixed 30-byte inline value and upstream's is
    /// inline-or-heap with no limit, so a ticket naming a longer one is a
    /// ticket this build cannot represent.
    CustomAddrTooLong,
    /// The wire discriminant names a ticket layout this build has no arm for.
    /// Upstream `ParseError::Verify`; postcard's own `UnknownVariant` covers
    /// the same ground for a field that is not the ticket discriminator.
    UnknownTicketVariant,
};

/// Everything a ticket can refuse, from the text in to the value out.
pub const DecodeError = TextError || BodyError || postcard.Error || Allocator.Error;

/// Symbols in the base32 of `byte_length` bytes. Neither base32 pads.
pub fn base32Length(byte_length: usize) usize {
    return @divFloor(byte_length * 8 + 4, 5);
}

/// Bytes in the base32 of `symbol_count` symbols, floored: the last symbol
/// carries bits below the byte boundary, and `decodeBase32` is what decides
/// whether they are zero.
pub fn byteLength(symbol_count: usize) usize {
    return @divFloor(symbol_count * 5, 8);
}

/// Length of the text form of a `byte_length`-byte body. The size a caller
/// has to hand `encodeText`.
pub fn textLength(comptime kind: []const u8, byte_length: usize) usize {
    return kind.len + base32Length(byte_length);
}

/// The base32 body of a ticket of kind `kind`, or the reason `text` is not
/// one.
///
/// Nothing is decoded here. This is the only step that can fail on the prefix,
/// and it is separate so that sizing a decode buffer does not mean trusting a
/// prefix that has not been checked.
pub fn splitBody(comptime kind: []const u8, text: []const u8) TextError![]const u8 {
    if (!std.mem.startsWith(u8, text, kind)) return error.UnknownKind;
    return text[kind.len..];
}

/// `kind` followed by unpadded RFC 4648 base32 of `body`, with the whole
/// string lower cased **after** the two are concatenated.
///
/// The prefix is required to be lower case already, at compile time. That is
/// what makes the single lower casing pass unambiguous: there is nothing else
/// in the function that could have lower cased anything, so the body comes
/// out lower case because the concatenation happened first, and a ticket that
/// came out with an upper case body was built in the other order.
///
/// The text returned is the prefix of `out` that was filled and not a copy of
/// it, so `out` must stay alive and unwritten for as long as the string is
/// read, and a later write through `out` invalidates it. An `out` shorter than
/// `textLength(kind, body.len)` is `error.BufferFull` and writes nothing,
/// because the length is checked before the first byte is copied.
pub fn encodeText(
    comptime kind: []const u8,
    body: []const u8,
    out: []u8,
) TextError![]const u8 {
    comptime for (kind) |c| {
        if (!std.ascii.isLower(c)) {
            @compileError("a ticket kind prefix is lower case ascii");
        }
    };
    const need = textLength(kind, body.len);
    if (out.len < need) return error.BufferFull;
    @memcpy(out[0..kind.len], kind);
    encodeBase32(body, out[kind.len..need]);
    // Over the whole string, and after the concatenation above. base32 emits
    // upper case; this is the only step that makes it lower.
    for (out[0..need]) |*c| c.* = std.ascii.toLower(c.*);
    return out[0..need];
}

/// Unpadded RFC 4648 base32 of `body` into `out`, which must be
/// `base32Length(body.len)` long.
///
/// The same loop `base/base32.zig` runs, with the length as a value instead of
/// a type parameter.
pub fn encodeBase32(body: []const u8, out: []u8) void {
    std.debug.assert(out.len == base32Length(body.len));
    var accumulator: u32 = 0;
    var bits: u4 = 0;
    var index: usize = 0;

    for (body) |byte| {
        accumulator = (accumulator << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out[index] = rfc4648[@intCast((accumulator >> bits) & 0x1f)];
            index += 1;
        }
        accumulator &= (@as(u32, 1) << bits) - 1;
    }
    // Fewer than five bits are left, and they are left aligned with zero
    // below. `decodeBase32` rejects a non-zero pad, which is what keeps one
    // ticket from having two spellings.
    if (bits > 0) {
        out[index] = rfc4648[@intCast((accumulator << @intCast(5 - bits)) & 0x1f)];
        index += 1;
    }
    std.debug.assert(index == out.len);
}

/// Unpadded RFC 4648 base32 of `symbols` into `out`, which must be
/// `byteLength(symbols.len)` long.
///
/// Either case decodes. `data_encoding` is upper case only, and upstream
/// upper-cases the body before handing it over
/// (`data_encoding::BASE32_NOPAD.decode(rest.to_ascii_uppercase()…)`), so
/// every ticket upstream accepts is one this accepts, and the lower case
/// spelling our own encoder emits is the same value.
pub fn decodeBase32(symbols: []const u8, out: []u8) TextError!void {
    const length = byteLength(symbols.len);
    if (out.len < length) return error.BufferFull;
    // A symbol count no encoder produces. Not `BufferFull`: the text is whole
    // and names a byte count the alphabet cannot spell.
    if (base32Length(length) != symbols.len) return error.BadBase32Length;
    const bytes = out[0..length];

    var accumulator: u32 = 0;
    var bits: u4 = 0;
    var index: usize = 0;

    for (symbols) |c| {
        const symbol = symbolOf(c) orelse return error.BadBase32Symbol;
        accumulator = (accumulator << 5) | symbol;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            bytes[index] = @truncate(accumulator >> bits);
            index += 1;
        }
        accumulator &= (@as(u32, 1) << bits) - 1;
    }

    std.debug.assert(bits < 8);
    if (bits > 0 and accumulator != 0) return error.NonZeroBase32Padding;
    std.debug.assert(index == bytes.len);
}

fn symbolOf(c: u8) ?u5 {
    // Folded to the alphabet's own case rather than the alphabet folded to
    // the input's: `rfc4648` is the table, so folding it would be a 32-entry
    // fold to do once instead of once per symbol.
    const upper = std.ascii.toUpper(c);
    inline for (rfc4648, 0..) |symbol, i| {
        if (upper == symbol) return @intCast(i);
    }
    return null;
}

// -- The fields every kind shares -------------------------------------------

/// The longest text `RelayUrl.format` can produce: the longest scheme, an RFC
/// 1035 host at its limit, the longest port, and the trailing slash
/// invariant 4 requires.
pub const relay_url_text_max = "https://".len + RelayUrl.max_host_length + ":65535".len + 1;

/// The `TransportAddr` discriminant, a `varint(u32)` like every other enum on
/// these wires.
///
/// Exhaustive on purpose: a peer may name any number at all, and one with no
/// arm here is `error.UnknownVariant` rather than a value this build cannot
/// switch on.
pub const TransportTag = enum(u32) { relay = 0, ip = 1, custom = 2 };

/// postcard's `SocketAddr`: an externally tagged family, the address, the
/// port. `std::net::SocketAddr` serialises the two fields of a struct and
/// postcard writes a struct as its fields, so the family byte is the only
/// tag there is.
///
/// Exhaustive on purpose, for the same reason `TransportTag` is: a family
/// byte this build has no arm for is `error.UnknownVariant` rather than an
/// address that happens to be short. Private, because `writeSocketAddr` is
/// the only way this build writes one.
const IpFamily = enum(u32) { v4 = 0, v6 = 1 };

/// A node id, inline: 32 raw bytes and no length prefix.
///
/// `PublicKey::serialize` sends `self.0.as_bytes().serialize(…)` when the
/// serializer is not human readable, and postcard is not, and a `[u8; 32]`
/// is a tuple of 32 `u8`s. The `00` in front of the 32 bytes in upstream's own
/// vector is the ticket variant, not a length.
pub fn writeNodeId(writer: *postcard.Writer, id: NodeId) postcard.Error!void {
    try writer.writeArray(NodeId.byte_length, &id.toBytes());
}

/// 32 raw bytes as a `NodeId`. The bytes are checked, so a well-formed
/// encoding of a non-point is `error.NotANodeId` rather than a value.
pub fn readNodeId(reader: *postcard.Reader) (postcard.Error || error{NotANodeId})!NodeId {
    const bytes = try reader.readArray(NodeId.byte_length);
    return NodeId.fromBytes(bytes) catch error.NotANodeId;
}

/// A relay URL, as its canonical text: a length prefix and the bytes.
///
/// Invariant 4 is why this is a rendering and not a structured value. The URL
/// goes on the wire as the text a human would write, trailing slash and all,
/// and a different spelling is a different relay to a peer.
pub fn writeRelayUrl(writer: *postcard.Writer, url: RelayUrl) postcard.Error!void {
    var scratch: [relay_url_text_max]u8 = undefined;
    var out = std.Io.Writer.fixed(&scratch);
    // Unreachable for any `RelayUrl.parse` accepted: every term of
    // `relay_url_text_max` is a field bound and `format` writes one of each.
    url.format(&out) catch return error.BufferFull;
    try writer.writeBytes(scratch[0..out.end]);
}

/// A relay URL from its length-prefixed text. The text is validated UTF-8 by
/// `readStr` and then by `RelayUrl.parse`, so both a malformed encoding and a
/// URL this build will not accept are refused — the latter as
/// `error.BadRelayUrl`.
pub fn readRelayUrl(reader: *postcard.Reader) (postcard.Error || error{BadRelayUrl})!RelayUrl {
    const text = try reader.readStr();
    return RelayUrl.parse(text) catch error.BadRelayUrl;
}

/// A socket address: the family as a `varint(u32)`, then the address bytes and
/// the port. An exhaustive family enum, so a family byte this build has no arm
/// for is `error.UnknownVariant`.
pub fn writeSocketAddr(writer: *postcard.Writer, value: SocketAddr) postcard.Error!void {
    switch (value.ip) {
        .v4 => |octets| {
            try writer.writeVariant(IpFamily.v4);
            try writer.writeArray(octets.len, &octets);
        },
        .v6 => |octets| {
            try writer.writeVariant(IpFamily.v6);
            try writer.writeArray(octets.len, &octets);
        },
    }
    try writer.writeU16(value.port);
}

/// A socket address read back. The value owns its bytes and borrows nothing;
/// the reader is left on the first byte after the port.
pub fn readSocketAddr(reader: *postcard.Reader) postcard.Error!SocketAddr {
    const family = try reader.readVariant(IpFamily);
    return .{
        .ip = switch (family) {
            .v4 => .{ .v4 = try reader.readArray(4) },
            .v6 => .{ .v6 = try reader.readArray(16) },
        },
        .port = try reader.readU16(),
    };
}

/// One address off the wire, as its tag then its value.
pub fn writeTransportAddr(writer: *postcard.Writer, one: TransportAddr) postcard.Error!void {
    switch (one) {
        .relay => |url| {
            try writer.writeVariant(TransportTag.relay);
            try writeRelayUrl(writer, url);
        },
        .ip => |socket| {
            try writer.writeVariant(TransportTag.ip);
            try writeSocketAddr(writer, socket);
        },
        .custom => |custom| {
            try writer.writeVariant(TransportTag.custom);
            try writer.writeU64(custom.id);
            try writer.writeBytes(custom.data);
        },
    }
}

/// One address read back, with a custom payload still borrowing the reader's
/// input. The decoders that call this copy the payload after the list is
/// canonical, so a value this returns is only meaningful while the frame it
/// was read from is alive.
pub fn readTransportAddr(
    reader: *postcard.Reader,
) (postcard.Error || error{ BadRelayUrl, CustomAddrTooLong })!TransportAddr {
    return switch (try reader.readVariant(TransportTag)) {
        .relay => .{ .relay = try readRelayUrl(reader) },
        .ip => .{ .ip = try readSocketAddr(reader) },
        .custom => try readCustomAddr(reader),
    };
}

fn readCustomAddr(
    reader: *postcard.Reader,
) (postcard.Error || error{CustomAddrTooLong})!TransportAddr {
    const id = try reader.readU64();
    const data = try reader.readBytes();
    if (data.len > max_inline_length) return error.CustomAddrTooLong;
    return .{ .custom = .{ .id = id, .data = data } };
}

/// The most bytes `writeTransportAddr` can write for `one`, which is what a
/// caller sizing one buffer for a whole address list adds up.
pub fn maxTransportAddrLength(one: TransportAddr) usize {
    return switch (one) {
        .relay => 1 + postcard.varintMax(u64) * 2 + relay_url_text_max,
        .ip => 1 + 1 + 16 + postcard.varintMax(u16),
        .custom => |custom| 1 + postcard.varintMax(u64) * 2 + custom.data.len,
    };
}

/// Sort an address list into `TransportAddr.order` and drop duplicates.
/// Returns the surviving prefix, which is shorter than the input exactly when
/// the input held a duplicate.
///
/// postcard reads a `BTreeSet` by inserting, so upstream's own decoder
/// collapses duplicates and imposes the set's order on whatever order the
/// bytes arrived in. Appending would do neither, and a `NodeAddr` whose list
/// is neither sorted nor unique breaks invariant 2 — which is what makes a
/// ticket an identifier rather than a fresh value on every send, and what
/// makes the bytes a function of the value rather than of the encoding.
///
/// Every ticket upstream writes is already in this order, so in practice this
/// is one comparison pass; the sort is what makes the guarantee hold for a
/// peer that sends the same address twice, or out of order.
///
/// Nothing is allocated and nothing is freed, and no payload is copied: a
/// duplicate is dropped as a value, and every surviving `.custom` arm is still
/// the borrow it was before the call. A caller that needs owned payloads has
/// to make that copy itself, which is what both decoders do — and which is why
/// collapsing here rather than after the copies is what keeps a repeated
/// address from costing an allocation.
pub fn canonicalizeAddrs(addrs: []TransportAddr) []TransportAddr {
    var out = addrs;
    std.mem.sort(TransportAddr, out, {}, lessTransportAddr);
    var kept: usize = 0;
    // Writes land at or behind the read cursor, so nothing is overwritten
    // before it is read.
    for (out) |one| {
        if (kept != 0 and out[kept - 1].order(one) == .eq) continue;
        out[kept] = one;
        kept += 1;
    }
    out.len = kept;
    return out;
}

fn lessTransportAddr(_: void, a: TransportAddr, b: TransportAddr) bool {
    return orderTransport(a, b) == .lt;
}
