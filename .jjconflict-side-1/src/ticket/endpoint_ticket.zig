//! Tickets: a value, the postcard a peer reads, and the string a human pastes.
//!
//! This module is a port of `iroh-tickets` 1.0.0, `src/lib.rs` and
//! `src/endpoint.rs`, at commit
//! `cec7f1e119003980f238819e0f320ccb0ceaa691`, fetched 2026-09-30. iroh 1.3.0
//! has no ticket source of its own — `iroh-base/src/` at
//! `187f59e80afdae6bd9866002b33d3365c00b06d8` holds four files and none of
//! them is this — so the crate that owns the type is the upstream. The field
//! order below is that crate's, byte for byte, because a ticket is read by a
//! peer that knows nothing about ozai.
//!
//! # The three forms, and why they are three
//!
//! postcard bytes are what goes on the wire. The text form is what a person
//! pastes into a chat. The two are not interchangeable and neither one is
//! derivable from the other without a buffer, so `encode` and `encodeString`
//! take one each: the text is 1.6 times the bytes, and no single buffer holds
//! both without an in-place expansion, which costs more clarity than it saves
//! bytes on a value that is built once to be pasted.
//!
//! # The order the text form is built in
//!
//! `encodeString` is the kind prefix, then unpadded base32 of the bytes, and
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
//! # Shared scaffolding
//!
//! Upstream puts the prefix, the base32 and the error set in the `Ticket`
//! trait and lets each kind supply only `KIND`, `encode_bytes` and
//! `decode_bytes`. Zig has no traits, and ozai has no module to put the trait
//! in, so they live here and `blob_ticket.zig` imports them. That is why this
//! file, which is otherwise about one ticket kind, also knows how a relay URL
//! and a socket address are written: those are the fields the two kinds share.
//!
//! # Purity
//!
//! No clock, no environment, no global. A decode takes the allocator it uses
//! and hands back a `Decoded`, because a custom transport's payload has to
//! outlive the frame the bytes were read in — invariant 6 — and a ticket read
//! off the wire therefore owns storage a ticket built by hand does not. That
//! is the whole reason for the wrapper; `Decoded`'s doc says the rest.

const std = @import("std");
const addr = @import("../base/addr.zig");
const key = @import("../base/key.zig");
const postcard = @import("../wire/postcard.zig");

const Allocator = std.mem.Allocator;

pub const NodeId = key.NodeId;
pub const NodeAddr = addr.NodeAddr;
pub const TransportAddr = addr.TransportAddr;
pub const SocketAddr = addr.SocketAddr;
pub const RelayUrl = addr.RelayUrl;
pub const CustomAddr = addr.CustomAddr;

// -- The text form -----------------------------------------------------------

/// RFC 4648 base32, the alphabet `data_encoding::BASE32_NOPAD` emits.
///
/// Upper case, and *not* either of the alphabets in `base/base32.zig`: those
/// are sized at comptime, which a node id wants and a ticket cannot use, since
/// the body of a ticket is however many bytes the address list made it. This
/// is the same bit packer with the length as a value.
pub const rfc4648 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

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
    return (byte_length * 8 + 4) / 5;
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

/// The postcard bytes a ticket's text form names, into `out`.
///
/// `out` may be longer than the answer; the returned slice is the prefix that
/// was filled. This is `splitBody` then `decodeBase32`, and it exists so a
/// caller that already sized a buffer does not have to allocate one.
pub fn decodeText(
    comptime kind: []const u8,
    text: []const u8,
    out: []u8,
) TextError![]const u8 {
    const symbols = try splitBody(kind, text);
    const length = byteLength(symbols.len);
    if (out.len < length) return error.BufferFull;
    try decodeBase32(symbols, out[0..length]);
    return out[0..length];
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

// -- The fields both kinds share ---------------------------------------------

/// The longest text `RelayUrl.format` can produce: the longest scheme, an RFC
/// 1035 host at its limit, the longest port, and the trailing slash
/// invariant 4 requires.
pub const relay_url_text_max = "https://".len + addr.RelayUrl.max_host_length + ":65535".len + 1;

const WireVariant = enum(u32) { variant1 = 0 };

const TransportTag = enum(u32) { relay = 0, ip = 1, custom = 2 };

/// postcard's `SocketAddr`: an externally tagged family, the address, the
/// port. `std::net::SocketAddr` serialises the two fields of a struct and
/// postcard writes a struct as its fields, so the family byte is the only
/// tag there is.
const IpFamily = enum(u32) { v4 = 0, v6 = 1 };

/// A node id, inline: 32 raw bytes and no length prefix.
///
/// `PublicKey::serialize` sends `self.0.as_bytes().serialize(…)` when the
/// serializer is not human readable, and postcard is not, and a `[u8; 32]`
/// is a tuple of 32 `u8`s. The `00` in front of the 32 bytes in upstream's own
/// vector is the ticket variant, not a length.
pub fn writeNodeId(writer: *postcard.Writer, id: NodeId) postcard.Error!void {
    try writer.writeArray(key.NodeId.byte_length, &id.toBytes());
}

pub fn readNodeId(reader: *postcard.Reader) (postcard.Error || BodyError)!NodeId {
    const bytes = try reader.readArray(key.NodeId.byte_length);
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

pub fn readRelayUrl(reader: *postcard.Reader) (postcard.Error || BodyError)!RelayUrl {
    const text = try reader.readStr();
    return RelayUrl.parse(text) catch error.BadRelayUrl;
}

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

fn writeTransportAddr(writer: *postcard.Writer, one: TransportAddr) postcard.Error!void {
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

fn readTransportAddr(
    alloc: Allocator,
    reader: *postcard.Reader,
) (postcard.Error || BodyError || Allocator.Error)!TransportAddr {
    return switch (try reader.readVariant(TransportTag)) {
        .relay => .{ .relay = try readRelayUrl(reader) },
        .ip => .{ .ip = try readSocketAddr(reader) },
        .custom => try readCustomAddr(alloc, reader),
    };
}

fn readCustomAddr(
    alloc: Allocator,
    reader: *postcard.Reader,
) (postcard.Error || BodyError || Allocator.Error)!TransportAddr {
    const id = try reader.readU64();
    const data = try reader.readBytes();
    if (data.len > addr.max_inline_length) return error.CustomAddrTooLong;
    return .{ .custom = .{ .id = id, .data = try alloc.dupe(u8, data) } };
}

fn maxTransportAddrLength(one: TransportAddr) usize {
    return switch (one) {
        .relay => 1 + postcard.varintMax(u64) * 2 + relay_url_text_max,
        .ip => 1 + 1 + 16 + postcard.varintMax(u16),
        .custom => |custom| 1 + postcard.varintMax(u64) * 2 + custom.data.len,
    };
}

/// Sort an address list into `TransportAddr.order` and drop duplicates.
/// Returns the surviving prefix, which is always the whole slice.
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
    return a.order(b) == .lt;
}

// -- The endpoint ticket -----------------------------------------------------

/// `endpoint` — a node id and every address that might reach it.
///
/// Variant 1 carries the whole `EndpointAddr`, so unlike a blob ticket this
/// one is lossless: every `TransportAddr` a peer can hold survives the round
/// trip, and `encode` has nothing to report.
pub const EndpointTicket = struct {
    /// The kind prefix, and the only spelling `decodeString` accepts.
    pub const kind = "endpoint";

    addr: NodeAddr,

    pub fn new(address: NodeAddr) EndpointTicket {
        return .{ .addr = address };
    }

    /// postcard variant 1: the ticket discriminant, the node id, then the
    /// address list as a length and that many `TransportAddr`s.
    ///
    /// The list is `NodeAddr.addrs` in slice order, which is
    /// `TransportAddr.order` order and duplicate-free — invariant 2. That is
    /// what makes the bytes a function of the address rather than of the order
    /// it was built in, and it is the same order upstream's `BTreeSet`
    /// iterates, because postcard writes a set in its iteration order.
    pub fn encode(self: EndpointTicket, out: []u8) postcard.Error![]const u8 {
        var writer = postcard.Writer.init(out);
        try writer.writeVariant(WireVariant.variant1);
        try writeNodeId(&writer, self.addr.node_id);
        try writer.writeLen(self.addr.addrs.len);
        for (self.addr.addrs) |one| try writeTransportAddr(&writer, one);
        return writer.finish();
    }

    /// The postcard bytes as they would be written, for a caller that wants
    /// the length without producing them.
    pub fn maxEncodedLength(self: EndpointTicket) usize {
        var total: usize = 1 + key.NodeId.byte_length + postcard.varintMax(u64);
        for (self.addr.addrs) |one| total += maxTransportAddrLength(one);
        return total;
    }

    /// The canonical text form of `body`, which must be what `encode`
    /// produced for this ticket. `textLength(kind, …)` sizes `out`.
    pub fn encodeString(
        self: EndpointTicket,
        body: []const u8,
        out: []u8,
    ) TextError![]const u8 {
        _ = self;
        return encodeText(kind, body, out);
    }

    /// postcard bytes to a ticket.
    ///
    /// `alloc` takes the address list and every custom transport payload in
    /// it, and the result says so, so that the two cannot be confused with a
    /// ticket the caller built and therefore owns differently.
    pub fn decodeBytes(alloc: Allocator, bytes: []const u8) DecodeError!Decoded {
        var reader = postcard.Reader.init(bytes);
        // The ticket discriminant is read as a number rather than through
        // `readVariant`, because a wrong one is not an unknown enum arm: it is
        // a ticket layout this build has no arm for, which is a different
        // thing from a field inside a ticket carrying an arm we lack, and a
        // caller reads the two differently.
        if (try reader.readU32() != @intFromEnum(WireVariant.variant1)) {
            return error.UnknownTicketVariant;
        }

        const id = try readNodeId(&reader);
        // `readLen` has already refused a count the remaining bytes cannot
        // satisfy, and a `TransportAddr` is at least one byte, so the loop
        // below is bounded by the size of the input.
        const count = try reader.readLen();

        var addrs: std.ArrayList(TransportAddr) = .empty;
        errdefer addrs.deinit(alloc);
        errdefer freeCustomPayloads(alloc, addrs.items);
        for (0..count) |_| try addrs.append(alloc, try readTransportAddr(alloc, &reader));
        try reader.finish();
        // The wire order is upstream's `BTreeSet` order, which a peer is free
        // to ignore, and the set collapses a repeated address on the way in.
        // Both happen here; see `canonicalizeAddrs`.
        addrs.items = canonicalizeAddrs(addrs.items);

        return .{ .ticket = .{
            .addr = .{ .node_id = id, .addrs = try addrs.toOwnedSlice(alloc) },
        } };
    }

    /// A ticket's text form to a ticket. The base32 body is decoded through a
    /// fresh allocation, because its length is whatever the text said it was.
    pub fn decodeString(alloc: Allocator, text: []const u8) DecodeError!Decoded {
        const symbols = try splitBody(kind, text);
        const raw = try alloc.alloc(u8, byteLength(symbols.len));
        defer alloc.free(raw);
        try decodeBase32(symbols, raw);
        return decodeBytes(alloc, raw);
    }
};

/// A ticket that was read off the wire, and therefore owns its storage.
///
/// The wrapper is not ceremony. A `TransportAddr::Custom` carries a payload
/// that has to outlive the frame the bytes were read in — invariant 6 — so
/// reading one means copying it onto the heap, and the copy is owned by the
/// code that made it. A ticket built from a `NodeAddr` the caller made
/// borrows that address's payloads instead, and a `deinit` that could not tell
/// those two apart would free a borrow. Only `decodeBytes` and `decodeString`
/// produce one of these, so only they can be freed this way.
pub const Decoded = struct {
    ticket: EndpointTicket,

    /// Free the address list and every custom transport payload in it, all of
    /// which came from `alloc` when the ticket was read.
    ///
    /// Inserting a *new* custom address into the list borrows that address's
    /// payload, and freeing it here would free a borrow. Inserting an address
    /// of any other kind is fine: the payloads already in the list are the
    /// same ones either way.
    pub fn deinit(self: Decoded, alloc: Allocator) void {
        freeCustomPayloads(alloc, self.ticket.addr.addrs);
        self.ticket.addr.deinit(alloc);
    }
};

fn freeCustomPayloads(alloc: Allocator, addrs: []const TransportAddr) void {
    for (addrs) |one| {
        if (one == .custom) alloc.free(one.custom.data);
    }
}

const t = std.testing;

// Golden vectors below. The bytes are upstream's own, from
// `test "test_ticket_base32"` in `iroh-tickets` `src/endpoint.rs` at commit
// cec7f1e119003980f238819e0f320ccb0ceaa691, fetched 2026-09-30, read through
// the hexdump comment upstream annotates it with. The ticket string is a real
// published ticket: `tmc/go-iroh` `endpointticket/example_test.go` at commit
// a22a7c30ef8d5892ba144e2f72461edb3c541bdb hands that exact string to its
// decoder and asserts it names the id and two addresses.

// Half-length buffers rule out NoSpaceLeft. Invalid captured hex therefore
// fails the test that requested it, rather than terminating the whole runner.

const golden_hex =
    "00" ++
    "ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6" ++
    "02" ++
    // TransportAddr::Relay
    "00" ++
    // the relay url, 16 bytes
    "10" ++ "687474703a2f2f646572702e6d652e2f" ++
    // TransportAddr::Ip
    "01" ++
    // SocketAddr::V4
    "00" ++
    // 127.0.0.1, port 1024
    "7f0000018008";

const golden_ticket =
    "endpointacxfr74igmsbvsbnn73wcecg5vt3kbzncqwfrdiampuufwnhkublmaq" ++
    "acbuhi5dqhixs6zdfojyc43lffyxqcad7aaaadaai";

const golden_id_hex = "ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6";

fn expectHexEqual(expected_hex: []const u8, got: []const u8) !void {
    try t.expectEqual(expected_hex.len / 2, got.len);
    var index: usize = 0;
    while (index < got.len) : (index += 1) {
        var nibbles: [1]u8 = undefined;
        _ = try std.fmt.hexToBytes(&nibbles, expected_hex[2 * index ..][0..2]);
        try t.expectEqual(nibbles[0], got[index]);
    }
}

/// The address the golden vector names, built the way a caller would.
fn goldenAddr(alloc: Allocator) !NodeAddr {
    const id = try NodeId.parseHex(golden_id_hex);
    var address = try NodeAddr.withRelay(alloc, id, try RelayUrl.parse("http://derp.me./"));
    const socket: SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 1024 };
    address = (try address.insert(alloc, .{ .ip = socket })) orelse
        return error.TestUnexpectedResult;
    return address;
}

test "golden: the endpoint ticket bytes, iroh-tickets src/endpoint.rs" {
    var bytes: [golden_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, golden_hex);

    const alloc = t.allocator;
    const decoded = try EndpointTicket.decodeBytes(alloc, bytes[0..60]);
    defer decoded.deinit(alloc);

    try t.expectEqualStrings(golden_id_hex, decoded.ticket.addr.node_id.toHex()[0..]);
    try t.expectEqual(@as(usize, 2), decoded.ticket.addr.addrs.len);
    try t.expectEqual(TransportAddr.relay, std.meta.activeTag(decoded.ticket.addr.addrs[0]));
    try t.expectEqualStrings("derp.me.", decoded.ticket.addr.addrs[0].relay.hostSlice());
    try t.expectEqual(TransportAddr.ip, std.meta.activeTag(decoded.ticket.addr.addrs[1]));
    try t.expectEqual(@as(u16, 1024), decoded.ticket.addr.addrs[1].ip.port);

    const address = try goldenAddr(alloc);
    defer address.deinit(alloc);

    var again: [64]u8 = undefined;
    try expectHexEqual(golden_hex, try decoded.ticket.encode(&again));
}

test "golden: the endpoint ticket text form, tmc/go-iroh endpointticket" {
    const alloc = t.allocator;
    const decoded = try EndpointTicket.decodeString(alloc, golden_ticket);
    defer decoded.deinit(alloc);

    try t.expectEqualStrings(golden_id_hex, decoded.ticket.addr.node_id.toHex()[0..]);
    try t.expectEqual(@as(usize, 2), decoded.ticket.addr.addrs.len);

    var body: [64]u8 = undefined;
    const bytes = try decoded.ticket.encode(&body);
    var text: [128]u8 = undefined;
    try t.expectEqualStrings(golden_ticket, try decoded.ticket.encodeString(bytes, &text));
}

test "the text form is a fixed point" {
    const alloc = t.allocator;
    const address = try goldenAddr(alloc);
    defer address.deinit(alloc);
    const ticket = EndpointTicket.new(address);

    var body: [64]u8 = undefined;
    const bytes = try ticket.encode(&body);

    var first: [128]u8 = undefined;
    var second: [128]u8 = undefined;
    const once = try ticket.encodeString(bytes, &first);
    const twice = try EndpointTicket.decodeString(alloc, once);
    defer twice.deinit(alloc);
    const again = try twice.ticket.encodeString(try twice.ticket.encode(&body), &second);

    try t.expectEqualStrings(once, again);
    try t.expectEqual(textLength(EndpointTicket.kind, bytes.len), once.len);
}

test "the lower casing happens after the prefix, not before it" {
    const alloc = t.allocator;
    const address = try goldenAddr(alloc);
    defer address.deinit(alloc);
    const ticket = EndpointTicket.new(address);

    var body: [64]u8 = undefined;
    const bytes = try ticket.encode(&body);
    var text: [128]u8 = undefined;
    const written = try ticket.encodeString(bytes, &text);

    // base32 is upper case, and it is what lands in the buffer first. The
    // digits are in neither case, so the claim is about the letters.
    for (rfc4648) |c| try t.expect(!std.ascii.isLower(c));
    // The prefix is byte-identical to the kind and is in front.
    try t.expectEqualStrings(EndpointTicket.kind, written[0..EndpointTicket.kind.len]);
    // Nothing in the result is upper case, so the lower casing covered the
    // body. An implementation that lower cased the prefix and appended the
    // base32 untouched would leave 96 upper case bytes here and fail.
    for (written) |c| try t.expect(!std.ascii.isUpper(c));
    // And it covered the concatenation rather than either half: a body
    // assembled from the prefix alone would be the prefix.
    try t.expect(written.len > EndpointTicket.kind.len);

    // Upper case in the *body* is upstream's rule, not ours: `decode_string`
    // upper-cases what is left after the prefix before `data_encoding` sees
    // it. The prefix is not folded, which is the other half of the same
    // function and is checked in the test above.
    var upper: [128]u8 = undefined;
    const shouted_text = upper[0..written.len];
    @memcpy(shouted_text, written);
    const shouted_body = shouted_text[EndpointTicket.kind.len..];
    _ = std.ascii.upperString(shouted_body, written[EndpointTicket.kind.len..]);
    const shouted = try EndpointTicket.decodeString(alloc, shouted_text);
    defer shouted.deinit(alloc);
    try t.expect(std.ascii.eqlIgnoreCase(written, shouted_text));
    try t.expectEqualStrings(golden_id_hex, shouted.ticket.addr.node_id.toHex()[0..]);
}

test "a foreign kind prefix is not a ticket" {
    const alloc = t.allocator;
    try t.expectError(error.UnknownKind, EndpointTicket.decodeString(alloc, ""));
    try t.expectError(error.UnknownKind, EndpointTicket.decodeString(alloc, "blob"));
    // The prefix is matched exactly and is lower case. A ticket shouted in
    // its prefix is a different string, which is upstream's rule too: it
    // strips `Self::KIND` and does not fold case.
    try t.expectError(
        error.UnknownKind,
        EndpointTicket.decodeString(alloc, "Endpoint" ++ golden_ticket["endpoint".len..]),
    );
    // A prefix that is a prefix of the kind is a kind of nothing.
    try t.expectError(error.UnknownKind, EndpointTicket.decodeString(alloc, "endpoin"));
    try t.expectError(error.UnknownKind, EndpointTicket.decodeString(alloc, " endpoint"));
}

test "a body that is not whole bytes is refused" {
    // One symbol, and then six. Neither is a count `base32Length` produces
    // for any byte count: one is fewer than the two the smallest body needs,
    // and six is between the five a three-byte body produces and the seven a
    // four-byte body does. The text is complete in both cases, which is why
    // this is its own error and not `UnexpectedEnd`.
    try t.expectError(error.BadBase32Length, EndpointTicket.decodeString(t.allocator, "endpointa"));
    try t.expectError(
        error.BadBase32Length,
        EndpointTicket.decodeString(t.allocator, "endpointaaaaaa"),
    );
}

test "a character outside the alphabet is refused" {
    // '0', '1', '8' and '9' are the four symbols RFC 4648 base32 leaves out,
    // and two symbols is a legal body, so the length check passes and this is
    // the failure under test rather than the length one.
    for ("0189!=") |c| {
        var text: [16]u8 = undefined;
        @memcpy(text[0..EndpointTicket.kind.len], EndpointTicket.kind);
        text[EndpointTicket.kind.len] = 'a';
        text[EndpointTicket.kind.len + 1] = c;
        try t.expectError(error.BadBase32Symbol, EndpointTicket.decodeString(t.allocator, &text));
    }
}

test "bytes below the boundary are refused" {
    // 59 bytes is 95 symbols, and 95 * 5 is 475 bits for 472 bits of body,
    // so the last symbol carries two real bits and three pad bits. The
    // captured ticket is 60 bytes and therefore has none, which is why this
    // drops a byte rather than tampering with the ticket: `data-encoding`
    // checks trailing bits, and an encoder that emitted value in them would
    // be giving one ticket two spellings.
    var bytes: [golden_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, golden_hex);

    var buffer: [128]u8 = undefined;
    const body = bytes[0..59];
    @memcpy(buffer[0..EndpointTicket.kind.len], EndpointTicket.kind);
    const symbols = buffer[EndpointTicket.kind.len..][0..base32Length(body.len)];
    encodeBase32(body, symbols);
    const text = buffer[0 .. EndpointTicket.kind.len + symbols.len];
    try t.expectEqual(@as(usize, 95), symbols.len);

    // `encodeBase32` emits upper case — the lower casing belongs to
    // `encodeText` and is applied over the whole string — so the last symbol
    // here is 'A' and all five of its bits are pad.
    try t.expectEqual(@as(u8, 'A'), symbols[symbols.len - 1]);
    symbols[symbols.len - 1] = 'B';
    try t.expectError(error.NonZeroBase32Padding, EndpointTicket.decodeString(t.allocator, text));
}

test "trailing bytes after the body are refused" {
    const alloc = t.allocator;
    // One byte past the vector, so the byte this test adds past the body has
    // somewhere to land.
    var body: [golden_hex.len / 2 + 1]u8 = undefined;
    _ = try std.fmt.hexToBytes(body[0 .. golden_hex.len / 2], golden_hex);
    body[60] = 0x00;

    const decoded = EndpointTicket.decodeBytes(alloc, body[0..61]);
    try t.expectError(error.TrailingBytes, decoded);

    // The same through the text form: two more symbols are one more zero
    // byte, so the length stays legal and the failure is the one under test.
    var text: [128]u8 = undefined;
    @memcpy(text[0..golden_ticket.len], golden_ticket);
    text[golden_ticket.len] = 'a';
    text[golden_ticket.len + 1] = 'a';
    try t.expectError(
        error.TrailingBytes,
        EndpointTicket.decodeString(alloc, text[0 .. golden_ticket.len + 2]),
    );
}

test "a truncated body is refused" {
    const alloc = t.allocator;
    var bytes: [golden_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, golden_hex);

    // Cut inside a fixed-width field, or at the very end of the frame, and it
    // simply stops: `UnexpectedEnd`. Cut just after the address count and the
    // frame is not short — it claims two addresses and does not hold them,
    // which is `BadLength`, and is why the two are separate members of
    // `postcard.Error`.
    for ([_]usize{ 0, 1, 8, 20, 32, 33, 59 }) |length| {
        try t.expectError(error.UnexpectedEnd, EndpointTicket.decodeBytes(alloc, bytes[0..length]));
    }
    for ([_]usize{ 34, 35, 40, 50 }) |length| {
        try t.expectError(error.BadLength, EndpointTicket.decodeBytes(alloc, bytes[0..length]));
    }
}

test "a wire variant this build has no arm for is refused" {
    const alloc = t.allocator;
    var body: [golden_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&body, golden_hex);
    body[0] = 0x01;
    try t.expectError(error.UnknownTicketVariant, EndpointTicket.decodeBytes(alloc, &body));
}

test "an address list longer than the body is refused" {
    const alloc = t.allocator;
    var body: [golden_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&body, golden_hex);
    // The count is at offset 33. A peer may name any `u64` it likes and the
    // bytes behind it do not have to exist.
    body[33] = 0xff;
    body[34] = 0xff;
    body[35] = 0xff;
    body[36] = 0x7f;
    try t.expectError(error.BadLength, EndpointTicket.decodeBytes(alloc, &body));
}

test "a custom transport survives an endpoint ticket" {
    const alloc = t.allocator;
    var storage: [addr.max_inline_length]u8 = undefined;

    const id = try NodeId.parseHex(golden_id_hex);
    var address = try NodeAddr.withRelay(alloc, id, try RelayUrl.parse("https://a.example./"));
    const socket: SocketAddr = .{ .ip = .{ .v4 = .{ 192, 0, 2, 7 } }, .port = 41641 };
    address = (try address.insert(alloc, .{ .ip = socket })) orelse
        return error.TestUnexpectedResult;
    const transport = try CustomAddr.parse("2a_abab", &storage);
    address = (try address.insert(alloc, .{ .custom = transport })) orelse
        return error.TestUnexpectedResult;
    defer address.deinit(alloc);
    const ticket = EndpointTicket.new(address);

    var body: [128]u8 = undefined;
    const bytes = try ticket.encode(&body);
    var text: [256]u8 = undefined;
    const written = try ticket.encodeString(bytes, &text);

    const decoded = try EndpointTicket.decodeString(alloc, written);
    defer decoded.deinit(alloc);

    try t.expectEqual(@as(usize, 3), decoded.ticket.addr.addrs.len);
    const custom = decoded.ticket.addr.addrs[2];
    try t.expectEqual(TransportAddr.custom, std.meta.activeTag(custom));
    try t.expectEqual(@as(u64, 0x2a), custom.custom.id);
    try t.expectEqualSlices(u8, &.{ 0xab, 0xab }, custom.custom.data);

    // `EndpointTicket` is lossless, which is the whole difference from a blob
    // ticket: a re-encode is the same bytes.
    var again: [128]u8 = undefined;
    try t.expectEqualSlices(u8, bytes, try decoded.ticket.encode(&again));
}

test "a custom payload longer than a CustomAddr holds is refused" {
    const alloc = t.allocator;
    var body: [128]u8 = undefined;
    var writer = postcard.Writer.init(&body);
    try writer.writeVariant(WireVariant.variant1);
    try writeNodeId(&writer, try NodeId.parseHex(golden_id_hex));
    try writer.writeLen(1);
    try writer.writeVariant(TransportTag.custom);
    try writer.writeU64(1);
    try writer.writeBytes(&[_]u8{0xaa} ** (addr.max_inline_length + 1));

    try t.expectError(error.CustomAddrTooLong, EndpointTicket.decodeBytes(alloc, writer.finish()));
}

test "a relay url the address layer will not take is refused" {
    const alloc = t.allocator;
    var body: [128]u8 = undefined;
    var writer = postcard.Writer.init(&body);
    try writer.writeVariant(WireVariant.variant1);
    try writeNodeId(&writer, try NodeId.parseHex(golden_id_hex));
    try writer.writeLen(1);
    try writer.writeVariant(TransportTag.relay);
    try writer.writeStr("not a url");

    try t.expectError(error.BadRelayUrl, EndpointTicket.decodeBytes(alloc, writer.finish()));
}

test "an endpoint id that is not a point is refused" {
    const alloc = t.allocator;
    var body: [128]u8 = undefined;
    _ = try std.fmt.hexToBytes(body[0 .. golden_hex.len / 2], golden_hex);
    @memset(body[1..33], 0xff);
    try t.expectError(error.NotANodeId, EndpointTicket.decodeBytes(alloc, &body));
}

test "maxEncodedLength bounds every encoding this module writes" {
    const alloc = t.allocator;
    var storage: [addr.max_inline_length]u8 = undefined;
    const id = try NodeId.parseHex(golden_id_hex);

    var address = try NodeAddr.withRelay(alloc, id, try RelayUrl.parse("https://a.example./"));
    const socket: SocketAddr = .{ .ip = .{ .v6 = [_]u8{ 0x20, 0x01 } ** 8 }, .port = 65535 };
    address = (try address.insert(alloc, .{ .ip = socket })) orelse
        return error.TestUnexpectedResult;
    const custom = try CustomAddr.parse(
        "ffffffffffffffff_00112233445566778899aabbccddeeff",
        &storage,
    );
    address = (try address.insert(alloc, .{ .custom = custom })) orelse
        return error.TestUnexpectedResult;
    defer address.deinit(alloc);

    const ticket = EndpointTicket.new(address);
    var body: [1024]u8 = undefined;
    const bytes = try ticket.encode(&body);
    try t.expect(bytes.len <= ticket.maxEncodedLength());
    try t.expect(ticket.maxEncodedLength() < body.len);
}

test "encodeString refuses a buffer it cannot fill" {
    const alloc = t.allocator;
    const address = try goldenAddr(alloc);
    defer address.deinit(alloc);
    const ticket = EndpointTicket.new(address);
    var body: [64]u8 = undefined;
    const bytes = try ticket.encode(&body);

    var text: [128]u8 = undefined;
    try t.expectError(
        error.BufferFull,
        ticket.encodeString(bytes, text[0 .. golden_ticket.len - 1]),
    );
}

test "a decoded address list is sorted and duplicate-free whatever order it arrives in" {
    const alloc = t.allocator;
    // Four addresses, the two from the golden vector twice over and out of
    // order. postcard reads a `BTreeSet` by inserting, so a peer that sends
    // this gets the same two addresses upstream would have built, and the
    // re-encode is the captured spelling rather than this one.
    var body: [128]u8 = undefined;
    var writer = postcard.Writer.init(&body);
    try writer.writeVariant(WireVariant.variant1);
    try writeNodeId(&writer, try NodeId.parseHex(golden_id_hex));
    try writer.writeLen(4);
    const ip: SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 1024 };
    const relay: RelayUrl = try RelayUrl.parse("http://derp.me./");
    try writeTransportAddr(&writer, .{ .ip = ip });
    try writeTransportAddr(&writer, .{ .relay = relay });
    try writeTransportAddr(&writer, .{ .relay = relay });
    try writeTransportAddr(&writer, .{ .ip = ip });

    const decoded = try EndpointTicket.decodeBytes(alloc, writer.finish());
    defer decoded.deinit(alloc);
    try t.expectEqual(@as(usize, 2), decoded.ticket.addr.addrs.len);
    try t.expectEqual(TransportAddr.relay, std.meta.activeTag(decoded.ticket.addr.addrs[0]));
    try t.expectEqual(TransportAddr.ip, std.meta.activeTag(decoded.ticket.addr.addrs[1]));

    var again: [64]u8 = undefined;
    try expectHexEqual(golden_hex, try decoded.ticket.encode(&again));
}
