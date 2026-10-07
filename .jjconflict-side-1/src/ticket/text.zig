//! The text form of a ticket: the string a human pastes into a chat.
//!
//! A port of `iroh-tickets` 1.0.0, `src/lib.rs`, at commit
//! `cec7f1e119003980f238819e0f320ccb0ceaa691`, fetched 2026-09-30, read
//! through the `Ticket` trait it declares there. Upstream puts the kind
//! prefix, the alphabet, the length arithmetic and the error set in that
//! trait and lets each kind supply only `KIND`, `encode_bytes` and
//! `decode_bytes`; Zig has no traits, and ozai has no module to put the trait
//! in, so the half both kinds share lives here and `endpoint_ticket.zig`
//! re-exports it.
//!
//! # The order the text form is built in
//!
//! `encodeText` is the kind prefix, then unpadded base32 of the body, and the
//! *whole string* lower cased **after** the two are concatenated. Upstream is
//! `Self::KIND.to_string()`, then `encode_append`, then
//! `out.make_ascii_lowercase()`. The order is load bearing in one direction
//! only, and it is the direction that breaks: base32 emits upper case, so a
//! ticket whose body was left alone is a ticket whose body is upper case. A
//! peer still reads it — `decodeBase32` upper-cases before decoding — but it is
//! a second spelling of one value, which is the thing
//! `docs/ARCHITECTURE.md` invariant 2 exists to prevent. `encodeText` takes
//! the kind as a `comptime` parameter and refuses a prefix that is not lower
//! case, so the only lower casing that can happen is the one over the whole
//! string, and that is the one the tests pin.
//!
//! # The alphabet is not `base/base32.zig`'s
//!
//! Upstream emits `data_encoding::BASE32_NOPAD`, and this is that alphabet:
//! upper case, unpadded, with the length as a value rather than a type
//! parameter. The two alphabets in `base/base32.zig` are sized at comptime,
//! which a node id wants and a ticket cannot use, since the body of a ticket
//! is however many bytes the address list made it. This is the same bit packer
//! with the length as a value.
//!
//! # The error sets, and why both are here
//!
//! `TextError` and `BodyError` are upstream's one `ParseError` split by where
//! the refusal happens: `TextError` names a string that is not a ticket of
//! this kind, `BodyError` a body this build will not take. They are declared
//! together because they are one vocabulary — `DecodeError` is their union,
//! and `body.zig` returns `BodyError` from its own field readers — so a split
//! across the two modules would make the whole refusal vocabulary of a ticket
//! readable only by following an import.
//!
//! Nothing here knows what a ticket holds; `body.zig` does, and the dependency
//! runs one way. No clock, no environment, no global.
const std = @import("std");

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
