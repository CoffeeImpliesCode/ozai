//! The two base32 alphabets the ozai wire formats depend on.
//!
//! `z32` is the pkarr DNS-label alphabet from BEP-0044. `dnssec` is the RFC 4648
//! alphabet, emitted lowercase, used for the local TLS server name. The alphabets
//! differ and so do their case rules, so they are two instantiations of one bit
//! packer rather than one alphabet with a flag.

const std = @import("std");

/// A base32 alphabet: 32 distinct symbols and the case rule for decoding.
///
/// The symbols are the encoding, so they have to be distinct: a repeat would
/// give one symbol two values and make `decode` lossy in a way nothing
/// downstream could see. Both alphabets here are 32 ASCII bytes.
pub const Alphabet = struct {
    /// The 32 symbols, in value order: symbol `i` is the five-bit value `i`.
    symbols: *const [32]u8,
    /// z-base-32 is case-sensitive; RFC 4648 base32 in DNS labels is not.
    /// A `false` here is what makes an upper-case z32 label a different text
    /// rather than a second spelling of one key.
    case_insensitive: bool,
};

/// pkarr (BEP-0044) label alphabet.
pub const z32: Alphabet = .{
    .symbols = "ybndrfg8ejkmcpqxot1uwisza345h769",
    .case_insensitive = false,
};

/// Hex-extended base32, emitted lowercase so it is a legal DNS label, and
/// case-insensitive on the way in. This is the alphabet iroh's TLS server name
/// uses, and it is *not* RFC 4648: the digits run 0-9 rather than 2-7, which is
/// what lets a key survive a DNS label without a lookalike transposition.
pub const dnssec: Alphabet = .{
    .symbols = "0123456789abcdefghijklmnopqrstuv",
    .case_insensitive = true,
};

/// Encoded length of `n` bytes: ceil(n * 8 / 5). Neither alphabet pads.
///
/// Zero is a value: `n == 0` is the empty string, and `decode` accepts it.
/// `encode` does not, because the packer has no symbol to write for it; see
/// that function.
pub fn encodedLen(comptime n: usize) usize {
    return (n * 8 + 4) / 5;
}

/// `bytes` in `alphabet`, as exactly `encodedLen(n)` symbols, returned by
/// value with no allocation and no borrow of the input.
///
/// `n` must be greater than zero: a comptime assertion refuses the empty
/// input. `decode` carries no such assertion, so `decode(alphabet, 0, "")` is
/// a legal call and returns no bytes; nothing in this module makes one, and
/// every encoding here is a fixed-width key or label.
pub fn encode(
    comptime alphabet: Alphabet,
    comptime n: usize,
    bytes: *const [n]u8,
) [encodedLen(n)]u8 {
    comptime std.debug.assert(n > 0);

    var out: [encodedLen(n)]u8 = undefined;
    var accumulator: u32 = 0;
    var bits: u4 = 0;
    var index: usize = 0;

    for (bytes) |byte| {
        accumulator = (accumulator << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out[index] = alphabet.symbols[@intCast((accumulator >> bits) & 0x1f)];
            index += 1;
        }
        // Drop what was already emitted so the accumulator cannot grow past the
        // bits still owed to the next symbol.
        accumulator &= (@as(u32, 1) << bits) - 1;
    }

    // Fewer than 5 bits remain. Left-align them; the decoder rejects a
    // non-zero pad, which would otherwise give one key two spellings.
    if (bits > 0) {
        out[index] = alphabet.symbols[@intCast((accumulator << @intCast(5 - bits)) & 0x1f)];
        index += 1;
    }
    std.debug.assert(index == out.len);
    return out;
}

/// Everything a decode of one of these alphabets refuses.
///
/// The three are checked in this order — length, then symbols, then the
/// padding — so a text that breaks more than one rule is named for the first
/// it breaks, and a caller does not have to guess which rule took precedence.
pub const DecodeError = error{
    /// Wrong length. Both alphabets are unpadded, so the length is exact: not
    /// a shorter prefix and not a longer text with a usable prefix.
    InvalidLength,
    /// A character outside the alphabet, under the alphabet's own case rule:
    /// an upper-case symbol is one here and a different one in z-base-32.
    InvalidSymbol,
    /// The final symbol carried bits beyond the byte boundary. Encoding always
    /// emits zero there, so a non-zero pad means the text was not produced by
    /// this encoder — and accepting it would give one key two spellings.
    NonZeroPadding,
};

/// `text` as exactly `n` bytes, returned by value; nothing is allocated and
/// the result borrows nothing, so `text` may be released on return.
///
/// `text.len` must equal `encodedLen(n)`: the length is checked first, so a
/// text of the wrong length is `error.InvalidLength` whatever else is wrong
/// with it. `n` may be zero, in which case `text` must be empty.
///
/// Every remaining byte of the result is written before this returns; on any
/// error there is no result and `text` is untouched.
pub fn decode(
    comptime alphabet: Alphabet,
    comptime n: usize,
    text: []const u8,
) DecodeError![n]u8 {
    if (text.len != encodedLen(n)) return error.InvalidLength;

    var out: [n]u8 = undefined;
    var accumulator: u32 = 0;
    var bits: u4 = 0;
    var index: usize = 0;

    for (text) |c| {
        const symbol = decodeSymbol(alphabet, c) orelse return error.InvalidSymbol;
        accumulator = (accumulator << 5) | symbol;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            out[index] = @truncate(accumulator >> bits);
            index += 1;
        }
        accumulator &= (@as(u32, 1) << bits) - 1;
    }

    std.debug.assert(bits < 8);
    if (bits > 0 and accumulator != 0) return error.NonZeroPadding;
    std.debug.assert(index == n);
    return out;
}

fn decodeSymbol(comptime alphabet: Alphabet, c: u8) ?u5 {
    inline for (alphabet.symbols.*, 0..) |symbol, i| {
        if (c == symbol) return @intCast(i);
        if (alphabet.case_insensitive and
            std.ascii.toLower(c) == std.ascii.toLower(symbol)) return @intCast(i);
    }
    return null;
}

const t = std.testing;

// iroh publishes this label as the TLS server name for an all-zero secret key.
// It pins both the alphabet and the lowercase convention, so a drift in either
// breaks interoperability before anything else does.
test "dnssec base32 round trips the iroh tls-name vector" {
    const label = "7dl2ff6emqi2qol3l382krodedij45bn3nh479hqo14a32qpr8kg";
    try t.expectEqual(@as(usize, 52), label.len);
    const bytes = try decode(dnssec, 32, label);
    try t.expectEqualStrings(label, &encode(dnssec, 32, &bytes));
}

test "base32 round trips every length one through four" {
    inline for (.{ 1, 2, 3, 4, 5, 31, 32, 33, 64 }) |n| {
        var bytes: [n]u8 = undefined;
        for (&bytes, 0..) |*byte, i| byte.* = @truncate(@as(usize, i) *% 37 +% 11);
        const round = try decode(z32, n, &encode(z32, n, &bytes));
        try std.testing.expectEqualSlices(u8, &bytes, &round);
    }
}

test "z-base-32 rejects a bad symbol" {
    // '0' is in neither alphabet.
    try std.testing.expectError(
        error.InvalidSymbol,
        decode(z32, 32, "0" ** 52),
    );
}

test "z-base-32 rejects a wrong length" {
    try std.testing.expectError(error.InvalidLength, decode(z32, 32, "y" ** 51));
    try std.testing.expectError(error.InvalidLength, decode(z32, 32, "y" ** 53));
}

test "decode rejects non-zero padding bits" {
    // 32 bytes need 52 symbols; the last carries 4 real bits and 1 pad bit.
    // 'y' is symbol 0, so swap in a symbol whose low bit is set.
    var text = encode(z32, 32, &([_]u8{0} ** 32));
    text[text.len - 1] = 'b';
    try std.testing.expectError(error.NonZeroPadding, decode(z32, 32, &text));
}

test "dnssec base32 accepts either case and emits lower" {
    const bytes = [_]u8{0xfb} ** 32;
    const lower = encode(dnssec, 32, &bytes);
    for (lower) |c| try t.expect(std.ascii.isLower(c) or std.ascii.isDigit(c));

    const decoded = try decode(dnssec, 32, &lower);
    try t.expectEqualSlices(u8, &bytes, &decoded);

    var upper: [lower.len]u8 = undefined;
    _ = std.ascii.upperString(&upper, &lower);
    const decoded_upper = try decode(dnssec, 32, &upper);
    try t.expectEqualSlices(u8, &bytes, &decoded_upper);
}

test "z-base-32 is case sensitive" {
    const bytes = [_]u8{0xff} ** 32;
    const text = encode(z32, 32, &bytes);
    var upper: [text.len]u8 = undefined;
    _ = std.ascii.upperString(&upper, &text);
    try t.expectError(error.InvalidSymbol, decode(z32, 32, &upper));
}
