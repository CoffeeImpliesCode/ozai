//! Fuzz target for the two base32 decoders.
//!
//! One target file and one corpus directory per decoder: `zig build fuzz`
//! replays the corpus, and `zig build fuzz --fuzz=<N>` hands the same corpus to
//! Zig's coverage-guided fuzzer and lets it mutate for N iterations. Later
//! milestones add a sibling of this pair per decoder, not a second harness.

const std = @import("std");
const ozai = @import("ozai");
const base32 = ozai.base32;
const t = std.testing;

/// Seeds are the raw text a decoder is handed, byte for byte: length is the
/// first thing `decode` looks at, so a seed one symbol short is a case rather
/// than a typo. `test/corpus/<decoder>/` is the record, and a file there is
/// live only once it is named here.
const corpus = [_][]const u8{
    @embedFile("corpus/base32/empty"), // 0 bytes: nothing to decode
    @embedFile("corpus/base32/one_byte"), // 1 byte: a symbol with no peers
    @embedFile("corpus/base32/zeros_z32"), // 52 'y', the 32-byte zero key
    @embedFile("corpus/base32/wrong_length"), // 51 'y': one short of 52
    @embedFile("corpus/base32/iroh_tls_name"), // upstream golden vector
    @embedFile("corpus/base32/bad_symbol"), // 52 '0': in neither alphabet
};

/// Byte counts ozai decodes. A NodeId is 32, whose trailing pad is four bits
/// wide; 1 and 31 leave two, the other shape a padding bug would hide in.
const sizes = [_]usize{ 1, 31, 32 };

const alphabets = [_]base32.Alphabet{ base32.z32, base32.dnssec };

/// Long enough to overrun every `encodedLen` below, so a mutated input can
/// still reach a length check it was not grown for.
const input_buffer_len = 64;

comptime {
    // A seed longer than the window the fuzzer reads into would be cut short on
    // its way to the oracle, and the length check would never see the rest.
    for (corpus) |seed| std.debug.assert(seed.len <= input_buffer_len);
}

/// The fuzzer keeps one of these by pointer for the whole run, so it is empty
/// by design: everything the oracle needs is comptime.
const Context = struct {};

test "base32 decode" {
    // A fuzz test is a plain test to a plain build. Without `-ffuzz` the runner
    // walks the corpus instead of handing it to the fuzzer, which is what makes
    // a bare `zig build fuzz` a bounded gate rather than an empty step.
    try t.fuzz(Context{}, testOne, .{ .corpus = &corpus });
}

fn testOne(_: Context, smith: *t.Smith) anyerror!void {
    var buffer: [input_buffer_len]u8 = undefined;
    // `in` is the corpus entry verbatim while the corpus is replayed, and null
    // when the fuzzer drives, in which case `slice` consumes its input.
    const text = if (smith.in) |replay| replay else buffer[0..smith.slice(&buffer)];
    inline for (sizes) |n| {
        inline for (alphabets) |alphabet| {
            try check(alphabet, n, text);
        }
    }
}

/// Three oracles over one decode.
///
/// The cause oracle recomputes the verdict from the alphabet rather than
/// reading it back out of the decoder, so the two fail in different ways: an
/// oracle copied from the code under test agrees with the bug it is meant to
/// catch.
fn check(comptime alphabet: base32.Alphabet, comptime n: usize, text: []const u8) !void {
    const decoded = base32.decode(alphabet, n, text);
    if (decoded) |bytes| {
        // Oracle: length. Only the length can make a text illegal, so an
        // accepted one carries the exact symbol count.
        try t.expectEqual(base32.encodedLen(n), text.len);
        // Oracle: spelling. A key has the one name this alphabet emits, and an
        // alphabet that folds case on the way in folds it on the way out too,
        // rather than echoing back a spelling the encoder would never write.
        var folded: [input_buffer_len]u8 = undefined;
        _ = std.ascii.lowerString(&folded, text);
        const spelling = if (alphabet.case_insensitive) folded[0..text.len] else text;
        try t.expectEqualStrings(&base32.encode(alphabet, n, &bytes), spelling);
        // Oracle: fidelity. The bytes are what the text said, in both
        // directions, so a decode cannot quietly lose the low bits.
        const re_encoded = base32.encode(alphabet, n, &bytes);
        const re_decoded = try base32.decode(alphabet, n, &re_encoded);
        try t.expectEqualSlices(u8, &bytes, &re_decoded);
    } else |err| {
        // Oracle: cause. A rejection is legal only where the alphabet and the
        // trailing pad bits condemn the text, and for the reason named.
        if (condemn(alphabet, n, text)) |reason| {
            try t.expectEqual(reason, err);
        } else {
            return error.ValidTextRejected;
        }
    }
}

/// Why `text` is not the encoding of `n` bytes, or null when it is one.
fn condemn(
    comptime alphabet: base32.Alphabet,
    comptime n: usize,
    text: []const u8,
) ?base32.DecodeError {
    if (text.len != base32.encodedLen(n)) return error.InvalidLength;
    const table = comptime symbolTable(alphabet);
    // The pad sits below the last symbol, and there is one: past the length
    // check above, `text` is exactly `encodedLen(n)` symbols long, and
    // `encodedLen` is `ceil(n * 8 / 5)` over sizes that all exceed one. The
    // scan hands that symbol over, so the read below needs no index first
    // proved non-negative. The empty seed in the corpus is condemned as a
    // wrong length above, never as an underflow here.
    var last: u8 = absent;
    for (text) |c| {
        if (table[c] == absent) return error.InvalidSymbol;
        last = c;
    }
    // What the last symbol leaves below the byte boundary is padding, and the
    // encoder left-aligns the real bits above it, so a set bit down there means
    // the text came from somewhere else.
    const pad_bits: u3 = @intCast((5 * base32.encodedLen(n)) % 8);
    const pad_mask: u5 = (@as(u5, 1) << pad_bits) - 1;
    if (table[last] & pad_mask != 0) return error.NonZeroPadding;
    return null;
}

const absent: u8 = 0xff;

/// A 256-entry reverse index of the alphabet, one of which this crate builds
/// and the other of which the decoder does not get to see.
fn symbolTable(comptime alphabet: base32.Alphabet) [256]u8 {
    comptime var table = [_]u8{absent} ** 256;
    inline for (alphabet.symbols.*, 0..) |symbol, i| {
        table[symbol] = @intCast(i);
        if (alphabet.case_insensitive) {
            table[std.ascii.toLower(symbol)] = @intCast(i);
            table[std.ascii.toUpper(symbol)] = @intCast(i);
        }
    }
    return table;
}
