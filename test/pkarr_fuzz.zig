//! Fuzz target for the pkarr packet decoder, the signable form, and the two
//! signature checks.
//!
//! One target file and one corpus directory per decoder: `zig build fuzz`
//! replays the corpus, and `zig build fuzz --fuzz=<N>` hands the same corpus
//! to Zig's coverage-guided fuzzer and lets it mutate for N iterations. A
//! decoder is only worth this once the same bytes have been shown not to
//! panic, and a pkarr packet is the first thing in discovery whose every
//! field arrives verbatim from a stranger's HTTP response.

const std = @import("std");
const ozai = @import("ozai");
const pkarr = ozai.pkarr;
const t = std.testing;

/// Seeds are the raw bytes a relay or a DHT peer would hand over. The first
/// four are the shapes the decoder's own errors name, and the last three are
/// packets the reference `pkarr` crate produced: `captured` is its 213-byte
/// output, `at_max_size` is a packet of exactly `max_packet_length`, and
/// `bad_public_key` is `at_max_size`'s header with its key replaced by 32
/// bytes that are not a curve point. `test/corpus/pkarr/` is the record, and
/// a file there is live only once it is named here.
const corpus = [_][]const u8{
    @embedFile("corpus/pkarr/empty"), // 0 bytes: no header at all
    @embedFile("corpus/pkarr/short_header"), // 103 bytes: one short of a header
    @embedFile("corpus/pkarr/header_only"), // a header with no body at all
    @embedFile("corpus/pkarr/over_cap"), // 1105 bytes: one over the cap
    @embedFile("corpus/pkarr/captured"), // a real 213-byte packet
    @embedFile("corpus/pkarr/at_max_size"), // a real 1104-byte packet
    @embedFile("corpus/pkarr/bad_public_key"), // a header that is not a key
};

/// Long enough to overrun the cap, so a mutated input can still reach the
/// length check it was not grown for, and short enough that the signable
/// form and the re-encoding both fit the fuzzer's stack.
const input_buffer_len = 1200;

/// A node nobody in this file is a packet from, so `verify` against it has to
/// be a different answer from `verify` against the packet's own key.
const other_seed = [_]u8{8} ** ozai.SecretKey.seed_length;

comptime {
    // A seed longer than the window the fuzzer reads into would be cut short
    // on its way to the oracle, and the length check would never see the rest.
    for (corpus) |seed| std.debug.assert(seed.len <= input_buffer_len);
}

/// The fuzzer keeps one of these by pointer for the whole run, so it is empty
/// by design: everything the oracle needs is comptime.
const Context = struct {};

test "pkarr packet decode" {
    // A fuzz test is a plain test to a plain build. Without `-ffuzz` the runner
    // walks the corpus instead of handing it to the fuzzer, which is what makes
    // a bare `zig build fuzz` a bounded gate rather than an empty step.
    try t.fuzz(Context{}, testOne, .{ .corpus = &corpus });
}

test "pkarr oracle permits correct field boundary rejections" {
    // Only the sign bit is outside y; p and p+1 remain noncanonical for either sign.
    const prime: u256 = (@as(u256, 1) << 255) - 19;
    const boundaries = [_]struct { y: u256, canonical: bool }{
        .{ .y = prime - 1, .canonical = true },
        .{ .y = prime, .canonical = false },
        .{ .y = prime + 1, .canonical = false },
    };
    for (boundaries) |boundary| {
        for ([_]u8{ 0, 0x80 }) |sign_bit| {
            var bytes = [_]u8{0} ** (pkarr.header_length + 1);
            std.mem.writeInt(u256, bytes[0..32], boundary.y, .little);
            bytes[31] |= sign_bit;
            if (boundary.canonical) {
                const packet = try pkarr.Packet.parse(&bytes);
                try t.expectEqualSlices(u8, bytes[pkarr.header_length..], packet.dns);
            } else {
                try t.expectError(error.BadPublicKey, pkarr.Packet.parse(&bytes));
            }
            try check(&bytes);
        }
    }
}

fn testOne(_: Context, smith: *t.Smith) anyerror!void {
    var buffer: [input_buffer_len]u8 = undefined;
    // `in` is the corpus entry verbatim while the corpus is replayed, and null
    // when the fuzzer drives, in which case `slice` consumes its input.
    const bytes = if (smith.in) |replay| replay else buffer[0..smith.slice(&buffer)];
    try check(bytes);
}

/// Three oracles over one decode.
fn check(bytes: []const u8) !void {
    const packet = pkarr.Packet.parse(bytes) catch |err| {
        // Oracle: cause. A rejection is legal only where the lengths or the
        // key itself condemn the bytes, and for the reason named.
        if (condemn(bytes)) |reason| {
            try t.expectEqual(reason, err);
            return;
        }
        return error.ValidPacketRejected;
    };

    // Oracle: extent. An accepted packet's body is the tail of its input and
    // is inside the cap, so a length is never read from one place and reported
    // as another.
    try t.expectEqual(bytes.len, pkarr.header_length + packet.dns.len);
    try t.expect(packet.dns.len <= pkarr.max_dns_length);
    try t.expectEqualSlices(u8, bytes[pkarr.header_length..], packet.dns);

    // Oracle: fidelity. The re-encoding of a decoded packet is the packet, so
    // a decode cannot quietly drop a byte, reorder the header or re-spell the
    // timestamp's endianness.
    var out: [pkarr.max_packet_length]u8 = undefined;
    const reencoded = try packet.encode(&out);
    try t.expectEqualSlices(u8, bytes, reencoded);

    try checkSignable(packet);
    try checkVerify(bytes, packet);
}

/// The signable form is the BEP-0044 prefix over this packet's own timestamp
/// and body, and nothing else. The prefix is recomputed here rather than read
/// back out of `signableForm`, so an oracle copied from the code under test
/// agrees with the bug it is meant to catch.
fn checkSignable(packet: pkarr.Packet) !void {
    var scratch: [pkarr.max_signable_length]u8 = undefined;
    const signable = try packet.signable(&scratch);

    var expected: [pkarr.max_signable_length]u8 = undefined;
    const prefix = try std.fmt.bufPrint(&expected, "3:seqi{d}e1:v{d}:", .{
        packet.timestamp,
        packet.dns.len,
    });
    try t.expectEqualSlices(u8, prefix, signable[0..prefix.len]);
    try t.expectEqualSlices(u8, packet.dns, signable[prefix.len..]);
    // The bound is a promise about length, not about content.
    try t.expect(signable.len <= pkarr.max_signable_length);
}

/// The two checks, against each other, and against the bytes the packet came
/// from.
fn checkVerify(bytes: []const u8, packet: pkarr.Packet) !void {
    const other = (try ozai.SecretKey.fromSeed(other_seed)).nodeId();
    if (packet.public_key.order(other) == .eq) return error.OtherKeyIsThisKey;

    // Oracle: which node. `verify` adds the question of who the caller was
    // asking about to the question of who signed, so against a different key
    // it has one answer, and that answer is not a signature failure — the
    // distinction upstream has no error for.
    try t.expectError(error.WrongSigner, packet.verify(other));

    // Oracle: agreement. Named against the packet's own key the two entry
    // points ask the same question, so they must reach the same verdict.
    try t.expectEqual(
        verdict(packet.verifySelf()),
        verdict(packet.verify(packet.public_key)),
    );

    // Oracle: the signable form is a different message from the packet. A
    // signature covering one cannot cover the other, and a check that accepted
    // both would be accepting anything. This is invariant 11 held against
    // every packet the fuzzer finds.
    packet.verifySelf() catch |err| {
        try t.expectEqual(pkarr.VerifyError.BadSignature, err);
        packet.signature.verify(bytes, packet.public_key) catch |raw_err| {
            try t.expectEqual(ozai.KeyError.BadSignature, raw_err);
            return;
        };
        return error.RawBytesVerified;
    };
}

/// A check's outcome as a value, so two checks can be compared rather than
/// each run and thrown away.
fn verdict(result: anyerror!void) ?anyerror {
    if (result) |_| return null else |err| return err;
}

/// Why `bytes` is not a packet, or null when it is one.
///
/// Both the lengths and the key are recomputed rather than read back out of
/// the decoder, so this oracle fails in a different way from the code it is
/// checking: an oracle copied from `parse` would agree with the bug it is
/// meant to catch.
fn condemn(bytes: []const u8) ?pkarr.Error {
    if (bytes.len < pkarr.header_length) return error.TooShort;
    if (bytes.len > pkarr.max_packet_length) return error.TooLarge;
    if (!isCanonicalPoint(bytes[0..pkarr.signature_offset])) return error.BadPublicKey;
    return null;
}

/// Whether 32 little-endian bytes could be an ed25519 public key.
///
/// An ed25519 point encoding is a little-endian `y` below the field prime
/// `p = 2^255 - 19`, with the top bit of the last byte carrying the sign of
/// `x`. So the test is: clear that bit, and the remaining value is below `p`.
/// This is the rule `NodeId.fromBytes` applies, written out here so the
/// oracle does not ask the code under test what it thinks.
fn isCanonicalPoint(key_bytes: []const u8) bool {
    const prime: u256 = (@as(u256, 1) << 255) - 19;
    var y = std.mem.readInt(u256, key_bytes[0..32], .little);
    y &= (@as(u256, 1) << 255) - 1; // The sign bit of `x` sits above every bit of `y`.
    return y < prime;
}
