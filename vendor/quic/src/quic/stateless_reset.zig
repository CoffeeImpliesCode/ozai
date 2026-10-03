//! Stateless reset tokens and the reset packet that carries one (RFC 9000
//! §10.3).
//!
//! Everything here is a fixed-size computation: no allocator, no clock, no
//! global key. The static key is a parameter, so the caller holds both it and
//! the generator used for the reset packet's noise, and neither is retained.
//! `Connection` derives its own token with `computeToken` and
//! `connection_manager` recognises a peer's with `isStatelessReset`.

const std = @import("std");
const crypto = std.crypto;
const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;

/// Bytes in a stateless reset token, and the length of the fixed token buffer
/// every function here takes or returns. RFC 9000 §10.3 fixes it at 16.
pub const TOKEN_LEN: usize = 16;

/// Shortest packet that can carry a reset: a 1-byte short header, at least 4
/// bytes of noise so it does not look like a Retry, and the 16-byte token.
/// `generatePacket` refuses to write less and `isStatelessReset` refuses to
/// look at less, so a packet shorter than this is never mistaken for a reset.
///
pub const MIN_PACKET_LEN: usize = 21; // RFC 9000 §10.3: at least 1 byte header + 4 random + 16 token

/// `HMAC-SHA256(static_key, conn_id)` truncated to its first 16 bytes, which
/// is `TOKEN_LEN`. The result is deterministic in its two arguments and is
/// returned by value: it borrows nothing, allocates nothing, and the same
/// `static_key` and `conn_id` always produce the same 16 bytes. That is what
/// lets a peer be recognised from a token alone, and it means `static_key` is
/// secret material whose disclosure lets anyone forge resets for the
/// connections it covers.
pub fn computeToken(static_key: [16]u8, conn_id: []const u8) [TOKEN_LEN]u8 {
    var mac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&mac, conn_id, &static_key);
    return mac[0..TOKEN_LEN].*;
}

/// Generate a stateless reset packet (RFC 9000 §10.3) into `out` and return
/// its length.
///
/// Format: random header bytes (looks like short header) + stateless_reset_token as last 16 bytes.
/// Returns the number of bytes written, or 0 if max_size is too small.
///
/// The packet is `min(max_size, out.len)` bytes long, so `out` bounds it as
/// well as `max_size` does and neither is an error to exceed. On the 0 path
/// `out` is left exactly as the caller passed it — nothing is drawn and
/// nothing is written, because a packet shorter than `MIN_PACKET_LEN` is
/// rejected before the generator is touched. On a non-zero return the whole
/// of `out[0..n]` is written, the long-header bit is cleared and the fixed bit
/// set on the first byte, and `out[n - TOKEN_LEN .. n]` is
/// `computeToken(static_key, conn_id)`. The caller owns the bytes and must
/// keep `out` alive for as long as it holds that slice; nothing is retained.
///
/// `random` fills the bytes in front of the token and is read nowhere else. The
/// token is the unforgeable part, and it is not drawn here at all: it is
/// HMAC(static_key, conn_id), so a third party cannot compute one for a
/// connection whose static key it does not have. These bytes are the other half
/// of that promise (RFC 9000 §10.3.3) — the noise that lets a reset pass as
/// traffic and keeps a blind attacker from synthesising one. So they must be
/// unpredictable in production; a fixed pattern would hand back the off-path DoS
/// the reset exists to stop. The draw is a parameter, not a global, so a weak
/// source cannot be substituted silently: `std.Random` has no null that means
/// "skip it", there is no fallback that quietly reaches for the process CSPRNG,
/// and the caller that holds the CSPRNG has to name it. A test names a seeded
/// one, which is the only way the round trip below can assert on the bytes it
/// produced.
///
/// This is synchronous and reentrant-free: it allocates nothing, blocks on
/// nothing, and touches only `out` and the caller's own generator.
pub fn generatePacket(
    out: []u8,
    max_size: usize,
    static_key: [16]u8,
    conn_id: []const u8,
    random: std.Random,
) usize {
    const size = @min(max_size, out.len);
    if (size < MIN_PACKET_LEN) return 0;

    // Fill entire packet with random bytes
    random.bytes(out[0..size]);

    // First byte: must look like short header (bit 7 clear = 0, fixed bit 6 = random already)
    // Clear the long header bit (0x80)
    out[0] &= 0x7F;
    // Set the fixed bit (0x40) — RFC 9000 §10.3 says it SHOULD be set to avoid being
    // discarded, but the RFC also says "An endpoint MUST treat any packet ending in a
    // valid stateless reset token as a Stateless Reset". We set it for compatibility.
    out[0] |= 0x40;

    // Write the stateless reset token as the last 16 bytes
    const token = computeToken(static_key, conn_id);
    @memcpy(out[size - TOKEN_LEN .. size], &token);

    return size;
}

/// Check if a received packet is a stateless reset by comparing its last 16 bytes
/// against known peer reset tokens.
///
/// `data` is the datagram as received, so the token is read off its tail and
/// nothing is copied; `tokens` is the caller's list of every token this
/// endpoint believes a peer might reset with. Anything shorter than
/// `MIN_PACKET_LEN` is false without a comparison — there is no room for a
/// token — and the scan stops at the first match, so the work done depends on
/// which token matched and on where it sits in the list.
///
/// Every individual comparison is constant-time, so the answer does not leak
/// a token's contents. Nothing is retained and nothing is allocated; both
/// arguments must stay alive and unmodified for the duration of the call, and
/// neither is reachable afterwards.
pub fn isStatelessReset(data: []const u8, tokens: []const [TOKEN_LEN]u8) bool {
    if (data.len < MIN_PACKET_LEN) return false;

    const packet_token = data[data.len - TOKEN_LEN ..][0..TOKEN_LEN];
    for (tokens) |known_token| {
        // Constant-time compare: the reset token is a secret; a timing
        // oracle here would leak it (RFC 9000 §10.3).
        if (crypto.timing_safe.eql([TOKEN_LEN]u8, packet_token.*, known_token)) return true;
    }
    return false;
}

// Token determinism: same key + CID produces same token
test "computeToken deterministic" {
    const key = [_]u8{0x01} ** 16;
    const cid = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };

    const t1 = computeToken(key, &cid);
    const t2 = computeToken(key, &cid);
    try std.testing.expectEqualSlices(u8, &t1, &t2);
}

// Different CIDs produce different tokens
test "computeToken different CIDs" {
    const key = [_]u8{0x01} ** 16;
    const cid1 = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    const cid2 = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDE };

    const t1 = computeToken(key, &cid1);
    const t2 = computeToken(key, &cid2);
    try std.testing.expect(!std.mem.eql(u8, &t1, &t2));
}

// Generate + detect roundtrip
test "generatePacket and isStatelessReset roundtrip" {
    const key = [_]u8{0x42} ** 16;
    const cid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

    var prng = std.Random.DefaultPrng.init(0x72657365);
    var buf: [64]u8 = undefined;
    const size = generatePacket(&buf, 64, key, &cid, prng.random());
    try std.testing.expect(size == 64);

    // First byte should look like short header
    try std.testing.expect(buf[0] & 0x80 == 0); // not long header
    try std.testing.expect(buf[0] & 0x40 != 0); // fixed bit set

    // Should be detected with matching token
    const token = computeToken(key, &cid);
    const tokens = [_][TOKEN_LEN]u8{token};
    try std.testing.expect(isStatelessReset(buf[0..size], &tokens));
}

// Wrong token not detected
test "isStatelessReset wrong token" {
    const key = [_]u8{0x42} ** 16;
    const cid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

    var prng = std.Random.DefaultPrng.init(0x77726f6e);
    var buf: [64]u8 = undefined;
    const size = generatePacket(&buf, 64, key, &cid, prng.random());

    // Try with a different token
    const wrong_token = [_]u8{0xFF} ** TOKEN_LEN;
    const tokens = [_][TOKEN_LEN]u8{wrong_token};
    try std.testing.expect(!isStatelessReset(buf[0..size], &tokens));
}

// Minimum size enforcement
test "isStatelessReset minimum size" {
    const token = [_]u8{0xAA} ** TOKEN_LEN;
    const tokens = [_][TOKEN_LEN]u8{token};

    // 20 bytes is too small (need at least 21)
    var small_buf: [20]u8 = undefined;
    @memcpy(small_buf[4..20], &token);
    try std.testing.expect(!isStatelessReset(&small_buf, &tokens));

    // 21 bytes is the minimum
    var min_buf: [21]u8 = undefined;
    @memcpy(min_buf[5..21], &token);
    try std.testing.expect(isStatelessReset(&min_buf, &tokens));
}

// generatePacket too small
test "generatePacket too small" {
    const key = [_]u8{0x01} ** 16;
    const cid = [_]u8{0x01};

    var prng = std.Random.DefaultPrng.init(0x746f6f73);
    var buf: [64]u8 = undefined;
    // max_size < MIN_PACKET_LEN should return 0
    const size = generatePacket(&buf, 20, key, &cid, prng.random());
    try std.testing.expect(size == 0);
}
