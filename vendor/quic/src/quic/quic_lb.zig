//! QUIC-LB: connection-id encoding and decoding for load balancers
//! (draft-ietf-quic-load-balancers). A cid here is a first octet, this
//! server's id and a nonce — in the clear, or encrypted with one shared key
//! by a single AES pass when the two together are 16 bytes and by a four-pass
//! Feistel otherwise. The nonce and any greased bits come from the caller's
//! `std.Random`; nothing here reads a clock or allocates.

const std = @import("std");
const crypto = std.crypto;
const Aes128 = crypto.core.aes.Aes128;

/// QUIC-LB configuration for CID encoding.
///
/// **The two lengths are one obligation, not two.** A CID this module makes
/// is a first octet followed by `server_id_len` bytes of server id and
/// `nonce_len` bytes of nonce, so `cidLength` is the whole of it and QUIC's
/// own 20-byte limit on a connection id (RFC 9000 §17.2) is the bound:
/// `server_id_len + nonce_len` must be at most 19. Each field's own range —
/// 1 to 15 and 4 to 18 — is necessary and not sufficient, and the sum is what
/// decides whether the result is a CID at all.
///
/// Nothing checks the sum. A config is written down once, by whoever wrote
/// it, and checking it on the accept path would be a runtime cost to catch a
/// value that is wrong on every packet; so it is a programmer obligation, and
/// a config outside it is a bug — `generateCid` will write more bytes into
/// `buf` than a connection id may hold, and `extractServerId` will decode
/// past the end of its own buffer.
pub const Config = struct {
    /// Which load balancer this is, in bits 7-5 of the first octet and never
    /// encrypted: a peer has to be able to tell which config encoded an id
    /// before it can decode one.
    config_id: u3,
    /// This server's own id, carried at the front of every CID it hands out
    /// and recovered by `extractServerId`. Only the first `server_id_len`
    /// bytes are ever read; the rest are padding, and a config that leaves
    /// them set is not wrong because nothing looks at them.
    server_id: [15]u8 = @splat(0),
    /// Bytes of this server's id a CID carries. 1 to 15; see the combined
    /// rule on the type.
    server_id_len: u4,
    /// Bytes of unguessable nonce after the server id: what stops one peer
    /// from naming another's CID. 4 to 18; see the combined rule on the
    /// type.
    nonce_len: u5,
    /// The key the server id and nonce are encrypted under, or null to send
    /// them in the clear. Plaintext keeps routing working while handing the
    /// server list to anyone who reads an id off the wire.
    key: ?[16]u8 = null,
    /// Whether the first octet's low five bits carry the CID length. A
    /// deployment that can take the length from the config spends them on
    /// nothing instead, and a greased value there is what a protocol that
    /// wants no fingerprint spends them on.
    encode_length: bool = true,
};

/// Total CID length: 1 (first octet) + server_id_len + nonce_len.
///
/// At most 20 for any config in range, because the combined rule on `Config`
/// is what keeps the result a connection id at all; a config outside that
/// range returns a length no peer may be given. Nothing is checked here, and
/// nothing is read but the two lengths.
pub fn cidLength(config: *const Config) u8 {
    return 1 + @as(u8, config.server_id_len) + @as(u8, config.nonce_len);
}

/// Generate a QUIC-LB encoded CID into buf.
///
/// Writes exactly `cidLength(config)` bytes — the first octet, then
/// `server_id_len` bytes of server id, then `nonce_len` bytes of nonce — and
/// leaves the rest of `buf` untouched. `buf.len >= cidLength(config)` is
/// asserted rather than returned, so it is unchecked in ReleaseFast and
/// ReleaseSmall.
///
/// The nonce, and the low five bits of the first octet when `encode_length`
/// is false, are drawn from `random`. The bytes drawn are copied into `buf`,
/// not borrowed, so the caller keeps the only reference to them; the engine
/// is the caller's and this call advances it, which is what makes two CIDs
/// from one engine differ. The reset token issued beside a CID is drawn from
/// that same generator, so a CID drawn from a process CSPRNG next to an
/// injected token would be the one thing a test cannot pin.
///
/// With `config.key` set, everything after the first octet is encrypted and
/// the octet itself is not — a peer has to read the config id before it can
/// decode anything. Without it, the id and nonce go on the wire as they are.
/// Nothing is allocated and nothing is retained.
pub fn generateCid(config: *const Config, buf: []u8, random: std.Random) void {
    const total = cidLength(config);
    std.debug.assert(buf.len >= total);

    // First octet: config_id in bits 7-5
    const config_bits: u8 = @as(u8, config.config_id) << 5;
    if (config.encode_length) {
        // Bits 4-0 encode (CID length - 1)
        buf[0] = config_bits | (total - 1);
    } else {
        // Bits 4-0 are random
        buf[0] = config_bits | (random.int(u8) & 0x1F);
    }

    const sid_len: u8 = @as(u8, config.server_id_len);
    const nonce_len: u8 = @as(u8, config.nonce_len);

    // Place server_id and nonce into bytes 1..total
    @memcpy(buf[1 .. 1 + sid_len], config.server_id[0..sid_len]);
    // Fill nonce with random bytes
    random.bytes(buf[1 + sid_len .. total]);

    // Encrypt if key is set
    if (config.key) |key| {
        const payload_len = sid_len + nonce_len;
        if (payload_len == 16) {
            // Single-pass AES-ECB: encrypt bytes 1..17
            singlePassEncrypt(key, buf[1..17]);
        } else {
            // 4-pass Feistel cipher
            feistelEncrypt(key, buf[1..total], payload_len);
        }
    }
}

/// Extract server_id from a QUIC-LB encoded CID.
///
/// Writes `config.server_id_len` bytes to `out[0..config.server_id_len]` and
/// leaves the rest of `out` alone. Returns false, having written nothing, in
/// two cases: `cid` is shorter than `cidLength(config)`, or `out` is shorter
/// than `config.server_id_len`.
///
/// `cid` is borrowed for the call and never modified — with a key the payload
/// is decoded into a local buffer — and the id is in `out` when this returns
/// true, not only after the caller checks. The decode is parameterised by the
/// config alone: nothing here compares the first octet's config id, so a
/// caller matching several configs has to do that itself. Nothing is
/// allocated.
pub fn extractServerId(config: *const Config, cid: []const u8, out: []u8) bool {
    const total = cidLength(config);
    if (cid.len < total) return false;

    const sid_len: u8 = @as(u8, config.server_id_len);
    const nonce_len: u8 = @as(u8, config.nonce_len);
    const payload_len = sid_len + nonce_len;

    if (out.len < sid_len) return false;

    if (config.key) |key| {
        // Decrypt in a temporary buffer (don't mutate input)
        var tmp: [20]u8 = undefined; // max payload: 15 + 18 = 33, but CID max is 20
        @memcpy(tmp[0..payload_len], cid[1 .. 1 + payload_len]);

        if (payload_len == 16) {
            singlePassDecrypt(key, tmp[0..16]);
        } else {
            feistelDecrypt(key, tmp[0..payload_len], payload_len);
        }
        @memcpy(out[0..sid_len], tmp[0..sid_len]);
    } else {
        // Plaintext: server_id is at bytes 1..1+sid_len
        @memcpy(out[0..sid_len], cid[1 .. 1 + sid_len]);
    }

    return true;
}

/// Extract the config_id (bits 7-5) from the first octet of a CID.
///
/// Every octet has an answer, so this cannot fail; telling whether that
/// answer names this deployment is the caller's comparison.
pub fn extractConfigId(first_octet: u8) u3 {
    return @intCast(first_octet >> 5);
}

// --- Internal cipher functions ---

/// Single-pass AES-ECB encrypt (for payload_len == 16).
fn singlePassEncrypt(key: [16]u8, data: *[16]u8) void {
    const ctx = Aes128.initEnc(key);
    var out: [16]u8 = undefined;
    ctx.encrypt(&out, data);
    data.* = out;
}

/// Single-pass AES-ECB decrypt (for payload_len == 16).
fn singlePassDecrypt(key: [16]u8, data: *[16]u8) void {
    const ctx = Aes128.initDec(key);
    var out: [16]u8 = undefined;
    ctx.decrypt(&out, data);
    data.* = out;
}

/// 4-pass Feistel encrypt in place.
/// data[0..total_len] contains server_id ++ nonce.
///
/// `data` must hold at least `total_len` bytes, which is the width of the
/// payload being encoded and the largest a connection id can carry; only the
/// first `total_len` bytes are read and written. `key` is passed by value.
/// Each round is a XOR, which is why `feistelDecrypt` runs the same rounds in
/// the opposite order. Nothing is allocated and nothing is retained.
pub fn feistelEncrypt(key: [16]u8, data: []u8, total_len: u8) void {
    const half_len: u8 = (total_len + 1) / 2; // ceil(N/2)
    const right_len: u8 = total_len - half_len;

    // Round 1: right ^= truncate(AES(expand(left, N, 1)), right_len)
    {
        var block = expandBlock(data[0..half_len], half_len, total_len, 1);
        const ctx = Aes128.initEnc(key);
        var enc: [16]u8 = undefined;
        ctx.encrypt(&enc, &block);
        xorSlice(data[half_len..total_len], enc[0..right_len]);
    }

    // Round 2: left ^= truncate(AES(expand(right, N, 2)), half_len)
    {
        var block = expandBlock(data[half_len..total_len], right_len, total_len, 2);
        const ctx = Aes128.initEnc(key);
        var enc: [16]u8 = undefined;
        ctx.encrypt(&enc, &block);
        xorSlice(data[0..half_len], enc[0..half_len]);
    }

    // Round 3: right ^= truncate(AES(expand(left, N, 3)), right_len)
    {
        var block = expandBlock(data[0..half_len], half_len, total_len, 3);
        const ctx = Aes128.initEnc(key);
        var enc: [16]u8 = undefined;
        ctx.encrypt(&enc, &block);
        xorSlice(data[half_len..total_len], enc[0..right_len]);
    }

    // Round 4: left ^= truncate(AES(expand(right, N, 4)), half_len)
    {
        var block = expandBlock(data[half_len..total_len], right_len, total_len, 4);
        const ctx = Aes128.initEnc(key);
        var enc: [16]u8 = undefined;
        ctx.encrypt(&enc, &block);
        xorSlice(data[0..half_len], enc[0..half_len]);
    }
}

/// 4-pass Feistel decrypt in place.
/// data[0..total_len] contains encrypted server_id ++ nonce.
///
/// `total_len` is the payload width the matching `feistelEncrypt` was given,
/// not `data.len`: a longer buffer comes back with only its first
/// `total_len` bytes decoded, and a shorter one is a caller error. `key` is
/// passed by value. Nothing is allocated and nothing is retained.
pub fn feistelDecrypt(key: [16]u8, data: []u8, total_len: u8) void {
    const half_len: u8 = (total_len + 1) / 2; // ceil(N/2)
    const right_len: u8 = total_len - half_len;

    // Undo Round 4: left ^= truncate(AES(expand(right, N, 4)), half_len)
    {
        var block = expandBlock(data[half_len..total_len], right_len, total_len, 4);
        const ctx = Aes128.initEnc(key);
        var enc: [16]u8 = undefined;
        ctx.encrypt(&enc, &block);
        xorSlice(data[0..half_len], enc[0..half_len]);
    }

    // Undo Round 3: right ^= truncate(AES(expand(left, N, 3)), right_len)
    {
        var block = expandBlock(data[0..half_len], half_len, total_len, 3);
        const ctx = Aes128.initEnc(key);
        var enc: [16]u8 = undefined;
        ctx.encrypt(&enc, &block);
        xorSlice(data[half_len..total_len], enc[0..right_len]);
    }

    // Undo Round 2: left ^= truncate(AES(expand(right, N, 2)), half_len)
    {
        var block = expandBlock(data[half_len..total_len], right_len, total_len, 2);
        const ctx = Aes128.initEnc(key);
        var enc: [16]u8 = undefined;
        ctx.encrypt(&enc, &block);
        xorSlice(data[0..half_len], enc[0..half_len]);
    }

    // Undo Round 1: right ^= truncate(AES(expand(left, N, 1)), right_len)
    {
        var block = expandBlock(data[0..half_len], half_len, total_len, 1);
        const ctx = Aes128.initEnc(key);
        var enc: [16]u8 = undefined;
        ctx.encrypt(&enc, &block);
        xorSlice(data[half_len..total_len], enc[0..right_len]);
    }
}

/// Build the 16-byte AES input block: [half_data | zero_padding | total_len | round]
fn expandBlock(half: []const u8, half_len: u8, total_len: u8, round: u8) [16]u8 {
    var block: [16]u8 = @splat(0);
    @memcpy(block[0..half_len], half[0..half_len]);
    // Positions 14 and 15 hold total_len and round number
    block[14] = total_len;
    block[15] = round;
    return block;
}

/// XOR src into dst in place.
fn xorSlice(dst: []u8, src: []const u8) void {
    for (dst, src) |*d, s| {
        d.* ^= s;
    }
}

// --- Tests ---

// Plaintext roundtrip: generate CID, extract server_id, verify match
test "quic_lb plaintext roundtrip" {
    var config = Config{
        .config_id = 2,
        .server_id_len = 4,
        .nonce_len = 6,
    };
    config.server_id[0] = 0xAB;
    config.server_id[1] = 0xCD;
    config.server_id[2] = 0x12;
    config.server_id[3] = 0x34;

    const total = cidLength(&config);
    try std.testing.expectEqual(@as(u8, 11), total); // 1 + 4 + 6

    var prng = std.Random.DefaultPrng.init(0x6a697474);
    const random = prng.random();
    var cid: [20]u8 = undefined;
    generateCid(&config, &cid, random);

    // Verify config_id in first octet
    try std.testing.expectEqual(@as(u3, 2), extractConfigId(cid[0]));

    // Verify encoded length in first octet
    try std.testing.expectEqual(@as(u8, 10), cid[0] & 0x1F); // total - 1 = 10

    // Extract and verify server_id
    var extracted_sid: [15]u8 = undefined;
    try std.testing.expect(extractServerId(&config, &cid, &extracted_sid));
    try std.testing.expectEqualSlices(u8, &.{ 0xAB, 0xCD, 0x12, 0x34 }, extracted_sid[0..4]);
}

// Encrypted roundtrip (Feistel): generate CID, extract server_id, verify match
test "quic_lb encrypted roundtrip feistel" {
    var config = Config{
        .config_id = 3,
        .server_id_len = 4,
        .nonce_len = 6,
        .key = .{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 },
    };
    config.server_id[0] = 0xDE;
    config.server_id[1] = 0xAD;
    config.server_id[2] = 0xBE;
    config.server_id[3] = 0xEF;

    const total = cidLength(&config);
    try std.testing.expectEqual(@as(u8, 11), total);

    var prng = std.Random.DefaultPrng.init(0x6a697474);
    const random = prng.random();
    var cid: [20]u8 = undefined;
    generateCid(&config, &cid, random);

    // Config ID preserved in first octet (not encrypted)
    try std.testing.expectEqual(@as(u3, 3), extractConfigId(cid[0]));

    // Encrypted bytes should differ from plaintext server_id
    // (with overwhelming probability given random nonce)
    const plaintext_match = std.mem.eql(u8, cid[1..5], &.{ 0xDE, 0xAD, 0xBE, 0xEF });
    // Not guaranteed to be different, but extremely likely
    _ = plaintext_match;

    // Extract and verify server_id
    var extracted_sid: [15]u8 = undefined;
    try std.testing.expect(extractServerId(&config, &cid, &extracted_sid));
    try std.testing.expectEqualSlices(u8, &.{ 0xDE, 0xAD, 0xBE, 0xEF }, extracted_sid[0..4]);
}

// Single-pass AES-ECB (server_id_len + nonce_len == 16)
test "quic_lb single pass aes ecb" {
    var config = Config{
        .config_id = 1,
        .server_id_len = 8,
        .nonce_len = 8,
        .key = .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99 },
    };
    config.server_id[0] = 0x01;
    config.server_id[1] = 0x02;
    config.server_id[2] = 0x03;
    config.server_id[3] = 0x04;
    config.server_id[4] = 0x05;
    config.server_id[5] = 0x06;
    config.server_id[6] = 0x07;
    config.server_id[7] = 0x08;

    const total = cidLength(&config);
    try std.testing.expectEqual(@as(u8, 17), total); // 1 + 8 + 8

    var prng = std.Random.DefaultPrng.init(0x6a697474);
    const random = prng.random();
    var cid: [20]u8 = undefined;
    generateCid(&config, &cid, random);

    // Extract and verify server_id
    var extracted_sid: [15]u8 = undefined;
    try std.testing.expect(extractServerId(&config, &cid, &extracted_sid));
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 }, extracted_sid[0..8]);
}

// Config ID extraction from first octet
test "quic_lb config id extraction" {
    try std.testing.expectEqual(@as(u3, 0), extractConfigId(0b000_00000));
    try std.testing.expectEqual(@as(u3, 1), extractConfigId(0b001_00000));
    try std.testing.expectEqual(@as(u3, 3), extractConfigId(0b011_10101));
    try std.testing.expectEqual(@as(u3, 6), extractConfigId(0b110_11111));
    try std.testing.expectEqual(@as(u3, 7), extractConfigId(0b111_00000));
}

// Different CIDs for same server_id (nonce uniqueness)
test "quic_lb nonce uniqueness" {
    var config = Config{
        .config_id = 0,
        .server_id_len = 2,
        .nonce_len = 6,
    };
    config.server_id[0] = 0xAA;
    config.server_id[1] = 0xBB;

    var prng = std.Random.DefaultPrng.init(0x6a697474);
    const random = prng.random();
    var cid1: [20]u8 = undefined;
    var cid2: [20]u8 = undefined;
    generateCid(&config, &cid1, random);
    generateCid(&config, &cid2, random);

    const total = cidLength(&config);
    // CIDs should be different (with overwhelming probability)
    try std.testing.expect(!std.mem.eql(u8, cid1[0..total], cid2[0..total]));

    // But both should extract to the same server_id
    var sid1: [15]u8 = undefined;
    var sid2: [15]u8 = undefined;
    try std.testing.expect(extractServerId(&config, &cid1, &sid1));
    try std.testing.expect(extractServerId(&config, &cid2, &sid2));
    try std.testing.expectEqualSlices(u8, sid1[0..2], sid2[0..2]);
    try std.testing.expectEqualSlices(u8, &.{ 0xAA, 0xBB }, sid1[0..2]);
}

// CID too short returns false
test "quic_lb extract from short cid" {
    var config = Config{
        .config_id = 0,
        .server_id_len = 4,
        .nonce_len = 6,
    };
    var out: [15]u8 = undefined;
    const short_cid = [_]u8{ 0x00, 0x01, 0x02 };
    try std.testing.expect(!extractServerId(&config, &short_cid, &out));
}

// Feistel encrypt/decrypt roundtrip with known data
test "quic_lb feistel roundtrip deterministic" {
    const key = [16]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    var data = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44 };
    const original = data;

    feistelEncrypt(key, &data, 10);
    // Encrypted should differ from original
    try std.testing.expect(!std.mem.eql(u8, &data, &original));

    feistelDecrypt(key, &data, 10);
    // Decrypted should match original
    try std.testing.expectEqualSlices(u8, &original, &data);
}

// Single-pass AES roundtrip with known data
test "quic_lb single pass aes roundtrip deterministic" {
    const key = [16]u8{ 0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F };
    var data: [16]u8 = .{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    const original = data;

    singlePassEncrypt(key, &data);
    try std.testing.expect(!std.mem.eql(u8, &data, &original));

    singlePassDecrypt(key, &data);
    try std.testing.expectEqualSlices(u8, &original, &data);
}

// Encrypted roundtrip with encode_length=false
test "quic_lb encrypted no length encoding" {
    var config = Config{
        .config_id = 5,
        .server_id_len = 3,
        .nonce_len = 5,
        .key = .{ 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x00 },
        .encode_length = false,
    };
    config.server_id[0] = 0x11;
    config.server_id[1] = 0x22;
    config.server_id[2] = 0x33;

    var prng = std.Random.DefaultPrng.init(0x6a697474);
    const random = prng.random();
    var cid: [20]u8 = undefined;
    generateCid(&config, &cid, random);

    // Config ID still in bits 7-5
    try std.testing.expectEqual(@as(u3, 5), extractConfigId(cid[0]));

    // Extract server_id
    var extracted_sid: [15]u8 = undefined;
    try std.testing.expect(extractServerId(&config, &cid, &extracted_sid));
    try std.testing.expectEqualSlices(u8, &.{ 0x11, 0x22, 0x33 }, extracted_sid[0..3]);
}

test "quic_lb: the longest connection id the lengths may combine into round-trips" {
    // The two lengths are combined into one payload, and the payload plus the
    // first octet is a connection id, so the sum is what QUIC's 20-byte limit
    // bounds. 15 bytes of server id and 4 of nonce is that maximum: the
    // longest id a peer may be given, and the one the decoder's fixed buffer
    // is sized for.
    const key = [16]u8{ 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0 };
    var config = Config{
        .config_id = 6,
        .server_id_len = 15,
        .nonce_len = 4,
        .key = key,
    };
    @memset(&config.server_id, 0xa5);
    try std.testing.expectEqual(@as(u8, 20), cidLength(&config));

    var prng = std.Random.DefaultPrng.init(0x6c6f6e67);
    var cid: [20]u8 = undefined;
    generateCid(&config, &cid, prng.random());

    var extracted: [15]u8 = undefined;
    try std.testing.expect(extractServerId(&config, &cid, &extracted));
    try std.testing.expectEqualSlices(u8, &config.server_id, &extracted);
}

test "quic_lb: the longest connection id also round-trips without a key" {
    var config = Config{
        .config_id = 0,
        .server_id_len = 15,
        .nonce_len = 4,
    };
    @memset(&config.server_id, 0x5a);
    try std.testing.expectEqual(@as(u8, 20), cidLength(&config));

    var prng = std.Random.DefaultPrng.init(0x706c6169);
    var cid: [20]u8 = undefined;
    generateCid(&config, &cid, prng.random());

    var extracted: [15]u8 = undefined;
    try std.testing.expect(extractServerId(&config, &cid, &extracted));
    try std.testing.expectEqualSlices(u8, &config.server_id, &extracted);
}

test "quic_lb: a shorter connection id leaves the decoder's buffer half empty" {
    // The buffer is sized for the longest id QUIC allows, not for the one this
    // config produces, so the decode of a short id must not depend on the
    // bytes behind it: anything left over from an earlier packet must not
    // reach the server id.
    const key = [16]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00 };
    var config = Config{
        .config_id = 3,
        .server_id_len = 2,
        .nonce_len = 4,
        .key = key,
    };
    config.server_id[0] = 0xde;
    config.server_id[1] = 0xad;

    var prng = std.Random.DefaultPrng.init(0x62756666);
    // A whole 20-byte buffer with a 7-byte connection id at its front and the
    // rest left as another packet's bytes.
    var buffer = @as([20]u8, @splat(0xff));
    var cid: [7]u8 = undefined;
    generateCid(&config, &cid, prng.random());
    @memcpy(buffer[0..cid.len], &cid);

    var extracted = @as([15]u8, @splat(0xaa));
    try std.testing.expect(extractServerId(&config, buffer[0..], &extracted));
    try std.testing.expectEqualSlices(u8, config.server_id[0..2], extracted[0..2]);
    try std.testing.expectEqualSlices(u8, &@as([13]u8, @splat(0xaa)), extracted[2..]);
}
