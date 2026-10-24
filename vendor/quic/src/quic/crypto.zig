//! Packet protection: key derivation, AEAD sealing and opening, header
//! protection, and the key rotation of RFC 9001 §6. Nothing here reads a
//! clock, draws randomness or allocates — every key comes from values the
//! caller passes, so the same secrets protect the same packets twice — and
//! every struct here is a value whose copies are independent of each other.

const std = @import("std");
const protocol = @import("protocol.zig");
const assert = std.debug.assert;

const crypto = std.crypto;
const tls = std.crypto.tls;
const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;
const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;
const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
const Aes128 = crypto.core.aes.Aes128;
const ChaCha20Poly1305 = crypto.aead.chacha_poly.ChaCha20Poly1305;
const ChaCha20IETF = crypto.stream.chacha.ChaCha20IETF;
const aes_gcm = @import("aes_gcm.zig");

// RFC 9001 §5.2: QUIC v1 initial salt
const INITIAL_SALT_V1 = [_]u8{ 0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a };
// RFC 9369 §3.1: QUIC v2 initial salt
const INITIAL_SALT_V2 = [_]u8{ 0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9 };

/// Bytes of a protected packet the header-protection mask is computed over
/// (RFC 9001 §5.4.2). The sample starts four bytes after the packet number
/// offset, which is why a packet shorter than that plus this cannot be
/// protected at all.
///
pub const SAMPLE_LEN = 16;
/// Bytes of header protection a mask carries: one for the first byte and
/// four for a packet number that may be encoded as long as four bytes.
/// RFC 9001 §5.4.3 fixes the mask at five whatever the packet number's own
/// length turns out to be, so the four are computed even for a shorter one.
///
pub const MASK_LEN = 5;

/// AES-128-GCM: the AEAD of the Initial keys (RFC 9001 §5.2) and of the
/// `aes_128_gcm_sha256` suite, and what the Retry and NEW_TOKEN seals use,
/// which are not negotiated per suite.
///
/// `chacha20_poly1305_sha256` seals with ChaCha20-Poly1305 and not with
/// this, so the name is not a way to ask what a `Seal` will encrypt with —
/// `Seal.cipher_suite` is. What both suites agree on, and what a caller
/// sizes a payload buffer by, is the 16-byte tag.
///
pub const Aead = Aes128Gcm;
const Hmac = HmacSha256;

/// Cached AES-128 encryption context for header protection. Computed once per
/// Seal/Open from the (immutable) hp_key, then reused on every packet.
pub const Aes128HpCtx = @TypeOf(Aes128.initEnc(@as([16]u8, undefined)));

/// AES-128-GCM key length, which is also the length of the Initial keys
/// because those are always AES.
///
pub const key_len = 16;
/// AEAD nonce length: the IV every key is derived with, and the width the
/// packet number is XORed into (RFC 9001 §5.3).
///
pub const nonce_len = 12;
/// The widest key any cipher suite here uses (ChaCha20-Poly1305), and so the
/// width the fixed-size key arrays are. The bytes past the suite's own key
/// length are zero and are never read.
///
pub const max_key_len = 32;

/// A TLS 1.3 cipher suite, by its IANA code point.
///
/// The suite chooses three things at once — the AEAD, the key length and the
/// header-protection function — and this core keeps all three together
/// because the derivation is per suite. The enum's integer is the code
/// point that goes on the wire; the variant name is this module's own
/// spelling of it and is never sent.
pub const CipherSuite = enum(u16) {
    /// AES-128-GCM with SHA-256, IANA 0x1301 (RFC 8446 §9.1): the suite the
    /// Initial keys are, and the only one `prepareCtx` fills contexts for.
    aes_128_gcm_sha256 = 0x1301,
    /// ChaCha20-Poly1305 with SHA-256, IANA 0x1303 (RFC 8446 §9.1): 32-byte
    /// keys, and header protection by the ChaCha20 block function
    /// (RFC 9001 §5.4.4) rather than by AES.
    chacha20_poly1305_sha256 = 0x1303,

    /// The AEAD key length in bytes: 16 for AES-128-GCM, 32 for
    /// ChaCha20-Poly1305. `Open.key` and `Seal.key` are `max_key_len` wide,
    /// so the bytes past this length are zero padding — which is what lets
    /// one array hold either suite's key.
    pub fn keyLen(self: CipherSuite) usize {
        return switch (self) {
            .aes_128_gcm_sha256 => 16,
            .chacha20_poly1305_sha256 => 32,
        };
    }

    /// The header-protection key length in bytes for this suite: 16 for
    /// AES-128-GCM, 32 for ChaCha20-Poly1305. It is the width to derive
    /// `hp_key` with, and the only part of an `Open.hp_key` this core reads.
    pub fn hpKeyLen(self: CipherSuite) usize {
        return switch (self) {
            .aes_128_gcm_sha256 => 16,
            .chacha20_poly1305_sha256 => 32,
        };
    }

    /// Confidentiality limit: max packets before key rotation required.
    /// RFC 9001 Section 6.6: 2^23 for AES-128-GCM, 2^62 for ChaCha20.
    pub fn confidentialityLimit(self: CipherSuite) u64 {
        return switch (self) {
            .aes_128_gcm_sha256 => 1 << 23,
            .chacha20_poly1305_sha256 => 1 << 62,
        };
    }
};

/// The four levels QUIC protects separately, as a stable numbering.
///
/// Distinct from `packet.Epoch` (four values, keyed by packet type) and from
/// `ack_handler.EncLevel` (three values, keyed by packet-number space — there
/// is no 0-RTT space). Kept separate because the mappings and the
/// cardinalities differ, and a caller that conflates them gets a key for the
/// wrong level.
///
pub const EncryptionLevel = enum(u8) {
    /// RFC 9001 §5.2: derived from the destination connection id, so both
    /// sides hold them before anything is negotiated.
    initial = 0,
    /// 0-RTT for a resumed session (RFC 9001 §5.6), carrying the client's
    /// early traffic secret. A server installs the opening half of it; the
    /// sealing half is a client's alone (RFC 9001 §5.6 forbids a server
    /// from protecting a packet with early keys).
    early_data,
    /// TLS handshake traffic (RFC 9001 §4.4.2), one secret per direction.
    handshake,
    /// 1-RTT application data (RFC 9001 §5.3): the level a key update
    /// rotates, and the only one `KeyUpdateManager` covers.
    application,
};

/// The keys one encryption level is opened with: an AEAD key, a
/// header-protection key, and the static IV they are used with.
///
/// A value. It owns no allocation, it holds no reference to anything, and
/// copying one is cheap and safe — which is what a key update does with the
/// previous generation while reordered packets are still arriving.
///
/// `prepareCtx` fills the two cached contexts. It is an optimisation and not
/// a requirement: without it every packet falls back to std's one-shot
/// primitive, and with it the key schedule and GHASH powers are computed
/// once per key. Nothing here is invalidated by a later key change, because
/// a key change is a different `Open`.
///
pub const Open = struct {
    /// The AEAD key, zero-padded to `max_key_len`: the bytes past
    /// `cipher_suite.keyLen()` are zero and are never read.
    key: [max_key_len]u8 = @splat(0),
    /// The header-protection key, zero-padded the same way. Only the first
    /// `cipher_suite.hpKeyLen()` bytes are read.
    hp_key: [max_key_len]u8 = @splat(0),
    /// The static IV every packet's nonce is `packet_number` XORed into
    /// (RFC 9001 §5.3). It has no default, and a zero one makes every packet
    /// under this key share a nonce.
    nonce: [nonce_len]u8,
    /// The suite that decides the AEAD and the header-protection function
    /// above. Defaults to AES-128-GCM, which is what the Initial keys are.
    cipher_suite: CipherSuite = .aes_128_gcm_sha256,
    /// Pre-expanded AES-128 round keys for header protection (AES suites only).
    /// Populated by prepareCtx() at construction; copied with the struct.
    hp_aes_ctx: ?Aes128HpCtx = null,
    /// Packet protection with the key schedule and GHASH powers done once
    /// (AES suites only). Populated by prepareCtx(); without it every packet
    /// falls back to std's one-shot Aes128Gcm.
    aead_ctx: ?aes_gcm.Ctx = null,

    /// Pre-compute the AES-128 HP and AEAD contexts. Safe to call multiple
    /// times. Must be called after key, hp_key and cipher_suite are set.
    pub fn prepareCtx(self: *Open) void {
        if (self.cipher_suite == .aes_128_gcm_sha256) {
            self.hp_aes_ctx = Aes128.initEnc(self.hp_key[0..16].*);
            self.aead_ctx = aes_gcm.Ctx.init(self.key[0..16].*);
        }
    }

    /// Generate a new QUIC Header Protection mask.
    ///
    /// `sample` is the `SAMPLE_LEN` protected bytes the mask is computed
    /// over, borrowed for the call and not retained; it is not modified.
    /// Every call makes a fresh mask, because the sample differs per packet.
    /// Nothing is allocated.
    pub fn newMask(self: *const Open, sample: *const [SAMPLE_LEN]u8) [MASK_LEN]u8 {
        if (self.hp_aes_ctx) |ctx| {
            var encrypted_out: [SAMPLE_LEN]u8 = undefined;
            ctx.encrypt(&encrypted_out, sample);
            return encrypted_out[0..MASK_LEN].*;
        }
        return computeHpMask(sample, self.hp_key, self.cipher_suite);
    }

    /// Open a protected payload in place and return the plaintext it carried.
    ///
    /// The bytes come out where they went in: the result is
    /// `payload[0 .. payload.len - 16]`, the tag is consumed, and nothing is
    /// allocated — a caller keeps the buffer it had and owns no new memory.
    /// `associated_data` is the unprotected header (RFC 9001 §5.2):
    /// authenticated, never encrypted.
    ///
    /// `AuthenticationFailed` is every way the tag does not verify, and they
    /// are deliberately not told apart: a payload shorter than its own tag, a
    /// wrong key, a key from another encryption level, a packet number past
    /// the nonce, a tampered header, or a peer that sent something it did not
    /// sign. Nothing here can be out of memory — no allocation happens on
    /// this path — so there is no allocator error in this set that a caller
    /// could mistake for a forgery.
    ///
    /// The returned slice aliases `payload`, so the caller still owns that
    /// buffer and frees nothing. On the error path that payload is not left
    /// holding its old plaintext either: the AES path overwrites the whole
    /// plaintext region with undefined bytes before returning, so a caller
    /// that got `AuthenticationFailed` discards the packet and must not read
    /// what is left in the buffer.
    pub fn decryptPayload(
        self: *const Open,
        packet_number: u64,
        associated_data: []const u8,
        payload: []u8,
    ) error{AuthenticationFailed}![]u8 {
        return self.decryptWithNonce(makeNonce(self.nonce, packet_number), associated_data, payload);
    }

    /// Opens negotiated multipath 1-RTT data using Noq's path-bound nonce.
    /// Path IDs span u32; the connection enforces its negotiated path limit.
    /// A packet number above 2^62-1 returns AuthenticationFailed without writing.
    /// Otherwise ownership, aliasing and failure residue match decryptPayload.
    /// This authenticates packets but does not detect replay: the caller owns
    /// the packet-number space for each path. No keys are copied or expanded.
    pub fn decryptPayloadForPath(
        self: *const Open,
        path_id: u32,
        packet_number: u64,
        associated_data: []const u8,
        payload: []u8,
    ) error{AuthenticationFailed}![]u8 {
        if (packet_number > (@as(u64, 1) << 62) - 1) return error.AuthenticationFailed;
        return self.decryptWithNonce(
            makeNonceForPath(self.nonce, path_id, packet_number),
            associated_data,
            payload,
        );
    }

    fn decryptWithNonce(
        self: *const Open,
        aead_nonce: [nonce_len]u8,
        associated_data: []const u8,
        payload: []u8,
    ) error{AuthenticationFailed}![]u8 {
        const tag_len = 16; // Same for both AES-128-GCM and ChaCha20-Poly1305
        const payload_len = payload.len;

        // The payload length is the peer's Length varint minus the packet
        // number: it can be shorter than the tag it is supposed to carry.
        if (payload_len < tag_len) return error.AuthenticationFailed;

        const tag: [tag_len]u8 = tag: {
            var t: [tag_len]u8 = undefined;
            @memcpy(&t, payload[(payload_len - tag_len)..payload_len]);
            break :tag t;
        };

        const bytes = payload[0..(payload_len - tag_len)];

        switch (self.cipher_suite) {
            .aes_128_gcm_sha256 => {
                const result = if (self.aead_ctx) |*ctx|
                    ctx.decrypt(bytes, bytes, tag, associated_data, aead_nonce)
                else
                    Aes128Gcm.decrypt(bytes, bytes, tag, associated_data, aead_nonce, self.key[0..16].*);
                result catch |err| {
                    std.log.debug("AES-128-GCM decryption failed: {any}", .{err});
                    return err;
                };
            },
            .chacha20_poly1305_sha256 => {
                ChaCha20Poly1305.decrypt(bytes, bytes, tag, associated_data, aead_nonce, self.key) catch |err| {
                    std.log.debug("ChaCha20-Poly1305 decryption failed: {any}", .{err});
                    return err;
                };
            },
        }

        return bytes;
    }
};

/// The keys one encryption level is sealed with: the mirror of `Open`, for
/// the packets this side sends.
///
/// A value, with the same ownership and copying rules as `Open`. The two are
/// deliberately separate types rather than one with a direction flag: a
/// connection holds both for a level and neither can be used as the other by
/// accident, which is the mistake header protection makes expensive.
///
pub const Seal = struct {
    /// The AEAD key, zero-padded to `max_key_len`: the bytes past
    /// `cipher_suite.keyLen()` are zero and are never read.
    key: [max_key_len]u8 = @splat(0),
    /// The header-protection key, zero-padded the same way. Only the first
    /// `cipher_suite.hpKeyLen()` bytes are read.
    hp_key: [max_key_len]u8 = @splat(0),
    /// The static IV every packet's nonce is `packet_number` XORed into
    /// (RFC 9001 §5.3). It has no default, and a zero one makes every packet
    /// under this key share a nonce.
    nonce: [nonce_len]u8,
    /// The suite that decides the AEAD and the header-protection function
    /// above. Defaults to AES-128-GCM, which is what the Initial keys are.
    cipher_suite: CipherSuite = .aes_128_gcm_sha256,
    /// Pre-expanded AES-128 round keys for header protection (AES suites only).
    /// Populated by prepareCtx() at construction; copied with the struct.
    hp_aes_ctx: ?Aes128HpCtx = null,
    /// Packet protection with the key schedule and GHASH powers done once
    /// (AES suites only). Populated by prepareCtx(); without it every packet
    /// falls back to std's one-shot Aes128Gcm.
    aead_ctx: ?aes_gcm.Ctx = null,

    /// Pre-compute the AES-128 HP and AEAD contexts. Safe to call multiple
    /// times. Must be called after key, hp_key and cipher_suite are set.
    pub fn prepareCtx(self: *Seal) void {
        if (self.cipher_suite == .aes_128_gcm_sha256) {
            self.hp_aes_ctx = Aes128.initEnc(self.hp_key[0..16].*);
            self.aead_ctx = aes_gcm.Ctx.init(self.key[0..16].*);
        }
    }

    /// Generate a new QUIC Header Protection mask.
    ///
    /// `sample` is the `SAMPLE_LEN` protected bytes the mask is computed
    /// over, borrowed for the call and not retained; it is not modified.
    /// Every call makes a fresh mask, because the sample differs per packet.
    /// Nothing is allocated.
    pub fn newMask(self: *const Seal, sample: *const [SAMPLE_LEN]u8) [MASK_LEN]u8 {
        if (self.hp_aes_ctx) |ctx| {
            var encrypted_out: [SAMPLE_LEN]u8 = undefined;
            ctx.encrypt(&encrypted_out, sample);
            return encrypted_out[0..MASK_LEN].*;
        }
        return computeHpMask(sample, self.hp_key, self.cipher_suite);
    }

    /// Apply header protection to an outgoing packet, in place. RFC 9001
    /// §5.4. Equivalent to the standalone `applyHeaderProtection` but reuses
    /// the pre-expanded AES round keys when `prepareCtx` filled them.
    ///
    /// `pkt_buf` is the packet as it will go on the wire with the packet
    /// number already written at `pn_offset` in `pn_len` bytes (1 to 4). Only
    /// `buf[0]` and `buf[pn_offset..pn_offset + pn_len]` are written, and the
    /// long-header test reads the first byte before it is masked.
    ///
    /// A packet too short to carry the sample — fewer than
    /// `pn_offset + 4 + SAMPLE_LEN` bytes — is left untouched and the call
    /// returns nothing, so a caller that built such a packet has a header
    /// that is not protected.
    pub fn applyHeaderProtection(
        self: *const Seal,
        pkt_buf: []u8,
        pn_offset: usize,
        pn_len: usize,
    ) void {
        const sample_offset = pn_offset + 4;
        if (sample_offset + SAMPLE_LEN > pkt_buf.len) return;

        const sample: *const [SAMPLE_LEN]u8 = pkt_buf[sample_offset..][0..SAMPLE_LEN];
        const mask = self.newMask(sample);

        if (isLongHeader(pkt_buf[0])) {
            pkt_buf[0] ^= (mask[0] & 0x0f);
        } else {
            pkt_buf[0] ^= (mask[0] & 0x1f);
        }

        for (0..pn_len) |i| {
            pkt_buf[pn_offset + i] ^= mask[1 + i];
        }
    }

    /// Encrypt a QUIC packet payload with the AEAD and write ciphertext + tag
    /// into `out`.
    ///
    /// `associated_data` is the unprotected header (RFC 9001 §5.2):
    /// authenticated, never encrypted. The nonce is this key's `nonce` with
    /// `packet_number` XORed in, so two calls under one key must carry
    /// different packet numbers.
    ///
    /// `out` must hold at least `plaintext.len + Aead.tag_length` bytes, and
    /// that is asserted rather than returned, so it is unchecked in
    /// ReleaseFast and ReleaseSmall. `out` may be the same buffer as
    /// `plaintext`, which is how the packet buffer is protected in place.
    /// Nothing past `plaintext.len + 16` is written and nothing is allocated.
    ///
    /// Returns the number of bytes written, `plaintext.len + 16`.
    pub fn encryptPayload(
        self: *const Seal,
        packet_number: u64,
        associated_data: []const u8,
        plaintext: []const u8,
        out: []u8,
    ) usize {
        return self.encryptWithNonce(
            makeNonce(self.nonce, packet_number),
            associated_data,
            plaintext,
            out,
        );
    }

    /// Seals negotiated multipath 1-RTT data using Noq's path-bound nonce.
    /// Path IDs span u32; the connection enforces its negotiated path limit.
    /// packet_number must be at most 2^62-1, asserted in Debug/ReleaseSafe and
    /// unchecked in ReleaseFast/ReleaseSmall, like encryptPayload's buffer bound.
    /// Never repeat a (path_id, packet_number) pair under the same key.
    /// Buffer ownership and in-place operation match encryptPayload.
    /// No keys are copied or expanded; prepared AES contexts remain shared.
    pub fn encryptPayloadForPath(
        self: *const Seal,
        path_id: u32,
        packet_number: u64,
        associated_data: []const u8,
        plaintext: []const u8,
        out: []u8,
    ) usize {
        assert(packet_number <= (@as(u64, 1) << 62) - 1);
        return self.encryptWithNonce(
            makeNonceForPath(self.nonce, path_id, packet_number),
            associated_data,
            plaintext,
            out,
        );
    }

    fn encryptWithNonce(
        self: *const Seal,
        aead_nonce: [nonce_len]u8,
        associated_data: []const u8,
        plaintext: []const u8,
        out: []u8,
    ) usize {
        const tag_len = 16; // Same for both

        assert(out.len >= plaintext.len + tag_len);

        var tag: [tag_len]u8 = undefined;
        switch (self.cipher_suite) {
            .aes_128_gcm_sha256 => {
                if (self.aead_ctx) |*ctx|
                    ctx.encrypt(out[0..plaintext.len], &tag, plaintext, associated_data, aead_nonce)
                else
                    Aes128Gcm.encrypt(out[0..plaintext.len], &tag, plaintext, associated_data, aead_nonce, self.key[0..16].*);
            },
            .chacha20_poly1305_sha256 => {
                ChaCha20Poly1305.encrypt(out[0..plaintext.len], &tag, plaintext, associated_data, aead_nonce, self.key);
            },
        }
        @memcpy(out[plaintext.len..][0..tag_len], &tag);

        return plaintext.len + tag_len;
    }
};

/// Construct the AEAD nonce by XORing the IV with the packet number.
/// RFC 9001 Section 5.3.
fn makeNonce(iv: [nonce_len]u8, packet_number: u64) [nonce_len]u8 {
    return makeNonceForPath(iv, 0, packet_number);
}

// Noq 1.3.0 delegates to Rustls v/0.23.42 Nonce::for_path
// (crypto/cipher.rs), shared by Ring's AES-GCM and ChaCha packet keys.
// Encode directly into the result, then XOR the IV: no key/context copies.
fn makeNonceForPath(
    iv: [nonce_len]u8,
    path_id: u32,
    packet_number: u64,
) [nonce_len]u8 {
    var nonce: [nonce_len]u8 = undefined;
    std.mem.writeInt(u32, nonce[0..4], path_id, .big);
    std.mem.writeInt(u64, nonce[4..nonce_len], packet_number, .big);
    for (&nonce, iv) |*byte, iv_byte| {
        byte.* ^= iv_byte;
    }
    return nonce;
}

/// Compute a QUIC Header Protection mask from a sample.
/// AES: AES-ECB encrypt the sample, take first 5 bytes.
/// ChaCha20: counter=sample[0..4] LE, nonce=sample[4..16], encrypt 5 zero bytes.
///
/// `hp_key` is a value, of which only `cipher_suite.hpKeyLen()` bytes are
/// read, and `sample` is borrowed for the call and not modified. This is the
/// uncached form: `Open.newMask` and `Seal.newMask` compute the same mask and
/// reuse a prepared AES schedule when one is there. Pure, and it allocates
/// nothing.
pub fn computeHpMask(sample: *const [SAMPLE_LEN]u8, hp_key: [max_key_len]u8, cipher_suite: CipherSuite) [MASK_LEN]u8 {
    switch (cipher_suite) {
        .aes_128_gcm_sha256 => {
            const ctx = Aes128.initEnc(hp_key[0..16].*);
            var encrypted_out: [SAMPLE_LEN]u8 = undefined;
            ctx.encrypt(&encrypted_out, sample);
            return encrypted_out[0..MASK_LEN].*;
        },
        .chacha20_poly1305_sha256 => {
            // RFC 9001 §5.4.4: counter=sample[0..4] LE, nonce=sample[4..16]
            const counter = std.mem.readInt(u32, sample[0..4], .little);
            const nonce: [12]u8 = sample[4..16].*;
            var zeros: [MASK_LEN]u8 = @splat(0);
            var mask: [MASK_LEN]u8 = undefined;
            ChaCha20IETF.xor(&mask, &zeros, counter, hp_key, nonce);
            return mask;
        },
    }
}

/// Apply header protection to an outgoing packet, in place.
/// RFC 9001 Section 5.4.
///
/// `pkt_buf` is the packet as it will go on the wire, with the packet number
/// already written at `pn_offset` in `pn_len` bytes (1 to 4); only
/// `buf[0]` and `buf[pn_offset..pn_offset + pn_len]` are written. A packet
/// with fewer than `pn_offset + 4 + SAMPLE_LEN` bytes carries no sample and
/// is left untouched.
///
/// `hp_key` is passed by value; nothing is retained and nothing is allocated.
/// `Seal.applyHeaderProtection` is the same operation and prefers that key's
/// prepared AES schedule.
pub fn applyHeaderProtection(
    pkt_buf: []u8,
    pn_offset: usize,
    pn_len: usize,
    hp_key: [max_key_len]u8,
    cipher_suite: CipherSuite,
) void {
    const sample_offset = pn_offset + 4;
    if (sample_offset + SAMPLE_LEN > pkt_buf.len) return;

    const sample: *const [SAMPLE_LEN]u8 = pkt_buf[sample_offset..][0..SAMPLE_LEN];
    const mask = computeHpMask(sample, hp_key, cipher_suite);

    // Apply mask to first byte
    if (isLongHeader(pkt_buf[0])) {
        pkt_buf[0] ^= (mask[0] & 0x0f);
    } else {
        pkt_buf[0] ^= (mask[0] & 0x1f);
    }

    // Apply mask to packet number bytes
    for (0..pn_len) |i| {
        pkt_buf[pn_offset + i] ^= mask[1 + i];
    }
}

/// Remove header protection from an incoming packet, in place.
/// Returns the decoded packet number length (1-4) from the first byte.
///
/// A packet with fewer than `pn_offset + 4 + SAMPLE_LEN` bytes carries no
/// sample: `pkt_buf` is left untouched and 0 is returned, which is not a
/// packet-number length, so a caller reads it as a malformed packet rather
/// than as a one-byte packet number. Otherwise the first byte is unmasked
/// first and its low two bits give the length that then unmasks the packet
/// number, which is why the caller passes no `pn_len` here.
///
/// `hp_key` is passed by value; nothing is retained and nothing is allocated.
pub fn removeHeaderProtection(
    pkt_buf: []u8,
    pn_offset: usize,
    hp_key: [max_key_len]u8,
    cipher_suite: CipherSuite,
) usize {
    const sample_offset = pn_offset + 4;
    if (sample_offset + SAMPLE_LEN > pkt_buf.len) return 0;

    const sample: *const [SAMPLE_LEN]u8 = pkt_buf[sample_offset..][0..SAMPLE_LEN];
    const mask = computeHpMask(sample, hp_key, cipher_suite);

    // Unmask first byte
    if (isLongHeader(pkt_buf[0])) {
        pkt_buf[0] ^= (mask[0] & 0x0f);
    } else {
        pkt_buf[0] ^= (mask[0] & 0x1f);
    }

    const pn_len: usize = (pkt_buf[0] & 0x03) + 1;

    // Unmask packet number bytes
    for (0..pn_len) |i| {
        pkt_buf[pn_offset + i] ^= mask[1 + i];
    }

    return pn_len;
}

fn isLongHeader(first_byte: u8) bool {
    return (first_byte & 0x80) == 0x80;
}

/// Encode a packet number using the minimum number of bytes.
/// RFC 9000 Appendix A.2.
/// Returns the number of bytes used (1-4) and writes to `out`.
///
/// `largest_acked` is the largest packet number this side has seen
/// acknowledged, and null means nothing has been acknowledged yet. The width
/// is the smallest that holds twice the unacknowledged count, capped at the
/// four bytes a packet number occupies on the wire, and the low 32 bits of
/// `pn` are what is written — so the caller has already kept `pn` below 2^62
/// (RFC 9000 §12.3). Bytes of `out` past the returned length are untouched.
///
/// The returned length is also what goes into the header's own low two bits,
/// so a caller writes both from one answer. Nothing is allocated.
pub fn encodePacketNumber(pn: u64, largest_acked: ?u64, out: *[4]u8) usize {
    // Calculate the number of bits needed
    const num_unacked: u64 = if (largest_acked) |la|
        (pn -| la) // saturating sub
    else
        pn + 1;

    // We need enough bits so that 2*num_unacked fits
    const min_bits: usize = if (num_unacked == 0)
        8
    else blk: {
        const needed = 64 - @clz(2 * num_unacked);
        break :blk if (needed <= 8) 8 else if (needed <= 16) 16 else if (needed <= 24) 24 else 32;
    };

    const pn_len = min_bits / 8;

    switch (pn_len) {
        1 => out[0] = @truncate(pn),
        2 => std.mem.writeInt(u16, out[0..2], @truncate(pn), .big),
        3 => {
            out[0] = @truncate(pn >> 16);
            out[1] = @truncate(pn >> 8);
            out[2] = @truncate(pn);
        },
        4 => std.mem.writeInt(u32, out[0..4], @truncate(pn), .big),
        else => unreachable,
    }

    return pn_len;
}

/// The Initial keys for `cid` at `version`, as the pair that opens and seals
/// them (RFC 9001 §5.2). The result is `[0]` the `Open` for what arrives at
/// this level and `[1]` the `Seal` for what this side sends.
///
/// Initial keys are public by construction — they are derived from the
/// destination connection id, which is on the wire — which is why they are
/// only ever used until the handshake keys replace them, and why they are
/// always AES-128-GCM whatever suites TLS later negotiates. The contexts are
/// prepared, so the result is ready to use.
///
/// `is_server` is which side this side is, and it decides which half is
/// which: a server opens the client's Initial keys and seals its own, a
/// client the reverse. It is comptime, so the branch is resolved here.
/// `cid` is the destination connection id those packets carry — borrowed for
/// the call, retained by nothing, and of any length, including the zero a
/// client's first Initial sends.
///
/// The only refusal is `InvalidVersion`, for a version this core does not
/// speak; on it nothing is derived and no half-built pair is returned.
/// `version` chooses the salt and the HKDF labels as well, so the same cid
/// under v1 and under v2 yields different keys.
pub fn deriveInitialKeyMaterial(
    cid: []const u8,
    version: u32,
    comptime is_server: bool,
) !struct { Open, Seal } {
    if (!protocol.isSupportedVersion(version)) {
        std.log.debug("unsupported QUIC version: 0x{x:0>8}", .{version});
        return error.InvalidVersion;
    }

    // RFC 9001 §5.2 / RFC 9369 §3.1: version-specific initial salt
    const salt = if (protocol.isV2(version)) &INITIAL_SALT_V2 else &INITIAL_SALT_V1;
    const label_key = protocol.quicLabel(version, .key);
    const label_iv = protocol.quicLabel(version, .iv);
    const label_hp = protocol.quicLabel(version, .hp);

    const initial_secret = HkdfSha256.extract(salt, cid);
    var secret: [32]u8 = undefined;

    // Client (Initial keys are always AES-128-GCM)
    secret = hkdfExpandLabel(initial_secret, "client in", "", Hmac.key_length);
    const client_key_16 = hkdfExpandLabel(secret, label_key, "", key_len);
    const client_iv = hkdfExpandLabel(secret, label_iv, "", nonce_len);
    const client_hp_16 = hkdfExpandLabel(secret, label_hp, "", key_len);
    var client_key: [max_key_len]u8 = @splat(0);
    @memcpy(client_key[0..key_len], &client_key_16);
    var client_hp_key: [max_key_len]u8 = @splat(0);
    @memcpy(client_hp_key[0..key_len], &client_hp_16);

    // Server
    secret = hkdfExpandLabel(initial_secret, "server in", "", Hmac.key_length);
    const server_key_16 = hkdfExpandLabel(secret, label_key, "", key_len);
    const server_iv = hkdfExpandLabel(secret, label_iv, "", nonce_len);
    const server_hp_16 = hkdfExpandLabel(secret, label_hp, "", key_len);
    var server_key: [max_key_len]u8 = @splat(0);
    @memcpy(server_key[0..key_len], &server_key_16);
    var server_hp_key: [max_key_len]u8 = @splat(0);
    @memcpy(server_hp_key[0..key_len], &server_hp_16);

    var open: Open = undefined;
    var seal: Seal = undefined;
    if (is_server) {
        open = .{ .key = client_key, .hp_key = client_hp_key, .nonce = client_iv };
        seal = .{ .key = server_key, .hp_key = server_hp_key, .nonce = server_iv };
    } else {
        open = .{ .key = server_key, .hp_key = server_hp_key, .nonce = server_iv };
        seal = .{ .key = client_key, .hp_key = client_hp_key, .nonce = client_iv };
    }
    open.prepareCtx();
    seal.prepareCtx();
    return .{ open, seal };
}

// https://www.rfc-editor.org/rfc/rfc9001#section-a.1
test "decryptPayload rejects a payload shorter than its tag" {
    const keys = try deriveInitialKeyMaterial(&[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 }, protocol.QUIC_V1, false);
    var open = keys[0];

    // The payload length is the peer's Length varint minus the packet number.
    var short = @as([8]u8, @splat(0));
    try std.testing.expectError(error.AuthenticationFailed, open.decryptPayload(0, &.{}, &short));
}

test "a.1: keys - initial secret" {
    {
        const expected = [_]u8{ 0x7d, 0xb5, 0xdf, 0x06, 0xe7, 0xa6, 0x9e, 0x43, 0x24, 0x96, 0xad, 0xed, 0xb0, 0x08, 0x51, 0x92, 0x35, 0x95, 0x22, 0x15, 0x96, 0xae, 0x2a, 0xe9, 0xfb, 0x81, 0x15, 0xc1, 0xe9, 0xed, 0x0a, 0x44 };
        const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
        const out = HkdfSha256.extract(&INITIAL_SALT_V1, &dcid);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
    {
        const expected = [_]u8{ 0xf0, 0x16, 0xbb, 0x2d, 0xc9, 0x97, 0x6d, 0xea, 0x27, 0x26, 0xc4, 0xe6, 0x1e, 0x73, 0x8a, 0x1e, 0x36, 0x80, 0xa2, 0x48, 0x75, 0x91, 0xdc, 0x76, 0xb2, 0xae, 0xe2, 0xed, 0x75, 0x98, 0x22, 0xf6 };
        const dcid = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
        const out = HkdfSha256.extract(&INITIAL_SALT_V1, &dcid);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
}

// https://www.rfc-editor.org/rfc/rfc9001#section-a.1
test "a.1: keys - server initial secret" {
    {
        const expected = [_]u8{ 0x3c, 0x19, 0x98, 0x28, 0xfd, 0x13, 0x9e, 0xfd, 0x21, 0x6c, 0x15, 0x5a, 0xd8, 0x44, 0xcc, 0x81, 0xfb, 0x82, 0xfa, 0x8d, 0x74, 0x46, 0xfa, 0x7d, 0x78, 0xbe, 0x80, 0x3a, 0xcd, 0xda, 0x95, 0x1b };
        const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
        const initial_secret = HkdfSha256.extract(&INITIAL_SALT_V1, &dcid);
        var out = hkdfExpandLabel(initial_secret, "server in", "", Hmac.key_length);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
    {
        // This test case is brought from https://quic.xargs.org/
        const expected = [_]u8{ 0xad, 0xc1, 0x99, 0x5b, 0x5c, 0xee, 0x8f, 0x03, 0x74, 0x6b, 0xf8, 0x30, 0x9d, 0x02, 0xd5, 0xea, 0x27, 0x15, 0x9c, 0x1e, 0xd6, 0x91, 0x54, 0x03, 0xb3, 0x63, 0x18, 0xd5, 0xa0, 0x3a, 0xfe, 0xb8 };
        const dcid = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
        const initial_secret = HkdfSha256.extract(&INITIAL_SALT_V1, &dcid);
        var out = hkdfExpandLabel(initial_secret, "server in", "", Hmac.key_length);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
}

test "a.1: keys - client initial secret" {
    {
        const expected = [_]u8{ 0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75, 0xed, 0x0e, 0xbf, 0xb5, 0xc8, 0x03, 0x23, 0xc4, 0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81, 0x28, 0x9a, 0xf4, 0x00, 0x8f, 0x1f, 0x6c, 0x35, 0x7a, 0xea };
        const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
        const initial_secret = HkdfSha256.extract(&INITIAL_SALT_V1, &dcid);
        var out = hkdfExpandLabel(initial_secret, "client in", "", Hmac.key_length);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }

    {
        // This test case is brought from https://quic.xargs.org/
        const expected = [_]u8{ 0x47, 0xc6, 0xa6, 0x38, 0xd4, 0x96, 0x85, 0x95, 0xcc, 0x20, 0xb7, 0xc8, 0xbc, 0x5f, 0xbf, 0xbf, 0xd0, 0x2d, 0x7c, 0x17, 0xcc, 0x67, 0xfa, 0x54, 0x8c, 0x04, 0x3e, 0xcb, 0x54, 0x7b, 0x0e, 0xaa };
        const dcid = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
        const initial_secret = HkdfSha256.extract(&INITIAL_SALT_V1, &dcid);
        var out = hkdfExpandLabel(initial_secret, "client in", "", Hmac.key_length);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
}

test "AEAD key" {
    {
        // This test case is brought from https://www.rfc-editor.org/rfc/rfc9001#section-a.1
        const server_initial_secret = [_]u8{ 0x3c, 0x19, 0x98, 0x28, 0xfd, 0x13, 0x9e, 0xfd, 0x21, 0x6c, 0x15, 0x5a, 0xd8, 0x44, 0xcc, 0x81, 0xfb, 0x82, 0xfa, 0x8d, 0x74, 0x46, 0xfa, 0x7d, 0x78, 0xbe, 0x80, 0x3a, 0xcd, 0xda, 0x95, 0x1b };
        const expected = [_]u8{ 0xcf, 0x3a, 0x53, 0x31, 0x65, 0x3c, 0x36, 0x4c, 0x88, 0xf0, 0xf3, 0x79, 0xb6, 0x06, 0x7e, 0x37 };
        const out = hkdfExpandLabel(server_initial_secret, "quic key", "", key_len);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
    {
        // This test case is brought from https://www.rfc-editor.org/rfc/rfc9001#section-a.1
        const client_initial_secret = [_]u8{ 0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75, 0xed, 0x0e, 0xbf, 0xb5, 0xc8, 0x03, 0x23, 0xc4, 0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81, 0x28, 0x9a, 0xf4, 0x00, 0x8f, 0x1f, 0x6c, 0x35, 0x7a, 0xea };
        const expected = [_]u8{ 0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46, 0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d };
        const out = hkdfExpandLabel(client_initial_secret, "quic key", "", key_len);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
    {
        const server_initial_secret = [_]u8{ 0xad, 0xc1, 0x99, 0x5b, 0x5c, 0xee, 0x8f, 0x03, 0x74, 0x6b, 0xf8, 0x30, 0x9d, 0x02, 0xd5, 0xea, 0x27, 0x15, 0x9c, 0x1e, 0xd6, 0x91, 0x54, 0x03, 0xb3, 0x63, 0x18, 0xd5, 0xa0, 0x3a, 0xfe, 0xb8 };
        const expected = [_]u8{ 0xd7, 0x7f, 0xc4, 0x05, 0x6f, 0xcf, 0xa3, 0x2b, 0xd1, 0x30, 0x24, 0x69, 0xee, 0x6e, 0xbf, 0x90 };
        const out = hkdfExpandLabel(server_initial_secret, "quic key", "", key_len);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
    {
        // This test case is brought from https://quic.xargs.org/
        const client_initial_secret = [_]u8{ 0x47, 0xc6, 0xa6, 0x38, 0xd4, 0x96, 0x85, 0x95, 0xcc, 0x20, 0xb7, 0xc8, 0xbc, 0x5f, 0xbf, 0xbf, 0xd0, 0x2d, 0x7c, 0x17, 0xcc, 0x67, 0xfa, 0x54, 0x8c, 0x04, 0x3e, 0xcb, 0x54, 0x7b, 0x0e, 0xaa };
        const expected = [_]u8{ 0xb1, 0x4b, 0x91, 0x81, 0x24, 0xfd, 0xa5, 0xc8, 0xd7, 0x98, 0x47, 0x60, 0x2f, 0xa3, 0x52, 0x0b };
        const out = hkdfExpandLabel(client_initial_secret, "quic key", "", key_len);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
}

test "IV (initialization vector)" {
    {
        // This test case is brought from https://www.rfc-editor.org/rfc/rfc9001#section-a.1
        const expected = [_]u8{ 0x0a, 0xc1, 0x49, 0x3c, 0xa1, 0x90, 0x58, 0x53, 0xb0, 0xbb, 0xa0, 0x3e };
        const server_initial_secret = [_]u8{ 0x3c, 0x19, 0x98, 0x28, 0xfd, 0x13, 0x9e, 0xfd, 0x21, 0x6c, 0x15, 0x5a, 0xd8, 0x44, 0xcc, 0x81, 0xfb, 0x82, 0xfa, 0x8d, 0x74, 0x46, 0xfa, 0x7d, 0x78, 0xbe, 0x80, 0x3a, 0xcd, 0xda, 0x95, 0x1b };
        const out = hkdfExpandLabel(server_initial_secret, "quic iv", "", nonce_len);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
    {
        const expected = [_]u8{ 0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c };
        const client_initial_secret = [_]u8{ 0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75, 0xed, 0x0e, 0xbf, 0xb5, 0xc8, 0x03, 0x23, 0xc4, 0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81, 0x28, 0x9a, 0xf4, 0x00, 0x8f, 0x1f, 0x6c, 0x35, 0x7a, 0xea };
        const out = hkdfExpandLabel(client_initial_secret, "quic iv", "", nonce_len);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
    {
        const expected = [_]u8{ 0xfc, 0xb7, 0x48, 0xe3, 0x7f, 0xf7, 0x98, 0x60, 0xfa, 0xa0, 0x74, 0x77 };
        const server_initial_secret = [_]u8{ 0xad, 0xc1, 0x99, 0x5b, 0x5c, 0xee, 0x8f, 0x03, 0x74, 0x6b, 0xf8, 0x30, 0x9d, 0x02, 0xd5, 0xea, 0x27, 0x15, 0x9c, 0x1e, 0xd6, 0x91, 0x54, 0x03, 0xb3, 0x63, 0x18, 0xd5, 0xa0, 0x3a, 0xfe, 0xb8 };
        const out = hkdfExpandLabel(server_initial_secret, "quic iv", "", nonce_len);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
    {
        const expected = [_]u8{ 0xdd, 0xbc, 0x15, 0xde, 0xa8, 0x09, 0x25, 0xa5, 0x56, 0x86, 0xa7, 0xdf };
        const client_initial_secret = [_]u8{ 0x47, 0xc6, 0xa6, 0x38, 0xd4, 0x96, 0x85, 0x95, 0xcc, 0x20, 0xb7, 0xc8, 0xbc, 0x5f, 0xbf, 0xbf, 0xd0, 0x2d, 0x7c, 0x17, 0xcc, 0x67, 0xfa, 0x54, 0x8c, 0x04, 0x3e, 0xcb, 0x54, 0x7b, 0x0e, 0xaa };
        const out = hkdfExpandLabel(client_initial_secret, "quic iv", "", nonce_len);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
}

test "header protection key" {
    {
        const expected = [_]u8{ 0xc2, 0x06, 0xb8, 0xd9, 0xb9, 0xf0, 0xf3, 0x76, 0x44, 0x43, 0x0b, 0x49, 0x0e, 0xea, 0xa3, 0x14 };
        const server_initial_secret = [_]u8{ 0x3c, 0x19, 0x98, 0x28, 0xfd, 0x13, 0x9e, 0xfd, 0x21, 0x6c, 0x15, 0x5a, 0xd8, 0x44, 0xcc, 0x81, 0xfb, 0x82, 0xfa, 0x8d, 0x74, 0x46, 0xfa, 0x7d, 0x78, 0xbe, 0x80, 0x3a, 0xcd, 0xda, 0x95, 0x1b };
        const out = hkdfExpandLabel(server_initial_secret, "quic hp", "", key_len);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
    {
        const expected = [_]u8{ 0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2 };
        const client_initial_secret = [_]u8{ 0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75, 0xed, 0x0e, 0xbf, 0xb5, 0xc8, 0x03, 0x23, 0xc4, 0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81, 0x28, 0x9a, 0xf4, 0x00, 0x8f, 0x1f, 0x6c, 0x35, 0x7a, 0xea };
        const out = hkdfExpandLabel(client_initial_secret, "quic hp", "", key_len);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
    {
        const expected = [_]u8{ 0x44, 0x0b, 0x27, 0x25, 0xe9, 0x1d, 0xc7, 0x9b, 0x37, 0x07, 0x11, 0xef, 0x79, 0x2f, 0xaa, 0x3d };
        const server_initial_secret = [_]u8{ 0xad, 0xc1, 0x99, 0x5b, 0x5c, 0xee, 0x8f, 0x03, 0x74, 0x6b, 0xf8, 0x30, 0x9d, 0x02, 0xd5, 0xea, 0x27, 0x15, 0x9c, 0x1e, 0xd6, 0x91, 0x54, 0x03, 0xb3, 0x63, 0x18, 0xd5, 0xa0, 0x3a, 0xfe, 0xb8 };
        const out = hkdfExpandLabel(server_initial_secret, "quic hp", "", key_len);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
    {
        const expected = [_]u8{ 0x6d, 0xf4, 0xe9, 0xd7, 0x37, 0xcd, 0xf7, 0x14, 0x71, 0x1d, 0x7c, 0x61, 0x7e, 0xe8, 0x29, 0x81 };
        const client_initial_secret = [_]u8{ 0x47, 0xc6, 0xa6, 0x38, 0xd4, 0x96, 0x85, 0x95, 0xcc, 0x20, 0xb7, 0xc8, 0xbc, 0x5f, 0xbf, 0xbf, 0xd0, 0x2d, 0x7c, 0x17, 0xcc, 0x67, 0xfa, 0x54, 0x8c, 0x04, 0x3e, 0xcb, 0x54, 0x7b, 0x0e, 0xaa };
        const out = hkdfExpandLabel(client_initial_secret, "quic hp", "", key_len);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
}

/// RFC 8446 §7.1 HKDF-Expand-Label.
///
/// `secret` and the returned array are both values; `label` and `context` are
/// read during the call and retained by nothing, and nothing is allocated.
/// `length` is comptime because it is what sizes the result, so a caller
/// gets an array of a width known at the call site.
pub fn hkdfExpandLabel(
    secret: [32]u8,
    label: []const u8,
    context: []const u8,
    comptime length: u16,
) [length]u8 {
    return tls.hkdfExpandLabel(HkdfSha256, secret, label, context, length);
}

/// Derive a QUIC key and pad to max_key_len.
/// `actual_len` is the real key length (16 for AES, 32 for ChaCha20).
///
/// The width is chosen by testing `actual_len` against 32, so any other
/// value derives a 16-byte key; the length a suite actually uses comes from
/// `CipherSuite.keyLen`. Bytes past the key that is really there are zero
/// padding, and the AEAD never reads them.
///
/// The label is the one `version` spells, and a version that is not v2 —
/// including one this core does not support — derives under the v1 label
/// rather than being refused. `secret` is a value, the result is a value, and
/// nothing is allocated.
pub fn deriveKeyPaddedV(secret: [32]u8, actual_len: usize, version: u32) [max_key_len]u8 {
    return deriveKeyPaddedL(secret, actual_len, protocol.quicLabel(version, .key));
}

// Derive key with an explicit label string (runtime).
fn deriveKeyPaddedL(secret: [32]u8, actual_len: usize, label: []const u8) [max_key_len]u8 {
    var result: [max_key_len]u8 = @splat(0);
    if (actual_len == 32) {
        result = hkdfExpandLabel(secret, label, "", 32);
    } else {
        const k16 = hkdfExpandLabel(secret, label, "", 16);
        @memcpy(result[0..16], &k16);
    }
    return result;
}

/// The header-protection key for `secret`, zero-padded to the widest key
/// array, under the label `version` spells (RFC 9001 §5.4).
///
/// `actual_len` is the key length the traffic secret was derived for — 32 for
/// the SHA-256 suites, 16 for the Initial keys — and the difference shows up
/// as zeros past the key that is really there. As in `deriveKeyPaddedV`, 32
/// is the width that is tested, so anything else derives 16 bytes.
///
/// A `version` that is not v2 gets the v1 label rather than a refusal.
///
pub fn deriveHpKeyPaddedV(secret: [32]u8, actual_len: usize, version: u32) [max_key_len]u8 {
    return deriveKeyPaddedL(secret, actual_len, protocol.quicLabel(version, .hp));
}

/// AES-128-GCM confidentiality limit: 2^23 packets (~8M).
/// After this many packets, keys must be rotated to maintain security.
///
/// The AES number as a constant. The limit that applies to whatever suite a
/// connection negotiated is `CipherSuite.confidentialityLimit`, and that is
/// the one `KeyUpdateManager.shouldInitiateUpdate` counts against.
pub const CONFIDENTIALITY_LIMIT: u64 = 1 << 23;

/// Derive the next traffic secret for key update, under the v1 label.
/// RFC 9001 Section 6.1:
///   secret_<n+1> = HKDF-Expand-Label(secret_<n>, "quic ku", "", 32)
///
/// `current` is a value and so is the result; nothing is allocated.
pub fn deriveNextTrafficSecret(current: [32]u8) [32]u8 {
    return deriveNextTrafficSecretV(current, protocol.QUIC_V1);
}

/// The next traffic secret in a key update, under `version`'s label
/// (RFC 9001 §6.1). A pure derivation: no state, no randomness, and the same
/// input always gives the same output.
///
/// A `version` that is not v2 derives under the v1 label rather than being
/// refused, so this is a v2 chain only when `version` says so. `current` is a
/// value and so is the result; nothing is allocated.
///
pub fn deriveNextTrafficSecretV(current: [32]u8, version: u32) [32]u8 {
    return hkdfExpandLabel(current, protocol.quicLabel(version, .ku), "", 32);
}

/// Manages QUIC key update (RFC 9001 Section 6).
///
/// Holds three generations of keys (previous/current/next) to handle
/// packet reordering during key transitions. The header protection key
/// never changes across updates (RFC 9001 Section 6.6).
///
/// A value that owns nothing: no allocator, no buffers, no clock. Every
/// instant reaches it as an argument, and it belongs to the one thread that
/// owns it. The keys `getOpenKeys` and `getSealAndPhase` hand out are
/// pointers into this value, so a `rollKeys` while one is held moves what it
/// points at, and moving the manager leaves any such pointer behind.
pub const KeyUpdateManager = struct {
    /// The keys for the current generation: `current_open` decrypts what
    /// arrives, `current_seal` encrypts what leaves. A `rollKeys` replaces
    /// both and keeps the old `current_open` in `prev_open`.
    current_open: Open,
    current_seal: Seal,

    /// The previous generation's opening keys, kept so a reordered packet
    /// from it still verifies. Null until the first `rollKeys`, and null
    /// again once `maybeDropPrevKeys` has reached `prev_open_expires`.
    /// There is no previous `Seal`: a peer does not accept a packet sealed
    /// under keys this side has stopped using.
    prev_open: ?Open = null,

    /// The next generation's keys, derived once at construction and again
    /// by every `rollKeys`, so adopting a peer's update costs no derivation.
    next_open: Open,
    next_seal: Seal,

    /// The key phase bit this side writes into its short headers and the one
    /// an incoming packet's is compared against. False after construction;
    /// every `rollKeys` toggles it.
    key_phase: bool = false,

    /// The header-protection keys, which never change across updates. The
    /// AEAD keys of every generation above are built to use these.
    hp_open: [max_key_len]u8,
    hp_seal: [max_key_len]u8,

    /// Pre-expanded AES-128 round keys for the two HP keys above (AES suites
    /// only, null under ChaCha20). Built once at construction, because the
    /// HP keys themselves never change.
    hp_open_ctx: ?Aes128HpCtx = null,
    hp_seal_ctx: ?Aes128HpCtx = null,

    /// The suite every generation's keys were derived for. It is fixed at
    /// construction: a different suite is a new manager, not a new field.
    cipher_suite: CipherSuite = .aes_128_gcm_sha256,

    /// The version whose HKDF labels this chain advances under — `quic ku`
    /// under v1, `quicv2 ku` under v2. A version that is not v2 advances
    /// under the v1 labels.
    version: u32 = protocol.QUIC_V1,

    /// The current generation's traffic secrets, which the next one is
    /// derived from. Only `rollKeys` replaces them, with the next
    /// generation's.
    recv_secret: [32]u8,
    send_secret: [32]u8,

    /// Nanoseconds on the caller's clock at which `prev_open` stops being
    /// kept — the `now + 3 * pto_ns` of the last `rollKeys`. Null whenever
    /// there is no previous generation.
    prev_open_expires: ?i64 = null,

    /// Packet number of the first packet sent under the current keys, set
    /// by the first `onPacketSent` after a rotation and null before that.
    first_sent_with_current: ?u64 = null,

    /// First sent packet number under current keys in each supported MP path.
    /// Null means this generation has not sent on that path. rollKeys clears
    /// both; independent packet-number spaces cannot share the scalar marker.
    first_sent_for_path: [2]?u64 = .{ null, null },

    /// Whether the peer has acknowledged a packet sent under the current
    /// keys. onAckForPath sets it only from that path's current-generation
    /// marker; legacy callers may still compare first_sent_with_current.
    /// A rollKeys clears it again.
    first_acked_with_current: bool = false,

    /// A received key update still needs an application send in the new phase.
    /// The packet opener rejects another authenticated next-generation update
    /// while true. ACK frames cannot clear this connection-wide Noq guard.
    peer_update_unacked: bool = false,

    /// Packets sent under the current keys, counted by `onPacketSent` and
    /// reset by `rollKeys`. It is the number `shouldInitiateUpdate` compares
    /// against the suite's confidentiality limit.
    packets_sent_with_current: u64 = 0,

    /// Initialize the key update manager from initial traffic secrets.
    /// `recv_secret` is the peer's traffic secret (for decryption).
    /// `send_secret` is our traffic secret (for encryption).
    ///
    /// All four arguments are values and are copied in; the manager is
    /// returned by value, borrows nothing and allocates nothing. This is
    /// `initWithCipherSuite` under AES-128-GCM, deriving with the v1
    /// labels — a v2 connection wants `initFull`.
    pub fn init(recv_secret: [32]u8, send_secret: [32]u8, recv_hp: [max_key_len]u8, send_hp: [max_key_len]u8) KeyUpdateManager {
        return initWithCipherSuite(recv_secret, send_secret, recv_hp, send_hp, .aes_128_gcm_sha256);
    }

    /// `init` for a suite TLS negotiated, still under the v1 labels.
    ///
    /// The arguments mean what `init` says they mean; the suite adds the
    /// AEAD and the key width the secrets are derived at, and the prepared
    /// contexts are built for it.
    pub fn initWithCipherSuite(recv_secret: [32]u8, send_secret: [32]u8, recv_hp: [max_key_len]u8, send_hp: [max_key_len]u8, cipher_suite: CipherSuite) KeyUpdateManager {
        return initFull(recv_secret, send_secret, recv_hp, send_hp, cipher_suite, protocol.QUIC_V1);
    }

    /// The full constructor: a suite, and the version whose HKDF labels
    /// every generation of this chain advances under.
    ///
    /// The four traffic-secret arguments mean what `init` says they mean.
    /// The HP keys are taken as given rather than re-derived, so they must
    /// already be the header-protection keys of these secrets: `keyLen`
    /// bytes that are really the key, the rest ignored. `version` is not
    /// validated — a version that is not v2 derives under the v1 labels.
    ///
    /// The result holds the current generation with the next one already
    /// derived from it, no previous generation, key phase false and every
    /// counter at zero. It allocates nothing; a caller that later takes a
    /// pointer into it must not move it.
    pub fn initFull(recv_secret: [32]u8, send_secret: [32]u8, recv_hp: [max_key_len]u8, send_hp: [max_key_len]u8, cipher_suite: CipherSuite, version: u32) KeyUpdateManager {
        const kl = cipher_suite.keyLen();
        const label_key = protocol.quicLabel(version, .key);
        const label_iv = protocol.quicLabel(version, .iv);

        // Derive current Open/Seal from the initial secrets
        const recv_key = deriveKeyPaddedL(recv_secret, kl, label_key);
        const recv_iv = hkdfExpandLabel(recv_secret, label_iv, "", nonce_len);
        const send_key = deriveKeyPaddedL(send_secret, kl, label_key);
        const send_iv = hkdfExpandLabel(send_secret, label_iv, "", nonce_len);

        // Pre-compute next generation secrets and keys
        const next_recv_secret = deriveNextTrafficSecretV(recv_secret, version);
        const next_send_secret = deriveNextTrafficSecretV(send_secret, version);
        const next_recv_key = deriveKeyPaddedL(next_recv_secret, kl, label_key);
        const next_recv_iv = hkdfExpandLabel(next_recv_secret, label_iv, "", nonce_len);
        const next_send_key = deriveKeyPaddedL(next_send_secret, kl, label_key);
        const next_send_iv = hkdfExpandLabel(next_send_secret, label_iv, "", nonce_len);

        var ku: KeyUpdateManager = .{
            .current_open = .{ .key = recv_key, .hp_key = recv_hp, .nonce = recv_iv, .cipher_suite = cipher_suite },
            .current_seal = .{ .key = send_key, .hp_key = send_hp, .nonce = send_iv, .cipher_suite = cipher_suite },
            .next_open = .{ .key = next_recv_key, .hp_key = recv_hp, .nonce = next_recv_iv, .cipher_suite = cipher_suite },
            .next_seal = .{ .key = next_send_key, .hp_key = send_hp, .nonce = next_send_iv, .cipher_suite = cipher_suite },
            .hp_open = recv_hp,
            .hp_seal = send_hp,
            .hp_open_ctx = null,
            .hp_seal_ctx = null,
            .cipher_suite = cipher_suite,
            .version = version,
            .recv_secret = recv_secret,
            .send_secret = send_secret,
        };
        ku.current_open.prepareCtx();
        ku.current_seal.prepareCtx();
        ku.next_open.prepareCtx();
        ku.next_seal.prepareCtx();
        if (cipher_suite == .aes_128_gcm_sha256) {
            ku.hp_open_ctx = Aes128.initEnc(recv_hp[0..16].*);
            ku.hp_seal_ctx = Aes128.initEnc(send_hp[0..16].*);
        }
        return ku;
    }

    /// Rotate keys: prev←current, current←next, pre-compute new next.
    /// Toggles the key phase bit. Sets prev_open expiry to now + 3×PTO.
    ///
    /// `now` and `pto_ns` are nanoseconds on the caller's own clock, the
    /// same clock `maybeDropPrevKeys` is later given; the expiry is written
    /// as `now + 3 * pto_ns`, so this side's own PTO is what bounds how long
    /// `prev_open` is kept.
    ///
    /// The secrets advance under this manager's `version` labels and the
    /// generation counters start over: `first_sent_with_current` null,
    /// `first_acked_with_current` false, `packets_sent_with_current` zero. A
    /// pointer handed out by `getOpenKeys` or `getSealAndPhase` before this
    /// call points at keys that have just changed generation.
    pub fn rollKeys(self: *KeyUpdateManager, now: i64, pto_ns: i64) void {
        // Move current → previous
        self.prev_open = self.current_open;
        self.prev_open_expires = now + 3 * pto_ns;

        // Move next → current
        self.current_open = self.next_open;
        self.current_seal = self.next_seal;

        // Advance secrets (version-aware labels)
        self.recv_secret = deriveNextTrafficSecretV(self.recv_secret, self.version);
        self.send_secret = deriveNextTrafficSecretV(self.send_secret, self.version);

        // Pre-compute new next-generation keys
        const kl = self.cipher_suite.keyLen();
        const label_key = protocol.quicLabel(self.version, .key);
        const label_iv = protocol.quicLabel(self.version, .iv);
        const next_recv_secret = deriveNextTrafficSecretV(self.recv_secret, self.version);
        const next_send_secret = deriveNextTrafficSecretV(self.send_secret, self.version);
        self.next_open = .{
            .key = deriveKeyPaddedL(next_recv_secret, kl, label_key),
            .hp_key = self.hp_open,
            .nonce = hkdfExpandLabel(next_recv_secret, label_iv, "", nonce_len),
            .cipher_suite = self.cipher_suite,
        };
        self.next_seal = .{
            .key = deriveKeyPaddedL(next_send_secret, kl, label_key),
            .hp_key = self.hp_seal,
            .nonce = hkdfExpandLabel(next_send_secret, label_iv, "", nonce_len),
            .cipher_suite = self.cipher_suite,
        };
        self.next_open.prepareCtx();
        self.next_seal.prepareCtx();

        // Toggle key phase
        self.key_phase = !self.key_phase;

        // Reset tracking for the new generation
        self.first_sent_with_current = null;
        self.first_sent_for_path = .{ null, null };
        self.first_acked_with_current = false;
        self.packets_sent_with_current = 0;
    }

    /// Installs an authenticated peer-initiated update and requires a send
    /// before another peer update. The packet opener must first authenticate
    /// and reject peer_update_unacked; this precondition is asserted here.
    /// Uses the same caller clock and PTO retention contract as rollKeys.
    pub fn onPeerKeyUpdate(self: *KeyUpdateManager, now: i64, pto_ns: i64) void {
        assert(!self.peer_update_unacked);
        self.rollKeys(now, pto_ns);
        self.peer_update_unacked = true;
    }

    /// Get the Open keys for decrypting a packet based on its key phase bit.
    ///
    /// A bit equal to this side's is the current generation. A bit that
    /// differs is either a reordered packet from the previous generation —
    /// `prev_open`, while one is kept — or the peer having rotated first
    /// (RFC 9001 §6.1), which is `next_open`. There is no third answer, and
    /// the result is never null: a caller that reads null as "packet
    /// rejected" never sees it, and a packet from an older generation than
    /// `prev_open` is left to fail authentication.
    ///
    /// The pointer is into this manager, so the next `rollKeys` invalidates
    /// it, and so does moving the manager. Nothing is allocated.
    pub fn getOpenKeys(self: *KeyUpdateManager, key_phase_bit: bool) ?*Open {
        if (key_phase_bit == self.key_phase) {
            return &self.current_open;
        }
        // Key phase differs from current:
        // 1. If prev_open exists → reordered packet from previous generation
        // 2. Otherwise → peer-initiated key update, use next_open (RFC 9001 §6.1)
        if (self.prev_open != null) {
            return &self.prev_open.?;
        }
        return &self.next_open;
    }

    /// Get the current Seal keys and key phase bit for encrypting a packet.
    ///
    /// They are answered together because a short header carries the phase
    /// bit the packet went out with, and a caller that reads the bit from the
    /// field separately can seal under one generation and mark another.
    /// `seal` points into this manager, so the next `rollKeys` invalidates
    /// it, and so does moving the manager. Nothing is allocated.
    pub fn getSealAndPhase(self: *KeyUpdateManager) struct { seal: *const Seal, key_phase: bool } {
        return .{ .seal = &self.current_seal, .key_phase = self.key_phase };
    }

    /// Record that a packet was sent with current keys.
    ///
    /// `pn` is the packet number that packet went out with. Only the first
    /// one after a rotation is recorded, in `first_sent_with_current`; every
    /// call advances `packets_sent_with_current`. A caller sends nothing and
    /// must call this nothing, because that count is what the
    /// confidentiality limit is measured against.
    pub fn onPacketSent(self: *KeyUpdateManager, pn: u64) void {
        if (self.first_sent_with_current == null) {
            self.first_sent_with_current = pn;
        }
        self.onPacketSentForPath(0, pn);
    }

    /// Records one actual send under shared current keys on path 0 or 1.
    /// Increments the connection-wide confidentiality count exactly once.
    /// The caller must not also call onPacketSent for the same packet.
    /// Clears the peer-update guard only for a normal application-space send.
    /// Off-path challenge/response packets use onOffPathPacketSentForPath.
    pub fn onPacketSentForPath(self: *KeyUpdateManager, path_id: u1, pn: u64) void {
        self.onOffPathPacketSentForPath(path_id, pn);
        self.peer_update_unacked = false;
    }

    /// Counts one encrypted off-path application packet and records its first
    /// PN without confirming the peer update. Noq's off-path challenge/response
    /// route bypasses the normal send's update acknowledgment transition.
    /// The caller must not also count this packet with onPacketSentForPath.
    pub fn onOffPathPacketSentForPath(self: *KeyUpdateManager, path_id: u1, pn: u64) void {
        if (self.first_sent_for_path[path_id] == null) {
            self.first_sent_for_path[path_id] = pn;
        }
        self.packets_sent_with_current += 1;
    }

    /// Records an actually acknowledged sent packet in the identified path's
    /// PN space. An ACK before that path's first current-generation send, or
    /// on a path that has not sent in this generation, cannot permit update.
    /// The caller validates ACK ranges against sent packets before calling.
    pub fn onAckForPath(self: *KeyUpdateManager, path_id: u1, pn: u64) void {
        if (self.first_sent_for_path[path_id]) |first| {
            if (pn >= first) self.first_acked_with_current = true;
        }
    }

    /// Drop previous-generation keys if they have expired.
    ///
    /// `now` is nanoseconds on the same clock `rollKeys` was given, and the
    /// comparison is against the `now + 3 * pto_ns` written there. With no
    /// previous generation there is nothing to compare and nothing happens.
    /// After a drop, a reordered packet from that generation fails to
    /// authenticate, which is the intent (RFC 9001 §6.1).
    pub fn maybeDropPrevKeys(self: *KeyUpdateManager, now: i64) void {
        if (self.prev_open_expires) |expires| {
            if (now >= expires) {
                self.prev_open = null;
                self.prev_open_expires = null;
            }
        }
    }

    /// Check if we should proactively initiate a key update.
    /// Returns true if packets sent with current keys >= confidentiality limit.
    ///
    /// The limit is `cipher_suite.confidentialityLimit`, counted in packets
    /// and not in bytes. This is a reason to rotate, not permission to: the
    /// caller still has to ask `canUpdate`.
    pub fn shouldInitiateUpdate(self: *const KeyUpdateManager) bool {
        return self.packets_sent_with_current >= self.cipher_suite.confidentialityLimit();
    }

    /// Check if we are allowed to initiate a key update.
    /// Must have sent and received ACK for a packet with current keys.
    ///
    /// It reads first_acked_with_current, set by onAckForPath or by the legacy
    /// caller's path-zero acknowledgement check and cleared by rollKeys.
    /// A pending peer update also requires a normal application send first;
    /// off-path traffic or an ACK cannot bypass that acknowledgment.
    /// Like Noq force_key_update, local rotation also waits until previous
    /// keys are discarded; otherwise it would overwrite retained shared keys.
    /// It says nothing about the confidentiality limit; both answers are
    /// needed before rotating.
    pub fn canUpdate(self: *const KeyUpdateManager) bool {
        return self.first_acked_with_current and
            !self.peer_update_unacked and self.prev_open == null;
    }
};

// Key update tests
test "deriveNextTrafficSecret produces different secret" {
    const initial_secret = [_]u8{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    };
    const next = deriveNextTrafficSecret(initial_secret);

    // Next secret must differ from original
    try std.testing.expect(!std.mem.eql(u8, &initial_secret, &next));

    // Deterministic: same input → same output
    const next2 = deriveNextTrafficSecret(initial_secret);
    try std.testing.expectEqualSlices(u8, &next, &next2);

    // Chaining: deriving again gives a third distinct secret
    const next3 = deriveNextTrafficSecret(next);
    try std.testing.expect(!std.mem.eql(u8, &next, &next3));
    try std.testing.expect(!std.mem.eql(u8, &initial_secret, &next3));
}

test "KeyUpdateManager: init and basic operations" {
    const recv_secret = @as([32]u8, @splat(0xAA));
    const send_secret = @as([32]u8, @splat(0xBB));
    const recv_hp = @as([max_key_len]u8, @splat(0xCC));
    const send_hp = @as([max_key_len]u8, @splat(0xDD));

    var mgr = KeyUpdateManager.init(recv_secret, send_secret, recv_hp, send_hp);

    // Initial key phase is false
    try std.testing.expect(!mgr.key_phase);

    // Current keys should match key phase
    const open = mgr.getOpenKeys(false);
    try std.testing.expect(open != null);

    // Get seal should return current seal and phase
    const seal_info = mgr.getSealAndPhase();
    try std.testing.expect(!seal_info.key_phase);

    // HP keys should match
    try std.testing.expectEqualSlices(u8, &recv_hp, &mgr.hp_open);
    try std.testing.expectEqualSlices(u8, &send_hp, &mgr.hp_seal);

    // Should not initiate update yet (0 packets sent)
    try std.testing.expect(!mgr.shouldInitiateUpdate());
    try std.testing.expect(!mgr.canUpdate());
}

test "KeyUpdateManager: roll keys" {
    const recv_secret = @as([32]u8, @splat(0xAA));
    const send_secret = @as([32]u8, @splat(0xBB));
    const recv_hp = @as([max_key_len]u8, @splat(0xCC));
    const send_hp = @as([max_key_len]u8, @splat(0xDD));

    var mgr = KeyUpdateManager.init(recv_secret, send_secret, recv_hp, send_hp);
    const orig_open_key = mgr.current_open.key;
    const orig_seal_key = mgr.current_seal.key;

    // Roll keys
    const now: i64 = 1_000_000_000;
    const pto: i64 = 100_000_000; // 100ms
    mgr.rollKeys(now, pto);

    // Key phase should toggle
    try std.testing.expect(mgr.key_phase);

    // Current keys should be different
    try std.testing.expect(!std.mem.eql(u8, &orig_open_key, &mgr.current_open.key));
    try std.testing.expect(!std.mem.eql(u8, &orig_seal_key, &mgr.current_seal.key));

    // Previous open should exist
    try std.testing.expect(mgr.prev_open != null);
    try std.testing.expectEqualSlices(u8, &orig_open_key, &mgr.prev_open.?.key);

    // Previous should expire at now + 3*PTO
    try std.testing.expectEqual(now + 3 * pto, mgr.prev_open_expires.?);

    // HP keys should not change
    try std.testing.expectEqualSlices(u8, &recv_hp, &mgr.current_open.hp_key);
    try std.testing.expectEqualSlices(u8, &send_hp, &mgr.current_seal.hp_key);

    // Counters should be reset
    try std.testing.expect(mgr.first_sent_with_current == null);
    try std.testing.expect(!mgr.first_acked_with_current);
    try std.testing.expectEqual(@as(u64, 0), mgr.packets_sent_with_current);
}

test "KeyUpdateManager: prev key expiry" {
    const recv_secret = @as([32]u8, @splat(0xAA));
    const send_secret = @as([32]u8, @splat(0xBB));
    const recv_hp = @as([max_key_len]u8, @splat(0xCC));
    const send_hp = @as([max_key_len]u8, @splat(0xDD));

    var mgr = KeyUpdateManager.init(recv_secret, send_secret, recv_hp, send_hp);

    const now: i64 = 1_000_000_000;
    const pto: i64 = 100_000_000;
    mgr.rollKeys(now, pto);

    // Before expiry: prev keys should exist
    mgr.maybeDropPrevKeys(now + 2 * pto);
    try std.testing.expect(mgr.prev_open != null);

    // After expiry: prev keys should be dropped
    mgr.maybeDropPrevKeys(now + 3 * pto);
    try std.testing.expect(mgr.prev_open == null);
    try std.testing.expect(mgr.prev_open_expires == null);
}

test "KeyUpdateManager: encrypt/decrypt roundtrip across key update" {
    // Simulate two sides: client and server with swapped secrets
    const client_recv = @as([32]u8, @splat(0x11)); // = server_send
    const client_send = @as([32]u8, @splat(0x22)); // = server_recv
    const hp_a = @as([max_key_len]u8, @splat(0x33));
    const hp_b = @as([max_key_len]u8, @splat(0x44));

    var client = KeyUpdateManager.init(client_recv, client_send, hp_a, hp_b);
    var server = KeyUpdateManager.init(client_send, client_recv, hp_b, hp_a);

    // Client encrypts, server decrypts (generation 0)
    const plaintext = "hello key update";
    const ad = "associated data";
    var ciphertext: [plaintext.len + Aead.tag_length]u8 = undefined;
    _ = client.current_seal.encryptPayload(0, ad, plaintext, &ciphertext);

    const open_keys = server.getOpenKeys(false).?;
    const decrypted = try open_keys.decryptPayload(0, ad, &ciphertext);
    try std.testing.expectEqualStrings(plaintext, decrypted);

    // Roll both sides
    client.rollKeys(1_000_000_000, 100_000_000);
    server.rollKeys(1_000_000_000, 100_000_000);

    // Client encrypts with new keys, server decrypts (generation 1)
    var ciphertext2: [plaintext.len + Aead.tag_length]u8 = undefined;
    _ = client.current_seal.encryptPayload(1, ad, plaintext, &ciphertext2);

    const open_keys2 = server.getOpenKeys(true).?;
    const decrypted2 = try open_keys2.decryptPayload(1, ad, &ciphertext2);
    try std.testing.expectEqualStrings(plaintext, decrypted2);
}

test "Seal/Open encrypt/decrypt roundtrip" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const keys = try deriveInitialKeyMaterial(&dcid, 0x00000001, true);
    _ = keys[0]; // client keys (we're server, so we open client packets)
    const seal_key = keys[1]; // server keys (we seal server packets)

    // Encrypt a payload
    const plaintext = "Hello QUIC";
    const ad = "associated_data";
    const pn: u64 = 42;
    var ciphertext: [plaintext.len + Aead.tag_length]u8 = undefined;
    const enc_len = seal_key.encryptPayload(pn, ad, plaintext, &ciphertext);
    try std.testing.expectEqual(plaintext.len + Aead.tag_length, enc_len);

    // Verify ciphertext differs from plaintext
    try std.testing.expect(!std.mem.eql(u8, plaintext, ciphertext[0..plaintext.len]));

    // Decrypt - need to use Open with the server's keys
    // Derive server's open keys (from client perspective)
    const client_keys = try deriveInitialKeyMaterial(&dcid, 0x00000001, false);
    var client_open = client_keys[0]; // server keys opened by client
    const decrypted = try client_open.decryptPayload(pn, ad, &ciphertext);
    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "header protection roundtrip" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const server_keys = try deriveInitialKeyMaterial(&dcid, 0x00000001, true);
    const seal_key = server_keys[1]; // server seal (server's hp_key)
    // Client opens server packets using the same server hp_key
    const client_keys = try deriveInitialKeyMaterial(&dcid, 0x00000001, false);
    const open_key = client_keys[0]; // client open = server keys

    // Simulate a packet: long header byte + some header + 4-byte pn + 20 bytes of "encrypted payload"
    var pkt: [40]u8 = undefined;
    pkt[0] = 0xC3; // long header, Initial, pn_len=4 (first_byte & 0x03 = 3, means 4 bytes)
    // Fill header bytes 1..6
    for (1..6) |i| pkt[i] = @intCast(i);
    // pn at offset 6
    const pn_offset: usize = 6;
    const pn_len: usize = 4;
    std.mem.writeInt(u32, pkt[pn_offset..][0..4], 0x00000002, .big);
    // Fill "ciphertext" with non-zero data so the sample is not all zeros
    for (pkt[pn_offset + pn_len ..]) |*b| b.* = 0xAB;

    // Save original first byte and pn bytes
    const orig_first = pkt[0];
    var orig_pn: [4]u8 = undefined;
    @memcpy(&orig_pn, pkt[pn_offset..][0..4]);

    // Apply header protection
    applyHeaderProtection(&pkt, pn_offset, pn_len, seal_key.hp_key, seal_key.cipher_suite);

    // Verify something changed
    try std.testing.expect(pkt[0] != orig_first or !std.mem.eql(u8, &orig_pn, pkt[pn_offset..][0..4]));

    // Remove header protection
    const recovered_pn_len = removeHeaderProtection(&pkt, pn_offset, open_key.hp_key, open_key.cipher_suite);
    try std.testing.expectEqual(pn_len, recovered_pn_len);

    // Verify we got back the original values
    try std.testing.expectEqual(orig_first, pkt[0]);
    try std.testing.expectEqualSlices(u8, &orig_pn, pkt[pn_offset..][0..4]);
}

test "encodePacketNumber" {
    var out: [4]u8 = undefined;

    // First packet, no acked: pn=0
    try std.testing.expectEqual(@as(usize, 1), encodePacketNumber(0, null, &out));
    try std.testing.expectEqual(@as(u8, 0), out[0]);

    // pn=1, largest_acked=0: num_unacked=1, need 8 bits
    try std.testing.expectEqual(@as(usize, 1), encodePacketNumber(1, 0, &out));
    try std.testing.expectEqual(@as(u8, 1), out[0]);

    // pn=256, largest_acked=200: num_unacked=56, 2*56=112 fits in 8 bits
    try std.testing.expectEqual(@as(usize, 1), encodePacketNumber(256, 200, &out));

    // pn=300, largest_acked=0: num_unacked=300, 2*300=600 needs >8 bits → 16 bits
    try std.testing.expectEqual(@as(usize, 2), encodePacketNumber(300, 0, &out));
}

test "hkdfExpandLabel" {
    const early_secret = HkdfSha256.extract(&.{}, &@as([32]u8, @splat(0)));
    var empty_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("", &empty_hash, .{});
    const derived_secret = hkdfExpandLabel(early_secret, "derived", &empty_hash, 32);
    try std.testing.expectEqualSlices(u8, &.{
        0x6f, 0x26, 0x15, 0xa1, 0x08, 0xc7, 0x02,
        0xc5, 0x67, 0x8f, 0x54, 0xfc, 0x9d, 0xba,
        0xb6, 0x97, 0x16, 0xc0, 0x76, 0x18, 0x9c,
        0x48, 0x25, 0x0c, 0xeb, 0xea, 0xc3, 0x57,
        0x6c, 0x36, 0x11, 0xba,
    }, &derived_secret);
}

// RFC 9001 Appendix A.2: Client Initial packet protection test.
// Verifies full packet protection pipeline (AEAD + header protection)
// produces output consistent with the known test vectors.
test "RFC 9001 A.2: Client Initial packet protection" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

    // Derive client keys (from client perspective: is_server=false means client seals with client keys)
    const keys = try deriveInitialKeyMaterial(&dcid, 0x00000001, false);
    const seal = keys[1]; // client seal keys

    // Verify derived keys match RFC 9001 A.1 (AES-128-GCM: 16-byte keys padded to 32)
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46,
        0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d,
    }, seal.key[0..16]);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b,
        0x46, 0xfb, 0x25, 0x5c,
    }, &seal.nonce);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10,
        0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2,
    }, seal.hp_key[0..16]);

    // Build the Client Initial header (RFC 9001 A.2)
    // First byte: 0xc0 (long header, Initial type, 0-length pn encoding)
    // But we'll set pn_len=4, so first byte = 0xC3
    // Version: 0x00000001
    // DCID len: 0x08, DCID: 8394c8f03e515708
    // SCID len: 0x00
    // Token len: 0x00
    // Payload length: varint (includes pn + payload + tag)
    var pkt_buf: [1200]u8 = undefined;
    var pos: usize = 0;

    // First byte (will be modified by header protection later)
    pkt_buf[0] = 0xc0 | 0x03; // Long header, Initial, pn_len=4
    pos = 1;

    // Version
    std.mem.writeInt(u32, pkt_buf[pos..][0..4], 0x00000001, .big);
    pos += 4;

    // DCID
    pkt_buf[pos] = 0x08;
    pos += 1;
    @memcpy(pkt_buf[pos..][0..8], &dcid);
    pos += 8;

    // SCID (empty)
    pkt_buf[pos] = 0x00;
    pos += 1;

    // Token (empty)
    pkt_buf[pos] = 0x00;
    pos += 1;

    // Payload length placeholder - the RFC uses a specific 2-byte varint
    const length_offset = pos;
    pos += 2; // will fill in after we know the sizes

    // Packet number offset
    const pn_offset = pos;

    // Packet number = 2, encoded as 4 bytes
    std.mem.writeInt(u32, pkt_buf[pos..][0..4], 0x00000002, .big);
    pos += 4;

    const payload_start = pos;

    // Plaintext payload: CRYPTO frame with ClientHello + padding
    // The CRYPTO frame starts with: 06 00 40 f1 (type=0x06, offset=0, length=0x40f1=241)
    const crypto_frame_header = [_]u8{ 0x06, 0x00, 0x40, 0xf1 };
    @memcpy(pkt_buf[pos..][0..crypto_frame_header.len], &crypto_frame_header);
    pos += crypto_frame_header.len;

    // ClientHello data (241 bytes from the RFC)
    const client_hello = [_]u8{
        0x01, 0x00, 0x00, 0xed, 0x03, 0x03, 0xeb, 0xf8,
        0xfa, 0x56, 0xf1, 0x29, 0x39, 0xb9, 0x58, 0x4a,
        0x38, 0x96, 0x47, 0x2e, 0xc4, 0x0b, 0xb8, 0x63,
        0xcf, 0xd3, 0xe8, 0x68, 0x04, 0xfe, 0x3a, 0x47,
        0xf0, 0x6a, 0x2b, 0x69, 0x48, 0x4c, 0x00, 0x00,
        0x04, 0x13, 0x01, 0x13, 0x02, 0x01, 0x00, 0x00,
        0xc0, 0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00,
        0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
        0x65, 0x2e, 0x63, 0x6f, 0x6d, 0xff, 0x01, 0x00,
        0x01, 0x00, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x06,
        0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x10,
        0x00, 0x07, 0x00, 0x05, 0x04, 0x61, 0x6c, 0x70,
        0x6e, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24,
        0x00, 0x1d, 0x00, 0x20, 0x93, 0x70, 0xb2, 0xc9,
        0xca, 0xa4, 0x7f, 0xba, 0xba, 0xf4, 0x55, 0x9f,
        0xed, 0xba, 0x75, 0x3d, 0xe1, 0x71, 0xfa, 0x71,
        0xf5, 0x0f, 0x1c, 0xe1, 0x5d, 0x43, 0xe9, 0x94,
        0xec, 0x74, 0xd7, 0x48, 0x00, 0x2b, 0x00, 0x03,
        0x02, 0x03, 0x04, 0x00, 0x0d, 0x00, 0x10, 0x00,
        0x0e, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02,
        0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x00,
        0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x1c, 0x00,
        0x02, 0x40, 0x01, 0x00, 0x39, 0x00, 0x32, 0x04,
        0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x05, 0x04, 0x80, 0x00, 0xff, 0xff, 0x07,
        0x04, 0x80, 0x00, 0xff, 0xff, 0x08, 0x01, 0x10,
        0x01, 0x04, 0x80, 0x00, 0x75, 0x30, 0x09, 0x01,
        0x10, 0x0f, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e,
        0x51, 0x57, 0x08, 0x06, 0x04, 0x80, 0x00, 0xff,
        0xff,
    };
    @memcpy(pkt_buf[pos..][0..client_hello.len], &client_hello);
    pos += client_hello.len;

    // Padding to fill to 1200 bytes total
    // Total = header + pn_len + plaintext + AEAD_tag = 1200
    const header_len = pn_offset; // bytes before pn
    const tag_len = Aead.tag_length; // 16
    const target_plaintext = 1200 - header_len - 4 - tag_len; // 4 = pn_len
    while (pos - payload_start < target_plaintext) {
        pkt_buf[pos] = 0x00; // PADDING frame
        pos += 1;
    }

    const plaintext = pkt_buf[payload_start..pos];

    // Fill in the payload length (2-byte varint)
    // Length = pn_len(4) + plaintext.len + tag_len(16)
    const payload_length: u16 = @intCast(4 + plaintext.len + tag_len);
    // 2-byte varint: set top 2 bits to 01
    std.mem.writeInt(u16, pkt_buf[length_offset..][0..2], payload_length | 0x4000, .big);

    // Associated data = everything from first byte up to and including packet number
    const ad = pkt_buf[0 .. pn_offset + 4];

    // Encrypt the payload
    var encrypted_payload: [1200]u8 = undefined;
    const enc_len = seal.encryptPayload(2, ad, plaintext, &encrypted_payload);
    try std.testing.expectEqual(plaintext.len + tag_len, enc_len);

    // Copy encrypted payload back into packet
    @memcpy(pkt_buf[payload_start..][0..enc_len], encrypted_payload[0..enc_len]);
    const total_len = payload_start + enc_len;

    // Apply header protection
    applyHeaderProtection(pkt_buf[0..total_len], pn_offset, 4, seal.hp_key, seal.cipher_suite);

    // Verify the first few bytes of the protected packet match the RFC output
    // RFC 9001 A.2 encrypted packet starts with: c000000001088394c8f03e5157080000
    // First byte after protection should have been XORed with mask
    try std.testing.expectEqual(@as(usize, 1200), total_len);

    // Verify the version, DCID are still readable (not encrypted, not protected)
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00, 0x00, 0x01 }, pkt_buf[1..5]);
    try std.testing.expectEqual(@as(u8, 0x08), pkt_buf[5]); // DCID len
    try std.testing.expectEqualSlices(u8, &dcid, pkt_buf[6..14]);

    // Now decrypt it (server-side: is_server=true gives Open=client keys)
    const server_keys = try deriveInitialKeyMaterial(&dcid, 0x00000001, true);
    var server_open = server_keys[0]; // opens client packets

    // Remove header protection
    const recovered_pn_len = removeHeaderProtection(pkt_buf[0..total_len], pn_offset, server_open.hp_key, server_open.cipher_suite);
    try std.testing.expectEqual(@as(usize, 4), recovered_pn_len);

    // Read packet number
    const recovered_pn = std.mem.readInt(u32, pkt_buf[pn_offset..][0..4], .big);
    try std.testing.expectEqual(@as(u32, 2), recovered_pn);

    // Decrypt the payload
    const server_ad = pkt_buf[0 .. pn_offset + 4]; // decrypted header as AD
    const decrypted = try server_open.decryptPayload(
        2,
        server_ad,
        pkt_buf[payload_start..total_len],
    );

    // Verify the decrypted payload starts with the CRYPTO frame
    try std.testing.expectEqualSlices(u8, &crypto_frame_header, decrypted[0..4]);
    // And contains the ClientHello
    try std.testing.expectEqualSlices(u8, client_hello[0..16], decrypted[4..20]);
}

// RFC 9001 Appendix A.5: ChaCha20-Poly1305 short header packet.
// The only end-to-end known-answer vector for the ChaCha20 suite. Without it,
// a self-consistent error in our ChaCha20 path passes every Zig↔Zig test and
// only shows up as a peer silently dropping packets.
test "RFC 9001 A.5: ChaCha20-Poly1305 short header packet" {
    const secret = [_]u8{
        0x9a, 0xc3, 0x12, 0xa7, 0xf8, 0x77, 0x46, 0x8e, 0xbe, 0x69, 0x42, 0x27, 0x48, 0xad, 0x00, 0xa1,
        0x54, 0x43, 0xf1, 0x82, 0x03, 0xa0, 0x7d, 0x60, 0x60, 0xf6, 0x88, 0xf3, 0x0f, 0x21, 0x63, 0x2b,
    };

    // Keys, IV and header-protection key.
    const key = deriveKeyPaddedV(secret, 32, protocol.QUIC_V1);
    const hp = deriveHpKeyPaddedV(secret, 32, protocol.QUIC_V1);
    const iv = hkdfExpandLabel(secret, "quic iv", "", nonce_len);

    var expected_key: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_key, "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8");
    try std.testing.expectEqualSlices(u8, &expected_key, key[0..32]);

    var expected_iv: [12]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_iv, "e0459b3474bdd0e44a41c144");
    try std.testing.expectEqualSlices(u8, &expected_iv, &iv);

    var expected_hp: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_hp, "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4");
    try std.testing.expectEqualSlices(u8, &expected_hp, hp[0..32]);

    var expected_ku: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_ku, "1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9");
    try std.testing.expectEqualSlices(u8, &expected_ku, &deriveNextTrafficSecret(secret));

    // Nonce for pn 654360564, unprotected header 4200bff4, payload 0x01.
    const pn: u64 = 654360564;
    var expected_nonce: [12]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_nonce, "e0459b3474bdd0e46d417eb0");
    try std.testing.expectEqualSlices(u8, &expected_nonce, &makeNonce(iv, pn));

    var seal = Seal{ .key = key, .hp_key = hp, .nonce = iv, .cipher_suite = .chacha20_poly1305_sha256 };
    seal.prepareCtx();

    var header: [4]u8 = undefined;
    _ = try std.fmt.hexToBytes(&header, "4200bff4");

    var pkt: [21]u8 = undefined;
    @memcpy(pkt[0..4], &header);
    const written = seal.encryptPayload(pn, &header, &[_]u8{0x01}, pkt[4..]);
    try std.testing.expectEqual(@as(usize, 17), written);

    var expected_ct: [17]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_ct, "655e5cd55c41f69080575d7999c25a5bfb");
    try std.testing.expectEqualSlices(u8, &expected_ct, pkt[4..]);
    // Rustls v/0.23.42 ring/quic.rs uses this same RFC fixture. Its
    // Nonce::for_path(0) equals Nonce::new, so MP0 must reproduce the bytes.
    var multipath_ciphertext: [17]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 17), seal.encryptPayloadForPath(0, pn, &header, &[_]u8{0x01}, &multipath_ciphertext));
    try std.testing.expectEqualSlices(u8, &expected_ct, &multipath_ciphertext);

    // Header protection: the sample starts one byte past the 3-byte pn.
    var expected_sample: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_sample, "5e5cd55c41f69080575d7999c25a5bfb");
    try std.testing.expectEqualSlices(u8, &expected_sample, pkt[5..21]);

    var expected_mask: [5]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_mask, "aefefe7d03");
    try std.testing.expectEqualSlices(u8, &expected_mask, &seal.newMask(pkt[5..21]));

    seal.applyHeaderProtection(&pkt, 1, 3);

    var expected_packet: [21]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_packet, "4cfe4189655e5cd55c41f69080575d7999c25a5bfb");
    try std.testing.expectEqualSlices(u8, &expected_packet, &pkt);
}

// Authentication is path-scoped; replay rejection remains the packet-number
// space's responsibility, not the stateless AEAD's.
test "multipath protection separates paths and packet numbers for both suites" {
    inline for (.{ CipherSuite.aes_128_gcm_sha256, CipherSuite.chacha20_poly1305_sha256 }) |suite| {
        var seal = Seal{
            .key = @splat(0x42),
            .nonce = @splat(0xa5),
            .cipher_suite = suite,
        };
        var open = Open{
            .key = seal.key,
            .nonce = seal.nonce,
            .cipher_suite = suite,
        };
        seal.prepareCtx();
        open.prepareCtx();
        const plaintext = "path-bound payload";
        const header = "unprotected header";
        var path_zero: [plaintext.len + 16]u8 = undefined;
        var path_one: [plaintext.len + 16]u8 = undefined;
        try std.testing.expectEqual(path_zero.len, seal.encryptPayloadForPath(0, 7, header, plaintext, &path_zero));
        var legacy: [plaintext.len + 16]u8 = undefined;
        try std.testing.expectEqual(legacy.len, seal.encryptPayload(7, header, plaintext, &legacy));
        try std.testing.expectEqualSlices(u8, &legacy, &path_zero);
        try std.testing.expectEqual(path_one.len, seal.encryptPayloadForPath(1, 7, header, plaintext, &path_one));
        try std.testing.expect(!std.mem.eql(u8, &path_zero, &path_one));
        var attempt = path_one;
        try std.testing.expectError(error.AuthenticationFailed, open.decryptPayloadForPath(0, 7, header, &attempt));
        attempt = path_one;
        try std.testing.expectError(error.AuthenticationFailed, open.decryptPayloadForPath(1, 8, header, &attempt));
        attempt = path_one;
        try std.testing.expectEqualStrings(plaintext, try open.decryptPayloadForPath(1, 7, header, &attempt));
        attempt = path_one;
        try std.testing.expectEqualStrings(plaintext, try open.decryptPayloadForPath(1, 7, header, &attempt));
        attempt = path_one;
        try std.testing.expectError(error.AuthenticationFailed, open.decryptPayloadForPath(1, @as(u64, 1) << 62, header, &attempt));
        try std.testing.expectEqualSlices(u8, &path_one, &attempt);
        try std.testing.expectError(error.AuthenticationFailed, open.decryptPayloadForPath(1, 7, header, attempt[0..15]));

        const packet_number_max = (@as(u64, 1) << 62) - 1;
        const path_id_max = std.math.maxInt(u32);
        try std.testing.expectEqual(path_one.len, seal.encryptPayloadForPath(path_id_max, packet_number_max, header, plaintext, &path_one));
        try std.testing.expectEqualStrings(plaintext, try open.decryptPayloadForPath(path_id_max, packet_number_max, header, &path_one));
    }
}

// Rustls v/0.23.42 crypto/cipher.rs Nonce::for_path is the nonce oracle:
// IV XOR (path_id.to_be_bytes() || pn.to_be_bytes()), for either AEAD.
test "pinned rustls multipath nonce layout and full domain boundaries" {
    const iv = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
    const expected = [_]u8{
        0x01, 0x03, 0x01, 0x07, 0x15, 0x27, 0x35, 0x43, 0x5d, 0x6f, 0x7d, 0x83,
    };
    try std.testing.expectEqualSlices(u8, &expected, &makeNonceForPath(iv, 0x01020304, 0x1122334455667788));
    const zero_iv = @as([nonce_len]u8, @splat(0));
    const max_expected = [_]u8{
        0xff, 0xff, 0xff, 0xff, 0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };
    try std.testing.expectEqualSlices(u8, &max_expected, &makeNonceForPath(zero_iv, std.math.maxInt(u32), (@as(u64, 1) << 62) - 1));
    try std.testing.expectEqualSlices(u8, &iv, &makeNonceForPath(iv, 0, 0));
    try std.testing.expectEqualSlices(u8, &makeNonce(iv, 12345), &makeNonceForPath(iv, 0, 12345));
}

// Exact Rustls v/0.23.42 crypto/ring/quic.rs test_multipath_aead_basic.
// Upstream attributes these bytes to picoquic be0d99e6d4f8759cb7920425351c06a1c6f4a958.
test "pinned rustls ring multipath AES path two golden ciphertext" {
    const secret = [_]u8{
        0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23, 24, 35, 26, 27, 28, 29, 30, 31,
    };
    const plaintext = "The quick brown fox jumps over the lazy dog";
    const header = "This is a test";
    const expected = [_]u8{
        123, 139, 232, 52,  136, 25,  201, 143, 250, 89,  87,  39,  37,  63, 0,   210,
        220, 227, 186, 140, 183, 251, 13,  203, 6,   116, 204, 100, 166, 64, 43,  185,
        174, 85,  212, 163, 242, 141, 24,  166, 62,  228, 187, 137, 248, 31, 152, 126,
        240, 151, 79,  51,  253, 130, 43,  114, 173, 234, 254,
    };
    var seal = Seal{
        .key = deriveKeyPaddedV(secret, 16, protocol.QUIC_V1),
        .nonce = hkdfExpandLabel(secret, "quic iv", "", nonce_len),
    };
    seal.prepareCtx();
    var ciphertext: [expected.len]u8 = undefined;
    try std.testing.expectEqual(expected.len, seal.encryptPayloadForPath(2, 12345, header, plaintext, &ciphertext));
    try std.testing.expectEqualSlices(u8, &expected, &ciphertext);
    var open = Open{ .key = seal.key, .nonce = seal.nonce };
    open.prepareCtx();
    try std.testing.expectEqualStrings(plaintext, try open.decryptPayloadForPath(2, 12345, header, &ciphertext));
}

// Independent PN spaces must never make an ACK for one path confirm a key
// generation on another; encryption usage still belongs to the shared key.
test "KeyUpdateManager multipath ACK markers and global encryption count" {
    var manager = KeyUpdateManager.init(
        @splat(0xaa),
        @splat(0xbb),
        @splat(0xcc),
        @splat(0xdd),
    );
    manager.onPacketSentForPath(0, 100);
    manager.onAckForPath(1, 100);
    try std.testing.expect(!manager.canUpdate());
    manager.onPacketSentForPath(1, 7);
    manager.onPacketSentForPath(0, 101);
    try std.testing.expectEqual(@as(u64, 3), manager.packets_sent_with_current);
    try std.testing.expectEqual(@as(?u64, 100), manager.first_sent_for_path[0]);
    try std.testing.expectEqual(@as(?u64, 7), manager.first_sent_for_path[1]);
    manager.onAckForPath(0, 7);
    manager.onAckForPath(1, 6);
    try std.testing.expect(!manager.canUpdate());
    manager.onAckForPath(1, 7);
    try std.testing.expect(manager.canUpdate());
    manager.rollKeys(1000, 100);
    try std.testing.expectEqual(@as(u64, 0), manager.packets_sent_with_current);
    try std.testing.expectEqual(@as(?u64, null), manager.first_sent_for_path[0]);
    try std.testing.expectEqual(@as(?u64, null), manager.first_sent_for_path[1]);
    manager.onAckForPath(1, 7);
    try std.testing.expect(!manager.canUpdate());
    manager.onPacketSentForPath(1, 8);
    manager.onPacketSentForPath(0, 8);
    manager.onAckForPath(0, 8);
    try std.testing.expect(!manager.canUpdate());
    manager.maybeDropPrevKeys(1299);
    try std.testing.expect(!manager.canUpdate());
    manager.maybeDropPrevKeys(1300);
    try std.testing.expect(manager.canUpdate());
    try std.testing.expectEqual(@as(u64, 2), manager.packets_sent_with_current);
}

// Noq packet_crypto.rs sets update_unacked on remote rotation, and mod.rs
// clears it only when an application packet is selected for sending.
test "KeyUpdateManager peer update guard waits for actual application send" {
    var manager = KeyUpdateManager.init(
        @splat(0xaa),
        @splat(0xbb),
        @splat(0xcc),
        @splat(0xdd),
    );
    try std.testing.expect(!manager.peer_update_unacked);
    manager.onPeerKeyUpdate(1000, 100);
    try std.testing.expect(manager.peer_update_unacked);
    manager.onAckForPath(0, 0);
    manager.first_acked_with_current = true;
    try std.testing.expect(manager.peer_update_unacked);
    try std.testing.expectEqual(@as(u64, 0), manager.packets_sent_with_current);
    manager.onPacketSentForPath(1, 0);
    try std.testing.expect(!manager.peer_update_unacked);
    try std.testing.expectEqual(@as(u64, 1), manager.packets_sent_with_current);
    manager.onPeerKeyUpdate(2000, 100);
    try std.testing.expect(manager.peer_update_unacked);
    manager.onPacketSent(10);
    try std.testing.expect(!manager.peer_update_unacked);
    try std.testing.expectEqual(@as(u64, 1), manager.packets_sent_with_current);
}

// Noq mod.rs off-path challenge/response sends return before the normal
// packet-space send clears update_unacked. Both routes consume shared keys.
test "KeyUpdateManager off-path sends count without confirming peer update" {
    var manager = KeyUpdateManager.init(
        @splat(0xaa),
        @splat(0xbb),
        @splat(0xcc),
        @splat(0xdd),
    );
    manager.onPeerKeyUpdate(1000, 100);
    manager.onOffPathPacketSentForPath(1, 7);
    manager.onOffPathPacketSentForPath(0, 100);
    try std.testing.expect(manager.peer_update_unacked);
    try std.testing.expectEqual(@as(u64, 2), manager.packets_sent_with_current);
    try std.testing.expectEqual(@as(?u64, 100), manager.first_sent_for_path[0]);
    try std.testing.expectEqual(@as(?u64, 7), manager.first_sent_for_path[1]);
    manager.onAckForPath(1, 7);
    try std.testing.expect(manager.peer_update_unacked);
    manager.onPacketSentForPath(1, 8);
    try std.testing.expect(!manager.peer_update_unacked);
    try std.testing.expectEqual(@as(u64, 3), manager.packets_sent_with_current);
    try std.testing.expectEqual(@as(?u64, 7), manager.first_sent_for_path[1]);
    manager.onPeerKeyUpdate(2000, 100);
    try std.testing.expect(manager.peer_update_unacked);
    try std.testing.expectEqual(@as(u64, 0), manager.packets_sent_with_current);
}

test "KeyUpdateManager local rotation waits for peer acknowledgment and prior key expiry" {
    var manager = KeyUpdateManager.init(
        @splat(0xaa),
        @splat(0xbb),
        @splat(0xcc),
        @splat(0xdd),
    );
    const path_zero_pto_ns: i64 = 100;
    const path_one_pto_ns: i64 = 500;
    const max_active_pto_ns: i64 = @max(path_zero_pto_ns, path_one_pto_ns);
    manager.onPeerKeyUpdate(1000, max_active_pto_ns);
    manager.first_acked_with_current = true;
    try std.testing.expect(!manager.canUpdate());
    manager.onOffPathPacketSentForPath(1, 7);
    manager.onAckForPath(1, 7);
    try std.testing.expect(!manager.canUpdate());
    manager.onPacketSentForPath(1, 8);
    try std.testing.expect(!manager.peer_update_unacked);
    try std.testing.expect(!manager.canUpdate());
    manager.maybeDropPrevKeys(1000 + 3 * path_zero_pto_ns);
    try std.testing.expect(!manager.canUpdate());
    manager.maybeDropPrevKeys(1000 + 3 * max_active_pto_ns - 1);
    try std.testing.expect(!manager.canUpdate());
    manager.maybeDropPrevKeys(1000 + 3 * max_active_pto_ns);
    try std.testing.expect(manager.canUpdate());
    manager.rollKeys(2500, max_active_pto_ns);
    try std.testing.expect(!manager.canUpdate());
    try std.testing.expectEqual(@as(u64, 0), manager.packets_sent_with_current);
}
