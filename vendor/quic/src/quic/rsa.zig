//! RSA private keys and RSASSA-PSS signing (RFC 8017), for TLS 1.3
//! CertificateVerify with the rsa_pss_rsae_* schemes (RFC 8446 §4.2.3).
//!
//! The two CRT exponentiations, which are almost the whole cost of a signature,
//! run on `mont.zig`. The cheap remainder — reducing the message into each
//! prime's range, recombining the halves, and the self-check — stays on
//! `std.crypto.ff`. Both are constant time in the exponent.
//!
//! Each signature is checked against the public exponent before it is returned,
//! so a fault in one CRT half cannot hand out a signature that factors the
//! modulus (Boneh-DeMillo-Lipton).

const std = @import("std");
const ff = std.crypto.ff;
const mont = @import("mont.zig");
const mem = std.mem;

/// Smallest modulus this module will sign with, in bits. Below it
/// `parsePkcs1` answers `error.UnsupportedKey` rather than degrading.
pub const min_bits = 2048;
/// Largest modulus this module will sign with, in bits, and the width every
/// fixed buffer here is sized for: a signature, an encoded message, and each
/// CRT half are all at most this many bits. `mont.zig`'s half-width ceiling is
/// checked against this at comptime.
pub const max_bits = 4096;
/// Longest signature: one modulus length.
/// `signPss` takes `out` at exactly this size for every key, so one buffer
/// serves any key this module accepts; only `out[0..signatureLength]` is
/// written.
pub const max_signature_len = max_bits / 8;

const Modulus = ff.Modulus(max_bits);
const PrimeModulus = ff.Modulus(max_bits / 2);
const max_prime_len = max_bits / 16;

comptime {
    // mont.zig sizes its limb arrays for one CRT half.
    std.debug.assert(mont.max_bits >= max_bits / 2);
}

// 1.2.840.113549.1.1.1
const rsa_encryption_oid = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };

/// Every failure a key can have. The three are ordered by how much was
/// established: `DecodeError` is the encoding, `UnsupportedKey` is a
/// well-formed key outside what this module signs with, and `InvalidKey` is a
/// key whose numbers do not belong together.
pub const Error = error{
    /// Not a well-formed key encoding.
    DecodeError,
    /// Well formed, but not a two-prime RSA key of 2048–4096 bits.
    UnsupportedKey,
    /// The key's numbers do not fit together.
    InvalidKey,
};

/// A two-prime RSA private key. The fields are big-endian magnitudes without
/// leading zeros, borrowed from the DER the key was parsed from.
///
/// All seven slices borrow one buffer — the DER `parsePkcs1` was handed — and
/// nothing is copied. The key is valid only while that buffer is alive and
/// unmodified, and a caller who needs the key to outlive the DER must copy it.
/// The value itself owns nothing and has no teardown; copying a `PrivateKey`
/// copies the borrows, not the bytes, so every copy depends on the same DER.
pub const PrivateKey = struct {
    /// The modulus n, the public half. Its byte length is
    /// `signatureLength` and its bit length is `modulusBits`.
    n: []const u8,
    /// The public exponent e. Capped at four bytes because std's verifier, and
    /// so the self-check, takes exponents below 2^32.
    e: []const u8,
    /// The first prime factor p, at most half the modulus.
    p: []const u8,
    /// The second prime factor q, at most half the modulus.
    q: []const u8,
    /// d mod (p - 1)
    dp: []const u8,
    /// d mod (q - 1)
    dq: []const u8,
    /// q^-1 mod p
    qinv: []const u8,

    /// Parses a PKCS#1 RSAPrivateKey (RFC 8017 A.1.2). Checks the structure
    /// and sizes only; `check` proves the numbers belong together.
    ///
    /// The returned key's seven slices point into `der`: nothing is copied and
    /// nothing is allocated, so `der` must stay alive and unmodified for as
    /// long as the key or any copy of it is used. On any error no key is
    /// produced and `der` is untouched.
    pub fn parsePkcs1(der: []const u8) Error!PrivateKey {
        var outer: Reader = .{ .buf = der };
        var r: Reader = .{ .buf = try outer.element(tag_sequence) };
        if (!outer.done()) return error.DecodeError;

        const version = try r.unsigned();
        // Version 1 carries otherPrimeInfos: multi-prime keys.
        if (version.len != 0) return error.UnsupportedKey;
        var key: PrivateKey = undefined;
        key.n = try r.unsigned();
        key.e = try r.unsigned();
        _ = try r.unsigned(); // d: the CRT values below replace it
        key.p = try r.unsigned();
        key.q = try r.unsigned();
        key.dp = try r.unsigned();
        key.dq = try r.unsigned();
        key.qinv = try r.unsigned();
        if (!r.done()) return error.DecodeError;

        const bits = key.modulusBits();
        if (bits < min_bits or bits > max_bits) return error.UnsupportedKey;
        if (key.n[key.n.len - 1] & 1 == 0) return error.InvalidKey;
        // std's verifier, and so our self-check, takes exponents below 2^32.
        if (key.e.len > 4) return error.UnsupportedKey;
        if (key.e[key.e.len - 1] & 1 == 0 or (key.e.len == 1 and key.e[0] < 3)) return error.InvalidKey;
        for ([_][]const u8{ key.p, key.q, key.dp, key.dq, key.qinv }) |v| {
            if (v.len == 0 or v.len > max_prime_len) return error.InvalidKey;
        }
        if (key.p[key.p.len - 1] & 1 == 0 or key.q[key.q.len - 1] & 1 == 0) return error.InvalidKey;
        return key;
    }

    /// Returns the PKCS#1 RSAPrivateKey inside a PKCS#8 PrivateKeyInfo
    /// (RFC 5208) whose algorithm is rsaEncryption.
    ///
    /// The result is a view into `der`, not a copy: it borrows the same memory
    /// for as long as it is used, and the caller must not write to `der` while
    /// holding it. Passing it to `parsePkcs1` produces a `PrivateKey` that
    /// keeps borrowing `der` transitively, so the two obligations are one.
    /// A non-rsaEncryption algorithm is `error.UnsupportedKey`; a malformed
    /// one is `error.DecodeError`, and neither writes anything.
    pub fn pkcs1FromPkcs8(der: []const u8) Error![]const u8 {
        var outer: Reader = .{ .buf = der };
        var r: Reader = .{ .buf = try outer.element(tag_sequence) };
        if (!outer.done()) return error.DecodeError;

        const version = try r.unsigned();
        if (version.len > 1 or (version.len == 1 and version[0] > 1)) return error.DecodeError;
        var alg: Reader = .{ .buf = try r.element(tag_sequence) };
        if (!mem.eql(u8, try alg.element(tag_oid), &rsa_encryption_oid)) return error.UnsupportedKey;
        if (!alg.done()) {
            if ((try alg.element(tag_null)).len != 0 or !alg.done()) return error.DecodeError;
        }
        // Attributes and a public key may follow; neither is needed.
        return r.element(tag_octet_string);
    }

    /// The modulus size in bits, counted from the leading byte, so it is at
    /// most `max_bits` for a key `parsePkcs1` accepted and 0 for a key whose
    /// `n` is empty. Reads only; nothing is validated here.
    pub fn modulusBits(self: PrivateKey) usize {
        if (self.n.len == 0) return 0;
        return self.n.len * 8 - @clz(self.n[0]);
    }

    /// Signature length: the modulus length in bytes.
    ///
    /// Fixed per key, not per call: it is `n.len`, at most
    /// `max_signature_len` for an accepted key. `signPss` returns exactly
    /// this many bytes and a TLS 1.3 CertificateVerify carries them verbatim.
    pub fn signatureLength(self: PrivateKey) usize {
        return self.n.len;
    }

    /// Signs one message, proving the key's numbers fit together. A private
    /// key that fails here would fail every handshake.
    ///
    /// Signs a fixed string with a zero salt and throws the signature away, so
    /// it costs a full RSA operation and allocates one stack buffer. Every
    /// failure of `signPss` arrives here as `error.InvalidKey`: this proves
    /// the key, not that this particular signing succeeded, and nothing is
    /// retained.
    pub fn check(self: PrivateKey) Error!void {
        var sig: [max_signature_len]u8 = undefined;
        const salt: [32]u8 = @splat(0);
        _ = self.signPssWithSalt(std.crypto.hash.sha2.Sha256, "key check", &salt, &sig) catch return error.InvalidKey;
    }

    /// RSASSA-PSS with MGF1 over `Hash` and a salt as long as the digest,
    /// the parameters TLS 1.3 requires. Returns the signature, `out[0..n.len]`.
    ///
    /// `random` is drawn once, for the salt, and nowhere else. The salt is
    /// what makes PSS randomised rather than deterministic (RFC 8017 §9.1.1):
    /// two signatures over one message must not be the same bytes, or a peer
    /// that compares them learns the transcript repeated, and a salt that
    /// repeats is the fixed padding a Bleichenbacher-style forgery works
    /// from. Production hands this a CSPRNG; a test hands it a seeded one, so
    /// the signature is the same bytes on every run.
    ///
    /// The result borrows `out`, not `msg` and not the key: it is
    /// `out[0..signatureLength]`, valid until the caller rewrites `out`.
    /// `error.UnsupportedKey` is a modulus too long for PSS to encode into and
    /// `error.InvalidKey` is the self-check rejecting the result; on either,
    /// `out[0..signatureLength]` is left zeroed or untouched, never a partial
    /// signature, so the caller must not read it after an error. `out` beyond
    /// that prefix is never written at all.
    ///
    /// Constant time in the exponent and the message, so the call is safe on a
    /// thread the key is otherwise shared with. It allocates nothing and
    /// retains nothing; `msg` and `random` are used only for this call.
    pub fn signPss(
        self: PrivateKey,
        comptime Hash: type,
        msg: []const u8,
        out: *[max_signature_len]u8,
        random: std.Random,
    ) Error![]const u8 {
        var salt: [Hash.digest_length]u8 = undefined;
        random.bytes(&salt);
        return self.signPssWithSalt(Hash, msg, &salt, out);
    }

    fn signPssWithSalt(
        self: PrivateKey,
        comptime Hash: type,
        msg: []const u8,
        salt: *const [Hash.digest_length]u8,
        out: *[max_signature_len]u8,
    ) Error![]const u8 {
        const k = self.n.len;
        if (k > max_signature_len) return error.UnsupportedKey;
        var em: [max_signature_len]u8 = undefined;
        try encodePss(Hash, msg, salt, self.modulusBits() - 1, em[0..k]);
        try self.privateOp(em[0..k], out[0..k]);
        return out[0..k];
    }

    /// out = in^d mod n, via the CRT, verified with the public exponent.
    fn privateOp(self: PrivateKey, in: []const u8, out: []u8) Error!void {
        const k = self.n.len;
        const n = Modulus.fromBytes(self.n, .big) catch return error.InvalidKey;
        const p = PrimeModulus.fromBytes(self.p, .big) catch return error.InvalidKey;
        const q = PrimeModulus.fromBytes(self.q, .big) catch return error.InvalidKey;
        const m_wide = ff.Uint(max_bits).fromBytes(in, .big) catch return error.InvalidKey;

        // Pad the exponents to the prime's length so their size leaks nothing.
        var exp_buf: [max_prime_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &exp_buf);
        var base_buf: [PrimeModulus.Fe.encoded_bytes]u8 = undefined;
        defer std.crypto.secureZero(u8, &base_buf);
        var half_buf: [max_prime_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &half_buf);

        // ff reduces the message into each prime's range; mont.zig raises it.
        const mp = mont.Modulus.fromBytes(self.p) catch return error.InvalidKey;
        p.reduce(m_wide).toBytes(&base_buf, .big) catch return error.InvalidKey;
        mp.pow(&base_buf, try padded(&exp_buf, self.dp, self.p.len), half_buf[0..self.p.len]) catch
            return error.InvalidKey;
        const m1 = PrimeModulus.Fe.fromBytes(p, half_buf[0..self.p.len], .big) catch return error.InvalidKey;

        const mq = mont.Modulus.fromBytes(self.q) catch return error.InvalidKey;
        q.reduce(m_wide).toBytes(&base_buf, .big) catch return error.InvalidKey;
        mq.pow(&base_buf, try padded(&exp_buf, self.dq, self.q.len), half_buf[0..self.q.len]) catch
            return error.InvalidKey;
        const m2 = PrimeModulus.Fe.fromBytes(q, half_buf[0..self.q.len], .big) catch return error.InvalidKey;

        // h = qinv * (m1 - m2) mod p; s = m2 + h * q, which is below n.
        var bytes: [PrimeModulus.Fe.encoded_bytes]u8 = undefined;
        defer std.crypto.secureZero(u8, &bytes);
        m2.toBytes(&bytes, .big) catch return error.InvalidKey;
        const m2_mod_p = p.reduce(ff.Uint(max_bits / 2).fromBytes(&bytes, .big) catch return error.InvalidKey);
        const m2_mod_n = Modulus.Fe.fromBytes(n, &bytes, .big) catch return error.InvalidKey;
        const qinv = PrimeModulus.Fe.fromBytes(p, self.qinv, .big) catch return error.InvalidKey;
        const h = p.mul(qinv, p.sub(m1, m2_mod_p));
        h.toBytes(&bytes, .big) catch return error.InvalidKey;
        const h_mod_n = Modulus.Fe.fromBytes(n, &bytes, .big) catch return error.InvalidKey;
        const q_mod_n = Modulus.Fe.fromBytes(n, self.q, .big) catch return error.InvalidKey;
        const s = n.add(n.mul(h_mod_n, q_mod_n), m2_mod_n);

        s.toBytes(out[0..k], .big) catch return error.InvalidKey;
        var recovered: [max_signature_len]u8 = undefined;
        const back = n.powWithEncodedPublicExponent(s, self.e, .big) catch return error.InvalidKey;
        back.toBytes(recovered[0..k], .big) catch return error.InvalidKey;
        if (!mem.eql(u8, recovered[0..k], in)) {
            @memset(out[0..k], 0);
            return error.InvalidKey;
        }
    }
};

fn padded(buf: *[max_prime_len]u8, v: []const u8, len: usize) Error![]const u8 {
    if (v.len > len) return error.InvalidKey;
    @memset(buf[0 .. len - v.len], 0);
    @memcpy(buf[len - v.len ..][0..v.len], v);
    return buf[0..len];
}

/// EMSA-PSS-ENCODE (RFC 8017 §9.1.1), written right-aligned into `out`,
/// which is the modulus length: a leading zero byte when em_bits is a
/// multiple of 8.
fn encodePss(comptime Hash: type, msg: []const u8, salt: *const [Hash.digest_length]u8, em_bits: usize, out: []u8) Error!void {
    const h_len = Hash.digest_length;
    const em_len = (em_bits + 7) / 8;
    if (em_len < 2 * h_len + 2 or em_len > out.len) return error.UnsupportedKey;
    @memset(out[0 .. out.len - em_len], 0);
    const em = out[out.len - em_len ..];

    var m_hash: [h_len]u8 = undefined;
    Hash.hash(msg, &m_hash, .{});
    var h: [h_len]u8 = undefined;
    var hasher: Hash = .init(.{});
    hasher.update(&@as([8]u8, @splat(0)));
    hasher.update(&m_hash);
    hasher.update(salt);
    hasher.final(&h);

    // DB = PS || 0x01 || salt, masked with MGF1(H).
    const db = em[0 .. em_len - h_len - 1];
    @memset(db[0 .. db.len - h_len - 1], 0);
    db[db.len - h_len - 1] = 0x01;
    @memcpy(db[db.len - h_len ..], salt);
    var counter: u32 = 0;
    var i: usize = 0;
    while (i < db.len) : (counter += 1) {
        var block: [h_len]u8 = undefined;
        var mgf: Hash = .init(.{});
        mgf.update(&h);
        var c: [4]u8 = undefined;
        mem.writeInt(u32, &c, counter, .big);
        mgf.update(&c);
        mgf.final(&block);
        const n = @min(h_len, db.len - i);
        for (db[i..][0..n], block[0..n]) |*d, b| d.* ^= b;
        i += n;
    }
    db[0] &= @as(u8, 0xff) >> @intCast(8 * em_len - em_bits);
    @memcpy(em[em_len - h_len - 1 ..][0..h_len], &h);
    em[em_len - 1] = 0xbc;
}

const tag_sequence = 0x30;
const tag_integer = 0x02;
const tag_octet_string = 0x04;
const tag_null = 0x05;
const tag_oid = 0x06;

/// Minimal DER reader: definite lengths only, every read bounds-checked.
const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn done(r: *const Reader) bool {
        return r.pos == r.buf.len;
    }

    fn element(r: *Reader, tag: u8) Error![]const u8 {
        if (r.buf.len - r.pos < 2 or r.buf[r.pos] != tag) return error.DecodeError;
        var len: usize = r.buf[r.pos + 1];
        r.pos += 2;
        if (len & 0x80 != 0) {
            const n = len & 0x7f;
            // Keys are far below 16 MiB.
            if (n == 0 or n > 3 or r.buf.len - r.pos < n) return error.DecodeError;
            len = 0;
            for (r.buf[r.pos..][0..n]) |b| len = (len << 8) | b;
            r.pos += n;
        }
        if (r.buf.len - r.pos < len) return error.DecodeError;
        defer r.pos += len;
        return r.buf[r.pos..][0..len];
    }

    /// A non-negative INTEGER's magnitude, leading zeros stripped (so zero
    /// is empty).
    fn unsigned(r: *Reader) Error![]const u8 {
        const v = try r.element(tag_integer);
        if (v.len == 0 or v[0] & 0x80 != 0) return error.DecodeError;
        return mem.trimStart(u8, v, &.{0});
    }
};

// ─── Tests ───────────────────────────────────────────────────────────

const testing = std.testing;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;
const Sha512 = std.crypto.hash.sha2.Sha512;
const Certificate = std.crypto.Certificate;

/// A fixed RSA-2048 key, PKCS#1 DER (RFC 8017 A.1.2), hex.
///
/// A TEST KEY. It has no security property: the private half is published
/// here and upstream, and nothing guards it. It signs nothing but the
/// fixture message below. Read it as test data, never as a credential.
///
/// Upstream material, not regenerated: these bytes are the
/// `test_rsa_key_pkcs1_pem` of endel/quic-zig `src/tls/test_certs.zig` at
/// commit 14b9dc3e5e8429d07e7ed18619c7b4f4baaa3719, base64-decoded to DER.
/// The fixture file went with the X.509 walk the TLS patch removed, so the
/// key moved here verbatim rather than being made again.
///
/// The signer is only worth testing on a real key: `check` proves the
/// numbers fit together, and a signature over an invented modulus would
/// prove nothing at all. It is in the file rather than generated per run
/// because a key a run builds is a key a failing assertion cannot be
/// reproduced against. Replacing it means regenerating the signature below,
/// which is pinned against it.
const test_key_hex =
    "308204a302010002820101008b96e513a5db9ccec516ab110e1c0b9f730af10d" ++
    "ec5ebd1c3769f9821b125542b6d6d37f49c9eed18e55f8131dd25d096fe88aed" ++
    "a6c7796f376803acc214ca2d5767cb7f7f2d90ffc20e8fbbb90ccf09e56c8bad" ++
    "1af8ca032439e1b486f0f9674bd6027706ed4048af4d0589f69ad736157d8624" ++
    "f3a95b083319d8a7766f3aed439f6bc8353133f00b5211a6372a77275f6cef91" ++
    "cd13096280ac42fc34d4c8f0768094741eec24667f9847de38d49cff2cf37a2d" ++
    "5cd6b5c2a142a3d39aed10735f895e37288649a15cf6d5f65093c0f79ffdff50" ++
    "e94c3c79a9e5ede51674b07ec29a20ab9813aa416b4df563593737f50700a27b" ++
    "163de9f7ee28e1128659d97f02030100010282010018bedd494863d03e8f8ddf" ++
    "319cd0b7f6c24c3443859d9de4bca61ac747c94e380f75b1f4a4be198a28b370" ++
    "d0e2be8223c424f34c01fee6b6229a5bdc6a63891bd49cdfe4704541a9355ba3" ++
    "7b61e8b56349ba9e6047a1c71e1b73ef613372d0a3d13bd52008a85277102c95" ++
    "48c9e0d53a0f413b609d996e3bdbe33f1720d5c31a3d8eaf432976d051dee1f9" ++
    "fb819411b751c0be36aee9b1425f4a3a730261fd194ff9f1f3e01ed8a8ab58ec" ++
    "de8da2107379c15c7b544d359db906d693d5fcf97411803906dcb7d3ec799a9e" ++
    "45ec240fd3224aca4a2ad762585cea9254536c610e2e02120b1a6b4748deb491" ++
    "27e202b2c24baa681be77f8483ebc8b298ff31d16102818100c2e0c26685060d" ++
    "e0cc1f8b476817c8ea7d54a860066fb7b0edcdf904f0d142dcae7dc76fd4e1b3" ++
    "b11770fa8bedece19b2c42e1bef16ad26916b08a3455c67a26661919bb09d37a" ++
    "560e520c39c04698437f46e9083d827247e10e7e6f98407074556abcd73f648e" ++
    "a274b21b137ac14e02aedb1bd439f0684a2d025de6e6ff228702818100b75ee1" ++
    "65b9ff20c191e00d3c0c34f02de946dc4012deb89838bb9ca83b0bb02290a1c2" ++
    "e27c7c08cda51c52ee05f781cd47c16cbe41a1b2e594849f9f6f164b2ee5dd81" ++
    "19c3269c41450e78322d19e828d245e75425f57b0d1743c6636e0f220fa5b888" ++
    "8377f709325504a739b86a70563d99eb2ae6cdd6376bd17322c4e23749028180" ++
    "39d9bcfbf01b56fd57bb397e6e21396c9ade09c9cfbf54597a8ebd90c0e86e1f" ++
    "d2d0d5e695dc969a48aa2a4665cfff3d304b7e764f767595eabd679997a8fed3" ++
    "ed5520354cfa7183a066ace86bf2c8faa88ae55ca3ddd88d0bfb607f424446dd" ++
    "d209889ba15ef994b26db8e9f473f3f389f2d37511ea131b89f6fce731c5a57b" ++
    "028181009b69ce0d42d3e9f64565a8b1e102a921b059ff684ad5fb8c00617a47" ++
    "d72b73d007d721ee856536acdca8a1dcdcafc692aea3503ffc2e490a6d92ee1a" ++
    "d9b3026bb024c93b857bdee92ed731a60d35acdf943feced13f2f7a4c3b80c97" ++
    "cefb027a5291911a23fdfb0c6ea42ffb2ac3038d044ec4d32aa5004f1e91794c" ++
    "d9a385090281804db9a3cdf1f0f2df0023c818935a3227772de93bd382d56cc7" ++
    "223a57562df8b7c76d84063ff190bbddf885598a0ff93d613977a3f3fc62159e" ++
    "b4cdae64a8f69ea66864794cb4178e151de0f7bd69287a4b8e2bc42e8527d95e" ++
    "0685386ea0ec31e6f8108dfc0ecfd03f6333aee1d7e23bbfd1c4e9d3ce018f0f" ++
    "aab6843ba42948";

/// The signature OpenSSL accepted for `test_key_hex`'s public half over
/// "quic-zig rsa-pss fixture" with salt 0x00..0x1f. Pinned bytes rather than
/// a computed one: a signer that had drifted would still verify against a
/// signature of its own making, and only bytes from outside catch that.
///
/// Also upstream: the `test_rsa_pss_fixture_hex` of the same commit, which
/// upstream's own comment ties to this very test. Both halves of the pair
/// moved together, so the vector is the one OpenSSL signed rather than one
/// this file signs and then agrees with.
const openssl_pss_signature_hex =
    "0ab1f504ca9b6fa0786a9695a3166e0d1fc327e6faa2b9e1783dc38ef1c4ddf2" ++
    "ff7c023f44a2652bf79487d497a9928d96039643c99e05036e64cafce95b7a0e" ++
    "8f98ab5c82ea9cced5a3a60534054444d9463d0019a1dba0bf37571e9cc2f021" ++
    "a0b6d1ebef898b31b98d998393989a7bd35fcb6515a8f3a7b6cf79e3836df06d" ++
    "500ca2f5651993cb557fbe6da15251dbc8dfd51c3634c8cdcb18ad6b32edfa1d" ++
    "7954e2824def11094b3da8139daa08daa01c8062c9205d766b4e284dba30231e" ++
    "a1d18d9f4fadb58e7d0a2e3073eba52ad548e49a1875f94f24279ac4e7bd213b" ++
    "3f882c2c0bee88be1e08b489adc6d1f5df504bcd8c06890eecfca53b6c3398fb";

/// The smallest DER writer these tests need. The length is the part that
/// earns its keep: an RSA key is 1191 bytes, well past the short form, and
/// a length byte that lies is somebody else's decode error.
const Der = struct {
    buf: []u8,
    pos: usize = 0,

    /// tag, length, value.
    fn tlv(d: *Der, tag: u8, value: []const u8) void {
        d.header(tag, value.len);
        @memcpy(d.buf[d.pos..][0..value.len], value);
        d.pos += value.len;
    }

    /// tag and length with no value: for the outer element of a structure
    /// whose contents are already in place.
    fn header(d: *Der, tag: u8, len: usize) void {
        d.buf[d.pos] = tag;
        d.pos += 1;
        if (len < 0x80) {
            d.buf[d.pos] = @intCast(len);
            d.pos += 1;
        } else {
            std.debug.assert(len < 0x10000);
            d.buf[d.pos] = 0x82;
            mem.writeInt(u16, d.buf[d.pos + 1 ..][0..2], @intCast(len), .big);
            d.pos += 3;
        }
    }

    /// The width of the header `tlv` will write for `len` bytes of value.
    fn headerSize(len: usize) usize {
        return if (len < 0x80) 2 else 4;
    }
};

/// A PKCS#8 PrivateKeyInfo (RFC 5208) around `body`: SEQUENCE { INTEGER 0,
/// AlgorithmIdentifier { OID }, OCTET STRING { body } }.
///
/// Built rather than pasted beside the key, so that the two encodings the
/// test below compares are the same bytes by construction: a fixture pair
/// that disagreed would be testing the paste.
fn privateKeyInfo(oid: []const u8, body: []const u8, out: []u8) []const u8 {
    var alg: [16]u8 = undefined;
    var a: Der = .{ .buf = &alg };
    a.tlv(tag_oid, oid);
    var d: Der = .{ .buf = out };
    d.tlv(tag_integer, &.{0});
    d.tlv(tag_sequence, alg[0..a.pos]);
    d.tlv(tag_octet_string, body);
    // The SEQUENCE header belongs in front of bytes already laid down, and
    // it is wider in the long form than in the short one, so the content
    // moves rather than the header guessing.
    const content = d.pos;
    const head = Der.headerSize(content);
    @memmove(out[head..][0..content], out[0..content]);
    var h: Der = .{ .buf = out };
    h.header(tag_sequence, content);
    std.debug.assert(h.pos == head);
    return out[0 .. content + head];
}

/// An Ed25519 seed as PKCS#8 (RFC 8410): the same PrivateKeyInfo with a
/// different OID and a bare key inside the OCTET STRING.
fn ed25519Pkcs8(seed: []const u8, out: []u8) []const u8 {
    var key: [40]u8 = undefined;
    var k: Der = .{ .buf = &key };
    k.tlv(tag_octet_string, seed);
    return privateKeyInfo(&[_]u8{ 0x2b, 0x65, 0x70 }, key[0..k.pos], out);
}

/// The key in the encoding `parsePkcs1` takes. `buf` only has to be big
/// enough; `hexToBytes` insists on an exact fit.
fn testKeyDer(buf: []u8) ![]const u8 {
    return std.fmt.hexToBytes(buf[0 .. test_key_hex.len / 2], test_key_hex);
}

fn testKey(buf: []u8) !PrivateKey {
    return PrivateKey.parsePkcs1(try testKeyDer(buf));
}

/// The key's public half: what a certificate carries, and what `signPss` is
/// checked against.
fn publicKey(key: PrivateKey) !Certificate.rsa.PublicKey {
    return Certificate.rsa.PublicKey.fromBytes(key.e, key.n);
}

test "PKCS#1 and PKCS#8 encodings parse to the same key" {
    var buf1: [2048]u8 = undefined;
    var buf8: [2048]u8 = undefined;
    var wrapped: [2048]u8 = undefined;
    const k1 = try testKey(&buf1);
    const k8 = try PrivateKey.parsePkcs1(try PrivateKey.pkcs1FromPkcs8(
        privateKeyInfo(&rsa_encryption_oid, try testKeyDer(&buf8), &wrapped),
    ));
    try testing.expectEqual(2048, k1.modulusBits());
    inline for (.{ "n", "e", "p", "q", "dp", "dq", "qinv" }) |f| {
        try testing.expectEqualSlices(u8, @field(k1, f), @field(k8, f));
    }
    try k1.check();

    // The public half is the same key, not a copy of the private one: the
    // signature below verifies under it, and under nothing else.
    var pub_n: [256]u8 = undefined;
    try (try publicKey(k1)).n.toBytes(&pub_n, .big);
    try testing.expectEqualSlices(u8, k1.n, &pub_n);
}

test "PSS signatures verify with std's verifier, for every TLS hash" {
    var buf: [2048]u8 = undefined;
    const key = try testKey(&buf);
    const public = try publicKey(key);
    var sig: [max_signature_len]u8 = undefined;
    // Seeded: the salt is the whole of the signature's freedom, so a fixed
    // seed is a fixed signature and a failing verify can be reproduced.
    var prng = std.Random.DefaultPrng.init(0x70733321);
    inline for (.{ Sha256, Sha384, Sha512 }) |H| {
        const s = try key.signPss(H, "message", &sig, prng.random());
        try testing.expectEqual(256, s.len);
        try Certificate.rsa.PSSSignature.verify(256, s[0..256].*, "message", public, H);
        try testing.expectError(error.InvalidSignature, Certificate.rsa.PSSSignature.verify(256, s[0..256].*, "massage", public, H));
    }
}

test "a PSS signature matches one OpenSSL verified" {
    // `openssl pkeyutl -verify -pubin -inkey rsa.test.pem -sigfile sig.bin
    // -in msg.sha256 -pkeyopt rsa_padding_mode:pss -pkeyopt
    // rsa_pss_saltlen:32 -pkeyopt digest:sha256` accepts these bytes over
    // `test_key_hex`'s key.
    var buf: [2048]u8 = undefined;
    const key = try testKey(&buf);
    var salt: [32]u8 = undefined;
    for (&salt, 0..) |*b, i| b.* = @intCast(i);
    var sig: [max_signature_len]u8 = undefined;
    const s = try key.signPssWithSalt(Sha256, "quic-zig rsa-pss fixture", &salt, &sig);
    var expected: [256]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, openssl_pss_signature_hex);
    try testing.expectEqualSlices(u8, &expected, s);
}

test "keys that do not fit together are rejected" {
    var buf: [2048]u8 = undefined;
    const good = try testKey(&buf);

    var bad = good;
    bad.dp = good.dq; // wrong CRT exponent
    try testing.expectError(error.InvalidKey, bad.check());

    bad = good;
    bad.qinv = good.dp;
    try testing.expectError(error.InvalidKey, bad.check());

    // Swapped primes keep p*q but break qinv.
    bad = good;
    bad.p = good.q;
    bad.q = good.p;
    bad.dp = good.dq;
    bad.dq = good.dp;
    try testing.expectError(error.InvalidKey, bad.check());
}

test "malformed and unsupported encodings" {
    var buf: [2048]u8 = undefined;
    const der = try testKeyDer(&buf);
    // Every truncation fails cleanly.
    for (0..der.len) |n| try testing.expect(std.meta.isError(PrivateKey.parsePkcs1(der[0..n])));

    // Multi-prime (version 1).
    var copy: [2048]u8 = undefined;
    @memcpy(copy[0..der.len], der);
    const version_at = mem.indexOf(u8, der[0..8], &.{ 0x02, 0x01, 0x00 }).?;
    copy[version_at + 2] = 1;
    try testing.expectError(error.UnsupportedKey, PrivateKey.parsePkcs1(copy[0..der.len]));

    // An Ed25519 PKCS#8 key is not RSA. It is the right shape and 48 bytes
    // long, so the only thing refusing it is the algorithm.
    var ed_buf: [128]u8 = undefined;
    const ed = ed25519Pkcs8(&[_]u8{0x2b} ** 32, &ed_buf);
    try testing.expectEqual(48, ed.len);
    try testing.expectError(error.UnsupportedKey, PrivateKey.pkcs1FromPkcs8(ed));
}

