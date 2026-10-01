// TLS 1.3 handshake for QUIC (RFC 8446 + RFC 9001)
//
// Supports TLS_AES_128_GCM_SHA256 (0x1301) only.
// X25519 for key exchange. Ed25519 for a peer's identity, and for the
// CertificateVerify that proves possession of it.
//
// A peer's certificate is a 44-byte DER `SubjectPublicKeyInfo` around the 32
// raw bytes of an Ed25519 key, and those 32 bytes are the node id. There is
// no chain to walk, no host name to match and no validity date to read: a
// peer is the key it presents or the handshake ends. Upstream validated an
// X.509 chain here, and every part of that is gone — see
// `liftEd25519Spki`, which is the whole of certificate validation now.

const std = @import("std");
const io = @import("../io_compat.zig");
const crypto = std.crypto;
const tls = std.crypto.tls;
const quic_crypto = @import("crypto.zig");
const protocol = @import("protocol.zig");
const transport_params = @import("transport_params.zig");
const limits = @import("limits.zig");
pub const rsa = @import("rsa.zig");

const Certificate = std.crypto.Certificate;

const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;
const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = crypto.hash.sha2.Sha256;
const Sha384 = crypto.hash.sha2.Sha384;
const Sha512 = crypto.hash.sha2.Sha512;
const X25519 = crypto.dh.X25519;
const EcdsaP256Sha256 = crypto.sign.ecdsa.EcdsaP256Sha256;
const ecdsa_p256 = @import("ecdsa_p256.zig");
const Ed25519 = crypto.sign.Ed25519;
const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;

// Handshake message types, extension types, signature schemes, named groups,
// cipher suites and protocol version all come from std.crypto.tls enums
// (HandshakeType, ExtensionType, SignatureScheme, NamedGroup, CipherSuite,
// ProtocolVersion) at their use sites.

const P256 = crypto.ecc.P256;

pub const EncryptionLevel = quic_crypto.EncryptionLevel;

pub const PrivateKeyAlgorithm = enum {
    ecdsa_p256_sha256,
    ed25519,
    /// Signs with RSA-PSS (rsa_pss_rsae_*), SHA-256 unless the client offers
    /// only SHA-384 or SHA-512.
    rsa,
};

/// The CertificateVerify scheme for a key, from the client's
/// signature_algorithms (the list body: big-endian u16s). Null when the
/// client offers none that fits.
pub fn signatureSchemeFor(alg: PrivateKeyAlgorithm, offered: []const u8) ?tls.SignatureScheme {
    const ours: []const tls.SignatureScheme = switch (alg) {
        .ecdsa_p256_sha256 => &.{.ecdsa_secp256r1_sha256},
        .ed25519 => &.{.ed25519},
        // rsa_pss_pss_* needs an RSASSA-PSS certificate; ours are rsaEncryption.
        .rsa => &.{ .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512 },
    };
    for (ours) |scheme| {
        var i: usize = 0;
        while (i + 2 <= offered.len) : (i += 2) {
            if (std.mem.readInt(u16, offered[i..][0..2], .big) == @intFromEnum(scheme)) return scheme;
        }
    }
    return null;
}

// ─── CertificateVerify signature verification ────────────────────────

/// Checks a CertificateVerify signature made with the leaf's public key.
pub fn verifyCertificateVerifySignature(
    pub_key_bytes: []const u8,
    pub_key_algo: Certificate.AlgorithmCategory,
    sig_algo: u16,
    sig_bytes: []const u8,
    signed_content: []const u8,
) HandshakeError!void {
    const scheme: tls.SignatureScheme = @enumFromInt(sig_algo);
    switch (scheme) {
        .ecdsa_secp256r1_sha256 => {
            if (pub_key_algo != .X9_62_id_ecPublicKey) return error.BadCertificateVerify;
            const pub_key = EcdsaP256Sha256.PublicKey.fromSec1(pub_key_bytes) catch return error.BadCertificateVerify;
            const sig = EcdsaP256Sha256.Signature.fromDer(sig_bytes) catch return error.BadCertificateVerify;
            sig.verify(signed_content, pub_key) catch return error.BadCertificateVerify;
        },
        .ecdsa_secp384r1_sha384 => {
            if (pub_key_algo != .X9_62_id_ecPublicKey) return error.BadCertificateVerify;
            const P384 = crypto.sign.ecdsa.EcdsaP384Sha384;
            const pub_key = P384.PublicKey.fromSec1(pub_key_bytes) catch return error.BadCertificateVerify;
            const sig = P384.Signature.fromDer(sig_bytes) catch return error.BadCertificateVerify;
            sig.verify(signed_content, pub_key) catch return error.BadCertificateVerify;
        },
        .ed25519 => {
            if (pub_key_algo != .curveEd25519) return error.BadCertificateVerify;
            if (pub_key_bytes.len != Ed25519.PublicKey.encoded_length) return error.BadCertificateVerify;
            if (sig_bytes.len != Ed25519.Signature.encoded_length) return error.BadCertificateVerify;
            const pub_key = Ed25519.PublicKey.fromBytes(pub_key_bytes[0..Ed25519.PublicKey.encoded_length].*) catch return error.BadCertificateVerify;
            const sig = Ed25519.Signature.fromBytes(sig_bytes[0..Ed25519.Signature.encoded_length].*);
            sig.verify(signed_content, pub_key) catch return error.BadCertificateVerify;
        },
        .rsa_pss_rsae_sha256 => verifyRsaPss(pub_key_bytes, pub_key_algo, sig_bytes, signed_content, Sha256) catch return error.BadCertificateVerify,
        .rsa_pss_rsae_sha384 => verifyRsaPss(pub_key_bytes, pub_key_algo, sig_bytes, signed_content, Sha384) catch return error.BadCertificateVerify,
        .rsa_pss_rsae_sha512 => verifyRsaPss(pub_key_bytes, pub_key_algo, sig_bytes, signed_content, Sha512) catch return error.BadCertificateVerify,
        else => return error.BadCertificateVerify,
    }
}

fn verifyRsaPss(
    pub_key_bytes: []const u8,
    pub_key_algo: Certificate.AlgorithmCategory,
    sig_bytes: []const u8,
    signed_content: []const u8,
    comptime Hash: type,
) !void {
    if (pub_key_algo != .rsaEncryption) return error.BadCertificateVerify;
    const std_rsa = Certificate.rsa;
    const pk_components = std_rsa.PublicKey.parseDer(pub_key_bytes) catch return error.BadCertificateVerify;
    const public_key = std_rsa.PublicKey.fromBytes(pk_components.exponent, pk_components.modulus) catch return error.BadCertificateVerify;

    switch (pk_components.modulus.len) {
        inline 128, 256, 384, 512 => |modulus_len| {
            if (sig_bytes.len != modulus_len) return error.BadCertificateVerify;
            std_rsa.PSSSignature.verify(modulus_len, sig_bytes[0..modulus_len].*, signed_content, public_key, Hash) catch return error.BadCertificateVerify;
        },
        else => return error.BadCertificateVerify,
    }
}

// ─── Peer identity: a raw Ed25519 SubjectPublicKeyInfo ───────────────

/// The key an Ed25519 `SubjectPublicKeyInfo` wraps, and the node id it is.
/// Named once so the encoder, the decoder and the tests cannot drift on it.
const ed25519_key_len = Ed25519.PublicKey.encoded_length;

/// A peer's certificate, whole: a DER `SubjectPublicKeyInfo` (RFC 5280
/// §4.1.2.7) around `ed25519_key_len` raw bytes. RFC 8410 §3 fixes the
/// AlgorithmIdentifier — the OID `1.3.101.112` and absent parameters — so DER
/// fixes the length, and no part of it is negotiable.
pub const ed25519_spki_len = 44;

/// Why a peer's certificate is not a raw Ed25519 identity. Both are
/// `bad_certificate` on the wire (RFC 8446 §4.2.1); the split is here so a
/// caller can tell malformed DER from an algorithm we do not use, and so
/// neither is quietly accepted as the other.
pub const SpkiError = error{
    /// Not 44 bytes, or not the two elements an Ed25519 SPKI is.
    MalformedSubjectPublicKeyInfo,
    /// A well-formed SPKI naming an algorithm other than Ed25519.
    UnsupportedSubjectPublicKeyInfo,
};

/// The 12 bytes of an Ed25519 SPKI that are not the key: the outer SEQUENCE
/// and its length, the AlgorithmIdentifier, the BIT STRING header, and the
/// count of unused bits (zero — a key is a whole number of bytes). The
/// lengths are the whole reason the element is exactly 44 bytes, and 42 of
/// those are accounted for here.
const ed25519_spki_prefix = [_]u8{
    0x30, 0x2A, // SEQUENCE, 42 bytes
    0x30, 0x05, // SEQUENCE, 5 bytes: AlgorithmIdentifier
    0x06, 0x03, 0x2B, 0x65, 0x70, // OBJECT IDENTIFIER 1.3.101.112
    0x03, 0x21, 0x00, // BIT STRING, 33 bytes, no unused bits
};

/// The certificate a peer whose node id is `key` presents: the 44-byte SPKI
/// around it. The inverse of `liftEd25519Spki`, and what goes in
/// `ServerCertificate.cert_chain_der` when a node is its own trust anchor.
pub fn ed25519Spki(key: *const [ed25519_key_len]u8) [ed25519_spki_len]u8 {
    var der = [_]u8{0} ** ed25519_spki_len;
    @memcpy(der[0..ed25519_spki_prefix.len], &ed25519_spki_prefix);
    @memcpy(der[ed25519_spki_prefix.len..], key);
    return der;
}

/// The 32 bytes of Ed25519 key inside a peer's certificate.
///
/// This is the whole of certificate validation in this stack. Upstream parsed
/// the certificate as X.509, matched the host name, walked the issuer chain
/// and verified the leaf against a CA bundle; a peer holding an Ed25519 key
/// has no CA to chain to, so all of that is deleted rather than left behind a
/// flag (DECISIONS/0001 step 3). A certificate that is not one of these is
/// refused, which is what keeps a stack that insists on parsing X.509 from
/// being an iroh peer at all.
pub fn liftEd25519Spki(der: []const u8) SpkiError![ed25519_key_len]u8 {
    // The length is fixed, so this is also the whole bounds check: nothing
    // below can read outside `der`.
    if (der.len != ed25519_spki_len) return error.MalformedSubjectPublicKeyInfo;

    const spki = readTlv(der, 0, der.len) orelse return error.MalformedSubjectPublicKeyInfo;
    if (spki.tag != 0x30 or spki.end != der.len) return error.MalformedSubjectPublicKeyInfo;
    const alg = readTlv(der, spki.start, spki.end) orelse return error.MalformedSubjectPublicKeyInfo;
    const bits = readTlv(der, alg.end, spki.end) orelse return error.MalformedSubjectPublicKeyInfo;
    if (alg.tag != 0x30 or bits.end != spki.end) return error.MalformedSubjectPublicKeyInfo;

    const oid = readTlv(der, alg.start, alg.end) orelse return error.MalformedSubjectPublicKeyInfo;
    if (oid.tag != 0x06) return error.MalformedSubjectPublicKeyInfo;
    // RFC 8410 §3: the Ed25519 AlgorithmIdentifier carries absent parameters,
    // and DER admits nothing else in that slot.
    if (oid.end != alg.end) return error.MalformedSubjectPublicKeyInfo;
    if (!std.mem.eql(u8, der[oid.start..oid.end], &[_]u8{ 0x2B, 0x65, 0x70 })) {
        return error.UnsupportedSubjectPublicKeyInfo;
    }

    // BIT STRING: the unused-bit count, then the key itself.
    if (bits.tag != 0x03 or bits.end - bits.start != ed25519_key_len + 1) {
        return error.MalformedSubjectPublicKeyInfo;
    }
    if (der[bits.start] != 0) return error.MalformedSubjectPublicKeyInfo;
    var key: [ed25519_key_len]u8 = undefined;
    @memcpy(&key, der[bits.start + 1 ..][0..ed25519_key_len]);
    return key;
}

/// The algorithm of every key `liftEd25519Spki` returns, known by
/// construction rather than by parsing: an SPKI this stack accepts is
/// Ed25519 or it is refused. Named once because it is what makes
/// `verifyCertificateVerifySignature`'s `.ed25519` arm reachable for a peer
/// certificate — the arm demands this category, and upstream could only ever
/// produce it from an X.509 parse, so the arm was dead for a raw SPKI.
const lifted_key_algo: Certificate.AlgorithmCategory = .curveEd25519;

const Tlv = struct { tag: u8, start: usize, end: usize };

/// One element at `pos`, its contents within `limit`. Single-byte tags only,
/// as std reads them; definite lengths of up to four bytes.
fn readTlv(b: []const u8, pos: usize, limit: usize) ?Tlv {
    if (pos >= limit or limit - pos < 2) return null;
    const tag = b[pos];
    if (tag & 0x1f == 0x1f) return null;
    const first = b[pos + 1];
    var i = pos + 2;
    var len: usize = first;
    if (first >= 0x80) {
        const n: usize = first & 0x7f;
        if (n == 0 or n > 4 or n > limit - i) return null;
        len = 0;
        for (b[i..][0..n]) |x| len = (len << 8) | x;
        i += n;
    }
    if (len > limit - i) return null;
    return .{ .tag = tag, .start = i, .end = i + len };
}

// ─── Client certificates (RFC 8446 §4.3.2, §4.4.2) ───────────────────

/// A server's policy for client certificates: the CertificateRequest it
/// sends and how it judges the answer. Shared by the QUIC server
/// (`TlsConfig.client_auth`, `CertEntry.client_auth`) and `tls_server`.
///
/// A client's certificate is judged the way a server's is: lifted out of its
/// `SubjectPublicKeyInfo` and compared against `expect_node_id`. A
/// certificate that fails that always fails the handshake with
/// bad_certificate; `mode` only decides what happens when the client sends
/// none.
///
/// A policy in force does not opt the connection out of resumption. TLS 1.3
/// does not currently send a CertificateRequest on a PSK handshake (RFC 8446
/// Appendix E.3), and the combination that appendix calls unsafe is an
/// *external* PSK, which two endpoints may share and authenticate each other
/// with. A PSK out of a NewSessionTicket is the case it singles out as sound:
/// the binder makes the client's signature cover the server's certificate
/// transitively. So a resumed connection here asks for the certificate and
/// the client answers exactly as it does on a full handshake, and every
/// connection proves its certificate afresh. What the PSK removes is the
/// server's own Certificate and CertificateVerify. It does not remove the
/// client identity, because a session ticket is bearer material: it is handed
/// to the client and replayable, so a node id recovered from one would be a
/// credential rather than a proof of possession (DECISIONS/0001 item 4).
pub const ClientAuth = struct {
    /// The node id the client's certificate has to carry. Null accepts any
    /// key, and then the client has proved possession of the id it presented
    /// rather than being the node we asked for.
    expect_node_id: ?[32]u8 = null,
    mode: Mode = .required,

    pub const Mode = enum {
        /// No certificate: the handshake fails with certificate_required.
        required,
        /// No certificate: the handshake completes without a client identity.
        optional,
    };
};

/// Signature schemes a client may sign its CertificateVerify with, as the
/// signature_algorithms body of our CertificateRequest. The rsa_pkcs1
/// entries cover certificate signatures only (RFC 8446 §4.2.3);
/// `verifyCertificateVerifySignature` refuses them for CertificateVerify.
pub const client_auth_signature_schemes = blk: {
    const schemes = [_]tls.SignatureScheme{
        .ecdsa_secp256r1_sha256, .ecdsa_secp384r1_sha384, .ed25519,
        .rsa_pss_rsae_sha256,    .rsa_pss_rsae_sha384,    .rsa_pss_rsae_sha512,
        .rsa_pkcs1_sha256,       .rsa_pkcs1_sha384,       .rsa_pkcs1_sha512,
    };
    var out: [schemes.len * 2]u8 = undefined;
    for (schemes, 0..) |s, i| std.mem.writeInt(u16, out[i * 2 ..][0..2], @intFromEnum(s), .big);
    break :blk out;
};

/// A CertificateRequest (RFC 8446 §4.3.2) with an empty context, offering
/// `client_auth_signature_schemes`. Returns a slice of `buf`.
///
/// No certificate_authorities extension: a client identity here is a raw key,
/// so there is no issuer to point it at and nothing for a client to choose
/// between. The extension is still parsed on the way in, because a peer we
/// do not control may send one.
pub fn buildCertificateRequest(buf: []u8) error{BufferTooSmall}![]const u8 {
    const sig = client_auth_signature_schemes;
    const exts_len: usize = 4 + 2 + sig.len;
    const total = 4 + 1 + 2 + exts_len;
    if (buf.len < total or total - 4 > std.math.maxInt(u24)) return error.BufferTooSmall;
    buf[0] = @intFromEnum(tls.HandshakeType.certificate_request);
    std.mem.writeInt(u24, buf[1..4], @intCast(total - 4), .big);
    buf[4] = 0; // certificate_request_context
    writeU16(buf[5..], @intCast(exts_len));
    var pos: usize = 7;
    pos = writeExtHeader(buf, pos, @intFromEnum(tls.ExtensionType.signature_algorithms), 2 + sig.len);
    writeU16(buf[pos..], @intCast(sig.len));
    pos += 2;
    @memcpy(buf[pos..][0..sig.len], &sig);
    pos += sig.len;
    return buf[0..pos];
}

/// The signature_algorithms list body from a CertificateRequest's body (the
/// message without its 4-byte header); `DecodeError` on a malformed one.
/// RFC 8446 §4.3.2 makes the extension mandatory.
pub fn parseCertificateRequest(body: []const u8) error{ DecodeError, MissingExtension, IllegalParameter }![]const u8 {
    if (body.len < 1) return error.DecodeError;
    const ctx_len = body[0];
    // Only post-handshake auth may carry a context, and we never do that.
    if (ctx_len != 0) return error.IllegalParameter;
    if (body.len < 3) return error.DecodeError;
    const exts_len = readU16(body[1..]);
    if (3 + @as(usize, exts_len) != body.len) return error.DecodeError;
    var pos: usize = 3;
    var sig_algs: ?[]const u8 = null;
    while (pos < body.len) {
        if (pos + 4 > body.len) return error.DecodeError;
        const kind = readU16(body[pos..]);
        const len = readU16(body[pos + 2 ..]);
        pos += 4;
        if (pos + len > body.len) return error.DecodeError;
        const data = body[pos..][0..len];
        pos += len;
        if (kind == @intFromEnum(tls.ExtensionType.signature_algorithms)) {
            if (sig_algs != null) return error.IllegalParameter;
            if (data.len < 2 or readU16(data) + 2 != data.len or data.len % 2 != 0) return error.DecodeError;
            sig_algs = data[2..];
        }
    }
    return sig_algs orelse error.MissingExtension;
}

/// The leaf of a Certificate message body (RFC 8446 §4.4.2) and up to
/// `out.len` certificates, leaf first, in `out`. Null for an empty list.
/// The context must be empty: we never send one.
pub fn parseCertificateList(body: []const u8, out: [][]const u8) error{ DecodeError, IllegalParameter, BadCertificate }!?[]const []const u8 {
    if (body.len < 4) return error.DecodeError;
    if (body[0] != 0) return error.IllegalParameter;
    const list_len = std.mem.readInt(u24, body[1..4], .big);
    if (4 + @as(usize, list_len) != body.len) return error.DecodeError;
    var pos: usize = 4;
    var n: usize = 0;
    while (pos < body.len) {
        if (pos + 3 > body.len) return error.DecodeError;
        const len = std.mem.readInt(u24, body[pos..][0..3], .big);
        pos += 3;
        if (len == 0 or pos + len + 2 > body.len) return error.DecodeError;
        if (n == out.len) return error.BadCertificate;
        out[n] = body[pos..][0..len];
        n += 1;
        pos += len;
        const ext_len = readU16(body[pos..]);
        pos += 2;
        if (pos + ext_len > body.len) return error.DecodeError;
        pos += ext_len;
    }
    return if (n == 0) null else out[0..n];
}

// ─── TranscriptHash ──────────────────────────────────────────────────

pub const TranscriptHash = struct {
    state: Sha256,

    pub fn init() TranscriptHash {
        return .{ .state = Sha256.init(.{}) };
    }

    // Update with a raw TLS handshake message (type + 3-byte length + body).
    pub fn update(self: *TranscriptHash, msg: []const u8) void {
        self.state.update(msg);
    }

    pub fn current(self: *const TranscriptHash) [32]u8 {
        // Copy the state to get a snapshot without consuming it
        var copy = self.state;
        return copy.finalResult();
    }
};

// ─── KeySchedule ─────────────────────────────────────────────────────

pub const KeySchedule = struct {
    early_secret: [32]u8,
    handshake_secret: [32]u8,
    master_secret: [32]u8,
    client_handshake_traffic_secret: [32]u8,
    server_handshake_traffic_secret: [32]u8,
    client_app_traffic_secret: [32]u8,
    server_app_traffic_secret: [32]u8,
    resumption_master_secret: [32]u8 = .{0} ** 32,
    client_early_traffic_secret: [32]u8 = .{0} ** 32,
    computed_handshake: bool = false,
    computed_app: bool = false,

    pub fn init() KeySchedule {
        var ks: KeySchedule = undefined;
        ks.computed_handshake = false;
        ks.computed_app = false;
        ks.resumption_master_secret = .{0} ** 32;
        ks.client_early_traffic_secret = .{0} ** 32;
        // early_secret = HKDF-Extract(salt=0, IKM=0)
        const zero_key: [32]u8 = .{0} ** 32;
        ks.early_secret = HkdfSha256.extract(&(.{0} ** 1), &zero_key);
        return ks;
    }

    // Initialize with a PSK (for session resumption)
    pub fn initWithPsk(psk: [32]u8) KeySchedule {
        var ks: KeySchedule = undefined;
        ks.computed_handshake = false;
        ks.computed_app = false;
        ks.resumption_master_secret = .{0} ** 32;
        ks.client_early_traffic_secret = .{0} ** 32;
        // early_secret = HKDF-Extract(salt=0, IKM=PSK)
        ks.early_secret = HkdfSha256.extract(&(.{0} ** 1), &psk);
        return ks;
    }

    // Derive client early traffic secret for 0-RTT data
    pub fn deriveEarlyDataSecret(self: *KeySchedule, transcript_hash: [32]u8) void {
        self.client_early_traffic_secret = deriveSecret(self.early_secret, "c e traffic", transcript_hash);
    }

    // Derive resumption master secret (after full handshake transcript)
    pub fn deriveResumptionMasterSecret(self: *KeySchedule, transcript_hash: [32]u8) void {
        self.resumption_master_secret = deriveSecret(self.master_secret, "res master", transcript_hash);
    }

    // Derive handshake secrets from the shared secret and transcript hash.
    pub fn deriveHandshakeSecrets(self: *KeySchedule, shared_secret: []const u8, transcript_hash: [32]u8) void {
        // derived1 = Derive-Secret(early_secret, "derived", Hash(""))
        const empty_hash = tls.emptyHash(Sha256);
        const derived1 = deriveSecret(self.early_secret, "derived", empty_hash);

        // handshake_secret = HKDF-Extract(derived1, shared_secret)
        self.handshake_secret = HkdfSha256.extract(&derived1, shared_secret);

        // c_hs_traffic = Derive-Secret(handshake_secret, "c hs traffic", transcript)
        self.client_handshake_traffic_secret = deriveSecret(self.handshake_secret, "c hs traffic", transcript_hash);

        // s_hs_traffic = Derive-Secret(handshake_secret, "s hs traffic", transcript)
        self.server_handshake_traffic_secret = deriveSecret(self.handshake_secret, "s hs traffic", transcript_hash);

        self.computed_handshake = true;
    }

    // Derive application secrets from the transcript hash after server Finished.
    pub fn deriveAppSecrets(self: *KeySchedule, transcript_hash: [32]u8) void {
        // derived2 = Derive-Secret(handshake_secret, "derived", Hash(""))
        const empty_hash = tls.emptyHash(Sha256);
        const derived2 = deriveSecret(self.handshake_secret, "derived", empty_hash);

        // master_secret = HKDF-Extract(derived2, 0)
        const zero_key: [32]u8 = .{0} ** 32;
        self.master_secret = HkdfSha256.extract(&derived2, &zero_key);

        // c_ap_traffic = Derive-Secret(master_secret, "c ap traffic", transcript)
        self.client_app_traffic_secret = deriveSecret(self.master_secret, "c ap traffic", transcript_hash);

        // s_ap_traffic = Derive-Secret(master_secret, "s ap traffic", transcript)
        self.server_app_traffic_secret = deriveSecret(self.master_secret, "s ap traffic", transcript_hash);

        self.computed_app = true;
    }

    // Derive QUIC Open/Seal keys from a traffic secret (AES-128-GCM, 16-byte keys).
    pub fn deriveQuicKeys(traffic_secret: [32]u8) struct { key: [16]u8, iv: [12]u8, hp: [16]u8 } {
        return .{
            .key = quic_crypto.hkdfExpandLabel(traffic_secret, "quic key", "", 16),
            .iv = quic_crypto.hkdfExpandLabel(traffic_secret, "quic iv", "", 12),
            .hp = quic_crypto.hkdfExpandLabel(traffic_secret, "quic hp", "", 16),
        };
    }

    pub fn makeOpen(traffic_secret: [32]u8) quic_crypto.Open {
        return makeOpenWithCipher(traffic_secret, .aes_128_gcm_sha256);
    }

    pub fn makeSeal(traffic_secret: [32]u8) quic_crypto.Seal {
        return makeSealWithCipher(traffic_secret, .aes_128_gcm_sha256);
    }

    pub fn makeOpenWithCipher(traffic_secret: [32]u8, cipher: quic_crypto.CipherSuite) quic_crypto.Open {
        return makeOpenFull(traffic_secret, cipher, protocol.QUIC_V1);
    }

    pub fn makeSealWithCipher(traffic_secret: [32]u8, cipher: quic_crypto.CipherSuite) quic_crypto.Seal {
        return makeSealFull(traffic_secret, cipher, protocol.QUIC_V1);
    }

    pub fn makeOpenFull(traffic_secret: [32]u8, cipher: quic_crypto.CipherSuite, version: u32) quic_crypto.Open {
        const kl = cipher.keyLen();
        const label_iv = protocol.quicLabel(version, .iv);
        var open: quic_crypto.Open = .{
            .key = quic_crypto.deriveKeyPaddedV(traffic_secret, kl, version),
            .nonce = quic_crypto.hkdfExpandLabel(traffic_secret, label_iv, "", 12),
            .hp_key = quic_crypto.deriveHpKeyPaddedV(traffic_secret, cipher.hpKeyLen(), version),
            .cipher_suite = cipher,
        };
        open.prepareCtx();
        return open;
    }

    pub fn makeSealFull(traffic_secret: [32]u8, cipher: quic_crypto.CipherSuite, version: u32) quic_crypto.Seal {
        const kl = cipher.keyLen();
        const label_iv = protocol.quicLabel(version, .iv);
        var seal: quic_crypto.Seal = .{
            .key = quic_crypto.deriveKeyPaddedV(traffic_secret, kl, version),
            .nonce = quic_crypto.hkdfExpandLabel(traffic_secret, label_iv, "", 12),
            .hp_key = quic_crypto.deriveHpKeyPaddedV(traffic_secret, cipher.hpKeyLen(), version),
            .cipher_suite = cipher,
        };
        seal.prepareCtx();
        return seal;
    }

    // Compute the Finished verify_data.
    pub fn computeFinishedVerifyData(base_key: [32]u8, transcript_hash: [32]u8) [32]u8 {
        const finished_key = quic_crypto.hkdfExpandLabel(base_key, "finished", "", 32);
        return tls.hmac(HmacSha256, &transcript_hash, finished_key);
    }

    fn deriveSecret(secret: [32]u8, comptime label: []const u8, transcript_hash: [32]u8) [32]u8 {
        return quic_crypto.hkdfExpandLabel(secret, label, &transcript_hash, 32);
    }
};

// ─── Session Ticket (0-RTT resumption) ───────────────────────────────

pub const SessionTicket = struct {
    psk: [32]u8, // Pre-shared key derived from resumption_master_secret
    ticket: [512]u8 = .{0} ** 512, // Opaque ticket data (encrypted by server)
    ticket_len: u16 = 0,
    ticket_age_add: u32 = 0, // Age obfuscation value
    /// A second on the caller's clock, not on the epoch. Only differences
    /// against another stamp from that same clock are ever taken of it, so
    /// the base cancels and nothing here depends on what zero means.
    creation_time: i64 = 0,
    lifetime: u32 = 0, // Seconds
    max_early_data_size: u32 = 0, // From early_data extension
    alpn: [16]u8 = .{0} ** 16, // Negotiated ALPN
    alpn_len: u8 = 0,

    // RFC 9000 §7.4.1: remembered transport parameters for 0-RTT
    initial_max_data: u64 = 0,
    initial_max_stream_data_bidi_local: u64 = 0,
    initial_max_stream_data_bidi_remote: u64 = 0,
    initial_max_stream_data_uni: u64 = 0,
    initial_max_streams_bidi: u64 = 0,
    initial_max_streams_uni: u64 = 0,
    active_connection_id_limit: u64 = 2,

    pub fn getTicket(self: *const SessionTicket) []const u8 {
        return self.ticket[0..self.ticket_len];
    }

    pub fn getAlpn(self: *const SessionTicket) []const u8 {
        return self.alpn[0..self.alpn_len];
    }

    pub fn isExpired(self: *const SessionTicket, now_s: i64) bool {
        return (now_s - self.creation_time) > @as(i64, self.lifetime);
    }
};

/// The largest sealed ticket this stack writes: a fixed plaintext plus
/// AES-128-GCM's 16-byte tag. Named once because both ends of the ticket
/// path need the same number — the writer sizes its buffer and the reader
/// bounds what it will copy — and two spellings of it are two chances to
/// read past one of them.
const sealed_ticket_len = 80;

/// A server's ticket sealing key: AES-128-GCM, so 16 bytes (RFC 8446
/// §4.6.1 leaves the construction to the server). One value for a server's
/// whole life, and the only way to make one is `generate` — there is no
/// `rotate` and no setter, so a key cannot change under the tickets it
/// sealed without that being written out.
///
/// `generate` takes the caller's entropy rather than reaching for a global:
/// a handshake driven from a global CSPRNG could not be driven twice with
/// two generators, which is the property the whole pure core is for
/// (DECISIONS/0002).
pub const TicketKey = struct {
    bytes: [16]u8,

    pub fn generate(random: std.Random) TicketKey {
        var key: TicketKey = undefined;
        random.bytes(&key.bytes);
        return key;
    }
};

/// Resumption, as one value.
///
/// A client resumes with a ticket it holds; a server issues and accepts
/// tickets under a key it holds. One field on `TlsConfig`, not two,
/// because the two are one fact — a ticket is only resumable by the key
/// that sealed it — and a pair of fields lets a caller name a ticket from
/// one key and a key from another without either of them noticing. That
/// pairing is what DECISIONS/0001 item 1 asks for, and making it a value
/// rather than a convention is the only version of it that survives
/// contact with a caller who rebuilds the config for every connection.
///
/// The tag says which end is speaking, so a client config cannot be handed
/// a sealing key and a server config cannot be handed a ticket.
pub const Resumption = union(enum) {
    server: TicketKey,
    client: *const SessionTicket,

    /// The key to seal and open tickets under, or null on a config that
    /// issues none — which a client config always is. Static, and named for
    /// the optional, because that is what a config field holds and Zig will
    /// not find a union's members through one.
    pub fn serverKey(self: ?Resumption) ?TicketKey {
        return switch (self orelse return null) {
            .server => |key| key,
            .client => null,
        };
    }

    /// The ticket to resume with, or null on a config that resumes with
    /// none — which a server config always is.
    pub fn clientTicket(self: ?Resumption) ?*const SessionTicket {
        return switch (self orelse return null) {
            .client => |ticket| ticket,
            .server => null,
        };
    }
};

// ─── Server certificates / SNI ───────────────────────────────────────

/// A certificate chain and the private key for its leaf.
pub const ServerCertificate = struct {
    /// DER-encoded certificates, leaf first.
    cert_chain_der: []const []const u8,
    /// Raw P-256 scalar or Ed25519 seed (32 bytes), or an RSA key's PKCS#1
    /// DER, as `extractPrivateKey` returns them.
    private_key_bytes: []const u8,
    private_key_algorithm: PrivateKeyAlgorithm = .ecdsa_p256_sha256,
};

/// A certificate served for a set of host names. Shared by the QUIC server
/// (`TlsConfig.certs`) and the TCP TLS server (`tls_server.Config.certs`).
pub const CertEntry = struct {
    /// Host names this certificate is served for. `"*.example.com"` matches
    /// exactly one label (`a.example.com`, not `example.com` or
    /// `a.b.example.com`). Matching is ASCII case-insensitive.
    server_names: []const []const u8,
    cert: ServerCertificate,
    /// Ask clients that reach this certificate for one of their own.
    client_auth: ?*const ClientAuth = null,
};

pub const CertSelection = struct {
    entry: *const CertEntry,
    /// False when the client sent no SNI or nothing matched it, so the first
    /// entry was used as the default.
    matched: bool,
};

/// Picks the certificate for a ClientHello's SNI: an exact name first, then a
/// one-label wildcard, then `entries[0]`. Returns null only when `entries` is
/// empty.
pub fn selectCertificate(entries: []const CertEntry, sni: ?[]const u8) ?CertSelection {
    return selectCertificateFor(entries, sni, null);
}

/// `selectCertificate`, preferring within each step (exact, wildcard,
/// default) the first entry whose key can sign with one of `sig_algs`, the
/// client's signature_algorithms list body. The default step considers every
/// entry, so a client that cannot verify `entries[0]` gets another
/// certificate rather than a failed handshake.
pub fn selectCertificateFor(entries: []const CertEntry, sni: ?[]const u8, sig_algs: ?[]const u8) ?CertSelection {
    if (entries.len == 0) return null;
    const Pick = struct {
        sig_algs: ?[]const u8,
        first: ?*const CertEntry = null,
        usable: ?*const CertEntry = null,

        fn add(pick: *@This(), e: *const CertEntry) void {
            if (pick.first == null) pick.first = e;
            if (pick.usable != null) return;
            const offered = pick.sig_algs orelse return;
            if (signatureSchemeFor(e.cert.private_key_algorithm, offered) != null) pick.usable = e;
        }

        fn best(pick: @This()) ?*const CertEntry {
            return pick.usable orelse pick.first;
        }
    };

    // A trailing dot names the same host (RFC 6066 forbids it, clients still send it).
    const raw = sni orelse "";
    const name = if (raw.len > 0 and raw[raw.len - 1] == '.') raw[0 .. raw.len - 1] else raw;
    if (name.len > 0) {
        var exact: Pick = .{ .sig_algs = sig_algs };
        for (entries) |*e| {
            for (e.server_names) |n| {
                if (std.ascii.eqlIgnoreCase(n, name)) {
                    exact.add(e);
                    break;
                }
            }
        }
        if (exact.best()) |e| return .{ .entry = e, .matched = true };

        if (std.mem.indexOfScalar(u8, name, '.')) |dot| {
            if (dot > 0) {
                const parent = name[dot..]; // ".example.com"
                var wildcard: Pick = .{ .sig_algs = sig_algs };
                for (entries) |*e| {
                    for (e.server_names) |n| {
                        if (n.len > 2 and n[0] == '*' and n[1] == '.' and std.ascii.eqlIgnoreCase(n[1..], parent)) {
                            wildcard.add(e);
                            break;
                        }
                    }
                }
                if (wildcard.best()) |e| return .{ .entry = e, .matched = true };
            }
        }
    }
    var default: Pick = .{ .sig_algs = sig_algs };
    for (entries) |*e| default.add(e);
    return .{ .entry = default.best().?, .matched = false };
}

/// Parses the host_name out of a server_name extension body (RFC 6066 §3).
/// Returns null for a list with no host_name entry.
pub fn parseServerNameExtension(data: []const u8) error{DecodeError}!?[]const u8 {
    if (data.len < 2) return error.DecodeError;
    const list_len: usize = readU16(data); // widened: + 2 overflows u16 at 0xFFFF
    if (list_len + 2 != data.len or list_len == 0) return error.DecodeError;
    var pos: usize = 2;
    var host: ?[]const u8 = null;
    while (pos < data.len) {
        if (pos + 3 > data.len) return error.DecodeError;
        const name_type = data[pos];
        const len = readU16(data[pos + 1 ..]);
        pos += 3;
        if (pos + len > data.len) return error.DecodeError;
        if (name_type == 0) {
            if (host != null or len == 0) return error.DecodeError;
            host = data[pos..][0..len];
        }
        pos += len;
    }
    return host;
}

// ─── TLS Config ──────────────────────────────────────────────────────

/// One TLS 1.3 session's configuration.
///
/// There is no chain to walk and no flag to switch that off: a peer is
/// identified by the key its certificate carries, and the two ways of
/// saying which key that is — a node id (`expect_peer_node_id`) or a
/// fingerprint of the certificate itself (`cert_hashes`) — are fields here,
/// said separately, rather than one switch that stands for both.
pub const TlsConfig = struct {
    cert_chain_der: []const []const u8, // DER-encoded certificates
    private_key_bytes: []const u8, // See ServerCertificate.private_key_bytes
    private_key_algorithm: PrivateKeyAlgorithm = .ecdsa_p256_sha256,
    /// Server only: certificates chosen by the ClientHello's SNI (see
    /// `selectCertificate`). When non-empty, this replaces `cert_chain_der` /
    /// `private_key_bytes` / `private_key_algorithm`, with `certs[0]` as the
    /// default for a client that sends no SNI or an unknown name.
    certs: []const CertEntry = &.{},
    alpn: []const []const u8,
    /// Server only: ask for a client certificate. With `certs`, the
    /// selected entry's `client_auth` applies instead.
    client_auth: ?*const ClientAuth = null,
    /// Client only: presented when the server asks for a certificate;
    /// without one the client answers with an empty Certificate.
    client_certificate: ?ServerCertificate = null,
    server_name: ?[]const u8 = null, // SNI (client only)
    /// The node id the peer's certificate has to carry, compared byte for
    /// byte against the 32 bytes lifted from its `SubjectPublicKeyInfo`.
    /// Null accepts any key, and then the peer has proved possession of
    /// whatever id it presented rather than being the node we wanted.
    expect_peer_node_id: ?[32]u8 = null,
    /// SHA-256 fingerprints of acceptable leaf certificates — the
    /// `serverCertificateHashes` bargain from the W3C WebTransport API, taken
    /// over the raw 44 bytes. When set, the fingerprint stands in for a
    /// chain; no chain is walked either way.
    cert_hashes: ?[]const [32]u8 = null,
    /// Client only: remembered transport parameters for 0-RTT, carried
    /// forward from the connection that was issued the ticket.
    ///
    /// Not the handshake's resumption input — `resumption` is, and it is
    /// the only one, so a ticket and the key that opens it cannot be set
    /// apart on the same config. This field stays because
    /// `connection.zig` reads it for exactly this: the parameters are an
    /// optimisation, and dropping them costs 0-RTT its remembered limits
    /// and nothing else.
    session_ticket: ?*const SessionTicket = null,
    /// Resumption, on either end: a client names the ticket it resumes
    /// with, a server the key it seals and opens tickets under. Null is a
    /// connection that never resumes, and it is one null for both roles.
    resumption: ?Resumption = null,
    cipher_suite_only: ?quic_crypto.CipherSuite = null, // If set, offer ONLY this cipher suite
    quic_version: u32 = protocol.QUIC_V1, // QUIC version (affects HKDF labels)
};

// ─── Handshake state machine ─────────────────────────────────────────

pub const HandshakeError = error{
    UnexpectedMessage,
    DecodeError,
    BadCertificate,
    BadCertificateVerify,
    BadFinished,
    InternalError,
    KeyScheduleError,
    NoKeyShare,
    UnsupportedVersion,
    NoApplicationProtocol,
    MissingExtension,
    /// The client offers no signature scheme our certificate can use.
    HandshakeFailure,
    TransportParameterError,
    /// `ClientAuth.mode` is `.required` and the client sent no certificate.
    CertificateRequired,
    IllegalParameter,
};

pub const Action = union(enum) {
    send_data: SendData,
    install_keys: InstallKeys,
    wait_for_data,
    complete,
    // Internal: signal to continue processing
    _continue,
};

pub const SendData = struct {
    level: EncryptionLevel,
    data: []const u8,
};

pub const InstallKeys = struct {
    level: EncryptionLevel,
    open: quic_crypto.Open,
    seal: quic_crypto.Seal,
};

const HandshakeState = enum {
    // Client states
    client_start,
    client_wait_server_hello,
    client_wait_encrypted_extensions,
    client_wait_certificate,
    client_wait_certificate_verify,
    client_wait_finished,
    client_send_finished,

    // Server states
    server_wait_client_hello,
    server_send_server_hello,
    server_send_encrypted_extensions,
    server_send_certificate_request,
    server_send_certificate,
    server_send_certificate_verify,
    server_send_finished,
    server_wait_client_certificate,
    server_wait_client_certificate_verify,
    server_wait_client_finished,
    server_send_ticket,

    // Shared
    connected,
};

pub const Tls13Handshake = struct {
    state: HandshakeState,
    is_server: bool,
    transcript: TranscriptHash,
    key_schedule: KeySchedule,
    config: TlsConfig,
    local_transport_params: transport_params.TransportParams,
    peer_transport_params: ?transport_params.TransportParams = null,

    // X25519 key pair
    x25519_secret: [32]u8 = undefined,
    x25519_public: [32]u8 = undefined,
    peer_x25519_public: [32]u8 = undefined,

    // P-256 key exchange
    p256_secret: [32]u8 = undefined,
    p256_public: [65]u8 = undefined, // our uncompressed public point
    peer_p256_public: [65]u8 = undefined, // peer's uncompressed public point
    negotiated_group: tls.NamedGroup = .x25519,

    // Outgoing flight, built in place; see limits.tls_handshake_out.
    out_buf: [limits.tls_handshake_out]u8 = undefined,
    out_len: usize = 0,

    // Pending actions returned by step()
    pending_install_handshake: bool = false,
    pending_install_app: bool = false,
    handshake_keys_installed: bool = false,
    app_keys_installed: bool = false,

    // Pre-encoded transport params (avoids dangling slice issues after struct move)
    tp_encoded: [256]u8 = undefined,
    tp_encoded_len: usize = 0,

    // Peer flight being reassembled; see limits.tls_handshake_in.
    in_buf: [limits.tls_handshake_in]u8 = undefined,
    in_len: usize = 0,
    in_offset: usize = 0,

    // Client random for ServerHello matching
    client_random: [32]u8 = undefined,

    // Peer's legacy_session_id from ClientHello (must be echoed in ServerHello)
    peer_session_id: [32]u8 = .{0} ** 32,
    peer_session_id_len: u8 = 0,

    // Server hello random
    server_random: [32]u8 = undefined,

    /// The peer's node id, lifted out of the 32 bytes its certificate's
    /// `SubjectPublicKeyInfo` carries. Null until a Certificate is accepted,
    /// and the only thing a lifted key ever has to be.
    peer_node_id: ?[32]u8 = null,

    // Transcript hash at server Finished for app key derivation
    transcript_at_server_finished: [32]u8 = undefined,

    // Negotiated cipher suite (set during ServerHello processing)
    negotiated_cipher_suite: quic_crypto.CipherSuite = .aes_128_gcm_sha256,

    // PSK / 0-RTT fields
    using_psk: bool = false,

    /// Client: the server asked for a client certificate. Without one to
    /// offer, RFC 8446 4.4.2 says the answer is still a Certificate message
    /// — an empty one — which has to be in the transcript before Finished.
    certificate_requested: bool = false,
    /// Client: how we sign our CertificateVerify; null sends an empty
    /// Certificate.
    client_sig_scheme: ?tls.SignatureScheme = null,

    /// Server: the client-auth policy in force, from the selected
    /// certificate entry or `config.client_auth`.
    client_auth: ?*const ClientAuth = null,
    /// Server: the client's verified leaf certificate (DER), owned by
    /// `allocator`.
    peer_cert: ?[]u8 = null,
    /// Holds `peer_cert`; the connection sets it. Without it a client-auth
    /// handshake fails with internal_error.
    allocator: ?std.mem.Allocator = null,

    /// Server: the ClientHello carried the early_data extension. RFC 8446
    /// 4.2.10 only lets EncryptedExtensions answer an extension the client
    /// offered, so accepting a PSK is not on its own a licence to send it.
    early_data_offered: bool = false,
    /// Server side: which of `config.alpn` the client also offered. A
    /// server advertising several has to echo the one that matched, not
    /// its own first choice.
    selected_alpn: [32]u8 = .{0} ** 32,
    selected_alpn_len: usize = 0,

    /// Server: the certificate we present — the config's single one, or the
    /// `config.certs` entry the ClientHello's SNI selected.
    server_cert: ServerCertificate = undefined,
    /// Server: the CertificateVerify scheme, picked from the ClientHello.
    server_sig_scheme: tls.SignatureScheme = .ecdsa_secp256r1_sha256,

    zero_rtt_accepted: bool = false,
    pending_install_early: bool = false,
    received_ticket: ?SessionTicket = null,
    ticket_nonce_counter: u32 = 0,

    /// The protocol in force: what the server matched, or — on a client,
    /// or before a match — the first one we offered.
    pub fn negotiatedAlpn(self: *const @This()) []const u8 {
        if (self.selected_alpn_len > 0) return self.selected_alpn[0..self.selected_alpn_len];
        return if (self.config.alpn.len > 0) self.config.alpn[0] else "";
    }

    /// Builds the client handshake in place. Tls13Handshake is ~52 KB, and
    /// returning it by value is the single largest contributor to the stack
    /// frame of anything that opens a connection — see quic/limits.zig.
    ///
    /// `random` is the caller's entropy, taken by value and drawn from only
    /// here. A handshake that reached for a global CSPRNG could not be driven
    /// twice with two different generators, and that is the property the pure
    /// core is for (DECISIONS/0002).
    pub fn initClientInto(
        out: *Tls13Handshake,
        config: TlsConfig,
        local_tp: transport_params.TransportParams,
        random: std.Random,
    ) void {
        const self = out;
        self.state = .client_start;
        self.is_server = false;
        self.transcript = TranscriptHash.init();
        self.key_schedule = if (Resumption.clientTicket(config.resumption)) |ticket|
            KeySchedule.initWithPsk(ticket.psk)
        else
            KeySchedule.init();
        self.config = config;
        self.local_transport_params = local_tp;
        self.peer_transport_params = null;
        self.out_len = 0;
        self.in_len = 0;
        self.in_offset = 0;
        self.pending_install_handshake = false;
        self.pending_install_app = false;
        self.pending_install_early = false;
        self.handshake_keys_installed = false;
        self.app_keys_installed = false;
        self.peer_node_id = null;
        self.negotiated_cipher_suite = .aes_128_gcm_sha256;
        self.using_psk = false;
        self.certificate_requested = false;
        self.client_sig_scheme = null;
        self.client_auth = null;
        self.peer_cert = null;
        self.allocator = null;
        self.early_data_offered = false;
        self.selected_alpn_len = 0;
        self.zero_rtt_accepted = false;
        self.received_ticket = null;
        self.ticket_nonce_counter = 0;
        self.peer_session_id_len = 0;
        self.peer_session_id = .{0} ** 32;

        // Pre-encode transport params to avoid dangling slices after struct move.
        // `random` buys exactly one thing here and it is not a secret: the
        // greased parameter's id and its 1-4 value bytes. RFC 9000 §18.1
        // makes that pair a probe — a peer that only ever sees one id learns
        // to tolerate that id — so the caller is entitled to draw it afresh
        // per handshake, and no transport parameter is a key.
        var tp_fbs = io.fixedBufferStream(&self.tp_encoded);
        local_tp.encode(&tp_fbs, random) catch {};
        self.tp_encoded_len = tp_fbs.seek;

        // Generate X25519 key pair
        random.bytes(&self.x25519_secret);
        self.x25519_public = X25519.recoverPublicKey(self.x25519_secret) catch blk: {
            // If key is bad (unlikely), regenerate
            random.bytes(&self.x25519_secret);
            break :blk X25519.recoverPublicKey(self.x25519_secret) catch unreachable;
        };

        // Generate P-256 key pair (offered alongside X25519 in ClientHello)
        random.bytes(&self.p256_secret);
        self.p256_public = (P256.basePoint.mulPublic(self.p256_secret, .big) catch blk: {
            random.bytes(&self.p256_secret);
            break :blk P256.basePoint.mulPublic(self.p256_secret, .big) catch unreachable;
        }).toUncompressedSec1();
        self.negotiated_group = .x25519;
    }

    pub fn initClient(
        config: TlsConfig,
        local_tp: transport_params.TransportParams,
        random: std.Random,
    ) Tls13Handshake {
        var self: Tls13Handshake = undefined;
        initClientInto(&self, config, local_tp, random);
        return self;
    }

    pub fn initServer(
        config: TlsConfig,
        local_tp: transport_params.TransportParams,
        random: std.Random,
    ) Tls13Handshake {
        var self: Tls13Handshake = undefined;
        initServerInto(&self, config, local_tp, random);
        return self;
    }

    /// Builds the server handshake in place — see initClientInto.
    pub fn initServerInto(
        out: *Tls13Handshake,
        config: TlsConfig,
        local_tp: transport_params.TransportParams,
        random: std.Random,
    ) void {
        const self = out;
        self.state = .server_wait_client_hello;
        self.is_server = true;
        self.transcript = TranscriptHash.init();
        self.key_schedule = KeySchedule.init();
        self.config = config;
        self.server_cert = if (config.certs.len > 0) config.certs[0].cert else .{
            .cert_chain_der = config.cert_chain_der,
            .private_key_bytes = config.private_key_bytes,
            .private_key_algorithm = config.private_key_algorithm,
        };
        self.local_transport_params = local_tp;
        self.peer_transport_params = null;
        self.out_len = 0;
        self.in_len = 0;
        self.in_offset = 0;
        self.pending_install_handshake = false;
        self.pending_install_app = false;
        self.pending_install_early = false;
        self.handshake_keys_installed = false;
        self.app_keys_installed = false;
        self.peer_node_id = null;
        self.negotiated_cipher_suite = .aes_128_gcm_sha256;
        self.using_psk = false;
        self.certificate_requested = false;
        self.client_sig_scheme = null;
        self.client_auth = null;
        self.peer_cert = null;
        self.allocator = null;
        self.early_data_offered = false;
        self.selected_alpn_len = 0;
        self.zero_rtt_accepted = false;
        self.received_ticket = null;
        self.ticket_nonce_counter = 0;
        self.peer_session_id_len = 0;
        self.peer_session_id = .{0} ** 32;

        // Pre-encode transport params to avoid dangling slices after struct move.
        // Same grease probe the client encodes, and the same reason it draws:
        // a randomised reserved id keeps a peer's tolerance general. It is a
        // protocol probe, not a secret, and unlike the ECDSA nonce and the PSS
        // salt below, repeating it costs nothing.
        var tp_fbs = io.fixedBufferStream(&self.tp_encoded);
        local_tp.encode(&tp_fbs, random) catch {};
        self.tp_encoded_len = tp_fbs.seek;

        // Generate X25519 key pair
        random.bytes(&self.x25519_secret);
        self.x25519_public = X25519.recoverPublicKey(self.x25519_secret) catch blk: {
            random.bytes(&self.x25519_secret);
            break :blk X25519.recoverPublicKey(self.x25519_secret) catch unreachable;
        };
        self.negotiated_group = .x25519;
    }

    // Provide incoming crypto stream data to the handshake.
    pub fn provideData(self: *Tls13Handshake, data: []const u8) void {
        // Compact buffer if we've consumed some data and need space
        if (self.in_offset > 0 and self.in_len - self.in_offset + data.len > self.in_buf.len - self.in_offset) {
            const remaining = self.in_len - self.in_offset;
            if (remaining > 0) {
                @memmove(self.in_buf[0..remaining], self.in_buf[self.in_offset..self.in_len]);
            }
            self.in_len = remaining;
            self.in_offset = 0;
        }
        const available = self.in_buf.len - self.in_len;
        const copy_len = @min(data.len, available);
        @memcpy(self.in_buf[self.in_len..][0..copy_len], data[0..copy_len]);
        self.in_len += copy_len;
    }

    // Step the handshake state machine. Returns an action for the caller.
    // Call repeatedly until you get wait_for_data or complete.
    //
    // `now_s` is a second on the caller's clock and `random` is the caller's
    // entropy, both passed in per step and never stored: a handshake holding
    // either could not be driven twice with two different clocks.
    //
    // The base of `now_s` is not specified, and the connection supplies a
    // monotonic instant. That is enough. The one value written from it is a
    // session ticket's creation time, and it goes into a ticket this server
    // seals with AES-128-GCM under `ticket_key`, so the peer receives opaque
    // bytes and cannot read the base. The field is not read back on this side
    // either: a resuming server recovers only the PSK from the sealed ticket,
    // and the client stamps its own `creation_time` from its own `now_s` when
    // it parses the ticket. So what the arithmetic needs is just that both
    // sides of every subtraction come off one clock, which they do — the age
    // in `buildClientHello` is the client's resumption instant minus the
    // client's parse instant. A monotonic base that restarts with the process
    // could only mis-age a ticket that outlived the clock that stamped it,
    // and a process cannot outlive its own clock.
    //
    // Nothing else in this file needs a clock at all: every timeout belongs to
    // the connection, not to TLS.
    pub fn step(self: *Tls13Handshake, now_s: i64, random: std.Random) !Action {
        // If we need to install early (0-RTT) keys, do that first
        if (self.pending_install_early) {
            self.pending_install_early = false;
            const cs = self.negotiated_cipher_suite;
            const qv = self.config.quic_version;
            return Action{ .install_keys = .{
                .level = .early_data,
                .open = KeySchedule.makeOpenFull(self.key_schedule.client_early_traffic_secret, cs, qv),
                .seal = KeySchedule.makeSealFull(self.key_schedule.client_early_traffic_secret, cs, qv),
            } };
        }

        // If we need to install handshake keys, do that first
        // Handshake keys use the negotiated cipher suite (only Initial keys use AES-128-GCM)
        if (self.pending_install_handshake) {
            self.pending_install_handshake = false;
            self.handshake_keys_installed = true;
            const cs = self.negotiated_cipher_suite;
            const qv = self.config.quic_version;
            if (self.is_server) {
                return Action{ .install_keys = .{
                    .level = .handshake,
                    .open = KeySchedule.makeOpenFull(self.key_schedule.client_handshake_traffic_secret, cs, qv),
                    .seal = KeySchedule.makeSealFull(self.key_schedule.server_handshake_traffic_secret, cs, qv),
                } };
            } else {
                return Action{ .install_keys = .{
                    .level = .handshake,
                    .open = KeySchedule.makeOpenFull(self.key_schedule.server_handshake_traffic_secret, cs, qv),
                    .seal = KeySchedule.makeSealFull(self.key_schedule.client_handshake_traffic_secret, cs, qv),
                } };
            }
        }

        // If we need to install app keys, use the negotiated cipher suite
        if (self.pending_install_app) {
            self.pending_install_app = false;
            self.app_keys_installed = true;
            const cs = self.negotiated_cipher_suite;
            const qv = self.config.quic_version;
            if (self.is_server) {
                return Action{ .install_keys = .{
                    .level = .application,
                    .open = KeySchedule.makeOpenFull(self.key_schedule.client_app_traffic_secret, cs, qv),
                    .seal = KeySchedule.makeSealFull(self.key_schedule.server_app_traffic_secret, cs, qv),
                } };
            } else {
                return Action{ .install_keys = .{
                    .level = .application,
                    .open = KeySchedule.makeOpenFull(self.key_schedule.server_app_traffic_secret, cs, qv),
                    .seal = KeySchedule.makeSealFull(self.key_schedule.client_app_traffic_secret, cs, qv),
                } };
            }
        }

        switch (self.state) {
            .client_start => return self.clientBuildHello(now_s, random),
            .client_wait_server_hello => return self.clientProcessServerHello(),
            .client_wait_encrypted_extensions => return self.clientProcessEncryptedExtensions(),
            // A PSK skips the server's Certificate and CertificateVerify and
            // nothing else — see `ClientAuth` for why a policy in force does
            // not stop the CertificateRequest. Skipping this state on
            // `using_psk` left the server waiting for a Certificate the
            // client had been told, by that skip, never to send.
            .client_wait_certificate => return self.clientProcessCertificate(),
            .client_wait_certificate_verify => return self.clientProcessCertificateVerify(),
            .client_wait_finished => return self.clientProcessFinished(),
            .client_send_finished => return self.clientSendFinished(random),

            .server_wait_client_hello => return self.serverProcessClientHello(random),
            .server_send_server_hello => return self.serverBuildServerHello(random),
            .server_send_encrypted_extensions => return self.serverBuildEncryptedExtensions(),
            .server_send_certificate_request => return self.serverBuildCertificateRequest(),
            .server_send_certificate => return self.serverBuildCertificate(),
            .server_send_certificate_verify => return self.serverBuildCertificateVerify(random),
            .server_send_finished => return self.serverBuildFinished(),
            .server_wait_client_certificate => return self.serverProcessClientCertificate(),
            .server_wait_client_certificate_verify => return self.serverProcessClientCertificateVerify(),
            .server_wait_client_finished => return self.serverProcessClientFinished(),
            .server_send_ticket => return self.serverSendTicket(now_s, random),

            .connected => {
                // Check for post-handshake messages
                if (self.readHandshakeMsg()) |msg| {
                    // RFC 9001 §6: KeyUpdate (24) MUST NOT be used in QUIC
                    if (msg[0] == 24) return error.UnexpectedMessage;
                    // RFC 9001 §8.3: EndOfEarlyData (5) MUST NOT be sent in QUIC
                    if (msg[0] == 5) return error.UnexpectedMessage;
                    if (!self.is_server and msg[0] == @intFromEnum(tls.HandshakeType.new_session_ticket)) {
                        self.parseNewSessionTicket(msg, now_s);
                        return ._continue;
                    }
                }
                return .complete;
            },
        }
    }

    pub fn isComplete(self: *const Tls13Handshake) bool {
        return self.state == .connected;
    }

    /// Frees what the handshake allocated. The struct itself is the caller's.
    pub fn deinit(self: *Tls13Handshake) void {
        if (self.peer_cert) |c| if (self.allocator) |a| a.free(c);
        self.peer_cert = null;
    }

    /// Server: the client's certificate — the 44-byte `SubjectPublicKeyInfo`
    /// its node id is wrapped in — once the handshake completes. Null when
    /// none was asked for, or `.optional` and none was sent.
    pub fn peerCertificate(self: *const Tls13Handshake) ?[]const u8 {
        if (self.state != .connected) return null;
        return self.peer_cert;
    }

    /// The node id the peer's certificate carried, or null before one was
    /// accepted. Compared against `expect_peer_node_id` when that is set;
    /// with no pin, this is a claim the peer proved it holds.
    pub fn peerNodeId(self: *const Tls13Handshake) ?[32]u8 {
        if (self.state != .connected) return null;
        return self.peer_node_id;
    }

    // ─── Client states ───────────────────────────────────────────────

    fn clientBuildHello(self: *Tls13Handshake, now_s: i64, random: std.Random) !Action {
        random.bytes(&self.client_random);

        var buf: [4096]u8 = undefined;
        const msg = buildClientHello(
            &buf,
            &self.client_random,
            &self.x25519_public,
            &self.p256_public,
            self.config.alpn,
            self.config.server_name,
            self.tp_encoded[0..self.tp_encoded_len],
            Resumption.clientTicket(self.config.resumption),
            &self.key_schedule,
            self.config.cipher_suite_only,
            now_s,
        ) catch return error.InternalError;

        self.transcript.update(msg);

        // If we have a session ticket, derive early data secret for 0-RTT
        if (Resumption.clientTicket(self.config.resumption) != null) {
            const transcript_hash = self.transcript.current();
            self.key_schedule.deriveEarlyDataSecret(transcript_hash);
            self.pending_install_early = true;

        }

        @memcpy(self.out_buf[0..msg.len], msg);
        self.out_len = msg.len;

        self.state = .client_wait_server_hello;
        return Action{ .send_data = .{
            .level = .initial,
            .data = self.out_buf[0..self.out_len],
        } };
    }

    fn clientProcessServerHello(self: *Tls13Handshake) !Action {
        const msg = self.readHandshakeMsg() orelse return .wait_for_data;

        if (msg[0] != @intFromEnum(tls.HandshakeType.server_hello)) return error.UnexpectedMessage;

        // Parse ServerHello
        const body = msg[4..]; // skip type + 3-byte length
        if (body.len < 2 + 32 + 1) return error.DecodeError;

        // legacy_version(2) + random(32) + session_id_len(1) + session_id + cipher_suite(2) + compression(1) + extensions
        var pos: usize = 0;
        pos += 2; // legacy_version = 0x0303
        @memcpy(&self.server_random, body[pos..][0..32]);
        pos += 32;

        const session_id_len = body[pos];
        pos += 1;
        pos += session_id_len; // skip session_id echo

        if (pos + 3 > body.len) return error.DecodeError;
        const cipher_suite_raw = readU16(body[pos..]);
        pos += 2;
        if (cipher_suite_raw == @intFromEnum(tls.CipherSuite.AES_128_GCM_SHA256)) {
            self.negotiated_cipher_suite = .aes_128_gcm_sha256;
        } else if (cipher_suite_raw == @intFromEnum(tls.CipherSuite.CHACHA20_POLY1305_SHA256)) {
            self.negotiated_cipher_suite = .chacha20_poly1305_sha256;
        } else {
            return error.UnsupportedVersion;
        }

        pos += 1; // compression_method = 0

        // Parse extensions
        if (pos + 2 > body.len) return error.DecodeError;
        const ext_len = readU16(body[pos..]);
        pos += 2;

        var found_key_share = false;
        var ext_pos: usize = 0;
        const ext_data = body[pos..][0..ext_len];
        while (ext_pos + 4 <= ext_data.len) {
            const etype = readU16(ext_data[ext_pos..]);
            ext_pos += 2;
            const elen = readU16(ext_data[ext_pos..]);
            ext_pos += 2;

            if (etype == @intFromEnum(tls.ExtensionType.key_share)) {
                // key_share: named_group(2) + key_exchange_length(2) + key_exchange(...)
                if (elen < 4) return error.DecodeError;
                const group = readU16(ext_data[ext_pos..]);
                const kelen = readU16(ext_data[ext_pos + 2 ..]);
                if (group == @intFromEnum(tls.NamedGroup.x25519) and kelen == 32 and ext_pos + 4 + 32 <= ext_data.len) {
                    @memcpy(&self.peer_x25519_public, ext_data[ext_pos + 4 ..][0..32]);
                    self.negotiated_group = .x25519;
                    found_key_share = true;
                } else if (group == @intFromEnum(tls.NamedGroup.secp256r1) and kelen == 65 and ext_pos + 4 + 65 <= ext_data.len) {
                    @memcpy(&self.peer_p256_public, ext_data[ext_pos + 4 ..][0..65]);
                    self.negotiated_group = .secp256r1;
                    found_key_share = true;
                } else {
                    return error.NoKeyShare;
                }
            } else if (etype == @intFromEnum(tls.ExtensionType.pre_shared_key)) {
                // Server accepted PSK: selected_identity(2) = 0x0000
                if (elen >= 2) {
                    const selected = readU16(ext_data[ext_pos..]);
                    if (selected == 0) {
                        self.using_psk = true;
                    }
                }
            }
            ext_pos += elen;
        }

        if (!found_key_share) return error.NoKeyShare;

        // Update transcript with ServerHello
        self.transcript.update(msg);

        // Compute shared secret based on negotiated group
        var shared_secret: [32]u8 = undefined;
        if (self.negotiated_group == .secp256r1) {
            const peer_point = P256.fromSec1(self.peer_p256_public[0..65]) catch return error.KeyScheduleError;
            const shared_point = peer_point.mulPublic(self.p256_secret, .big) catch return error.KeyScheduleError;
            const shared_uncompressed = shared_point.toUncompressedSec1();
            @memcpy(&shared_secret, shared_uncompressed[1..33]);
        } else {
            shared_secret = X25519.scalarmult(self.x25519_secret, self.peer_x25519_public) catch return error.KeyScheduleError;
        }

        // Derive handshake secrets
        const transcript_hash = self.transcript.current();
        self.key_schedule.deriveHandshakeSecrets(&shared_secret, transcript_hash);

        // Signal to install handshake keys
        self.pending_install_handshake = true;
        self.state = .client_wait_encrypted_extensions;
        return ._continue;
    }

    fn clientProcessEncryptedExtensions(self: *Tls13Handshake) !Action {
        const msg = self.readHandshakeMsg() orelse return .wait_for_data;

        if (msg[0] != @intFromEnum(tls.HandshakeType.encrypted_extensions)) return error.UnexpectedMessage;

        // Parse EncryptedExtensions to extract transport params + ALPN + early_data
        self.parseEncryptedExtensions(msg[4..]) catch |e| switch (e) {
            error.TransportParameterError => {}, // reported as missing below
            else => return e,
        };

        // RFC 9001 §8.2: quic_transport_parameters extension MUST be present
        if (self.peer_transport_params == null) {
            return error.MissingExtension;
        }

        self.transcript.update(msg);
        self.state = .client_wait_certificate;
        return ._continue;
    }

    fn clientProcessCertificate(self: *Tls13Handshake) !Action {
        // A resumed handshake has no server certificate to process, so what
        // follows EncryptedExtensions on one is a CertificateRequest or the
        // server's Finished. The Finished is answered by
        // `clientProcessFinished`, which reads it itself, so it is looked at
        // rather than taken here.
        if (self.using_psk) {
            const next = self.peekHandshakeMsg() orelse return .wait_for_data;
            if (next[0] == @intFromEnum(tls.HandshakeType.finished)) {
                self.state = .client_wait_finished;
                return ._continue;
            }
        }

        const msg = self.readHandshakeMsg() orelse return .wait_for_data;

        // RFC 8446 4.3.2: a server that wants a client certificate asks here,
        // between EncryptedExtensions and its own Certificate. Cloudflare's
        // edge does — `cdn.moq.dev` failed at this message — and refusing it
        // ends the handshake over a request we are allowed to decline.
        if (msg[0] == @intFromEnum(tls.HandshakeType.certificate_request)) {
            if (self.certificate_requested) return error.UnexpectedMessage;
            const offered = parseCertificateRequest(msg[4..]) catch |err| return switch (err) {
                error.MissingExtension => error.MissingExtension,
                error.IllegalParameter => error.IllegalParameter,
                error.DecodeError => error.DecodeError,
            };
            self.certificate_requested = true;
            if (self.config.client_certificate) |c| self.client_sig_scheme = signatureSchemeFor(c.private_key_algorithm, offered);
            self.transcript.update(msg);
            return ._continue;
        }

        if (msg[0] != @intFromEnum(tls.HandshakeType.certificate)) return error.UnexpectedMessage;

        const body = msg[4..];
        if (body.len < 4) return error.DecodeError;

        // Parse Certificate message body (RFC 8446 §4.4.2)
        const context_len = body[0];
        var pos: usize = 1 + context_len;
        if (pos + 3 > body.len) return error.DecodeError;

        const cert_list_len = (@as(usize, body[pos]) << 16) | (@as(usize, body[pos + 1]) << 8) | @as(usize, body[pos + 2]);
        pos += 3;

        if (pos + cert_list_len > body.len) return error.DecodeError;

        const cert_list_end = pos + cert_list_len;
        var cert_index: usize = 0;

        while (pos < cert_list_end) {
            if (pos + 3 > cert_list_end) return error.DecodeError;
            const cert_data_len = (@as(usize, body[pos]) << 16) | (@as(usize, body[pos + 1]) << 8) | @as(usize, body[pos + 2]);
            pos += 3;

            if (pos + cert_data_len > cert_list_end) return error.DecodeError;
            const cert_der = body[pos..][0..cert_data_len];
            pos += cert_data_len;

            // Skip per-certificate extensions
            if (pos + 2 > cert_list_end) return error.DecodeError;
            const ext_len = (@as(usize, body[pos]) << 8) | @as(usize, body[pos + 1]);
            pos += 2 + ext_len;

            // The identity model: the peer's certificate is a 44-byte DER
            // `SubjectPublicKeyInfo` around the 32 bytes of its Ed25519 key,
            // and those bytes are the node id. There is no chain to walk, no
            // host name to match and no validity date to read, so the leaf is
            // the whole of it and the rest of the list is framing to skip.
            if (cert_index == 0) {
                const key = liftEd25519Spki(cert_der) catch return error.BadCertificate;
                if (self.config.expect_peer_node_id) |expected| {
                    if (!crypto.timing_safe.eql([32]u8, key, expected)) return error.BadCertificate;
                }
                if (self.config.cert_hashes) |hashes| {
                    var digest: [32]u8 = undefined;
                    Sha256.hash(cert_der, &digest, .{});
                    var matched = false;
                    for (hashes) |h| {
                        if (crypto.timing_safe.eql([32]u8, h, digest)) matched = true;
                    }
                    if (!matched) return error.BadCertificate;
                }
                self.peer_node_id = key;
            }

            cert_index += 1;
        }

        self.transcript.update(msg);
        self.state = .client_wait_certificate_verify;
        return ._continue;
    }

    fn clientProcessCertificateVerify(self: *Tls13Handshake) !Action {
        const msg = self.readHandshakeMsg() orelse return .wait_for_data;

        if (msg[0] != @intFromEnum(tls.HandshakeType.certificate_verify)) return error.UnexpectedMessage;

        if (self.peer_node_id) |peer_key| {
            // Get transcript hash BEFORE updating with CertificateVerify
            const transcript_hash = self.transcript.current();

            const body = msg[4..];
            if (body.len < 4) return error.DecodeError;

            const sig_algo = (@as(u16, body[0]) << 8) | @as(u16, body[1]);
            const sig_len = (@as(usize, body[2]) << 8) | @as(usize, body[3]);
            if (body.len < 4 + sig_len) return error.DecodeError;
            const sig_bytes = body[4..][0..sig_len];

            // Build signed content: 64 spaces + label + 0x00 + transcript_hash
            const label = "TLS 1.3, server CertificateVerify";
            var signed_content: [64 + label.len + 1 + 32]u8 = undefined;
            @memset(signed_content[0..64], 0x20);
            @memcpy(signed_content[64..][0..label.len], label);
            signed_content[64 + label.len] = 0x00;
            @memcpy(signed_content[64 + label.len + 1 ..][0..32], &transcript_hash);

            verifyCertificateVerifySignature(
                &peer_key,
                lifted_key_algo,
                sig_algo,
                sig_bytes,
                &signed_content,
            ) catch return error.BadCertificateVerify;
        }

        self.transcript.update(msg);
        self.state = .client_wait_finished;
        return ._continue;
    }

    fn clientProcessFinished(self: *Tls13Handshake) !Action {
        const msg = self.readHandshakeMsg() orelse return .wait_for_data;

        if (msg[0] != @intFromEnum(tls.HandshakeType.finished)) return error.UnexpectedMessage;

        const body = msg[4..];
        if (body.len != 32) return error.BadFinished;

        // Verify server Finished
        const transcript_hash = self.transcript.current();
        const expected = KeySchedule.computeFinishedVerifyData(
            self.key_schedule.server_handshake_traffic_secret,
            transcript_hash,
        );

        // Constant-time MAC compare (RFC 8446 §4.4.4). Length is public
        // (fixed by the cipher suite hash), the verify_data is secret.
        if (body.len != expected.len or
            !crypto.timing_safe.eql([expected.len]u8, body[0..expected.len].*, expected)) return error.BadFinished;

        // Update transcript with server Finished
        self.transcript.update(msg);

        // Save transcript hash for app key derivation
        self.transcript_at_server_finished = self.transcript.current();

        // Derive application secrets
        self.key_schedule.deriveAppSecrets(self.transcript_at_server_finished);
        self.pending_install_app = true;

        self.state = .client_send_finished;
        return ._continue;
    }

    fn clientSendFinished(self: *Tls13Handshake, random: std.Random) !Action {
        var pos: usize = 0;

        // RFC 8446 4.4.2: having been asked, the client answers with its
        // certificate, or even with nothing to offer — an empty
        // certificate_list, and no CertificateVerify to go with it. The
        // context is zero length: 4.3.2 only allows a non-empty one for
        // post-handshake auth, which RFC 9001 4.4 forbids over QUIC anyway.
        if (!self.certificate_requested) {} else if (self.client_sig_scheme) |scheme| {
            const cert = self.config.client_certificate.?;
            const cert_msg = buildCertificate(self.out_buf[pos..], cert.cert_chain_der) catch return error.InternalError;
            self.transcript.update(cert_msg);
            pos += cert_msg.len;
            if (self.out_buf.len - pos < 8 + rsa.max_signature_len + 36) return error.InternalError;
            const cv = buildCertificateVerify(
                self.out_buf[pos..],
                self.transcript.current(),
                cert.private_key_bytes,
                scheme,
                false, // is_server
                random,
            ) catch return error.InternalError;
            self.transcript.update(cv);
            pos += cv.len;
        } else {
            const empty_cert = [_]u8{
                @intFromEnum(tls.HandshakeType.certificate),
                0, 0, 4, // length
                0, // certificate_request_context length
                0, 0, 0, // certificate_list length
            };
            self.transcript.update(&empty_cert);
            @memcpy(self.out_buf[pos..][0..empty_cert.len], &empty_cert);
            pos += empty_cert.len;
        }

        // Compute client Finished
        const transcript_hash = self.transcript.current();
        const verify_data = KeySchedule.computeFinishedVerifyData(
            self.key_schedule.client_handshake_traffic_secret,
            transcript_hash,
        );

        // Build Finished message: type(1) + length(3) + verify_data(32)
        var msg: [36]u8 = undefined;
        msg[0] = @intFromEnum(tls.HandshakeType.finished);
        msg[1] = 0;
        msg[2] = 0;
        msg[3] = 32;
        @memcpy(msg[4..][0..32], &verify_data);

        self.transcript.update(&msg);

        @memcpy(self.out_buf[pos..][0..36], &msg);
        self.out_len = pos + 36;

        self.state = .connected;
        return Action{ .send_data = .{
            .level = .handshake,
            .data = self.out_buf[0..self.out_len],
        } };
    }

    // ─── Server states ───────────────────────────────────────────────

    fn serverProcessClientHello(self: *Tls13Handshake, random: std.Random) !Action {
        const msg = self.readHandshakeMsg() orelse return .wait_for_data;

        if (msg[0] != @intFromEnum(tls.HandshakeType.client_hello)) return error.UnexpectedMessage;

        const body = msg[4..];
        if (body.len < 2 + 32 + 1) return error.DecodeError;

        var pos: usize = 0;
        pos += 2; // legacy_version
        @memcpy(&self.client_random, body[pos..][0..32]);
        pos += 32;

        const session_id_len = body[pos];
        pos += 1;
        // Save peer's legacy_session_id for ServerHello echo (RFC 8446 §4.1.3)
        if (session_id_len > 0 and session_id_len <= 32) {
            self.peer_session_id_len = session_id_len;
            @memcpy(self.peer_session_id[0..session_id_len], body[pos..][0..session_id_len]);
            std.log.info("ClientHello: legacy_session_id len={d}", .{session_id_len});
        }
        pos += session_id_len; // skip session_id

        // Cipher suites — select the best one we support
        if (pos + 2 > body.len) return error.DecodeError;
        const cs_len = readU16(body[pos..]);
        pos += 2;
        {
            var cs_found = false;
            var cs_pos: usize = 0;
            while (cs_pos + 2 <= cs_len) : (cs_pos += 2) {
                const cs_id = readU16(body[pos + cs_pos ..]);
                // If cipher_suite_only is set, only accept that cipher
                if (self.config.cipher_suite_only) |required| {
                    if (cs_id == @intFromEnum(required)) {
                        self.negotiated_cipher_suite = required;
                        cs_found = true;
                        break;
                    }
                } else {
                    if (cs_id == @intFromEnum(tls.CipherSuite.AES_128_GCM_SHA256) and !cs_found) {
                        self.negotiated_cipher_suite = .aes_128_gcm_sha256;
                        cs_found = true;
                    } else if (cs_id == @intFromEnum(tls.CipherSuite.CHACHA20_POLY1305_SHA256) and !cs_found) {
                        self.negotiated_cipher_suite = .chacha20_poly1305_sha256;
                        cs_found = true;
                    }
                }
            }
            if (!cs_found) return error.UnsupportedVersion;
        }
        pos += cs_len;

        // Compression methods
        if (pos >= body.len) return error.DecodeError;
        const cm_len = body[pos];
        pos += 1;
        pos += cm_len;

        // Extensions
        if (pos + 2 > body.len) return error.DecodeError;
        const ext_len = readU16(body[pos..]);
        pos += 2;

        var found_key_share = false;
        var sni: ?[]const u8 = null;
        var sig_algs: ?[]const u8 = null;
        var psk_ext_offset: ?usize = null; // offset into ext_data where PSK extension starts
        var psk_ext_len: usize = 0;
        var ext_pos: usize = 0;
        const ext_data = body[pos..][0..@min(ext_len, body.len - pos)];
        while (ext_pos + 4 <= ext_data.len) {
            const etype = readU16(ext_data[ext_pos..]);
            ext_pos += 2;
            const elen = readU16(ext_data[ext_pos..]);
            ext_pos += 2;

            if (ext_pos + elen > ext_data.len) break;

            if (etype == @intFromEnum(tls.ExtensionType.key_share)) {
                // client_shares_len(2) + [named_group(2) + key_len(2) + key(...)]
                // Prefer X25519, fall back to secp256r1 (P-256)
                if (elen >= 2) {
                    var found_p256 = false;
                    var share_pos: usize = 2; // skip client_shares_len
                    while (share_pos + 4 <= elen) {
                        const group = readU16(ext_data[ext_pos + share_pos ..]);
                        const kelen = readU16(ext_data[ext_pos + share_pos + 2 ..]);
                        share_pos += 4;
                        if (group == @intFromEnum(tls.NamedGroup.x25519) and kelen == 32 and share_pos + 32 <= elen) {
                            @memcpy(&self.peer_x25519_public, ext_data[ext_pos + share_pos ..][0..32]);
                            self.negotiated_group = .x25519;
                            found_key_share = true;
                            break;
                        } else if (group == @intFromEnum(tls.NamedGroup.secp256r1) and kelen == 65 and share_pos + 65 <= elen) {
                            @memcpy(&self.peer_p256_public, ext_data[ext_pos + share_pos ..][0..65]);
                            found_p256 = true;
                        }
                        share_pos += kelen;
                    }
                    // Use P-256 if X25519 not found
                    if (!found_key_share and found_p256) {
                        self.negotiated_group = .secp256r1;
                        found_key_share = true;
                    }
                }
            } else if (etype == @intFromEnum(tls.ExtensionType.quic_transport_parameters)) {
                const tp_data = ext_data[ext_pos..][0..elen];
                self.peer_transport_params = transport_params.TransportParams.decode(tp_data) catch {
                    return error.TransportParameterError;
                };
            } else if (etype == @intFromEnum(tls.ExtensionType.application_layer_protocol_negotiation)) {
                // Parse client's ALPN list and try to match with our configured ALPNs
                if (elen >= 2) {
                    const list_len = readU16(ext_data[ext_pos..]);
                    var alpn_pos: usize = 2;
                    var matched = false;
                    while (alpn_pos < 2 + list_len and alpn_pos + 1 <= elen) {
                        const proto_len = ext_data[ext_pos + alpn_pos];
                        alpn_pos += 1;
                        if (alpn_pos + proto_len > elen) break;
                        const proto = ext_data[ext_pos + alpn_pos ..][0..proto_len];
                        for (self.config.alpn) |our_proto| {
                            if (std.mem.eql(u8, proto, our_proto)) {
                                matched = true;
                                const n = @min(proto.len, self.selected_alpn.len);
                                @memcpy(self.selected_alpn[0..n], proto[0..n]);
                                self.selected_alpn_len = n;
                                break;
                            }
                        }
                        if (matched) break;
                        alpn_pos += proto_len;
                    }
                    if (!matched and self.config.alpn.len > 0) {
                        return error.NoApplicationProtocol;
                    }
                }
            } else if (etype == @intFromEnum(tls.ExtensionType.pre_shared_key)) {
                // PSK extension must be the last one (RFC 8446 §4.2.11)
                psk_ext_offset = ext_pos;
                psk_ext_len = elen;
            } else if (etype == @intFromEnum(tls.ExtensionType.early_data)) {
                self.early_data_offered = true;
            } else if (etype == @intFromEnum(tls.ExtensionType.server_name)) {
                sni = parseServerNameExtension(ext_data[ext_pos..][0..elen]) catch return error.DecodeError;
            } else if (etype == @intFromEnum(tls.ExtensionType.signature_algorithms)) {
                if (elen < 2 or @as(usize, readU16(ext_data[ext_pos..])) + 2 != elen or elen % 2 != 0) return error.DecodeError;
                sig_algs = ext_data[ext_pos + 2 ..][0 .. elen - 2];
            }
            ext_pos += elen;
        }

        if (!found_key_share) return error.NoKeyShare;
        self.client_auth = self.config.client_auth;
        if (self.config.certs.len > 0) {
            const entry = selectCertificateFor(self.config.certs, sni, sig_algs).?.entry;
            self.server_cert = entry.cert;
            self.client_auth = entry.client_auth;
        }
        if (self.client_auth != null and self.allocator == null) return error.InternalError;

        // RFC 9001 §8.2: quic_transport_parameters extension MUST be present
        if (self.peer_transport_params == null) {
            return error.MissingExtension;
        }

        // Try to process PSK extension if present and we have a ticket key.
        // A policy in force does not refuse the PSK: resumption and a client
        // certificate are not alternatives, and skipping the CertificateRequest
        // is what left a resumed connection reaching the end with a pin in
        // force and nothing to compare against it (DECISIONS/0001 item 4).
        if (psk_ext_offset != null and self.serverTicketKey() != null) {
            std.log.info("PSK extension found, attempting PSK processing", .{});
            self.tryProcessPsk(msg, body, pos, ext_data, psk_ext_offset.?, psk_ext_len);
            if (self.using_psk) {
                std.log.info("PSK accepted, using resumption", .{});
            } else {
                std.log.info("PSK rejected, full handshake", .{});
            }
        }

        if (!self.using_psk) {
            // RFC 8446 §4.2.3: certificate authentication needs a scheme the client offered.
            const offered = sig_algs orelse return error.MissingExtension;
            self.server_sig_scheme = signatureSchemeFor(self.server_cert.private_key_algorithm, offered) orelse
                return error.HandshakeFailure;
        }

        // Update transcript with ClientHello
        self.transcript.update(msg);
        std.log.info("transcript after CH: {x}", .{self.transcript.current()});

        // If PSK accepted, derive early data secret for 0-RTT decryption
        if (self.using_psk) {
            const transcript_hash = self.transcript.current();
            self.key_schedule.deriveEarlyDataSecret(transcript_hash);
            self.pending_install_early = true;

        }

        // RFC 9368: Compatible Version Negotiation
        // If client sent version_information advertising v2 and we support v2, switch.
        if (self.peer_transport_params) |peer_tp| {
            if (peer_tp.version_info_chosen != null and self.local_transport_params.version_info_chosen != null) {
                // Check if client supports v2 and we do too
                if (peer_tp.hasAvailableVersion(protocol.QUIC_V2) and
                    self.local_transport_params.hasAvailableVersion(protocol.QUIC_V2))
                {
                    std.log.info("compatible version negotiation: switching to QUIC v2", .{});
                    self.config.quic_version = protocol.QUIC_V2;
                    // Update our version_information to reflect the chosen version
                    self.local_transport_params.version_info_chosen = protocol.QUIC_V2;
                    // Re-encode transport params so EncryptedExtensions carries
                    // the updated chosen_version. The draw is the greased
                    // parameter again, and it is a fresh draw rather than the
                    // bytes the first encode settled on: this is a second
                    // probe of the same peer, and a peer must not learn an id
                    // by being handed one twice.
                    var tp_fbs = io.fixedBufferStream(&self.tp_encoded);
                    self.local_transport_params.encode(&tp_fbs, random) catch {};
                    self.tp_encoded_len = tp_fbs.seek;
                }
            }
        }

        self.state = .server_send_server_hello;
        return ._continue;
    }

    fn serverBuildServerHello(self: *Tls13Handshake, random: std.Random) !Action {
        random.bytes(&self.server_random);

        // Prepare key share based on negotiated group
        var ks_data_buf: [65]u8 = undefined;
        const ks_data: []const u8 = if (self.negotiated_group == .secp256r1) blk: {
            // Generate P-256 ephemeral key pair
            random.bytes(&self.p256_secret);
            self.p256_public = (P256.basePoint.mulPublic(self.p256_secret, .big) catch return error.KeyScheduleError).toUncompressedSec1();
            @memcpy(&ks_data_buf, &self.p256_public);
            break :blk ks_data_buf[0..65];
        } else blk: {
            @memcpy(ks_data_buf[0..32], &self.x25519_public);
            break :blk ks_data_buf[0..32];
        };

        var buf: [512]u8 = undefined;
        const msg = buildServerHello(
            &buf,
            &self.server_random,
            self.negotiated_group,
            ks_data,
            self.peer_session_id[0..self.peer_session_id_len],
            self.using_psk,
            self.negotiated_cipher_suite,
        ) catch return error.InternalError;

        self.transcript.update(msg);
        std.log.info("server transcript after SH ({d} bytes): {x}", .{ msg.len, self.transcript.current() });

        // Compute shared secret based on negotiated group
        var shared_secret: [32]u8 = undefined;
        if (self.negotiated_group == .secp256r1) {
            // P-256 ECDH: multiply peer's public key by our secret
            const peer_point = P256.fromSec1(self.peer_p256_public[0..65]) catch return error.KeyScheduleError;
            const shared_point = peer_point.mulPublic(self.p256_secret, .big) catch return error.KeyScheduleError;
            // Extract X coordinate (bytes 1..33 of uncompressed point)
            const shared_uncompressed = shared_point.toUncompressedSec1();
            @memcpy(&shared_secret, shared_uncompressed[1..33]);
        } else {
            shared_secret = X25519.scalarmult(self.x25519_secret, self.peer_x25519_public) catch return error.KeyScheduleError;
        }

        // Derive handshake secrets
        const transcript_hash = self.transcript.current();
        self.key_schedule.deriveHandshakeSecrets(&shared_secret, transcript_hash);

        @memcpy(self.out_buf[0..msg.len], msg);
        self.out_len = msg.len;

        // Signal to install handshake keys, then send EE at handshake level
        self.pending_install_handshake = true;
        self.state = .server_send_encrypted_extensions;
        return Action{ .send_data = .{
            .level = .initial,
            .data = self.out_buf[0..self.out_len],
        } };
    }

    fn serverBuildEncryptedExtensions(self: *Tls13Handshake) !Action {
        var buf: [1024]u8 = undefined;
        // RFC 7301 §3.1: exactly the one protocol selected, never our list.
        const selected = [_][]const u8{self.selected_alpn[0..self.selected_alpn_len]};
        const msg = buildEncryptedExtensionsFromEncoded(
            &buf,
            if (self.selected_alpn_len > 0) &selected else &.{},
            self.tp_encoded[0..self.tp_encoded_len],
            self.zero_rtt_accepted, // early_data only answers a client that asked
        ) catch return error.InternalError;

        self.transcript.update(msg);
        {
            var ee_sha: [32]u8 = undefined;
            crypto.hash.sha2.Sha256.hash(msg, &ee_sha, .{});
            std.log.info("transcript after EE ({d} bytes): {x}, msg_sha256={x}", .{ msg.len, self.transcript.current(), ee_sha });
        }

        @memcpy(self.out_buf[0..msg.len], msg);
        self.out_len = msg.len;

        // What the next message is, decided once. A CertificateRequest is
        // asked for whenever a policy is in force, PSK or not; only this
        // server's own Certificate is what a PSK removes.
        self.state = if (self.client_auth != null)
            .server_send_certificate_request
        else if (self.using_psk)
            .server_send_finished
        else
            .server_send_certificate;
        return Action{ .send_data = .{
            .level = .handshake,
            .data = self.out_buf[0..self.out_len],
        } };
    }

    fn serverBuildCertificateRequest(self: *Tls13Handshake) !Action {
        const msg = buildCertificateRequest(&self.out_buf) catch return error.InternalError;
        self.out_len = msg.len;
        self.transcript.update(msg);
        // The PSK removed this server's Certificate, not the request that
        // asks the client for one. The two used to disagree here and at the
        // state above, and either disagreement was the bypass.
        self.state = if (self.using_psk) .server_send_finished else .server_send_certificate;
        return Action{ .send_data = .{
            .level = .handshake,
            .data = self.out_buf[0..self.out_len],
        } };
    }

    fn serverBuildCertificate(self: *Tls13Handshake) !Action {
        // Built straight into out_buf: a local of the same size would be a
        // 32 KB stack duplicate of a field we already own.
        const msg = buildCertificate(&self.out_buf, self.server_cert.cert_chain_der) catch return error.InternalError;
        self.out_len = msg.len;

        self.transcript.update(msg);
        {
            var cert_sha: [32]u8 = undefined;
            crypto.hash.sha2.Sha256.hash(msg, &cert_sha, .{});
            std.log.info("transcript after Cert ({d} bytes): {x}, msg_sha256={x}", .{ msg.len, self.transcript.current(), cert_sha });
        }

        self.state = .server_send_certificate_verify;
        return Action{ .send_data = .{
            .level = .handshake,
            .data = self.out_buf[0..self.out_len],
        } };
    }

    fn serverBuildCertificateVerify(self: *Tls13Handshake, random: std.Random) !Action {
        const transcript_hash = self.transcript.current();

        var buf: [8 + rsa.max_signature_len]u8 = undefined;
        const msg = buildCertificateVerify(
            &buf,
            transcript_hash,
            self.server_cert.private_key_bytes,
            self.server_sig_scheme,
            true, // is_server
            random,
        ) catch return error.InternalError;

        self.transcript.update(msg);

        @memcpy(self.out_buf[0..msg.len], msg);
        self.out_len = msg.len;

        self.state = .server_send_finished;
        return Action{ .send_data = .{
            .level = .handshake,
            .data = self.out_buf[0..self.out_len],
        } };
    }

    fn serverBuildFinished(self: *Tls13Handshake) !Action {
        const transcript_hash = self.transcript.current();
        const verify_data = KeySchedule.computeFinishedVerifyData(
            self.key_schedule.server_handshake_traffic_secret,
            transcript_hash,
        );

        var msg: [36]u8 = undefined;
        msg[0] = @intFromEnum(tls.HandshakeType.finished);
        msg[1] = 0;
        msg[2] = 0;
        msg[3] = 32;
        @memcpy(msg[4..][0..32], &verify_data);

        self.transcript.update(&msg);

        // Save transcript for app keys
        self.transcript_at_server_finished = self.transcript.current();
        self.key_schedule.deriveAppSecrets(self.transcript_at_server_finished);
        self.pending_install_app = true;

        @memcpy(self.out_buf[0..36], &msg);
        self.out_len = 36;

        self.state = if (self.client_auth != null) .server_wait_client_certificate else .server_wait_client_finished;
        return Action{ .send_data = .{
            .level = .handshake,
            .data = self.out_buf[0..self.out_len],
        } };
    }

    fn serverProcessClientFinished(self: *Tls13Handshake) !Action {
        const msg = self.readHandshakeMsg() orelse return .wait_for_data;

        if (msg[0] != @intFromEnum(tls.HandshakeType.finished)) return error.UnexpectedMessage;

        const body = msg[4..];
        if (body.len != 32) return error.BadFinished;

        // Verify client Finished
        const transcript_hash = self.transcript.current();
        const expected = KeySchedule.computeFinishedVerifyData(
            self.key_schedule.client_handshake_traffic_secret,
            transcript_hash,
        );

        // Constant-time MAC compare (RFC 8446 §4.4.4). Length is public
        // (fixed by the cipher suite hash), the verify_data is secret.
        if (body.len != expected.len or
            !crypto.timing_safe.eql([expected.len]u8, body[0..expected.len].*, expected)) return error.BadFinished;

        self.transcript.update(msg);

        // A ticket is owed whenever this side seals them at all. A policy in
        // force does not stop it: the ticket carries no identity, so it is
        // never what authenticates the client.
        if (self.serverTicketKey() != null) {
            self.state = .server_send_ticket;
            return ._continue;
        }

        return self.serverFinish();
    }

    /// The key this side seals and opens tickets under, or null when it
    /// seals none. Named once because the writer and the PSK reader have
    /// to agree on it, and a disagreement between them is a server that
    /// seals under one key and opens under another.
    fn serverTicketKey(self: *const Tls13Handshake) ?TicketKey {
        return Resumption.serverKey(self.config.resumption);
    }

    /// Whether this handshake may declare the connection complete.
    ///
    /// A policy in force means the connection completes only on an identity
    /// this server verified. `serverProcessClientCertificate` is the sole
    /// writer of `peer_node_id` and the sole comparison of
    /// `auth.expect_node_id`, and a PSK does not reach it — which is
    /// exactly why this is asked separately: the state machine routes a
    /// resumed connection through the CertificateRequest just as it routes
    /// a full one, and this refuses the handshake rather than the
    /// connection if some future path ever skips it. Both writers of
    /// `connected` ask it, so there is one answer and no flag to remember.
    fn serverIdentityEstablished(self: *const Tls13Handshake) bool {
        const auth = self.client_auth orelse return true;
        return auth.mode == .optional or self.peer_node_id != null;
    }

    /// The one place a server handshake reaches `connected` without owing
    /// a ticket.
    fn serverFinish(self: *Tls13Handshake) error{CertificateRequired}!Action {
        if (!self.serverIdentityEstablished()) return error.CertificateRequired;
        self.state = .connected;
        return .complete;
    }

    fn serverProcessClientCertificate(self: *Tls13Handshake) !Action {
        const msg = self.readHandshakeMsg() orelse return .wait_for_data;
        if (msg[0] != @intFromEnum(tls.HandshakeType.certificate)) return error.UnexpectedMessage;
        const auth = self.client_auth.?;
        // One certificate or none. A client identity is a key, and a key has
        // no issuer to sit under, so a longer list is a peer offering a chain
        // this stack would have to walk — and would not.
        var certs: [1][]const u8 = undefined;
        const list = (try parseCertificateList(msg[4..], &certs)) orelse {
            if (auth.mode == .required) return error.CertificateRequired;
            self.transcript.update(msg);
            self.state = .server_wait_client_finished;
            return ._continue;
        };
        // The mirror of `clientProcessCertificate`: lift the key, compare it
        // with the id the server asked for, and leave the key the
        // CertificateVerify is about to be checked against.
        const key = liftEd25519Spki(list[0]) catch return error.BadCertificate;
        if (auth.expect_node_id) |expected| {
            if (!crypto.timing_safe.eql([32]u8, key, expected)) return error.BadCertificate;
        }
        const gpa = self.allocator orelse return error.InternalError;
        self.peer_cert = gpa.dupe(u8, list[0]) catch return error.InternalError;
        self.peer_node_id = key;
        self.transcript.update(msg);
        self.state = .server_wait_client_certificate_verify;
        return ._continue;
    }

    fn serverProcessClientCertificateVerify(self: *Tls13Handshake) !Action {
        const msg = self.readHandshakeMsg() orelse return .wait_for_data;
        if (msg[0] != @intFromEnum(tls.HandshakeType.certificate_verify)) return error.UnexpectedMessage;
        const body = msg[4..];
        if (body.len < 4) return error.DecodeError;
        const scheme = readU16(body);
        const sig_len = readU16(body[2..]);
        if (body.len != 4 + @as(usize, sig_len)) return error.DecodeError;
        var offered = false;
        var i: usize = 0;
        while (i < client_auth_signature_schemes.len) : (i += 2) {
            if (readU16(client_auth_signature_schemes[i..]) == scheme) offered = true;
        }
        if (!offered) return error.IllegalParameter;

        const peer_key = self.peer_node_id orelse return error.InternalError;
        const label = "TLS 1.3, client CertificateVerify";
        var content: [64 + label.len + 1 + 32]u8 = undefined;
        @memset(content[0..64], 0x20);
        @memcpy(content[64..][0..label.len], label);
        content[64 + label.len] = 0x00;
        content[64 + label.len + 1 ..][0..32].* = self.transcript.current();
        verifyCertificateVerifySignature(
            &peer_key,
            lifted_key_algo,
            scheme,
            body[4..],
            &content,
        ) catch return error.BadCertificateVerify;
        self.transcript.update(msg);
        self.state = .server_wait_client_finished;
        return ._continue;
    }

    // ─── Server: Send NewSessionTicket ──────────────────────────────

    fn serverSendTicket(self: *Tls13Handshake, now_s: i64, random: std.Random) !Action {
        const ticket_key = self.serverTicketKey() orelse return error.InternalError;

        // Derive resumption master secret
        const transcript_hash = self.transcript.current();
        self.key_schedule.deriveResumptionMasterSecret(transcript_hash);

        // Generate ticket nonce
        var nonce_buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &nonce_buf, self.ticket_nonce_counter, .big);
        self.ticket_nonce_counter += 1;

        // PSK = HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, 32)
        const psk = quic_crypto.hkdfExpandLabel(self.key_schedule.resumption_master_secret, "resumption", &nonce_buf, 32);

        // Generate random ticket_age_add
        var ticket_age_add_bytes: [4]u8 = undefined;
        random.bytes(&ticket_age_add_bytes);
        const ticket_age_add = std.mem.readInt(u32, &ticket_age_add_bytes, .big);

        // Build ticket plaintext: psk(32) || creation_time(8) || alpn_len(1) || alpn
        var ticket_plain: [64]u8 = .{0} ** 64;
        @memcpy(ticket_plain[0..32], &psk);
        std.mem.writeInt(i64, ticket_plain[32..40], now_s, .big);
        const alpn_bytes = self.negotiatedAlpn();
        const alpn_copy_len: u8 = @intCast(@min(alpn_bytes.len, 16));
        ticket_plain[40] = alpn_copy_len;
        @memcpy(ticket_plain[41..][0..alpn_copy_len], alpn_bytes[0..alpn_copy_len]);
        const plaintext_len = 41 + @as(usize, alpn_copy_len);

        // Encrypt ticket with AES-128-GCM using ticket_key
        var nonce_for_ticket: [12]u8 = .{0} ** 12;
        @memcpy(nonce_for_ticket[8..12], &nonce_buf);
        var encrypted_ticket: [sealed_ticket_len]u8 = undefined; // plaintext + 16 tag
        var tag: [16]u8 = undefined;
        Aes128Gcm.encrypt(
            encrypted_ticket[0..plaintext_len],
            &tag,
            ticket_plain[0..plaintext_len],
            "",
            nonce_for_ticket,
            ticket_key.bytes,
        );
        @memcpy(encrypted_ticket[plaintext_len..][0..16], &tag);
        const encrypted_len = plaintext_len + 16;

        // Build NewSessionTicket message (RFC 8446 §4.6.1):
        // type(1) + length(3) + lifetime(4) + ticket_age_add(4) + nonce_len(1) + nonce(4) +
        // ticket_len(2) + ticket(N) + extensions_len(2) + early_data_ext(type=42, len=2+4, max=0xffffffff)
        const lifetime: u32 = 7 * 24 * 3600; // 7 days
        const ext_data_len: u16 = 4 + 4; // type(2) + len(2) + max_early_data(4)
        const nst_body_len: u24 = @intCast(4 + 4 + 1 + 4 + 2 + encrypted_len + 2 + ext_data_len);

        var nst: [256]u8 = undefined;
        var nst_pos: usize = 0;

        nst[0] = @intFromEnum(tls.HandshakeType.new_session_ticket);
        nst[1] = @intCast(nst_body_len >> 16);
        nst[2] = @intCast((nst_body_len >> 8) & 0xff);
        nst[3] = @intCast(nst_body_len & 0xff);
        nst_pos = 4;

        // lifetime
        std.mem.writeInt(u32, nst[nst_pos..][0..4], lifetime, .big);
        nst_pos += 4;

        // ticket_age_add
        std.mem.writeInt(u32, nst[nst_pos..][0..4], ticket_age_add, .big);
        nst_pos += 4;

        // nonce
        nst[nst_pos] = 4; // nonce length
        nst_pos += 1;
        @memcpy(nst[nst_pos..][0..4], &nonce_buf);
        nst_pos += 4;

        // ticket
        writeU16(nst[nst_pos..], @intCast(encrypted_len));
        nst_pos += 2;
        @memcpy(nst[nst_pos..][0..encrypted_len], encrypted_ticket[0..encrypted_len]);
        nst_pos += encrypted_len;

        // extensions: early_data with max_early_data_size = 0xffffffff
        writeU16(nst[nst_pos..], ext_data_len);
        nst_pos += 2;
        writeU16(nst[nst_pos..], @intFromEnum(tls.ExtensionType.early_data));
        nst_pos += 2;
        writeU16(nst[nst_pos..], 4); // extension data length
        nst_pos += 2;
        std.mem.writeInt(u32, nst[nst_pos..][0..4], 0xffffffff, .big);
        nst_pos += 4;

        @memcpy(self.out_buf[0..nst_pos], nst[0..nst_pos]);
        self.out_len = nst_pos;

        if (!self.serverIdentityEstablished()) return error.CertificateRequired;
        self.state = .connected;
        return Action{ .send_data = .{
            .level = .application,
            .data = self.out_buf[0..self.out_len],
        } };
    }

    // ─── Server: Try to process PSK from ClientHello ────────────────

    fn tryProcessPsk(
        self: *Tls13Handshake,
        msg: []const u8,
        body: []const u8,
        ext_start_in_body: usize,
        ext_data: []const u8,
        psk_ext_offset: usize,
        psk_ext_len: usize,
    ) void {
        const ticket_key = self.serverTicketKey() orelse return;

        if (psk_ext_len < 6) return;
        const psk_data = ext_data[psk_ext_offset..][0..psk_ext_len];

        // Parse identities list
        const identities_len = readU16(psk_data[0..]);
        if (2 + identities_len > psk_ext_len) return;

        // Parse first identity
        var id_pos: usize = 2;
        if (id_pos + 2 > 2 + identities_len) return;
        const identity_len = readU16(psk_data[id_pos..]);
        id_pos += 2;
        if (id_pos + identity_len + 4 > 2 + identities_len) return;
        const identity = psk_data[id_pos..][0..identity_len];

        // Parse binders list (after identities)
        var binders_start: usize = 2 + identities_len;
        if (binders_start + 2 > psk_ext_len) return;
        const binders_len = readU16(psk_data[binders_start..]);
        binders_start += 2;
        if (binders_start + binders_len > psk_ext_len) return;

        // First binder
        if (binders_start >= psk_ext_len) return;
        const binder_len = psk_data[binders_start];
        if (binder_len != 32) return;
        if (binders_start + 1 + 32 > psk_ext_len) return;
        const received_binder = psk_data[binders_start + 1 ..][0..32];

        // Decrypt ticket identity to get PSK
        if (identity_len < 16 + 1) return; // at least tag + 1 byte
        // A ticket this server sealed is one plaintext plus a 16-byte tag
        // and no longer. A longer identity is a peer offering something that
        // would be copied past the end of two fixed buffers below, and a
        // server holding a key reaches this from the wire on every
        // ClientHello — client-auth policy or not.
        if (identity_len > sealed_ticket_len) return;
        const ciphertext_len = identity_len - 16;

        // Reconstruct nonce from ticket (we use the last 4 bytes of identity as hint)
        var ticket_nonce: [12]u8 = .{0} ** 12;
        // Use zeros as nonce — server encrypts with incrementing nonce_buf in [8..12]
        // We need to try nonce counter values. For simplicity, try a few.
        var decrypted: [64]u8 = undefined;
        var psk_found = false;
        var found_psk: [32]u8 = undefined;

        for (0..256) |nonce_try| {
            std.mem.writeInt(u32, ticket_nonce[8..12], @intCast(nonce_try), .big);
            var ct_copy: [80]u8 = undefined;
            @memcpy(ct_copy[0..identity_len], identity[0..identity_len]);
            const tag_start = ciphertext_len;
            const tag: [16]u8 = ct_copy[tag_start..][0..16].*;

            Aes128Gcm.decrypt(
                decrypted[0..ciphertext_len],
                ct_copy[0..ciphertext_len],
                tag,
                "",
                ticket_nonce,
                ticket_key.bytes,
            ) catch continue;

            // Decrypted successfully
            if (ciphertext_len >= 32) {
                @memcpy(&found_psk, decrypted[0..32]);
                psk_found = true;
                break;
            }
        }

        if (!psk_found) return;

        // Compute binder key from PSK WITHOUT modifying self.key_schedule yet
        // (if binder fails, we must leave key_schedule untouched)
        const temp_ks = KeySchedule.initWithPsk(found_psk);

        // Verify binder
        // binder_key = Derive-Secret(early_secret, "res binder", Hash(""))
        const empty_hash = tls.emptyHash(Sha256);
        const binder_key = quic_crypto.hkdfExpandLabel(temp_ks.early_secret, "res binder", &empty_hash, 32);

        // Partial ClientHello = up to and including identities field (RFC 8446 §4.2.11.2)
        // Exclude: binders_len_field(2) + binder_entries(binders_len)
        const partial_len = msg.len - @as(usize, binders_len) - 2;
        _ = body;
        _ = ext_start_in_body;

        var partial_hash: Sha256 = Sha256.init(.{});
        partial_hash.update(msg[0..partial_len]);
        var partial_transcript = partial_hash.finalResult();

        const expected_binder = KeySchedule.computeFinishedVerifyData(binder_key, partial_transcript);
        _ = &partial_transcript;

        // Constant-time compare of the PSK binder HMAC (RFC 8446 §4.2.11.2).
        if (!crypto.timing_safe.eql([expected_binder.len]u8, received_binder.*, expected_binder)) {
            std.log.warn("PSK binder verification failed, falling back to full handshake", .{});
            return;
        }

        // Binder verified — now safe to install PSK key schedule
        self.key_schedule = temp_ks;
        self.using_psk = true;
        self.zero_rtt_accepted = self.early_data_offered;
    }

    // ─── Client: Parse NewSessionTicket ──────────────────────────────

    fn parseNewSessionTicket(self: *Tls13Handshake, msg: []const u8, now_s: i64) void {
        const body = msg[4..];
        if (body.len < 13) return; // minimum: lifetime(4) + age_add(4) + nonce_len(1) + nonce(>=0) + ticket_len(2)

        var pos: usize = 0;
        const lifetime = std.mem.readInt(u32, body[pos..][0..4], .big);
        pos += 4;
        const ticket_age_add = std.mem.readInt(u32, body[pos..][0..4], .big);
        pos += 4;

        const nonce_len = body[pos];
        pos += 1;
        if (pos + nonce_len > body.len) return;
        const nonce_data = body[pos..][0..nonce_len];
        pos += nonce_len;

        if (pos + 2 > body.len) return;
        const ticket_len = readU16(body[pos..]);
        pos += 2;
        if (pos + ticket_len > body.len) return;
        const ticket_data = body[pos..][0..ticket_len];
        pos += ticket_len;

        // Parse extensions
        var max_early_data: u32 = 0;
        if (pos + 2 <= body.len) {
            const ext_len = readU16(body[pos..]);
            pos += 2;
            var ext_pos: usize = 0;
            const ext_end = @min(pos + ext_len, body.len);
            const ext_buf = body[pos..ext_end];
            while (ext_pos + 4 <= ext_buf.len) {
                const etype = readU16(ext_buf[ext_pos..]);
                ext_pos += 2;
                const elen = readU16(ext_buf[ext_pos..]);
                ext_pos += 2;
                if (ext_pos + elen > ext_buf.len) break;
                if (etype == @intFromEnum(tls.ExtensionType.early_data) and elen >= 4) {
                    max_early_data = std.mem.readInt(u32, ext_buf[ext_pos..][0..4], .big);
                }
                ext_pos += elen;
            }
        }

        // Derive PSK from resumption_master_secret + nonce
        // First compute resumption_master_secret if not yet done
        if (!self.key_schedule.computed_app) return;
        const full_transcript = self.transcript.current();
        self.key_schedule.deriveResumptionMasterSecret(full_transcript);

        const psk = quic_crypto.hkdfExpandLabel(self.key_schedule.resumption_master_secret, "resumption", nonce_data, 32);

        var ticket: SessionTicket = .{ .psk = psk };
        ticket.lifetime = lifetime;
        ticket.ticket_age_add = ticket_age_add;
        ticket.creation_time = now_s;
        ticket.max_early_data_size = max_early_data;

        const copy_len: u16 = @intCast(@min(ticket_data.len, ticket.ticket.len));
        @memcpy(ticket.ticket[0..copy_len], ticket_data[0..copy_len]);
        ticket.ticket_len = copy_len;

        // Store ALPN from config
        if (self.config.alpn.len > 0) {
            const alpn_src = self.config.alpn[0];
            const alpn_copy: u8 = @intCast(@min(alpn_src.len, 16));
            @memcpy(ticket.alpn[0..alpn_copy], alpn_src[0..alpn_copy]);
            ticket.alpn_len = alpn_copy;
        }

        // RFC 9000 §7.4.1: remember server's transport params for 0-RTT resumption
        if (self.peer_transport_params) |peer_tp| {
            ticket.initial_max_data = peer_tp.initial_max_data;
            ticket.initial_max_stream_data_bidi_local = peer_tp.initial_max_stream_data_bidi_local;
            ticket.initial_max_stream_data_bidi_remote = peer_tp.initial_max_stream_data_bidi_remote;
            ticket.initial_max_stream_data_uni = peer_tp.initial_max_stream_data_uni;
            ticket.initial_max_streams_bidi = peer_tp.initial_max_streams_bidi;
            ticket.initial_max_streams_uni = peer_tp.initial_max_streams_uni;
            ticket.active_connection_id_limit = peer_tp.active_connection_id_limit;
        }

        self.received_ticket = ticket;
    }

    // ─── Helpers ─────────────────────────────────────────────────────

    // Try to read a complete handshake message from the input buffer.
    // Returns the full message (type + 3-byte length + body) or null.
    fn readHandshakeMsg(self: *Tls13Handshake) ?[]const u8 {
        const msg = self.peekHandshakeMsg() orelse return null;
        self.in_offset += msg.len;

        // Compact the buffer if we've consumed everything
        if (self.in_offset == self.in_len) {
            self.in_offset = 0;
            self.in_len = 0;
        }

        return msg;
    }

    /// The next complete handshake message, without taking it.
    ///
    /// A resumed client has to know that what is next is the server's
    /// Finished before it changes state, and `readHandshakeMsg` has stepped
    /// past it by the time it knows. So the resumed path asks first.
    fn peekHandshakeMsg(self: *const Tls13Handshake) ?[]const u8 {
        const available = self.in_len - self.in_offset;
        if (available < 4) return null;

        const msg_len = (@as(usize, self.in_buf[self.in_offset + 1]) << 16) |
            (@as(usize, self.in_buf[self.in_offset + 2]) << 8) |
            @as(usize, self.in_buf[self.in_offset + 3]);

        const total_len = 4 + msg_len;
        if (available < total_len) return null;

        return self.in_buf[self.in_offset..][0..total_len];
    }

    fn parseEncryptedExtensions(self: *Tls13Handshake, body: []const u8) !void {
        if (body.len < 2) return;
        const ext_len = readU16(body[0..]);
        var ext_pos: usize = 0;
        const ext_data = body[2..][0..@min(ext_len, body.len - 2)];
        while (ext_pos + 4 <= ext_data.len) {
            const etype = readU16(ext_data[ext_pos..]);
            ext_pos += 2;
            const elen = readU16(ext_data[ext_pos..]);
            ext_pos += 2;
            if (ext_pos + elen > ext_data.len) break;

            if (etype == @intFromEnum(tls.ExtensionType.quic_transport_parameters)) {
                const tp_data = ext_data[ext_pos..][0..elen];
                self.peer_transport_params = transport_params.TransportParams.decode(tp_data) catch {
                    return error.TransportParameterError;
                };
            } else if (etype == @intFromEnum(tls.ExtensionType.early_data)) {
                // Server accepted early data (0-RTT)
                self.zero_rtt_accepted = true;
            } else if (etype == @intFromEnum(tls.ExtensionType.application_layer_protocol_negotiation)) {
                // RFC 7301 §3.1: exactly one protocol, and one we offered.
                const d = ext_data[ext_pos..][0..elen];
                if (d.len < 3 or readU16(d) != d.len - 2 or @as(usize, d[2]) + 3 != d.len) return error.DecodeError;
                const proto = d[3..];
                for (self.config.alpn) |ours| {
                    if (std.mem.eql(u8, ours, proto)) break;
                } else return error.IllegalParameter;
                if (proto.len > self.selected_alpn.len) return error.IllegalParameter;
                @memcpy(self.selected_alpn[0..proto.len], proto);
                self.selected_alpn_len = proto.len;
            }
            ext_pos += elen;
        }
    }
};

// ─── Message builders ────────────────────────────────────────────────

fn buildClientHello(
    buf: []u8,
    client_random: *const [32]u8,
    x25519_pub: *const [32]u8,
    p256_pub: *const [65]u8,
    alpn_list: []const []const u8,
    server_name: ?[]const u8,
    tp_encoded_data: []const u8,
    session_ticket: ?*const SessionTicket,
    key_schedule: *KeySchedule,
    cipher_suite_only: ?quic_crypto.CipherSuite,
    now_s: i64,
) ![]const u8 {
    // Build the body first, then wrap with type + length
    var pos: usize = 4; // reserve space for type + 3-byte length

    // legacy_version = 0x0303
    buf[pos] = 0x03;
    buf[pos + 1] = 0x03;
    pos += 2;

    // random
    @memcpy(buf[pos..][0..32], client_random);
    pos += 32;

    // session_id (empty, but TLS 1.3 middlebox compat says 32 bytes)
    // For QUIC, we use empty session_id per RFC 9001 Section 4.1.2
    buf[pos] = 0; // session_id_len = 0
    pos += 1;

    // cipher_suites
    if (cipher_suite_only) |cs| {
        // Offer only the specified cipher suite (e.g., for chacha20 interop test)
        writeU16(buf[pos..], 2);
        pos += 2;
        writeU16(buf[pos..], @intFromEnum(cs));
        pos += 2;
    } else {
        // Offer both AES-128-GCM and ChaCha20-Poly1305
        writeU16(buf[pos..], 4);
        pos += 2;
        writeU16(buf[pos..], @intFromEnum(tls.CipherSuite.AES_128_GCM_SHA256));
        pos += 2;
        writeU16(buf[pos..], @intFromEnum(tls.CipherSuite.CHACHA20_POLY1305_SHA256));
        pos += 2;
    }

    // compression_methods: 1 byte length + null compression
    buf[pos] = 1;
    pos += 1;
    buf[pos] = 0;
    pos += 1;

    // Extensions
    const ext_start = pos;
    pos += 2; // extensions length placeholder

    // supported_versions extension
    pos = writeExtHeader(buf, pos, @intFromEnum(tls.ExtensionType.supported_versions), 3);
    buf[pos] = 2; // list length
    pos += 1;
    writeU16(buf[pos..], @intFromEnum(tls.ProtocolVersion.tls_1_3));
    pos += 2;

    // key_share extension (X25519 + P-256)
    const x25519_share_len = 2 + 2 + 32; // group(2) + len(2) + key(32)
    const p256_share_len = 2 + 2 + 65; // group(2) + len(2) + key(65)
    const shares_total: u16 = x25519_share_len + p256_share_len;
    pos = writeExtHeader(buf, pos, @intFromEnum(tls.ExtensionType.key_share), 2 + shares_total);
    writeU16(buf[pos..], shares_total); // client_shares length
    pos += 2;
    // X25519 share (preferred)
    writeU16(buf[pos..], @intFromEnum(tls.NamedGroup.x25519));
    pos += 2;
    writeU16(buf[pos..], 32);
    pos += 2;
    @memcpy(buf[pos..][0..32], x25519_pub);
    pos += 32;
    // P-256 share (fallback)
    writeU16(buf[pos..], @intFromEnum(tls.NamedGroup.secp256r1));
    pos += 2;
    writeU16(buf[pos..], 65);
    pos += 2;
    @memcpy(buf[pos..][0..65], p256_pub);
    pos += 65;

    // signature_algorithms extension
    pos = writeExtHeader(buf, pos, @intFromEnum(tls.ExtensionType.signature_algorithms), 2 + 10);
    writeU16(buf[pos..], 10); // list length (5 algorithms x 2 bytes)
    pos += 2;
    writeU16(buf[pos..], @intFromEnum(tls.SignatureScheme.ed25519));
    pos += 2;
    writeU16(buf[pos..], @intFromEnum(tls.SignatureScheme.ecdsa_secp256r1_sha256));
    pos += 2;
    writeU16(buf[pos..], @intFromEnum(tls.SignatureScheme.rsa_pss_rsae_sha256));
    pos += 2;
    writeU16(buf[pos..], @intFromEnum(tls.SignatureScheme.rsa_pss_rsae_sha384));
    pos += 2;
    writeU16(buf[pos..], @intFromEnum(tls.SignatureScheme.rsa_pss_rsae_sha512));
    pos += 2;

    // supported_groups extension
    pos = writeExtHeader(buf, pos, @intFromEnum(tls.ExtensionType.supported_groups), 2 + 4);
    writeU16(buf[pos..], 4); // list length (2 groups x 2 bytes)
    pos += 2;
    writeU16(buf[pos..], @intFromEnum(tls.NamedGroup.x25519));
    pos += 2;
    writeU16(buf[pos..], @intFromEnum(tls.NamedGroup.secp256r1));
    pos += 2;

    // SNI extension
    if (server_name) |sni| {
        const sni_ext_len = 2 + 1 + 2 + sni.len; // server_name_list_len + type + host_name_len + host_name
        pos = writeExtHeader(buf, pos, @intFromEnum(tls.ExtensionType.server_name), sni_ext_len);
        const list_len: u16 = @intCast(1 + 2 + sni.len);
        writeU16(buf[pos..], list_len);
        pos += 2;
        buf[pos] = 0; // host_name type
        pos += 1;
        writeU16(buf[pos..], @intCast(sni.len));
        pos += 2;
        @memcpy(buf[pos..][0..sni.len], sni);
        pos += sni.len;
    }

    // ALPN extension
    if (alpn_list.len > 0) {
        var alpn_total: usize = 0;
        for (alpn_list) |proto| {
            alpn_total += 1 + proto.len;
        }
        pos = writeExtHeader(buf, pos, @intFromEnum(tls.ExtensionType.application_layer_protocol_negotiation), 2 + alpn_total);
        writeU16(buf[pos..], @intCast(alpn_total));
        pos += 2;
        for (alpn_list) |proto| {
            buf[pos] = @intCast(proto.len);
            pos += 1;
            @memcpy(buf[pos..][0..proto.len], proto);
            pos += proto.len;
        }
    }

    // QUIC transport parameters extension (pre-encoded)
    pos = writeExtHeader(buf, pos, @intFromEnum(tls.ExtensionType.quic_transport_parameters), tp_encoded_data.len);
    @memcpy(buf[pos..][0..tp_encoded_data.len], tp_encoded_data);
    pos += tp_encoded_data.len;

    // psk_key_exchange_modes extension (type=45) — always included so
    // servers know we support session tickets and can send NewSessionTicket.
    // modes_list_len(1) + mode(1)=0x01 (psk_dhe_ke)
    pos = writeExtHeader(buf, pos, @intFromEnum(tls.ExtensionType.psk_key_exchange_modes), 2);
    buf[pos] = 1; // modes list length
    pos += 1;
    buf[pos] = 0x01; // psk_dhe_ke
    pos += 1;

    // PSK extensions (must be last, per RFC 8446 §4.2.11)
    if (session_ticket) |ticket| {
        // early_data extension (RFC 8446 §4.2.10) — empty payload in ClientHello
        // Tells the server we intend to send 0-RTT data
        pos = writeExtHeader(buf, pos, @intFromEnum(tls.ExtensionType.early_data), 0);

        // pre_shared_key extension (type=41) - MUST be last
        const ticket_bytes = ticket.getTicket();
        const obfuscated_age: u32 = blk: {
            // RFC 8446 4.2.11: the obfuscated age is mod 2^32, so a ticket
            // older than ~49 days wraps rather than aborting.
            const age_ms: u32 = @truncate(@as(u64, @intCast(@max(0, now_s - ticket.creation_time))) *% 1000);
            break :blk age_ms +% ticket.ticket_age_add;
        };

        // identities: identities_len(2) + [identity_len(2) + identity + obfuscated_age(4)]
        const identities_len: u16 = @intCast(2 + ticket_bytes.len + 4);
        // binders: binders_len(2) + [binder_len(1) + binder(32)]
        const binders_len: u16 = 1 + 32;
        const psk_ext_total: u16 = 2 + identities_len + 2 + binders_len;

        pos = writeExtHeader(buf, pos, @intFromEnum(tls.ExtensionType.pre_shared_key), psk_ext_total);

        // Identities
        writeU16(buf[pos..], identities_len);
        pos += 2;
        writeU16(buf[pos..], @intCast(ticket_bytes.len));
        pos += 2;
        @memcpy(buf[pos..][0..ticket_bytes.len], ticket_bytes);
        pos += ticket_bytes.len;
        std.mem.writeInt(u32, buf[pos..][0..4], obfuscated_age, .big);
        pos += 4;

        // Binders placeholder (32 zero bytes, will be replaced)
        writeU16(buf[pos..], binders_len);
        pos += 2;
        buf[pos] = 32; // binder length
        pos += 1;
        const binder_value_offset = pos;
        @memset(buf[pos..][0..32], 0);
        pos += 32;

        // Fill in extensions length and message header BEFORE computing binder
        const ext_len: u16 = @intCast(pos - ext_start - 2);
        writeU16(buf[ext_start..], ext_len);

        const body_len: u24 = @intCast(pos - 4);
        buf[0] = @intFromEnum(tls.HandshakeType.client_hello);
        buf[1] = @intCast(body_len >> 16);
        buf[2] = @intCast((body_len >> 8) & 0xff);
        buf[3] = @intCast(body_len & 0xff);

        // Now compute the real binder
        // binder_key = Derive-Secret(early_secret, "res binder", Hash(""))
        const empty_hash = tls.emptyHash(Sha256);
        const binder_key = quic_crypto.hkdfExpandLabel(key_schedule.early_secret, "res binder", &empty_hash, 32);

        // partial_ch = everything up to and including identities (RFC 8446 §4.2.11.2)
        // Exclude: binders_len_field(2) + binder_len(1) + binder_value(32) = 35 bytes
        const partial_len = pos - 2 - binders_len;
        var partial_hasher = Sha256.init(.{});
        partial_hasher.update(buf[0..partial_len]);
        const partial_hash = partial_hasher.finalResult();

        const binder = KeySchedule.computeFinishedVerifyData(binder_key, partial_hash);
        @memcpy(buf[binder_value_offset..][0..32], &binder);

        return buf[0..pos];
    }

    // Fill in extensions length
    const ext_len: u16 = @intCast(pos - ext_start - 2);
    writeU16(buf[ext_start..], ext_len);

    // Fill in message header
    const body_len: u24 = @intCast(pos - 4);
    buf[0] = @intFromEnum(tls.HandshakeType.client_hello);
    buf[1] = @intCast(body_len >> 16);
    buf[2] = @intCast((body_len >> 8) & 0xff);
    buf[3] = @intCast(body_len & 0xff);

    return buf[0..pos];
}

fn buildServerHello(
    buf: []u8,
    server_random: *const [32]u8,
    key_share_group: tls.NamedGroup,
    key_share_data: []const u8,
    session_id_echo: []const u8,
    using_psk: bool,
    cipher_suite: quic_crypto.CipherSuite,
) ![]const u8 {
    var pos: usize = 4; // reserve for header

    // legacy_version = 0x0303
    buf[pos] = 0x03;
    buf[pos + 1] = 0x03;
    pos += 2;

    // random
    @memcpy(buf[pos..][0..32], server_random);
    pos += 32;

    // legacy_session_id_echo (RFC 8446 §4.1.3: echo the client's value)
    buf[pos] = @intCast(session_id_echo.len);
    pos += 1;
    if (session_id_echo.len > 0) {
        @memcpy(buf[pos..][0..session_id_echo.len], session_id_echo);
        pos += session_id_echo.len;
    }

    // cipher_suite (use negotiated from ClientHello)
    writeU16(buf[pos..], @intFromEnum(cipher_suite));
    pos += 2;

    // compression_method
    buf[pos] = 0;
    pos += 1;

    // Extensions
    const ext_start = pos;
    pos += 2; // extensions length placeholder

    // supported_versions
    pos = writeExtHeader(buf, pos, @intFromEnum(tls.ExtensionType.supported_versions), 2);
    writeU16(buf[pos..], @intFromEnum(tls.ProtocolVersion.tls_1_3));
    pos += 2;

    // key_share (server's key)
    const ks_len: u16 = @intCast(2 + 2 + key_share_data.len);
    pos = writeExtHeader(buf, pos, @intFromEnum(tls.ExtensionType.key_share), ks_len);
    writeU16(buf[pos..], @intFromEnum(key_share_group));
    pos += 2;
    writeU16(buf[pos..], @intCast(key_share_data.len));
    pos += 2;
    @memcpy(buf[pos..][0..key_share_data.len], key_share_data);
    pos += key_share_data.len;

    // pre_shared_key extension (selected_identity = 0)
    if (using_psk) {
        pos = writeExtHeader(buf, pos, @intFromEnum(tls.ExtensionType.pre_shared_key), 2);
        writeU16(buf[pos..], 0); // selected_identity = 0
        pos += 2;
    }

    // Fill in extensions length
    const ext_len: u16 = @intCast(pos - ext_start - 2);
    writeU16(buf[ext_start..], ext_len);

    // Fill in message header
    const body_len: u24 = @intCast(pos - 4);
    buf[0] = @intFromEnum(tls.HandshakeType.server_hello);
    buf[1] = @intCast(body_len >> 16);
    buf[2] = @intCast((body_len >> 8) & 0xff);
    buf[3] = @intCast(body_len & 0xff);

    return buf[0..pos];
}

fn buildEncryptedExtensionsFromEncoded(
    buf: []u8,
    alpn_list: []const []const u8,
    tp_encoded_data: []const u8,
    include_early_data: bool,
) ![]const u8 {
    var pos: usize = 4; // reserve for header

    // Extensions list
    const ext_list_start = pos;
    pos += 2; // extensions length placeholder

    // ALPN
    if (alpn_list.len > 0) {
        var alpn_total: usize = 0;
        for (alpn_list) |proto| {
            alpn_total += 1 + proto.len;
        }
        pos = writeExtHeader(buf, pos, @intFromEnum(tls.ExtensionType.application_layer_protocol_negotiation), 2 + alpn_total);
        writeU16(buf[pos..], @intCast(alpn_total));
        pos += 2;
        for (alpn_list) |proto| {
            buf[pos] = @intCast(proto.len);
            pos += 1;
            @memcpy(buf[pos..][0..proto.len], proto);
            pos += proto.len;
        }
    }

    // QUIC transport parameters (pre-encoded)
    pos = writeExtHeader(buf, pos, @intFromEnum(tls.ExtensionType.quic_transport_parameters), tp_encoded_data.len);
    @memcpy(buf[pos..][0..tp_encoded_data.len], tp_encoded_data);
    pos += tp_encoded_data.len;

    // early_data extension (empty payload in EE, per RFC 8446 §4.2.10)
    if (include_early_data) {
        pos = writeExtHeader(buf, pos, @intFromEnum(tls.ExtensionType.early_data), 0);
    }

    // Fill in extensions length
    const ext_len: u16 = @intCast(pos - ext_list_start - 2);
    writeU16(buf[ext_list_start..], ext_len);

    // Fill in message header
    const body_len: u24 = @intCast(pos - 4);
    buf[0] = @intFromEnum(tls.HandshakeType.encrypted_extensions);
    buf[1] = @intCast(body_len >> 16);
    buf[2] = @intCast((body_len >> 8) & 0xff);
    buf[3] = @intCast(body_len & 0xff);

    return buf[0..pos];
}

fn buildCertificate(buf: []u8, cert_chain: []const []const u8) ![]const u8 {
    var pos: usize = 4; // reserve for header

    // certificate_request_context (empty for server)
    buf[pos] = 0;
    pos += 1;

    // certificate_list length placeholder
    const cert_list_start = pos;
    pos += 3; // 3-byte length

    for (cert_chain) |cert_der| {
        // 5 = 3-byte length + 2-byte empty extensions
        if (cert_der.len + 5 > buf.len - pos) return error.CertChainTooLarge;

        // cert_data length (3 bytes)
        const cert_len: u24 = @intCast(cert_der.len);
        buf[pos] = @intCast(cert_len >> 16);
        buf[pos + 1] = @intCast((cert_len >> 8) & 0xff);
        buf[pos + 2] = @intCast(cert_len & 0xff);
        pos += 3;

        // cert_data
        @memcpy(buf[pos..][0..cert_der.len], cert_der);
        pos += cert_der.len;

        // extensions (empty)
        writeU16(buf[pos..], 0);
        pos += 2;
    }

    // Fill in certificate_list length
    const cert_list_len: u24 = @intCast(pos - cert_list_start - 3);
    buf[cert_list_start] = @intCast(cert_list_len >> 16);
    buf[cert_list_start + 1] = @intCast((cert_list_len >> 8) & 0xff);
    buf[cert_list_start + 2] = @intCast(cert_list_len & 0xff);

    // Fill in message header
    const body_len: u24 = @intCast(pos - 4);
    buf[0] = @intFromEnum(tls.HandshakeType.certificate);
    buf[1] = @intCast(body_len >> 16);
    buf[2] = @intCast((body_len >> 8) & 0xff);
    buf[3] = @intCast(body_len & 0xff);

    return buf[0..pos];
}

/// Signs CertificateVerify content with `scheme`, which `signatureSchemeFor`
/// picked for the key. Returns a slice of `out`.
///
/// `random` is drawn on two of the four branches, for two unrelated reasons,
/// and Ed25519 is drawn on for neither. P-256 needs a fresh nonce `k` per
/// signature: a repeated `k` over two messages hands over the private key
/// outright, so that draw is load-bearing. RSA-PSS needs a fresh salt, but
/// for the weaker reason RFC 8017 §9.1.1 gives — it keeps the signature
/// randomised rather than deterministic, so a peer cannot learn the
/// transcript repeated and cannot fix the padding it works from. A repeated
/// PSS salt is a defect; a repeated ECDSA nonce is a key compromise, and the
/// two are not interchangeable. Ed25519 derives its nonce from the key and
/// the message (RFC 8032), so a random one is a hedge against fault attacks
/// this path does not take, and would cost the pure core an entropy draw on
/// the one signature scheme an iroh peer ever signs with.
pub fn signCertificateVerify(
    scheme: tls.SignatureScheme,
    private_key_bytes: []const u8,
    content: []const u8,
    out: *[rsa.max_signature_len]u8,
    random: std.Random,
) error{InternalError}![]const u8 {
    switch (scheme) {
        .ecdsa_secp256r1_sha256 => {
            if (private_key_bytes.len != 32) return error.InternalError;
            var noise: [32]u8 = undefined;
            random.bytes(&noise);
            const seed = private_key_bytes[0..32].*;
            // Ours, not std's: the same signature, with k·G off a table.
            const sig = ecdsa_p256.sign(seed, content, noise) catch return error.InternalError;
            return sig.toDer(out[0..EcdsaP256Sha256.Signature.der_encoded_length_max]);
        },
        .ed25519 => {
            if (private_key_bytes.len != 32) return error.InternalError;
            const seed = private_key_bytes[0..32].*;
            const kp = Ed25519.KeyPair.generateDeterministic(seed) catch return error.InternalError;
            const sig = kp.sign(content, null) catch return error.InternalError;
            out[0..Ed25519.Signature.encoded_length].* = sig.toBytes();
            return out[0..Ed25519.Signature.encoded_length];
        },
        inline .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512 => |s| {
            const Hash = switch (s) {
                .rsa_pss_rsae_sha256 => Sha256,
                .rsa_pss_rsae_sha384 => Sha384,
                else => Sha512,
            };
            const key = rsa.PrivateKey.parsePkcs1(private_key_bytes) catch return error.InternalError;
            // The draw is the PSS salt, not a nonce: the caller is entitled
            // to it because a randomised start is what keeps two signatures
            // over one transcript from being the same bytes. It is drawn, not
            // derived from the key, precisely so the salt cannot be replayed
            // as a fingerprint.
            return key.signPss(Hash, content, out, random) catch return error.InternalError;
        },
        else => return error.InternalError,
    }
}

fn buildCertificateVerify(
    buf: []u8,
    transcript_hash: [32]u8,
    private_key_bytes: []const u8,
    scheme: tls.SignatureScheme,
    is_server: bool,
    random: std.Random,
) ![]const u8 {
    // Build the content to sign:
    // 0x20 repeated 64 times + context_string + 0x00 + transcript_hash
    var sign_content: [64 + 33 + 1 + 32]u8 = undefined;
    @memset(sign_content[0..64], 0x20);
    const context_str = if (is_server) "TLS 1.3, server CertificateVerify" else "TLS 1.3, client CertificateVerify";
    @memcpy(sign_content[64..][0..33], context_str);
    sign_content[64 + 33] = 0x00;
    @memcpy(sign_content[64 + 34 ..][0..32], &transcript_hash);

    var sig_storage: [rsa.max_signature_len]u8 = undefined;
    const sig = try signCertificateVerify(scheme, private_key_bytes, &sign_content, &sig_storage, random);
    const sig_algo: u16 = @intFromEnum(scheme);
    const sig_len = sig.len;

    // Build message
    var pos: usize = 4; // reserve for header

    // signature_algorithm
    writeU16(buf[pos..], sig_algo);
    pos += 2;

    // signature length + signature
    writeU16(buf[pos..], @intCast(sig_len));
    pos += 2;
    @memcpy(buf[pos..][0..sig_len], sig_storage[0..sig_len]);
    pos += sig_len;

    // Fill in message header
    const body_len: u24 = @intCast(pos - 4);
    buf[0] = @intFromEnum(tls.HandshakeType.certificate_verify);
    buf[1] = @intCast(body_len >> 16);
    buf[2] = @intCast((body_len >> 8) & 0xff);
    buf[3] = @intCast(body_len & 0xff);

    return buf[0..pos];
}

// ─── Utility functions ───────────────────────────────────────────────

fn writeExtHeader(buf: []u8, pos: usize, ext_type: u16, ext_len: usize) usize {
    writeU16(buf[pos..], ext_type);
    writeU16(buf[pos + 2 ..], @intCast(ext_len));
    return pos + 4;
}

fn readU16(data: []const u8) u16 {
    return std.mem.readInt(u16, data[0..2], .big);
}

fn writeU16(buf: []u8, val: u16) void {
    std.mem.writeInt(u16, buf[0..2], val, .big);
}

// ─── Minimal PEM parser ──────────────────────────────────────────────

pub fn parsePemCert(pem_data: []const u8, out: []u8) ![]const u8 {
    return parsePemSection(pem_data, "CERTIFICATE", out);
}

pub fn parsePemPrivateKey(pem_data: []const u8, out: []u8) ![]const u8 {
    return parsePemSection(pem_data, "EC PRIVATE KEY", out) catch
        parsePemSection(pem_data, "RSA PRIVATE KEY", out) catch
        parsePemSection(pem_data, "PRIVATE KEY", out); // PKCS#8
}

fn parsePemSection(pem_data: []const u8, comptime label: []const u8, out: []u8) ![]const u8 {
    const begin_marker = "-----BEGIN " ++ label ++ "-----";
    const end_marker = "-----END " ++ label ++ "-----";

    const begin_idx = std.mem.indexOf(u8, pem_data, begin_marker) orelse return error.DecodeError;
    const after_begin = begin_idx + begin_marker.len;
    const end_idx = std.mem.indexOf(u8, pem_data[after_begin..], end_marker) orelse return error.DecodeError;
    const base64_data = pem_data[after_begin..][0..end_idx];

    // Strip whitespace and decode base64
    var clean: [8192]u8 = undefined;
    var clean_len: usize = 0;
    for (base64_data) |c| {
        if (c != '\n' and c != '\r' and c != ' ' and c != '\t') {
            if (clean_len >= clean.len) return error.DecodeError;
            clean[clean_len] = c;
            clean_len += 1;
        }
    }

    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(clean[0..clean_len]) catch return error.DecodeError;
    if (decoded_len > out.len) return error.DecodeError;
    std.base64.standard.Decoder.decode(out[0..decoded_len], clean[0..clean_len]) catch return error.DecodeError;
    return out[0..decoded_len];
}

// Extract the 32-byte raw private key from a DER-encoded EC private key.
// RFC 5915: ECPrivateKey ::= SEQUENCE { version, privateKey, ... }
pub fn extractEcPrivateKey(der: []const u8) ![]const u8 {
    // Simple DER walk: SEQUENCE -> version INTEGER -> OCTET STRING (the key)
    if (der.len < 2) return error.DecodeError;
    if (der[0] != 0x30) return error.DecodeError; // SEQUENCE

    var pos: usize = 2;
    // skip length byte(s)
    if (der[1] & 0x80 != 0) {
        const num_len_bytes = der[1] & 0x7f;
        pos += num_len_bytes;
    }

    // version: INTEGER
    if (pos >= der.len or der[pos] != 0x02) return error.DecodeError;
    pos += 1;
    const ver_len = der[pos];
    pos += 1 + ver_len;

    // privateKey: OCTET STRING
    if (pos >= der.len or der[pos] != 0x04) return error.DecodeError;
    pos += 1;
    const key_len = der[pos];
    pos += 1;
    if (key_len != 32) return error.DecodeError;
    if (pos + 32 > der.len) return error.DecodeError;
    return der[pos..][0..32];
}

// Extract the 32-byte raw private key from a PKCS#8 DER-encoded private key.
// PKCS#8: SEQUENCE { version, AlgorithmIdentifier, OCTET STRING { ECPrivateKey } }
pub fn extractPkcs8EcPrivateKey(der: []const u8) ![]const u8 {
    // Walk the outer SEQUENCE
    if (der.len < 2 or der[0] != 0x30) return error.DecodeError;

    var pos: usize = 2;
    if (der[1] & 0x80 != 0) {
        pos += der[1] & 0x7f;
    }

    // Skip version INTEGER
    if (pos >= der.len or der[pos] != 0x02) return error.DecodeError;
    pos += 1;
    const ver_len = der[pos];
    pos += 1 + ver_len;

    // Skip AlgorithmIdentifier SEQUENCE (handle multi-byte length)
    if (pos >= der.len or der[pos] != 0x30) return error.DecodeError;
    pos += 1;
    var alg_len: usize = der[pos];
    pos += 1;
    if (alg_len & 0x80 != 0) {
        const num = alg_len & 0x7f;
        alg_len = 0;
        for (0..num) |i| {
            alg_len = (alg_len << 8) | der[pos + i];
        }
        pos += num;
    }
    pos += alg_len;

    // OCTET STRING containing ECPrivateKey
    if (pos >= der.len or der[pos] != 0x04) return error.DecodeError;
    pos += 1;
    var octet_len: usize = der[pos];
    pos += 1;
    if (octet_len & 0x80 != 0) {
        const num = octet_len & 0x7f;
        octet_len = 0;
        for (0..num) |i| {
            octet_len = (octet_len << 8) | der[pos + i];
        }
        pos += num;
    }

    // The contained value is an ECPrivateKey
    return extractEcPrivateKey(der[pos..][0..octet_len]);
}

fn readDerValue(der: []const u8, pos: *usize, expected_tag: u8) ![]const u8 {
    if (pos.* >= der.len or der[pos.*] != expected_tag) return error.DecodeError;
    pos.* += 1;
    if (pos.* >= der.len) return error.DecodeError;

    var len: usize = der[pos.*];
    pos.* += 1;
    if (len & 0x80 != 0) {
        const num = len & 0x7f;
        if (num == 0 or num > @sizeOf(usize) or pos.* + num > der.len) return error.DecodeError;
        len = 0;
        for (0..num) |i| {
            len = (len << 8) | der[pos.* + i];
        }
        pos.* += num;
    }

    if (pos.* + len > der.len) return error.DecodeError;
    const value = der[pos.*..][0..len];
    pos.* += len;
    return value;
}

// Extract the 32-byte Ed25519 seed from a PKCS#8 DER-encoded private key.
// RFC 8410: AlgorithmIdentifier OID 1.3.101.112, PrivateKey OCTET STRING.
pub fn extractEd25519PrivateKey(der: []const u8) ![]const u8 {
    var outer_pos: usize = 0;
    const outer = try readDerValue(der, &outer_pos, 0x30);

    var pos: usize = 0;
    _ = try readDerValue(outer, &pos, 0x02); // version

    const algorithm = try readDerValue(outer, &pos, 0x30);
    var algorithm_pos: usize = 0;
    const oid = try readDerValue(algorithm, &algorithm_pos, 0x06);
    if (!std.mem.eql(u8, oid, &.{ 0x2b, 0x65, 0x70 })) return error.DecodeError;
    if (algorithm_pos != algorithm.len) return error.DecodeError;

    const private_key = try readDerValue(outer, &pos, 0x04);
    if (private_key.len == 32) return private_key;

    var nested_pos: usize = 0;
    const nested = try readDerValue(private_key, &nested_pos, 0x04);
    if (nested_pos != private_key.len or nested.len != 32) return error.DecodeError;
    return nested;
}

/// An RSA private key, PKCS#1 or PKCS#8 DER, as the PKCS#1 RSAPrivateKey
/// that `ServerCertificate.private_key_bytes` takes (a slice of `der`).
/// Two-prime keys of 2048 to 4096 bits; the key signs once here to prove its
/// numbers fit together.
pub fn extractRsaPrivateKey(der: []const u8) rsa.Error![]const u8 {
    const pkcs1 = rsa.PrivateKey.pkcs1FromPkcs8(der) catch |err| switch (err) {
        error.DecodeError => der, // not PKCS#8
        else => return err,
    };
    const key = try rsa.PrivateKey.parsePkcs1(pkcs1);
    try key.check();
    return pkcs1;
}

pub const PrivateKey = struct {
    /// A slice of the DER it was extracted from.
    bytes: []const u8,
    algorithm: PrivateKeyAlgorithm,
};

/// Recognizes an EC P-256 (SEC1 or PKCS#8), Ed25519 (PKCS#8) or RSA (PKCS#1
/// or PKCS#8) private key, as `parsePemPrivateKey` decodes it.
pub fn extractPrivateKey(der: []const u8) error{ UnsupportedKey, InvalidKey }!PrivateKey {
    if (extractEcPrivateKey(der)) |k| return .{ .bytes = k, .algorithm = .ecdsa_p256_sha256 } else |_| {}
    if (extractPkcs8EcPrivateKey(der)) |k| return .{ .bytes = k, .algorithm = .ecdsa_p256_sha256 } else |_| {}
    if (extractEd25519PrivateKey(der)) |k| return .{ .bytes = k, .algorithm = .ed25519 } else |_| {}
    const k = extractRsaPrivateKey(der) catch |err| return switch (err) {
        error.InvalidKey => error.InvalidKey,
        else => error.UnsupportedKey,
    };
    return .{ .bytes = k, .algorithm = .rsa };
}


// ─── Tests ───────────────────────────────────────────────────────────

test "parsePemCert: rejects a section larger than the scratch buffer" {
    const begin = "-----BEGIN CERTIFICATE-----\n";
    const end = "\n-----END CERTIFICATE-----\n";
    var pem: [begin.len + 9000 + end.len]u8 = undefined;
    @memcpy(pem[0..begin.len], begin);
    @memset(pem[begin.len..][0..9000], 'A');
    @memcpy(pem[begin.len + 9000 ..], end);
    var out: [16384]u8 = undefined;
    try std.testing.expectError(error.DecodeError, parsePemCert(&pem, &out));
}

test "TranscriptHash: basic usage" {
    var th = TranscriptHash.init();

    const msg1 = [_]u8{ 0x01, 0x00, 0x00, 0x03, 0xaa, 0xbb, 0xcc };
    th.update(&msg1);

    const h1 = th.current();
    const h2 = th.current();
    // Same snapshot should give same hash
    try std.testing.expectEqualSlices(u8, &h1, &h2);

    // After more data, hash should change
    th.update(&msg1);
    const h3 = th.current();
    try std.testing.expect(!std.mem.eql(u8, &h1, &h3));
}

test "KeySchedule: derive-secret produces known output for zeros" {
    // Verify early_secret matches the known value
    var ks = KeySchedule.init();
    const zero_key: [32]u8 = .{0} ** 32;

    // early_secret should be HKDF-Extract(salt=0x00, IKM=0x00*32)
    const expected_early = HkdfSha256.extract(&(.{0} ** 1), &zero_key);
    try std.testing.expectEqualSlices(u8, &expected_early, &ks.early_secret);

    // Derive handshake with a fake shared secret and transcript
    var fake_shared: [32]u8 = undefined;
    @memset(&fake_shared, 0x42);
    var fake_transcript: [32]u8 = undefined;
    @memset(&fake_transcript, 0x01);
    ks.deriveHandshakeSecrets(&fake_shared, fake_transcript);

    // Verify secrets are not all-zero (sanity check)
    try std.testing.expect(!std.mem.eql(u8, &ks.client_handshake_traffic_secret, &(.{0} ** 32)));
    try std.testing.expect(!std.mem.eql(u8, &ks.server_handshake_traffic_secret, &(.{0} ** 32)));

    // Derive app secrets
    ks.deriveAppSecrets(fake_transcript);
    try std.testing.expect(!std.mem.eql(u8, &ks.client_app_traffic_secret, &(.{0} ** 32)));
}

test "KeySchedule: finished verify_data" {
    const secret: [32]u8 = .{0x42} ** 32;
    const transcript: [32]u8 = .{0x01} ** 32;
    const vd = KeySchedule.computeFinishedVerifyData(secret, transcript);

    // Verify it's deterministic
    const vd2 = KeySchedule.computeFinishedVerifyData(secret, transcript);
    try std.testing.expectEqualSlices(u8, &vd, &vd2);

    // Different inputs produce different output
    const vd3 = KeySchedule.computeFinishedVerifyData(secret, .{0x02} ** 32);
    try std.testing.expect(!std.mem.eql(u8, &vd, &vd3));
}

test "buildClientHello: produces valid message" {
    var random: [32]u8 = undefined;
    @memset(&random, 0xAA);
    var pub_key: [32]u8 = undefined;
    @memset(&pub_key, 0xBB);

    const tp = transport_params.TransportParams{
        .initial_max_data = 1048576,
        .initial_max_streams_bidi = 100,
    };

    // Pre-encode transport params. Seeded, not a production generator: the
    // draw is the greased parameter, and a fixed seed makes those bytes the
    // same on every run so a failure here reads as a diff rather than as
    // noise. "grea", for the parameter being greased.
    var tp_prng = std.Random.DefaultPrng.init(0x67726561);
    var tp_enc_buf: [256]u8 = undefined;
    var tp_fbs = io.fixedBufferStream(&tp_enc_buf);
    try tp.encode(&tp_fbs, tp_prng.random());
    const tp_encoded = tp_fbs.buffered();

    var ks = KeySchedule.init();
    var buf: [4096]u8 = undefined;
    var p256_pub: [65]u8 = undefined;
    @memset(&p256_pub, 0xCC);
    const msg = try buildClientHello(
        &buf,
        &random,
        &pub_key,
        &p256_pub,
        &[_][]const u8{"h3"},
        "example.com",
        tp_encoded,
        null,
        &ks,
        null,
        test_now_s,
    );

    // Check message type
    try std.testing.expectEqual(@as(u8, @intFromEnum(tls.HandshakeType.client_hello)), msg[0]);

    // Check length consistency
    const body_len = (@as(usize, msg[1]) << 16) | (@as(usize, msg[2]) << 8) | @as(usize, msg[3]);
    try std.testing.expectEqual(msg.len - 4, body_len);

    // Check legacy_version
    try std.testing.expectEqual(@as(u8, 0x03), msg[4]);
    try std.testing.expectEqual(@as(u8, 0x03), msg[5]);
}

test "buildServerHello: produces valid message" {
    var random: [32]u8 = undefined;
    @memset(&random, 0xCC);
    var pub_key: [32]u8 = undefined;
    @memset(&pub_key, 0xDD);
    var client_random: [32]u8 = undefined;
    @memset(&client_random, 0xAA);

    var buf: [512]u8 = undefined;
    const msg = try buildServerHello(&buf, &random, .x25519, &pub_key, &client_random, false, .aes_128_gcm_sha256);

    try std.testing.expectEqual(@as(u8, @intFromEnum(tls.HandshakeType.server_hello)), msg[0]);
    const body_len = (@as(usize, msg[1]) << 16) | (@as(usize, msg[2]) << 8) | @as(usize, msg[3]);
    try std.testing.expectEqual(msg.len - 4, body_len);
}

test "loopback handshake: client and server complete" {
    // A peer's certificate is a 44-byte SPKI around the node id it owns, so
    // the server presents one and the client pins the id inside it. The pair
    // also has to agree on application secrets, which is the rest of the
    // handshake and the part that is easy to break.
    var server = Identity.init(server_seed);
    server.link();
    var entropy: Counted = .{};
    const tp = transport_params.TransportParams{
        .initial_max_data = 1048576,
        .initial_max_streams_bidi = 100,
    };

    var srv = Tls13Handshake.initServer(.{
        .cert_chain_der = &server.chain,
        .private_key_bytes = &server.seed,
        .private_key_algorithm = .ed25519,
        .alpn = &[_][]const u8{"h3"},
    }, tp, entropy.random());
    var cli = Tls13Handshake.initClient(.{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &[_][]const u8{"h3"},
        .server_name = "localhost",
        .expect_peer_node_id = server.node_id,
    }, tp, entropy.random());
    try driveLoopback(&cli, &srv, entropy.random());

    try std.testing.expectEqual(server.node_id, cli.peerNodeId().?);
    try std.testing.expectEqualSlices(
        u8,
        &cli.key_schedule.client_app_traffic_secret,
        &srv.key_schedule.client_app_traffic_secret,
    );
    try std.testing.expectEqualSlices(
        u8,
        &cli.key_schedule.server_app_traffic_secret,
        &srv.key_schedule.server_app_traffic_secret,
    );
}

test "loopback handshake: the server answers with the one ALPN it chose" {
    var server = Identity.init(server_seed);
    server.link();
    var entropy: Counted = .{};
    const tp = transport_params.TransportParams{ .initial_max_data = 1048576 };

    // Echoing the whole list made quic-go fail the handshake with decode_error.
    var srv = Tls13Handshake.initServer(.{
        .cert_chain_der = &server.chain,
        .private_key_bytes = &server.seed,
        .private_key_algorithm = .ed25519,
        .alpn = &[_][]const u8{ "h3", "moqt-18", "moqt-17" },
    }, tp, entropy.random());
    var cli = Tls13Handshake.initClient(.{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &[_][]const u8{ "moqt-17", "moqt-18" },
        .server_name = "localhost",
        .expect_peer_node_id = server.node_id,
    }, tp, entropy.random());
    try driveLoopback(&cli, &srv, entropy.random());
    // The client's order wins; both sides must agree on it.
    try std.testing.expectEqualStrings("moqt-17", srv.negotiatedAlpn());
    try std.testing.expectEqualStrings("moqt-17", cli.negotiatedAlpn());
}

fn driveLoopback(client: *Tls13Handshake, server: *Tls13Handshake, random: std.Random) !void {
    var client_done = false;
    var server_done = false;
    var iterations: usize = 0;

    while ((!client_done or !server_done) and iterations < 100) {
        iterations += 1;

        // Step client
        if (!client_done) {
            const action = try client.step(test_now_s, random);
            switch (action) {
                .send_data => |sd| {
                    if (sd.level == .initial) {
                        server.provideData(sd.data);
                    } else {
                        server.provideData(sd.data);
                    }
                },
                .install_keys => {},
                .wait_for_data => {},
                .complete => client_done = true,
                ._continue => {},
            }
        }

        // Step server
        if (!server_done) {
            const action = try server.step(test_now_s, random);
            switch (action) {
                .send_data => |sd| {
                    _ = sd;
                    // Server sends at initial level (ServerHello) and handshake level
                    // Route to client input
                    client.provideData(server.out_buf[0..server.out_len]);
                },
                .install_keys => {},
                .wait_for_data => {},
                .complete => server_done = true,
                ._continue => {},
            }
        }
    }

    try std.testing.expect(client_done);
    try std.testing.expect(server_done);
    try std.testing.expect(client.isComplete());
    try std.testing.expect(server.isComplete());
}

// PSK binder computation test
test "PSK binder computation: deterministic and correct" {
    const psk: [32]u8 = .{0x42} ** 32;
    var ks = KeySchedule.initWithPsk(psk);

    // early_secret should differ from zero-PSK init
    var ks_zero = KeySchedule.init();
    try std.testing.expect(!std.mem.eql(u8, &ks.early_secret, &ks_zero.early_secret));
    _ = &ks_zero;

    // binder_key = Derive-Secret(early_secret, "res binder", Hash(""))
    const empty_hash = tls.emptyHash(Sha256);
    const binder_key = quic_crypto.hkdfExpandLabel(ks.early_secret, "res binder", &empty_hash, 32);

    // Compute binder for a fake partial transcript
    const fake_transcript: [32]u8 = .{0x01} ** 32;
    const binder = KeySchedule.computeFinishedVerifyData(binder_key, fake_transcript);

    // Deterministic
    const binder2 = KeySchedule.computeFinishedVerifyData(binder_key, fake_transcript);
    try std.testing.expectEqualSlices(u8, &binder, &binder2);

    // Different transcript produces different binder
    const binder3 = KeySchedule.computeFinishedVerifyData(binder_key, .{0x02} ** 32);
    try std.testing.expect(!std.mem.eql(u8, &binder, &binder3));
}

// Early key derivation test
test "early key derivation: client_early_traffic_secret from PSK" {
    const psk: [32]u8 = .{0xAA} ** 32;
    var ks = KeySchedule.initWithPsk(psk);

    const transcript: [32]u8 = .{0xBB} ** 32;
    ks.deriveEarlyDataSecret(transcript);

    // Should produce a non-zero secret
    try std.testing.expect(!std.mem.eql(u8, &ks.client_early_traffic_secret, &(.{0} ** 32)));

    // Derive QUIC keys from early traffic secret
    const keys = KeySchedule.deriveQuicKeys(ks.client_early_traffic_secret);
    try std.testing.expect(!std.mem.eql(u8, &keys.key, &(.{0} ** 16)));
    try std.testing.expect(!std.mem.eql(u8, &keys.iv, &(.{0} ** 12)));
}

// Loopback PSK resumption test: full handshake → ticket → PSK handshake
test "loopback PSK resumption: two handshakes with session ticket" {
    // A resumption skips the certificate entirely, so the identity the first
    // handshake pinned is the one the second handshake has to reach without
    // seeing it again.
    var server = Identity.init(server_seed);
    server.link();
    var entropy: Counted = .{};
    const ticket_key = TicketKey.generate(entropy.random());

    const server_config = TlsConfig{
        .cert_chain_der = &server.chain,
        .private_key_bytes = &server.seed,
        .private_key_algorithm = .ed25519,
        .alpn = &[_][]const u8{"h3"},
        .resumption = .{ .server = ticket_key },
    };

    const client_config = TlsConfig{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &[_][]const u8{"h3"},
        .server_name = "localhost",
        .expect_peer_node_id = server.node_id,
    };

    const tp = transport_params.TransportParams{
        .initial_max_data = 1048576,
        .initial_max_streams_bidi = 100,
    };

    // ─── First handshake: full (no PSK) ─────────────
    var server1 = Tls13Handshake.initServer(server_config, tp, entropy.random());
    var client1 = Tls13Handshake.initClient(client_config, tp, entropy.random());

    var client_done = false;
    var server_done = false;
    var iterations: usize = 0;

    while ((!client_done or !server_done) and iterations < 100) {
        iterations += 1;

        if (!client_done) {
            const action = try client1.step(test_now_s, entropy.random());
            switch (action) {
                .send_data => |sd| {
                    _ = sd;
                    server1.provideData(client1.out_buf[0..client1.out_len]);
                },
                .install_keys => {},
                .wait_for_data => {},
                .complete => client_done = true,
                ._continue => {},
            }
        }

        if (!server_done) {
            const action = try server1.step(test_now_s, entropy.random());
            switch (action) {
                .send_data => |sd| {
                    _ = sd;
                    // Feed server output to client (including post-handshake NST)
                    client1.provideData(server1.out_buf[0..server1.out_len]);
                },
                .install_keys => {},
                .wait_for_data => {},
                .complete => server_done = true,
                ._continue => {},
            }
        }
    }

    try std.testing.expect(client_done);
    try std.testing.expect(server_done);

    // Step client a few more times to process post-handshake messages (NST)
    var post_hs: usize = 0;
    while (post_hs < 10) : (post_hs += 1) {
        const action = try client1.step(test_now_s, entropy.random());
        switch (action) {
            .complete => break,
            ._continue => continue,
            else => break,
        }
    }

    // Client should have received a session ticket
    try std.testing.expect(client1.received_ticket != null);
    const ticket = client1.received_ticket.?;
    try std.testing.expect(ticket.ticket_len > 0);
    try std.testing.expect(ticket.lifetime > 0);

    // ─── Second handshake: PSK resumption ─────────────
    var psk_client_config = client_config;
    psk_client_config.resumption = .{ .client = &ticket };

    var server2 = Tls13Handshake.initServer(server_config, tp, entropy.random());
    var client2 = Tls13Handshake.initClient(psk_client_config, tp, entropy.random());

    client_done = false;
    server_done = false;
    iterations = 0;
    var client_got_early_keys = false;
    var server_got_early_keys = false;
    var server_used_psk = false;

    while ((!client_done or !server_done) and iterations < 100) {
        iterations += 1;

        if (!client_done) {
            const action = try client2.step(test_now_s, entropy.random());
            switch (action) {
                .send_data => |sd| {
                    _ = sd;
                    server2.provideData(client2.out_buf[0..client2.out_len]);
                },
                .install_keys => |ik| {
                    if (ik.level == .early_data) client_got_early_keys = true;
                },
                .wait_for_data => {},
                .complete => client_done = true,
                ._continue => {},
            }
        }

        if (!server_done) {
            const action = try server2.step(test_now_s, entropy.random());
            switch (action) {
                .send_data => |sd| {
                    _ = sd;
                    client2.provideData(server2.out_buf[0..server2.out_len]);
                },
                .install_keys => |ik| {
                    if (ik.level == .early_data) server_got_early_keys = true;
                },
                .wait_for_data => {},
                .complete => server_done = true,
                ._continue => {},
            }
        }
    }

    try std.testing.expect(client_done);
    try std.testing.expect(server_done);

    // Verify PSK was used (server skipped cert)
    server_used_psk = server2.using_psk;
    try std.testing.expect(server_used_psk);
    try std.testing.expect(client2.using_psk);

    // Early keys should have been installed on both sides
    try std.testing.expect(client_got_early_keys);
    try std.testing.expect(server_got_early_keys);

    // Both sides should have matching app secrets
    try std.testing.expectEqualSlices(
        u8,
        &client2.key_schedule.client_app_traffic_secret,
        &server2.key_schedule.client_app_traffic_secret,
    );
    try std.testing.expectEqualSlices(
        u8,
        &client2.key_schedule.server_app_traffic_secret,
        &server2.key_schedule.server_app_traffic_secret,
    );
}

// NewSessionTicket roundtrip test
test "NewSessionTicket: build and parse roundtrip" {
    const psk: [32]u8 = .{0x55} ** 32;
    const ticket_data = [_]u8{0xAA} ** 64;

    // Build a SessionTicket manually
    var original = SessionTicket{ .psk = psk };
    original.lifetime = 86400;
    original.ticket_age_add = 0x12345678;
    original.creation_time = test_now_s;
    original.max_early_data_size = 0xffffffff;
    @memcpy(original.ticket[0..64], &ticket_data);
    original.ticket_len = 64;
    @memcpy(original.alpn[0..2], "h3");
    original.alpn_len = 2;

    // Verify accessors
    try std.testing.expectEqual(@as(u16, 64), original.ticket_len);
    try std.testing.expectEqualSlices(u8, "h3", original.getAlpn());
    try std.testing.expect(!original.isExpired(test_now_s));
    // The creation time is a second on whatever clock stamped it, and
    // `isExpired` compares against one passed in rather than one read, so the
    // base is the caller's business and only the difference is used here.
    try std.testing.expect(original.isExpired(test_now_s + original.lifetime + 1));

    // Verify PSK is stored correctly
    try std.testing.expectEqualSlices(u8, &psk, &original.psk);
}

test "server: early_data in EncryptedExtensions only answers a client that offered it" {
    var buf: [512]u8 = undefined;
    const alpn = [_][]const u8{"h3"};

    const without = try buildEncryptedExtensionsFromEncoded(&buf, &alpn, &.{}, false);
    const len_without = without.len;

    var buf2: [512]u8 = undefined;
    const with = try buildEncryptedExtensionsFromEncoded(&buf2, &alpn, &.{}, true);

    // The extension is 4 bytes of header and no payload (RFC 8446 §4.2.10).
    try std.testing.expectEqual(len_without + 4, with.len);
}

test "client answers a CertificateRequest with an empty Certificate" {
    // Cloudflare's edge asks for a client certificate — cdn.moq.dev failed
    // here with UnexpectedMessage — and RFC 8446 4.4.2 says the answer is a
    // Certificate message even with nothing to put in it.
    var entropy: Counted = .{};
    var client = Tls13Handshake.initClient(.{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &[_][]const u8{"h3"},
        .server_name = "localhost",
    }, .{}, entropy.random());

    client.state = .client_wait_certificate;
    client.provideData(&[_]u8{
        0x0d, 0x00, 0x00, 0x1d, // CertificateRequest, 29 bytes
        0x00, // certificate_request_context: empty
        0x00, 0x1a, // extensions, 26 bytes
        0x00, 0x0d, 0x00, 0x16, 0x00, 0x14, // signature_algorithms, 10 of them
        0x05, 0x03, 0x04, 0x03, 0x08, 0x07,
        0x08, 0x06, 0x08, 0x05, 0x08, 0x04,
        0x06, 0x01, 0x05, 0x01, 0x04, 0x01,
        0x02, 0x01,
    });

    try std.testing.expect(try client.step(test_now_s, entropy.random()) == ._continue);
    try std.testing.expect(client.certificate_requested);

    // The empty Certificate goes out ahead of Finished and into the
    // transcript with it, or the server rejects our Finished.
    client.state = .client_send_finished;
    const action = try client.step(test_now_s, entropy.random());
    const out = action.send_data.data;

    try std.testing.expectEqual(@as(usize, 8 + 36), out.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x0b, 0, 0, 4, 0, 0, 0, 0 }, out[0..8]);
    try std.testing.expectEqual(@intFromEnum(tls.HandshakeType.finished), out[8]);
}

test "client without a CertificateRequest sends only Finished" {
    var entropy: Counted = .{};
    var client = Tls13Handshake.initClient(.{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &[_][]const u8{"h3"},
        .server_name = "localhost",
    }, .{}, entropy.random());

    client.state = .client_send_finished;
    const action = try client.step(test_now_s, entropy.random());
    try std.testing.expectEqual(@as(usize, 36), action.send_data.data.len);
}

test "the *Into constructors leave no bool to chance" {
    // They assign field by field onto memory the caller allocated, so a field
    // added with a default is silently never written. certificate_requested
    // read as garbage that way and made the client answer a CertificateRequest
    // no server had sent — which only showed up on one platform, because the
    // byte happened to be zero on the other.
    const config = TlsConfig{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &[_][]const u8{"h3"},
        .server_name = "localhost",
    };

    const hs = try std.testing.allocator.create(Tls13Handshake);
    var entropy: Counted = .{};
    defer std.testing.allocator.destroy(hs);

    inline for (.{ true, false }) |server| {
        // 0x01, not a poison byte: an uninitialised bool has to read back
        // as a *valid* `true` for the assertion below to mean anything.
        @memset(std.mem.asBytes(hs), 0x01);
        if (server) {
            Tls13Handshake.initServerInto(hs, config, .{}, entropy.random());
        } else {
            Tls13Handshake.initClientInto(hs, config, .{}, entropy.random());
        }

        inline for (@typeInfo(Tls13Handshake).@"struct".fields) |f| {
            if (f.type == bool and !std.mem.eql(u8, f.name, "is_server")) {
                if (comptime f.defaultValue()) |dflt| {
                    try std.testing.expectEqual(dflt, @field(hs, f.name));
                }
            }
        }
        try std.testing.expectEqual(server, hs.is_server);
    }
}

// ─── Peer identity fixtures ───────────────────────────────────────────

/// Two Ed25519 seeds, one per end. Fixed, so every run names the same two
/// nodes and a failing assertion can be read straight off the bytes.
const server_seed: [32]u8 = @splat(0x53);
const client_seed: [32]u8 = @splat(0x43);

/// The node id a seed owns. `generateDeterministic` fails only on a
/// degenerate seed, which a fixed byte pattern is not.
fn nodeIdOf(seed: [32]u8) [32]u8 {
    const kp = Ed25519.KeyPair.generateDeterministic(seed) catch unreachable;
    return kp.public_key.toBytes();
}

/// A generator that counts what it is asked for, so a test can say that
/// signing an Ed25519 CertificateVerify drew nothing.
const Counted = struct {
    inner: std.Random.DefaultPrng = .init(0xc0ffee),
    drawn: usize = 0,

    fn fill(self: *@This(), buf: []u8) void {
        self.drawn += 1;
        self.inner.random().bytes(buf);
    }

    fn random(self: *@This()) std.Random {
        return std.Random.init(self, fill);
    }
};

/// A second on the caller's clock, for the handshakes below. Fixed on
/// purpose: nothing in this file may reach the real clock, and the ticket age
/// arithmetic is all differences, so one frozen instant drives them all.
const test_now_s: i64 = 1_788_000_000;

/// A node: the key it owns, the 44 bytes it presents, the seed behind them,
/// and the one-element chain it presents them in.
const Identity = struct {
    seed: [32]u8,
    node_id: [32]u8,
    spki: [ed25519_spki_len]u8,
    chain: [1][]const u8 = [_][]const u8{&.{}},

    fn init(seed: [32]u8) Identity {
        const node_id = nodeIdOf(seed);
        return .{ .seed = seed, .node_id = node_id, .spki = ed25519Spki(&node_id) };
    }

    /// Point this node's chain at its own 44 bytes, and call it on a `var`
    /// that outlives the handshake. Separate from `init` because a `var self`
    /// inside `init` is a temporary: a `ServerCertificate` built over a list
    /// literal points at the literal, so a chain wired there segfaults the
    /// first time a flight is built.
    fn link(self: *Identity) void {
        self.chain[0] = &self.spki;
    }

    /// What this node presents, and the key behind it. Borrows `self`.
    fn certificate(self: *const Identity) ServerCertificate {
        return .{
            .cert_chain_der = &self.chain,
            .private_key_bytes = &self.seed,
            .private_key_algorithm = .ed25519,
        };
    }
};

const DriveError = HandshakeError || error{ HandshakeStalled, OutOfMemory };

/// Drives a handshake to completion, returning the error the first end that
/// refused with, or `error.HandshakeStalled` when neither finished. On
/// success the server's view of the client certificate, if it asked for one,
/// lands in `peer_cert_out`.
///
/// `peer_buf` has to be as long as the longest certificate the client may
/// present: the server's copy is written into it, not allocated.
fn handshake(
    gpa: std.mem.Allocator,
    client_config: TlsConfig,
    server_config: TlsConfig,
    peer_cert_out: *?[]const u8,
    peer_buf: []u8,
) DriveError!?HandshakeError {
    const tp = transport_params.TransportParams{ .initial_max_data = 1 << 20, .initial_max_streams_bidi = 10 };
    const server = try gpa.create(Tls13Handshake);
    defer gpa.destroy(server);
    const client = try gpa.create(Tls13Handshake);
    defer gpa.destroy(client);
    var entropy: Counted = .{};

    Tls13Handshake.initServerInto(server, server_config, tp, entropy.random());
    server.allocator = gpa;
    defer server.deinit();
    Tls13Handshake.initClientInto(client, client_config, tp, entropy.random());

    var client_done = false;
    var server_done = false;
    var i: usize = 0;
    while ((!client_done or !server_done) and i < 100) : (i += 1) {
        if (!client_done) {
            const action = client.step(test_now_s, entropy.random()) catch |err| return refused(err);
            switch (action) {
                .send_data => |sd| server.provideData(sd.data),
                .complete => client_done = true,
                else => {},
            }
        }
        if (!server_done) {
            const action = server.step(test_now_s, entropy.random()) catch |err| return refused(err);
            switch (action) {
                .send_data => client.provideData(server.out_buf[0..server.out_len]),
                .complete => server_done = true,
                else => {},
            }
        }
    }
    if (!client_done or !server_done) return error.HandshakeStalled;

    peer_cert_out.* = null;
    if (server.peerCertificate()) |c| {
        @memcpy(peer_buf[0..c.len], c);
        peer_cert_out.* = peer_buf[0..c.len];
    }
    return null;
}

/// The refusal a handshake reported, as a value to compare against. The
/// result of `handshake` is an optional because Zig has no error union with an
/// error-set payload, and spelling the optional at every call site is worse
/// than naming it once.
fn refused(err: HandshakeError) ?HandshakeError {
    return err;
}

/// The client half of a handshake: expects `server_node`, and answers a
/// CertificateRequest with `client`'s own identity.
fn clientConfig(expect_server: [32]u8, client: *const Identity) TlsConfig {
    return .{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &[_][]const u8{"h3"},
        .server_name = "relay.test",
        .expect_peer_node_id = expect_server,
        .client_certificate = client.certificate(),
    };
}

/// The server half: serves `entries` and judges a client certificate with
/// `auth`. The policy goes on every entry as well as on the config, because
/// a server with a certificate list takes the selected entry's policy and
/// ignores the config's — see `TlsConfig.client_auth`.
fn serverConfig(entries: []CertEntry, auth: *const ClientAuth) TlsConfig {
    for (entries) |*e| e.client_auth = auth;
    return .{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .certs = entries,
        .alpn = &[_][]const u8{"h3"},
        .client_auth = auth,
    };
}

/// One connection's two ends, built from configs and kept so a test can
/// read what they made of it afterwards. 52 KB apiece, so they are heap.
const Ends = struct {
    server: *Tls13Handshake,
    client: *Tls13Handshake,

    fn init(gpa: std.mem.Allocator, cc: TlsConfig, sc: TlsConfig, random: std.Random) !Ends {
        const tp = transport_params.TransportParams{
            .initial_max_data = 1 << 20,
            .initial_max_streams_bidi = 10,
        };
        const server = try gpa.create(Tls13Handshake);
        errdefer gpa.destroy(server);
        const client = try gpa.create(Tls13Handshake);
        Tls13Handshake.initServerInto(server, sc, tp, random);
        server.allocator = gpa;
        Tls13Handshake.initClientInto(client, cc, tp, random);
        return .{ .server = server, .client = client };
    }

    fn deinit(self: *Ends, gpa: std.mem.Allocator) void {
        self.server.deinit();
        gpa.destroy(self.server);
        gpa.destroy(self.client);
    }
};

/// Drives one connection to completion and then pumps the NewSessionTicket
/// that follows it, which is where the client's ticket comes from — so the
/// caller does not have to know that the ticket is a post-handshake message
/// rather than part of the handshake. Returns the first refusal, as
/// `handshake` does.
fn connect(ends: *Ends, random: std.Random) DriveError!?HandshakeError {
    var client_done = false;
    var server_done = false;
    var i: usize = 0;
    while ((!client_done or !server_done) and i < 100) : (i += 1) {
        if (!client_done) {
            const action = ends.client.step(test_now_s, random) catch |err| return refused(err);
            switch (action) {
                .send_data => |sd| ends.server.provideData(sd.data),
                .complete => client_done = true,
                else => {},
            }
        }
        if (!server_done) {
            const action = ends.server.step(test_now_s, random) catch |err| return refused(err);
            switch (action) {
                .send_data => ends.client.provideData(ends.server.out_buf[0..ends.server.out_len]),
                .complete => server_done = true,
                else => {},
            }
        }
    }
    if (!client_done or !server_done) return error.HandshakeStalled;

    var post: usize = 0;
    while (post < 8) : (post += 1) {
        const action = ends.client.step(test_now_s, random) catch |err| return refused(err);
        switch (action) {
            ._continue => continue,
            else => break,
        }
    }
    return null;
}

test "a pinned client resumes, and the pin holds on the resumed connection" {
    const gpa = std.testing.allocator;
    var server = Identity.init(server_seed);
    server.link();
    var client = Identity.init(client_seed);
    client.link();
    var entropy: Counted = .{};
    const random = entropy.random();

    // One key for the server's whole life, drawn once. This is the value
    // DECISIONS/0001 item 1 is about: a key drawn per connection seals
    // tickets nothing can reopen, and the connection that follows does not
    // say so.
    const ticket_key = TicketKey.generate(random);
    var auth: ClientAuth = .{ .expect_node_id = client.node_id, .mode = .required };
    var entries = [_]CertEntry{.{ .server_names = &.{}, .cert = server.certificate() }};
    var server_config = serverConfig(&entries, &auth);
    server_config.resumption = .{ .server = ticket_key };

    // First connection: a full handshake, and the ticket it leaves behind.
    var first = try Ends.init(gpa, clientConfig(server.node_id, &client), server_config, random);
    defer first.deinit(gpa);
    try std.testing.expect((try connect(&first, random)) == null);
    try std.testing.expect(!first.server.using_psk);
    try std.testing.expectEqual(client.node_id, first.server.peerNodeId().?);
    const ticket = first.client.received_ticket orelse return error.HandshakeStalled;

    // Second connection under the same key. The server's certificate is not
    // on the wire this time, and that is what makes the second connection
    // observably not a full handshake: the client's own pin on the server
    // survives it, which it could not if there were a certificate left to
    // compare against.
    var resuming = clientConfig(server.node_id, &client);
    resuming.resumption = .{ .client = &ticket };
    var second = try Ends.init(gpa, resuming, server_config, random);
    defer second.deinit(gpa);
    try std.testing.expect((try connect(&second, random)) == null);
    try std.testing.expect(second.server.using_psk);
    try std.testing.expect(second.client.using_psk);
    try std.testing.expect(second.client.peerNodeId() == null);

    // And the client is not authenticated by the ticket. A resumed
    // connection asks for the certificate exactly as a full one does, and
    // the answer is what the pin is compared against.
    try std.testing.expect(second.client.certificate_requested);
    try std.testing.expectEqual(client.node_id, second.server.peerNodeId().?);
    try std.testing.expectEqual(ed25519_spki_len, second.server.peerCertificate().?.len);
}

test "a ticket the server's current key cannot open is refused, not resumed" {
    const gpa = std.testing.allocator;
    var server = Identity.init(server_seed);
    server.link();
    var client = Identity.init(client_seed);
    client.link();
    var entropy: Counted = .{};
    const random = entropy.random();
    var auth: ClientAuth = .{ .expect_node_id = client.node_id, .mode = .required };
    var entries = [_]CertEntry{.{ .server_names = &.{}, .cert = server.certificate() }};

    var issued = serverConfig(&entries, &auth);
    issued.resumption = .{ .server = TicketKey.generate(random) };
    var first = try Ends.init(gpa, clientConfig(server.node_id, &client), issued, random);
    defer first.deinit(gpa);
    try std.testing.expect((try connect(&first, random)) == null);
    const ticket = first.client.received_ticket orelse return error.HandshakeStalled;

    // The key rotates, as a server's does when it restarts or an operator
    // replaces it, and the ticket cannot be opened under the new one.
    var rotated = serverConfig(&entries, &auth);
    rotated.resumption = .{ .server = TicketKey.generate(random) };
    var resuming = clientConfig(server.node_id, &client);
    resuming.resumption = .{ .client = &ticket };
    var second = try Ends.init(gpa, resuming, rotated, random);
    defer second.deinit(gpa);
    // Refusing the ticket is the server's answer, and this is what it looks
    // like: the connection does not resume and it does not complete. The
    // client offered a PSK and the server declined it, and this stack has
    // one handshake schedule rather than two, so the client verifies the
    // server's Finished against the schedule it committed to and refuses
    // it. What item 1 exists to prevent is the opposite outcome — both ends
    // believing they had resumed when they had not — and `using_psk` is
    // where that would show.
    try std.testing.expectEqual(refused(error.BadFinished), try connect(&second, random));
    try std.testing.expect(!second.server.using_psk);
    try std.testing.expect(!second.server.isComplete());
    try std.testing.expect(!second.client.isComplete());
}

test "a resumed connection with a pin in force cannot complete without a certificate" {
    const gpa = std.testing.allocator;
    var server = Identity.init(server_seed);
    server.link();
    var client = Identity.init(client_seed);
    client.link();
    var entropy: Counted = .{};
    const random = entropy.random();
    var auth: ClientAuth = .{ .expect_node_id = client.node_id, .mode = .required };
    var entries = [_]CertEntry{.{ .server_names = &.{}, .cert = server.certificate() }};
    var server_config = serverConfig(&entries, &auth);
    server_config.resumption = .{ .server = TicketKey.generate(random) };

    var first = try Ends.init(gpa, clientConfig(server.node_id, &client), server_config, random);
    defer first.deinit(gpa);
    try std.testing.expect((try connect(&first, random)) == null);
    const ticket = first.client.received_ticket orelse return error.HandshakeStalled;

    // The client resumes and has no certificate to answer the
    // CertificateRequest with. The PSK is accepted — `using_psk` says so,
    // and it is the acceptance that used to be the bypass — and the
    // handshake then stops at the request rather than reaching the end with
    // a pin in force and nothing to compare it against. This is item 4.
    var anonymous = clientConfig(server.node_id, &client);
    anonymous.client_certificate = null;
    anonymous.resumption = .{ .client = &ticket };
    var ends = try Ends.init(gpa, anonymous, server_config, random);
    defer ends.deinit(gpa);
    try std.testing.expectEqual(refused(error.CertificateRequired), try connect(&ends, random));
    try std.testing.expect(ends.server.using_psk);
    try std.testing.expect(ends.client.certificate_requested);
    try std.testing.expect(ends.server.peerNodeId() == null);
    try std.testing.expect(!ends.server.isComplete());
}

test "a ticket and the key that opens it are one value" {
    const gpa = std.testing.allocator;
    var server = Identity.init(server_seed);
    server.link();
    var client = Identity.init(client_seed);
    client.link();
    var entropy: Counted = .{};
    const random = entropy.random();
    var auth: ClientAuth = .{ .expect_node_id = client.node_id };
    var entries = [_]CertEntry{.{ .server_names = &.{}, .cert = server.certificate() }};

    // A ticket on the server side is not a key, and the handshake says so
    // rather than leaving a caller to find out: the server issues nothing,
    // so the client is left holding no ticket and the next connection
    // cannot resume. Before `Resumption` these were two fields and the
    // pairing was expressible — a ticket in one, a key in the other,
    // neither of them noticing.
    var held: SessionTicket = .{ .psk = .{0x55} ** 32 };
    var config = serverConfig(&entries, &auth);
    config.resumption = .{ .client = &held };
    try std.testing.expect(Resumption.serverKey(config.resumption) == null);

    var ends = try Ends.init(gpa, clientConfig(server.node_id, &client), config, random);
    defer ends.deinit(gpa);
    try std.testing.expect((try connect(&ends, random)) == null);
    try std.testing.expect(ends.client.received_ticket == null);
    // The connection is still authenticated; refusing the ticket costs a
    // resumption, not a handshake.
    try std.testing.expectEqual(client.node_id, ends.server.peerNodeId().?);
}

test "a 44-byte Ed25519 SPKI is a peer certificate in both directions" {
    const gpa = std.testing.allocator;
    var server = Identity.init(server_seed);
    server.link();
    var client = Identity.init(client_seed);
    client.link();
    var auth: ClientAuth = .{ .expect_node_id = client.node_id };
    var entries = [_]CertEntry{.{ .server_names = &.{}, .cert = server.certificate() }};
    var peer: ?[]const u8 = null;
    var buf: [ed25519_spki_len]u8 = undefined;

    // The claim the whole certificate model rests on: 44 bytes, the last 32
    // of them the node id.
    try std.testing.expectEqual(@as(usize, 44), server.spki.len);
    try std.testing.expectEqualSlices(u8, &server.node_id, server.spki[12..]);

    try std.testing.expectEqual(null, try handshake(
        gpa,
        clientConfig(server.node_id, &client),
        serverConfig(&entries, &auth),
        &peer,
        &buf,
    ));

    // The server's view of the client is the client's own 44 bytes. The dialer
    // presented a certificate too, and the server pinned it.
    try std.testing.expectEqualSlices(u8, &client.spki, peer.?);
}

test "a peer whose key is one byte off is refused, and so is one that cannot sign" {
    const gpa = std.testing.allocator;
    var server = Identity.init(server_seed);
    server.link();
    var client = Identity.init(client_seed);
    client.link();
    var stranger = Identity.init(@splat(0x99));
    stranger.link();
    var auth: ClientAuth = .{ .expect_node_id = client.node_id };
    var peer: ?[]const u8 = null;
    var buf: [ed25519_spki_len]u8 = undefined;

    // One flipped bit in the key the server presents. The CertificateVerify
    // it sends is valid for the key it really holds, so nothing but the
    // comparison against the id the client asked for catches this.
    var flipped = server;
    flipped.spki[43] ^= 1;
    flipped.link();
    var flipped_entries = [_]CertEntry{.{ .server_names = &.{}, .cert = flipped.certificate() }};
    try std.testing.expectEqual(refused(error.BadCertificate), try handshake(
        gpa,
        clientConfig(server.node_id, &client),
        serverConfig(&flipped_entries, &auth),
        &peer,
        &buf,
    ));

    // The same flip on the other side of the comparison: the id the client
    // expects is not the key the server has.
    var wrong_pin = server.node_id;
    wrong_pin[0] ^= 0x80;
    var entries = [_]CertEntry{.{ .server_names = &.{}, .cert = server.certificate() }};
    try std.testing.expectEqual(refused(error.BadCertificate), try handshake(
        gpa,
        clientConfig(wrong_pin, &client),
        serverConfig(&entries, &auth),
        &peer,
        &buf,
    ));

    // The right key in the certificate and a different key behind the
    // CertificateVerify. Only the signature check catches this, and reaching
    // it is the whole reason `verifyCertificateVerifySignature`'s `.ed25519`
    // arm has to be live for a raw SPKI rather than skipped.
    const impostor = ServerCertificate{
        .cert_chain_der = &server.chain,
        .private_key_bytes = &stranger.seed,
        .private_key_algorithm = .ed25519,
    };
    var impostor_entries = [_]CertEntry{.{ .server_names = &.{}, .cert = impostor }};
    try std.testing.expectEqual(refused(error.BadCertificateVerify), try handshake(
        gpa,
        clientConfig(server.node_id, &client),
        serverConfig(&impostor_entries, &auth),
        &peer,
        &buf,
    ));

    // And the client side of the same question: a client that answers a
    // CertificateRequest with somebody else's key is refused the same way.
    const borrowed = ServerCertificate{
        .cert_chain_der = &stranger.chain,
        .private_key_bytes = &client.seed,
        .private_key_algorithm = .ed25519,
    };
    var borrowed_client = clientConfig(server.node_id, &client);
    borrowed_client.client_certificate = borrowed;
    try std.testing.expectEqual(refused(error.BadCertificate), try handshake(
        gpa,
        borrowed_client,
        serverConfig(&entries, &auth),
        &peer,
        &buf,
    ));
}

test "a certificate that is not a raw Ed25519 SPKI is a bad certificate" {
    const gpa = std.testing.allocator;
    var server = Identity.init(server_seed);
    server.link();
    var client = Identity.init(client_seed);
    client.link();
    var auth: ClientAuth = .{ .expect_node_id = client.node_id };
    var peer: ?[]const u8 = null;
    var buf: [2048]u8 = undefined;

    // A well-formed DER SubjectPublicKeyInfo naming P-256, with a real
    // public key in it and a real ECDSA signature behind it. Everything an
    // X.509 certificate would carry except the certificate: 91 bytes where
    // this stack lifts 44, and an algorithm in the middle that is not
    // Ed25519.
    var x509: P256Cert = undefined;
    x509.init(std.testing.io);
    x509.link();
    var x509_entries = [_]CertEntry{.{ .server_names = &.{}, .cert = x509.certificate() }};
    try std.testing.expectEqual(refused(error.BadCertificate), try handshake(
        gpa,
        clientConfig(server.node_id, &client),
        serverConfig(&x509_entries, &auth),
        &peer,
        &buf,
    ));

    // 65 bytes of uncompressed P-256 point: what the in-process harness used
    // to present, and what passed only because nothing was ever checked.
    const kp = EcdsaP256Sha256.KeyPair.generate(std.testing.io);
    const secret = kp.secret_key.toBytes();
    const point = kp.public_key.toUncompressedSec1();
    const point_chain = [_][]const u8{&point};
    const point_cert = ServerCertificate{ .cert_chain_der = &point_chain, .private_key_bytes = &secret };
    var point_entries = [_]CertEntry{.{ .server_names = &.{}, .cert = point_cert }};
    try std.testing.expectEqual(refused(error.BadCertificate), try handshake(
        gpa,
        clientConfig(server.node_id, &client),
        serverConfig(&point_entries, &auth),
        &peer,
        &buf,
    ));

    // The same question the other way round, with the server asking: a client
    // certificate that is not a raw SPKI is refused just as firmly, and the
    // 44 bytes the server does get are what the pin is compared against.
    var point_client = clientConfig(server.node_id, &client);
    point_client.client_certificate = point_cert;
    var good_entries = [_]CertEntry{.{ .server_names = &.{}, .cert = server.certificate() }};
    try std.testing.expectEqual(refused(error.BadCertificate), try handshake(
        gpa,
        point_client,
        serverConfig(&good_entries, &auth),
        &peer,
        &buf,
    ));
}

test "liftEd25519Spki: the 44 bytes, and every way of not being them" {
    const key: [32]u8 = @splat(0x2b);
    const der = ed25519Spki(&key);

    // The prefix is the claim the identity model makes about DER, so it is
    // pinned here rather than left to whatever the encoder happens to emit.
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00,
    }, der[0..12]);
    try std.testing.expectEqual(key, try liftEd25519Spki(&der));

    // Another key in the same shape lifts to that key and no other.
    const other: [32]u8 = @splat(0x2c);
    try std.testing.expectEqual(other, try liftEd25519Spki(&ed25519Spki(&other)));

    // Every truncation, and one byte more, is malformed. So is no bytes.
    for (0..der.len) |n| {
        try std.testing.expectError(error.MalformedSubjectPublicKeyInfo, liftEd25519Spki(der[0..n]));
    }
    var longer: [ed25519_spki_len + 1]u8 = undefined;
    @memcpy(longer[0..der.len], &der);
    longer[ed25519_spki_len] = 0;
    try std.testing.expectError(error.MalformedSubjectPublicKeyInfo, liftEd25519Spki(&longer));
    try std.testing.expectError(error.MalformedSubjectPublicKeyInfo, liftEd25519Spki(&.{}));

    // A well-formed SPKI naming another algorithm is a different refusal from
    // malformed DER, and is refused just as firmly. 1.3.101.113 is Ed448: the
    // same arc, the same OID length, so the 44 bytes are untouched.
    var wrong_alg = der;
    wrong_alg[8] = 0x6E;
    try std.testing.expectError(error.UnsupportedSubjectPublicKeyInfo, liftEd25519Spki(&wrong_alg));

    // 44 bytes that are not an SPKI. Each case names one thing the structure
    // has to be true of, so a decoder that stopped checking any one of them
    // fails here: the outer tag, the outer length, the AlgorithmIdentifier's
    // tag, its length, the OID's length, something that is not a BIT STRING,
    // a BIT STRING of the wrong size, and a key that claims unused bits.
    const broken_cases = [_]struct { at: usize, to: u8 }{
        .{ .at = 0, .to = 0x31 },
        .{ .at = 1, .to = 0x2B },
        .{ .at = 2, .to = 0x31 },
        .{ .at = 3, .to = 0x07 },
        .{ .at = 4, .to = 0x07 },
        .{ .at = 5, .to = 0x07 },
        .{ .at = 9, .to = 0x04 },
        .{ .at = 10, .to = 0x20 },
        .{ .at = 11, .to = 0x01 },
    };
    for (broken_cases) |c| {
        var broken = der;
        broken[c.at] = c.to;
        try std.testing.expectError(error.MalformedSubjectPublicKeyInfo, liftEd25519Spki(&broken));
    }
}

test "an Ed25519 CertificateVerify is signed without drawing anything" {
    // RFC 8032 derives the nonce from the key and the message, so the
    // deterministic signature needs no draw — and the deterministic path is
    // the only one an iroh peer ever takes. Upstream drew 32 bytes before it
    // knew which scheme it was signing with, so the draw happened on this path
    // too; a test that merely passed would not have noticed, which is why
    // this one counts.
    const label = "TLS 1.3, server CertificateVerify";
    var content: [64 + label.len + 1]u8 = undefined;
    @memset(content[0..64], 0x20);
    @memcpy(content[64..][0..label.len], label);
    content[64 + label.len] = 0x00;

    const node_id = nodeIdOf(server_seed);
    var out: [rsa.max_signature_len]u8 = undefined;

    var ed: Counted = .{};
    const sig = try signCertificateVerify(.ed25519, &server_seed, &content, &out, ed.random());
    try std.testing.expectEqual(Ed25519.Signature.encoded_length, sig.len);
    try std.testing.expectEqual(@as(usize, 0), ed.drawn);

    // P-256 is the one scheme here that needs a fresh nonce, and it takes
    // exactly one — so the count above is the algorithm's doing, not a
    // generator that happens to be quiet.
    const p256_seed: [32]u8 = @splat(0x11);
    // A buffer of its own: `sig` is a slice into `out`, and overwriting that
    // would leave the assertion below verifying nothing.
    var p256_out: [rsa.max_signature_len]u8 = undefined;
    var p256: Counted = .{};
    _ = try signCertificateVerify(.ecdsa_secp256r1_sha256, &p256_seed, &content, &p256_out, p256.random());
    try std.testing.expectEqual(@as(usize, 1), p256.drawn);

    // And the signature is the lifted key's own, which is the check a peer
    // makes on it.
    try verifyCertificateVerifySignature(
        &node_id,
        lifted_key_algo,
        @intFromEnum(tls.SignatureScheme.ed25519),
        sig,
        &content,
    );
}

test "a peer's certificate bytes are read, never trusted, whatever they say" {
    // `certificateWellFormed` used to stand in front of std's X.509 parser so
    // that a lying certificate could not index out of bounds. There is no
    // X.509 parser left to stand in front of, and the invariant is stronger
    // than the one it protected: a corrupted certificate either lifts the
    // bytes it actually carries or is a declared error, and never crashes.
    const der = ed25519Spki(&nodeIdOf(server_seed));
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const r = prng.random();
    var buf: [ed25519_spki_len]u8 = undefined;
    var lifted_count: usize = 0;
    var refused_count: usize = 0;
    for (0..5000) |_| {
        @memcpy(&buf, &der);
        for (0..r.intRangeAtMost(usize, 1, 4)) |_| {
            buf[r.uintLessThan(usize, buf.len)] = r.int(u8);
        }
        const len = r.intRangeAtMost(usize, buf.len / 2, buf.len);
        if (liftEd25519Spki(buf[0..len])) |lifted| {
            lifted_count += 1;
            // What it lifts is the bytes it carries, and no others: the last
            // 32 of a 44-byte SPKI, which is only reachable at full length.
            try std.testing.expectEqualSlices(u8, buf[12..len], &lifted);
        } else |err| {
            try std.testing.expect(err == error.MalformedSubjectPublicKeyInfo or
                err == error.UnsupportedSubjectPublicKeyInfo);
            refused_count += 1;
        }
    }
    // Neither outcome may be vacuous: a run that corrupted nothing, or that
    // only ever hit the key, would satisfy the assertions above on its own.
    try std.testing.expect(lifted_count > 0);
    try std.testing.expect(refused_count > 0);
}

test "a QUIC server picks its certificate by SNI, and the pin says which" {
    const gpa = std.testing.allocator;
    var server = Identity.init(server_seed);
    server.link();
    var other = Identity.init(@splat(0x7e));
    other.link();
    var client = Identity.init(client_seed);
    client.link();
    var auth: ClientAuth = .{ .expect_node_id = client.node_id };
    var peer: ?[]const u8 = null;
    var buf: [ed25519_spki_len]u8 = undefined;

    // The SNI that matches the wildcard gets the certificate the client
    // pinned, so the handshake finishes; a name that matches the other entry
    // gets a certificate the client did not ask for, so it does not.
    var by_name = [_]CertEntry{
        .{ .server_names = &.{"other.test"}, .cert = other.certificate() },
        .{ .server_names = &.{"*.test"}, .cert = server.certificate() },
    };
    try std.testing.expectEqual(null, try handshake(
        gpa,
        clientConfig(server.node_id, &client),
        serverConfig(&by_name, &auth),
        &peer,
        &buf,
    ));

    // Nothing here matches relay.test, so the default entry is served, and
    // the default is a certificate the client did not ask for.
    var wrong_default = [_]CertEntry{
        .{ .server_names = &.{"unrelated.example"}, .cert = other.certificate() },
        .{ .server_names = &.{"other.test"}, .cert = server.certificate() },
    };
    try std.testing.expectEqual(refused(error.BadCertificate), try handshake(
        gpa,
        clientConfig(server.node_id, &client),
        serverConfig(&wrong_default, &auth),
        &peer,
        &buf,
    ));
}

test "selectCertificate: exact, then one-label wildcard, then the first entry" {
    const cert: ServerCertificate = .{ .cert_chain_der = &.{}, .private_key_bytes = &.{} };
    const entries = [_]CertEntry{
        .{ .server_names = &.{"default.test"}, .cert = cert },
        .{ .server_names = &.{"*.example.com"}, .cert = cert },
        .{ .server_names = &.{ "api.example.com", "Other.Test" }, .cert = cert },
    };
    const T = struct {
        fn pick(e: []const CertEntry, sni: ?[]const u8) struct { usize, bool } {
            const sel = selectCertificate(e, sni).?;
            return .{ (@intFromPtr(sel.entry) - @intFromPtr(e.ptr)) / @sizeOf(CertEntry), sel.matched };
        }
    };
    try std.testing.expectEqual(.{ 2, true }, T.pick(&entries, "api.example.com"));
    try std.testing.expectEqual(.{ 2, true }, T.pick(&entries, "other.test"));
    try std.testing.expectEqual(.{ 1, true }, T.pick(&entries, "www.EXAMPLE.com"));
    try std.testing.expectEqual(.{ 1, true }, T.pick(&entries, "www.example.com."));
    try std.testing.expectEqual(.{ 0, false }, T.pick(&entries, "a.b.example.com"));
    try std.testing.expectEqual(.{ 0, false }, T.pick(&entries, "example.com"));
    try std.testing.expectEqual(.{ 0, false }, T.pick(&entries, ".example.com"));
    try std.testing.expectEqual(.{ 0, true }, T.pick(&entries, "default.test"));
    try std.testing.expectEqual(.{ 0, false }, T.pick(&entries, null));
    try std.testing.expect(selectCertificate(&.{}, "x") == null);
}

test "server_name: a list length of 0xFFFF is a decode error, not an overflow" {
    var ext: [2 + 3 + 9]u8 = undefined;
    ext[0..2].* = .{ 0xff, 0xff };
    ext[2] = 0;
    ext[3..5].* = .{ 0, 9 };
    @memcpy(ext[5..], "localhost");
    try std.testing.expectError(error.DecodeError, parseServerNameExtension(&ext));

    std.mem.writeInt(u16, ext[0..2], ext.len - 2, .big);
    try std.testing.expectEqualStrings("localhost", (try parseServerNameExtension(&ext)).?);
}

// ─── Certificates the tests below present ─────────────────────────────
//
// Built from keys rather than pasted as certificates: the chain, the key
// behind it and the signature over it are one object here, and a fixture
// that could disagree with itself would be testing the paste.

/// The smallest DER writer a certificate needs. The length is the part
/// that earns its keep — an RSA key is 1191 bytes, well past the short
/// form — and so is `close`, because a structure's header goes in front of
/// bytes already laid down and is wider in the long form than the short.
const Der = struct {
    buf: []u8,
    pos: usize = 0,

    /// tag, length, value.
    fn tlv(d: *Der, tag: u8, value: []const u8) void {
        d.header(tag, value.len);
        @memcpy(d.buf[d.pos..][0..value.len], value);
        d.pos += value.len;
    }

    /// tag and length, no value.
    fn header(d: *Der, tag: u8, len: usize) void {
        d.buf[d.pos] = tag;
        d.pos += 1;
        if (len < 0x80) {
            d.buf[d.pos] = @intCast(len);
            d.pos += 1;
        } else {
            std.debug.assert(len < 0x10000);
            d.buf[d.pos] = 0x82;
            std.mem.writeInt(u16, d.buf[d.pos + 1 ..][0..2], @intCast(len), .big);
            d.pos += 3;
        }
    }

    /// Closes a structure whose content is already written. The content
    /// moves up to make room for the header rather than the header
    /// guessing how wide it will be.
    fn close(d: *Der, tag: u8) void {
        const content = d.pos;
        const head: usize = if (content < 0x80) 2 else 4;
        @memmove(d.buf[head..][0..content], d.buf[0..content]);
        var h: Der = .{ .buf = d.buf };
        h.header(tag, content);
        std.debug.assert(h.pos == head);
        d.pos = content + head;
    }
};

/// 1.2.840.113549.1.1.1, rsaEncryption.
const rsa_encryption_oid = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };

/// A magnitude as a DER INTEGER body, with the leading zero a value whose
/// top bit is set needs to stay positive.
fn derMagnitude(magnitude: []const u8, scratch: []u8) []const u8 {
    if (magnitude[0] & 0x80 == 0) return magnitude;
    scratch[0] = 0;
    @memcpy(scratch[1..][0..magnitude.len], magnitude);
    return scratch[0 .. 1 + magnitude.len];
}

/// A PKCS#8 PrivateKeyInfo (RFC 5208) around `body`: SEQUENCE { INTEGER 0,
/// AlgorithmIdentifier { OID }, OCTET STRING { body } }.
fn privateKeyInfo(oid: []const u8, body: []const u8, out: []u8) []const u8 {
    var alg: [16]u8 = undefined;
    var a: Der = .{ .buf = &alg };
    a.tlv(0x06, oid);
    var d: Der = .{ .buf = out };
    d.tlv(0x02, &.{0});
    d.tlv(0x30, alg[0..a.pos]);
    d.tlv(0x04, body);
    d.close(0x30);
    return out[0..d.pos];
}

/// The key's SubjectPublicKeyInfo (RFC 5280 §4.1.2.7): what an X.509
/// certificate carries for an RSA key, and the shape this stack refuses to
/// lift. Built from the key so the chain and the key cannot disagree.
fn rsaSpki(key: rsa.PrivateKey, out: []u8) []const u8 {
    var alg: [16]u8 = undefined;
    var a: Der = .{ .buf = &alg };
    a.tlv(0x06, &rsa_encryption_oid);
    a.tlv(0x05, &.{}); // NULL

    var signed: [257]u8 = undefined;
    var nums: [288]u8 = undefined;
    var n: Der = .{ .buf = &nums };
    n.tlv(0x02, derMagnitude(key.n, &signed));
    n.tlv(0x02, key.e);
    var key_der: [304]u8 = undefined; // RSAPublicKey ::= SEQUENCE { n, e }
    var k: Der = .{ .buf = &key_der };
    k.tlv(0x30, nums[0..n.pos]);

    var bits: [320]u8 = undefined;
    bits[0] = 0; // no unused bits in the key
    @memcpy(bits[1..][0..k.pos], key_der[0..k.pos]);

    var d: Der = .{ .buf = out };
    d.tlv(0x30, alg[0..a.pos]);
    d.tlv(0x03, bits[0 .. 1 + k.pos]);
    d.close(0x30);
    return out[0..d.pos];
}

/// A fixed RSA-2048 key, PKCS#1 DER, hex: the key `rsa.zig`'s tests sign
/// with, pasted here rather than shared because a test block's declarations
/// are not importable and a fixture belongs to the test that reads it.
///
/// A TEST KEY. It has no security property: the private half is published
/// here and upstream, and nothing guards it. Read it as test data, never as
/// a credential. Upstream material, not regenerated: these bytes are the
/// `test_rsa_key_pkcs1_pem` of endel/quic-zig `src/tls/test_certs.zig` at
/// commit 14b9dc3e5e8429d07e7ed18619c7b4f4baaa3719, base64-decoded to DER.
const test_rsa_key_hex =
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

/// An RSA certificate: this key's SubjectPublicKeyInfo in a one-element
/// chain, and the key behind it in one encoding or the other.
///
/// RSA is a legal CertificateVerify scheme whatever the certificate around
/// the key is — a peer whose certificate is a bare Ed25519 key can still be
/// asked for an RSA signature — which is why `rsa.zig` is here at all, and
/// why these tests do not go away with the rest of the X.509 walk.
const RsaCert = struct {
    key_der: [2048]u8 = undefined,
    wrapped: [2048]u8 = undefined,
    spki: [512]u8 = undefined,
    chain: [1][]const u8 = [_][]const u8{&.{}},
    key: PrivateKey = undefined,

    /// The key, and the SPKI it is presented in.
    fn init(self: *RsaCert) !void {
        const der = try std.fmt.hexToBytes(self.key_der[0 .. test_rsa_key_hex.len / 2], test_rsa_key_hex);
        var scratch: [512]u8 = undefined;
        const spki = rsaSpki(try rsa.PrivateKey.parsePkcs1(der), &scratch);
        @memcpy(self.spki[0..spki.len], spki);
    }

    /// Reads the key out of one encoding or the other and points the chain
    /// at it. They are the same key: the PKCS#8 is built around the PKCS#1,
    /// not pasted beside it. Separate from `init` for the reason
    /// `Identity.link` gives — the pointers here name this struct's own
    /// buffers, and a struct is copied after `init` returns.
    fn link(self: *RsaCert, pkcs1: bool) !void {
        const der = self.key_der[0 .. test_rsa_key_hex.len / 2];
        self.key = try extractPrivateKey(if (pkcs1) der else privateKeyInfo(&rsa_encryption_oid, der, &self.wrapped));
        self.chain[0] = &self.spki;
    }

    fn certificate(self: *const RsaCert) ServerCertificate {
        return .{
            .cert_chain_der = &self.chain,
            .private_key_bytes = self.key.bytes,
            .private_key_algorithm = self.key.algorithm,
        };
    }
};

/// The 26 bytes that name P-256 in a SubjectPublicKeyInfo, in front of the
/// 65-byte uncompressed point: SEQUENCE { SEQUENCE { ecPublicKey,
/// prime256v1 }, BIT STRING }.
const p256_spki_prefix = [_]u8{
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
};

/// A P-256 certificate: this key's own SubjectPublicKeyInfo, 91 bytes of
/// it where this stack lifts 44. Drawn per run from the caller's random
/// source, so there is no key here to keep.
const P256Cert = struct {
    spki: [p256_spki_prefix.len + 65]u8 = undefined,
    scalar: [32]u8 = undefined,
    chain: [1][]const u8 = [_][]const u8{&.{}},

    fn init(self: *P256Cert, random_io: std.Io) void {
        const kp = EcdsaP256Sha256.KeyPair.generate(random_io);
        @memcpy(self.spki[0..p256_spki_prefix.len], &p256_spki_prefix);
        @memcpy(self.spki[p256_spki_prefix.len..], &kp.public_key.toUncompressedSec1());
        self.scalar = kp.secret_key.toBytes();
    }

    /// Point the chain at this key's own bytes, and call it on a `var` that
    /// outlives the handshake: `Identity.link` says why.
    fn link(self: *P256Cert) void {
        self.chain[0] = &self.spki;
    }

    fn certificate(self: *const P256Cert) ServerCertificate {
        return .{ .cert_chain_der = &self.chain, .private_key_bytes = &self.scalar };
    }
};

test "an RSA key is recognized from either PKCS encoding, and refused as a peer" {
    // Key extraction is still the caller's job — an ozai node reads its own
    // Ed25519 seed out of a PKCS#8 the same way — and both encodings have to
    // yield the same key. What this stack refuses is the certificate around
    // it: an RSA `SubjectPublicKeyInfo` is not a node id, and a peer offering
    // one is not an iroh peer however well it signs.
    for ([_]bool{ true, false }) |pkcs1| {
        var rsa_cert: RsaCert = undefined;
        try rsa_cert.init();
        try rsa_cert.link(pkcs1);
        try std.testing.expectEqual(PrivateKeyAlgorithm.rsa, rsa_cert.certificate().private_key_algorithm);
        var other: RsaCert = undefined;
        try other.init();
        try other.link(!pkcs1);
        try std.testing.expectEqualSlices(
            u8,
            rsa_cert.certificate().private_key_bytes,
            other.certificate().private_key_bytes,
        );
    }

    var rsa_cert: RsaCert = undefined;
    try rsa_cert.init();
    try rsa_cert.link(false);
    var client = Identity.init(client_seed);
    client.link();
    var auth: ClientAuth = .{};
    var entries = [_]CertEntry{.{ .server_names = &.{}, .cert = rsa_cert.certificate() }};
    var peer: ?[]const u8 = null;
    var buf: [2048]u8 = undefined;
    try std.testing.expectEqual(refused(error.BadCertificate), try handshake(
        std.testing.allocator,
        clientConfig(@splat(0x77), &client),
        serverConfig(&entries, &auth),
        &peer,
        &buf,
    ));
}

/// The server's answer to our client's ClientHello with its
/// signature_algorithms list replaced by `schemes` (null: extension renamed away).
fn serverAnswer(cert: ServerCertificate, schemes: ?[5]tls.SignatureScheme) !void {
    const tp = transport_params.TransportParams{ .initial_max_data = 1 << 20 };
    var entropy: Counted = .{};
    var server = Tls13Handshake.initServer(.{
        .cert_chain_der = cert.cert_chain_der,
        .private_key_bytes = cert.private_key_bytes,
        .private_key_algorithm = cert.private_key_algorithm,
        .alpn = &[_][]const u8{"h3"},
    }, tp, entropy.random());
    var client = Tls13Handshake.initClient(.{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &[_][]const u8{"h3"},
        .server_name = "localhost",
    }, tp, entropy.random());
    const ch = while (true) {
        switch (try client.step(test_now_s, entropy.random())) {
            .send_data => |sd| break sd.data,
            else => {},
        }
    };
    var buf: [2048]u8 = undefined;
    const msg = buf[0..ch.len];
    @memcpy(msg, ch);
    const at = std.mem.indexOf(u8, msg, &.{ 0x00, 0x0d, 0x00, 0x0c, 0x00, 0x0a }).?;
    if (schemes) |list| {
        for (list, 0..) |scheme, i| std.mem.writeInt(u16, msg[at + 6 + 2 * i ..][0..2], @intFromEnum(scheme), .big);
    } else {
        msg[at + 1] = 0xfa; // an unassigned extension type
    }
    server.provideData(msg);
    while (true) {
        switch (try server.step(test_now_s, entropy.random())) {
            .send_data => return,
            else => {},
        }
    }
}

test "a QUIC server fails a client that offers no scheme for its certificate" {
    var rsa_cert: RsaCert = undefined;
    try rsa_cert.init();
    try rsa_cert.link(false);
    var ec: P256Cert = undefined;
    ec.init(std.testing.io);
    ec.link();
    const rsa_presented = rsa_cert.certificate();
    const p256_presented = ec.certificate();

    const no_pss: [5]tls.SignatureScheme = .{ .ecdsa_secp256r1_sha256, .ed25519, .rsa_pkcs1_sha256, .rsa_pss_pss_sha256, .ecdsa_secp384r1_sha384 };
    const only_pss512: [5]tls.SignatureScheme = @splat(.rsa_pss_rsae_sha512);
    try std.testing.expectError(error.HandshakeFailure, serverAnswer(rsa_presented, no_pss));
    try std.testing.expectError(error.HandshakeFailure, serverAnswer(p256_presented, only_pss512));
    try std.testing.expectError(error.MissingExtension, serverAnswer(rsa_presented, null));
    try serverAnswer(rsa_presented, only_pss512);
    try serverAnswer(p256_presented, no_pss);
}

test "selectCertificateFor: a key the client can verify wins within each step" {
    const ec: ServerCertificate = .{ .cert_chain_der = &.{}, .private_key_bytes = &.{} };
    const rsa_key: ServerCertificate = .{ .cert_chain_der = &.{}, .private_key_bytes = &.{}, .private_key_algorithm = .rsa };
    const entries = [_]CertEntry{
        .{ .server_names = &.{"default.test"}, .cert = ec },
        .{ .server_names = &.{"*.example.com"}, .cert = ec },
        .{ .server_names = &.{"*.example.com"}, .cert = rsa_key },
        .{ .server_names = &.{"api.example.com"}, .cert = ec },
    };
    const pss = [_]u8{ 0x08, 0x04 };
    const ecdsa = [_]u8{ 0x04, 0x03 };
    const T = struct {
        fn pick(e: []const CertEntry, sni: ?[]const u8, offered: []const u8) struct { usize, bool } {
            const sel = selectCertificateFor(e, sni, offered).?;
            return .{ (@intFromPtr(sel.entry) - @intFromPtr(e.ptr)) / @sizeOf(CertEntry), sel.matched };
        }
    };
    try std.testing.expectEqual(.{ 1, true }, T.pick(&entries, "www.example.com", &ecdsa));
    try std.testing.expectEqual(.{ 2, true }, T.pick(&entries, "www.example.com", &pss));
    // An exact match is not given up for a usable wildcard.
    try std.testing.expectEqual(.{ 3, true }, T.pick(&entries, "api.example.com", &pss));
    try std.testing.expectEqual(.{ 2, false }, T.pick(&entries, null, &pss));
    try std.testing.expectEqual(.{ 0, false }, T.pick(&entries, "other.test", &.{ 0x08, 0x07 }));
    try std.testing.expectEqual(tls.SignatureScheme.rsa_pss_rsae_sha384, signatureSchemeFor(.rsa, &.{ 0x08, 0x06, 0x08, 0x05 }).?);
    try std.testing.expect(signatureSchemeFor(.rsa, &.{ 0x08, 0x09, 0x04, 0x01 }) == null);
}


test "QUIC client certificates: a raw SPKI identity, required or optional" {
    const gpa = std.testing.allocator;
    var server = Identity.init(server_seed);
    server.link();
    var client = Identity.init(client_seed);
    client.link();
    var stranger = Identity.init(@splat(0x11));
    stranger.link();
    var auth: ClientAuth = .{ .expect_node_id = client.node_id };
    var entries = [_]CertEntry{.{ .server_names = &.{}, .cert = server.certificate() }};
    var peer: ?[]const u8 = null;
    var buf: [ed25519_spki_len]u8 = undefined;

    // Asked, and answering: the dialer's own 44 bytes reach the server, and
    // the id inside them is the one it pinned.
    try std.testing.expectEqual(null, try handshake(
        gpa,
        clientConfig(server.node_id, &client),
        serverConfig(&entries, &auth),
        &peer,
        &buf,
    ));
    try std.testing.expectEqualSlices(u8, &client.spki, peer.?);

    // Asked, and silent. `.required` refuses that; `.optional` completes with
    // no client identity at all, which is a server that asked and took the
    // answer for what it was.
    var silent = clientConfig(server.node_id, &client);
    silent.client_certificate = null;
    try std.testing.expectEqual(refused(error.CertificateRequired), try handshake(
        gpa,
        silent,
        serverConfig(&entries, &auth),
        &peer,
        &buf,
    ));
    auth.mode = .optional;
    try std.testing.expectEqual(null, try handshake(
        gpa,
        silent,
        serverConfig(&entries, &auth),
        &peer,
        &buf,
    ));
    try std.testing.expectEqual(null, peer);

    // Asked, and answered with somebody else's key. The CertificateRequest
    // offers no issuer to choose from, so there is nothing a client can do
    // here but present the wrong identity.
    var wrong = silent;
    wrong.client_certificate = stranger.certificate();
    auth.mode = .required;
    try std.testing.expectEqual(refused(error.BadCertificate), try handshake(
        gpa,
        wrong,
        serverConfig(&entries, &auth),
        &peer,
        &buf,
    ));
}

test "parseCertificateRequest and parseCertificateList reject malformed input" {
    // A CertificateRequest carries no certificate_authorities any more, and
    // one that arrives with one is still parsed rather than refused: a peer
    // that sends it is not us.
    var buf: [256]u8 = undefined;
    const req = try buildCertificateRequest(&buf);
    try std.testing.expectEqualSlices(u8, &client_auth_signature_schemes, try parseCertificateRequest(req[4..]));
    // Every truncation fails cleanly.
    for (0..req.len - 4) |n| {
        if (parseCertificateRequest(req[4..][0..n])) |_| return error.TestUnexpectedResult else |_| {}
    }
    try std.testing.expectError(error.IllegalParameter, parseCertificateRequest(&.{ 1, 0, 0, 0 }));
    try std.testing.expectError(error.MissingExtension, parseCertificateRequest(&.{ 0, 0, 0 }));

    var chain: [2][]const u8 = undefined;
    try std.testing.expectEqual(null, try parseCertificateList(&.{ 0, 0, 0, 0 }, &chain));
    try std.testing.expectError(error.IllegalParameter, parseCertificateList(&.{ 1, 0, 0, 0 }, &chain));
    try std.testing.expectError(error.DecodeError, parseCertificateList(&.{ 0, 0, 0, 5, 0, 0, 1, 0xaa, 0 }, &chain));
    const one = [_]u8{ 0, 0, 0, 6, 0, 0, 1, 0xaa, 0, 0 };
    try std.testing.expectEqual(@as(usize, 1), (try parseCertificateList(&one, &chain)).?.len);
    const three = [_]u8{ 0, 0, 0, 18, 0, 0, 1, 0xaa, 0, 0, 0, 0, 1, 0xbb, 0, 0, 0, 0, 1, 0xcc, 0, 0 };
    try std.testing.expectError(error.BadCertificate, parseCertificateList(&three, &chain));
}

