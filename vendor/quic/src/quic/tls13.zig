//! TLS 1.3 handshake for QUIC (RFC 8446 + RFC 9001), sans-IO.
//!
//! Offers TLS_AES_128_GCM_SHA256 (0x1301) and
//! TLS_CHACHA20_POLY1305_SHA256 (0x1303); AES is what a handshake free to
//! choose settles on.
//! X25519 for key exchange. Ed25519 for a peer's identity, and for the
//! CertificateVerify that proves possession of it.
//!
//! A peer's certificate is a 44-byte DER `SubjectPublicKeyInfo` around the 32
//! raw bytes of an Ed25519 key, and those 32 bytes are the node id. There is
//! no chain to walk, no host name to match and no validity date to read: a
//! peer is the key it presents or the handshake ends. Upstream validated an
//! X.509 chain here, and every part of that is gone — see `liftEd25519Spki`,
//! which is the whole of certificate validation now.
//!
//! X.509 wrapping is what makes those bytes legible to a peer, and RFC 7250 is
//! what says so on the wire: both ends offer `client_certificate_type` and
//! `server_certificate_type` in the ClientHello and settle each one in the
//! EncryptedExtensions, and an absent extension — which RFC 7250 §4.1 makes an
//! implicit X.509 — is refused rather than defaulted. So the `Certificate`
//! payload below is a `SubjectPublicKeyInfo` because the handshake negotiated
//! one, and not because nothing else was ever tried.
//!
//! The state machine is `Tls13Handshake`, driven by `step` with bytes from
//! the crypto streams and an `Action` back. Time and randomness are
//! arguments on `step`, never stored: nothing here reads a clock or reaches
//! for a CSPRNG, so two runs driven with two clocks and two generators are
//! two different runs. A `TlsConfig` is copied in whole and its slices are
//! borrowed, all of it for the handshake's life, and `deinit` releases what
//! the handshake allocated — which is owed after a failed handshake too.

const std = @import("std");
const io = @import("../io_compat.zig");
const crypto = std.crypto;
const tls = std.crypto.tls;
const quic_crypto = @import("crypto.zig");
const protocol = @import("protocol.zig");
const transport_params = @import("transport_params.zig");
const limits = @import("limits.zig");
/// Re-exported so a caller can name the private-key types without importing
/// `rsa.zig` itself; the contract is at that file's own declarations.
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

/// The three QUIC encryption levels and their numeric encoding. Re-exported
/// from `crypto.zig`, which owns the contract; `Action.level` and
/// `CryptoStreamManager.getStream` both use these values as indices.
pub const EncryptionLevel = quic_crypto.EncryptionLevel;

/// Which private key a certificate's leaf is signed with, and therefore
/// which CertificateVerify scheme this side can produce. It is a property of
/// the key material, not a preference: `signatureSchemeFor` maps it onto the
/// schemes the peer's `signature_algorithms` offers.
pub const PrivateKeyAlgorithm = enum {
    /// ECDSA over P-256 with SHA-256. The default in every config that does
    /// not say otherwise, and the only scheme a node id certificate is
    /// verified with when the peer's certificate is an X.509 one.
    ecdsa_p256_sha256,
    /// Ed25519, RFC 8032. What a node presents as itself, and what
    /// `liftEd25519Spki` extracts from a peer's certificate.
    ed25519,
    /// Signs with RSA-PSS (rsa_pss_rsae_*), SHA-256 unless the client offers
    /// only SHA-384 or SHA-512.
    rsa,
};

/// The CertificateVerify scheme for a key, from the client's
/// signature_algorithms (the list body: big-endian u16s). Null when the
/// client offers none that fits.
///
/// `offered` is borrowed and is walked in preference order per algorithm —
/// ECDSA, then Ed25519, then RSA from SHA-256 down — so the result is the
/// first of this key's schemes the client listed, not the client's first
/// scheme that this key supports. Null is what makes a server unable to
/// complete: `HandshakeFailure` is the error the caller sees.
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
///
/// `sig_algo` is the scheme from the peer's CertificateVerify, and
/// `signed_content` the 64-space-padded transcript string built for it. A
/// `null` scheme, a public key whose category does not match the scheme, a
/// key that will not parse, or a signature that does not verify are all the
/// same answer: `error.BadCertificateVerify`, with nothing retained. The
/// caller cannot tell a forged signature from an unsupported one, which is
/// deliberate — the distinction would tell a prober which half they got.
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

// ─── RFC 7250 certificate type ───────────────────────────────────────

/// RFC 7250 §3's `CertificateType`, and the one value this stack
/// negotiates.
///
/// `x509` is named because the negotiation is *about* which of these the
/// `Certificate` payload carries: a peer that sends no extension at all has
/// said X.509 by default (RFC 7250 §4.1), and a stack whose whole identity
/// model is a bare `SubjectPublicKeyInfo` has to refuse that rather than read
/// a certificate it cannot parse. `raw_public_key` is that
/// `SubjectPublicKeyInfo` — the 44-byte DER around the 32 bytes of an Ed25519
/// key, with nothing wrapped around it, which is what `liftEd25519Spki` reads.
///
/// `generic_cert` and `open_pgp_cert` are here for the same reason: the IANA
/// registry is open, and an extension naming a value this build does not know
/// is a `DecodeError` rather than a quiet "not RawPublicKey".
pub const CertificateType = enum(u8) {
    /// RFC 5246. The default when no extension is sent, and so the value a
    /// peer has selected by omission.
    x509 = 0,
    /// RFC 5089.
    open_pgp_cert = 1,
    /// RFC 7250 §3. The only type this stack offers, selects or accepts.
    raw_public_key = 2,
    /// RFC 7250 §3, a placeholder for types from the same registry.
    generic_cert = 3,
};

comptime {
    // The two extensions are the whole of RFC 7250's wire surface, and a
    // peer's dispatch is keyed on their numbers. std names them; these two
    // values are what the names mean, so a toolchain that renumbered them
    // would have every peer disagreeing with this stack in silence.
    if (@intFromEnum(tls.ExtensionType.client_certificate_type) != 19) {
        @compileError("RFC 7250's client_certificate_type is 19 and std no longer agrees");
    }
    if (@intFromEnum(tls.ExtensionType.server_certificate_type) != 20) {
        @compileError("RFC 7250's server_certificate_type is 20 and std no longer agrees");
    }
}

/// The type this stack offers, selects and accepts, named once because four
/// sites write it and a fifth refuses everything else: the two builders, the
/// two parsers' callers, and the fail-closed checks that make any other value
/// an error. iroh presents a bare Ed25519 `SubjectPublicKeyInfo` in both
/// directions, so this is the only certificate type there is here.
pub const negotiated_certificate_type: CertificateType = .raw_public_key;

/// RFC 7250 §3's `CertificateType certificate_types<1..2^8-1>`: the form a
/// ClientHello uses — a one-byte count and that many one-byte types. The
/// count is the vector's own length, so the extension body closes it.
pub const certificate_type_offer_len = 2;

/// RFC 7250 §3's bare `CertificateType`: the form a server's answer uses, one
/// byte and no count in front of it. §4.2 spells out why the two forms
/// differ: "only a single value is permitted in the server_certificate_type
/// extension when carried in the server hello", and the client's type has the
/// same structure.
pub const certificate_type_selection_len = 1;

/// Writes the offer a client makes, naming `kind` alone — RFC 7250 §4.1's "a
/// list containing a single element", which is what a client that speaks one
/// certificate type sends.
///
/// `out` is the caller's; the bytes written are
/// `out[0..certificate_type_offer_len]`. `error.BufferTooSmall` when `out`
/// cannot hold them, which is a caller's buffer and not a message this stack
/// builds — so the refusal is the caller's to size against, not one a peer
/// can provoke.
pub fn encodeCertificateTypeOffer(
    out: []u8,
    kind: CertificateType,
) error{BufferTooSmall}![]const u8 {
    if (out.len < certificate_type_offer_len) return error.BufferTooSmall;
    out[0] = 1; // the count: this stack offers exactly one type
    out[1] = @intFromEnum(kind);
    return out[0..certificate_type_offer_len];
}

/// Writes the selection a server makes, naming `kind` alone — RFC 7250 §3's
/// bare `CertificateType`, with no count in front of it.
pub fn encodeCertificateTypeSelection(
    out: []u8,
    kind: CertificateType,
) error{BufferTooSmall}![]const u8 {
    if (out.len < certificate_type_selection_len) return error.BufferTooSmall;
    out[0] = @intFromEnum(kind);
    return out[0..certificate_type_selection_len];
}

/// RFC 7250 §3's `CertificateType certificate_types<1..2^8-1>`, parsed: the
/// types offered, borrowed from `data`.
///
/// `error.DecodeError` for a body that does not close the extension, and for
/// a count of zero — the vector's own minimum is one, so a zero-length list
/// is not an offer of nothing but a body this grammar has no shape for.
pub fn parseCertificateTypeOffer(data: []const u8) error{DecodeError}![]const u8 {
    if (data.len < 2) return error.DecodeError;
    const count: usize = data[0];
    if (count == 0 or count + 1 != data.len) return error.DecodeError;
    return data[1..];
}

/// Whether `offer` — a body from `parseCertificateTypeOffer` — names `kind`.
///
/// A byte outside the IANA registry is skipped rather than refused: the
/// registry is open, so a peer may offer a type added after this build, and
/// the question here is whether *this* type is among the offers.
pub fn offerContains(offer: []const u8, kind: CertificateType) bool {
    for (offer) |byte| {
        if (byte == @intFromEnum(kind)) return true;
    }
    return false;
}

/// RFC 7250 §3's bare `CertificateType`, parsed: the type a server selected.
///
/// `error.DecodeError` for a body that is not exactly one byte — §3 puts no
/// count here, so a longer body is not a selection of several types but a
/// message this grammar has no shape for — and for a value outside the IANA
/// registry, which is a field this build cannot decode rather than a type it
/// decided against.
pub fn parseCertificateTypeSelection(data: []const u8) error{DecodeError}!CertificateType {
    if (data.len != certificate_type_selection_len) return error.DecodeError;
    return switch (data[0]) {
        @intFromEnum(CertificateType.x509) => .x509,
        @intFromEnum(CertificateType.open_pgp_cert) => .open_pgp_cert,
        @intFromEnum(CertificateType.raw_public_key) => .raw_public_key,
        @intFromEnum(CertificateType.generic_cert) => .generic_cert,
        else => error.DecodeError,
    };
}

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
///
/// What a set node id actually buys, stated once here because two fields of
/// two structs would each say it: the check is that the 32 bytes inside the
/// peer's `SubjectPublicKeyInfo` equal this array, byte for byte. It is not
/// a lookup, not a membership test and not a chain walk — a certificate that
/// carries some other key fails with `error.BadCertificate` whatever issued
/// it, and a peer that presents this key with a signature made by anything
/// else fails at the CertificateVerify with `error.BadCertificateVerify`.
/// Together those two make it a proof of possession rather than a claim.
///
/// With `null` the check does not run, and the handshake succeeds for any key
/// the peer can sign with: the connection then knows the peer holds the id it
/// presented and nothing more. A caller that wants identity and leaves this
/// null has a connection with a key and no node.
pub const ClientAuth = struct {
    /// The node id the client's certificate has to carry. Null accepts any
    /// key, and then the client has proved possession of the id it presented
    /// rather than being the node we asked for.
    ///
    /// Compared against the key lifted from the peer's certificate, so it
    /// pins the key and not a subject, an issuer or a name. A client that
    /// sends no certificate fails on `mode` before this is consulted —
    /// unless this is set, which is itself a demand for a certificate. A pin
    /// is about which node has to be the one on the other end, and a mode
    /// that lets a client through with nothing does not waive it: such a
    /// client fails with `error.CertificateRequired`. A client that sends one
    /// carrying a different key fails on this, with `error.BadCertificate`,
    /// whatever `mode` says.
    expect_node_id: ?[32]u8 = null,
    /// What happens when the client sends no certificate at all. `.required`
    /// is the default and fails the handshake with
    /// `error.CertificateRequired`; `.optional` lets it through with no
    /// client identity, and `peerNodeId` then answers null.
    mode: Mode = .required,

    /// Whether a client that sends no certificate is refused or let through.
    /// Two tags, exhaustive, and no third answer: a peer that sends a
    /// certificate is judged by `expect_node_id` either way.
    pub const Mode = enum {
        /// No certificate: the handshake fails with certificate_required.
        /// The default. `expect_node_id` is not consulted, because there is
        /// nothing to compare — the absence is the failure.
        required,
        /// No certificate: the handshake completes without a client identity.
        /// The connection is established and authenticated as the server, and
        /// nothing about the client is known; a caller that treats this as
        /// `required` has an unauthenticated peer. `expect_node_id` is not
        /// waived by this mode and does not waive it: a policy that names a
        /// node demands that node's certificate, so an empty
        /// `certificate_list` is `error.CertificateRequired` here as it is
        /// under `required`.
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
///
/// The result borrows `buf` and is valid until the caller writes it again.
/// `error.BufferTooSmall` when `buf` cannot hold the whole message — which
/// is the only failure — and it is checked before anything is written, so
/// `buf` is untouched on that path. The size is fixed, so a caller can
/// compute it once; the returned slice is shorter by the extension header
/// this build emits and is not a compile-time constant.
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
///
/// `body` is borrowed and the result points into it, so the slice dies with
/// the buffer it was parsed from. `error.IllegalParameter` for a non-empty
/// context — this stack never sends post-handshake authentication — or for a
/// second signature_algorithms extension; `error.MissingExtension` when
/// there is none, which RFC 8446 §4.3.2 makes mandatory; `error.DecodeError`
/// for a length that does not close the message or an odd-length list.
/// Nothing is allocated, so no failure leaves state behind.
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
            // RFC 8446 §4.2.3's `SignatureScheme supported_signature_algorithms<2..2^16-1>`
            // is measured against a byte count, so the peer's length is read as
            // a `usize`: a peer that writes `ff ff` names a list longer than any
            // buffer, and adding two to it in a `u16` would overflow before the
            // comparison could answer that.
            if (data.len < 2 or @as(usize, readU16(data)) + 2 != data.len or data.len % 2 != 0) return error.DecodeError;
            sig_algs = data[2..];
        }
    }
    return sig_algs orelse error.MissingExtension;
}

/// The leaf of a Certificate message body (RFC 8446 §4.4.2) and up to
/// `out.len` certificates, leaf first, in `out`. Null for an empty list.
/// The context must be empty: we never send one.
///
/// Every slice written into `out` borrows `body`, so the whole `out` dies
/// with the buffer the message was parsed from; nothing is copied and the
/// caller frees nothing. `out` is only written up to the point of failure —
/// on error the first `n` entries hold valid slices and the rest keep
/// whatever the caller had there, so `out` is not cleared and not filled.
///
/// `error.IllegalParameter` for a non-empty context, which only
/// post-handshake authentication uses here; `error.BadCertificate` when the
/// chain is longer than `out`, which is the caller's bound on chain depth and
/// not a claim that the chain is bad; `error.DecodeError` for a zero-length
/// certificate, a length that does not close the message, or an extension
/// block that runs past it. Null is the answer for a well-formed empty list,
/// which is how a client answers a CertificateRequest it cannot meet.
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

/// The running SHA-256 over every handshake message, which is what every
/// Finished, CertificateVerify and key derivation in TLS 1.3 is computed
/// over.
///
/// It owns nothing and borrows nothing: `update` copies the bytes it is
/// given, so the caller's buffer is free immediately, and a copy of the
/// struct is an independent transcript. `current` snapshots rather than
/// consumes, so a caller may take the hash as often as it likes and then
/// keep going. Not thread-safe.
pub const TranscriptHash = struct {
    /// The running hash state. The whole of the transcript, and the reason a
    /// `TranscriptHash` may be copied: it is a value, not a pointer.
    state: Sha256,

    /// An empty transcript: the hash of nothing, which is the value TLS 1.3
    /// calls `Hash("")` and the first input to every derivation.
    pub fn init() TranscriptHash {
        return .{ .state = Sha256.init(.{}) };
    }

    /// Update with a raw TLS handshake message (type + 3-byte length + body).
    ///
    /// The whole message, header included, and in wire order: the transcript
    /// is a hash of bytes exactly as they appear, so a caller that skips the
    /// four-byte header, reorders anything, or feeds a re-encoded message
    /// instead of the received one computes a different — and wrong —
    /// Finished. `msg` is borrowed and not retained.
    pub fn update(self: *TranscriptHash, msg: []const u8) void {
        self.state.update(msg);
    }

    /// The hash of everything fed in so far, without consuming the
    /// transcript. This is the value passed to every `derive*` method and to
    /// `computeFinishedVerifyData`, and the one a handshake must snapshot
    /// before adding its own Finished to the transcript.
    pub fn current(self: *const TranscriptHash) [32]u8 {
        // Copy the state to get a snapshot without consuming it
        var copy = self.state;
        return copy.finalResult();
    }
};

// ─── KeySchedule ─────────────────────────────────────────────────────

/// The RFC 8446 §7.1 key schedule: every secret TLS 1.3 derives, and the
/// QUIC key contexts made from them.
///
/// It owns nothing and borrows nothing, and holds no clock: every secret is
/// derived from arguments the caller supplies — a PSK, a shared secret, a
/// transcript hash — so the same inputs give the same schedule. It is a
/// plain value of nine 32-byte secrets and two flags; copying one copies
/// the secrets, and there is no `deinit` because there is nothing to release.
/// A schedule that has not been derived from yet has zero in the fields
/// marked optional below, which is why `computed_handshake` and
/// `computed_app` exist rather than a test for zero.
///
/// The methods that take a traffic secret (`makeOpen`, `makeSeal` and their
/// variants) are static and allocate nothing: the returned `Open` and `Seal`
/// own no memory, so copying one is cheap and safe.
pub const KeySchedule = struct {
    /// The 0-RTT secret, from which the early traffic secret is derived.
    /// Valid from `init` or `initWithPsk` and never zero afterwards.
    early_secret: [32]u8,
    /// Set by `deriveHandshakeSecrets` from the shared secret and the
    /// transcript. Before that call it is undefined, not zero — read it only
    /// when `computed_handshake` is set.
    handshake_secret: [32]u8,
    /// Set by `deriveAppSecrets`, which is what makes `computed_app` true.
    /// Undefined until then.
    master_secret: [32]u8,
    /// The handshake traffic secret this side writes with: the server's on a
    /// server, the client's on a client. Set together with the peer's by
    /// `deriveHandshakeSecrets`.
    client_handshake_traffic_secret: [32]u8,
    /// The handshake traffic secret the peer writes with, and so the one this
    /// side decrypts with. The mirror of the field above.
    server_handshake_traffic_secret: [32]u8,
    /// The application traffic secret this side writes with, set by
    /// `deriveAppSecrets`. The mirror of the two fields below it.
    client_app_traffic_secret: [32]u8,
    /// The application traffic secret the peer writes with, set by
    /// `deriveAppSecrets`.
    server_app_traffic_secret: [32]u8,
    /// Zero until `deriveResumptionMasterSecret` runs, which is after the
    /// full transcript. Zero is the "no ticket will be issued" answer, not an
    /// unusable secret.
    resumption_master_secret: [32]u8 = .{0} ** 32,
    /// The client early traffic secret for 0-RTT. Zero until
    /// `deriveEarlyDataSecret` runs; a 0-RTT key made from a zero secret
    /// would be one anyone could forge, so no caller may make one before it.
    client_early_traffic_secret: [32]u8 = .{0} ** 32,
    /// Whether `deriveHandshakeSecrets` has run, and so whether the
    /// handshake secrets above hold anything. A flag rather than a zero test,
    /// because a real secret can be all zeros.
    computed_handshake: bool = false,
    /// Whether `deriveAppSecrets` has run, for the application secrets.
    computed_app: bool = false,

    /// A full handshake's schedule: the early secret extracted from a zero
    /// salt and a zero input key, and nothing derived from it yet.
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
    /// A resumed handshake's schedule, with `early_secret` extracted from the
    /// ticket's PSK instead of a zero key. `psk` is taken by value; the
    /// caller may release whatever it came from.
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

    /// Derives the client early traffic secret for 0-RTT from
    /// `early_secret` and the transcript hash as it stands *through* the
    /// ClientHello — RFC 8446 §7.1 draws `c e traffic` over `ClientHello`
    /// itself, so the hash is taken once that message is in and before the
    /// ServerHello is. Must run before any 0-RTT key is made; it is a
    /// resumption-only step, and a full handshake never calls it.
    pub fn deriveEarlyDataSecret(self: *KeySchedule, transcript_hash: [32]u8) void {
        self.client_early_traffic_secret = deriveSecret(self.early_secret, "c e traffic", transcript_hash);
    }

    /// Derives the resumption master secret, which is what a server seals a
    /// session ticket under and what a client recovers a PSK from (§4.6.1
    /// expands it with the ticket's nonce into the PSK itself).
    ///
    /// `transcript_hash` is the transcript through the *client's* Finished:
    /// RFC 8446 §7.1 draws `res master` over `ClientHello...client Finished`,
    /// and this is where both roles call it — a server derives it as it seals
    /// the ticket, having verified that Finished first, and a client derives
    /// it parsing a NewSessionTicket that arrives after its own. A hash taken
    /// anywhere else is a secret the peer never derives, and the ticket is
    /// then never resumed rather than refused.
    pub fn deriveResumptionMasterSecret(self: *KeySchedule, transcript_hash: [32]u8) void {
        self.resumption_master_secret = deriveSecret(self.master_secret, "res master", transcript_hash);
    }

    /// Derives the handshake secrets from the shared secret and transcript
    /// hash. Sets both handshake traffic secrets and `computed_handshake`.
    /// `shared_secret` is borrowed and not retained, so the caller may clear
    /// its copy immediately. Idempotent in effect, not in state: a second
    /// call with a different shared secret silently replaces the first.
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

    /// Derives the master and application traffic secrets, and sets
    /// `computed_app`. `transcript_hash` is the transcript through the
    /// server's Finished — RFC 8446 §7.1 draws both application traffic
    /// secrets over `ClientHello...server Finished` — and that is where each
    /// role is when it calls: a client has just verified that message, a
    /// server has just added its own. Nothing keys off the master secret this
    /// produces, because the Finished that follows is checked against the
    /// handshake traffic secret; the point is the transcript alone. A hash
    /// taken anywhere else yields application keys the peer cannot derive.
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

    /// An `Open` for QUIC v1 with AES-128-GCM. It owns no allocation, so it
    /// is cheap to copy and safe to keep; the peer never sees it.
    pub fn makeOpen(traffic_secret: [32]u8) quic_crypto.Open {
        return makeOpenWithCipher(traffic_secret, .aes_128_gcm_sha256);
    }

    /// A `Seal` for QUIC v1 with AES-128-GCM, on the same terms as `makeOpen`.
    /// The keys are copied in and the secret is not retained.
    pub fn makeSeal(traffic_secret: [32]u8) quic_crypto.Seal {
        return makeSealWithCipher(traffic_secret, .aes_128_gcm_sha256);
    }

    /// As `makeOpen`, for a chosen cipher suite, still with the QUIC v1 HKDF
    /// labels.
    pub fn makeOpenWithCipher(traffic_secret: [32]u8, cipher: quic_crypto.CipherSuite) quic_crypto.Open {
        return makeOpenFull(traffic_secret, cipher, protocol.QUIC_V1);
    }

    /// As `makeSeal`, for a chosen cipher suite, still with the QUIC v1 HKDF
    /// labels.
    pub fn makeSealWithCipher(traffic_secret: [32]u8, cipher: quic_crypto.CipherSuite) quic_crypto.Seal {
        return makeSealFull(traffic_secret, cipher, protocol.QUIC_V1);
    }

    /// An `Open` for a chosen cipher suite and QUIC version. `version`
    /// selects the HKDF label prefix, so it must be the version the traffic
    /// secret itself was derived under: a mismatch produces a key the peer
    /// cannot reproduce, which shows up as every packet failing to decrypt
    /// rather than as an error here.
    ///
    /// The returned context is prepared, so it is ready to use and owns no
    /// allocation.
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

    /// As `makeSeal`, for a chosen cipher suite and QUIC version, with the
    /// same requirement that `version` match the derivation.
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

    /// Computes the Finished verify_data: an HMAC over the transcript hash
    /// keyed by the base traffic secret, which is what RFC 8446 §4.4.4
    /// defines. Static, so each side can compute the other's value without a
    /// handshake object; `base_key` is the traffic secret being finished and
    /// `transcript_hash` the transcript up to but not including this
    /// Finished.
    pub fn computeFinishedVerifyData(base_key: [32]u8, transcript_hash: [32]u8) [32]u8 {
        const finished_key = quic_crypto.hkdfExpandLabel(base_key, "finished", "", 32);
        return tls.hmac(HmacSha256, &transcript_hash, finished_key);
    }

    fn deriveSecret(secret: [32]u8, comptime label: []const u8, transcript_hash: [32]u8) [32]u8 {
        return quic_crypto.hkdfExpandLabel(secret, label, &transcript_hash, 32);
    }
};

// ─── Session Ticket (0-RTT resumption) ───────────────────────────────

/// The longest application protocol this stack can have negotiated, in bytes:
/// the width of the one selection a handshake records. RFC 7301 lets a
/// ProtocolName run to 255, and this is the construction precondition that
/// sits below that — a name this stack cannot select is one it cannot record
/// in a ticket, compare against one, or hand to an application, so a server
/// refuses to select it rather than recording a prefix of it as if the prefix
/// were the protocol. See `Tls13Handshake.selected_alpn` for what each end
/// does with a name over it, and `sealed_ticket_len` for why a ticket has
/// room for exactly this many.
const negotiated_alpn_len_max = 32;

/// One resumption ticket, from both ends: what a server seals and hands out,
/// and what a client parses back out of a NewSessionTicket.
///
/// It is a plain value with no allocator and no borrow — the `ticket` array is
/// inline, at most 512 bytes — so it can be stored in a config, returned by
/// value and copied freely. What the *caller* must keep is the
/// `Resumption.client` pointer that refers to it, which stays borrowed for
/// the handshake's life.
///
/// A ticket is bearer material: whoever holds `psk` resumes as the peer this
/// connection authenticated. That is why a client config keeps it behind
/// `TlsConfig.resumption` and why a server's sealing key and a client's
/// ticket cannot be set independently of each other.
///
/// `creation_time` and `lifetime` are whole seconds and only ever enter an
/// arithmetic difference, never a comparison against an epoch. What that
/// needs is that the stamps and the ages compared against them come off
/// clocks sharing one epoch, not that one clock object or one process
/// produced both — `Tls13Handshake.step`'s `now_s` is that clock.
pub const SessionTicket = struct {
    /// Pre-shared key derived from resumption_master_secret
    ///
    /// The secret a resumed handshake starts from. It is the whole security
    /// of the resumption: possession of it is what a replayed ticket proves.
    psk: [32]u8,
    /// Opaque ticket data (encrypted by server)
    ///
    /// At most 512 bytes; `ticket_len` says how many. The server fills it
    /// with AES-128-GCM output under its `TicketKey` and a client fills it
    /// with the bytes from the NewSessionTicket, so neither end can read the
    /// other's fields out of it.
    ticket: [512]u8 = .{0} ** 512,
    /// Bytes of `ticket` in use. Whoever writes it keeps it at or below
    /// `ticket.len`; `getTicket` slices with it and does not re-check, so a
    /// larger value is the caller's to not write. Zero is a ticket that was
    /// never filled, not an empty one.
    ticket_len: u16 = 0,
    /// Age obfuscation value, a u32 the server draws once per ticket.
    ///
    /// RFC 8446 §4.6.1 adds it to a resuming client's age in milliseconds to
    /// form the obfuscated age it offers, wrapping modulo 2^32. Zero — the
    /// default — is a ticket that never stored one, and costs nothing to
    /// send: a server opens a ticket without reading that field, so no age
    /// check here depends on it and a zero is not a weaker ticket.
    ticket_age_add: u32 = 0,
    /// A second on the caller's clock, not on the epoch. Only differences
    /// against another stamp from that same clock are ever taken of it, so
    /// the base cancels and nothing here depends on what zero means.
    creation_time: i64 = 0,
    /// How long the ticket stays usable, in seconds from `creation_time`.
    /// Zero — the default — is "not recorded", and makes `isExpired` answer
    /// true as soon as the clock is one second past the instant it was
    /// stamped. Nothing else consults it: a server opens a ticket without
    /// reading it.
    lifetime: u32 = 0,
    /// How much 0-RTT data the issuing server said it would accept, in bytes,
    /// as its NewSessionTicket's early_data extension advertised it. Zero —
    /// the default — is a ticket that carried no such extension.
    ///
    /// Nothing here reads it: a ClientHello built from any usable ticket
    /// offers early_data whatever this says, and the server answers from its
    /// own state. Honouring it is the caller's, and a resuming client that
    /// sends 0-RTT against a zero here sends it unpermitted.
    max_early_data_size: u32 = 0,
    /// The cipher suite the connection that issued this ticket negotiated.
    ///
    /// A resuming client offers this one suite and nothing else, and makes its
    /// 0-RTT keys with it: RFC 9001 §4.6 requires both endpoints to build 0-RTT
    /// out of the same connection's information, and a client's 0-RTT keys are
    /// derived before a ServerHello can name a suite.
    ///
    /// It narrows that offer only while `TlsConfig.cipher_suite_only` is
    /// `null`. Set, that field names the suite offered and built with instead
    /// and this one is not read, and a ticket the handshake will not offer at
    /// all — one from another QUIC version — narrows nothing either.
    cipher_suite: quic_crypto.CipherSuite = .aes_128_gcm_sha256,
    /// The QUIC version the connection that issued this ticket ended on: its
    /// negotiated version, which under compatible version negotiation is not
    /// the version its first flight was built with. The version 0-RTT keys
    /// are labelled for is the other one again — see
    /// `Tls13Handshake.original_version`.
    ///
    /// A ticket belongs to one QUIC version (RFC 9369 §5), and both ends
    /// compare this against the version the resuming connection starts on,
    /// not the one it ends on: a client whose first flight is version 1 may
    /// negotiate version 2 and still resume a version-1 ticket, while a
    /// ticket issued on a connection that ended on version 2 is usable only
    /// where the next one starts on version 2. A mismatch is not a failure —
    /// the client resumes nothing and offers no early_data. The default is
    /// `protocol.QUIC_V1`, the version a ticket written by hand starts on.
    quic_version: u32 = protocol.QUIC_V1,
    /// The protocol the connection that issued this ticket negotiated.
    ///
    /// At most `negotiated_alpn_len_max` bytes; `alpn_len` says how many, and
    /// it is the whole protocol or nothing: both writers copy the connection's
    /// selection verbatim, so what this says is the name RFC 8446 §4.2.10
    /// asks the next connection to be the same as. A truncated name would be a
    /// different protocol, and every check below compares names.
    ///
    /// This is the one field the resuming end has to agree with, in both
    /// directions, and both directions are enforced rather than documented:
    /// `resumableTicket` offers a ticket only while the client's own proposal
    /// still holds this protocol — a ticket whose protocol the proposal no
    /// longer names is not offered at all, so the connection is a full
    /// handshake — and a server that opens this ticket compares the sealed
    /// name against the protocol it just selected and accepts no early data
    /// when they differ. A zero `alpn_len` is a ticket from a connection that
    /// negotiated no protocol, which matches a proposal of no protocols and
    /// no other.
    alpn: [negotiated_alpn_len_max]u8 = .{0} ** negotiated_alpn_len_max,
    /// Bytes of `alpn` in use. Whoever writes it keeps it at or below
    /// `alpn.len`, exactly as `ticket_len` does for `ticket`; `getAlpn` slices
    /// with it and does not re-check.
    alpn_len: u8 = 0,

    // RFC 9000 §7.4.1: remembered transport parameters for 0-RTT
    ///
    /// What the connection that issued the ticket was told, carried forward
    /// so a 0-RTT attempt is sent under limits the peer has already granted.
    /// These are an optimisation: dropping them costs 0-RTT its remembered
    /// limits and nothing else, and they are not consulted on a full
    /// handshake. A remembered limit below what the peer has since granted is
    /// simply superseded when the peer's own parameters arrive.
    initial_max_data: u64 = 0,
    initial_max_stream_data_bidi_local: u64 = 0,
    initial_max_stream_data_bidi_remote: u64 = 0,
    initial_max_stream_data_uni: u64 = 0,
    initial_max_streams_bidi: u64 = 0,
    initial_max_streams_uni: u64 = 0,
    /// The connection id limit to assume before the peer's parameters arrive.
    /// Two is RFC 9000 §5.1.1's floor and this stack's default; a peer that
    /// advertised a higher one supersedes it.
    active_connection_id_limit: u64 = 2,

    /// The opaque ticket bytes, as a slice of the inline array. Valid as long
    /// as the ticket is not moved or overwritten, and freed with nothing.
    /// Requires `ticket_len` at or below `ticket.len`, which is the writer's
    /// obligation and is not re-checked here.
    pub fn getTicket(self: *const SessionTicket) []const u8 {
        return self.ticket[0..self.ticket_len];
    }

    /// The protocol the connection that issued this ticket negotiated, whole
    /// and at most `negotiated_alpn_len_max` bytes. A resumed handshake offers
    /// this one again or offers no ticket at all; a zero `alpn_len` is a
    /// ticket from a connection that negotiated no protocol. Requires
    /// `alpn_len` at or below `alpn.len`, as `getTicket` does for `ticket_len`.
    pub fn getAlpn(self: *const SessionTicket) []const u8 {
        return self.alpn[0..self.alpn_len];
    }

    /// Whether the ticket is past `lifetime` at `now_s`. Both are seconds and
    /// the comparison is a plain difference, so the two must come off one
    /// epoch; nothing else consults the answer, and a caller holding a ticket
    /// is the only thing that can act on it. A zero `lifetime` — the default
    /// — makes it true one second past `creation_time`, the safe answer for a
    /// ticket whose lifetime was never recorded.
    pub fn isExpired(self: *const SessionTicket, now_s: i64) bool {
        return (now_s - self.creation_time) > @as(i64, self.lifetime);
    }
};

/// The fixed head of a sealed ticket's plaintext: psk(32) || creation_time(8)
/// || quic_version(4) || alpn_len(1). The protocol follows it and runs to the
/// tag, so both ends of the ticket path need this number too, for the same
/// reason `sealed_ticket_len` is named once.
const sealed_ticket_fixed_len = 45;

/// The largest sealed ticket this stack writes: that fixed head, a
/// ticket-sized protocol and AES-128-GCM's 16-byte tag. Named once because
/// both ends of the ticket path need the same number — the writer sizes its
/// buffer and the reader bounds what it will copy — and two spellings of it
/// are two chances to read past one of them.
///
/// The protocol runs to `negotiated_alpn_len_max` rather than to RFC 7301's
/// 255 because a negotiated protocol is bounded by what a selection can hold:
/// RFC 8446 needs the whole name to compare two connections by it, and this
/// stack's selection is `negotiated_alpn_len_max` bytes wide (see
/// `Tls13Handshake.selected_alpn`).
///
/// A ticket an older build of this stack sealed opens unchanged — the length
/// is inside the tag and the name is the last field of the plaintext — and a
/// name it cut short at 16 is then a name no proposal of the real protocol
/// holds, so such a ticket resumes nothing and costs its holder one full
/// handshake. That is the cost of not recording a prefix as if it were the
/// protocol, and it falls only on tickets already in a caller's hand.
const sealed_ticket_len = sealed_ticket_fixed_len + negotiated_alpn_len_max + 16;

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
    /// The AES-128-GCM key itself. Sixteen bytes, held in the clear because
    /// the process holding it is the one sealing tickets; nothing here
    /// protects it at rest, which is why it is generated once and never
    /// written anywhere else.
    bytes: [16]u8,

    /// Draws a key from `random`, the caller's generator, borrowed for the
    /// call and not retained. A value with no deinit and no owner: whoever
    /// holds it owns the tickets it seals and opens them for as long as it
    /// lives, and there is no setter, so replacing a key means replacing
    /// every config that holds it.
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
/// The tag says which payload belongs to which end, so one value is never
/// half of each: a ticket arrives with the role that offers it and a key with
/// the role that seals it. It does not check that role against the
/// handshake's own. A client config handed `.server` has no ticket to offer
/// — `clientTicket` answers null — and runs a full handshake; a server
/// config handed `.client` seals and accepts no ticket — `serverKey` answers
/// null — which costs resumption without failing anything.
pub const Resumption = union(enum) {
    /// This side is a server: it seals tickets under this key and opens them
    /// under it, and holds the key by value.
    server: TicketKey,
    /// This side is a client: it resumes with this ticket, and borrows it —
    /// the `TlsConfig.resumption` pointer must outlive the handshake.
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
///
/// The chain and the key are borrowed: both must outlive the `TlsConfig`
/// that holds this and the handshake built from it, and neither is copied;
/// `private_key_algorithm` is a value and keeps nothing alive. The key is
/// the one that signs *this* side's CertificateVerify — it is not the
/// peer's, and `ClientAuth.expect_node_id` is what says whose is whose.
pub const ServerCertificate = struct {
    /// DER-encoded certificates, leaf first.
    ///
    /// This stack never walks the chain: `liftEd25519Spki` reads the leaf and
    /// that is the whole of validation. The rest is carried so a peer that
    /// does walk it has something to walk.
    cert_chain_der: []const []const u8,
    /// Raw P-256 scalar or Ed25519 seed (32 bytes), or an RSA key's PKCS#1
    /// DER, as `extractPrivateKey` returns them.
    private_key_bytes: []const u8,
    /// Which algorithm the key above is. Defaults to P-256 because that is
    /// what `extractPrivateKey` most often returns; a caller supplying an
    /// Ed25519 or RSA key must set it, or the handshake will pick a scheme
    /// the key cannot sign with and fail with `error.HandshakeFailure`.
    private_key_algorithm: PrivateKeyAlgorithm = .ecdsa_p256_sha256,
};

/// A certificate served for a set of host names. Shared by the QUIC server
/// (`TlsConfig.certs`) and the TCP TLS server (`tls_server.Config.certs`).
pub const CertEntry = struct {
    /// Host names this certificate is served for. `"*.example.com"` matches
    /// exactly one label (`a.example.com`, not `example.com` or
    /// `a.b.example.com`). Matching is ASCII case-insensitive.
    server_names: []const []const u8,
    /// The certificate and key to present. Borrowed from the same storage
    /// `server_names` names, and like them it has to outlive every handshake
    /// this entry serves.
    cert: ServerCertificate,
    /// Ask clients that reach this certificate for one of their own.
    ///
    /// Overrides `TlsConfig.client_auth` for this entry only, because a
    /// certificate served for some names may have a different policy from
    /// one served for others. Null means the connection-wide policy applies,
    /// not that no certificate is asked for.
    client_auth: ?*const ClientAuth = null,
};

/// The certificate chosen for a ClientHello, and whether the client's name
/// chose it. `entry` points into the `entries` slice the selection was made
/// from, so both it and `CertEntry.cert` borrow that slice and die with it;
/// nothing is copied.
pub const CertSelection = struct {
    entry: *const CertEntry,
    /// False when the client sent no SNI or nothing matched it, so the first
    /// entry was used as the default.
    ///
    /// The distinction a caller needs: false means this certificate was
    /// served because nothing better was available, and a client that sent a
    /// name this server does not serve got a certificate for a different
    /// name. True means the name matched and nothing is wrong.
    matched: bool,
};

/// Picks the certificate for a ClientHello's SNI: an exact name first, then a
/// one-label wildcard, then `entries[0]`. Returns null only when `entries` is
/// empty.
///
/// `sni` is the host_name out of the extension, or null when the client sent
/// none; a trailing dot is stripped, because RFC 6066 forbids it and clients
/// send it anyway. Matching is ASCII case-insensitive, and a `"*."` entry
/// matches exactly one label. `entries` is borrowed and not retained, nothing
/// is allocated, and the only failure is an empty list.
pub fn selectCertificate(entries: []const CertEntry, sni: ?[]const u8) ?CertSelection {
    return selectCertificateFor(entries, sni, null);
}

/// `selectCertificate`, preferring within each step (exact, wildcard,
/// default) the first entry whose key can sign with one of `sig_algs`, the
/// client's signature_algorithms list body. The default step considers every
/// entry, so a client that cannot verify `entries[0]` gets another
/// certificate rather than a failed handshake.
///
/// `sig_algs` is the list body, borrowed and not retained; null is the same
/// as passing no preference at all, which is what `selectCertificate` does.
/// The preference only chooses *within* a step: an exact match whose key the
/// client cannot verify still wins over a wildcard whose key it can, because
/// the name is what the client asked for. The result borrows `entries` and
/// nothing is allocated, so the only failure is an empty list.
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
///
/// The result borrows `data`, so it lives as long as the parsed extension and
/// nothing is allocated. Null is a well-formed list with no host_name — a
/// client that sent no name — and is not an error.
///
/// `error.DecodeError` for anything malformed: a length that does not close
/// the extension, an empty list, a second host_name entry, or a zero-length
/// name. Other name types in the list are skipped rather than refused, since
/// RFC 6066 §3 defines them for other uses and this stack has none.
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
/// The slices and the pointers borrow, and the scalars are copied. Every
/// slice and every pointer — the chain, the key, the ALPN strings, the
/// certificate list, the client-auth policy, the fingerprint list, the SNI,
/// the remembered ticket and, on a client, the ticket `resumption` names —
/// has to outlive the `Tls13Handshake` built from this config, and the
/// handshake stores the config itself rather than references into it.
/// `private_key_algorithm`, `expect_peer_node_id`, `cipher_suite_only`,
/// `quic_version` and the `Resumption.server` ticket key are values copied
/// in whole, so no handle outside the config reaches them. There is no
/// `deinit` for a config — the caller frees whatever it pointed at, in its
/// own order.
///
/// Two of those borrows are pointers the handshake reads at more than one
/// point across the flight rather than once: `client_auth` is consulted when
/// the CertificateRequest is decided and again after the client's
/// CertificateVerify, and `resumption` is read by the constructor and again
/// when the ClientHello is built. `session_ticket` the handshake never reads
/// at all. `*const` stops a write *through* those pointers, not through the
/// caller's own handle to the same object, so a caller that rewrites the
/// `ClientAuth` or the `SessionTicket` between two `step` calls changes a
/// handshake already under way. Leave every field alone once a handshake has
/// been built.
///
/// It is a plain value and may be copied or rebuilt per connection; a copy
/// shares every borrow with the original and must outlive the same span.
///
/// There is no chain to walk and no flag to switch that off: a peer is
/// identified by the key its certificate carries, and the two ways of
/// saying which key that is — a node id (`expect_peer_node_id`) or a
/// fingerprint of the certificate itself (`cert_hashes`) — are fields here,
/// said separately, rather than one switch that stands for both.
pub const TlsConfig = struct {
    /// This side's own certificate chain, leaf first, used when `certs` is
    /// empty. Ignored on a client and whenever `certs` is non-empty.
    cert_chain_der: []const []const u8,
    /// See ServerCertificate.private_key_bytes
    ///
    /// The key that signs this side's CertificateVerify, on the same terms.
    private_key_bytes: []const u8,
    /// Which algorithm the key above is, with the same default and the same
    /// consequence of getting it wrong as `ServerCertificate`'s.
    private_key_algorithm: PrivateKeyAlgorithm = .ecdsa_p256_sha256,
    /// Server only: certificates chosen by the ClientHello's SNI (see
    /// `selectCertificate`). When non-empty, this replaces `cert_chain_der` /
    /// `private_key_bytes` / `private_key_algorithm`, with `certs[0]` as the
    /// default for a client that sends no SNI or an unknown name.
    certs: []const CertEntry = &.{},
    /// The application protocols this side will speak, in the order it
    /// prefers them. A client offers the whole list in this order and fails
    /// with `error.IllegalParameter` when the server names one it did not
    /// offer; a server walks this list, in this order, and takes the first
    /// entry the client also named, so the negotiated protocol is this side's
    /// preference among the ones both ends speak and not the client's order.
    /// That is RFC 7301 §3.2's rule — "the server SHOULD select the most
    /// highly preferred protocol that it supports and that is also advertised
    /// by the client" — and this list is where that preference is written
    /// down. The server fails with `error.NoApplicationProtocol` whenever the
    /// client sent an ALPN list and none of its entries is one this list holds
    /// — an empty list included, because a server that supports none of what a
    /// client advertised is that same section's `no_application_protocol`, and
    /// a peer let through with no protocol is what it exists to prevent. A
    /// ClientHello carrying no ALPN extension is the other case and nothing is
    /// echoed in it either: the extension is then absent in both directions,
    /// `negotiatedAlpn` answers `""`, and neither end fails.
    /// A name of no length is refused wherever it arrives: RFC 7301 §3.1's
    /// `ProtocolName` is `opaque <1..2^8-1>` and says "Empty strings MUST NOT
    /// be included", so an offer or a selection carrying one is a
    /// `error.DecodeError` on the side that receives it. This list is not
    /// checked for it here — `TlsConfig` is a public struct, and a caller who
    /// fills one in with an empty name is refused by the peer rather than by
    /// the type.
    ///
    /// Each name is at most `negotiated_alpn_len_max` bytes, which is what a
    /// selection can hold: a longer one has no encoding here, and a server is
    /// not one it can match rather than one it truncates. RFC 7301's own
    /// ceiling is 255. A list this stack cannot encode whole — too many names,
    /// or too many bytes together for the ClientHello — fails the client's
    /// first `step` with `error.InternalError`; it is not trimmed.
    alpn: []const []const u8,
    /// Server only: ask for a client certificate. With `certs`, a selected
    /// entry that names its own `client_auth` replaces this for the names it
    /// is served for; an entry that names none inherits this one.
    client_auth: ?*const ClientAuth = null,
    /// Client only: presented when the server asks for a certificate and its
    /// signature_algorithms list offers a scheme this key can sign with.
    /// Without one, or with none the key can use, the client answers with an
    /// empty Certificate and no CertificateVerify — an answer, not a refusal,
    /// and a server whose policy is `.required` rejects it with
    /// `error.CertificateRequired`.
    client_certificate: ?ServerCertificate = null,
    /// The host name to put in the ClientHello's server_name extension.
    /// Client only, borrowed for the handshake's life, and null means no SNI
    /// at all — which is what a client connecting by address rather than by
    /// name sends, and what makes a server pick its default certificate.
    ///
    /// RFC 6066 puts no ceiling on the name, so the only bound here is the
    /// ClientHello's: one too long to encode fails the client's first `step`
    /// with `error.InternalError` rather than being written past the end of
    /// that message.
    server_name: ?[]const u8 = null, // SNI (client only)
    /// The node id the peer's certificate has to carry, compared byte for
    /// byte against the 32 bytes lifted from its `SubjectPublicKeyInfo`. A
    /// client checks its server's leaf with it and a server with
    /// `client_auth` in force checks the client's, and a leaf carrying
    /// another key fails with `error.BadCertificate` either way. Null
    /// accepts any key, and then the peer has proved possession of whatever
    /// id it presented rather than being the node we wanted.
    expect_peer_node_id: ?[32]u8 = null,
    /// SHA-256 fingerprints of acceptable leaf certificates — the
    /// `serverCertificateHashes` bargain from the W3C WebTransport API, taken
    /// over the raw 44 bytes. When set, the fingerprint stands in for a
    /// chain; no chain is walked either way. A client checks its server's
    /// leaf against these and fails with `error.BadCertificate` when none
    /// matches; a server never consults them, so on that side
    /// `client_auth` is the only way to say which client is wanted.
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
    /// The only cipher suite this side will offer or accept. Null offers
    /// both suites this stack implements — `aes_128_gcm_sha256` and
    /// `chacha20_poly1305_sha256`, in that order — and accepts either.
    ///
    /// Set, it decides the suite of a resuming client too, and it wins: the
    /// offer and the 0-RTT keys are this field's, not the ticket's
    /// `SessionTicket.cipher_suite`, because the client has to settle the
    /// suite before any ServerHello can name one and this is the one field a
    /// caller sets for both ends. Null leaves that choice to the ticket where
    /// there is one. A server that has it set accepts no other suite and
    /// refuses a ClientHello offering only another with
    /// `error.UnsupportedVersion`.
    cipher_suite_only: ?quic_crypto.CipherSuite = null,
    /// The QUIC version the Handshake and 1-RTT keys are labelled for, which is
    /// the version the connection is speaking once negotiation is done: the
    /// label prefix goes into every one of those derivations, so a mismatch
    /// yields keys the peer cannot reproduce and every packet fails to decrypt
    /// rather than an error at handshake time.
    ///
    /// A server overwrites this during `step`, once and only as RFC 9368
    /// compatible version negotiation selects another version from the list the
    /// client offered. A connection that adopted a negotiated version writes it
    /// here too, before the flight that taught it.
    ///
    /// 0-RTT is the exception and is labelled for the version the first flight
    /// was built with instead — see
    /// `Tls13Handshake.original_version`, which a constructor copies from here
    /// before anything can change it.
    quic_version: u32 = protocol.QUIC_V1,
};

// ─── Handshake state machine ─────────────────────────────────────────

/// Everything `Tls13Handshake.step` can fail with, and what each one means on
/// the wire.
///
/// Any member ends the handshake: `Connection` translates it into a QUIC
/// close — `TransportParameterError` into a TRANSPORT_PARAMETER_ERROR
/// transport error, every other member into CRYPTO_ERROR carrying the TLS
/// alert named on that tag — and the handshake value is not used again, so
/// there is nothing left to resume and no step to undo.
///
/// The value itself is where the failing step left it. `step` may have
/// appended this peer's message to `transcript`, moved `state` on, or set a
/// `pending_install_*` flag before it failed, and a server that already
/// accepted a client certificate has duplicated it into `peer_cert`. So
/// `deinit` is still owed on a handshake that ends in an error exactly as on
/// one that completes — that allocation is the residue there is — and a
/// caller that keeps stepping drives a conversation that never happened.
///
/// The tags are exhaustive, so a `switch` over them is checked, and
/// `InternalError` is the catch-all for anything a local step could not do.
pub const HandshakeError = error{
    /// A message arrived in a state that does not allow it, or one this
    /// stack refuses in QUIC: KeyUpdate (RFC 9001 §6) and EndOfEarlyData
    /// (§8.3) both MUST NOT be used and are refused here rather than
    /// handled. Maps to the `unexpected_message` alert.
    UnexpectedMessage,
    /// A handshake message did not parse: a length that does not close it, a
    /// field past the end, or a list whose own length disagrees with its
    /// contents. The one error a peer can trigger deliberately and cheaply.
    /// Maps to `decode_error`.
    DecodeError,
    /// The peer's certificate is unusable for a reason that is not its
    /// signature: a chain longer than the caller allowed in
    /// `parseCertificateList`, a certificate the SPKI rules reject, or a
    /// lifted key that is not the node id this side pinned — a mismatch
    /// rather than a malformed certificate, and it lands here rather than on
    /// `BadCertificateVerify`. Maps to `bad_certificate`.
    BadCertificate,
    /// The peer's CertificateVerify did not verify under the key its
    /// certificate carries: a forged signature, a signature made with
    /// anything other than that key, or a scheme this stack does not
    /// verify. `verifyCertificateVerifySignature` answers the same for all
    /// three, so a caller cannot tell a forgery from an unsupported scheme,
    /// which is deliberate. Maps to `decrypt_error`.
    BadCertificateVerify,
    /// The peer's Finished did not verify against the transcript this side
    /// has. Maps to `decrypt_error`; the connection closes, so nothing after
    /// this point is recoverable.
    BadFinished,
    /// A local step failed that the peer did not cause: an output buffer too
    /// small for a message this stack builds, or a private key that will not
    /// parse. Maps to `internal_error`.
    InternalError,
    /// The key exchange produced nothing usable: the peer's P-256 point did
    /// not parse, the scalar multiplication failed, or the X25519 scalarmult
    /// returned an all-zero shared secret. Maps to `internal_error`, because
    /// telling a peer its point was rejected is information it can use.
    KeyScheduleError,
    /// The ClientHello or ServerHello offered no key share this side can use:
    /// no group in common, or none of the offered groups produced a usable
    /// share. Maps to `handshake_failure`.
    NoKeyShare,
    /// The peer's supported_versions named no version this stack speaks.
    /// Maps to `protocol_version`.
    UnsupportedVersion,
    /// The peer named no application protocol, or named one this side does
    /// not offer in `alpn`. Maps to `no_application_protocol`.
    NoApplicationProtocol,
    /// An extension this stack requires for the message was absent —
    /// supported_versions, key_share, `signature_algorithms` in a
    /// CertificateRequest, the RFC 9001 transport parameters, or RFC 7250's
    /// certificate-type extension: `client_certificate_type` and
    /// `server_certificate_type` on both sides, because an absent one is an
    /// implicit X.509 (RFC 7250 §4.1) and this stack reads only a raw
    /// `SubjectPublicKeyInfo`. Maps to `missing_extension`.
    MissingExtension,
    /// The peer's `signature_algorithms` named no scheme this side's own
    /// certificate can be signed with: `signatureSchemeFor` found nothing, so
    /// there is no CertificateVerify the handshake could have agreed on.
    /// Maps to `handshake_failure`, RFC 8446's answer to a message that names
    /// no mutually supported parameter.
    HandshakeFailure,
    /// RFC 7250 §4.2's outcome 2: this server read the ClientHello's
    /// `client_certificate_type` or `server_certificate_type` offer, supports
    /// the extension, and has no certificate type in common with the client —
    /// this side offers the raw key and the client's offer does not name it.
    /// The RFC names its own answer: "the server terminates the session with a
    /// fatal alert of type unsupported_certificate" (§4.2), and RFC 8446 §6.2
    /// still carries that alert at 43. Maps to `unsupported_certificate`.
    UnsupportedCertificate,
    /// The peer's QUIC transport parameters are malformed or violate a limit
    /// this stack enforces. The one member of this set that is *not* a TLS
    /// alert: `Connection` turns it into a QUIC TRANSPORT_PARAMETER_ERROR
    /// transport close instead of a CRYPTO_ERROR.
    TransportParameterError,
    /// `ClientAuth.mode` is `.required` and the client sent no certificate.
    /// Also raised when a server must sign and has no certificate at all.
    /// Maps to `certificate_required`.
    CertificateRequired,
    /// A field carried a value RFC 8446 or RFC 7250 forbids: a non-empty
    /// certificate_request_context, a second copy of an extension, a context
    /// where this stack sends none, or a certificate type the peer did not
    /// offer — RFC 7250 §4.2 makes selecting one the client never named an
    /// illegal parameter, and it is the same fact as the two disagreeing
    /// about what the `Certificate` payload carries. Maps to
    /// `illegal_parameter`.
    IllegalParameter,
};

/// What one `step` produced, for the caller to carry out. Exhaustive, so a
/// `switch` over it is checked — with `_continue` in it, which is why the
/// tags below carry what a caller is meant to do rather than only what the
/// handshake did.
pub const Action = union(enum) {
    /// Handshake bytes to hand to the crypto stream at `level`. The bytes
    /// borrow the handshake's own output buffer, so the caller must queue
    /// them before the next `step`.
    send_data: SendData,
    /// Packet protection keys for `level`, to install in the connection. The
    /// contexts own no allocation and borrow nothing, so the caller keeps
    /// them by value for as long as the connection uses them. Nothing
    /// replaces them: KeyUpdate is refused with
    /// `error.UnexpectedMessage` in QUIC, so these are the last keys this
    /// handshake produces.
    install_keys: InstallKeys,
    /// Nothing more can be done until `provideData` supplies more of the
    /// peer's flight. `step` may be called again before that and will keep
    /// answering this.
    wait_for_data,
    /// The handshake is done: `isComplete` is true, keys are installed, and
    /// further `step` calls answer `complete` while still consuming
    /// post-handshake messages a client can receive.
    complete,
    // Internal: signal to continue processing
    /// Not a caller-visible outcome. `step` uses it to tell its own loop to
    /// go round again after consuming a message without producing anything,
    /// and returns it by accident: a caller that treats it as an action will
    /// do nothing at all and spin.
    _continue,
};

/// One flight of handshake bytes, at the encryption level they must be sent
/// under.
pub const SendData = struct {
    /// Where to write them. The bytes go into the crypto stream for this
    /// level, and must go there before the next `step`: the slice they borrow
    /// is the handshake's output buffer, which the next flight overwrites.
    level: EncryptionLevel,
    /// The bytes, borrowing the handshake's `out_buf`. Valid until the next
    /// `step` and no longer; the caller copies them into the crypto stream
    /// and frees nothing.
    data: []const u8,
};

/// The packet protection contexts for one encryption level.
pub const InstallKeys = struct {
    /// Which level these are for. `.early_data` is 0-RTT and arrives before
    /// the handshake completes; the other three replace what the connection
    /// already holds.
    level: EncryptionLevel,
    /// The context for reading packets at this level. The peer writes with
    /// the traffic secret this side does not hold.
    ///
    /// At `.early_data` this is the one half that works on a server and must
    /// not be used on a client: there is no server early traffic secret, so
    /// the value here is built from the *client's* early secret and a client
    /// that used it would be trying to read its own packets.
    open: quic_crypto.Open,
    /// The context for writing packets at this level, holding this side's
    /// traffic secret. It owns no allocation and does not retain the
    /// handshake.
    ///
    /// At `.early_data` this is the one half that works on a client and must
    /// not be used on a server: RFC 9001 §5.6 forbids a server from
    /// protecting any packet with 0-RTT keys, and the value here is the
    /// client's early secret, so a server that wrote with it would be sending
    /// packets no client can read.
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

/// One TLS 1.3 handshake in progress, and its whole state.
///
/// It is about 52 KB, almost all of it the inbound and outbound flight
/// buffers, which is why `initClientInto` and `initServerInto` build it in
/// place rather than returning it by value. It is a single value with one
/// owner: the caller supplies the storage, and `deinit` releases what the
/// handshake allocated inside it. Copying one copies the whole 52 KB and
/// would leave two owners of `peer_cert`, so a handshake must not be
/// copied.
///
/// What it borrows is `config` and everything `config` points at, plus
/// `local_transport_params`, which is encoded into `tp_encoded` during
/// construction precisely so a later move cannot leave a dangling slice.
/// All of it must outlive the handshake.
///
/// It reads no clock and holds no entropy: `step` takes `now_s` and
/// `random` per call and stores neither, so the same handshake driven twice
/// with two clocks is two different handshakes. `peer_cert` is the one
/// allocation it makes, and only a server with client authentication in force
/// ever allocates it.
///
/// Not thread-safe.
pub const Tls13Handshake = struct {
    /// Where in the flight this handshake is. Internal state, but readable:
    /// it is what `isComplete` reports, and a caller resuming a suspended
    /// handshake has nothing else to reconstruct progress from.
    state: HandshakeState,
    /// Which end this side speaks, fixed at construction. Decides the
    /// transcript order, which secrets are ours, and whether a client
    /// certificate is expected.
    is_server: bool,
    /// Every handshake message so far, in wire order. Appended to before a
    /// message is acted on, which is what makes Finished and
    /// CertificateVerify verifiable.
    transcript: TranscriptHash,
    /// The secrets derived so far. `computed_handshake` and `computed_app`
    /// say which of them hold anything.
    key_schedule: KeySchedule,
    /// The configuration, copied in by value at construction. Every slice in
    /// it still borrows the caller's memory, which is why the whole of
    /// `TlsConfig`'s borrow obligation lands here too.
    config: TlsConfig,
    /// This side's QUIC transport parameters, sent in the extension. Their
    /// connection ids borrow the connection's own arrays and are encoded
    /// into `tp_encoded` here, so this value may be moved afterwards without
    /// dangling.
    ///
    /// Not fixed at construction: a server overwrites `version_info_chosen`
    /// during `step` when compatible version negotiation selects another
    /// version, and re-encodes `tp_encoded` to match. A client never changes
    /// it.
    local_transport_params: transport_params.TransportParams,
    /// The peer's, once its extension has been decoded and checked, or null
    /// before that. A decoded set of parameters borrows the buffer it was
    /// decoded from — here the handshake's own `in_buf` — so it must not be
    /// read after a later `provideData` compacts that buffer.
    peer_transport_params: ?transport_params.TransportParams = null,

    // X25519 key pair
    /// This side's X25519 private scalar. Written once by the `init*`
    /// constructors from `random` and never read again except to derive the
    /// shared secret; the peer never sees it.
    x25519_secret: [32]u8 = undefined,
    /// This side's X25519 public key, offered in the key_share. Sent to the
    /// peer in the clear.
    x25519_public: [32]u8 = undefined,
    /// The peer's X25519 public key from the key_share. Undefined until a
    /// key share has been processed, and only meaningful for the group in
    /// `negotiated_group`.
    peer_x25519_public: [32]u8 = undefined,

    // P-256 key exchange
    /// This side's P-256 private scalar, the same arrangement as
    /// `x25519_secret`. Offered alongside X25519 in the ClientHello so a peer
    /// that does not do X25519 still has a group in common.
    p256_secret: [32]u8 = undefined,
    /// our uncompressed public point — the 0x04-prefixed SEC1 form offered
    /// in the key_share, and therefore public.
    p256_public: [65]u8 = undefined,
    /// peer's uncompressed public point — undefined until a key share has
    /// been processed, and only meaningful for the group in
    /// `negotiated_group`.
    peer_p256_public: [65]u8 = undefined,
    /// The group the shared secret came from. The ClientHello offers both,
    /// and only the one the peer echoed is used; a key share for the other
    /// group is present but never read.
    negotiated_group: tls.NamedGroup = .x25519,

    // Outgoing flight, built in place; see limits.tls_handshake_out.
    /// The flight being assembled, and the buffer every `SendData.data`
    /// borrows. Fixed at `limits.tls_handshake_out` bytes, which is the
    /// ceiling on one flight; a flight that would exceed it fails with
    /// `error.InternalError` rather than growing.
    out_buf: [limits.tls_handshake_out]u8 = undefined,
    /// Bytes of `out_buf` valid.
    out_len: usize = 0,

    // Pending actions returned by step()
    /// Set when handshake keys are ready; consumed by the next `step`, which
    /// returns the `InstallKeys` instead of doing anything else. A caller
    /// that sees it has not yet installed handshake keys.
    pending_install_handshake: bool = false,
    /// The same for the application keys, which arrive after the peer's
    /// Finished has been verified.
    pending_install_app: bool = false,
    /// Whether handshake keys have been handed out. Kept so the connection
    /// can tell "installed" from "not yet offered".
    handshake_keys_installed: bool = false,
    /// Whether 1-RTT keys have been handed out. False on a connection that
    /// never completes, and the reason a client with no server Finished is
    /// not sending application data.
    app_keys_installed: bool = false,

    // Pre-encoded transport params (avoids dangling slice issues after struct move)
    /// This side's transport parameters, already encoded, so the extension
    /// body can be written after the struct has moved without following a
    /// slice into the caller's arrays. The size is
    /// `transport_params.encode_len_max`, the largest a well-formed
    /// `TransportParams` can encode to, so a value this stack built always
    /// fits and only a malformed one does not.
    tp_encoded: [transport_params.encode_len_max]u8 = undefined,
    /// Bytes of `tp_encoded` valid. An encode that did not fit leaves this
    /// zero and fails the caller with `error.InternalError`: a partial
    /// parameter list is never published, because a zero-length extension is
    /// an extension to the peer and not the absence one.
    tp_encoded_len: usize = 0,

    // Peer flight being reassembled; see limits.tls_handshake_in.
    /// The peer's bytes, copied in by `provideData` and parsed in place.
    /// Fixed at `limits.tls_handshake_in`; `provideData` drops whatever it
    /// cannot hold rather than failing, so a flight larger than the buffer
    /// stalls the handshake instead of ending it.
    in_buf: [limits.tls_handshake_in]u8 = undefined,
    /// Bytes of `in_buf` valid.
    in_len: usize = 0,
    /// How far into `in_buf` the parser has consumed. `provideData`
    /// compacts the buffer when this is past zero and the next copy would not
    /// fit, which is also why `peer_transport_params` must not be read after
    /// a later call.
    in_offset: usize = 0,

    // Client random for ServerHello matching
    /// The random this client put in its ClientHello, kept so the ServerHello
    /// can be checked against it.
    client_random: [32]u8 = undefined,

    // Peer's legacy_session_id from ClientHello (must be echoed in ServerHello)
    /// The `legacy_session_id` the client sent, echoed verbatim in the
    /// ServerHello. RFC 8446 §4.1.2 caps it at 32 bytes, which is this
    /// buffer's own length, so the cap is what reading it enforces: a longer
    /// one is `error.DecodeError` at parse time rather than an id echoed back
    /// with its tail cut off.
    peer_session_id: [32]u8 = .{0} ** 32,
    /// Bytes of `peer_session_id` in use, at most 32.
    peer_session_id_len: u8 = 0,

    // Server hello random
    /// The random from the ServerHello. Checked against nothing here; it is
    /// kept because the transcript needs the bytes and a re-encode would not
    /// reproduce them.
    server_random: [32]u8 = undefined,

    /// The peer's node id, lifted out of the 32 bytes its certificate's
    /// `SubjectPublicKeyInfo` carries. Null until a Certificate is accepted,
    /// and the only thing a lifted key ever has to be.
    ///
    /// Lifted, not compared: whether it is the node the caller wanted is
    /// decided by `TlsConfig.expect_peer_node_id`, and a mismatch ends the
    /// handshake rather than leaving this field set to something rejected.
    peer_node_id: ?[32]u8 = null,

    // RFC 7250 negotiation. Both are set only by the message that settles
    // them, and neither end reads the other's, so one pair of fields names
    // the same two facts from either side of the wire.

    /// What the `server_certificate_type` extension settled: RFC 7250 §4.2's
    /// selection in EncryptedExtensions, on a client, and the offer in the
    /// ClientHello this server accepted, on a server.
    ///
    /// `.x509` is both "not settled yet" and "settled as X.509", and the two
    /// are not told apart here for the same reason `selected_alpn_len`'s zero
    /// is not: RFC 7250 §4.1 makes an absent extension an implicit X.509, and
    /// an X.509 peer is refused before this field is read, so no path reaches
    /// a certificate carrying one.
    negotiated_server_certificate_type: CertificateType = .x509,

    /// The same for `client_certificate_type`, which governs the certificate
    /// *this* side sends when it is asked for one. On a client it is
    /// `.raw_public_key` or the empty `Certificate` is answered; on a server
    /// it is the type this server may read the client's leaf as.
    negotiated_client_certificate_type: CertificateType = .x509,

    // Transcript hash at server Finished for app key derivation
    /// The transcript as of the server's Finished, snapshotted because the
    /// application secrets are derived from that point and the transcript
    /// keeps moving afterwards.
    transcript_at_server_finished: [32]u8 = undefined,

    // Negotiated cipher suite (set during ServerHello processing)
    /// The suite this handshake is using. A server sets it from the
    /// ClientHello; a client that is not resuming sets it from whatever its
    /// own offer settles on, and a client that is resuming sets it from its
    /// ticket when it builds the ClientHello — it offers that one suite and
    /// nothing else, so the answer is settled before the 0-RTT keys it has to
    /// make first. A ServerHello naming another overwrites it.
    ///
    /// This is the value every `makeOpen` and `makeSeal` is built with, so it
    /// must be set before those are derived, not after.
    negotiated_cipher_suite: quic_crypto.CipherSuite = .aes_128_gcm_sha256,

    // PSK / 0-RTT fields
    /// Whether this handshake resumed from a ticket. A PSK skips the
    /// server's own Certificate and CertificateVerify and nothing else; it
    /// does not skip the client's certificate, because a session ticket is
    /// bearer material.
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
    /// Server side: which of `config.alpn` the client also offered. Where
    /// more than one entry matches it is this side's first of them, so the
    /// selection is this side's preference rather than the client's order.
    ///
    /// At most `negotiated_alpn_len_max` bytes, and always the whole name: a
    /// server that matched an entry copies all of it and refuses to match one
    /// it cannot hold whole, so what lands here is the protocol and not a
    /// prefix of it. A client whose server names a longer protocol fails with
    /// `error.IllegalParameter`, which is RFC 7301's own answer to a server
    /// that selects something outside RFC 7301's 255-byte ceiling.
    selected_alpn: [negotiated_alpn_len_max]u8 = .{0} ** negotiated_alpn_len_max,
    /// Bytes of `selected_alpn` in use, at most `selected_alpn.len`. Zero is
    /// both "not chosen yet" and "nothing matched", which are not told apart
    /// here: `negotiatedAlpn` answers the config's first entry for either. The
    /// two writers that record a ticket read this slice rather than that
    /// fallback, so a ticket records a protocol only where one was selected.
    selected_alpn_len: usize = 0,

    /// Server: the certificate we present — the config's single one, or the
    /// `config.certs` entry the ClientHello's SNI selected.
    server_cert: ServerCertificate = undefined,
    /// Server: the CertificateVerify scheme, picked from the ClientHello.
    server_sig_scheme: tls.SignatureScheme = .ecdsa_secp256r1_sha256,

    /// Server: whether 0-RTT was accepted. Three things have to hold and
    /// none of them is a licence on its own: the client offered the
    /// early_data extension, the PSK opened, and the protocol this connection
    /// selected is the one sealed inside that ticket — RFC 8446 §4.2.10 has
    /// the server verify it, and early data is the issuing connection's own
    /// data under its own protocol. A connection whose selection differs
    /// resumes and discards its early data; this is the answer the connection
    /// acts on.
    zero_rtt_accepted: bool = false,
    /// Set once the 0-RTT keys are ready; consumed by the next `step`, which
    /// returns the `InstallKeys` and nothing else. The first thing a resumed
    /// client is handed.
    pending_install_early: bool = false,
    /// A NewSessionTicket this side received, parsed. The client holds at
    /// most the most recent one, so a later ticket replaces this; null until
    /// one arrives, after a server has none, and after one that does not
    /// parse — a malformed ticket is dropped and the handshake continues,
    /// because `step` cannot fail on a message that arrived after it
    /// completed.
    ///
    /// Parsing is all that happens: the bytes stay sealed, no age or lifetime
    /// is checked, and `psk` is derived from this connection's own
    /// resumption master secret. Only the server that sealed them can open
    /// them, and it does so when the next connection offers them back.
    received_ticket: ?SessionTicket = null,
    /// Nonce counter for each ticket this server issues, incremented per
    /// ticket. It is what makes two tickets from one handshake differ, so a
    /// peer cannot tell a replay from a fresh ticket by the ciphertext
    /// alone.
    ticket_nonce_counter: u32 = 0,

    /// The QUIC version this connection's first flight is built with, copied
    /// from `config.quic_version` by the constructor and never changed.
    ///
    /// Compatible version negotiation moves `config.quic_version` to the
    /// negotiated version mid-handshake, and the 0-RTT keys must not follow it:
    /// RFC 9369 §4.1 has the client keep sending 0-RTT in the original version
    /// and the server processing it there, so these keys are labelled with this
    /// one whatever the handshake went on to negotiate. It is also the version
    /// a session ticket is checked against, in both directions.
    original_version: u32 = protocol.QUIC_V1,

    /// The protocol in force: what the server matched, or — on a client,
    /// or before a match — the first one we offered.
    ///
    /// A slice of `selected_alpn`, of `config.alpn[0]` — which is the
    /// caller's own storage and not the handshake's — or a static empty
    /// string. A slice of `selected_alpn` is invalidated by the next `step`
    /// that changes the selection; either other branch is as stable as the
    /// config it borrows. Before a handshake this is the config's first entry
    /// rather than an answer, so a caller that reads it early sees an
    /// intention, not a negotiation.
    ///
    /// The fallback is not a negotiated protocol and nothing treats it as
    /// one: a ticket records `selected_alpn` (see `SessionTicket.alpn`), and
    /// the server compares a ticket's sealed protocol against the same slice.
    pub fn negotiatedAlpn(self: *const @This()) []const u8 {
        if (self.selected_alpn_len > 0) return self.selected_alpn[0..self.selected_alpn_len];
        return if (self.config.alpn.len > 0) self.config.alpn[0] else "";
    }

    /// The ticket this connection may offer, or null when the one it was handed
    /// belongs to another QUIC version or to another application protocol.
    ///
    /// RFC 9369 §5: "Clients MUST NOT use a session ticket or token from a
    /// QUIC version 1 connection to initiate a QUIC version 2 connection, and
    /// vice versa." The version inside the ticket is the version of the
    /// connection that issued it, and this connection initiates on
    /// `original_version`, so a ticket issued on a connection that negotiated
    /// version 2 is usable only where this one starts on version 2.
    ///
    /// RFC 8446 §4.2.10 is the other half: "The parameters for the 0-RTT data
    /// (version, symmetric cipher suite, Application-Layer Protocol Negotiation
    /// (ALPN) protocol, etc.) are those associated with the PSK in use.  For
    /// PSKs established via a NewSessionTicket message, the associated values
    /// are those which were negotiated in the connection which established
    /// the PSK." So a ticket is offered only while this connection's own
    /// proposal still holds the protocol that ticket records: a ticket from an
    /// h3 connection is not offered by a client that now proposes h2 alone,
    /// and a ticket from a connection that negotiated no protocol is offered
    /// only by a client proposing none.
    ///
    /// Null is an ordinary handshake rather than a failure: the client offers
    /// no PSK, no early_data extension and no 0-RTT, and the server
    /// authenticates it the ordinary way.
    fn resumableTicket(self: *const @This()) ?*const SessionTicket {
        const ticket = Resumption.clientTicket(self.config.resumption) orelse return null;
        if (ticket.quic_version != self.original_version) return null;
        if (!proposalHoldsProtocol(self.config.alpn, ticket.getAlpn())) return null;
        return ticket;
    }

    /// Whether a client about to offer `proposal` may offer a ticket that
    /// records `selected_protocol`, under RFC 8446 §4.2.10's rule that the
    /// 0-RTT parameters are the ones the PSK was established with. The whole
    /// name or nothing: this is an equality over names, so a protocol cut
    /// short is a different protocol and does not match.
    ///
    /// An empty `selected_protocol` is a ticket from a connection that
    /// negotiated none, and it matches only a proposal of none: any name
    /// selected out of a non-empty proposal is one the ticket knows nothing
    /// about, which is the case RFC 8446 §4.2.10 forbids sending early data
    /// under.
    fn proposalHoldsProtocol(proposal: []const []const u8, selected_protocol: []const u8) bool {
        if (selected_protocol.len == 0) return proposal.len == 0;
        for (proposal) |offered| {
            if (std.mem.eql(u8, offered, selected_protocol)) return true;
        }
        return false;
    }

    /// Builds the client handshake in place. Tls13Handshake is ~52 KB, and
    /// returning it by value is the single largest contributor to the stack
    /// frame of anything that opens a connection — see quic/limits.zig.
    ///
    /// `random` is the caller's entropy, taken by value and drawn from only
    /// here. A handshake that reached for a global CSPRNG could not be driven
    /// twice with two different generators, and that is the property the pure
    /// core is for (DECISIONS/0002).
    ///
    /// `out` is the caller's storage and stays theirs; this fills it in place
    /// and never frees it. `config` is copied in, which copies its borrows
    /// and not the bytes behind them, so every slice in it — the chain, the
    /// key, the ALPN strings, the SNI, the resumption ticket — must outlive
    /// `out`. `local_tp` is read and encoded here and then not needed, so its
    /// own borrows end with this call. `random` is borrowed for the call and
    /// not retained: two key pairs and the greased transport parameter come
    /// from it and nothing is stored but the resulting keys.
    ///
    /// Fails with `error.InternalError` if transport-parameter encoding fails
    /// or both P-256 scalar draws are invalid. A legal `local_tp` fits
    /// `transport_params.encode_len_max`; an encoding failure publishes no
    /// parameter prefix. On either error, do not use the partially built `out`.
    /// Otherwise it does no I/O: a client is ready to send its ClientHello at
    /// the first `step`.
    ///
    /// A `config.server_name` or `config.alpn` that the ClientHello cannot hold
    /// is not refused here — this constructor reports only what it cannot
    /// build — and the first `step` fails with the same `error.InternalError`
    /// instead. Nothing is trimmed to make room; see `buildClientHello`.
    pub fn initClientInto(
        out: *Tls13Handshake,
        config: TlsConfig,
        local_tp: transport_params.TransportParams,
        random: std.Random,
    ) error{InternalError}!void {
        const self = out;
        self.state = .client_start;
        self.is_server = false;
        self.transcript = TranscriptHash.init();
        self.config = config;
        self.original_version = config.quic_version;
        self.local_transport_params = local_tp;
        // The ticket this connection may resume with, which is not the one it
        // was handed when the two are from different QUIC versions: the key
        // schedule starts from that one's PSK and from nothing else.
        self.key_schedule = if (self.resumableTicket()) |ticket|
            KeySchedule.initWithPsk(ticket.psk)
        else
            KeySchedule.init();
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
        self.negotiated_server_certificate_type = .x509;
        self.negotiated_client_certificate_type = .x509;
        self.zero_rtt_accepted = false;
        self.received_ticket = null;
        self.ticket_nonce_counter = 0;
        self.peer_session_id_len = 0;
        self.peer_session_id = .{0} ** 32;

        // `out` is the caller's storage and every field here is written by
        // hand, so this struct's own default does not apply: a handshake that
        // selects no protocol would otherwise read a length nothing set, and
        // slice `selected_alpn` with it. Zero is what "nothing selected"
        // means, and nothing reads past it.
        self.selected_alpn_len = 0;

        // Nothing is published until the encode below says how much there is.
        self.tp_encoded_len = 0;
        // Pre-encode transport params to avoid dangling slices after struct move.
        // `random` buys exactly one thing here and it is not a secret: the
        // greased parameter's id and its 1-4 value bytes. RFC 9000 §18.1
        // makes that pair a probe — a peer that only ever sees one id learns
        // to tolerate that id — so the caller is entitled to draw it afresh
        // per handshake, and no transport parameter is a key.
        self.tp_encoded_len = try encodeTransportParams(self.tp_encoded[0..], local_tp, random);

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
            break :blk P256.basePoint.mulPublic(self.p256_secret, .big) catch
                return error.InternalError;
        }).toUncompressedSec1();
        self.negotiated_group = .x25519;
    }

    /// `initClientInto` returning by value, with its failure contract. The
    /// same 52 KB is copied out of this frame and into the caller's, so
    /// prefer the `*Into` form wherever the stack has a fixed place to put
    /// one; a caller that wants a value may `deinit` it exactly once, as with
    /// any handshake.
    pub fn initClient(
        config: TlsConfig,
        local_tp: transport_params.TransportParams,
        random: std.Random,
    ) error{InternalError}!Tls13Handshake {
        var self: Tls13Handshake = undefined;
        try initClientInto(&self, config, local_tp, random);
        return self;
    }

    /// `initServerInto` returning by value, with the same stack cost, the
    /// same ownership and the same failure contract as `initClient`.
    pub fn initServer(
        config: TlsConfig,
        local_tp: transport_params.TransportParams,
        random: std.Random,
    ) error{InternalError}!Tls13Handshake {
        var self: Tls13Handshake = undefined;
        try initServerInto(&self, config, local_tp, random);
        return self;
    }

    /// Builds the server handshake in place — see initClientInto.
    ///
    /// A server generates no P-256 key pair: it only ever answers with the
    /// group the client chose, so there is nothing of its own to offer. The
    /// greased transport parameter is drawn from `random` for the same
    /// protocol-probe reason as on the client, and unlike the ECDSA nonce and
    /// the PSS salt, repeating it costs nothing.
    pub fn initServerInto(
        out: *Tls13Handshake,
        config: TlsConfig,
        local_tp: transport_params.TransportParams,
        random: std.Random,
    ) error{InternalError}!void {
        const self = out;
        self.state = .server_wait_client_hello;
        self.is_server = true;
        self.transcript = TranscriptHash.init();
        self.key_schedule = KeySchedule.init();
        self.config = config;
        self.original_version = config.quic_version;
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
        self.negotiated_server_certificate_type = .x509;
        self.negotiated_client_certificate_type = .x509;
        self.zero_rtt_accepted = false;
        self.received_ticket = null;
        self.ticket_nonce_counter = 0;
        self.peer_session_id_len = 0;
        self.peer_session_id = .{0} ** 32;

        // The same field and the same reason as the client edge above: `out`
        // is uninitialized storage, this initializer writes every other field
        // itself, and a server that has selected nothing — an offer list with
        // no entry in common, or no ALPN extension at all — must still answer
        // EncryptedExtensions with an empty selection rather than with whatever
        // length the storage happened to hold.
        self.selected_alpn_len = 0;

        self.tp_encoded_len = 0;
        self.tp_encoded_len = try encodeTransportParams(self.tp_encoded[0..], local_tp, random);

        // Generate X25519 key pair
        random.bytes(&self.x25519_secret);
        self.x25519_public = X25519.recoverPublicKey(self.x25519_secret) catch blk: {
            random.bytes(&self.x25519_secret);
            break :blk X25519.recoverPublicKey(self.x25519_secret) catch unreachable;
        };
        self.negotiated_group = .x25519;
    }

    /// Hands the handshake more of the peer's flight, copied in.
    ///
    /// `data` is borrowed for the call and copied, so the caller's buffer is
    /// free immediately and may be reused as soon as this returns. Bytes are
    /// appended to the handshake's own inbound buffer, compacted first when
    /// the consumed prefix has left room at the end; a caller may therefore
    /// pass a slice of any part of its own buffer, including one that
    /// overlaps a previous call's.
    ///
    /// It cannot fail and it never rejects: whatever does not fit in
    /// `limits.tls_handshake_in` is dropped rather than refused, so a peer
    /// that sends a flight larger than the buffer stalls this handshake
    /// instead of ending it, and no error tells the caller anything was
    /// lost. Handing over data does not advance the state machine — `step`
    /// does.
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

    /// Advances the handshake by one step and returns the action the caller
    /// must carry out. Call repeatedly until it answers `wait_for_data` or
    /// `complete`.
    ///
    /// Exactly one action per call, and the caller must finish carrying it out
    /// before calling again: a `SendData` borrows the handshake's output
    /// buffer and the next `step` overwrites it, and an `InstallKeys` must
    /// reach the connection before the packets it protects are built. Keys
    /// are offered ahead of any work the state machine would otherwise do, so
    /// the first calls after a key derivation return `install_keys` and make
    /// no progress beyond it.
    ///
    /// `now_s` is a whole second on the caller's own clock and `random` is the
    /// caller's entropy. Both are borrowed for this call and neither is stored,
    /// so one handshake can be driven from two different clocks.
    ///
    /// The one value written from `now_s` is a session ticket's creation time,
    /// and the one value subtracted from it is a ticket's age when a resuming
    /// client offers it, so every value on both sides of that subtraction has
    /// to come off the same clock. A ticket may be stored and resumed much
    /// later — across processes — so what the arithmetic needs is that the
    /// epoch matches on both ends, not that one clock object or one process
    /// stamped and aged it.
    ///
    /// Every member of `HandshakeError` ends the handshake: the caller closes
    /// the connection on it and does not use this value again. That set is the
    /// whole of what this signature can return, so a caller switching over it
    /// is checked rather than told by a comment. `step` may already have
    /// appended this peer's message to the transcript, moved the state machine
    /// on, or set a `pending_install_*` flag before failing, so a caller that
    /// keeps stepping after an error drives a conversation that never
    /// happened.
    pub fn step(self: *Tls13Handshake, now_s: i64, random: std.Random) HandshakeError!Action {
        // If we need to install early (0-RTT) keys, do that first. Both halves
        // come off the client's early traffic secret, and this handshake's
        // suite is already settled: a server chose it from the ClientHello and
        // a resuming client committed to it there, which is the whole of why
        // the two ends' 0-RTT keys agree.
        //
        // Labelled with the version this connection started on and not with
        // `config.quic_version`: RFC 9369 §4.1 has the client keep sending
        // 0-RTT in the version of its first flight and the server process it
        // there, so a server that has already switched to version 2 still
        // opens what a version-1 client sealed.
        if (self.pending_install_early) {
            self.pending_install_early = false;
            const cs = self.negotiated_cipher_suite;
            const qv = self.original_version;
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

    /// Whether the handshake has reached `connected`. True from the moment
    /// `step` first answers `complete`, and it stays true: post-handshake
    /// messages a client receives afterwards are still consumed by `step`
    /// without changing the answer. A NewSessionTicket is one of them.
    pub fn isComplete(self: *const Tls13Handshake) bool {
        return self.state == .connected;
    }

    /// Frees what the handshake allocated. The struct itself is the caller's.
    ///
    /// One allocation, `peer_cert`, and only a server that asked for a client
    /// certificate ever makes it. Released with `allocator`, which the
    /// connection set through the same field; a handshake built without one
    /// never allocated and so has nothing to free. Afterwards the handshake
    /// is unusable, `peerCertificate` answers null because `peer_cert` is
    /// cleared, and a second `deinit` is a no-op rather than a double free.
    pub fn deinit(self: *Tls13Handshake) void {
        if (self.peer_cert) |c| if (self.allocator) |a| a.free(c);
        self.peer_cert = null;
    }

    /// Server: the client's certificate — the 44-byte `SubjectPublicKeyInfo`
    /// its node id is wrapped in — once the handshake completes. Null when
    /// none was asked for, or `.optional` and none was sent.
    ///
    /// The slice is owned by the handshake and borrowed here: the caller
    /// frees nothing, and `deinit` releases it, so a slice taken before
    /// `deinit` dangles after it. It is null until the state reaches
    /// `connected` even on a server that did receive a certificate, so a
    /// caller reading it while the handshake is still running sees null
    /// rather than a partial answer.
    pub fn peerCertificate(self: *const Tls13Handshake) ?[]const u8 {
        if (self.state != .connected) return null;
        return self.peer_cert;
    }

    /// The node id the peer's certificate carried, or null before one was
    /// accepted. Compared against `expect_peer_node_id` when that is set;
    /// with no pin, this is a claim the peer proved it holds.
    ///
    /// By value, so it survives `deinit` and can be kept for the life of the
    /// connection. Null until `connected`, and — on a client, or on a server
    /// with client authentication off — null for good: there is no node id
    /// when no certificate was asked for, which is why this is not an
    /// accessor for "the peer's identity" but for "the certificate it
    /// presented".
    ///
    /// When `expect_peer_node_id` was set, a mismatch ended the handshake
    /// before it completed, so a non-null answer here is already the node
    /// that was asked for and not merely a key.
    pub fn peerNodeId(self: *const Tls13Handshake) ?[32]u8 {
        if (self.state != .connected) return null;
        return self.peer_node_id;
    }

    // ─── Client states ───────────────────────────────────────────────

    fn clientBuildHello(self: *Tls13Handshake, now_s: i64, random: std.Random) !Action {
        random.bytes(&self.client_random);

        // One ticket answers all three of the decisions below: the suite this
        // handshake therefore uses, the identity the ClientHello carries, and
        // whether there is an early data secret at all. The suite is settled
        // before the first flight rather than after the ServerHello, because a
        // resuming client derives its 0-RTT keys before a ServerHello can name
        // one and RFC 9001 §4.6 requires both endpoints to build 0-RTT out of
        // the same connection's information.
        //
        // `resumableTicket` answers null for a ticket from another QUIC
        // version, and a handshake with none of it is a full handshake rather
        // than a failed one: no PSK, no early_data extension, no 0-RTT.
        const ticket = self.resumableTicket();
        const sole_suite = soleOfferedCipherSuite(self.config, ticket);
        if (sole_suite) |cs| self.negotiated_cipher_suite = cs;

        var buf: [4096]u8 = undefined;
        const msg = buildClientHello(
            &buf,
            &self.client_random,
            &self.x25519_public,
            &self.p256_public,
            self.config.alpn,
            self.config.server_name,
            self.tp_encoded[0..self.tp_encoded_len],
            ticket,
            &self.key_schedule,
            sole_suite,
            now_s,
        ) catch return error.InternalError;

        self.transcript.update(msg);

        // If we have a session ticket, derive early data secret for 0-RTT
        if (ticket != null) {
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

        // Extensions. The block is the last field of a ServerHello, so a
        // length past the end of the message is one this side cannot honour:
        // a hostile peer chooses it, and it used to be sliced in.
        if (pos + 2 > body.len) return error.DecodeError;
        const ext_len = readU16(body[pos..]);
        pos += 2;
        if (ext_len > body.len - pos) return error.DecodeError;

        var found_key_share = false;
        var ext_pos: usize = 0;
        const ext_data = body[pos..][0..ext_len];
        while (ext_pos + 4 <= ext_data.len) {
            const etype = readU16(ext_data[ext_pos..]);
            ext_pos += 2;
            const elen = readU16(ext_data[ext_pos..]);
            ext_pos += 2;
            if (ext_pos + elen > ext_data.len) return error.DecodeError;

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

        // RFC 7250 §4.1 makes an absent extension an implicit X.509 and §4.2
        // has the client treat that as the server's certificate type. This
        // client offered one type, so a server that names no type has chosen
        // one it cannot present and this connection cannot be authenticated:
        // refused here, before any certificate is read. `clientProcessCertificate`
        // relies on it — it reads the leaf as a raw `SubjectPublicKeyInfo`,
        // which is only what that leaf is once this check has passed.
        if (self.negotiated_server_certificate_type != negotiated_certificate_type) {
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
        //
        // Three things have to hold before this side's own key goes on the
        // wire, and none of them is a licence on its own: the server asked,
        // EncryptedExtensions settled `client_certificate_type` as
        // RawPublicKey, and a key is configured whose scheme the
        // CertificateRequest offered. The middle one is RFC 7250 §4.1's
        // default doing its work — a server that named no type wanted X.509,
        // and this client holds a bare `SubjectPublicKeyInfo` rather than a
        // certificate, so the answer to that request is the empty list.
        //
        // Anything short of all three is that same answer, and the empty
        // list is the one the server is built to read: it sits in
        // `.server_wait_client_certificate` *because* it asked, so a flight
        // that skipped the Certificate left its Finished to be read as one
        // and refused the connection with `unexpected_message`. A client
        // declining to authenticate does not say that; RFC 8446 §6.2's
        // `certificate_required` is what it says, and `auth.mode == .required`
        // reaches it from `serverProcessClientCertificate` on exactly this
        // message.
        if (!self.certificate_requested) {
            // RFC 8446 4.4.2: the client's flight carries a Certificate only
            // when a CertificateRequest asked for one. An empty list unasked
            // is a message the peer is not in a state to read: a server that
            // never requested client auth waits for Finished here.
        } else if (self.clientAuthScheme()) |scheme| {
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

    /// The scheme this client signs its own `CertificateVerify` with, or null
    /// when the answer to a `CertificateRequest` is an empty
    /// `certificate_list`.
    ///
    /// RFC 8446 §4.4.2 makes the empty list the answer whenever there is
    /// nothing to put in it, and this is the one place that decides whether
    /// there is: no key configured, a key whose scheme the request never
    /// offered, or a `client_certificate_type` the RFC 7250 §4.1 default left
    /// at X.509 — for which a bare `SubjectPublicKeyInfo` is not an answer at
    /// all. A *server* wants one of these three; anything less has to be the
    /// empty list, because the alternative is a flight with no Certificate in
    /// it and a `Finished` the peer reads as one.
    fn clientAuthScheme(self: *const Tls13Handshake) ?tls.SignatureScheme {
        if (self.config.client_certificate == null) return null;
        if (!clientCertificateIsRaw(self)) return null;
        return self.client_sig_scheme;
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
        if (session_id_len > self.peer_session_id.len or session_id_len > body.len - pos) {
            return error.DecodeError;
        }
        self.peer_session_id_len = session_id_len;
        @memcpy(self.peer_session_id[0..session_id_len], body[pos..][0..session_id_len]);
        pos += session_id_len;

        // Cipher suites — select the best one we support. A peer chooses both
        // the length and every byte under it, so a list that does not fit in
        // the message — or one that ends half way through a suite — is refused
        // rather than read past. Nothing here is authenticated yet, so this is
        // the first thing an unauthenticated peer reaches.
        if (pos + 2 > body.len) return error.DecodeError;
        const cs_len = readU16(body[pos..]);
        pos += 2;
        if (cs_len % 2 != 0 or cs_len > body.len - pos) return error.DecodeError;

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
        if (cm_len > body.len - pos) return error.DecodeError;
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
                // The server's own order is the one that decides. `config.alpn`
                // is what this side prefers, so the outer walk is ours and the
                // inner one the client's: the first entry here the peer also
                // named is the protocol. Walking the client's list instead
                // hands the selection to a peer that leads with a protocol we
                // serve later, which is the opposite of what a preference
                // order means to the caller that registered these entries in
                // it. RFC 7301 §3.2 asks only that the echoed name be one the
                // client advertised, so this is the server's to choose.
                // RFC 7301 §3.1 types `protocol_name_list` at `2..2^16-1`, so a
                // body that cannot hold the list's own length is not a list with
                // nothing in it: the `else` below refuses it. A ClientHello that
                // advertises no protocol carries no extension at all, which is
                // the case this whole branch is not reached for.
                if (elen >= 2) {
                    // RFC 7301 §3.1's `protocol_name_list` is measured against
                    // a byte count, so the peer's length is read as a `usize`:
                    // a peer that writes `ff ff` names a list longer than any
                    // buffer, and adding two to it in a `u16` would overflow
                    // before the comparison below could answer that.
                    const list_len: usize = readU16(ext_data[ext_pos..]);
                    // Every entry is read once here, before the selection below
                    // and outside it. RFC 7301 §3.1 types each entry as
                    // `ProtocolName`, `opaque <1..2^8-1>`, and says "Empty
                    // strings MUST NOT be included": an entry of no length is
                    // a `decode_error` and not a name. It is refused here rather
                    // than inside the walk because that walk matches against
                    // `config.alpn`, which is a caller's own list, and a caller
                    // may hold an empty name in it — the entry below would then
                    // pair with the peer's and record no protocol at all, which
                    // is what `negotiatedAlpn` then reads as its fallback.
                    var name_pos: usize = 2;
                    while (name_pos < 2 + list_len and name_pos < elen) {
                        const proto_len = ext_data[ext_pos + name_pos];
                        if (proto_len == 0) return error.DecodeError;
                        name_pos += 1 + proto_len;
                    }
                    var matched = false;
                    selection: for (self.config.alpn) |our_proto| {

                        // This walk does not repeat the empty-name refusal, and
                        // the order is what makes that sound: a zero-length
                        // `ProtocolName` is refused before this walk can reach
                        // it, so it is a `decode_error` rather than an entry the
                        // walk steps over — including in a list of nothing but
                        // empty entries, which is that rather than the
                        // `no_application_protocol` below.

                        // An entry this stack cannot hold whole is not one
                        // it can match: `selected_alpn` is where the
                        // selection lives, and a prefix of a protocol name
                        // is a different protocol. Skipping it leaves the
                        // offer unmatched, which is the refusal below.
                        if (our_proto.len > self.selected_alpn.len) continue;
                        var alpn_pos: usize = 2;
                        while (alpn_pos < 2 + list_len and alpn_pos + 1 <= elen) {
                            const proto_len = ext_data[ext_pos + alpn_pos];
                            alpn_pos += 1;
                            if (alpn_pos + proto_len > elen) break;
                            const proto = ext_data[ext_pos + alpn_pos ..][0..proto_len];
                            alpn_pos += proto_len;
                            if (!std.mem.eql(u8, proto, our_proto)) continue;
                            @memcpy(self.selected_alpn[0..proto.len], proto);
                            self.selected_alpn_len = proto.len;
                            matched = true;
                            break :selection;
                        }
                    }
                    // RFC 7301 §3.2: "In the event that the server supports no
                    // protocols that the client advertises, then the server
                    // SHALL respond with a fatal no_application_protocol
                    // alert." An offer list with nothing in it supports none of
                    // what the client named, so this is that refusal: the walk
                    // above selected nothing, and letting a peer through with
                    // no protocol at all is the outcome the section forbids. A
                    // ClientHello carrying no ALPN extension never reaches here
                    // — nothing was advertised, so nothing is echoed.
                    if (!matched) return error.NoApplicationProtocol;
                } else return error.DecodeError;
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
            } else if (etype == @intFromEnum(tls.ExtensionType.client_certificate_type)) {
                // RFC 8446 §4.2 allows one copy of an extension per block, and
                // a second copy is refused rather than treated as a better
                // offer: which of two copies wins is precisely what a second
                // copy would be for. The field doubles as the "have I seen it"
                // record, because it only leaves its initial value here.
                if (self.negotiated_client_certificate_type != .x509) return error.IllegalParameter;
                const offer = parseCertificateTypeOffer(ext_data[ext_pos..][0..elen]) catch
                    return error.DecodeError;
                // RFC 7250 §4.2, outcome 2: this server has exactly one
                // certificate type to give, so a client that did not offer it
                // has nothing in common and the session ends. There is no
                // X.509 to fall back to — `liftEd25519Spki` is the whole of
                // this stack's certificate validation and it reads a raw
                // `SubjectPublicKeyInfo` or nothing.
                if (!offerContains(offer, negotiated_certificate_type)) {
                    return error.UnsupportedCertificate;
                }
                self.negotiated_client_certificate_type = negotiated_certificate_type;
            } else if (etype == @intFromEnum(tls.ExtensionType.server_certificate_type)) {
                if (self.negotiated_server_certificate_type != .x509) return error.IllegalParameter;
                const offer = parseCertificateTypeOffer(ext_data[ext_pos..][0..elen]) catch
                    return error.DecodeError;
                // The same outcome 2 for the other extension: this is the type
                // this server would sign its own flight with, and a client
                // that cannot read one of those cannot verify this handshake.
                if (!offerContains(offer, negotiated_certificate_type)) {
                    return error.UnsupportedCertificate;
                }
                self.negotiated_server_certificate_type = negotiated_certificate_type;
            }
            ext_pos += elen;
        }

        if (!found_key_share) return error.NoKeyShare;

        // RFC 7250 §4.1: a client that omits an extension has selected X.509
        // by default, and this stack has no X.509 verifier to fall back to —
        // so an absent offer is a refusal here rather than a default. It is
        // settled after the key share and with the other obligations this
        // message carries, so a hello wrong in more than one way is reported
        // for the one a client can act on first.
        if (self.negotiated_server_certificate_type != negotiated_certificate_type or
            self.negotiated_client_certificate_type != negotiated_certificate_type)
        {
            return error.MissingExtension;
        }

        // The connection-wide policy, unless the entry the SNI selected names
        // one of its own. An entry that names none inherits what the
        // connection set: a statement about which certificate is served is
        // not a statement that nobody has to identify themselves, and taking
        // it as one left an anonymous client past a required pin.
        self.client_auth = self.config.client_auth;
        if (self.config.certs.len > 0) {
            const entry = selectCertificateFor(self.config.certs, sni, sig_algs).?.entry;
            self.server_cert = entry.cert;
            self.client_auth = entry.client_auth orelse self.config.client_auth;
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
            self.tryProcessPsk(msg, ext_data, psk_ext_offset.?, psk_ext_len);
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
                    self.tp_encoded_len = encodeTransportParams(self.tp_encoded[0..], self.local_transport_params, random) catch |err| {
                        // A prefix reached the array; the length must not go
                        // with it, and this handshake is over anyway.
                        self.tp_encoded_len = 0;
                        return err;
                    };
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
        // What the next message is, decided once: a CertificateRequest is
        // asked for whenever a policy is in force, PSK or not; only this
        // server's own Certificate is what a PSK removes. RFC 7250 §4.2
        // reads that same fact — `client_certificate_type` is named only
        // when a CertificateRequest follows — so one value decides both the
        // extension and the state, rather than two that could disagree.
        const request_client_certificate = self.client_auth != null;
        const msg = buildEncryptedExtensionsFromEncoded(
            &buf,
            if (self.selected_alpn_len > 0) &selected else &.{},
            self.tp_encoded[0..self.tp_encoded_len],
            self.zero_rtt_accepted, // early_data only answers a client that asked
            request_client_certificate,
        ) catch return error.InternalError;

        self.transcript.update(msg);

        @memcpy(self.out_buf[0..msg.len], msg);
        self.out_len = msg.len;

        self.state = if (request_client_certificate)
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
    /// this server verified, and a pin is asked for even where the mode would
    /// let a client through with nothing: `.optional` is about what to do with
    /// a client that has no certificate, not about which node may be absent.
    /// `serverProcessClientCertificate` is the sole writer of `peer_node_id`
    /// and the sole comparison of `auth.expect_node_id`, and a PSK does not
    /// reach it — which is exactly why this is asked separately: the state
    /// machine routes a resumed connection through the CertificateRequest
    /// just as it routes a full one, and this refuses the handshake rather
    /// than the connection if some future path ever skips it. Both writers of
    /// `connected` ask it, so there is one answer and no flag to remember.
    fn serverIdentityEstablished(self: *const Tls13Handshake) bool {
        const auth = self.client_auth orelse return true;
        if (auth.expect_node_id != null) return self.peer_node_id != null;
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
            // An empty `certificate_list` is RFC 8446 §4.4.2's answer for a
            // client with nothing to offer, and it is an answer only where
            // nothing was asked. `.optional` waives the certificate; a pin is
            // a demand for the node itself, which an empty list is not. So a
            // pin refuses here too, which is what keeps the `optional` answer
            // below from completing a connection whose peer this server never
            // identified.
            if (auth.mode == .required or auth.expect_node_id != null) return error.CertificateRequired;
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

        // Build ticket plaintext: psk(32) || creation_time(8) || quic_version(4)
        // || alpn_len(1) || alpn. The version is inside the AEAD tag, so it is
        // the version this server issued the ticket under and not a claim a peer
        // made about it — which is what RFC 9369 §5 makes a server validate.
        // It is the negotiated version: a connection that used compatible
        // version negotiation issues its tokens from where it ended on.
        var ticket_plain: [sealed_ticket_fixed_len + negotiated_alpn_len_max]u8 = .{0} ** (sealed_ticket_fixed_len + negotiated_alpn_len_max);
        @memcpy(ticket_plain[0..32], &psk);
        std.mem.writeInt(i64, ticket_plain[32..40], now_s, .big);
        std.mem.writeInt(u32, ticket_plain[40..44], self.config.quic_version, .big);
        // The protocol this connection selected, whole: RFC 8446 §4.2.10 makes
        // the 0-RTT parameters the ones negotiated in the connection that
        // established the PSK, and the next connection compares this name. Not
        // `negotiatedAlpn`, whose fallback is this config's first entry and so
        // a protocol this connection never agreed to, and never a prefix of
        // either: a ticket that records one names a protocol no peer chose.
        const alpn_bytes = self.selected_alpn[0..self.selected_alpn_len];
        ticket_plain[sealed_ticket_fixed_len - 1] = @intCast(alpn_bytes.len);
        @memcpy(ticket_plain[sealed_ticket_fixed_len..][0..alpn_bytes.len], alpn_bytes);
        const plaintext_len = sealed_ticket_fixed_len + alpn_bytes.len;

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
        // Fixed plaintext plus AEAD tag, so a ticket this server sealed is one
        // of exactly two shapes: with the QUIC version it was issued under, or
        // the shorter one an earlier build of this same stack wrote. A ticket
        // shorter than the fixed head is that older shape, and there is
        // nothing in it to authenticate the version against, so it is refused
        // the same way a foreign one is.
        if (ciphertext_len < sealed_ticket_fixed_len) return;

        // The plaintext this stack seals is the fixed head and a protocol, and
        // the tag is the rest of the largest sealed ticket: a decrypted copy
        // cannot be longer than `sealed_ticket_len` minus the tag.
        var decrypted: [sealed_ticket_len - 16]u8 = undefined;
        var psk_found = false;
        var found_psk: [32]u8 = undefined;
        var found_version: u32 = 0;

        for (0..256) |nonce_try| {
            std.mem.writeInt(u32, ticket_nonce[8..12], @intCast(nonce_try), .big);
            var ct_copy: [sealed_ticket_len]u8 = undefined;
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

            @memcpy(&found_psk, decrypted[0..32]);
            found_version = std.mem.readInt(u32, decrypted[40..44], .big);
            psk_found = true;
            break;
        }

        if (!psk_found) return;

        // The protocol sealed alongside the PSK, which is the one the
        // connection that issued this ticket negotiated. It runs to the end of
        // the plaintext, so a length that overruns it is a plaintext this
        // stack did not write and there is nothing to compare.
        const ticket_alpn_len = decrypted[sealed_ticket_fixed_len - 1];
        if (sealed_ticket_fixed_len + ticket_alpn_len > ciphertext_len) return;
        const ticket_alpn = decrypted[sealed_ticket_fixed_len..][0..ticket_alpn_len];

        // RFC 9369 §5: "Servers MUST validate the originating version of any
        // session ticket or token and not accept one issued from a different
        // version. A rejected ticket results in falling back to a full TLS
        // handshake, without 0-RTT." Compared against the version this
        // connection started on, not the negotiated one: a version-1 first
        // flight may negotiate version 2 and still resume on a version-1
        // ticket, and its 0-RTT is processed in version 1 (RFC 9369 §4.1).
        if (found_version != self.original_version) {
            std.log.warn("session ticket issued for version 0x{x:0>8}, connection is version 0x{x:0>8}; falling back to a full handshake", .{
                found_version,
                self.original_version,
            });
            return;
        }

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
        var partial_hash: Sha256 = Sha256.init(.{});
        partial_hash.update(msg[0..partial_len]);
        const partial_transcript = partial_hash.finalResult();

        const expected_binder = KeySchedule.computeFinishedVerifyData(binder_key, partial_transcript);

        // Constant-time compare of the PSK binder HMAC (RFC 8446 §4.2.11.2).
        if (!crypto.timing_safe.eql([expected_binder.len]u8, received_binder.*, expected_binder)) {
            std.log.warn("PSK binder verification failed, falling back to full handshake", .{});
            return;
        }

        // RFC 8446 §4.2.10: "In order to accept early data, the server MUST
        // have accepted a PSK cipher suite and selected the first key offered
        // in the client's pre_shared_key extension.  In addition, it MUST
        // verify that the following values are the same as those associated
        // with the selected PSK: The TLS version number, The selected cipher
        // suite, The selected ALPN protocol, if any ... If any of these checks
        // fail, the server MUST NOT respond with the extension". The version
        // is the check above and the suite is structural — a resuming client
        // offers the one its ticket was issued for and nothing else — which
        // leaves the protocol: the sealed name above against the one this
        // connection selected.
        //
        // Resumption survives a mismatch and 0-RTT does not. Early data is the
        // issuing connection's own data, sealed under its protocol, and this
        // connection has named another, so it is discarded while the PSK is
        // still used for the 1-RTT handshake.
        const alpn_matches = std.mem.eql(u8, ticket_alpn, self.selected_alpn[0..self.selected_alpn_len]);
        if (!alpn_matches and self.early_data_offered) {
            std.log.warn("session ticket was issued for ALPN {s}, this connection selected {s}; resuming without early data", .{
                ticket_alpn,
                self.selected_alpn[0..self.selected_alpn_len],
            });
        }

        // Binder verified — now safe to install PSK key schedule
        self.key_schedule = temp_ks;
        self.using_psk = true;
        self.zero_rtt_accepted = self.early_data_offered and alpn_matches;
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
        // The suite this connection negotiated, which is what the next one
        // resumes under: 0-RTT keys are made before a ServerHello names one.
        ticket.cipher_suite = self.negotiated_cipher_suite;
        // The version this connection ended on, which is the version the
        // ticket belongs to (RFC 9369 §5) and therefore the only one a later
        // connection may resume it on.
        ticket.quic_version = self.config.quic_version;

        const copy_len: u16 = @intCast(@min(ticket_data.len, ticket.ticket.len));
        @memcpy(ticket.ticket[0..copy_len], ticket_data[0..copy_len]);
        ticket.ticket_len = copy_len;

        // The protocol the server answered with, not the first one this client
        // offered: this is the selection the EncryptedExtensions made, read
        // rather than `negotiatedAlpn`, whose fallback is this config's first
        // entry — so a connection that selected no protocol records none
        // rather than a name neither end chose. The whole name, because
        // RFC 8446 §4.2.10 has the next connection compare it and a prefix of
        // one is a different protocol.
        const alpn_src = self.selected_alpn[0..self.selected_alpn_len];
        @memcpy(ticket.alpn[0..alpn_src.len], alpn_src);
        ticket.alpn_len = @intCast(alpn_src.len);

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
                // RFC 7301 §3.1 types the name a selection carries as
                // `opaque <1..2^8-1>` and says "Empty strings MUST NOT be
                // included", so `{0, 1, 0}` is not a selection of no protocol:
                // all three checks above pass for it and `proto` below would be
                // the empty string, which leaves `selected_alpn_len` at zero —
                // what `negotiatedAlpn` reads as "nothing was selected" and
                // falls back from. Refused here, ahead of the membership loop
                // and not inside it: `config.alpn` is a caller's own list and
                // may hold an empty name for this to match.
                if (d[2] == 0) return error.DecodeError;
                const proto = d[3..];
                for (self.config.alpn) |ours| {
                    if (std.mem.eql(u8, ours, proto)) break;
                } else return error.IllegalParameter;
                if (proto.len > self.selected_alpn.len) return error.IllegalParameter;
                @memcpy(self.selected_alpn[0..proto.len], proto);
                self.selected_alpn_len = proto.len;
            } else if (etype == @intFromEnum(tls.ExtensionType.server_certificate_type)) {
                // RFC 8446 §4.2: one copy of an extension per block, and the
                // field is the record of whether one was seen.
                if (self.negotiated_server_certificate_type != .x509) return error.IllegalParameter;
                const selected = parseCertificateTypeSelection(ext_data[ext_pos..][0..elen]) catch
                    return error.DecodeError;
                // RFC 7250 §4.2: the selection must be one the client offered,
                // and the only one this client offers is the raw key. A
                // server that answers with anything else has chosen a
                // certificate format this handshake cannot read — the
                // receiving half of the downgrade this check exists for.
                if (selected != negotiated_certificate_type) return error.IllegalParameter;
                self.negotiated_server_certificate_type = selected;
            } else if (etype == @intFromEnum(tls.ExtensionType.client_certificate_type)) {
                if (self.negotiated_client_certificate_type != .x509) return error.IllegalParameter;
                const selected = parseCertificateTypeSelection(ext_data[ext_pos..][0..elen]) catch
                    return error.DecodeError;
                if (selected != negotiated_certificate_type) return error.IllegalParameter;
                self.negotiated_client_certificate_type = selected;
            }
            ext_pos += elen;
        }
    }
};

/// Whether the client may present a raw `SubjectPublicKeyInfo` as its own
/// certificate.
///
/// A single answer rather than something the caller of `step` has to
/// combine: RFC 8446 §4.4.2 says the answer to a CertificateRequest this
/// client cannot meet in the server's own terms is an *empty* certificate_list,
/// so "not negotiated" is an answer to send rather than an error to raise — a
/// server that required a certificate says so itself, with
/// `certificate_required`.
pub fn clientCertificateIsRaw(self: *const Tls13Handshake) bool {
    return self.negotiated_client_certificate_type == negotiated_certificate_type;
}

// ─── Message builders ────────────────────────────────────────────────

/// The single cipher suite a handshake offers, or null when the offer is open
/// to both suites this stack implements.
///
/// `TlsConfig.cipher_suite_only` narrows the offer whenever it is set. Failing
/// that, a client resuming from a ticket offers exactly the suite that ticket
/// was issued for and nothing else: its 0-RTT keys are derived before a
/// ServerHello names a suite, and RFC 9001 §4.6 requires both endpoints to
/// build 0-RTT out of the same connection's information, so the suite has to
/// be settled from what the client already holds rather than from the answer.
/// A server has no such reason and answers null — it takes what the offer
/// names.
///
/// `ticket` is the one the handshake resolved as usable for this connection's
/// QUIC version, or null when it has none, so a ticket it will not offer
/// cannot narrow the offer either.
fn soleOfferedCipherSuite(config: TlsConfig, ticket: ?*const SessionTicket) ?quic_crypto.CipherSuite {
    if (config.cipher_suite_only) |cs| return cs;
    if (ticket) |t| return t.cipher_suite;
    return null;
}

/// Encodes `local_tp` into `buf` and returns how many bytes it wrote.
///
/// `error.InternalError` when the set does not fit. `TransportParams.encode`
/// rolls nothing back, so a prefix has reached `buf` by then and nothing that
/// returns this answer may publish it: a parameter list truncated to a
/// length is a different set of limits to the peer, not a smaller one.
///
/// Its own function because that is the only way the failure is reachable in a
/// test — a well-formed `TransportParams` fits
/// `transport_params.encode_len_max` exactly, so a handshake never trips it.
fn encodeTransportParams(
    buf: []u8,
    local_tp: transport_params.TransportParams,
    random: std.Random,
) error{InternalError}!usize {
    var tp_fbs = io.fixedBufferStream(buf);
    local_tp.encode(&tp_fbs, random) catch return error.InternalError;
    return tp_fbs.seek;
}

/// Whether `payload_len` bytes of extension payload fit at `pos` in a message
/// buffer of `buf_len`, extension header included.
///
/// Every variable-length extension in `buildClientHello` asks this before it
/// writes anything: the payload is borrowed storage the caller owns and the
/// buffer is one fixed array, so the two are compared first.
fn extFits(buf_len: usize, pos: usize, payload_len: usize) bool {
    return 4 + payload_len <= buf_len - pos;
}

/// Builds a ClientHello into `buf` and returns the bytes it wrote, or
/// `error.InternalError` when the caller's own configuration does not fit.
///
/// Everything variable in this message is the caller's: the SNI name, the
/// protocol list, the transport parameters and the resumption ticket are all
/// borrowed storage whose length no upstream check bounds, and `buf` is one
/// fixed array. Each is measured against what is left of `buf` by `extFits`
/// before anything is written, so a proposal too large to encode is this error
/// rather than a write past the end of the message. Nothing is trimmed to make
/// room: a truncated name or a dropped protocol would be a different message,
/// and a peer cannot tell a short one from a whole one.
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
    sole_suite: ?quic_crypto.CipherSuite,
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

    // cipher_suites. `sole_suite` names the one suite a handshake that offers
    // exactly one uses; null is an open offer of both suites this stack
    // implements, AES first so a server free to choose takes it.
    if (sole_suite) |cs| {
        writeU16(buf[pos..], 2);
        pos += 2;
        writeU16(buf[pos..], @intFromEnum(cs));
        pos += 2;
    } else {
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

    // RFC 7250 §4.1: both offers, each a single-entry list. This is what
    // makes the peer's `Certificate` payload a bare Ed25519
    // `SubjectPublicKeyInfo` rather than an X.509 certificate this stack has
    // no way to read, and it is the first flight, so a peer that does not
    // speak RFC 7250 refuses here rather than after the certificate it cannot
    // present. `pre_shared_key` must stay last (RFC 8446 §4.2.11), and this
    // is nowhere near it.
    pos = writeCertificateTypeOffer(buf, pos, .client_certificate_type);
    pos = writeCertificateTypeOffer(buf, pos, .server_certificate_type);

    // SNI extension
    if (server_name) |sni| {
        // RFC 6066 puts no ceiling on the name and nothing upstream bounds
        // it, so this message's own size is the bound.
        const sni_ext_len = 2 + 1 + 2 + sni.len; // server_name_list_len + type + host_name_len + host_name
        if (!extFits(buf.len, pos, sni_ext_len)) return error.InternalError;
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
            // RFC 7301: ProtocolName is `opaque <1..2^8-1>`, so the length
            // byte below has no encoding for a longer name. Refused, not
            // truncated: a prefix of a protocol name is another protocol.
            if (proto.len > std.math.maxInt(u8)) return error.InternalError;
            alpn_total += 1 + proto.len;
        }
        if (!extFits(buf.len, pos, 2 + alpn_total)) return error.InternalError;
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
    if (!extFits(buf.len, pos, tp_encoded_data.len)) return error.InternalError;
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
        // Both extensions in one compare, before either is written: the empty
        // early_data header, and the PSK extension carrying the identity the
        // caller put in this ticket — `ticket_len` is its to keep honest, per
        // `SessionTicket.getTicket` — with the binder that signs it.
        if (!extFits(buf.len, pos, 4 + psk_ext_total)) return error.InternalError;

        // early_data extension (RFC 8446 §4.2.10) — empty payload in ClientHello
        // Tells the server we intend to send 0-RTT data
        pos = writeExtHeader(buf, pos, @intFromEnum(tls.ExtensionType.early_data), 0);

        // pre_shared_key extension (type=41) - MUST be last
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

/// Builds the TLS 1.3 EncryptedExtensions this server answers a
/// ClientHello with.
///
/// `request_client_certificate` is whether a CertificateRequest follows
/// this message, and it is the whole of the difference between the two
/// RFC 7250 selections: §4.2 requires `server_certificate_type` whenever the
/// server chose raw public keys for its own `Certificate`, and requires
/// `client_certificate_type` to be *omitted* unless the server asks for a
/// client certificate. ozai authenticates both ends, so both are on the wire
/// there; a server with no `client_auth` sends one and says nothing about the
/// other, which is what the RFC asks for and what a client with nothing to
/// present needs to hear.
fn buildEncryptedExtensionsFromEncoded(
    buf: []u8,
    alpn_list: []const []const u8,
    tp_encoded_data: []const u8,
    include_early_data: bool,
    request_client_certificate: bool,
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

    // RFC 7250 §4.2: what the `Certificate` payload will carry, in both
    // directions. Each is the one permitted value the client offered, and the
    // count in front of the list is gone — the selection is a bare
    // `CertificateType`, not a list of them.
    pos = writeCertificateTypeSelection(buf, pos, .server_certificate_type);
    if (request_client_certificate) {
        pos = writeCertificateTypeSelection(buf, pos, .client_certificate_type);
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

/// Writes the RFC 7250 §3 extension `ext_type` carrying the offer this stack
/// makes — a single-entry list naming `negotiated_certificate_type` — and
/// returns the position after it.
///
/// The length is a constant and both messages that use this are built into a
/// buffer this stack sizes itself, so there is nothing to measure: a client
/// that cannot hold eleven more bytes of fixed extension block is a client
/// whose `ClientHello` is already out of room, and `buildClientHello` reports
/// that on the parts it measures (`extFits`) rather than here.
fn writeCertificateTypeOffer(buf: []u8, pos: usize, ext_type: tls.ExtensionType) usize {
    const next = writeExtHeader(buf, pos, @intFromEnum(ext_type), certificate_type_offer_len);
    const body = encodeCertificateTypeOffer(buf[next..], negotiated_certificate_type) catch
        unreachable; // the header just reserved certificate_type_offer_len bytes
    return next + body.len;
}

/// Writes the RFC 7250 §3 extension `ext_type` carrying the selection this
/// server makes, and returns the position after it. The mirror of
/// `writeCertificateTypeOffer` in every byte but the one the RFC's grammar
/// drops: the count goes with the list.
fn writeCertificateTypeSelection(buf: []u8, pos: usize, ext_type: tls.ExtensionType) usize {
    const next = writeExtHeader(buf, pos, @intFromEnum(ext_type), certificate_type_selection_len);
    const body = encodeCertificateTypeSelection(buf[next..], negotiated_certificate_type) catch
        unreachable; // the header just reserved certificate_type_selection_len bytes
    return next + body.len;
}

fn readU16(data: []const u8) u16 {
    return std.mem.readInt(u16, data[0..2], .big);
}

fn writeU16(buf: []u8, val: u16) void {
    std.mem.writeInt(u16, buf[0..2], val, .big);
}

// ─── Minimal PEM parser ──────────────────────────────────────────────

/// Decodes the base64 body of the first `CERTIFICATE` section of `pem_data`
/// into `out`, and returns the slice of `out` it used.
///
/// The result borrows `out` and the caller frees nothing; the input is
/// borrowed too. Only the first section is read, so a PEM bundle of several
/// certificates yields the leaf. `error.DecodeError` for a missing or
/// unterminated marker, a body longer than the parser's 8 KiB scratch buffer,
/// a base64 body that will not decode, and a decoded length that does not fit
/// `out` — in that last case `out` is untouched, and the error is the same one
/// a malformed body gives, so a caller cannot tell a short buffer from bad
/// input except by sizing `out` correctly.
pub fn parsePemCert(pem_data: []const u8, out: []u8) ![]const u8 {
    return parsePemSection(pem_data, "CERTIFICATE", out);
}

/// Decodes a private key from `pem_data` into `out`, trying `EC PRIVATE KEY`,
/// then `RSA PRIVATE KEY`, then `PRIVATE KEY` (PKCS#8).
///
/// The result borrows `out` as in `parsePemCert`. Which label matched is not
/// reported: the DER is the same either way and `extractPrivateKey` is what
/// says what it is, so a caller that needs to know should call that. The
/// `error.DecodeError` of the last attempt is the one returned when none of
/// the three sections is present, which is why a key file with a
/// `-----BEGIN OPENSSH PRIVATE KEY-----` header reports a decode failure
/// rather than an unsupported format.
///
/// The three labels are tried into the same `out`, so a section that matched
/// and then failed leaves its bytes there; only the returned slice is the
/// answer, and a caller that reads past it reads whatever the last attempt
/// wrote.
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
//
// A slice of `der`, so the caller frees nothing and the DER must outlive
// whatever is configured from it. `error.DecodeError` for anything that is
// not that shape, including an EC key that is not P-256 — the scalar must be
// exactly 32 bytes, which is what makes this P-256 and not P-384. Nothing is
// allocated, so no failure leaves anything behind.
//
// Every length here is read through `readDerValue`, so one that runs past the
// bytes that follow it, a tag with nothing behind it and an indefinite length
// (0x80) are refused rather than indexed: the input is a file the caller
// opened, and a truncated one must not take the process with it. An
// ECPrivateKey carrying a public key or parameters after the scalar still
// parses; only the two fields this needs are read.
pub fn extractEcPrivateKey(der: []const u8) ![]const u8 {
    var outer_pos: usize = 0;
    const body = try readDerValue(der, &outer_pos, 0x30);

    var pos: usize = 0;
    _ = try readDerValue(body, &pos, 0x02); // version
    const private_key = try readDerValue(body, &pos, 0x04);
    if (private_key.len != 32) return error.DecodeError;
    return private_key;
}

// Extract the 32-byte raw private key from a PKCS#8 DER-encoded private key.
// PKCS#8: SEQUENCE { version, AlgorithmIdentifier, OCTET STRING { ECPrivateKey } }
//
// A slice of `der`, borrowed as in `extractEcPrivateKey`, and the same
// `error.DecodeError` for anything that does not walk. Every length here is
// read through `readDerValue`, so one that runs past the bytes that follow
// it, an indefinite length (0x80) and a key cut short are all refused rather
// than indexed: the input is a file the caller opened, and a truncated one
// must not take the process with it. The AlgorithmIdentifier is skipped
// rather than checked, so a PKCS#8 wrapper around a non-EC key is not
// recognised here — `extractPrivateKey` is what tries each shape in turn.
pub fn extractPkcs8EcPrivateKey(der: []const u8) ![]const u8 {
    var outer_pos: usize = 0;
    const outer = try readDerValue(der, &outer_pos, 0x30);

    var pos: usize = 0;
    _ = try readDerValue(outer, &pos, 0x02); // version
    _ = try readDerValue(outer, &pos, 0x30); // AlgorithmIdentifier, unchecked

    // The contained value is an ECPrivateKey.
    return extractEcPrivateKey(try readDerValue(outer, &pos, 0x04));
}

fn readDerValue(der: []const u8, pos: *usize, expected_tag: u8) ![]const u8 {
    if (pos.* >= der.len or der[pos.*] != expected_tag) return error.DecodeError;
    pos.* += 1;
    if (pos.* >= der.len) return error.DecodeError;

    var len: usize = der[pos.*];
    pos.* += 1;
    if (len & 0x80 != 0) {
        const num = len & 0x7f;
        if (num == 0 or num > @sizeOf(usize) or num > der.len - pos.*) return error.DecodeError;
        len = 0;
        for (0..num) |i| {
            len = (len << 8) | der[pos.* + i];
        }
        pos.* += num;
    }

    // Both forms of this bound are the same subtraction: `pos.* + len` is an
    // addition of two values a peer chose, and it wraps when `len` is the
    // eight-byte length it is allowed to be.
    if (len > der.len - pos.*) return error.DecodeError;
    const value = der[pos.*..][0..len];
    pos.* += len;
    return value;
}

// Extract the 32-byte Ed25519 seed from a PKCS#8 DER-encoded private key.
// RFC 8410: AlgorithmIdentifier OID 1.3.101.112, PrivateKey OCTET STRING.
//
// A slice of `der`, borrowed. Unlike the EC path this one *does* check the
// OID and refuses an AlgorithmIdentifier with anything else in it, and it
// accepts the seed either directly in the PrivateKey OCTET STRING or wrapped
// in one more (RFC 8410's CurvePrivateKey). `error.DecodeError` for anything
// else, including a seed that is not 32 bytes.
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

/// A private key lifted out of DER: the bytes to sign with, and which
/// algorithm they are. A plain value with no allocator; `bytes` borrows the
/// DER it was extracted from and dies with it.
pub const PrivateKey = struct {
    /// A slice of the DER it was extracted from.
    ///
    /// Not copied and not owned: it points into the caller's decoded buffer,
    /// so that buffer must outlive both this value and the `TlsConfig` it
    /// eventually reaches. What the bytes are depends on `algorithm` — a raw
    /// P-256 scalar or Ed25519 seed of exactly 32 bytes, or a whole PKCS#1
    /// RSAPrivateKey for RSA — which is why the two are not interchangeable
    /// and why `TlsConfig.private_key_algorithm` has to be set from this
    /// rather than assumed.
    bytes: []const u8,
    /// Which of the three shapes `bytes` is, and therefore what a config
    /// holding it must sign with. Taken from whichever extractor succeeded,
    /// so it cannot disagree with `bytes`.
    algorithm: PrivateKeyAlgorithm,
};

/// Recognizes an EC P-256 (SEC1 or PKCS#8), Ed25519 (PKCS#8) or RSA (PKCS#1
/// or PKCS#8) private key, as `parsePemPrivateKey` decodes it.
///
/// Tries the three shapes in that order and returns the first that fits, so
/// a DER that could parse as more than one resolves the same way every time.
/// The result borrows `der` and frees nothing.
///
/// `error.UnsupportedKey` when the DER is well formed but is none of the
/// three — a DSA key, say — and `error.InvalidKey` when it is an RSA key
/// whose numbers do not fit together, which is the one case where something
/// was recognised and then refused. Both leave `der` untouched and nothing
/// allocated.
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

    var srv = try Tls13Handshake.initServer(.{
        .cert_chain_der = &server.chain,
        .private_key_bytes = &server.seed,
        .private_key_algorithm = .ed25519,
        .alpn = &[_][]const u8{"h3"},
    }, tp, entropy.random());
    var cli = try Tls13Handshake.initClient(.{
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
    var srv = try Tls13Handshake.initServer(.{
        .cert_chain_der = &server.chain,
        .private_key_bytes = &server.seed,
        .private_key_algorithm = .ed25519,
        .alpn = &[_][]const u8{ "h3", "moqt-18", "moqt-17" },
    }, tp, entropy.random());
    var cli = try Tls13Handshake.initClient(.{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &[_][]const u8{ "moqt-17", "moqt-18" },
        .server_name = "localhost",
        .expect_peer_node_id = server.node_id,
    }, tp, entropy.random());
    try driveLoopback(&cli, &srv, entropy.random());
    // This side's order decides where the lists disagree: the server prefers
    // moqt-18 to moqt-17, and both ends must agree on the one that won.
    try std.testing.expectEqualStrings("moqt-18", srv.negotiatedAlpn());
    try std.testing.expectEqualStrings("moqt-18", cli.negotiatedAlpn());
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

    // The packet protection keys come off that secret through the suite the
    // handshake negotiated, not off a fixed-width array: ChaCha's key is 32
    // bytes where AES-128's is 16, and a caller handed the wrong width gets a
    // key the peer cannot reproduce.
    const seal = KeySchedule.makeSealFull(ks.client_early_traffic_secret, .chacha20_poly1305_sha256, protocol.QUIC_V1);
    try std.testing.expectEqual(quic_crypto.CipherSuite.chacha20_poly1305_sha256, seal.cipher_suite);
    try std.testing.expect(!std.mem.eql(u8, &seal.key, &(.{0} ** seal.key.len)));
    try std.testing.expect(!std.mem.eql(u8, &seal.nonce, &(.{0} ** seal.nonce.len)));
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
    var server1 = try Tls13Handshake.initServer(server_config, tp, entropy.random());
    var client1 = try Tls13Handshake.initClient(client_config, tp, entropy.random());

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

    var server2 = try Tls13Handshake.initServer(server_config, tp, entropy.random());
    var client2 = try Tls13Handshake.initClient(psk_client_config, tp, entropy.random());

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

    const without = try buildEncryptedExtensionsFromEncoded(&buf, &alpn, &.{}, false, false);
    const len_without = without.len;

    var buf2: [512]u8 = undefined;
    const with = try buildEncryptedExtensionsFromEncoded(&buf2, &alpn, &.{}, true, false);

    // The extension is 4 bytes of header and no payload (RFC 8446 §4.2.10).
    try std.testing.expectEqual(len_without + 4, with.len);
}

test "client answers a CertificateRequest with an empty Certificate" {
    // Cloudflare's edge asks for a client certificate — cdn.moq.dev failed
    // here with UnexpectedMessage — and RFC 8446 4.4.2 says the answer is a
    // Certificate message even with nothing to put in it.
    var entropy: Counted = .{};
    var client = try Tls13Handshake.initClient(.{
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
    var client = try Tls13Handshake.initClient(.{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &[_][]const u8{"h3"},
        .server_name = "localhost",
    }, .{}, entropy.random());

    client.state = .client_send_finished;
    const action = try client.step(test_now_s, entropy.random());
    try std.testing.expectEqual(@as(usize, 36), action.send_data.data.len);
}

test "client construction refuses two invalid P-256 scalars" {
    const ZeroRandom = struct {
        fn fill(_: *@This(), bytes: []u8) void {
            @memset(bytes, 0);
        }
    };
    var entropy: ZeroRandom = .{};
    const random = std.Random.init(&entropy, ZeroRandom.fill);
    const hs = try std.testing.allocator.create(Tls13Handshake);
    defer std.testing.allocator.destroy(hs);
    try std.testing.expectError(error.InternalError, Tls13Handshake.initClientInto(
        hs,
        .{ .cert_chain_der = &.{}, .private_key_bytes = &.{}, .alpn = &.{} },
        .{},
        random,
    ));
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
            try Tls13Handshake.initServerInto(hs, config, .{}, entropy.random());
        } else {
            try Tls13Handshake.initClientInto(hs, config, .{}, entropy.random());
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

    try Tls13Handshake.initServerInto(server, server_config, tp, entropy.random());
    server.allocator = gpa;
    defer server.deinit();
    try Tls13Handshake.initClientInto(client, client_config, tp, entropy.random());

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
/// `auth`. The policy goes on the config and on no entry, because an entry
/// that names none inherits it — which is the case these tests are about,
/// and which a helper that stamped the policy onto every entry could not see.
fn serverConfig(entries: []const CertEntry, auth: *const ClientAuth) TlsConfig {
    return .{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .certs = entries,
        .alpn = &[_][]const u8{"h3"},
        .client_auth = auth,
    };
}

/// The transport parameters a connection with compatible version negotiation
/// advertises: v1 as chosen, with v2 among the versions available, which is
/// what lets a server that also offers v2 switch to it mid-handshake.
const cvn_params = transport_params.TransportParams{
    .initial_max_data = 1 << 20,
    .initial_max_streams_bidi = 10,
    .version_info_chosen = protocol.QUIC_V1,
    .version_info_available = .{ protocol.QUIC_V2, protocol.QUIC_V1, 0, 0, 0, 0, 0, 0 },
    .version_info_available_count = 2,
};

/// The same connection without version information at all: the parameter is
/// absent, so nothing on this connection can negotiate away from v1.
const v1_only_params = transport_params.TransportParams{
    .initial_max_data = 1 << 20,
    .initial_max_streams_bidi = 10,
};

/// One connection's two ends, built from configs and kept so a test can
/// read what they made of it afterwards. 52 KB apiece, so they are heap.
const Ends = struct {
    server: *Tls13Handshake,

    client: *Tls13Handshake,

    fn init(gpa: std.mem.Allocator, cc: TlsConfig, sc: TlsConfig, random: std.Random) !Ends {
        return initWithParams(gpa, cc, sc, random, v1_only_params, v1_only_params);
    }

    /// `client_tp` and `server_tp` are this client's and this server's own
    /// parameters. They differ when one side offers a version the other does
    /// not, which is the whole of what decides whether the handshake switches.
    fn initWithParams(
        gpa: std.mem.Allocator,
        cc: TlsConfig,
        sc: TlsConfig,
        random: std.Random,
        client_tp: transport_params.TransportParams,
        server_tp: transport_params.TransportParams,
    ) !Ends {
        const server = try gpa.create(Tls13Handshake);
        errdefer gpa.destroy(server);
        const client = try gpa.create(Tls13Handshake);
        errdefer gpa.destroy(client);
        try Tls13Handshake.initServerInto(server, sc, server_tp, random);
        server.allocator = gpa;
        try Tls13Handshake.initClientInto(client, cc, client_tp, random);
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
                .send_data => {
                    // RFC 9369 §4.1: the client learns the negotiated version
                    // from the first long header that differs from the one it
                    // chose, and adopts it before that flight reaches TLS — the
                    // Handshake secrets both ends derive are labelled for it.
                    // `Connection.recv` makes that switch on the packet path;
                    // driving the two ends here has to make it too, or a
                    // negotiated connection cannot get past the ServerHello.
                    adoptNegotiatedVersion(ends);
                    ends.client.provideData(ends.server.out_buf[0..ends.server.out_len]);
                },
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

/// Adopts the server's negotiated version on the client, as RFC 9369 §4.1
/// says a client does once it reads it off a long header. A client only
/// accepts a version it offered as available, and the original version stays
/// what the 0-RTT keys are labelled for.
fn adoptNegotiatedVersion(ends: *Ends) void {
    const negotiated = ends.server.config.quic_version;
    if (negotiated == ends.client.config.quic_version) return;
    if (!protocol.isSupportedVersion(negotiated)) return;
    if (!ends.client.local_transport_params.hasAvailableVersion(negotiated)) return;
    ends.client.config.quic_version = negotiated;
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
    var server = try Tls13Handshake.initServer(.{
        .cert_chain_der = cert.cert_chain_der,
        .private_key_bytes = cert.private_key_bytes,
        .private_key_algorithm = cert.private_key_algorithm,
        .alpn = &[_][]const u8{"h3"},
    }, tp, entropy.random());
    var client = try Tls13Handshake.initClient(.{
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

    // Asked, and silent. `.required` refuses that. `.optional` completes with
    // no client identity at all, which is a server that asked and took the
    // answer for what it was — but only once the pin is off, because a pin is a
    // demand for a certificate that `.optional` does not waive (see
    // `ClientAuth.Mode.optional`). `mode` is what this sub-case is about, so it
    // is the pin that leaves, and it leaves here rather than at `auth`'s
    // declaration, where the two sub-cases above still need it.
    var silent = clientConfig(server.node_id, &client);
    silent.client_certificate = null;
    try std.testing.expectEqual(refused(error.CertificateRequired), try handshake(
        gpa,
        silent,
        serverConfig(&entries, &auth),
        &peer,
        &buf,
    ));
    // `mode` decides what to do with a client that has nothing; the pin is a
    // demand for a certificate, and it is not waived. So this sub-case reads
    // `mode` on its own.
    auth.expect_node_id = null;
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
    // here but present the wrong identity. The pin is back in play because
    // this sub-case is about which key the client may carry, and the mode is
    // back to `.required`.
    var wrong = silent;
    wrong.client_certificate = stranger.certificate();
    auth.expect_node_id = client.node_id;
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

    // A list length that a `u16` addition cannot hold. Nine bytes, and every
    // length in them closes: an empty context, a six-byte extension block, one
    // `signature_algorithms` extension of two bytes whose own list length is
    // `ff ff`. Read as a `u16`, `ff ff + 2` is an integer overflow and the
    // process aborts before the comparison can answer — so the failure this
    // case exists for is a crash and not a wrong expectation. That is also why
    // the body is written out here rather than filled until it looks large:
    // nothing in it is large except the one length that traps, and a constant
    // has no unwritten bytes for a reader to wonder about.
    const overflowing: [9]u8 = .{
        0, // certificate_request_context, empty
        0,
        6, // extensions<0..2^16-1>, and 3 + 6 closes the nine
        0,
        @intFromEnum(tls.ExtensionType.signature_algorithms),
        0,
        2, // extension_data<0..2^16-1>, and 7 + 2 closes it
        0xff,
        0xff, // SignatureScheme supported_signature_algorithms<2..2^16-1>
    };
    try std.testing.expectError(error.DecodeError, parseCertificateRequest(&overflowing));

    var chain: [2][]const u8 = undefined;
    try std.testing.expectEqual(null, try parseCertificateList(&.{ 0, 0, 0, 0 }, &chain));
    try std.testing.expectError(error.IllegalParameter, parseCertificateList(&.{ 1, 0, 0, 0 }, &chain));
    try std.testing.expectError(error.DecodeError, parseCertificateList(&.{ 0, 0, 0, 5, 0, 0, 1, 0xaa, 0 }, &chain));
    const one = [_]u8{ 0, 0, 0, 6, 0, 0, 1, 0xaa, 0, 0 };
    try std.testing.expectEqual(@as(usize, 1), (try parseCertificateList(&one, &chain)).?.len);
    const three = [_]u8{ 0, 0, 0, 18, 0, 0, 1, 0xaa, 0, 0, 0, 0, 1, 0xbb, 0, 0, 0, 0, 1, 0xcc, 0, 0 };
    try std.testing.expectError(error.BadCertificate, parseCertificateList(&three, &chain));
}

/// What a server makes of a ClientHello: the error it refused with, or null
/// for any answer at all. A fresh handshake per call, because a handshake
/// that has already refused is not one to ask again.
fn serverVerdict(hello: []const u8, random: std.Random) ?HandshakeError {
    var server = Tls13Handshake.initServer(.{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &.{},
    }, .{}, random) catch |err| return err;
    server.allocator = std.testing.allocator;
    defer server.deinit();
    server.provideData(hello);
    if (server.step(test_now_s, random)) |_| {} else |err| return err;
    return null;
}

/// What a client makes of a ServerHello, in the terms `serverVerdict` uses.
fn clientVerdict(hello: []const u8, random: std.Random) ?HandshakeError {
    var client = Tls13Handshake.initClient(.{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &[_][]const u8{"h3"},
        .server_name = "localhost",
    }, .{}, random) catch |err| return err;
    // Its own first flight, so the handshake is waiting for a ServerHello
    // rather than still writing the ClientHello that starts it.
    if (client.step(test_now_s, random)) |_| {} else |err| return err;
    client.provideData(hello);
    if (client.step(test_now_s, random)) |_| {} else |err| return err;
    return null;
}

test "a ClientHello with an invalid legacy session ID is refused" {
    var entropy: Counted = .{};
    const random = entropy.random();
    var truncated: [4 + 35 + 7]u8 = @splat(0);
    truncated[0] = @intFromEnum(tls.HandshakeType.client_hello);
    truncated[3] = truncated.len - 4;
    truncated[4] = 3;
    truncated[5] = 3;
    truncated[4 + 34] = 32;
    try std.testing.expectEqual(
        @as(?HandshakeError, error.DecodeError),
        serverVerdict(&truncated, random),
    );

    var overlong: [4 + 35 + 33 + 2]u8 = @splat(0);
    overlong[0] = @intFromEnum(tls.HandshakeType.client_hello);
    overlong[3] = overlong.len - 4;
    overlong[4] = 3;
    overlong[5] = 3;
    overlong[4 + 34] = 33;
    try std.testing.expectEqual(
        @as(?HandshakeError, error.DecodeError),
        serverVerdict(&overlong, random),
    );
}

test "a ClientHello whose cipher-suite list runs past the message is refused" {
    var entropy: Counted = .{};
    const random = entropy.random();
    var client = try Tls13Handshake.initClient(.{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &[_][]const u8{"h3"},
    }, .{}, random);
    if (client.step(test_now_s, random)) |_| {} else |err| return err;

    // A peer chooses both the message length and the bytes inside it, so this
    // is anything a sender can put on the wire. The list length sits after
    // the legacy_version, the 32 random bytes and the empty session id.
    const cs_len_at = 4 + 2 + 32 + 1;

    // A length of 0xFFFF in a message of two hundred bytes or so: the walk
    // read suites from past the end of the message it was walking, and a
    // server is reachable by anyone who can send it one CRYPTO frame.
    var overlong = client.out_buf[0..client.out_len];
    writeU16(overlong[cs_len_at..], 0xffff);
    try std.testing.expectEqual(@as(?HandshakeError, error.DecodeError), serverVerdict(overlong, random));

    // And a length of one, which is a list of no suites at all. Rounding it
    // down to the suites that fit is the same defect with a smaller number.
    var ragged = client.out_buf[0..client.out_len];
    writeU16(ragged[cs_len_at..], 1);
    try std.testing.expectEqual(@as(?HandshakeError, error.DecodeError), serverVerdict(ragged, random));
}

test "a ServerHello whose extension block runs past the message is refused" {
    var entropy: Counted = .{};
    const random = entropy.random();
    var client = try Tls13Handshake.initClient(.{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &[_][]const u8{"h3"},
    }, .{}, random);
    const ch = switch (try client.step(test_now_s, random)) {
        .send_data => |sd| sd.data,
        else => unreachable,
    };

    // The server offers the one protocol this client does. RFC 7301 §3.2
    // refuses a server that supports none of what a client advertised, and a
    // refusal here would take away the ServerHello this vector is about.
    // `sh.len > 0` below is the fixture's own proof that one was produced; what
    // the vector claims is the `DecodeError` the client answers with.
    var server = try Tls13Handshake.initServer(.{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &[_][]const u8{"h3"},
    }, .{}, random);
    server.provideData(ch);
    var sh: []const u8 = &.{};
    var turns: usize = 0;
    while (sh.len == 0 and turns < 8) : (turns += 1) {
        switch (try server.step(test_now_s, random)) {
            .send_data => |sd| sh = sd.data,
            else => {},
        }
    }
    try std.testing.expect(sh.len > 0);

    // The extension block is the last field of a ServerHello, so its length
    // sits after the empty session id echo, the cipher suite and the
    // compression method. A length past the message used to be sliced in.
    const ext_len_at = 4 + 2 + 32 + 1 + 2 + 1;
    var hello: [512]u8 = undefined;
    @memcpy(hello[0..sh.len], sh);
    var overlong = hello[0..sh.len];
    writeU16(overlong[ext_len_at..], 0xffff);
    try std.testing.expectEqual(@as(?HandshakeError, error.DecodeError), clientVerdict(overlong, random));
}

test "a selected certificate with no policy of its own inherits the connection's" {
    const gpa = std.testing.allocator;
    var server = Identity.init(server_seed);
    server.link();
    var client = Identity.init(client_seed);
    client.link();
    var stranger = Identity.init(@splat(0x22));
    stranger.link();

    // The connection-wide policy asks for a client certificate and pins it to
    // one node. The entry the SNI selects says nothing about either, which is
    // a statement about that certificate, not a waiver of the connection's.
    const auth: ClientAuth = .{ .expect_node_id = client.node_id, .mode = .required };
    const entries = [_]CertEntry{.{ .server_names = &.{"relay.test"}, .cert = server.certificate() }};
    const server_config = TlsConfig{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .certs = &entries,
        .alpn = &[_][]const u8{"h3"},
        .client_auth = &auth,
    };
    var peer: ?[]const u8 = null;
    var buf: [ed25519_spki_len]u8 = undefined;

    // An anonymous client cannot walk past a required policy by being served
    // a certificate entry that names none: the pin is in force, so the
    // CertificateRequest is sent and an empty answer is refused.
    var anonymous = clientConfig(server.node_id, &client);
    anonymous.client_certificate = null;
    try std.testing.expectEqual(
        refused(error.CertificateRequired),
        try handshake(gpa, anonymous, server_config, &peer, &buf),
    );

    // And the client that does hold the pinned key still completes, and is
    // still judged against it.
    try std.testing.expectEqual(null, try handshake(
        gpa,
        clientConfig(server.node_id, &client),
        server_config,
        &peer,
        &buf,
    ));
    try std.testing.expectEqualSlices(u8, &client.spki, peer.?);

    // And a client holding somebody else's key is refused against the
    // inherited pin rather than waved through.
    var wrong = clientConfig(server.node_id, &client);
    wrong.client_certificate = stranger.certificate();
    try std.testing.expectEqual(refused(error.BadCertificate), try handshake(
        gpa,
        wrong,
        server_config,
        &peer,
        &buf,
    ));
}

/// The 0-RTT keys one connection installed at each end. Both halves are built
/// from the client's early traffic secret, so the seal a client made and the
/// open a server made have to be the same key or neither can read the other.
const EarlyKeys = struct {
    client_seal: quic_crypto.Seal,
    server_open: quic_crypto.Open,
};

/// Drives one connection to completion, collecting the 0-RTT keys each end
/// installs when `out` is given, then pumps the NewSessionTicket that leaves
/// the client holding a ticket the next connection can resume under.
fn pumpEarlyKeys(srv: *Tls13Handshake, cli: *Tls13Handshake, random: std.Random, out: ?*EarlyKeys) !void {
    var client_done = false;
    var server_done = false;
    var i: usize = 0;
    while ((!client_done or !server_done) and i < 100) : (i += 1) {
        if (!client_done) {
            switch (try cli.step(test_now_s, random)) {
                .send_data => |sd| srv.provideData(sd.data),
                .install_keys => |ik| {
                    if (ik.level == .early_data and out != null) out.?.client_seal = ik.seal;
                },
                .complete => client_done = true,
                else => {},
            }
        }
        if (!server_done) {
            switch (try srv.step(test_now_s, random)) {
                .send_data => cli.provideData(srv.out_buf[0..srv.out_len]),
                .install_keys => |ik| {
                    if (ik.level == .early_data and out != null) out.?.server_open = ik.open;
                },
                .complete => server_done = true,
                else => {},
            }
        }
    }
    if (!client_done or !server_done) return error.HandshakeStalled;

    var post: usize = 0;
    while (post < 8) : (post += 1) {
        switch (try cli.step(test_now_s, random)) {
            ._continue => continue,
            else => break,
        }
    }
}

test "both ends make the same 0-RTT keys when the suite is ChaCha" {
    // A client installs 0-RTT keys before any ServerHello has named a suite,
    // so the suite it makes them with has to be the one it offered. With
    // `cipher_suite_only = .chacha20_poly1305_sha256` the client made AES
    // keys and the server ChaCha ones, and neither end could read the first
    // flight of the resumed connection.
    //
    // The resumed connection narrows nothing: `cipher_suite_only` is null on
    // both ends, so a handshake between these two free to choose settles on
    // AES, and what has to carry the resumed connection to ChaCha instead is
    // the ticket. That the two ends agree on a suite is not evidence they
    // agreed on the ticket's — a client offering both suites and a server
    // answering from the offer agree on AES just as readily as on ChaCha.
    // What settles it is the first flight on the wire: the client seals it
    // under the early keys it installed and the server opens it under the
    // ones it installed, and a key from the wrong suite fails the tag.
    const gpa = std.testing.allocator;
    var entropy: Counted = .{};
    const random = entropy.random();
    var server = Identity.init(server_seed);
    server.link();

    const server_config = TlsConfig{
        .cert_chain_der = &server.chain,
        .private_key_bytes = &server.seed,
        .private_key_algorithm = .ed25519,
        .alpn = &[_][]const u8{"h3"},
        .cipher_suite_only = .chacha20_poly1305_sha256,
        .resumption = .{ .server = TicketKey.generate(random) },
    };
    const client_config = TlsConfig{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &[_][]const u8{"h3"},
        .server_name = "relay.test",
        .expect_peer_node_id = server.node_id,
        .cipher_suite_only = .chacha20_poly1305_sha256,
    };

    var first = try Ends.init(gpa, client_config, server_config, random);
    defer first.deinit(gpa);
    try pumpEarlyKeys(first.server, first.client, random, null);
    const ticket = first.client.received_ticket orelse return error.HandshakeStalled;
    try std.testing.expectEqual(quic_crypto.CipherSuite.chacha20_poly1305_sha256, ticket.cipher_suite);

    // The same pair of ends, now configured to name no suite at all, so what
    // the ticket says and what either would otherwise pick are not the same
    // answer.
    var resuming = client_config;
    resuming.cipher_suite_only = null;
    resuming.resumption = .{ .client = &ticket };
    var resuming_server = server_config;
    resuming_server.cipher_suite_only = null;
    var second = try Ends.init(gpa, resuming, resuming_server, random);
    defer second.deinit(gpa);

    var keys: EarlyKeys = undefined;
    try pumpEarlyKeys(second.server, second.client, random, &keys);
    // A ticket is bearer material only over an authenticated PSK, and 0-RTT
    // keys exist because this connection resumed; a fallback to a full
    // handshake would leave both ends without any to install.
    try std.testing.expect(second.client.using_psk);
    try std.testing.expect(second.server.using_psk);
    try std.testing.expectEqual(quic_crypto.CipherSuite.chacha20_poly1305_sha256, keys.client_seal.cipher_suite);
    try std.testing.expectEqual(quic_crypto.CipherSuite.chacha20_poly1305_sha256, keys.server_open.cipher_suite);

    // That first flight, as it goes on the wire: a 0-RTT long header
    // (RFC 9000 §17.2.2) whose first byte carries a one-byte packet number,
    // then the version, the destination connection ID, and the Length that
    // covers the packet number, the payload and the tag. The payload is a
    // STREAM frame (RFC 9000 §19.8); the header is only ever authenticated,
    // which is why it is passed to both halves as associated data.
    const pn: u64 = 3;
    const tag_len = quic_crypto.Aead.tag_length;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const pn_offset = 1 + 4 + 1 + dcid.len + 1 + 2;
    const payload_start = pn_offset + 1;
    const plaintext = [_]u8{ 0x08, 0x04, 'r', 'e', 'l', 'a', 'y', '.', 't', 'e', 's', 't', '/', '3' };

    var packet: [payload_start + plaintext.len + tag_len]u8 = undefined;
    packet[0] = 0xd0; // long header, 0-RTT type, one-byte packet number
    writeU16(packet[1..], @intCast(protocol.QUIC_V1));
    packet[5] = @intCast(dcid.len);
    @memcpy(packet[6..][0..dcid.len], &dcid);
    packet[6 + dcid.len] = 0x00; // no source connection ID
    writeU16(packet[7 + dcid.len ..], 0x4000 | @as(u16, @intCast(1 + plaintext.len + tag_len)));
    packet[pn_offset] = @intCast(pn);

    const sealed_len = keys.client_seal.encryptPayload(pn, packet[0..payload_start], &plaintext, packet[payload_start..]);
    try std.testing.expectEqual(plaintext.len + tag_len, sealed_len);
    keys.client_seal.applyHeaderProtection(packet[0..], pn_offset, 1);

    // The server's end of it. Header protection is keyed by the hp_key and
    // the AEAD by the key, the nonce and the suite, so this is where two ends
    // that derived different 0-RTT keys — a client that offered AES and sealed
    // under it, a server that answered with a suite the ticket never named —
    // stop being able to read the client at all.
    const recovered_pn_len = quic_crypto.removeHeaderProtection(
        packet[0..],
        pn_offset,
        keys.server_open.hp_key,
        keys.server_open.cipher_suite,
    );
    try std.testing.expectEqual(@as(usize, 1), recovered_pn_len);
    try std.testing.expectEqual(@as(u8, @intCast(pn)), packet[pn_offset]);
    const opened = try keys.server_open.decryptPayload(
        packet[pn_offset],
        packet[0..payload_start],
        packet[payload_start..],
    );
    try std.testing.expectEqualSlices(u8, &plaintext, opened);
}

test "0-RTT keys keep the first flight's version after a compatible switch" {
    // RFC 9369 §4.1: "Servers can accept 0-RTT and then process 0-RTT packets
    // from the original version." The 0-RTT traffic secret does not depend on
    // the version, but the packet-protection keys built from it do: `quic key`
    // and `quicv2 key` derive different bytes from one secret. A server that
    // switched its handshake to v2 and then labelled its early keys v2 opens
    // nothing the client sealed under the first flight's v1 labels, so every
    // 0-RTT packet is discarded before the handshake gets anywhere.
    const gpa = std.testing.allocator;
    var entropy = Counted{};
    const random = entropy.random();
    var server = Identity.init(server_seed);
    server.link();

    const server_config = TlsConfig{
        .cert_chain_der = &server.chain,
        .private_key_bytes = &server.seed,
        .private_key_algorithm = .ed25519,
        .alpn = &[_][]const u8{"h3"},
        .resumption = .{ .server = TicketKey.generate(random) },
    };
    const client_config = TlsConfig{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &[_][]const u8{"h3"},
        .server_name = "relay.test",
        .expect_peer_node_id = server.node_id,
    };

    // A version-1 connection is what issues the ticket: a ticket belongs to
    // the connection that issued it, and the second connection below starts on
    // version 1 as well.
    var first = try Ends.initWithParams(gpa, client_config, server_config, random, v1_only_params, v1_only_params);
    defer first.deinit(gpa);
    try std.testing.expect((try connect(&first, random)) == null);
    var ticket = first.client.received_ticket orelse return error.HandshakeStalled;

    // The second connection offers version 2 as available, so the server
    // negotiates it — and the ticket is still this connection's, because it
    // was issued for a version-1 first flight.
    var resuming = client_config;
    resuming.resumption = .{ .client = &ticket };
    var second = try Ends.initWithParams(gpa, resuming, server_config, random, cvn_params, cvn_params);
    defer second.deinit(gpa);

    // Both ends as far as their 0-RTT keys and no further: the Handshake
    // secrets are where this connection's two versions part company, and that
    // is a different question from which labels the early keys carry.
    var keys: EarlyKeys = undefined;
    switch (try second.client.step(test_now_s, random)) {
        .send_data => |sd| second.server.provideData(sd.data),
        else => return error.HandshakeStalled,
    }
    switch (try second.client.step(test_now_s, random)) {
        .install_keys => |ik| if (ik.level == .early_data) {
            keys.client_seal = ik.seal;
        } else return error.HandshakeStalled,
        else => return error.HandshakeStalled,
    }
    // The ClientHello is what the server decides on, so this is where it
    // switches. A server that never switched would pass the assertions below
    // without having labelled anything v2 at all.
    switch (try second.server.step(test_now_s, random)) {
        ._continue => {},
        else => return error.HandshakeStalled,
    }
    switch (try second.server.step(test_now_s, random)) {
        .install_keys => |ik| if (ik.level == .early_data) {
            keys.server_open = ik.open;
        } else return error.HandshakeStalled,
        else => return error.HandshakeStalled,
    }
    // The ticket was accepted: this connection's first flight is version 1 and
    // the ticket was issued for a version-1 connection.
    try std.testing.expect(second.server.using_psk);

    try std.testing.expectEqual(protocol.QUIC_V2, second.server.config.quic_version);
    try std.testing.expectEqualSlices(u8, &keys.client_seal.key, &keys.server_open.key);
    try std.testing.expectEqualSlices(u8, &keys.client_seal.hp_key, &keys.server_open.hp_key);
    try std.testing.expectEqualSlices(u8, &keys.client_seal.nonce, &keys.server_open.nonce);
}

test "a ticket issued under another version is refused, and no 0-RTT is accepted" {
    // RFC 9369 §5: "Servers MUST validate the originating version of any
    // session ticket or token and not accept one issued from a different
    // version. A rejected ticket results in falling back to a full TLS
    // handshake, without 0-RTT." The sealed ticket is the only place the
    // version it was issued under is recorded, so this is the server's check
    // to make and the only one a conforming peer cannot be trusted to have
    // made already.
    const gpa = std.testing.allocator;
    var entropy = Counted{};
    const random = entropy.random();
    var server = Identity.init(server_seed);
    server.link();

    const server_config = TlsConfig{
        .cert_chain_der = &server.chain,
        .private_key_bytes = &server.seed,
        .private_key_algorithm = .ed25519,
        .alpn = &[_][]const u8{"h3"},
        .resumption = .{ .server = TicketKey.generate(random) },
    };
    const client_config = TlsConfig{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &[_][]const u8{"h3"},
        .server_name = "relay.test",
        .expect_peer_node_id = server.node_id,
    };

    var first = try Ends.initWithParams(gpa, client_config, server_config, random, cvn_params, cvn_params);
    defer first.deinit(gpa);
    try std.testing.expect((try connect(&first, random)) == null);
    var ticket = first.client.received_ticket orelse return error.HandshakeStalled;

    // This client starts on version 2 — what a client holding a version-2
    // ticket and able to speak that version does — so it offers the ticket,
    // and this server supports both versions, so nothing filters it out. What
    // refuses it is the version sealed inside it, against the version of the
    // flight this server is processing. A conforming client never offers such
    // a ticket (see the test below), which is exactly why the server's own
    // check is the one that has to hold: only the server can read where the
    // ticket came from.
    //
    // The two halves of this pair therefore also disagree about the version
    // they label their keys with, so the handshake does not complete. What is
    // under test is the refusal, not the connection.
    var starting_v2 = client_config;
    starting_v2.quic_version = protocol.QUIC_V2;
    starting_v2.resumption = .{ .client = &ticket };
    var second = try Ends.initWithParams(gpa, starting_v2, server_config, random, cvn_params, cvn_params);
    defer second.deinit(gpa);

    _ = connect(&second, random) catch {};
    try std.testing.expect(!second.server.using_psk);
    try std.testing.expect(!second.server.zero_rtt_accepted);
    try std.testing.expect(!second.client.using_psk);
}

test "a client that starts on another version does not offer the ticket" {
    // The other half of RFC 9369 §5, on the client. This client starts on
    // version 1 while advertising that version 2 is available to it, so the
    // ticket is not unusable for want of a version it could reach — it belongs
    // to another connection's version. Offering it would put a 0-RTT flight on
    // the wire for a connection that cannot be one, and the server is entitled
    // to throw the whole thing away.
    const gpa = std.testing.allocator;
    var entropy = Counted{};
    const random = entropy.random();
    var server = Identity.init(server_seed);
    server.link();

    const server_config = TlsConfig{
        .cert_chain_der = &server.chain,
        .private_key_bytes = &server.seed,
        .private_key_algorithm = .ed25519,
        .alpn = &[_][]const u8{"h3"},
        .resumption = .{ .server = TicketKey.generate(random) },
    };
    const client_config = TlsConfig{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &[_][]const u8{"h3"},
        .server_name = "relay.test",
        .expect_peer_node_id = server.node_id,
    };

    var first = try Ends.initWithParams(gpa, client_config, server_config, random, cvn_params, cvn_params);
    defer first.deinit(gpa);
    try std.testing.expect((try connect(&first, random)) == null);
    var ticket = first.client.received_ticket orelse return error.HandshakeStalled;

    var resuming = client_config;
    resuming.resumption = .{ .client = &ticket };
    var second = try Ends.initWithParams(gpa, resuming, server_config, random, cvn_params, cvn_params);
    defer second.deinit(gpa);

    // Declining costs a resumption, not the connection: the handshake still
    // completes, and it still negotiates version 2.
    try std.testing.expect((try connect(&second, random)) == null);
    try std.testing.expect(!second.server.using_psk);
    try std.testing.expect(!second.client.using_psk);
    try std.testing.expectEqual(protocol.QUIC_V2, second.server.config.quic_version);
    try std.testing.expectEqual(protocol.QUIC_V2, second.client.config.quic_version);
}

test "a resuming client offers its ticket only while its own proposal holds that protocol" {
    // RFC 8446 §4.2.10: "The parameters for the 0-RTT data (version,
    // symmetric cipher suite, Application-Layer Protocol Negotiation (ALPN)
    // protocol, etc.) are those associated with the PSK in use.  For PSKs
    // established via a NewSessionTicket message, the associated values are
    // those which were negotiated in the connection which established the
    // PSK." The ticket says what that connection agreed, and this client
    // renames its own protocol between the two connections.
    const gpa = std.testing.allocator;
    var entropy: Counted = .{};
    const random = entropy.random();
    var server = Identity.init(server_seed);
    server.link();

    const server_config = TlsConfig{
        .cert_chain_der = &server.chain,
        .private_key_bytes = &server.seed,
        .private_key_algorithm = .ed25519,
        .alpn = &[_][]const u8{"h3"},
        .resumption = .{ .server = TicketKey.generate(random) },
    };
    const client_config = TlsConfig{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &[_][]const u8{"h3"},
        .server_name = "relay.test",
    };

    var first = try Ends.init(gpa, client_config, server_config, random);
    defer first.deinit(gpa);
    try std.testing.expect((try connect(&first, random)) == null);
    const ticket = first.client.received_ticket orelse return error.HandshakeStalled;
    try std.testing.expectEqualStrings("h3", ticket.getAlpn());

    // The operator's config names a different protocol now. This client
    // holds h3's ticket and would offer h2, and 0-RTT under it would be h3's
    // early data on an h2 connection — so there is nothing to offer, the way
    // there is nothing to offer a ticket from another QUIC version.
    const alpn_h2 = [_][]const u8{"h2"};
    var moved = server_config;
    moved.alpn = &alpn_h2;
    var moved_client = client_config;
    moved_client.alpn = &alpn_h2;
    moved_client.resumption = .{ .client = &ticket };
    var second = try Ends.init(gpa, moved_client, moved, random);
    defer second.deinit(gpa);

    // Declining costs a resumption, not a connection: this handshake is a
    // full one and it still negotiates the protocol the config now names.
    try std.testing.expect((try connect(&second, random)) == null);
    try std.testing.expect(!second.client.using_psk);
    try std.testing.expect(!second.server.using_psk);
    try std.testing.expect(!second.server.zero_rtt_accepted);
    try std.testing.expectEqualStrings("h2", second.client.negotiatedAlpn());
    try std.testing.expectEqualStrings("h2", second.server.negotiatedAlpn());
}

test "a ticket whose protocol is not the one this connection selects is resumed but sends no 0-RTT" {
    // RFC 8446 §4.2.10: "In order to accept early data, the server MUST ...
    // verify that the following values are the same as those associated with
    // the selected PSK: The TLS version number, The selected cipher suite,
    // The selected ALPN protocol, if any ... If any of these checks fail, the
    // server MUST NOT respond with the extension". Only the server can read
    // the protocol sealed inside the ticket, so this is its check to make
    // however careful a client was: a peer that offers the identity anyway
    // gets a resumption and no 0-RTT.
    const gpa = std.testing.allocator;
    var entropy: Counted = .{};
    const random = entropy.random();
    var server = Identity.init(server_seed);
    server.link();

    const server_config = TlsConfig{
        .cert_chain_der = &server.chain,
        .private_key_bytes = &server.seed,
        .private_key_algorithm = .ed25519,
        .alpn = &[_][]const u8{"h3"},
        .resumption = .{ .server = TicketKey.generate(random) },
    };
    const client_config = TlsConfig{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &[_][]const u8{"h3"},
        .server_name = "relay.test",
    };

    var first = try Ends.init(gpa, client_config, server_config, random);
    defer first.deinit(gpa);
    try std.testing.expect((try connect(&first, random)) == null);
    const ticket = first.client.received_ticket orelse return error.HandshakeStalled;

    // The same server, now serving a second protocol as well.
    const alpn_h2 = [_][]const u8{"h2"};
    const alpn_both = [_][]const u8{ "h3", "h2" };
    var both = server_config;
    both.alpn = &alpn_both;
    var second = try Ends.init(gpa, client_config, both, random);
    defer second.deinit(gpa);

    // The ClientHello is built here rather than driven out of `second.client`,
    // which offers no ticket: its own proposal no longer holds h3, and its
    // key schedule starts from no PSK at all. This one offers the identity
    // and asks for early data under h2, which is what a peer that did not
    // check its own proposal looks like.
    var buf: [4096]u8 = undefined;
    var client_random: [32]u8 = undefined;
    random.bytes(&client_random);
    var key_schedule = KeySchedule.initWithPsk(ticket.psk);
    const hello = try buildClientHello(
        &buf,
        &client_random,
        &second.client.x25519_public,
        &second.client.p256_public,
        &alpn_h2,
        null,
        second.client.tp_encoded[0..second.client.tp_encoded_len],
        &ticket,
        &key_schedule,
        ticket.cipher_suite,
        test_now_s,
    );
    second.server.provideData(hello);
    _ = try second.server.step(test_now_s, random);

    // The selection is h2 and the ticket says h3, so the server resumes on
    // what the client offered and refuses the early data it offered with it.
    try std.testing.expectEqualStrings("h2", second.server.negotiatedAlpn());
    try std.testing.expect(second.server.using_psk);
    try std.testing.expect(!second.server.zero_rtt_accepted);
}

test "a ticket records the protocol the connection negotiated, not a prefix of it" {
    // A prefix of a protocol name is a different protocol name, and the
    // checks RFC 8446 §4.2.10 asks for are comparisons of names. A protocol
    // longer than the sixteen bytes an older build recorded therefore has to
    // reach the ticket whole, and the connection that follows has to be able
    // to resume on all of it.
    const gpa = std.testing.allocator;
    var entropy: Counted = .{};
    const random = entropy.random();
    var server = Identity.init(server_seed);
    server.link();

    const wide_protocol: []const u8 = "p" ** 20;
    const alpn = [_][]const u8{wide_protocol};
    const server_config = TlsConfig{
        .cert_chain_der = &server.chain,
        .private_key_bytes = &server.seed,
        .private_key_algorithm = .ed25519,
        .alpn = &alpn,
        .resumption = .{ .server = TicketKey.generate(random) },
    };
    const client_config = TlsConfig{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &alpn,
        .server_name = "relay.test",
    };

    var first = try Ends.init(gpa, client_config, server_config, random);
    defer first.deinit(gpa);
    try std.testing.expect((try connect(&first, random)) == null);
    const ticket = first.client.received_ticket orelse return error.HandshakeStalled;
    try std.testing.expectEqualStrings(wide_protocol, ticket.getAlpn());

    var resuming = client_config;
    resuming.resumption = .{ .client = &ticket };
    var second = try Ends.init(gpa, resuming, server_config, random);
    defer second.deinit(gpa);
    try std.testing.expect((try connect(&second, random)) == null);
    try std.testing.expect(second.server.using_psk);
    try std.testing.expectEqualStrings(wide_protocol, second.client.negotiatedAlpn());
}

test "a local SNI name too long for the ClientHello is refused, not written past" {
    // RFC 6066 puts no ceiling on the name itself and `TlsConfig.server_name`
    // states no bound, and the ClientHello is built into one fixed buffer.
    // What does not fit is a refusal at the first `step` — the only error
    // this handshake reports for a local configuration — and not a write
    // past the end of that buffer.
    const name = [_]u8{'n'} ** (4096 + 64);
    var entropy: Counted = .{};
    const random = entropy.random();
    var client = try Tls13Handshake.initClient(.{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &[_][]const u8{"h3"},
        .server_name = &name,
    }, .{}, random);
    try std.testing.expectError(error.InternalError, client.step(test_now_s, random));
}

test "an ALPN proposal too long for the ClientHello is refused, not written past" {
    const gpa = std.testing.allocator;
    var entropy: Counted = .{};
    const random = entropy.random();

    // RFC 7301: ProtocolName is `opaque <1..2^8-1>`, so a protocol of 300
    // bytes has no encoding at all and there is nothing to send it in.
    const too_long = [_]u8{'x'} ** 300;
    var wide = try gpa.create(Tls13Handshake);
    defer gpa.destroy(wide);
    try Tls13Handshake.initClientInto(wide, .{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &[_][]const u8{&too_long},
    }, .{}, random);
    try std.testing.expectError(error.InternalError, wide.step(test_now_s, random));

    // And a list that fits the wire's own length fields but not this
    // message: twenty protocols of 255 bytes each, which the extension
    // would have to carry whole.
    var storage: [20][255]u8 = undefined;
    var list: [20][]const u8 = undefined;
    for (&storage, 0..) |*proto, i| {
        @memset(proto, 'x');
        list[i] = proto;
    }
    var bulky = try gpa.create(Tls13Handshake);
    defer gpa.destroy(bulky);
    try Tls13Handshake.initClientInto(bulky, .{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &list,
    }, .{}, random);
    try std.testing.expectError(error.InternalError, bulky.step(test_now_s, random));
}

test "a PKCS#8 EC key with a length this walk cannot honour is a decode error" {
    // A minimal RFC 5915 ECPrivateKey: SEQUENCE { version 1, privateKey }.
    const ec_key: [39]u8 = .{ 0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20 } ++ ([_]u8{0x42} ** 32);
    // And the RFC 5208 wrapper around it, with the AlgorithmIdentifier the
    // OID for ecPublicKey and nothing else.
    const wrapped: [57]u8 = .{
        0x30, 0x37, // SEQUENCE, 55
        0x02, 0x01, 0x00, // version 0
        0x30, 0x09, // AlgorithmIdentifier, 9
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // 1.2.840.10045.2.1
        0x04, 0x27, // privateKey OCTET STRING, 39
    } ++ ec_key;

    // Every truncation of a good key: a declared length that runs past the
    // bytes that follow it used to be sliced in rather than refused.
    for (0..wrapped.len) |n| {
        try std.testing.expectError(error.DecodeError, extractPkcs8EcPrivateKey(wrapped[0..n]));
    }
    try std.testing.expectEqualSlices(u8, ec_key[7..], try extractPkcs8EcPrivateKey(&wrapped));

    // A long-form length whose length bytes are not there, in each of the two
    // places a length is read. Both indexed those bytes without asking.
    const missing_alg_len = [_]u8{ 0x30, 0x0b, 0x02, 0x01, 0x00, 0x30, 0x84 };
    try std.testing.expectError(error.DecodeError, extractPkcs8EcPrivateKey(&missing_alg_len));
    const missing_octet_len = [_]u8{ 0x30, 0x09, 0x02, 0x01, 0x00, 0x30, 0x00, 0x04, 0x84 };
    try std.testing.expectError(error.DecodeError, extractPkcs8EcPrivateKey(&missing_octet_len));

    // An indefinite length names no end, and reading it as zero walked past
    // the field it stood for: this key parsed as one whose
    // AlgorithmIdentifier was empty, and it must not parse at all.
    const indefinite: [48]u8 = .{
        0x30, 0x2e, // SEQUENCE, 46
        0x02, 0x01, 0x00, // version 0
        0x30, 0x80, // AlgorithmIdentifier, indefinite
        0x04, 0x27, // privateKey OCTET STRING, 39
    } ++ ec_key;
    try std.testing.expectError(error.DecodeError, extractPkcs8EcPrivateKey(&indefinite));
}

test "an EC private key cut short inside its own lengths is a decode error" {
    // The RFC 5915 structure the PKCS#8 walk carries inside its privateKey
    // OCTET STRING, handed to the SEC1 walk directly — which is the first
    // shape `extractPrivateKey` tries on a file the caller opened.
    const ec_key: [39]u8 = .{ 0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20 } ++ ([_]u8{0x42} ** 32);
    try std.testing.expectEqualSlices(u8, ec_key[7..], try extractEcPrivateKey(&ec_key));

    // Every truncation of that key. Each of its two lengths is read one byte
    // after the tag it belongs to, so a file cut short at a tag was indexed
    // past its end — a trap rather than a refusal.
    for (0..ec_key.len) |n| {
        try std.testing.expectError(error.DecodeError, extractEcPrivateKey(ec_key[0..n]));
    }

    // A tag with nothing behind it: the whole file, three bytes long.
    const tag_only: [3]u8 = .{ 0x30, 0x01, 0x02 };
    try std.testing.expectError(error.DecodeError, extractEcPrivateKey(&tag_only));

    // And through the published extractor, which tries every encoding in turn
    // and ends on the RSA walk: this is not a key of any of them.
    try std.testing.expectError(error.UnsupportedKey, extractPrivateKey(&tag_only));
}

test "a DER length of all ones is refused, not added to" {
    // A SEQUENCE whose length is written the eight-byte way as 2^64-1. The
    // bound was `pos + len`, so adding the offset that follows the length to
    // that wraps: a trap in a checked build, a slice of whatever the sum came
    // to in a fast one. Nothing behind the length is reached, and the point
    // is that reaching it is the bug — so the body is filler.
    const unbounded: [47]u8 = .{ 0x30, 0x88 } ++ ([_]u8{0xff} ** 8) ++ ([_]u8{0x42} ** 37);

    // Both of these walk the length through `readDerValue`, so each one traps
    // on the same addition.
    try std.testing.expectError(error.DecodeError, extractEd25519PrivateKey(&unbounded));
    try std.testing.expectError(error.DecodeError, extractPkcs8EcPrivateKey(&unbounded));

    // And the same length one level down, where every envelope around it is
    // honest and only the ECPrivateKey's own length is out of range.
    const wrapped: [65]u8 = .{
        0x30, 0x3f, // SEQUENCE, 63
        0x02, 0x01, 0x00, // version 0
        0x30, 0x09, // AlgorithmIdentifier, 9
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // 1.2.840.10045.2.1
        0x04, 0x2f, // privateKey OCTET STRING, 47
    } ++ unbounded;
    try std.testing.expectError(error.DecodeError, extractPkcs8EcPrivateKey(&wrapped));
    try std.testing.expectError(error.DecodeError, extractEcPrivateKey(&unbounded));
}

test "a maximal transport-parameter set is published whole, or not at all" {
    // Every field at its own largest legal value, which is what
    // `transport_params.encode_len_max` exists to hold: three 20-byte
    // connection ids, a preferred address with a 20-byte id of its own, every
    // varint at the eight bytes it needs, and a full version_information list.
    const cid: [20]u8 = @splat(0xAB);
    var preferred = transport_params.PreferredAddress{
        .ipv4_port = 443,
        .ipv6_port = 443,
        .cid_len = 20,
        .stateless_reset_token = .{0x5a} ** 16,
    };
    @memcpy(preferred.cid_buf[0..20], &cid);
    const tp = transport_params.TransportParams{
        .original_destination_connection_id = &cid,
        .max_idle_timeout = std.math.maxInt(u62),
        .stateless_reset_token = .{0x3c} ** 16,
        .max_udp_payload_size = std.math.maxInt(u62),
        .initial_max_data = std.math.maxInt(u62),
        .initial_max_stream_data_bidi_local = std.math.maxInt(u62),
        .initial_max_stream_data_bidi_remote = std.math.maxInt(u62),
        .initial_max_stream_data_uni = std.math.maxInt(u62),
        .initial_max_streams_bidi = std.math.maxInt(u62),
        .initial_max_streams_uni = std.math.maxInt(u62),
        .ack_delay_exponent = 20,
        .max_ack_delay = std.math.maxInt(u62),
        .disable_active_migration = true,
        .preferred_address = preferred,
        .active_connection_id_limit = std.math.maxInt(u62),
        .initial_source_connection_id = &cid,
        .retry_source_connection_id = &cid,
        .max_datagram_frame_size = std.math.maxInt(u62),
        .min_ack_delay = std.math.maxInt(u62),
        .version_info_chosen = protocol.QUIC_V1,
        .version_info_available = .{protocol.QUIC_V2} ** 8,
        .version_info_available_count = 8,
    };
    var entropy: Counted = .{};
    const random = entropy.random();

    var buf: [transport_params.encode_len_max]u8 = undefined;
    const written = try encodeTransportParams(&buf, tp, random);
    // The greased parameter carries 1 to 4 value bytes, so a maximal set
    // costs 321 to 324. Anything above the bound would mean the derivation
    // beside it is wrong, and anything below 321 would mean this set is not
    // the one that bound was derived from.
    try std.testing.expect(written <= transport_params.encode_len_max);
    try std.testing.expect(written > transport_params.encode_len_max - 4);

    // One byte short of what the set needs is refused, not trimmed: a
    // parameter list cut short is a different set of limits to the peer, not
    // a smaller one, and publishing it under its truncated length is how a
    // peer ends up enforcing limits nobody wrote. The generator starts over
    // because the greased parameter's value length is the one byte that
    // differs between two encodings of the same set, and a second, shorter
    // draw would quietly fit.
    var again: Counted = .{};
    var tight: [transport_params.encode_len_max]u8 = undefined;
    try std.testing.expectError(
        error.InternalError,
        encodeTransportParams(tight[0 .. written - 1], tp, again.random()),
    );

    // And a handshake built from it carries all of it, not a prefix.
    var server: Tls13Handshake = undefined;
    try Tls13Handshake.initServerInto(&server, .{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &.{},
    }, tp, random);
    try std.testing.expect(server.tp_encoded_len <= transport_params.encode_len_max);
    try std.testing.expect(server.tp_encoded_len > transport_params.encode_len_max - 4);
}

test "a transport-parameter set that does not fit publishes none of itself" {
    // `error.InternalError` is the one way either constructor fails, and it is
    // the one a connection allocates a handshake for before it calls them. A
    // source connection id longer than an encoding can hold is how it is
    // reached: `encode_len_max` covers every field at its largest legal value,
    // so nothing within the bounds can reach it. The answer publishes
    // nothing, because a parameter list cut short is a different set of limits
    // to the peer rather than a smaller one.
    const oversized: [transport_params.encode_len_max]u8 = @splat(0xAB);
    const tp = transport_params.TransportParams{
        .initial_source_connection_id = &oversized,
    };
    const config: TlsConfig = .{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &.{},
    };

    var entropy = Counted{};
    for ([_]bool{ false, true }) |is_server| {
        var hs: Tls13Handshake = undefined;
        if (is_server) {
            try std.testing.expectError(
                error.InternalError,
                Tls13Handshake.initServerInto(&hs, config, tp, entropy.random()),
            );
        } else {
            try std.testing.expectError(
                error.InternalError,
                Tls13Handshake.initClientInto(&hs, config, tp, entropy.random()),
            );
        }
        try std.testing.expectEqual(@as(usize, 0), hs.tp_encoded_len);
    }
}
