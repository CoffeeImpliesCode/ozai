//! An independent oracle for the DER the TLS stack hands to and takes back:
//! the Ed25519 `SubjectPublicKeyInfo`, its encoder, and the private-key
//! extractors that walk the same TLVs.
//!
//! **What is under test, and what is not.** `ed25519Spki`, `liftEd25519Spki`,
//! `extractEcPrivateKey`, `extractPkcs8EcPrivateKey`, `extractEd25519PrivateKey`
//! and `extractPrivateKey` are all `pub` and all reached here. The two TLV
//! readers they share (`readTlv`, `readDerValue`) are private, so they are
//! reached only through the grammar below and are never named — which is the
//! point: an oracle that called them would agree with the decoder by
//! construction.
//!
//! **Why 44 bytes is the boundary that matters.** RFC 8410 §3 fixes the Ed25519
//! `AlgorithmIdentifier` and RFC 5280 §4.1.2.7 fixes the SEQUENCE around it, so
//! the DER is exactly 44 bytes and every one of them is accounted for: 2 for
//! the outer SEQUENCE header, 7 for the AlgorithmIdentifier, 35 for the BIT
//! STRING. The decoder's length arithmetic has almost no room, so the set of
//! accepted spellings is tiny and every refusal has a name.
//!
//! **The two rules the reference deliberately does not tighten.** `readTlv`'s
//! own contract is a single-byte tag and a *definite* length of up to four
//! bytes, and a length need not be in its shortest form — X.690's DER would
//! refuse both a five-byte length and `81 04` in place of `04`. The reference
//! allows both, because those leniencies are the contract under test and an
//! oracle that tightened them would report a finding against bytes this stack
//! documents as legal. Everything else — the grammar, the classification, the
//! encoder's bytes — is derived here and not read back out of the decoder.
//!
//! No allocator appears in this file's interface, and that is a fact rather
//! than an omission: every decoder below returns a slice borrowed from the
//! bytes it was handed, and the oracle's own storage is a fixed-size stack
//! value. A parameter nothing reaches for would be a fiction a caller has to
//! thread.
//!
//! Nothing here touches a clock, an `std.Io`, a global or a source file. The
//! references are written from RFC 5280, RFC 5915, RFC 5208 and RFC 8410, not
//! from the decoder's control flow, and where the two must agree — the five
//! length rules above — the agreement is stated rather than discovered.

const std = @import("std");
const tls13 = @import("quic").tls13;

/// What `check` reports. The four test tags are distinct on purpose: a decoder
/// that returned a *different* error is a different finding from one that
/// returned an error at all where the grammar says the bytes are legal, and a
/// caller reading a fuzz failure needs to tell those apart without reading
/// this file.
pub const Error = error{
    /// The decoder answered, but not in a shape the grammar has a name for.
    TestUnexpectedResult,
    /// A compared value differed: a lifted key, an extracted seed, or the
    /// algorithm tag that has to agree with the shape that matched.
    TestExpectedEqual,
    /// The decoder refused with the wrong error, so the two refusals are not
    /// the same fact about the bytes.
    TestExpectedError,
    /// The decoder refused where the grammar says the bytes are legal.
    TestUnexpectedError,
    /// The driver ran out of memory holding the bytes to decode.
    OutOfMemory,
};

/// RFC 8410 §3's algorithm OID `1.3.101.112` and the two fixed sizes, spelled
/// as the parts they cover. `tls13.ed25519_spki_prefix` is a second copy of
/// these numbers; this one exists so the comparison has two sides written
/// apart, and the comptime check below is what makes the two copies agree.
const alg_id_len: usize = 2 + (2 + 3);
const bits_len: usize = 2 + 1 + 32;
const spki_len: usize = 2 + alg_id_len + bits_len;
/// X.690 §8.19.4 packs the first two arcs into one byte and writes later arcs
/// base-128; 101 and 112 are both under 128, so all three are one byte each.
const ed25519_oid = [3]u8{ 1 * 40 + 3, 101, 112 };

comptime {
    if (spki_len != tls13.ed25519_spki_len) @compileError("the RFC 8410 SPKI is not the length the decoder says it is");
}

/// The one `SubjectPublicKeyInfo` an Ed25519 public key is written as, built
/// from the parts above rather than from a copied byte string.
fn refSpki(key: *const [32]u8) [spki_len]u8 {
    var out: [spki_len]u8 = undefined;
    out[0] = 0x30; // SEQUENCE
    out[1] = @intCast(spki_len - 2);
    out[2] = 0x30; // AlgorithmIdentifier
    out[3] = @intCast(alg_id_len - 2);
    out[4] = 0x06; // OBJECT IDENTIFIER
    out[5] = @intCast(ed25519_oid.len);
    @memcpy(out[6..9], &ed25519_oid);
    out[9] = 0x03; // BIT STRING
    out[10] = @intCast(bits_len - 2);
    out[11] = 0; // no unused bits: a key is a whole number of bytes
    @memcpy(out[12..], key);
    return out;
}

/// One ASN.1 element: its tag and the span of its contents within `limit`.
const El = struct { tag: u8, start: usize, end: usize };

/// X.690 §8.1's definite length, read the way `readTlv` states it does: a
/// single-byte tag and a definite length of at most `max_len` bytes. The two
/// width rules the module doc names are the two refusals below — no indefinite
/// form, and nothing wider than `max_len`.
fn element(comptime max_len: usize, b: []const u8, pos: usize, limit: usize) ?El {
    if (pos >= limit or limit - pos < 2) return null;
    const tag = b[pos];
    if (tag & 0x1f == 0x1f) return null; // a high-tag-number form this stack does not read
    var i = pos + 2;
    var len: usize = b[pos + 1];
    if (len >= 0x80) {
        const n: usize = len & 0x7f;
        if (n == 0 or n > max_len or n > limit - i) return null;
        len = 0;
        for (b[i..][0..n]) |x| len = (len << 8) | x;
        i += n;
    }
    if (len > limit - i) return null;
    return .{ .tag = tag, .start = i, .end = i + len };
}

/// The same element, read at the width `readDerValue` allows: as many length
/// bytes as a `usize` can hold, which is wider than the SPKI reader's four.
///
/// `pos` is left where the element *ends* and not where its contents begin,
/// which is the one rule X.690 §8.1.2 states: the length octets count contents
/// octets, so the element behind this one starts at `end`, and only an
/// element with empty contents has `end == start`. A walk that stopped at
/// `start` would read the second field of every SEQUENCE as the value of its
/// first, which is how a PKCS#8 key stops being a PKCS#8 key.
fn derValue(b: []const u8, pos: *usize, tag: u8) ?[]const u8 {
    const el = element(@sizeOf(usize), b, pos.*, b.len) orelse return null;
    if (el.tag != tag) return null;
    pos.* = el.end;
    return b[el.start..el.end];
}

/// What RFC 5280 §4.1.2.7 says about `SubjectPublicKeyInfo`,
///     SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier,
///                                        subjectPublicKey BIT STRING }
///     AlgorithmIdentifier   ::= SEQUENCE { algorithm OBJECT IDENTIFIER }
/// makes of a peer's bytes. `other_algorithm` is a well-formed
/// `AlgorithmIdentifier` naming something this stack does not use, which RFC
/// 8446 §4.2.1 makes a different `bad_certificate` reason from malformed DER
/// and so has to stay tellable from it.
const Lift = union(enum) {
    malformed,
    other_algorithm,
    key: [32]u8,
};

fn refLift(d: []const u8) Lift {
    if (d.len != spki_len) return .malformed;
    const spki = element(4, d, 0, spki_len) orelse return .malformed;
    if (spki.tag != 0x30 or spki.end != spki_len) return .malformed;
    const alg = element(4, d, spki.start, spki.end) orelse return .malformed;
    const bits = element(4, d, alg.end, spki.end) orelse return .malformed;
    if (alg.tag != 0x30 or bits.end != spki.end) return .malformed;
    const oid = element(4, d, alg.start, alg.end) orelse return .malformed;
    // RFC 8410 §3: the Ed25519 AlgorithmIdentifier carries absent parameters,
    // so the OID is the whole of it and nothing may sit behind it.
    if (oid.tag != 0x06 or oid.end != alg.end) return .malformed;
    if (!std.mem.eql(u8, d[oid.start..oid.end], &ed25519_oid)) return .other_algorithm;
    if (bits.tag != 0x03 or bits.end - bits.start != 33) return .malformed;
    if (d[bits.start] != 0) return .malformed;
    var key: [32]u8 = undefined;
    @memcpy(&key, d[bits.start + 1 ..][0..32]);
    return .{ .key = key };
}

/// RFC 5915 §3 `ECPrivateKey ::= SEQUENCE { version INTEGER, privateKey OCTET STRING, ... }`,
/// with the 32 bytes that make it a P-256 scalar. Fields after the scalar are
/// `[0]` and `[1]` and are not read, which is the grammar's own allowance.
fn refEcScalar(d: []const u8) ?[]const u8 {
    var p: usize = 0;
    const body = derValue(d, &p, 0x30) orelse return null;
    var q: usize = 0;
    _ = derValue(body, &q, 0x02) orelse return null;
    const scalar = derValue(body, &q, 0x04) orelse return null;
    if (scalar.len != 32) return null;
    return scalar;
}

/// RFC 5208 §6 `OneAsymmetricKey ::= SEQUENCE { version, privateKeyAlgorithm,
/// privateKey }` with an EC `ECPrivateKey` inside the last OCTET STRING.
fn refPkcs8EcScalar(d: []const u8) ?[]const u8 {
    var p: usize = 0;
    const outer = derValue(d, &p, 0x30) orelse return null;
    var q: usize = 0;
    _ = derValue(outer, &q, 0x02) orelse return null;
    _ = derValue(outer, &q, 0x30) orelse return null; // AlgorithmIdentifier, unchecked by this shape
    return refEcScalar(derValue(outer, &q, 0x04) orelse return null);
}

/// RFC 8410 §7: the same `OneAsymmetricKey` with the Ed25519 OID, whose
/// `privateKey` is either the 32-byte seed or RFC 8410 §7's `CurvePrivateKey`
/// wrapper around it.
fn refEd25519Seed(d: []const u8) ?[]const u8 {
    var p: usize = 0;
    const outer = derValue(d, &p, 0x30) orelse return null;
    var q: usize = 0;
    _ = derValue(outer, &q, 0x02) orelse return null;
    const alg = derValue(outer, &q, 0x30) orelse return null;
    var r: usize = 0;
    const oid = derValue(alg, &r, 0x06) orelse return null;
    if (!std.mem.eql(u8, oid, &ed25519_oid)) return null;
    if (r != alg.len) return null; // RFC 8410 §3: absent parameters, nothing else
    const key = derValue(outer, &q, 0x04) orelse return null;
    if (key.len == 32) return key;
    var s: usize = 0;
    const nested = derValue(key, &s, 0x04) orelse return null;
    if (s != key.len or nested.len != 32) return null;
    return nested;
}

/// The one call a fuzz driver makes: `input` is the bytes a peer would hand the
/// decoder, verbatim, with nothing trimmed and nothing padded.
pub fn check(input: []const u8) Error!void {
    try checkSpki(input);
    try checkSeed(input);
}

fn checkSpki(d: []const u8) Error!void {
    // Oracle: the classification. A refusal is legal only where the grammar
    // condemns the bytes, and for the reason named — malformed DER and another
    // algorithm are both `bad_certificate` on the wire and are not the same
    // fact about the bytes. The decoder answers with a key or with one of the
    // two refusals, so the key comes off the payload and the reason off the
    // error set; an error union is not itself something to switch on. `want`
    // is what `refLift` reads out of RFC 5280 §4.1.2.7 for the same bytes —
    // an independent walk with no decoder in it — so the two tags have to
    // agree, and only a `.key` carries on to the fidelity checks.
    const want = refLift(d);
    const verdict = if (tls13.liftEd25519Spki(d)) |k|
        Lift{ .key = k }
    else |err| switch (err) {
        error.MalformedSubjectPublicKeyInfo => Lift.malformed,
        error.UnsupportedSubjectPublicKeyInfo => Lift.other_algorithm,
    };
    if (std.meta.activeTag(verdict) != std.meta.activeTag(want)) return error.TestExpectedError;
    switch (want) {
        .malformed => return,
        .other_algorithm => return,
        .key => |key| {
            // Oracle: fidelity. RFC 5280 §4.1.2.7 puts the key in the
            // SEQUENCE's BIT STRING and `refLift` answers `.key` only for the
            // one spelling it could place, so those 32 bytes are the tail of
            // the message: a decode that reordered or invented them cannot
            // match the peer's own bytes read back at the offset the grammar
            // walked to. `refLift` does not hand that offset back, so it is
            // written as the length it proved — 44 octets, of which the key is
            // the last 32.
            if (!std.mem.eql(u8, &key, d[spki_len - 32 ..])) return error.TestExpectedEqual;
            // Oracle: the encoder, against the RFC bytes built above and not
            // against another copy of them. Two sides written apart.
            if (!std.mem.eql(u8, &tls13.ed25519Spki(&key), &refSpki(&key))) return error.TestExpectedEqual;
            // Oracle: fixed point. What comes out goes back in unchanged, so
            // no accepted spelling can be re-read as a different peer.
            const again = tls13.liftEd25519Spki(&tls13.ed25519Spki(&key)) catch
                return error.TestUnexpectedError;
            if (!std.mem.eql(u8, &again, &key)) return error.TestExpectedEqual;
        },
    }
}

fn checkSeed(d: []const u8) Error!void {
    try sameBytes(tls13.extractEd25519PrivateKey(d), refEd25519Seed(d));
    try sameBytes(tls13.extractEcPrivateKey(d), refEcScalar(d));
    try sameBytes(tls13.extractPkcs8EcPrivateKey(d), refPkcs8EcScalar(d));
    // `extractPrivateKey` tries the three shapes above in that order and an
    // RSA key last. With one of the three recognised, the algorithm tag it
    // reports is therefore decided by the grammar and cannot be a free choice.
    const ec = refEcScalar(d);
    const pkcs8 = refPkcs8EcScalar(d);
    const ed = refEd25519Seed(d);
    if (ec == null and pkcs8 == null and ed == null) return;
    const any = tls13.extractPrivateKey(d) catch return error.TestUnexpectedError;
    const want: tls13.PrivateKeyAlgorithm = if (ec != null or pkcs8 != null)
        .ecdsa_p256_sha256
    else
        .ed25519;
    if (any.algorithm != want) return error.TestExpectedEqual;
    const bytes = ec orelse pkcs8 orelse ed.?;
    if (!std.mem.eql(u8, any.bytes, bytes)) return error.TestExpectedEqual;
    // Oracle: borrowed. Each of the three decoders hands back a window into
    // the peer's own bytes rather than a copy of them, so the slice a caller
    // keeps has to point inside this input — and inside it whole, or a window
    // running past the end would pass.
    if (any.bytes.len > d.len) return error.TestExpectedEqual;
    const base = @intFromPtr(d.ptr);
    const at = @intFromPtr(any.bytes.ptr);
    if (at < base or at - base > d.len - any.bytes.len) return error.TestExpectedEqual;
}

/// One decoder against one reference: the same bytes in, the same bytes out or
/// the same refusal. `want` is null where the grammar says the DER is not that
/// shape at all, which the decoder's own error set collapses into one
/// `DecodeError` — so there is nothing left to name and only the fact is
/// checked.
fn sameBytes(got: anyerror![]const u8, want: ?[]const u8) Error!void {
    if (want) |bytes| {
        const lifted = got catch return error.TestUnexpectedError;
        if (!std.mem.eql(u8, lifted, bytes)) return error.TestExpectedEqual;
    } else if (got) |_| {
        return error.TestExpectedEqual;
    } else |_| {}
}
