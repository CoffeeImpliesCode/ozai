//! Node identity: the ed25519 key pair behind every ozai node address.
//!
//! `NodeId` is the public half and is the only identity ozai ever puts on the
//! wire in the clear. `SecretKey` is the signing half. `Signature` is a
//! detached ed25519 signature over bytes, with no algorithm negotiation.
//!
//! Divergence from iroh, on purpose: iroh calls the public half `PublicKey`
//! with a type alias `EndpointId`. ozai has one name, `NodeId`, because the
//! value is never used as a raw key in the API — every use is "address a node".

const std = @import("std");
const base32 = @import("base32.zig");

pub const Ed25519 = std.crypto.sign.Ed25519;

/// Errors from constructing a `NodeId` or a `SecretKey`.
pub const KeyError = error{
    /// The 32 bytes are not a canonical ed25519 point encoding.
    NotOnCurve,
    /// The seed derives the identity point and cannot sign.
    DegenerateSeed,
    /// The signature did not verify against this node id and message.
    BadSignature,
};

/// A node's public identity: 32 bytes of canonical ed25519 point.
///
/// Ordering is lexicographic over the 32 bytes, not by curve order. Every
/// sorted collection in ozai relies on it, so it is part of the type contract,
/// not an implementation detail.
///
/// An owned fixed-size value: nothing is allocated, nothing is borrowed, and
/// copying one copies the identity rather than a handle to it. A `NodeId` one
/// of the constructors below returned is a canonical point; that is a
/// precondition of the value and not an invariant the type enforces, because
/// the field is public and a struct literal validates nothing. See `key`.
pub const NodeId = struct {
    /// The canonical point. Reach for `toBytes` rather than this: the field
    /// is the encoding's business, and only the accessors know it is
    /// canonical already.
    ///
    /// **What this field holds is a precondition, not an invariant.** Every
    /// constructor on this type — `fromBytes` and the parsers built on it —
    /// checks the bytes and refuses a non-canonical encoding, and a `NodeId`
    /// they returned is a point; `SecretKey.nodeId` takes the canonical
    /// bytes key generation already produced. `key` is a plain public field
    /// with none of that behind it, so a `NodeId` written as a struct literal
    /// may be any 32 bytes at all and nothing here notices. Build a value from
    /// untrusted bytes with `fromBytes`, never with a literal, and check a
    /// signature over one with `Signature.verifyStrict`.
    key: Ed25519.PublicKey,

    /// The size of every byte form: hex, z-base-32 and the DNS label all
    /// encode this many bytes.
    pub const byte_length = Ed25519.PublicKey.encoded_length;
    /// Characters in the hex form.
    pub const hex_length = byte_length * 2;
    /// Both base32 forms are 52 characters for 32 bytes. A DNS label caps at
    /// 63, which is why a node id is never written as hex on a wire that a DNS
    /// label has to carry: hex would need 64 and would not fit.
    pub const z32_length = base32.encodedLen(byte_length);
    /// The same 52 characters in the DNS alphabet, for the local TLS name.
    pub const dnssec_length = base32.encodedLen(byte_length);
    /// Characters kept by `shortHex`.
    pub const short_hex_length = 10;

    /// Validate and wrap 32 bytes.
    ///
    /// `error.NotOnCurve` covers a non-canonical encoding as well as bytes
    /// that are not a point at all; there is no separate tag to tell them
    /// apart, because a caller has nothing to do differently with either.
    pub fn fromBytes(bytes: [byte_length]u8) KeyError!NodeId {
        return .{ .key = Ed25519.PublicKey.fromBytes(bytes) catch return error.NotOnCurve };
    }

    /// The 32 canonical bytes, copied out by value. Allocates nothing.
    pub fn toBytes(self: NodeId) [byte_length]u8 {
        return self.key.toBytes();
    }

    /// Lowercase hex, the form used in config files, logs and CLI output.
    pub fn toHex(self: NodeId) [hex_length]u8 {
        return std.fmt.bytesToHex(&self.toBytes(), .lower);
    }

    /// `text` as a node id: exactly `hex_length` hex digits, either case, and
    /// a point on the curve.
    ///
    /// Every failure is `error.NotOnCurve`, a wrong length included. That is
    /// deliberate: a config line with the wrong number of digits is a
    /// malformed node id, and a separate length tag would only tell a caller
    /// which of the two ways it typed the id it got wrong.
    pub fn parseHex(text: []const u8) KeyError!NodeId {
        if (text.len != hex_length) return error.NotOnCurve;
        var bytes: [byte_length]u8 = undefined;
        _ = std.fmt.hexToBytes(&bytes, text) catch return error.NotOnCurve;
        return fromBytes(bytes);
    }

    /// First `short_hex_length` hex characters, for human-facing lines where the
    /// full id would drown the rest of the message.
    pub fn shortHex(self: NodeId) [short_hex_length]u8 {
        const full = self.toHex();
        return full[0..short_hex_length].*;
    }

    /// z-base-32 form, the pkarr DNS label encoding.
    pub fn toZ32(self: NodeId) [z32_length]u8 {
        return base32.encode(base32.z32, byte_length, &self.toBytes());
    }

    /// `text` as a node id: exactly `z32_length` z-base-32 symbols in that
    /// alphabet's own case, and a point on the curve.
    ///
    /// The base32 failures are the caller's to read — a wrong length, a
    /// symbol outside the alphabet, or a non-zero pad — and the point check is
    /// `error.NotOnCurve`. An upper-case label is `error.InvalidSymbol`, not a
    /// second spelling of one id.
    pub fn parseZ32(text: []const u8) (KeyError || base32.DecodeError)!NodeId {
        return fromBytes(try base32.decode(base32.z32, byte_length, text));
    }

    /// `{hex-extended-base32}.iroh.invalid`, the name ozai's TLS stack uses
    /// *locally*.
    ///
    /// It is never sent as SNI. iroh stopped transmitting it in 1.0.3 because it
    /// discloses the peer id; it survives only to select the expected peer and to
    /// bucket the 0-RTT session cache. `.invalid` is reserved by RFC 2606 to
    /// never resolve, so a stray resolver cannot turn it into a real lookup.
    ///
    /// This is the DNS alphabet, not z-base-32. Both are 52 characters, which is
    /// why the mistake is easy to make and invisible until a handshake fails.
    pub fn toLocalTlsName(self: NodeId) [dnssec_length + ".iroh.invalid".len]u8 {
        var name: [dnssec_length + ".iroh.invalid".len]u8 = undefined;
        @memcpy(name[0..dnssec_length], &base32.encode(
            base32.dnssec,
            byte_length,
            &self.toBytes(),
        ));
        @memcpy(name[dnssec_length..], ".iroh.invalid");
        // ZBC cannot combine these two memcpy ranges to prove name is fully initialized.
        // zbc-disable-next-line: use-undefined
        return name;
    }

    /// `text` as a node id, where `text` is exactly what `toLocalTlsName`
    /// writes: the DNS-alphabet label and the `.iroh.invalid` suffix.
    ///
    /// A wrong length or a different suffix is `error.NotOnCurve` — the name
    /// is not this local name — and the label itself carries the base32
    /// failures. A near miss is refused rather than repaired, so a name that
    /// decodes is a name this build wrote.
    pub fn parseLocalTlsName(text: []const u8) (KeyError || base32.DecodeError)!NodeId {
        const suffix = ".iroh.invalid";
        if (text.len != dnssec_length + suffix.len) return error.NotOnCurve;
        if (!std.mem.eql(u8, text[dnssec_length..], suffix)) return error.NotOnCurve;
        return fromBytes(try base32.decode(base32.dnssec, byte_length, text[0..dnssec_length]));
    }

    /// Lexicographic over bytes. Named so a reader does not have to check
    /// whether this is the curve order.
    pub fn order(self: NodeId, other: NodeId) std.math.Order {
        return std.mem.order(u8, &self.toBytes(), &other.toBytes());
    }

    /// The lowercase hex of the 32 bytes, which is what `parseHex` reads back
    /// and what a config file and a log line both carry.
    pub fn format(self: NodeId, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.writeAll(&self.toHex());
    }
};

/// The signing half of a node identity.
///
/// The std secret key includes the canonical public bytes produced by key
/// generation. Reading them needs neither a second validation nor another copy
/// stored alongside the secret.
///
/// `deinit` zeroes the key. There is no `clone`: copying a secret key is a
/// decision the caller must make at the call site, with the copy visible. A
/// copy is an independent copy of the same secret rather than a second handle
/// on one, so each has to be zeroed on its own and zeroing one leaves the
/// other's bytes intact.
///
/// The type owns no allocator and stores no capability: every operation is
/// pure over its arguments.
pub const SecretKey = struct {
    /// The secret key, public half included.
    key: Ed25519.SecretKey,

    /// Bytes in `toBytes`: the full std encoding, seed plus public half.
    pub const byte_length = Ed25519.SecretKey.encoded_length;
    /// The 32-byte half that is the actual entropy source.
    pub const seed_length = Ed25519.KeyPair.seed_length;

    /// A key drawn from `io`'s randomness.
    ///
    /// `io` is used for that draw and for nothing else: it must be live for
    /// this call, it is not retained, and the key holds no reference to it — so
    /// the `Io` may be released the moment this returns. No allocator is
    /// involved. The returned key owns its secret bytes by value and exposes
    /// no caller-managed seed.
    ///
    /// Call `deinit` once per retained key value before its storage is reused.
    ///
    pub fn generate(io: std.Io) SecretKey {
        return .{ .key = Ed25519.KeyPair.generate(io).secret_key };
    }

    /// Derive a key deterministically. Used by tests and by anyone restoring a
    /// key from a seed phrase; the seed must come from a real CSPRNG.
    ///
    /// `error.DegenerateSeed` is the one seed that yields no signing key. The
    /// seed is read, not kept: the returned key borrows nothing from it.
    pub fn fromSeed(seed: [seed_length]u8) KeyError!SecretKey {
        const pair = Ed25519.KeyPair.generateDeterministic(seed) catch
            return error.DegenerateSeed;
        return .{ .key = pair.secret_key };
    }

    /// The public half of this key, taken from the canonical bytes key
    /// generation checked; no validation happens again.
    pub fn nodeId(self: SecretKey) NodeId {
        return .{ .key = .{ .bytes = self.key.publicKeyBytes() } };
    }

    /// A detached signature over `message`, deterministic for a given key and
    /// message. `message` is borrowed for the call only.
    ///
    /// The same key signing the same bytes twice gives the same 64 bytes,
    /// which is what lets a signed ticket stay a stable identifier.
    ///
    /// Aborts if Ed25519 rejects the derived signing operation. A zero
    /// deterministic nonce can produce `IdentityElement`; no error is returned
    /// to the caller. Use a key produced by `fromSeed`, not altered key bytes.
    pub fn sign(self: SecretKey, message: []const u8) Signature {
        // `noise = null` is deterministic ed25519 (RFC 8032). A P2P node signs
        // the same ticket twice on purpose: the bytes are public, and a
        // deterministic signature makes the ticket itself a stable identifier.
        const pair: Ed25519.KeyPair = .{
            .public_key = self.nodeId().key,
            .secret_key = self.key,
        };
        // Both halves use the public bytes checked by key generation, excluding
        // KeyMismatch and NonCanonical. The fixed base point excludes WeakPublicKey.
        // IdentityElement remains possible if the deterministic nonce reduces to
        // zero (about 2^-252). Preserve the total API with a defined abort, not UB.
        const signature = Ed25519.KeyPair.sign(pair, message, null) catch
            @panic("ed25519 sign failed on a key pair derived from one seed");
        return .{ .bytes = signature.toBytes() };
    }

    /// The full std encoding — seed and public half — copied out by value.
    ///
    /// The result is secret material in a plain array, with none of the
    /// zeroing `deinit` does: the caller owns this copy and has to dispose of
    /// it however it can.
    pub fn toBytes(self: SecretKey) [byte_length]u8 {
        return self.key.toBytes();
    }

    /// Zero this key's material in place. Must be called once per key before
    /// the storage the key lived in is reused; a `SecretKey` left in freed heap
    /// is a `SecretKey` an attacker reads.
    ///
    /// Only the receiver is wiped. A copy made earlier holds its own bytes
    /// and has to be zeroed on its own.
    // The volatile whole-receiver wipe is the terminal state. The analyzer
    // recognizes ordinary lifecycle assignments, not secureZero.
    // ziglint-ignore: Z030
    pub fn deinit(self: *SecretKey) void {
        std.crypto.secureZero(u8, @volatileCast(std.mem.asBytes(self)));
    }
};

/// A detached ed25519 signature: 64 bytes over some message.
///
/// A value with no lifetime, no allocation and no borrow of the message: a
/// signature is checked against a `NodeId` and the same bytes, and both are
/// the caller's to supply at that point. Nothing here is validated on the way
/// in — `fromBytes` takes any 64 bytes — because a signature that verifies is
/// a fact only `verify` or `verifyStrict` can establish.
pub const Signature = struct {
    /// The raw signature, in the RFC 8032 encoding.
    bytes: [Ed25519.Signature.encoded_length]u8,

    /// Bytes in the signature.
    pub const byte_length = Ed25519.Signature.encoded_length;

    /// Any 64 bytes as a signature. No check: the encoding is only meaningful
    /// next to the message and key `verify` is given.
    pub fn fromBytes(bytes: [byte_length]u8) Signature {
        return .{ .bytes = bytes };
    }

    /// The 64 bytes, copied out by value.
    pub fn toBytes(self: Signature) [byte_length]u8 {
        return self.bytes;
    }

    /// `verify` (not `verifyStrict`), which skips the small-order and
    /// non-canonical key pass and so costs no second decompression.
    ///
    /// **That skip makes a precondition of `node_id` rather than a claim about
    /// the type.** This form is correct when the key's canonicality is
    /// established — a `NodeId` from `NodeId.fromBytes` or any parser built on
    /// it, one derived from a seed, or one copied from a value so produced,
    /// which is where every id in ozai comes from. It is not a check on a
    /// `NodeId` a caller built as a struct literal out of bytes it did not
    /// validate; for one of those, and for anything that must match iroh
    /// byte-for-byte over hostile input, use `verifyStrict`.
    pub fn verify(self: Signature, message: []const u8, node_id: NodeId) KeyError!void {
        const ed_signature = Ed25519.Signature.fromBytes(self.bytes);
        ed_signature.verify(message, node_id.key) catch return error.BadSignature;
    }

    /// `verifyStrict` additionally rejects small-order and non-canonical keys,
    /// which is what iroh's `verify_strict` does. It is the right check on any
    /// key that arrived from the network rather than from `NodeId.fromBytes`,
    /// and on any `NodeId` built by struct literal — see the `key` field and
    /// `verify`.
    ///
    /// Both forms are `error.BadSignature` for every refusal — a wrong
    /// message, a wrong key, a malformed signature, and under this one a
    /// small-order key — and neither says which. `message` is borrowed for the
    /// call only.
    pub fn verifyStrict(self: Signature, message: []const u8, node_id: NodeId) KeyError!void {
        const ed_signature = Ed25519.Signature.fromBytes(self.bytes);
        ed_signature.verifyStrict(message, node_id.key) catch return error.BadSignature;
    }

    /// Lowercase hex, the form a log line and a ticket's signature field both
    /// carry.
    pub fn format(self: Signature, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.writeAll(&std.fmt.bytesToHex(&self.bytes, .lower));
    }
};

const t = std.testing;

// The vector iroh publishes for an all-zero secret key, as the local TLS name.
// If our seed derivation ever drifts from ed25519-as-RFC-8032, this is the
// first thing that breaks.
test "all-zero seed produces the iroh node id" {
    var secret = try SecretKey.fromSeed([_]u8{0} ** SecretKey.seed_length);
    defer secret.deinit();
    const node_id = secret.nodeId();
    try t.expectEqualStrings(
        "7dl2ff6emqi2qol3l382krodedij45bn3nh479hqo14a32qpr8kg.iroh.invalid",
        &node_id.toLocalTlsName(),
    );
    // The z-base-32 form is a different alphabet over the same bytes. The
    // interop vector is the DNS-legal label above; this checks only that the
    // two encodings describe one identity.
    const via_z32 = try NodeId.parseZ32(&node_id.toZ32());
    try t.expectEqual(node_id, via_z32);
}

test "local tls name round trips and rejects near misses" {
    var secret = try SecretKey.fromSeed([_]u8{0} ** SecretKey.seed_length);
    defer secret.deinit();
    const node_id = secret.nodeId();
    const name = node_id.toLocalTlsName();

    try t.expectEqualStrings(
        "7dl2ff6emqi2qol3l382krodedij45bn3nh479hqo14a32qpr8kg.iroh.invalid",
        &name,
    );
    try t.expectEqual(node_id, try NodeId.parseLocalTlsName(&name));

    // 'y' is past the end of the DNS alphabet, so the decoder names the fault
    // instead of blaming the whole name.
    var corrupt = name;
    corrupt[0] = 'y';
    try t.expectError(error.InvalidSymbol, NodeId.parseLocalTlsName(&corrupt));

    // The right label under a different suffix is a different name, not a near
    // miss on the label: the suffix is what makes the name local-only.
    try t.expectError(error.NotOnCurve, NodeId.parseLocalTlsName(
        "7dl2ff6emqi2qol3l382krodedij45bn3nh479hqo14a32qpr8kg.iroh.example",
    ));
}

test "hex and z32 round trip, and both reject a bad encoding" {
    const node_id = (try SecretKey.fromSeed([_]u8{7} ** SecretKey.seed_length)).nodeId();
    try t.expectEqual(node_id, try NodeId.parseHex(&node_id.toHex()));
    try t.expectEqual(node_id, try NodeId.parseZ32(&node_id.toZ32()));

    try t.expectError(error.NotOnCurve, NodeId.parseHex("deadbeef"));
    try t.expectError(error.InvalidLength, NodeId.parseZ32("y" ** 10));
    // Uppercase z-base-32 is a different alphabet position, not a case variant.
    try t.expectError(error.InvalidSymbol, NodeId.parseZ32("Y" ** NodeId.z32_length));
}

test "signatures verify only against the signing node and the signed bytes" {
    const secret = try SecretKey.fromSeed([_]u8{9} ** SecretKey.seed_length);
    const node_id = secret.nodeId();
    const message = "ozai";

    const signature = secret.sign(message);
    try signature.verify(message, node_id);

    try t.expectError(error.BadSignature, signature.verify("ozai!", node_id));
    const other = try SecretKey.fromSeed([_]u8{10} ** SecretKey.seed_length);
    try t.expectError(
        error.BadSignature,
        signature.verify(message, other.nodeId()),
    );
}

test "signing is deterministic" {
    const secret = try SecretKey.fromSeed([_]u8{3} ** SecretKey.seed_length);
    try t.expectEqual(secret.sign("same").toBytes(), secret.sign("same").toBytes());
}

test "node id ordering is lexicographic over bytes" {
    const low = try NodeId.fromBytes([_]u8{0x00} ** 32);
    const high = try NodeId.fromBytes([_]u8{0x00} ** 31 ++ [_]u8{0x01});
    try t.expectEqual(std.math.Order.lt, low.order(high));
    try t.expectEqual(std.math.Order.eq, low.order(try NodeId.fromBytes([_]u8{0} ** 32)));
}

test "non-canonical point bytes are rejected" {
    // y >= p has no curve point; the low 32 bytes of the field modulus plus a
    // high bit is the canonical test std applies.
    var bytes = [_]u8{0xff} ** 32;
    bytes[31] = 0x7f;
    bytes[0] = 0xed;
    try t.expectError(error.NotOnCurve, NodeId.fromBytes(bytes));
}

test "secret key zeroes itself on deinit" {
    var secret = try SecretKey.fromSeed([_]u8{5} ** SecretKey.seed_length);
    const before = secret.toBytes();
    try t.expect(std.mem.indexOfScalar(u8, &before, 5) != null);

    secret.deinit();
    try t.expect(std.mem.allEqual(u8, &secret.toBytes(), 0));
}
