//! A pkarr signed packet: the DNS answer a node publishes about itself, the
//! key that signs it, and the signature that makes it worth reading.
//!
//! The layout is BEP-0044's mutable-item signature applied to a DNS packet,
//! and it is specified in `pubky/pkarr` `design/base.md` at commit
//! aa4011cabc3676d533dd3c633dc0801c94bfca86, fetched 2026-09-30:
//!
//! ```abnf
//! SignedPacket = public-key signature timestamp dns-packet
//!
//! public-key  = 32 OCTET ; ed25519 public key
//! signature   = 64 OCTET ; ed25519 signature over the timestamp and dns packet
//! timestamp   =  8 OCTET ; big-endian UNIX timestamp in microseconds
//! dns-packet  =  * OCTET ; compressed encoded DNS answer packet
//! ```
//!
//! `pubky/pkarr` `pkarr/src/types/signed_packet.rs` at the same commit reads
//! the header as four fields at fixed offsets — `public_key()` at `[0..32]`,
//! `signature()` at `[32..96]`, `timestamp()` at `[96..104]`,
//! `encoded_packet()` at `[104..]` — and caps the whole thing at
//! `MAX_BYTES: u64 = 1104`. iroh's own copy of the same code, `iroh-dns/src/pkarr.rs`
//! at n0-computer/iroh commit 187f59e80afdae6bd9866002b33d3365c00b06d8, spells
//! the three constants out: `HEADER_SIZE = 104`, `MAX_DNS_PACKET_SIZE = 1000`,
//! `MAX_SIGNED_PACKET_SIZE = 1104`.
//!
//! # The signed bytes are not the packet
//!
//! What the signature covers is the BEP-0044 *signable* form of the value,
//! not the 104 header bytes and the body:
//!
//! ```abnf
//! signable = prefix dns-packet
//! prefix   = "3:seqi" timestamp "e1:v" dns-packet-length ":"
//! ```
//!
//! `signableForm` builds exactly that, and it is the single thing
//! `verify` checks. Signing the raw packet bytes produces a packet no pkarr
//! implementation accepts, which is the failure `docs/ARCHITECTURE.md`
//! invariant 11 exists to prevent. The test "the captured signature does not
//! verify over the raw bytes" is what holds that invariant in place: it fails
//! the moment the message handed to `verify` stops being the signable form.
//!
//! # The body is opaque here
//!
//! The body is a DNS packet, but this milestone does not parse DNS.
//! `Packet` carries the bytes, checks their length against the cap, and
//! signs and verifies over them exactly as it found them. Parsing the
//! records out is the resolver slice's job (`docs/PLAN.md` M5); a
//! half-implemented parser here would be a second, disagreeing
//! implementation of a grammar ozai does not yet own. The consequence is
//! recorded in the divergence list: ozai accepts a correctly signed packet
//! whose body is not a DNS packet, and upstream rejects it.
//!
//! # Purity
//!
//! Nothing here reads a clock, reads the environment, or allocates. The
//! timestamp is an argument, never `now()` — iroh's `Timestamp::now` keeps a
//! process-global `AtomicU64` to force strict monotonicity, which is the
//! `base`/`discovery` boundary's business, not this module's. Output storage
//! is always the caller's, for the reason `docs/ARCHITECTURE.md` invariant 6
//! gives: a decode never hands back a pointer into a frame it owns.

const std = @import("std");
const key = @import("../base/key.zig");

pub const NodeId = key.NodeId;
pub const SecretKey = key.SecretKey;
pub const Signature = key.Signature;

/// Where the signature starts: immediately after the public key, at 32.
pub const signature_offset = NodeId.byte_length;

/// Where the timestamp starts: immediately after the signature, at 96.
pub const timestamp_offset = signature_offset + Signature.byte_length;

/// Where the DNS body starts: immediately after the timestamp, at 104. The
/// three offsets are upstream's `public_key()` at `[0..32]`, `signature()` at
/// `[32..96]` and `timestamp()` at `[96..104]`; see the module comment.
pub const body_offset = timestamp_offset + 8;

/// The length of the header: the key, the signature, the timestamp, in that
/// order and at those offsets.
pub const header_length = body_offset;

/// The largest DNS body a pkarr packet may carry.
///
/// `pubky/pkarr` `pkarr/src/types/signed_packet.rs` at
/// aa4011cabc3676d533dd3c633dc0801c94bfca86 rejects a build whose
/// `encoded_packet.len()` is `> 1000`, and `from_bytes` rejects a whole
/// packet `> MAX_BYTES`. The prose in `design/base.md` at the same commit
/// says the body is "less than 1000 bytes", which would make 1000 illegal;
/// the code is what every implementation interoperates with, and
/// `design/base.md`'s own arithmetic — 1000 plus 64 plus 8 plus 32 — is 1104.
pub const max_dns_length = 1000;

/// The largest whole packet, header included: `MAX_BYTES` upstream, and
/// `MAX_SIGNED_PACKET_SIZE` in iroh. 1104 exactly; 1105 is refused.
pub const max_packet_length = header_length + max_dns_length;

/// The length of a relay body, which carries everything after the key because
/// the key is the path the request arrived on.
pub const relay_header_length = Signature.byte_length + 8;

/// A relay response, a DHT mutable item, or a whole packet: the same four
/// fields, with the key either present or supplied by the caller.
pub const Error = error{
    /// Fewer bytes than the header, so not one field of it is readable.
    TooShort,
    /// More than `max_packet_length` bytes.
    TooLarge,
    /// A public key field that is not exactly `NodeId.byte_length` bytes.
    BadPublicKeyLength,
    /// A signature field that is not exactly `Signature.byte_length` bytes.
    BadSignatureLength,
    /// A timestamp field that is not exactly eight bytes. There is no other
    /// reading of such a field: it is not zero-extended and not truncated,
    /// because both would invent a timestamp nobody signed.
    BadTimestampLength,
    /// A DNS body longer than `max_dns_length`.
    BodyTooLarge,
    /// The 32 header bytes are not a canonical ed25519 point encoding, so
    /// they are not a key that could have signed anything.
    BadPublicKey,
};

/// Errors from checking a signature.
pub const VerifyError = error{
    /// The header names a different node than the one the signature was
    /// checked against. Upstream has no such error: it writes the caller's
    /// key into the header and lets a failed signature check answer, so a
    /// lookup for the wrong node comes back as an indistinguishable
    /// `SignatureError`. The two are different faults — a signature that is
    /// wrong and a packet that is about someone else — and only the second
    /// one is worth retrying under a different key.
    WrongSigner,
    /// The signature did not verify over the signable form.
    BadSignature,
    /// The body is longer than `max_dns_length`, so there is no signable form
    /// of this packet to check and nothing behind it that a pkarr peer could
    /// have signed. Reachable only from a `Packet` built by hand: `parse`,
    /// `fromParts` and `fromRelayPayload` refuse that length before a packet
    /// exists.
    BodyTooLarge,
};

/// Errors from writing a packet or its signable form into caller storage.
///
/// Every one of these writes into a buffer sized for the longest legal form,
/// so the only thing left to refuse is a value the cap does not allow. It is a
/// narrower set than `Error`, which also names every way a decode can fail, and
/// it is separate because no decode failure is reachable from an encoder.
pub const EncodeError = error{
    /// The body is longer than `max_dns_length`, so it has no legal encoding.
    /// Reachable only from a `Packet` built by hand or widened after a decode.
    BodyTooLarge,
};

/// A signed pkarr packet: who signed it, when they say they signed it, and
/// the DNS body they stand behind.
///
/// `dns` borrows whatever the packet was parsed from; it is the only borrowed
/// field, and it is the caller's to keep alive, for the reason
/// `docs/ARCHITECTURE.md` invariant 6 gives. The key, the signature and the
/// timestamp are fixed-size values and are copies.
pub const Packet = struct {
    public_key: NodeId,
    signature: Signature,
    /// Microseconds since the unix epoch, as the eight big-endian bytes the
    /// header carries. Authored by the signer, and trusted only for ordering.
    timestamp: u64,
    /// The DNS body, exactly as it arrived, and at most `max_dns_length` bytes.
    /// Not parsed; see the module comment.
    ///
    /// That length is an invariant every decoder here establishes and no field
    /// list can: `Packet` is four public fields, so a hand-built one can hold a
    /// body over the cap. The two fixed buffers this file writes through — `out`
    /// in `encode`, `scratch` in `signable` — are sized for the cap and not for
    /// whatever this slice happens to be, so every one of those writes checks
    /// the length and answers `error.BodyTooLarge` rather than assuming it.
    dns: []const u8,

    /// Decode a whole packet: the wire form a DHT `v`/`k`/`sig`/`seq` item
    /// or a stored record reassembles into.
    pub fn parse(bytes: []const u8) Error!Packet {
        if (bytes.len < header_length) return error.TooShort;
        if (bytes.len > max_packet_length) return error.TooLarge;
        return fromParts(
            bytes[0..signature_offset],
            bytes[signature_offset..timestamp_offset],
            bytes[timestamp_offset..body_offset],
            bytes[body_offset..],
        );
    }

    /// Decode the four fields from four byte slices.
    ///
    /// This is the shape the fields arrive in wherever they are not adjacent
    /// in one buffer: a relay hands them over as a path segment and a body,
    /// and a DHT mutable item names them separately. Every field is copied out
    /// except `dns`, which is borrowed, so the caller can point the key and
    /// the signature at storage that dies at the end of the enclosing
    /// statement — `fromRelayPayload` does exactly that, and cannot do
    /// otherwise.
    pub fn fromParts(
        public_key: []const u8,
        signature: []const u8,
        timestamp: []const u8,
        dns: []const u8,
    ) Error!Packet {
        if (public_key.len != NodeId.byte_length) return error.BadPublicKeyLength;
        if (signature.len != Signature.byte_length) return error.BadSignatureLength;
        if (timestamp.len != 8) return error.BadTimestampLength;
        if (dns.len > max_dns_length) return error.BodyTooLarge;

        var key_bytes: [NodeId.byte_length]u8 = undefined;
        @memcpy(&key_bytes, public_key);
        return .{
            .public_key = NodeId.fromBytes(key_bytes) catch return error.BadPublicKey,
            .signature = Signature.fromBytes(signature[0..Signature.byte_length].*),
            .timestamp = std.mem.readInt(u64, timestamp[0..8], .big),
            .dns = dns,
        };
    }

    /// Decode a pkarr relay body: the signature, the timestamp and the DNS
    /// bytes, with the key named by the request rather than carried in the
    /// body.
    ///
    /// iroh resolves `https://<relay>/pkarr/<z32>` and hands the response to
    /// `SignedPacket::from_relay_payload(endpoint_id, &payload)` at
    /// n0-computer/iroh commit 187f59e80afdae6bd9866002b33d3365c00b06d8
    /// (`iroh/src/address_lookup/pkarr.rs`). The key it writes into the header
    /// is the one the caller asked about, so `verify(expected)` below checks
    /// a signature against the node id it was published under and not against
    /// whatever key the body claims.
    pub fn fromRelayPayload(expected: NodeId, payload: []const u8) Error!Packet {
        if (payload.len < relay_header_length) return error.TooShort;
        if (payload.len - relay_header_length > max_dns_length) return error.TooLarge;
        // A local, because `fromParts` copies the key out before returning and
        // the address of an expression temporary would not outlive the return.
        const key_bytes = expected.toBytes();
        return fromParts(
            &key_bytes,
            payload[0..Signature.byte_length],
            payload[Signature.byte_length..relay_header_length],
            payload[relay_header_length..],
        );
    }

    /// The bytes the signature covers: the BEP-0044 signable form of this
    /// packet's own timestamp and body, written into `out`.
    ///
    /// `error.BodyTooLarge` is the only failure: `out` is sized for the longest
    /// form a legal packet can produce, so nothing else can be short.
    pub fn signable(self: Packet, out: *[max_signable_length]u8) EncodeError![]const u8 {
        return signableForm(self.timestamp, self.dns, out);
    }

    /// The wire form, written into `out`, which is sized for the longest packet
    /// the cap allows.
    ///
    /// `error.BodyTooLarge` when `dns` is over the cap. No decoder produces
    /// such a packet — `parse` and `fromParts` refuse that length — but this is
    /// a struct of four public fields, and an encoder that trusted the cap would
    /// write past `out` rather than answer.
    pub fn encode(self: Packet, out: *[max_packet_length]u8) EncodeError![]const u8 {
        if (self.dns.len > max_dns_length) return error.BodyTooLarge;
        const key_bytes = self.public_key.toBytes();
        const sig_bytes = self.signature.toBytes();
        @memcpy(out[0..signature_offset], &key_bytes);
        @memcpy(out[signature_offset..timestamp_offset], &sig_bytes);
        std.mem.writeInt(u64, out[timestamp_offset..body_offset], self.timestamp, .big);
        @memcpy(out[body_offset..][0..self.dns.len], self.dns);
        return out[0 .. header_length + self.dns.len];
    }

    /// Check the signature against `expected`, strictly.
    ///
    /// `verifyStrict`, not `verify`: the 32 header bytes came off the network
    /// and `NodeId.fromBytes` only rejected a non-canonical `y`, which is the
    /// weaker check `docs/ARCHITECTURE.md` records under "Ed25519
    /// validation". A pkarr packet is exactly the "key that arrived from the
    /// network" case that note is about.
    pub fn verify(self: Packet, expected: NodeId) VerifyError!void {
        if (self.public_key.order(expected) != .eq) return error.WrongSigner;
        return self.verifySelf();
    }

    /// Check the signature against the key in this packet's own header,
    /// strictly. Use `verify` when the caller knows which node it asked for.
    ///
    /// `error.BodyTooLarge` is a refusal to check rather than a failed check: a
    /// body over the cap has no signable form, so there is nothing to verify
    /// against and reporting it as a bad signature would name a fault that did
    /// not happen.
    pub fn verifySelf(self: Packet) VerifyError!void {
        var scratch: [max_signable_length]u8 = undefined;
        const form = try self.signable(&scratch);
        self.signature.verifyStrict(form, self.public_key) catch
            return error.BadSignature;
    }
};

/// `"3:seqi" ++ timestamp ++ "e1:v" ++ length ++ ":" ++ dns`, the BEP-0044
/// signable form, written into caller storage and returned.
///
/// This is the message a pkarr signature is over, and the module comment's
/// `docs/ARCHITECTURE.md` invariant 11 is about it: it is not the packet.
/// `pubky/pkarr` `pkarr/src/types/signed_packet.rs` at commit
/// aa4011cabc3676d533dd3c633dc0801c94bfca86 spells it as
/// `format!("3:seqi{}e1:v{}:", timestamp, v.len())` followed by `v`, and
/// `iroh-dns/src/pkarr.rs` at n0-computer/iroh commit
/// 187f59e80afdae6bd9866002b33d3365c00b06d8 is the same function.
///
/// The prefix is written into `out[0..max_prefix_length]` rather than into
/// all of `out`: the format is given exactly the room its own worst case
/// needs, so `NoSpaceLeft` is a property of `max_prefix_length` being wrong
/// and of nothing else. A reader checks one constant, and it is checked.
/// `error.BodyTooLarge` when `dns` is longer than `max_dns_length`: the copy
/// below writes into a buffer sized for the cap, and a bound every caller has to
/// have checked is not a bound this function has.
pub fn signableForm(
    timestamp: u64,
    dns: []const u8,
    out: *[max_signable_length]u8,
) EncodeError![]const u8 {
    if (dns.len > max_dns_length) return error.BodyTooLarge;
    const prefix = std.fmt.bufPrint(out[0..max_prefix_length], "3:seqi{d}e1:v{d}:", .{
        timestamp,
        dns.len,
    }) catch |err| switch (err) {
        // The statement that `max_prefix_length` is wrong, made loud rather
        // than made silent.
        error.NoSpaceLeft => std.debug.panic(
            "the pkarr signable prefix needs more than {d} bytes",
            .{max_prefix_length},
        ),
    };
    // From `out`, not from `prefix`: `bufPrint` hands back only what it wrote.
    @memcpy(out[prefix.len..][0..dns.len], dns);
    return out[0 .. prefix.len + dns.len];
}

/// Longest prefix `signableForm` can write, bounded by the types it formats
/// and by nothing else: the six literal bytes `3:seqi`, a `u64` in decimal at
/// twenty digits, the four literal bytes `e1:v`, a `usize` in decimal at
/// twenty, and the colon. Deliberately not the narrower width the body cap
/// implies, because a bound that only holds for callers who already checked
/// the cap is one `signableForm` cannot check for itself.
pub const max_prefix_length = 6 + 20 + 4 + 20 + 1;

/// Longest signable form any legal packet can produce: the prefix at its
/// worst — twenty digits of timestamp, four of length, five of literal — plus
/// the largest body the cap allows. Narrower than `max_prefix_length` plus
/// the body, because a legal body length is at most four digits.
pub const max_signable_length = 6 + 20 + 4 + 4 + 1 + max_dns_length;

// The format writes into `out[0..max_prefix_length]`, so that slice has to
// exist. `signableForm` refuses a body over the cap before it copies anything,
// and this is the other half of that: the room the copy is then given.
comptime {
    std.debug.assert(max_prefix_length <= max_signable_length);
}

/// Sign `dns` with `secret` and write the whole wire form into `out`.
///
/// The timestamp is an argument. Reading a clock here would make a publisher
/// untestable and would put a global in a pure module, and iroh's
/// strictly-monotonic `Timestamp::now` in `iroh-dns/src/pkarr.rs` keeps a
/// process-global `AtomicU64` to do it — which is the caller's to own.
///
/// `scratch` receives the signable form, which is transient and is sized for
/// the largest legal body whether or not this one is.
///
/// `error.BodyTooLarge` when `dns` is over the cap, and nothing is written to
/// `out` on that path.
pub fn sign(
    secret: SecretKey,
    timestamp: u64,
    dns: []const u8,
    scratch: *[max_signable_length]u8,
    out: *[max_packet_length]u8,
) Error![]const u8 {
    const packet: Packet = .{
        .public_key = secret.nodeId(),
        .signature = secret.sign(try signableForm(timestamp, dns, scratch)),
        .timestamp = timestamp,
        .dns = dns,
    };
    return packet.encode(out);
}

const t = std.testing;

// Golden vectors below, all produced by running the reference implementation
// rather than by hand: the `pkarr` crate v8.0.2, which is
// `pubky/pkarr pkarr/src/types/signed_packet.rs` at commit
// aa4011cabc3676d533dd3c633dc0801c94bfca86, driven from a throwaway program
// on 2026-09-30 as
//
//     SignedPacket::builder()
//         .timestamp(Timestamp::from(1700000000000000))
//         .txt(Name::new("_iroh")?, TXT::new_with_string(value), 30)
//         .sign(&Keypair::from_secret_key(&[7u8; 32]))
//
// and dumped with `as_bytes()`. The seed is 32 bytes of `0x07`, the timestamp
// is 1700000000000000 microseconds, and the body is what the crate's
// `simple_dns` writes for that TXT record under the signer's own z-base-32
// origin, compressed. Every byte below is the reference implementation's.

/// The 32-byte seed the vectors were signed with, and the node id it derives.
const vector_seed = [_]u8{7} ** key.SecretKey.seed_length;
const vector_timestamp = 1_700_000_000_000_000;
const vector_node_id_hex = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";

/// A 213-byte packet: one TXT record naming the relay, TTL 30, under
/// `_iroh.<z32 of the key>`, name-compressed to a two-byte pointer. The
/// pubky/pkarr `pkarr` crate at aa4011cabc3676d533dd3c633dc0801c94bfca86.
/// A 213-byte packet: one TXT record naming the relay, TTL 30, under
/// `_iroh.<z32 of the key>`, name-compressed to a two-byte pointer. The
/// pubky/pkarr `pkarr` crate at aa4011cabc3676d533dd3c633dc0801c94bfca86.
const small_packet_hex =
    "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22ca97ce8c19b032ea33d1ab2c3" ++
    "27b6b62ab3ca9a5d0b1c74795c7950f7fc6335db6a654d3991bb21d72075d49a39d7e119d1247f126d6c1dcd" ++
    "6fa66162dfc2520800060a24181e4000000080000000000100000000055f69726f6834376a66676161396e75" ++
    "746a7969787a696b623774676d736639676b77713769717a3439387a72316e6435696731666e673465737900" ++
    "001000010000001e001b1a72656c61793d68747470733a2f2f6578616d706c652e636f6d2f";

/// The 109-byte body of `small_packet_hex`, the DNS answer on its own.
const small_dns_hex =
    "000080000000000100000000055f69726f6834376a66676161396e75746a7969787a696b623774676d736639" ++
    "676b77713769717a3439387a72316e6435696731666e673465737900001000010000001e001b1a72656c6179" ++
    "3d68747470733a2f2f6578616d706c652e636f6d2f";

/// A packet at the cap: the same key and the same timestamp, four TXT
/// records padded until the body is exactly 1000 bytes, so the packet
/// is exactly `max_packet_length`. The pkarr crate rejects `> 1000`,
/// which is how this length was reached rather than passed.
const at_max_packet_hex =
    "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c39f704933650dc07c1afd55b" ++
    "d029842beea933a5854e8bd0088c27a4036622650e66155ae2fa07b116d6160906e5d8e4852b1eb75eaa3e07" ++
    "2931a497e9a4b30500060a24181e4000000080000000000500000000055f69726f6834376a66676161396e75" ++
    "746a7969787a696b623774676d736639676b77713769717a3439387a72316e6435696731666e673465737900" ++
    "001000010000001e001b1a72656c61793d68747470733a2f2f6578616d706c652e636f6d2fc00c0010000100" ++
    "00001e00fffe7878787878787878787878787878787878787878787878787878787878787878787878787878" ++
    "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878" ++
    "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878" ++
    "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878" ++
    "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878" ++
    "78787878787878787878787878787878787878787878787878787878787878787878787878787878c00c0010" ++
    "00010000001e00fffe7878787878787878787878787878787878787878787878787878787878787878787878" ++
    "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878" ++
    "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878" ++
    "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878" ++
    "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878" ++
    "78787878787878787878787878787878787878787878787878787878787878787878787878787878787878c0" ++
    "0c001000010000001e00fffe7878787878787878787878787878787878787878787878787878787878787878" ++
    "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878" ++
    "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878" ++
    "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878" ++
    "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878" ++
    "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878" ++
    "7878c00c001000010000001e004e4d7878787878787878787878787878787878787878787878787878787878" ++
    "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878" ++
    "78787878";

test "golden: a captured packet decodes into its three fields" {
    var scratch: [max_packet_length]u8 = undefined;
    const captured = try hexBytes(&scratch, small_packet_hex);
    const packet = try Packet.parse(captured);

    // The key is the one the seed derives, so the header is where it says.
    var secret = try SecretKey.fromSeed(vector_seed);
    defer secret.deinit();
    try t.expectEqual(secret.nodeId(), packet.public_key);
    try t.expectEqualStrings(vector_node_id_hex, &packet.public_key.toHex());

    // The timestamp is the eight big-endian bytes at 96..104, and it is the
    // decimal number the signable prefix spells, not something else.
    try t.expectEqual(vector_timestamp, packet.timestamp);
    try t.expectEqualSlices(
        u8,
        &[_]u8{ 0x00, 0x06, 0x0a, 0x24, 0x18, 0x1e, 0x40, 0x00 },
        captured[timestamp_offset..body_offset],
    );

    // The body is the DNS answer, unmodified and unparsed.
    try t.expectEqual(@as(usize, 109), packet.dns.len);
    var body_scratch: [max_dns_length]u8 = undefined;
    const expected_body = try hexBytes(&body_scratch, small_dns_hex);
    try t.expectEqualSlices(u8, expected_body, packet.dns);

    // And the whole thing re-encodes to the bytes it was parsed from.
    var out: [max_packet_length]u8 = undefined;
    try expectHex(captured, try packet.encode(&out));
}

test "golden: the signable form is the BEP-0044 prefix, not the packet" {
    // Upstream's own expectation, from tmc/go-iroh
    // `internal/pkarr/pkarr_test.go` `TestSignablePrefix` at commit
    // 4280d6a9e8a7afe43e59d251ea5211d0b8a1d936: `signable(42, b"hi")` is
    // `"3:seqi42e1:v2:hi"`.
    var scratch: [max_signable_length]u8 = undefined;
    try t.expectEqualStrings("3:seqi42e1:v2:hi", try signableForm(42, "hi", &scratch));

    // The captured packet's own form, byte for byte: the marker, the decimal
    // timestamp, the `e1:v` record header, the decimal body length, the
    // colon, and then the body unchanged.
    var wire: [max_packet_length]u8 = undefined;
    const captured = try hexBytes(&wire, small_packet_hex);
    const packet = try Packet.parse(captured);
    const signable = try packet.signable(&scratch);
    try t.expectEqualStrings("3:seqi1700000000000000e1:v109:", signable[0..30]);
    try t.expectEqualSlices(u8, packet.dns, signable[30..]);

    // An empty body is still a form: the length is a zero, not an omission.
    try t.expectEqualStrings("3:seqi0e1:v0:", try signableForm(0, "", &scratch));

    // The bound is tight. A body at the cap under the largest timestamp there
    // is fills the buffer exactly, so a bound that was merely sufficient is
    // one this would not catch.
    var at_max: [max_dns_length]u8 = @splat(0x78);
    const longest = try signableForm(std.math.maxInt(u64), &at_max, &scratch);
    try t.expectEqual(max_signable_length, longest.len);
}

test "golden: a captured signature verifies against its own key and no other" {
    var scratch: [max_packet_length]u8 = undefined;
    const captured = try hexBytes(&scratch, small_packet_hex);
    const packet = try Packet.parse(captured);
    try packet.verify(packet.public_key);
    try packet.verifySelf();

    // Any other node, and it is the wrong signer rather than a bad signature.
    var other_secret = try SecretKey.fromSeed(other_seed);
    defer other_secret.deinit();
    try t.expectError(error.WrongSigner, packet.verify(other_secret.nodeId()));
    // `verifySelf` asks about the header's own key, so it has no opinion
    // about which node the caller wanted.
    try packet.verifySelf();

    // One flipped byte in the body, and the signature no longer covers it.
    var tampered: [max_packet_length]u8 = undefined;
    @memcpy(tampered[0..captured.len], captured);
    tampered[captured.len - 1] ^= 0xff;
    const changed = try Packet.parse(tampered[0..captured.len]);
    try t.expectError(error.BadSignature, changed.verifySelf());
    try t.expectError(error.BadSignature, changed.verify(packet.public_key));
}

test "the captured signature does not verify over the raw bytes" {
    // Invariant 11, held in place. If `verifySelf` ever signs or checks the
    // packet instead of the BEP-0044 signable form, this is the test that
    // fails: the reference implementation's signature is over the signable
    // form, so no encoding of the packet itself can be the message that
    // verifies against it.
    var scratch: [max_packet_length]u8 = undefined;
    const captured = try hexBytes(&scratch, small_packet_hex);
    const packet = try Packet.parse(captured);

    packet.signature.verify(captured, packet.public_key) catch |err| {
        try t.expectEqual(error.BadSignature, err);
        return;
    };
    return error.RawBytesVerified;
}

test "ozai signs a packet the reference implementation accepts byte for byte" {
    // The whole encoder, the signable form, the timestamp's byte order and
    // the header layout, held against bytes the pkarr crate produced. Any one
    // of them drifting moves one byte of this.
    var scratch: [max_packet_length]u8 = undefined;
    const captured = try hexBytes(&scratch, small_packet_hex);
    const body = try hexBytes(scratch[captured.len..], small_dns_hex);

    var secret = try SecretKey.fromSeed(vector_seed);
    defer secret.deinit();

    var signable: [max_signable_length]u8 = undefined;
    var out: [max_packet_length]u8 = undefined;
    const written = try sign(secret, vector_timestamp, body, &signable, &out);
    try expectHex(captured, written);
    try t.expectEqual(@as(usize, 213), written.len);
}

test "the cap is 1104 and it is enforced on both sides" {
    // The constants are the cited ones, not arithmetic that happens to agree.
    try t.expectEqual(@as(usize, 32), signature_offset);
    try t.expectEqual(@as(usize, 96), timestamp_offset);
    try t.expectEqual(@as(usize, 104), body_offset);
    try t.expectEqual(@as(usize, 104), header_length);
    try t.expectEqual(@as(usize, 1000), max_dns_length);
    try t.expectEqual(@as(usize, 1104), max_packet_length);

    // A real packet at the cap decodes, and its body is 1000 bytes.
    var scratch: [max_packet_length]u8 = undefined;
    const at_max = try hexBytes(&scratch, at_max_packet_hex);
    try t.expectEqual(max_packet_length, at_max.len);
    const big = try Packet.parse(at_max);
    try t.expectEqual(max_dns_length, big.dns.len);
    try t.expectEqual(vector_timestamp, big.timestamp);
    var out: [max_packet_length]u8 = undefined;
    try expectHex(at_max, try big.encode(&out));
    try big.verify(big.public_key);

    // One byte more is one byte too many, whether the overage is read as a
    // whole packet or built as a body.
    var over: [max_packet_length + 1]u8 = undefined;
    @memcpy(over[0..max_packet_length], at_max);
    over[max_packet_length] = 0x00;
    try t.expectError(error.TooLarge, Packet.parse(&over));

    var body_too_long: [max_dns_length + 1]u8 = @splat(0x78);
    var secret = try SecretKey.fromSeed(vector_seed);
    defer secret.deinit();
    var signable: [max_signable_length]u8 = undefined;
    try t.expectError(error.BodyTooLarge, sign(
        secret,
        vector_timestamp,
        &body_too_long,
        &signable,
        &out,
    ));

    // A 1000-byte body is signed, and a signed packet at the cap reads back.
    const at_cap_body = body_too_long[0..max_dns_length];
    const wire = try sign(secret, vector_timestamp, at_cap_body, &signable, &out);
    try t.expectEqual(max_packet_length, wire.len);
    const round_tripped = try Packet.parse(wire);
    try t.expectEqualSlices(u8, at_cap_body, round_tripped.dns);
    try round_tripped.verify(secret.nodeId());
}

test "a packet built by hand over the cap is refused, not written past" {
    // `Packet` is four public fields and nothing enforces the cap on a struct
    // literal, so a caller can hold a body no peer could have signed. Every
    // fixed buffer in this file is sized for the cap rather than for the slice
    // it was handed, so each of these three writes either checks the length or
    // runs off the end of a caller's buffer; they check it. The cap is not
    // reachable from a decoded packet, which is what makes this a hand-built
    // case and not a network one.
    var secret = try SecretKey.fromSeed(vector_seed);
    defer secret.deinit();

    var scratch: [max_signable_length]u8 = undefined;
    var out: [max_packet_length]u8 = undefined;
    var over: [max_dns_length + 1]u8 = @splat(0x78);
    var packet: Packet = .{
        .public_key = secret.nodeId(),
        .signature = secret.sign(
            try signableForm(vector_timestamp, over[0..max_dns_length], &scratch),
        ),
        .timestamp = vector_timestamp,
        .dns = &over,
    };

    try t.expectError(error.BodyTooLarge, packet.encode(&out));
    try t.expectError(error.BodyTooLarge, packet.signable(&scratch));
    try t.expectError(error.BodyTooLarge, packet.verifySelf());

    // And with the last byte dropped it is a packet again: the refusal is the
    // cap and not the shape of the value. The signature above was made over the
    // body at the cap, so this is also the round trip at the boundary.
    packet.dns = over[0..max_dns_length];
    try t.expectEqual(max_packet_length, (try packet.encode(&out)).len);
    try packet.verifySelf();
}

test "every declared decode error has a case" {
    var scratch: [max_packet_length]u8 = undefined;
    const captured = try hexBytes(&scratch, small_packet_hex);
    const header = captured[0..body_offset];
    const body = captured[body_offset..];
    var secret = try SecretKey.fromSeed(vector_seed);
    defer secret.deinit();

    // Too short: no header at all, and a header one byte short.
    try t.expectError(error.TooShort, Packet.parse(""));
    try t.expectError(error.TooShort, Packet.parse(captured[0 .. body_offset - 1]));

    // Too large: past the cap.
    var over: [max_packet_length + 1]u8 = @splat(0x00);
    @memcpy(over[0..captured.len], captured);
    try t.expectError(error.TooLarge, Packet.parse(&over));

    // Each field checked against its own length, because they arrive
    // separately from a DHT item and from a relay body.
    try t.expectError(
        error.BadPublicKeyLength,
        Packet.fromParts(
            header[0 .. signature_offset - 1],
            header[signature_offset..timestamp_offset],
            header[timestamp_offset..body_offset],
            body,
        ),
    );
    try t.expectError(
        error.BadSignatureLength,
        Packet.fromParts(
            header[0..signature_offset],
            header[signature_offset .. timestamp_offset - 1],
            header[timestamp_offset..body_offset],
            body,
        ),
    );
    try t.expectError(
        error.BadTimestampLength,
        Packet.fromParts(
            header[0..signature_offset],
            header[signature_offset..timestamp_offset],
            header[timestamp_offset .. body_offset - 1],
            body,
        ),
    );

    // A key that is not a canonical point is its own fault, named so a
    // caller can tell "this is not a key" from "this key did not sign it".
    var not_a_point: [body_offset]u8 = @splat(0);
    @memcpy(not_a_point[0..body_offset], header);
    @memset(not_a_point[0..signature_offset], 0xff);
    not_a_point[signature_offset - 1] = 0x7f;
    not_a_point[0] = 0xed;
    try t.expectError(error.BadPublicKey, Packet.parse(&not_a_point));

    // A body over the cap reaches the same wall through `fromParts`, which is
    // the path a DHT item takes.
    var long_body: [max_dns_length + 1]u8 = @splat(0x78);
    try t.expectError(
        error.BodyTooLarge,
        Packet.fromParts(
            header[0..signature_offset],
            header[signature_offset..timestamp_offset],
            header[timestamp_offset..body_offset],
            &long_body,
        ),
    );

    // A relay body carries no key, so it runs out of bytes eight earlier than
    // a whole packet does, and it passes the cap at eight earlier too.
    try t.expectError(error.TooShort, Packet.fromRelayPayload(
        secret.nodeId(),
        captured[signature_offset .. relay_header_length - 1],
    ));
    try t.expectError(error.TooLarge, Packet.fromRelayPayload(
        secret.nodeId(),
        over[0..max_packet_length],
    ));
}

test "a relay body is the packet without its key" {
    var scratch: [max_packet_length]u8 = undefined;
    const captured = try hexBytes(&scratch, small_packet_hex);
    const expected = try Packet.parse(captured);

    // iroh's `from_relay_payload`: the key comes from the request path.
    const payload = captured[signature_offset..];
    const relay = try Packet.fromRelayPayload(expected.public_key, payload);
    try t.expectEqual(expected.public_key, relay.public_key);
    try t.expectEqualSlices(u8, &expected.signature.bytes, &relay.signature.bytes);
    try t.expectEqual(expected.timestamp, relay.timestamp);
    try t.expectEqualSlices(u8, expected.dns, relay.dns);
    try relay.verify(expected.public_key);

    // Verified against a different node, it is the wrong signer. The body
    // carries no key to disagree with, so the name is the only thing that can.
    var other_secret = try SecretKey.fromSeed(other_seed);
    defer other_secret.deinit();
    try t.expectError(error.WrongSigner, relay.verify(other_secret.nodeId()));
}

test "the body is opaque, so an empty one is a packet and a nonsense one too" {
    // This milestone does not parse DNS. A header with no body parses, a body
    // of arbitrary bytes parses, and the signature still covers exactly what
    // the signer signed. Upstream calls `Packet::parse` on the body and
    // refuses the first two; the divergence belongs in the list.
    var secret = try SecretKey.fromSeed(vector_seed);
    defer secret.deinit();

    var signable: [max_signable_length]u8 = undefined;
    var out: [max_packet_length]u8 = undefined;

    for ([_][]const u8{ "", "not a dns packet", "\x00\x01\x02" }) |body| {
        const wire = try sign(secret, vector_timestamp, body, &signable, &out);
        try t.expectEqual(header_length + body.len, wire.len);

        const packet = try Packet.parse(wire);
        try t.expectEqualSlices(u8, body, packet.dns);
        try packet.verify(secret.nodeId());
    }
}

/// The seed the "a different node" cases use. Distinct from `vector_seed`, so
/// the node it derives is not the node the captured packets are about.
const other_seed = [_]u8{8} ** key.SecretKey.seed_length;

fn hexBytes(out: []u8, hex: []const u8) ![]const u8 {
    if (hex.len % 2 != 0) return error.OddHexLength;
    if (out.len < hex.len / 2) return error.BufferTooSmall;
    return std.fmt.hexToBytes(out[0 .. hex.len / 2], hex);
}

fn expectHex(expected: []const u8, actual: []const u8) !void {
    if (std.mem.eql(u8, expected, actual)) return;
    std.debug.print("expected {d} bytes: {s}\n     got {d} bytes: {s}\n", .{
        expected.len, &hexdump(expected),
        actual.len,   &hexdump(actual),
    });
    return error.WireFormatMismatch;
}

const max_dumped_bytes = 48;

fn hexdump(bytes: []const u8) [2 * max_dumped_bytes]u8 {
    var out: [2 * max_dumped_bytes]u8 = undefined;
    const digits = "0123456789abcdef";
    const shown = @min(bytes.len, max_dumped_bytes);
    for (bytes[0..shown], 0..) |byte, index| {
        out[index * 2] = digits[byte >> 4];
        out[index * 2 + 1] = digits[byte & 0x0f];
    }
    out[2 * shown] = ' ';
    out[2 * shown + 1] = '\n';
    return out;
}
