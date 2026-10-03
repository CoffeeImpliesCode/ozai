//! QUIC packet headers, packet-number spaces, the header-protection and AEAD
//! steps, and the Retry and NEW_TOKEN address tokens.
//!
//! **What borrows.** `parseQuicHeader` — and `Header.parse`, which is it —
//! returns a `Header` whose `dcid`, `scid` and `token` view `fbs.buffer`, so
//! that buffer must stay alive and unmodified while they are read; copying the
//! `Header` copies the views, not the bytes. Everything else returned here is
//! self-contained: `ValidatedToken` carries both CIDs inline,
//! `computeRetryIntegrityTag` returns a by-value array, and both decryptors
//! hand plaintext back inside the caller's own buffer.
//!
//! **What mutates.** `decrypt` and `decryptWithKeyUpdate` work in place: they
//! rewrite the first byte and the packet-number bytes, advance `fbs.seek`, and
//! fill `header` with the unprotected values. A failed call may have done any
//! of that already and leaves the plaintext region undefined, so a packet that
//! does not authenticate is discarded, not read again and not retried.
//!
//! **Who owns the output.** `generateRetryToken` and `generateNewToken` seal
//! into the caller's `out` and return the written prefix length, refusing a
//! short `out` with `error.BufferTooSmall` before touching it or the entropy;
//! `negotiateVersion`, `retry` and `Header.encode` write through a
//! caller-supplied writer and keep nothing. A writer failure leaves a prefix
//! to discard.
//!
//! **What is injected.** Nothing here allocates, reads a clock, or reaches for
//! a global RNG. Time arrives as an injected `now` in nanoseconds, and every
//! random draw as an injected `std.Random`: the token generators need fresh
//! nonces under their key, while `negotiateVersion` draws only the public
//! grease bytes, which a seeded generator serves as well as a CSPRNG.

const std = @import("std");
const io = @import("../io_compat.zig");
const address = @import("../address.zig");
const assert = std.debug.assert;

const protocol = @import("protocol.zig");
const crypto = @import("crypto.zig");
const util = @import("util.zig");
const stream = @import("stream.zig");

/// Network byte order, the order every field this module reads or writes is
/// in. It is a constant rather than a parameter because the wire is not
/// negotiable.
pub const ENDIAN = std.builtin.Endian.big;

/// Bit 7 of the first byte: set on every long-header packet, clear on every
/// short-header one. It is what tells a parser which header it is looking at
/// before anything else is read.
///
pub const LONG_HEADER_BIT: u8 = 0x80;
/// Bit 6 of the first byte. QUIC requires it on every packet a version of
/// this protocol defines, and a long-header packet without it is invalid
/// (RFC 9000 §17.2); on a short header it is part of what header protection
/// hides.
///
pub const FIXED_BIT: u8 = 0x40;
/// Bit 2 of a short header's first byte: which generation of 1-RTT keys
/// protected it, flipped on a key update (RFC 9001 §6.1).
///
pub const KEY_PHASE_BIT: u8 = 0x04;

/// Bit 5 of a short header's first byte, used for passive round-trip
/// measurement by the two ends rather than by the network (RFC 9000 §17.4).
///
pub const PACKET_SPIN_BIT = 0x20;
/// Mask for the two bits of a long header's first byte that carry the packet
/// type. The mapping from those bits to a type is version-dependent, which is
/// what `longHeaderPacketType` is for.
///
pub const PACKET_TYPE_MASK = 0xF0;

/// Capacity of this core's packet staging arrays. This is a local bound,
/// not a protocol-wide limit on UDP datagrams.
pub const MAX_PACKET_LEN = 1536;
/// Bytes of a packet number on the wire at most: QUIC encodes one in one to
/// four bytes, so the packet's own first byte says how long it is.
///
pub const MAX_PACKET_NUMBER_LEN = 4; // maxlength of a "packet number"

/// Longest connection id a peer may send, and the width every cid buffer in
/// this tree is sized to. A header naming a longer one is refused rather than
/// truncated, because a truncated id routes nowhere (RFC 9000 §17.2).
///
pub const CONNECTION_ID_MAX_SIZE: u8 = 20;

const PACKET_NUM_MASK: u8 = 0x03;

/// Bytes of a stateless reset token. Same size as the Retry integrity tag
/// below and for the same reason — both are 128-bit tags on the wire — but
/// they are different things and neither is defined in terms of the other.
///
pub const STATELESS_RESET_TOKEN_SIZE = 16;
/// Bytes of the tag at the end of a Retry packet, checked before the token it
/// follows is used (RFC 9000 §17.2.5).
///
pub const RETRY_INTEGRITY_TAG_SIZE = 16;
// RFC 9001 §5.8: QUIC v1 Retry integrity key/nonce
const RETRY_INTEGRITY_KEY_V1: [crypto.key_len]u8 = .{ 0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e };
const RETRY_INTEGRITY_NONCE_V1: [crypto.nonce_len]u8 = .{ 0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb };
// RFC 9369 §3.2: QUIC v2 Retry integrity key/nonce
const RETRY_INTEGRITY_KEY_V2: [crypto.key_len]u8 = .{ 0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2, 0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92 };
const RETRY_INTEGRITY_NONCE_V2: [crypto.nonce_len]u8 = .{ 0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a };

/// A packet type, as the value the header encodes it: a long header's bit
/// pattern with the header bit and fixed bit already in it, so the enum value
/// *is* the first byte for every type that carries one.
///
/// The value matters for short-header types (`.one_rtt` is `FIXED_BIT`) and is
/// only the canonical encoding for long ones, which v2 remaps; see
/// `longHeaderPacketType`.
///
pub const PacketType = enum(u8) {
    /// Initial packet
    initial = LONG_HEADER_BIT | FIXED_BIT | 0x00,

    /// Retry packet
    retry = LONG_HEADER_BIT | FIXED_BIT | 0x30,

    /// Handshake packet
    handshake = LONG_HEADER_BIT | FIXED_BIT | 0x20,

    /// 0-RTT packet
    zero_rtt = LONG_HEADER_BIT | FIXED_BIT | 0x10,

    /// Version negotiation packet
    version_negotiation = 0,

    /// 1-RTT short header packet
    one_rtt = FIXED_BIT,

    _,
};

/// Map the 2-bit long header packet type field to a logical PacketType,
/// accounting for version-specific bit assignments.
/// RFC 9369 §5.1: v2 uses different bit patterns than v1.
pub fn longHeaderPacketType(first_byte: u8, version: u32) PacketType {
    const type_bits = (first_byte >> 4) & 0x03; // bits 4-5
    if (protocol.isV2(version)) {
        // v2: 0b00=Retry, 0b01=Initial, 0b10=0-RTT, 0b11=Handshake
        return switch (type_bits) {
            0b00 => PacketType.retry,
            0b01 => PacketType.initial,
            0b10 => PacketType.zero_rtt,
            0b11 => PacketType.handshake,
            else => unreachable,
        };
    }
    // v1: 0b00=Initial, 0b01=0-RTT, 0b10=Handshake, 0b11=Retry
    return switch (type_bits) {
        0b00 => PacketType.initial,
        0b01 => PacketType.zero_rtt,
        0b10 => PacketType.handshake,
        0b11 => PacketType.retry,
        else => unreachable,
    };
}

/// Encode the 2-bit long header packet type field for a given version.
pub fn encodeLongHeaderTypeBits(pkt_type: PacketType, version: u32) u8 {
    const bits: u8 = if (protocol.isV2(version)) switch (pkt_type) {
        PacketType.retry => 0b00,
        PacketType.initial => 0b01,
        PacketType.zero_rtt => 0b10,
        PacketType.handshake => 0b11,
        else => 0,
    } else switch (pkt_type) {
        PacketType.initial => 0b00,
        PacketType.zero_rtt => 0b01,
        PacketType.handshake => 0b10,
        PacketType.retry => 0b11,
        else => 0,
    };
    return LONG_HEADER_BIT | FIXED_BIT | (bits << 4);
}

/// Encryption level for protected packet types, independent of QUIC version.
/// Retry and Version Negotiation have no encryption epoch.
pub const Epoch = enum(u8) {
    initial = 0,
    zero_rtt = 1,
    handshake = 2,
    application = 3,

    /// Map a protected packet type; otherwise return `error.InvalidPacketType`.
    pub fn fromPacketType(int: PacketType) !Epoch {
        return switch (int) {
            PacketType.initial => Epoch.initial,
            PacketType.zero_rtt => Epoch.zero_rtt,
            PacketType.handshake => Epoch.handshake,
            PacketType.one_rtt => Epoch.application,
            else => error.InvalidPacketType,
        };
    }
};

test "Epoch fromPacketType" {
    try std.testing.expectEqual(Epoch.fromPacketType(PacketType.initial), Epoch.initial);
    try std.testing.expectEqual(Epoch.fromPacketType(PacketType.zero_rtt), Epoch.zero_rtt);
    try std.testing.expectEqual(Epoch.fromPacketType(PacketType.handshake), Epoch.handshake);
    try std.testing.expectEqual(Epoch.fromPacketType(PacketType.one_rtt), Epoch.application);

    const err = Epoch.fromPacketType(PacketType.retry);
    try std.testing.expectError(error.InvalidPacketType, err);
}

/// Packet-shape and key-setup error tags. Individual operations also propagate
/// reader, writer and cryptographic errors. These are not wire close codes.
pub const PacketError = error{
    InvalidVersion,
    InvalidPacket,
    InvalidPacketType,
};

/// QUIC transport close codes. `crypto_error` is the base plus a TLS alert;
/// `no_error` denotes a graceful close.
pub const ErrorCode = enum(u16) {
    no_error = 0x0,
    internal_error = 0x1,
    connection_refused = 0x2,
    flow_control_error = 0x3,
    stream_limit_error = 0x4,
    stream_state_error = 0x5,
    final_size_error = 0x6,
    frame_encoding_error = 0x7,
    transport_parameter_error = 0x8,
    connection_id_limit_error = 0x9,
    protocol_violation = 0xa,
    invalid_token = 0xb,
    application_error = 0xc,
    crypto_buffer_exceeded = 0xd,
    key_update_error = 0xe,
    aead_limit_reached = 0xf,
    crypto_error = 0x100,
};

/// Header metadata with CID/token views borrowing the parsed buffer. Keep that
/// buffer live and unchanged while using them. Copies share those views.
/// The default has no valid packet type or length; parse or initialize both.
pub const Header = struct {
    const Self = @This();

    /// Long-header wire version; zero for Version Negotiation and short headers.
    version: u32 = 0,
    /// Must be initialized before encoding or dispatching the header.
    packet_type: PacketType = undefined,

    /// Destination Connection ID. Empty until the parser fills it — a short
    /// header whose DCID does not fit the datagram leaves it unset.
    dcid: []const u8 = &.{},

    /// Source Connection ID. Only a long header carries one, so this stays
    /// empty for every 1-RTT packet. It was `undefined`, which made reading it
    /// after a short-header parse depend on whatever was on the stack.
    scid: []const u8 = &.{},

    /// The address verification token of the packet. Only present in `Initial`
    /// and `Retry` packets.
    token: ?[]const u8 = null,
    /// What is left of this packet: everything after the header, up to and
    /// including the packet number. Set by `parse` for every packet type, and
    /// it is the only thing a reader of a coalesced datagram has to step to
    /// the next packet.
    ///
    /// For the types with a Length field — Initial, 0-RTT, Handshake — it is
    /// that field. For the types without one — Retry, 1-RTT, and Version
    /// Negotiation, which is a whole datagram by definition — it is
    /// everything left in the datagram. Nothing may read it as a length
    /// without knowing which of those it has.
    remainder_len: usize = undefined,

    /// The packet number. It's only meaningful after the header protection is
    /// removed.
    packet_number: u64 = 0,

    /// The length of the packet number. It's only meaningful after the header
    /// protection is removed.
    packet_number_len: usize = 0,

    /// The key phase bit of the packet. It's only meaningful after the header
    /// protection is removed.
    key_phase: bool = false,

    /// The spin bit for passive RTT measurement (RFC 9000 §17.4).
    /// Only meaningful for short (1-RTT) headers.
    spin_bit: bool = false,

    /// Whether reserved bits in the unprotected header are non-zero (RFC 9000 §17.2, §17.3).
    /// Set during header protection removal; checked in connection.recv().
    reserved_bits_set: bool = false,

    /// The offset of this packet's first byte within the buffer.
    /// Used to correctly handle coalesced packets.
    packet_start: usize = 0,

    /// Equivalent to `parseQuicHeader`; returned slices borrow `fbs.buffer`.
    pub fn parse(fbs: anytype, short_dcid_len: u8) !Header {
        return parseQuicHeader(fbs, short_dcid_len);
    }

    /// Encode the unprotected header prefix, not the Length, packet number,
    /// payload or Retry integrity tag. Borrows slices for the call.
    /// CID lengths must be at most 20; protected packet-number width is 1..4.
    /// Retry requires a token. Writer failures may leave a prefix to discard.
    pub fn encode(self: *Self, writer: anytype) !void {
        var first: usize = 0;

        // encode pkt num length.
        first |= (self.packet_number_len -| 1); // (saturating sub)

        // encode short header
        if (self.packet_type == PacketType.one_rtt) {
            // unset form bit for short header
            first &= ~LONG_HEADER_BIT; // bitwise NOT

            // set fixed bit
            first |= FIXED_BIT;

            // set key phase bit
            if (self.key_phase) {
                first |= KEY_PHASE_BIT;
            } else {
                first &= ~KEY_PHASE_BIT; // bitwise NOT
            }

            try writer.writeByte(@intCast(first));
            try writer.writeAll(self.dcid);

            return;
        }

        // encode long header (version-aware type bits)
        // first already has pn_len bits from line 207; OR in the type+fixed+long bits
        first |= encodeLongHeaderTypeBits(self.packet_type, self.version);

        try writer.writeByte(@intCast(first));
        try writer.writeInt(u32, self.version, ENDIAN);

        try writer.writeByte(@intCast(self.dcid.len));
        try writer.writeAll(self.dcid);

        try writer.writeByte(@intCast(self.scid.len));
        try writer.writeAll(self.scid);

        // Only Initial and Retry packets have a token.
        switch (self.packet_type) {
            PacketType.initial => {
                if (self.token) |t| {
                    try writeVarInt(writer, t.len);
                    try writer.writeAll(t);
                } else {
                    try writeVarInt(writer, 0);
                }
            },

            PacketType.retry => {
                // retry packets don't have a token length.
                try writer.writeAll(self.token.?);
            },

            else => {}, // do nothing
        }
    }
};

/// Inline 128-bit packet-number bitmap; `lower` is the number for bit zero.
/// Owns no resources. A copy is independent.
pub const PktNumWindow = struct {
    lower: u64,
    window: u128,
};

/// Packet protection state. Null key fields mean that direction has no keys.
/// Initialize `crypto_stream` before using it and release it with its allocator;
/// copies of an initialized stream share ownership, unlike inline key copies.
/// The default is sufficient only for key setup and packet-number tracking.
pub const PacketNumSpace = struct {
    /// Expected receive packet number used to reconstruct truncated numbers.
    next_packet_number: u64 = 0,

    crypto_open: ?crypto.Open = null,
    crypto_seal: ?crypto.Seal = null,

    crypto_stream: stream.Stream = undefined,

    /// Current AEAD tag width; does not mutate the space.
    pub fn cryptoTagLen(self: *PacketNumSpace) usize {
        _ = self;
        return crypto.Aead.tag_length;
    }

    /// Derive and replace both Initial key directions for `dcid` and `version`.
    /// Borrows input bytes only for the call. Unsupported versions propagate
    /// derivation errors without replacing the existing keys. Allocates nothing.
    pub fn setupInitial(self: *PacketNumSpace, dcid: []const u8, version: u32, comptime is_server: bool) !void {
        const keys = try crypto.deriveInitialKeyMaterial(dcid, version, is_server);
        self.crypto_open = keys[0];
        self.crypto_seal = keys[1];
    }
};

/// Splits a protected packet into the Associated Data and the ciphertext
/// (RFC 9001 5.3: the AD is the header with its first byte unprotected).
///
/// Both lengths are the peer's to choose — the Length varint for the payload,
/// the token for the header — so neither is trusted here. A Length below the
/// packet number length underflows the subtraction, and one above the
/// datagram reads past it.
fn splitProtected(header: *const Header, fbs: anytype, first_byte: u8, ad_buf: []u8) !struct {
    ad: []const u8,
    payload: []u8,
} {
    if (fbs.seek > fbs.buffer.len) return error.InvalidPacket;
    if (header.remainder_len < header.packet_number_len) return error.InvalidPacket;

    const payload_len = header.remainder_len - header.packet_number_len;
    if (payload_len > fbs.buffer.len - fbs.seek) return error.InvalidPacket;

    const pkt_start = header.packet_start;
    if (pkt_start >= fbs.seek) return error.InvalidPacket;
    const header_len = fbs.seek - pkt_start;
    if (header_len > ad_buf.len) return error.InvalidPacket;

    ad_buf[0] = first_byte;
    @memcpy(ad_buf[1..][0 .. header_len - 1], fbs.buffer[pkt_start + 1 .. fbs.seek]);

    return .{
        .ad = ad_buf[0..header_len],
        .payload = fbs.buffer[fbs.seek..][0..payload_len],
    };
}

/// Remove header protection from `header` and open its payload with the keys
/// `space` holds for its epoch, in place.
///
/// Returns the plaintext, which is the same memory the ciphertext was in: the
/// AEAD tag is consumed and the caller keeps the buffer it had, so this
/// allocates nothing. `header` is updated — first byte restored, packet
/// number decoded, reserved bits recorded — because the caller needs those
/// to process what comes out.
///
/// `header.packet_start` and `fbs.seek` must describe this packet in the buffer.
/// Missing keys return `error.UndecryptablePacket`; malformed bounds return
/// `error.InvalidPacket`; tag verification can return `error.AuthenticationFailed`.
/// Failure may advance the cursor and mutate header or buffer bytes: discard
/// the packet rather than retrying that mutated input.
pub fn decrypt(header: *Header, fbs: anytype, space: *const PacketNumSpace) ![]u8 {
    // We need at least 4 bytes for packet number + 16 for sample
    if (fbs.seek + 4 + crypto.SAMPLE_LEN > fbs.buffer.len) {
        std.log.debug("Not enough data for packet number + sample: pos={d}, buffer.len={d}", .{ fbs.seek, fbs.buffer.len });
        return error.InvalidPacket;
    }

    var first_byte = fbs.buffer[header.packet_start];

    // unprotect header
    const aead = &space.crypto_open.?;

    // RFC 9001 Section 5.4.2: Sample is taken 4 bytes after START of packet number field
    const sample_offset = fbs.seek + 4;
    if (sample_offset + crypto.SAMPLE_LEN > fbs.buffer.len) {
        std.log.debug("Not enough data for sample: offset={d}, buffer.len={d}", .{ sample_offset, fbs.buffer.len });
        return error.InvalidPacket;
    }

    var sample_buf: [crypto.SAMPLE_LEN]u8 = undefined;
    @memcpy(&sample_buf, fbs.buffer[sample_offset..][0..crypto.SAMPLE_LEN]);

    const mask = aead.newMask(&sample_buf);

    if (isLongHeader(first_byte)) {
        first_byte ^= (mask[0] & 0x0f);
    } else {
        first_byte ^= (mask[0] & 0x1f);
    }

    // Check reserved bits after header protection removal (RFC 9000 §17.2, §17.3)
    if (isLongHeader(first_byte)) {
        header.reserved_bits_set = (first_byte & 0x0c) != 0;
    } else {
        header.reserved_bits_set = (first_byte & 0x18) != 0;
    }

    // Extract key phase and spin bits from unprotected short header (RFC 9001 §5.4.1, RFC 9000 §17.4)
    if (!isLongHeader(first_byte)) {
        header.key_phase = (first_byte & KEY_PHASE_BIT) != 0;
        header.spin_bit = (first_byte & PACKET_SPIN_BIT) != 0;
    }

    // Calculate packet number length from the unprotected first byte BEFORE using it
    header.packet_number_len = @as(usize, @intCast(first_byte & PACKET_NUM_MASK)) + 1;

    // Remove header protection from packet number bytes
    var i: usize = 0;
    while (i < header.packet_number_len) : (i += 1) {
        fbs.buffer[fbs.seek + i] ^= mask[1 + i];
    }

    // Now extract the decrypted packet number
    const pn_ciphertext: *const [MAX_PACKET_NUMBER_LEN]u8 = fbs.buffer[fbs.seek..][0..MAX_PACKET_NUMBER_LEN];

    // read truncated/raw packet number
    const truncated_packet_number: u64 = try switch (header.packet_number_len) {
        1 => @as(u64, std.mem.readInt(u8, pn_ciphertext.*[0..util.sizeOf(u8)], ENDIAN)),
        2 => @as(u64, std.mem.readInt(u16, pn_ciphertext.*[0..util.sizeOf(u16)], ENDIAN)),
        3 => @as(u64, std.mem.readInt(u24, pn_ciphertext.*[0..util.sizeOf(u24)], ENDIAN)),
        4 => @as(u64, std.mem.readInt(u32, pn_ciphertext.*[0..util.sizeOf(u32)], ENDIAN)),
        else => error.InvalidPacket,
    };

    // Skip the packet number bytes in the buffer
    try fbs.seekBy(@intCast(header.packet_number_len));

    // A header runs to the whole datagram when the peer sends a long token.
    var header_bytes_buf: [MAX_PACKET_LEN]u8 = undefined;
    const split = try splitProtected(header, fbs, first_byte, &header_bytes_buf);
    const header_bytes = split.ad;
    const encrypted_payload = split.payload;

    // Decode packet number
    header.packet_number = decodePacketNumber(space.next_packet_number, truncated_packet_number, header.packet_number_len * 8);

    const decrypted = try aead.decryptPayload(
        header.packet_number,
        header_bytes,
        encrypted_payload,
    );

    // Write decrypted first byte back into the input buffer for further processing.
    fbs.buffer[header.packet_start] = first_byte;

    return decrypted;
}

/// Decrypt a 1-RTT packet using the KeyUpdateManager for key phase handling.
/// Uses the (unchanging) HP key for header unprotection, then selects the
/// appropriate AEAD keys based on the key phase bit (RFC 9001 Section 6).
/// Borrows every receiver for the call and returns plaintext in `fbs.buffer`.
/// As with `decrypt`, failure can mutate the header, cursor and bytes; discard
/// the packet. Null phase keys or malformed bounds return `error.InvalidPacket`;
/// AEAD authentication errors propagate. Allocates nothing.
pub fn decryptWithKeyUpdate(header: *Header, fbs: anytype, space: *const PacketNumSpace, ku: *crypto.KeyUpdateManager) ![]u8 {
    if (fbs.seek + 4 + crypto.SAMPLE_LEN > fbs.buffer.len) {
        return error.InvalidPacket;
    }

    var first_byte = fbs.buffer[header.packet_start];

    // Use the HP open key (never changes across key updates)
    const sample_offset = fbs.seek + 4;
    if (sample_offset + crypto.SAMPLE_LEN > fbs.buffer.len) {
        return error.InvalidPacket;
    }

    var sample_buf: [crypto.SAMPLE_LEN]u8 = undefined;
    @memcpy(&sample_buf, fbs.buffer[sample_offset..][0..crypto.SAMPLE_LEN]);

    // Generate mask using the invariant HP key (cipher-suite-aware).
    // Reuse the cached AES-128 round keys when available (AES suites).
    const mask_arr = blk: {
        if (ku.hp_open_ctx) |ctx| {
            var encrypted_out: [crypto.SAMPLE_LEN]u8 = undefined;
            ctx.encrypt(&encrypted_out, &sample_buf);
            break :blk encrypted_out[0..crypto.MASK_LEN].*;
        }
        break :blk crypto.computeHpMask(&sample_buf, ku.hp_open, ku.cipher_suite);
    };
    const mask = &mask_arr;

    // Short header unmasking
    first_byte ^= (mask[0] & 0x1f);

    // Check reserved bits (RFC 9000 §17.3)
    header.reserved_bits_set = (first_byte & 0x18) != 0;

    // Extract key phase and spin bits from unprotected first byte
    header.key_phase = (first_byte & KEY_PHASE_BIT) != 0;
    header.spin_bit = (first_byte & PACKET_SPIN_BIT) != 0;

    header.packet_number_len = @as(usize, @intCast(first_byte & PACKET_NUM_MASK)) + 1;

    // Unmask packet number bytes
    var i: usize = 0;
    while (i < header.packet_number_len) : (i += 1) {
        fbs.buffer[fbs.seek + i] ^= mask[1 + i];
    }

    // Extract truncated packet number
    const pn_ciphertext: *const [MAX_PACKET_NUMBER_LEN]u8 = fbs.buffer[fbs.seek..][0..MAX_PACKET_NUMBER_LEN];
    const truncated_packet_number: u64 = try switch (header.packet_number_len) {
        1 => @as(u64, std.mem.readInt(u8, pn_ciphertext.*[0..util.sizeOf(u8)], ENDIAN)),
        2 => @as(u64, std.mem.readInt(u16, pn_ciphertext.*[0..util.sizeOf(u16)], ENDIAN)),
        3 => @as(u64, std.mem.readInt(u24, pn_ciphertext.*[0..util.sizeOf(u24)], ENDIAN)),
        4 => @as(u64, std.mem.readInt(u32, pn_ciphertext.*[0..util.sizeOf(u32)], ENDIAN)),
        else => error.InvalidPacket,
    };

    try fbs.seekBy(@intCast(header.packet_number_len));

    var header_bytes_buf: [MAX_PACKET_LEN]u8 = undefined;
    const split = try splitProtected(header, fbs, first_byte, &header_bytes_buf);
    const header_bytes = split.ad;
    const encrypted_payload = split.payload;

    // Decode packet number
    header.packet_number = decodePacketNumber(space.next_packet_number, truncated_packet_number, header.packet_number_len * 8);

    // Select the right Open keys based on key phase
    var aead = ku.getOpenKeys(header.key_phase) orelse return error.InvalidPacket;

    const decrypted = try aead.decryptPayload(
        header.packet_number,
        header_bytes,
        encrypted_payload,
    );

    fbs.buffer[header.packet_start] = first_byte;

    return decrypted;
}

/// Whether the header-form bit selects the long-header layout.
pub fn isLongHeader(first_byte: u8) bool {
    return (first_byte & LONG_HEADER_BIT) == LONG_HEADER_BIT;
}

/// Parse at `fbs.seek`, leaving the cursor at this packet's remainder.
/// Requires a valid cursor and a known short-header CID length of at most 20.
/// CIDs and token borrow `fbs.buffer`; no storage is allocated.
/// Truncated fields propagate reader errors or `error.BufferTooShort`; invalid
/// CID lengths/fixed bits return packet errors. Errors may consume a prefix.
/// A short header with missing DCID bytes leaves an empty CID for the caller
/// to reject. Remainder bounds and protection are validated by decryption.
pub fn parseQuicHeader(fbs: anytype, short_dcid_len: u8) !Header {
    const packet_start_pos = fbs.seek;
    const first_byte = try fbs.takeByte();

    var header = Header{};
    header.packet_start = packet_start_pos;

    if (isLongHeader(first_byte)) {
        // Long header packet

        const version = try fbs.takeInt(u32, ENDIAN);
        header.version = version;

        const dcid_length = try fbs.takeByte();
        if (dcid_length > CONNECTION_ID_MAX_SIZE) {
            std.log.debug("Destination CID is too long ({any} bytes)", .{dcid_length});
            return error.PacketError;
        }
        if (fbs.seek + dcid_length > fbs.buffer.len) return error.BufferTooShort;

        header.dcid = fbs.buffer[fbs.seek..(fbs.seek + dcid_length)];

        // advance length
        fbs.seek += dcid_length;

        const scid_length = try fbs.takeByte();
        if (scid_length > CONNECTION_ID_MAX_SIZE) {
            std.log.debug("Source CID is too long ({any} bytes)", .{scid_length});
            return error.InvalidPacket;
        }
        if (fbs.seek + scid_length > fbs.buffer.len) return error.BufferTooShort;

        header.scid = fbs.buffer[fbs.seek..(fbs.seek + scid_length)];

        // advance scid_length
        fbs.seek += scid_length;

        if ((first_byte & FIXED_BIT) == 0) {
            std.log.debug("Packet fixed bit is zero", .{});
            return error.InvalidPacket;
        }

        // Use version-aware packet type mapping (v1 vs v2 bit patterns differ)
        if (version == 0) {
            header.packet_type = PacketType.version_negotiation;
        } else {
            header.packet_type = longHeaderPacketType(first_byte, version);
        }

        switch (header.packet_type) {
            PacketType.initial => {
                // NOTE: RFC 9000 Section 8.1 requires clients to send Initial packets
                // with at least 1200 bytes payload. This is validated when sending (in packet_packer),
                // not when receiving, since the server may send smaller Initial packets.

                const token_length = try readVarInt(fbs);
                if (token_length > 0) {
                    // compare in u64: seek + token_length would overflow a 32-bit usize
                    if (token_length > fbs.buffer.len - fbs.seek) return error.BufferTooShort;
                    const n: usize = @intCast(token_length);
                    header.token = fbs.buffer[fbs.seek..][0..n];
                    fbs.seek += n;
                }

                header.remainder_len = try readVarIntUsize(fbs);
            },

            PacketType.retry => {
                // Retry packet: everything after header, before 16-byte integrity tag, is the token
                const remaining = fbs.buffer.len - fbs.seek;
                if (remaining > RETRY_INTEGRITY_TAG_SIZE) {
                    header.token = fbs.buffer[fbs.seek .. fbs.buffer.len - RETRY_INTEGRITY_TAG_SIZE];
                }
                // Retry packets have no Length field — they consume the entire datagram
                header.remainder_len = remaining;
            },

            // No Length field, and no need of one: a VN packet is a whole
            // datagram by definition (RFC 9000 §6.1), so what is left of the
            // datagram is the packet.
            PacketType.version_negotiation => {
                header.remainder_len = fbs.buffer.len - fbs.seek;
            },

            PacketType.handshake, PacketType.zero_rtt => {
                // Long header packets (like Initial but without Token field)
                header.remainder_len = try readVarIntUsize(fbs);
            },

            PacketType.one_rtt => {
                // Short header packet (1-RTT)
                if (fbs.seek + short_dcid_len <= fbs.buffer.len) {
                    header.dcid = fbs.buffer[fbs.seek..(fbs.seek + short_dcid_len)];
                    fbs.seek += short_dcid_len;
                }

                header.remainder_len = fbs.buffer.len - fbs.seek;
            },

            else => {
                std.log.debug("Packet type not recognized: {any}", .{header.packet_type});
                header.remainder_len = try readVarIntUsize(fbs);
            },
        }
    } else {
        // Short header (1-RTT) packet

        header.packet_type = PacketType.one_rtt;

        // Short header: first_byte + DCID (known length from connection state) + payload
        if (fbs.seek + short_dcid_len <= fbs.buffer.len) {
            header.dcid = fbs.buffer[fbs.seek..(fbs.seek + short_dcid_len)];
            fbs.seek += short_dcid_len;
        }

        header.remainder_len = fbs.buffer.len - fbs.seek;
    }

    return header;
}

/// Write Version Negotiation with swapped CIDs, supported versions and grease.
/// Borrows header slices, writer and random engine for the call. CID lengths
/// must be at most 20. Writer errors leave a prefix; random draws are not undone.
pub fn negotiateVersion(header: Header, writer: anytype, random: std.Random) !void {
    // RFC 9000 §6.1: a long header's unused bits carry an arbitrary value
    // set by the server. That is greasing, not a secret — the byte goes out
    // in the clear and a peer that learns it learns nothing, so a seeded
    // generator is exactly as good as a CSPRNG here. It is a parameter only
    // so a test can assert on a fixed packet.
    try writer.writeByte(random.int(u8) | LONG_HEADER_BIT);
    try writer.writeInt(u32, 0, ENDIAN);

    try writer.writeByte(@intCast(header.scid.len));
    try writer.writeAll(header.scid);

    try writer.writeByte(@intCast(header.dcid.len));
    try writer.writeAll(header.dcid);

    for (protocol.SUPPORTED_VERSIONS) |version| {
        try writer.writeInt(u32, version, ENDIAN);
    }

    // RFC 9000 §6.3: Include a reserved version for greasing.
    // Reserved versions follow the pattern 0x?a?a?a?a. A greased version
    // exists so a client can prove it ignores a version it does not
    // implement; it is a public value on the wire and carries nothing
    // secret, so it must never be mistaken for a token or a nonce.
    var grease_bytes: [2]u8 = undefined;
    random.bytes(&grease_bytes);
    const grease_version: u32 = (@as(u32, grease_bytes[0] >> 4) << 28) | (0xa << 24) |
        (@as(u32, grease_bytes[0] & 0xf) << 20) | (0xa << 16) |
        (@as(u32, grease_bytes[1] >> 4) << 12) | (0xa << 8) |
        (@as(u32, grease_bytes[1] & 0xf) << 4) | 0xa;
    try writer.writeInt(u32, grease_version, ENDIAN);
}

/// Encode a complete Retry with `new_scid`, `token` and the version's tag.
/// Inputs are borrowed only for the call; CID lengths must be at most 20.
/// `fbs` must start empty. Encoding/capacity errors leave a prefix to discard.
pub fn retry(
    header: Header,
    new_scid: []u8, // original destination connection id
    token: []u8,
    fbs: anytype,
) !void {
    const writer = fbs;
    var hdr = Header{
        .version = header.version,
        .packet_type = PacketType.retry,
        .dcid = header.scid,
        .scid = new_scid,
        .token = token,
        .packet_number = 0,
        .packet_number_len = 0,
    };

    try hdr.encode(writer);

    const integrity_tag = try computeRetryIntegrityTag(fbs.buffered(), header.dcid, header.version);

    try writer.writeAll(&integrity_tag);
}

/// Compute the v1/v2 Retry integrity tag, borrowing both byte slices.
/// `odcid.len <= 20`; the pseudo-packet must fit 1400 bytes or returns
/// `error.NoSpaceLeft`. Allocates nothing and returns independent inline bytes.
pub fn computeRetryIntegrityTag(
    packet_bytes_without_tag: []const u8,
    odcid: []const u8,
    version: u32,
) ![crypto.Aead.tag_length]u8 {
    const key = if (protocol.isV2(version)) RETRY_INTEGRITY_KEY_V2 else RETRY_INTEGRITY_KEY_V1;
    const nonce = if (protocol.isV2(version)) RETRY_INTEGRITY_NONCE_V2 else RETRY_INTEGRITY_NONCE_V1;

    // Use stack buffer: 1 (odcid_len) + 20 (max odcid) + ~1300 (max packet) = 1321
    var buf: [1400]u8 = undefined;
    var inner_fbs = io.fixedBufferStream(&buf);
    const buf_writer = &inner_fbs;
    try buf_writer.writeByte(@intCast(odcid.len));
    try buf_writer.writeAll(odcid);
    try buf_writer.writeAll(packet_bytes_without_tag);

    const m = "";
    var c: [m.len]u8 = undefined;
    var tag: [crypto.Aead.tag_length]u8 = undefined;
    crypto.Aead.encrypt(&c, &tag, m, inner_fbs.buffered(), nonce, key);

    return tag;
}

/// Check a Retry tag without retaining or mutating inputs. Short packets and
/// mismatches return false; pseudo-packet capacity errors propagate as in
/// `computeRetryIntegrityTag`. `odcid.len` must be at most 20.
pub fn verifyRetryIntegrity(
    raw_packet: []const u8,
    odcid: []const u8,
    version: u32,
) !bool {
    if (raw_packet.len < RETRY_INTEGRITY_TAG_SIZE) return false;
    const packet_without_tag = raw_packet[0 .. raw_packet.len - RETRY_INTEGRITY_TAG_SIZE];
    const received_tag = raw_packet[raw_packet.len - RETRY_INTEGRITY_TAG_SIZE ..];
    const expected_tag = try computeRetryIntegrityTag(packet_without_tag, odcid, version);
    // Constant-time compare of the Retry integrity AEAD tag (RFC 9001 §5.8):
    // a non-constant-time check is an authentication-tag oracle.
    return std.crypto.timing_safe.eql([RETRY_INTEGRITY_TAG_SIZE]u8, received_tag[0..RETRY_INTEGRITY_TAG_SIZE].*, expected_tag);
}

// Encrypted Retry token format:
// nonce(12) || AES-128-GCM-encrypt(plaintext) || tag(16)
// Plaintext: odcid_len(1) + odcid(<=20) + retry_scid_len(1) + retry_scid(<=20)
//          + timestamp_ns(8) + address(Address.identity_length)
/// Nonce width of this issuer-private token format.
pub const TOKEN_NONCE_LEN = 12;
/// Authentication tag width of this issuer-private token format.
pub const TOKEN_TAG_LEN = 16;
/// Maximum plaintext with two at-most-20-byte CIDs and the complete address.
pub const TOKEN_MAX_PLAINTEXT_LEN = 1 + 20 + 1 + 20 + 8 + address.identity_length;
/// Output capacity required by `generateRetryToken`.
pub const TOKEN_MAX_LEN = TOKEN_NONCE_LEN + TOKEN_MAX_PLAINTEXT_LEN + TOKEN_TAG_LEN;

/// Seal an address-bound Retry token into caller-owned `out`.
/// CID lengths must be at most 20. `now` is nonnegative nanoseconds on the
/// validator's clock epoch. Production `random` must provide fresh CSPRNG
/// nonces under `token_key`; the engine is borrowed for the call.
/// `error.BufferTooSmall` leaves output and entropy untouched. Other encoding
/// errors may leave a prefix. Returns the written prefix length; allocates nothing.
pub fn generateRetryToken(
    out: []u8,
    odcid: []const u8,
    retry_scid: []const u8,
    client_addr: address.Address,
    token_key: [crypto.key_len]u8,
    now: i64,
    random: std.Random,
) !usize {
    if (out.len < TOKEN_MAX_LEN) return error.BufferTooSmall;

    // AEAD nonce for the token: a one-time value under `token_key`. Two
    // tokens sealed with the same nonce and key leak the keystream and the
    // key, so this must come from a real CSPRNG. It is injected rather than
    // read from a global only so a test can drive it; the production caller
    // supplies the same kind of generator it used before.
    var nonce: [TOKEN_NONCE_LEN]u8 = undefined;
    random.bytes(&nonce);
    @memcpy(out[0..TOKEN_NONCE_LEN], &nonce);

    // Build plaintext
    var plaintext: [TOKEN_MAX_PLAINTEXT_LEN]u8 = undefined;
    var pt_fbs = io.fixedBufferStream(&plaintext);
    const pt_writer = &pt_fbs;
    try pt_writer.writeByte(@intCast(odcid.len));
    try pt_writer.writeAll(odcid);
    try pt_writer.writeByte(@intCast(retry_scid.len));
    try pt_writer.writeAll(retry_scid);
    // Issuer and validator must use the same injected clock epoch.
    try pt_writer.writeInt(i64, now, ENDIAN);
    // The address is bound whole, family and scope included; `Address.identity`
    // is why the bytes are written rather than sliced out of a struct.
    try pt_writer.writeAll(&client_addr.identity());

    const pt_len = pt_fbs.seek;
    const pt_data = plaintext[0..pt_len];

    // Encrypt: no AD, just nonce+key
    var ciphertext_buf: [TOKEN_MAX_PLAINTEXT_LEN]u8 = undefined;
    var tag: [TOKEN_TAG_LEN]u8 = undefined;
    crypto.Aead.encrypt(
        ciphertext_buf[0..pt_len],
        &tag,
        pt_data,
        "",
        nonce,
        token_key,
    );

    @memcpy(out[TOKEN_NONCE_LEN..][0..pt_len], ciphertext_buf[0..pt_len]);
    @memcpy(out[TOKEN_NONCE_LEN + pt_len ..][0..TOKEN_TAG_LEN], &tag);

    return TOKEN_NONCE_LEN + pt_len + TOKEN_TAG_LEN;
}

/// Authenticated Retry CIDs copied into inline storage. Lengths are 0..20;
/// manual writes must preserve those bounds. Copies are independent.
pub const ValidatedToken = struct {
    odcid_buf: [20]u8 = .{0} ** 20,
    odcid_len: u8 = 0,
    retry_scid_buf: [20]u8 = .{0} ** 20,
    retry_scid_len: u8 = 0,

    /// Borrow the original DCID from this receiver until it is moved or rewritten.
    pub fn getOdcid(self: *const ValidatedToken) []const u8 {
        return self.odcid_buf[0..self.odcid_len];
    }

    /// Borrow the Retry SCID from this receiver until it is moved or rewritten.
    pub fn getRetryScid(self: *const ValidatedToken) []const u8 {
        return self.retry_scid_buf[0..self.retry_scid_len];
    }
};

// Token validity duration: 60 seconds
const TOKEN_MAX_AGE_NS: i64 = 60 * std.time.ns_per_s;

/// Open an address-bound Retry token. `now` is nonnegative nanoseconds on the
/// issuer's clock epoch. Invalid format, authentication, address, future time
/// or age over 60 seconds returns null. Inputs are borrowed for the call;
/// a returned value owns its CIDs inline and needs no release.
pub fn validateRetryToken(
    token_data: []const u8,
    client_addr: address.Address,
    token_key: [crypto.key_len]u8,
    now: i64,
) !?ValidatedToken {
    // A longer token is none of ours, and would overrun `plaintext`.
    if (token_data.len < TOKEN_NONCE_LEN + TOKEN_TAG_LEN + 2 or token_data.len > TOKEN_MAX_LEN) return null;

    const nonce = token_data[0..TOKEN_NONCE_LEN].*;
    const ct_len = token_data.len - TOKEN_NONCE_LEN - TOKEN_TAG_LEN;
    const ciphertext = token_data[TOKEN_NONCE_LEN..][0..ct_len];
    const tag = token_data[token_data.len - TOKEN_TAG_LEN ..][0..TOKEN_TAG_LEN].*;

    // Decrypt
    var plaintext: [TOKEN_MAX_PLAINTEXT_LEN]u8 = undefined;
    crypto.Aead.decrypt(
        plaintext[0..ct_len],
        ciphertext,
        tag,
        "",
        nonce,
        token_key,
    ) catch return null; // decryption failed = invalid token

    // Parse plaintext
    var pt_fbs = io.fixedBufferStream(plaintext[0..ct_len]);
    const pt_reader = &pt_fbs;

    var result = ValidatedToken{};

    // Read ODCID
    result.odcid_len = pt_reader.takeByte() catch return null;
    if (result.odcid_len > 20) return null;
    _ = pt_reader.readSliceShort(result.odcid_buf[0..result.odcid_len]) catch return null;

    // Read retry SCID
    result.retry_scid_len = pt_reader.takeByte() catch return null;
    if (result.retry_scid_len > 20) return null;
    _ = pt_reader.readSliceShort(result.retry_scid_buf[0..result.retry_scid_len]) catch return null;

    // Read timestamp and check age
    const timestamp = pt_reader.takeInt(i64, ENDIAN) catch return null;
    if (now - timestamp > TOKEN_MAX_AGE_NS or timestamp > now) return null;

    // The address the token was minted for, and nothing less than all of it.
    var addr_data: [address.identity_length]u8 = undefined;
    _ = pt_reader.readSliceShort(&addr_data) catch return null;
    const sealed = client_addr.identity();
    if (!std.mem.eql(u8, &addr_data, &sealed)) return null;

    return result;
}

// NEW_TOKEN token format (RFC 9000 §8.1.3):
// nonce(12) || AES-128-GCM-encrypt(plaintext) || tag(16)
// Plaintext: timestamp_ns(8) + address(Address.identity_length)
// Distinguishable from Retry tokens by shorter ciphertext.
const NEW_TOKEN_PLAINTEXT_LEN: usize = 8 + address.identity_length; // timestamp + address
const NEW_TOKEN_MAX_LEN: usize = TOKEN_NONCE_LEN + NEW_TOKEN_PLAINTEXT_LEN + TOKEN_TAG_LEN;

/// Seal a NEW_TOKEN address proof into caller storage using a fresh CSPRNG nonce.
/// `now` is nonnegative nanoseconds on the validator's clock epoch.
/// `error.BufferTooSmall` leaves output/entropy unchanged; returns the written
/// prefix length. Allocates nothing and retains no input.
pub fn generateNewToken(
    out: []u8,
    client_addr: address.Address,
    token_key: [crypto.key_len]u8,
    now: i64,
    random: std.Random,
) !usize {
    if (out.len < NEW_TOKEN_MAX_LEN) return error.BufferTooSmall;

    // AEAD nonce, one-time under `token_key`, as in `generateRetryToken`:
    // reuse under one key breaks the cipher. Injected, not global, so a
    // test can drive it; the production caller still supplies a CSPRNG.
    var nonce: [TOKEN_NONCE_LEN]u8 = undefined;
    random.bytes(&nonce);
    @memcpy(out[0..TOKEN_NONCE_LEN], &nonce);

    var plaintext: [NEW_TOKEN_PLAINTEXT_LEN]u8 = undefined;
    var pt_fbs = io.fixedBufferStream(&plaintext);
    const pt_writer = &pt_fbs;
    // This is an age check on the issuer's injected clock, not a wall date.
    try pt_writer.writeInt(i64, now, ENDIAN);
    try pt_writer.writeAll(&client_addr.identity());

    var ciphertext_buf: [NEW_TOKEN_PLAINTEXT_LEN]u8 = undefined;
    var tag: [TOKEN_TAG_LEN]u8 = undefined;
    crypto.Aead.encrypt(
        &ciphertext_buf,
        &tag,
        &plaintext,
        "",
        nonce,
        token_key,
    );

    @memcpy(out[TOKEN_NONCE_LEN..][0..NEW_TOKEN_PLAINTEXT_LEN], &ciphertext_buf);
    @memcpy(out[TOKEN_NONCE_LEN + NEW_TOKEN_PLAINTEXT_LEN ..][0..TOKEN_TAG_LEN], &tag);

    return NEW_TOKEN_MAX_LEN;
}

/// Verify format, tag, full address and age at most 60 seconds.
/// `now` is nonnegative nanoseconds on the issuer's epoch. Invalid or future
/// tokens return false. Inputs are read only for the call; allocates nothing.
pub fn validateNewToken(
    token_data: []const u8,
    client_addr: address.Address,
    token_key: [crypto.key_len]u8,
    now: i64,
) bool {
    if (token_data.len != NEW_TOKEN_MAX_LEN) return false;

    const nonce = token_data[0..TOKEN_NONCE_LEN].*;
    const ciphertext = token_data[TOKEN_NONCE_LEN..][0..NEW_TOKEN_PLAINTEXT_LEN];
    const tag = token_data[token_data.len - TOKEN_TAG_LEN ..][0..TOKEN_TAG_LEN].*;

    var plaintext: [NEW_TOKEN_PLAINTEXT_LEN]u8 = undefined;
    crypto.Aead.decrypt(
        &plaintext,
        ciphertext,
        tag,
        "",
        nonce,
        token_key,
    ) catch return false;

    var pt_fbs = io.fixedBufferStream(&plaintext);
    const pt_reader = &pt_fbs;

    const timestamp = pt_reader.takeInt(i64, ENDIAN) catch return false;
    if (now - timestamp > TOKEN_MAX_AGE_NS or timestamp > now) return false;

    var addr_data: [address.identity_length]u8 = undefined;
    _ = pt_reader.readSliceShort(&addr_data) catch return false;
    const sealed = client_addr.identity();
    if (!std.mem.eql(u8, &addr_data, &sealed)) return false;

    return true;
}

/// Decode a QUIC varint through `takeByte` and `takeInt`, borrowing the reader
/// for the call. Truncation propagates reader errors after a consumed prefix;
/// callers discard the enclosing malformed packet. Allocates nothing.
pub fn readVarInt(reader: anytype) !u64 {
    //
    // https://datatracker.ietf.org/doc/html/draft-ietf-quic-transport-16#section-16
    //
    //     For example, the eight octet sequence c2 19 7c 5e ff 14 e8 8c (in
    //     hexadecimal) decodes to the decimal value 151288809941952652; the
    //     four octet sequence 9d 7f 3e 7d decodes to 494878333; the two octet
    //     sequence 7b bd decodes to 15293; and the single octet 25 decodes to
    //     37 (as does the two octet sequence 40 25).
    //
    const first_byte = try reader.takeByte();

    // the first two bits of the first byte encode the length
    var len: i32 = @as(i32, 1) << @intCast((first_byte & 0xc0) >> 6);
    len = len - 1;

    var value: u64 = first_byte & 0x3F;
    while (len > 0) {
        len = len - 1;
        value = (value << 8);

        const red = try reader.takeByte();
        value = value + red;
    }

    return value;
}

/// Returns the number of bytes needed to encode a value as a QUIC variable-length integer.
/// Read a varint that will be used as a length or index. Wire varints are
/// u64; anything that cannot be a usize cannot describe a real buffer.
pub fn readVarIntUsize(reader: anytype) !usize {
    return std.math.cast(usize, try readVarInt(reader)) orelse error.VarIntTooLarge;
}

/// Varint width for values up to 2^62-1. Larger values also return 8 here:
/// this sizes encodings but does not validate them; `writeVarInt` does.
pub fn varIntLength(value: u64) usize {
    if (value <= 63) return 1;
    if (value <= 16383) return 2;
    if (value <= 1073741823) return 4;
    return 8;
}

/// Encode `value` through `writeByte` and `writeInt`, borrowing the writer.
/// Values above 2^62-1 return `error.VarIntTooLarge` without writing. Writer
/// failures may leave a prefix to discard. Allocates nothing.
pub fn writeVarInt(writer: anytype, value: u64) !void {
    if (value <= 63) {
        // 1-byte encoding: 00xxxxxx
        try writer.writeByte(@intCast(value));
    } else if (value <= 16383) {
        // 2-byte encoding: 01xxxxxx xxxxxxxx
        try writer.writeInt(u16, @intCast(value | (0b01 << 14)), ENDIAN);
    } else if (value <= 1073741823) {
        // 4-byte encoding: 10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
        try writer.writeInt(u32, @intCast(value | (0b10 << 30)), ENDIAN);
    } else if (value <= 4611686018427387903) {
        // 8-byte encoding: 11xxxxxx xxxxxxxx ... xxxxxxxx
        try writer.writeInt(u64, value | (0b11 << 62), ENDIAN);
    } else {
        return error.VarIntTooLarge;
    }
}

test "QUIC: a parsed header hands back real slices, even where it filled none" {
    // Both defaulted to `undefined`, so a caller that read `scid` after a
    // short-header parse read the stack. The randomized sweeps found it as a
    // usize overflow in one test and a failed @intCast in another, on Linux
    // only — which is what reading undefined memory looks like.
    {
        // Short header: one byte of flags, then a DCID the caller sizes.
        const short = [_]u8{ 0x40, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0xff };
        var fbs = io.fixedBufferStream(&short);
        const hdr = try Header.parse(&fbs, 8);
        try std.testing.expectEqual(PacketType.one_rtt, hdr.packet_type);
        try std.testing.expectEqual(@as(usize, 0), hdr.scid.len);
        try std.testing.expectEqual(@as(usize, 8), hdr.dcid.len);
    }
    {
        // ... and a DCID that does not fit leaves that one empty too.
        const truncated = [_]u8{ 0x40, 0xde, 0xad };
        var fbs = io.fixedBufferStream(&truncated);
        const hdr = try Header.parse(&fbs, 8);
        try std.testing.expectEqual(@as(usize, 0), hdr.dcid.len);
        try std.testing.expectEqual(@as(usize, 0), hdr.scid.len);
    }
}

test "QUIC: Variable-Length Integer Encoding" {
    // 1-byte encoding
    {
        var buf: [8]u8 = undefined;
        var fbs = io.fixedBufferStream(&buf);
        try writeVarInt(&fbs, 37);
        try std.testing.expectEqualSlices(u8, &[_]u8{0x25}, fbs.buffered());
    }
    // 2-byte encoding
    {
        var buf: [8]u8 = undefined;
        var fbs = io.fixedBufferStream(&buf);
        try writeVarInt(&fbs, 15293);
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0x7b, 0xbd }, fbs.buffered());
    }
    // 4-byte encoding
    {
        var buf: [8]u8 = undefined;
        var fbs = io.fixedBufferStream(&buf);
        try writeVarInt(&fbs, 494878333);
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0x9d, 0x7f, 0x3e, 0x7d }, fbs.buffered());
    }
    // 8-byte encoding
    {
        var buf: [8]u8 = undefined;
        var fbs = io.fixedBufferStream(&buf);
        try writeVarInt(&fbs, 151288809941952652);
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c }, fbs.buffered());
    }
}

test "QUIC: varIntLength" {
    try std.testing.expectEqual(@as(usize, 1), varIntLength(0));
    try std.testing.expectEqual(@as(usize, 1), varIntLength(63));
    try std.testing.expectEqual(@as(usize, 2), varIntLength(64));
    try std.testing.expectEqual(@as(usize, 2), varIntLength(16383));
    try std.testing.expectEqual(@as(usize, 4), varIntLength(16384));
    try std.testing.expectEqual(@as(usize, 4), varIntLength(1073741823));
    try std.testing.expectEqual(@as(usize, 8), varIntLength(1073741824));
}

test "QUIC: Variable-Length Integer Decoding" {
    var fbs = io.fixedBufferStream(&[_]u8{ 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c });
    try std.testing.expect(151288809941952652 == try readVarInt(&fbs));

    fbs = io.fixedBufferStream(&[_]u8{ 0x9d, 0x7f, 0x3e, 0x7d });
    try std.testing.expect(494878333 == try readVarInt(&fbs));

    fbs = io.fixedBufferStream(&[_]u8{ 0x7b, 0xbd });
    try std.testing.expect(15293 == try readVarInt(&fbs));

    fbs = io.fixedBufferStream(&[_]u8{0x25});
    try std.testing.expect(37 == try readVarInt(&fbs));

    fbs = io.fixedBufferStream(&[_]u8{ 0x40, 0x25 });
    try std.testing.expect(37 == try readVarInt(&fbs));
}

//
// Recover a packet number from a truncated packet number.
//
// See: Appendix A - Sample Packet Number Decoding Algorithm
// (https://datatracker.ietf.org/doc/html/rfc9000#appendix-A.3)
//
fn decodePacketNumber(expected_pkt_num: u64, truncated_pkt_num: u64, num_bits: usize) u64 {
    assert(num_bits <= 32); // The maximum length of a encoded packet number is 32 in bits.

    const window: u64 = @as(u64, 1) << @intCast(num_bits);
    const half_window = window / 2;
    const pkt_num_mask = window - 1;

    const candidate = (expected_pkt_num & ~pkt_num_mask) | truncated_pkt_num;

    if ((candidate + half_window <= expected_pkt_num) and (candidate < (1 << 62) - window)) {
        return candidate + window;
    }

    if ((candidate > expected_pkt_num + half_window) and (candidate >= window)) {
        return candidate - window;
    }

    return candidate;
}

/// A seeded generator so a run twice draws the same nonces and keys. The
/// same shape as the one in `connection.zig`: a `DefaultPrng` behind a
/// wrapper whose `random()` hands out the borrow. Nothing in a test here
/// depends on the *values* being secret — the keys are throwaway, the
/// nonces only have to differ from each other — so a fixed seed loses no
/// coverage and buys a reproducible failure.
const TestRandom = struct {
    prng: std.Random.DefaultPrng = .init(0x7a6b6579),

    fn random(self: *@This()) std.Random {
        return self.prng.random();
    }
};

/// The instant the token tests seal and age-check at, in monotonic
/// nanoseconds, the same units the production `now` carries.
const token_test_now: i64 = 1_000 * std.time.ns_per_s;

// Retry token roundtrip test
test "Retry token: generate and validate roundtrip" {
    var rng = TestRandom{};
    // A throwaway AEAD key: this test asks whether a token survives a
    // roundtrip, not whether the key was unpredictable.
    var token_key: [crypto.key_len]u8 = undefined;
    rng.random().bytes(&token_key);

    const odcid = &[_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const retry_scid = &[_]u8{ 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };
    const addr = address.Address.initIpv4(.{ 127, 0, 0, 1 }, 4433);

    var out: [TOKEN_MAX_LEN]u8 = undefined;
    const token_len = try generateRetryToken(&out, odcid, retry_scid, addr, token_key, token_test_now, rng.random());
    try std.testing.expect(token_len > TOKEN_NONCE_LEN + TOKEN_TAG_LEN);

    const validated = try validateRetryToken(out[0..token_len], addr, token_key, token_test_now);
    try std.testing.expect(validated != null);
    const v = validated.?;
    try std.testing.expectEqualSlices(u8, odcid, v.getOdcid());
    try std.testing.expectEqualSlices(u8, retry_scid, v.getRetryScid());
}

// Retry token: wrong address should fail
test "Retry token: wrong address rejected" {
    var rng = TestRandom{};
    var token_key: [crypto.key_len]u8 = undefined;
    rng.random().bytes(&token_key);

    const odcid = &[_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const retry_scid = &[_]u8{ 0x11, 0x12, 0x13, 0x14 };
    const addr1 = address.Address.initIpv4(.{ 127, 0, 0, 1 }, 0);

    var out: [TOKEN_MAX_LEN]u8 = undefined;
    const token_len = try generateRetryToken(&out, odcid, retry_scid, addr1, token_key, token_test_now, rng.random());

    // A different IPv4 address on the same family and port.
    const addr2 = address.Address.initIpv4(.{ 10, 0, 0, 1 }, 0);
    const validated = try validateRetryToken(out[0..token_len], addr2, token_key, token_test_now);
    try std.testing.expect(validated == null);
}

/// 2001:db8::1. The last byte is the tail, and below it is the only byte a
/// second address changes — so a test that swaps it is asserting about the
/// tail and about nothing else.
const ipv6_tail_one: [16]u8 = [_]u8{ 0x20, 0x01, 0x0d, 0xb8 } ++ [_]u8{0} ** 11 ++ [_]u8{1};

// The legacy binding omits the IPv6 tail; IPv4 tests cannot detect this.
test "Retry token: an IPv6 address differing only in its tail is not the same address" {
    var rng = TestRandom{};
    var token_key: [crypto.key_len]u8 = undefined;
    rng.random().bytes(&token_key);

    const odcid = &[_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const retry_scid = &[_]u8{ 0x11, 0x12, 0x13, 0x14 };
    const sealed = address.Address.initIpv6(ipv6_tail_one, 4433, 0);
    var tail_two = ipv6_tail_one;
    tail_two[15] = 2;
    const other_tail = address.Address.initIpv6(tail_two, 4433, 0);

    var out: [TOKEN_MAX_LEN]u8 = undefined;
    const token_len = try generateRetryToken(
        &out,
        odcid,
        retry_scid,
        sealed,
        token_key,
        token_test_now,
        rng.random(),
    );
    const token = out[0..token_len];

    // The control. Without it, a binding that rejected every IPv6 token would
    // pass the assertion below and ship a server that cannot validate any
    // address on the family most of its peers use.
    const accepted = try validateRetryToken(token, sealed, token_key, token_test_now);
    try std.testing.expect(accepted != null);

    const validated = try validateRetryToken(token, other_tail, token_key, token_test_now);
    try std.testing.expect(validated == null);
}

// The same tail, on the other token. The two formats share the address
// binding, so a fix that reached only `generateRetryToken` would leave this one
// accepting an address it was never minted for.
test "NEW_TOKEN: an IPv6 address differing only in its tail is not the same address" {
    var rng = TestRandom{};
    var token_key: [crypto.key_len]u8 = undefined;
    rng.random().bytes(&token_key);

    const sealed = address.Address.initIpv6(ipv6_tail_one, 4433, 0);
    var tail_two = ipv6_tail_one;
    tail_two[15] = 2;
    const other_tail = address.Address.initIpv6(tail_two, 4433, 0);

    var out: [NEW_TOKEN_MAX_LEN]u8 = undefined;
    const token_len = try generateNewToken(&out, sealed, token_key, token_test_now, rng.random());
    const token = out[0..token_len];

    // The control, for the same reason as the Retry token's.
    try std.testing.expect(validateNewToken(token, sealed, token_key, token_test_now));
    try std.testing.expect(!validateNewToken(token, other_tail, token_key, token_test_now));
}

// Retry token: wrong key should fail
test "Retry token: wrong key rejected" {
    var rng = TestRandom{};
    var token_key: [crypto.key_len]u8 = undefined;
    rng.random().bytes(&token_key);

    const odcid = &[_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const retry_scid = &[_]u8{ 0x11, 0x12, 0x13, 0x14 };
    const addr = address.Address.initIpv4(.{ 0, 0, 0, 0 }, 0);

    var out: [TOKEN_MAX_LEN]u8 = undefined;
    const token_len = try generateRetryToken(&out, odcid, retry_scid, addr, token_key, token_test_now, rng.random());

    // Different key
    var wrong_key: [crypto.key_len]u8 = undefined;
    rng.random().bytes(&wrong_key);
    const validated = try validateRetryToken(out[0..token_len], addr, wrong_key, token_test_now);
    try std.testing.expect(validated == null);
}

// Retry token: a peer-chosen length past our own tokens' is rejected
test "Retry token: oversized token rejected" {
    var rng = TestRandom{};
    var token_key: [crypto.key_len]u8 = undefined;
    rng.random().bytes(&token_key);
    const addr: address.Address = .unset;

    // A peer-chosen blob, past TOKEN_MAX_LEN so it is rejected on length
    // before any key is touched.
    var token: [200]u8 = undefined;
    rng.random().bytes(&token);
    try std.testing.expect(try validateRetryToken(&token, addr, token_key, token_test_now) == null);
}

// Retry integrity tag verification
test "Retry: integrity tag compute and verify" {
    const odcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

    // Build a minimal Retry-like packet (header only, no tag yet)
    var pkt_buf: [128]u8 = undefined;
    var pkt_fbs = io.fixedBufferStream(&pkt_buf);
    const pkt_writer = &pkt_fbs;

    // First byte: Retry packet type
    try pkt_writer.writeByte(@intFromEnum(PacketType.retry));
    // Version
    try pkt_writer.writeInt(u32, 0x00000001, ENDIAN);
    // DCID
    try pkt_writer.writeByte(4);
    try pkt_writer.writeAll(&[_]u8{ 0x01, 0x02, 0x03, 0x04 });
    // SCID
    try pkt_writer.writeByte(4);
    try pkt_writer.writeAll(&[_]u8{ 0x05, 0x06, 0x07, 0x08 });
    // Token
    try pkt_writer.writeAll("some_token_data");

    const pkt_without_tag = pkt_fbs.buffered();

    // Compute tag
    const tag = try computeRetryIntegrityTag(pkt_without_tag, odcid, 0x00000001);

    // Build full packet with tag
    var full_pkt: [256]u8 = undefined;
    @memcpy(full_pkt[0..pkt_without_tag.len], pkt_without_tag);
    @memcpy(full_pkt[pkt_without_tag.len..][0..RETRY_INTEGRITY_TAG_SIZE], &tag);
    const full_len = pkt_without_tag.len + RETRY_INTEGRITY_TAG_SIZE;

    // Verify
    const valid = try verifyRetryIntegrity(full_pkt[0..full_len], odcid, 0x00000001);
    try std.testing.expect(valid);

    // Tamper with packet and verify fails
    full_pkt[10] ^= 0xFF;
    const invalid = try verifyRetryIntegrity(full_pkt[0..full_len], odcid, 0x00000001);
    try std.testing.expect(!invalid);
}

// Header parsing tests

test "Header.parse: Initial packet" {
    // Build a minimal Initial packet header
    var buf: [64]u8 = undefined;
    var pos: usize = 0;
    // First byte: long header (0x80) | Initial (0x00) | fixed bit (0x40) | PN len 0 (0x00)
    buf[pos] = 0xC0;
    pos += 1;
    // Version: QUIC v1
    std.mem.writeInt(u32, buf[pos..][0..4], protocol.QUIC_V1, .big);
    pos += 4;
    // DCID length + DCID
    buf[pos] = 8;
    pos += 1;
    @memset(buf[pos..][0..8], 0xAA);
    pos += 8;
    // SCID length + SCID
    buf[pos] = 4;
    pos += 1;
    @memset(buf[pos..][0..4], 0xBB);
    pos += 4;
    // Token length (varint 0)
    buf[pos] = 0;
    pos += 1;
    // Payload length (varint: 2-byte encoding of 20)
    buf[pos] = 0x40;
    buf[pos + 1] = 20;
    pos += 2;
    // PN (1 byte, will be masked by header protection in practice)
    buf[pos] = 0x00;
    pos += 1;
    // Payload (19 bytes to fill the declared length - 1 PN byte)
    @memset(buf[pos..][0..19], 0x00);
    pos += 19;

    var fbs = io.fixedBufferStream(buf[0..pos]);
    const header = try Header.parse(&fbs, 8);
    try std.testing.expectEqual(PacketType.initial, header.packet_type);
    try std.testing.expectEqual(protocol.QUIC_V1, header.version);
    try std.testing.expectEqual(@as(usize, 8), header.dcid.len);
    try std.testing.expectEqual(@as(usize, 4), header.scid.len);
    // Token is present but empty (zero-length)
    if (header.token) |tok| {
        try std.testing.expectEqual(@as(usize, 0), tok.len);
    }
}

test "Header.parse: Short header (1-RTT)" {
    var buf: [32]u8 = undefined;
    // First byte: short header (0x00) | fixed bit (0x40) | PN len 0 (0x00)
    buf[0] = 0x40;
    // DCID (8 bytes)
    @memset(buf[1..9], 0xCC);
    // PN (1 byte) + payload
    buf[9] = 0x01;
    @memset(buf[10..20], 0x00);

    var fbs = io.fixedBufferStream(buf[0..20]);
    const header = try Header.parse(&fbs, 8);
    try std.testing.expectEqual(PacketType.one_rtt, header.packet_type);
    try std.testing.expectEqual(@as(usize, 8), header.dcid.len);
}

test "Header.parse rejects a long header with the fixed bit clear" {
    // 0x80: long header form, fixed bit clear (RFC 9000 17.2).
    var buf = [_]u8{ 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 };
    var fbs = io.fixedBufferStream(&buf);
    try std.testing.expectError(error.InvalidPacket, Header.parse(&fbs, 8));
}

test "splitProtected rejects lengths the datagram cannot back" {
    var buf = [_]u8{0} ** 64;
    var fbs = io.fixedBufferStream(&buf);
    fbs.seek = 10;

    var header = Header{ .packet_start = 0, .packet_number_len = 4, .remainder_len = 14 };
    var ad: [MAX_PACKET_LEN]u8 = undefined;

    const ok = try splitProtected(&header, &fbs, 0xc0, &ad);
    try std.testing.expectEqual(@as(usize, 10), ok.ad.len);
    try std.testing.expectEqual(@as(usize, 10), ok.payload.len);
    try std.testing.expectEqual(@as(u8, 0xc0), ok.ad[0]);

    // Below the packet number length the subtraction underflows.
    header.remainder_len = 2;
    try std.testing.expectError(error.InvalidPacket, splitProtected(&header, &fbs, 0xc0, &ad));

    // Above what is left of the datagram it reads past the end.
    header.remainder_len = 4 + 100;
    try std.testing.expectError(error.InvalidPacket, splitProtected(&header, &fbs, 0xc0, &ad));

    // A header longer than the buffer the associated data is built in — an
    // Initial's token is the peer's to size.
    header.remainder_len = 14;
    var small: [4]u8 = undefined;
    try std.testing.expectError(error.InvalidPacket, splitProtected(&header, &fbs, 0xc0, &small));
}

test "decodePacketNumber: RFC 9000 Appendix A examples" {
    // Example from RFC 9000 Appendix A:
    // largest_pn = 0xa82f30ea, truncated_pn = 0x9b32, pn_nbits = 16
    // Expected: 0xa82f9b32
    try std.testing.expectEqual(@as(u64, 0xa82f9b32), decodePacketNumber(0xa82f30ea, 0x9b32, 16));

    // Simple case: no wraparound
    try std.testing.expectEqual(@as(u64, 5), decodePacketNumber(4, 5, 8));

    // Wraparound case: truncated 0x00, largest 0xfe, 8 bits
    // Half = 128. candidate = (0xfe & ~0xff) | 0x00 = 0xfe00? No...
    // Let's use the simplest case: largest=0, truncated=0, nbits=8 -> 0
    try std.testing.expectEqual(@as(u64, 0), decodePacketNumber(0, 0, 8));
}

test "a version negotiation packet carries no length field, so it is the whole datagram" {
    // RFC 9000 §6.1: first byte with the long-header bit, a version of zero,
    // both connection ids, then the versions a peer may choose from. There is
    // no Length field anywhere in it.
    var bytes = [_]u8{0} ** 40;
    bytes[0] = 0xc0;
    std.mem.writeInt(u32, bytes[1..5], 0, .big);
    bytes[5] = 4;
    @memcpy(bytes[6..10], &[_]u8{ 1, 2, 3, 4 });
    bytes[10] = 4;
    @memcpy(bytes[11..15], &[_]u8{ 5, 6, 7, 8 });
    std.mem.writeInt(u32, bytes[15..19], protocol.QUIC_V1, .big);
    std.mem.writeInt(u32, bytes[19..23], protocol.QUIC_V2, .big);

    var fbs = io.fixedBufferStream(&bytes);
    const header = try Header.parse(&fbs, 0);
    try std.testing.expectEqual(PacketType.version_negotiation, header.packet_type);
    // What is left of the datagram is the packet, and a reader that walks a
    // coalesced datagram by this number steps over the whole thing instead of
    // a value it never had.
    try std.testing.expectEqual(bytes.len - fbs.seek, header.remainder_len);
}
