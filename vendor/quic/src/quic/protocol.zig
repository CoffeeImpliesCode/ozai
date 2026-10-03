//! The QUIC version numbers this core speaks, and the HKDF labels each one
//! derives its keys with (RFC 9000 §15, RFC 9369 §3.1).
//!
//! Nothing here allocates, reads a clock, or borrows: the module is version
//! constants plus three pure functions over a `u32`, and every result is a
//! number or a string literal with static lifetime. `isSupportedVersion` is
//! the gate a caller applies to a version off the wire; `isV2` and
//! `quicLabel` answer for a version already accepted, and treat anything that
//! is not `QUIC_V2` as v1.

/// Version 1 (RFC 9000). The wire constant is the version number 1, not a
/// small-integer encoding of one.
pub const QUIC_V1: u32 = 0x00000001;

/// Version 2 (RFC 9369). The wire constant is `0x6b3343cf`, ASCII "v2", and
/// is not adjacent to `QUIC_V1`: the two are independent numbers on the wire
/// and a downgrade between them is a downgrade between protocols.
pub const QUIC_V2: u32 = 0x6b3343cf; // RFC 9369

/// Every version this core accepts. `Connection` seeds its own version from
/// element 0 and sends this whole list as `version_information`'s available
/// set, so a peer supporting none of them is refused rather than connected on
/// a version this code cannot derive keys for.
pub const SUPPORTED_VERSIONS = [_]u32{ QUIC_V1, QUIC_V2 };

/// Whether `version` is in `SUPPORTED_VERSIONS`.
///
/// `version` is the raw wire value, so 0 — the Version Negotiation packet's
/// own marker (RFC 9000 §17.2) — is rejected here. A caller must answer this
/// before deriving key material from a version; nothing downstream does.
pub fn isSupportedVersion(version: u32) bool {
    for (SUPPORTED_VERSIONS) |v| {
        if (version == v) return true;
    }
    return false;
}

/// Returns true if the version uses QUIC v2 cryptographic constants.
///
/// Anything other than `QUIC_V2` — including a version not in
/// `SUPPORTED_VERSIONS` — answers as v1, so a caller that skipped
/// `isSupportedVersion` gets v1 constants rather than a diagnostic.
pub fn isV2(version: u32) bool {
    return version == QUIC_V2;
}

/// Return the appropriate HKDF label for a given version.
/// v1: "quic key", "quic iv", "quic hp", "quic ku"
/// v2: "quicv2 key", "quicv2 iv", "quicv2 hp", "quicv2 ku"
///
/// The result is a string literal in this file: static lifetime, nothing for
/// the caller to keep alive, and never invalidated. `base` names which of the
/// four TLS labels a derivation wants; `version` is not validated here, so an
/// unsupported version yields the v1 spelling — see `isV2`.
pub fn quicLabel(version: u32, comptime base: enum { key, iv, hp, ku }) []const u8 {
    return if (isV2(version)) switch (base) {
        .key => "quicv2 key",
        .iv => "quicv2 iv",
        .hp => "quicv2 hp",
        .ku => "quicv2 ku",
    } else switch (base) {
        .key => "quic key",
        .iv => "quic iv",
        .hp => "quic hp",
        .ku => "quic ku",
    };
}

const testing = @import("std").testing;

test "isSupportedVersion" {
    try testing.expect(isSupportedVersion(QUIC_V1));
    try testing.expect(isSupportedVersion(QUIC_V2));
    try testing.expect(!isSupportedVersion(0xdeadbeef));
    try testing.expect(!isSupportedVersion(0));
}

test "isV2" {
    try testing.expect(!isV2(QUIC_V1));
    try testing.expect(isV2(QUIC_V2));
}

test "quicLabel: v1 vs v2" {
    try testing.expectEqualStrings("quic key", quicLabel(QUIC_V1, .key));
    try testing.expectEqualStrings("quicv2 key", quicLabel(QUIC_V2, .key));
    try testing.expectEqualStrings("quic iv", quicLabel(QUIC_V1, .iv));
    try testing.expectEqualStrings("quicv2 hp", quicLabel(QUIC_V2, .hp));
    try testing.expectEqualStrings("quic ku", quicLabel(QUIC_V1, .ku));
}
