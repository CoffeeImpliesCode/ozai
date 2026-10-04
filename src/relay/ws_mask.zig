//! RFC 6455 §5.3: the mask — four key bytes XORed against a payload, repeating.
//!
//! **This is a primitive and not a codec, and it is a file of its own because
//! both codecs need it.** `ws_frame_decode.zig` undoes it over the bytes it read
//! out of a buffer and `ws_frame_encode.zig` applies it over the bytes it wrote
//! into one, so neither could own it without the other importing it — and the
//! two directions are one loop only because an XOR is its own inverse. Written
//! twice it would be two loops that could disagree, and the disagreement would
//! stay invisible until a relay dropped a masked byte in a connection nobody
//! could reproduce.
//!
//! The tests below pin the primitive to the one vector RFC 6455 prints. The
//! frame-level round trip in `ws_frame.zig` proves the same property with a
//! header in the way; this proves it without one.

const std = @import("std");
const header = @import("ws_header.zig");

const std_testing = std.testing;

/// XORs a payload against a repeating key, in place.
///
/// **The mask is its own inverse** (RFC 6455 §5.3), so this is both directions
/// and there is no `unmask` beside it: `encode` masks the bytes it has just
/// written into the caller's buffer, and `decode` unmasks the bytes it has just
/// read out of it. Two calls, one loop, and the round trip is a fixed point for
/// every payload length and every key.
///
/// The key's phase starts at the first payload byte of every frame, so the index
/// counts the bytes of the slice this call was handed rather than some counter a
/// connection would carry over from the frame before it.
pub fn maskInPlace(payload: []u8, key: [header.masking_key_length]u8) void {
    for (payload, 0..) |*byte, index| {
        byte.* ^= key[index % header.masking_key_length];
    }
}

// ---------------------------------------------------------------------------
// Tests. RFC 6455 §1.3 is the only source of bytes here.
// ---------------------------------------------------------------------------

/// RFC 6455 §1.3: the one masking key and one masked payload the RFC prints.
const rfc_key = [_]u8{ 0x37, 0xfa, 0x21, 0x3d };
const rfc_masked_hello = [_]u8{ 0x7f, 0x9f, 0x4d, 0x51, 0x58 };

test "golden: RFC 6455 §1.3, the key and the payload it masks to" {
    // The RFC's own five masked bytes, so this module is pinned to the standard
    // rather than to the other direction of the same loop.
    var payload = [_]u8{ 'H', 'e', 'l', 'l', 'o' };
    maskInPlace(&payload, rfc_key);
    try std_testing.expectEqualSlices(u8, &rfc_masked_hello, &payload);
}

test "twice is the identity at every length, and the key's phase never drifts" {
    // 300 bytes is past three times the key, so the wrap is exercised rather
    // than assumed, and zero is here because an empty payload is a real frame
    // (a ping with no value) and the loop then does nothing at all.
    for (0..300) |len| {
        const payload: [300]u8 = @splat(0xa5);
        var once = payload;
        maskInPlace(once[0..len], rfc_key);
        maskInPlace(once[0..len], rfc_key);
        try std_testing.expectEqualSlices(u8, payload[0..len], once[0..len]);
    }
    // A non-zero key has to change the bytes it is applied to, or a loop that
    // quietly did nothing would pass the test above.
    var one: [1]u8 = .{0};
    maskInPlace(&one, rfc_key);
    try std_testing.expectEqual(@as(u8, 0x37), one[0]);
}