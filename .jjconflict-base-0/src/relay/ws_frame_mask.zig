//! The masking transform of RFC 6455 section 5.3, in both directions.
//!
//! One transform and not two: the mask is its own inverse, so applying it to
//! bytes that are already masked unmaskes them. `relay/ws_frame_encode.zig`
//! applies it to the payload it has just written and `relay/ws_frame_decode.zig`
//! applies it to the payload it has just read, and neither direction is a
//! different function.
//!
//! RFC 6455 section 5.3 defines the transform as XOR with a four-byte key taken
//! modulo four over the payload:
//!
//! ```text
//! transformed[i] = original[i] XOR key[i mod 4]
//! ```
//!
//! Two facts about it are worth writing down because they are what the tests
//! hold it to. It is its own inverse, so `apply` twice is the identity; and the
//! key repeats every four bytes, so a payload whose length is a multiple of
//! four is the case where an index that ran one-based shows up — it produces a
//! payload whose last byte is wrong rather than one that is the wrong length.
//!
//! Nothing here allocates, reads a clock, or reaches for a global, and it
//! touches only the bytes it is given.

const std = @import("std");
const ws_frame_types = @import("ws_frame_types.zig");

const MaskKey = ws_frame_types.MaskKey;
const mask_key_length = ws_frame_types.mask_key_length;

const std_testing = std.testing;

/// Applies `key` to `bytes` in place. Applying it twice is the identity.
///
/// **The mask is a permutation of every byte, so this cannot fail.** It has no
/// length it can overflow, nothing to bounds-check beyond the slice it was
/// handed, and no error a caller could do anything about; that is why it is
/// `void` where `relay/frame_writer.zig`'s `write` is `error.BufferFull`.
///
/// The key index wraps on four, so the loop walks with a counter rather than
/// indexing modulo the payload length — a modulo by a payload length the caller
/// may have made zero is a divide by zero in a path with no business having
/// one, and the counter cannot be anything but zero to three.
pub fn apply(key: MaskKey, bytes: []u8) void {
    var index: usize = 0;
    for (bytes) |*byte| {
        byte.* ^= key[index];
        index = (index + 1) % mask_key_length;
    }
}

/// `src` masked with `key` into `out`, as the slice of `out` that holds it.
///
/// **A copy, because decoding never mutates the buffer it was handed.**
/// `relay/frame_decode.zig` borrows the caller's message bytes and promises
/// that nothing here changes them; a caller that decoded from a ring slot and
/// then unmasked in place would have broken that promise for every frame still
/// held from the last message.
///
/// `out` must be at least `src.len` bytes and is left untouched when it is not.
/// The refusal is `error.BufferFull`, the name `relay/frame_writer.zig` already
/// uses for a write that did not fit, because it is the same fact about the
/// same kind of buffer: the caller's storage, not the frame's legality. No
/// partial unmask is written, so a caller that retries with a larger buffer
/// starts from the payload it still has.
pub fn copy(key: MaskKey, src: []const u8, out: []u8) error{BufferFull}![]const u8 {
    if (out.len < src.len) return error.BufferFull;
    @memcpy(out[0..src.len], src);
    apply(key, out[0..src.len]);
    return out[0..src.len];
}

// --- tests

test "mask: the RFC 6455 section 5.7 masked example, in place and copied" {
    // RFC 6455 section 5.7's single-frame masked text message:
    //
    //   0x81 0x85 0x37 0xfa 0x21 0x3d 0x7f 0x9f 0x4d 0x51 0x58
    //
    // is "Hello" under the key 37 fa 21 3d. The last byte is the one that
    // catches a key index running one-based: 0x6f XOR 0x37 is 0x58, and only
    // because the key wraps on four.
    const key = ws_frame_types.fixedMaskKey();
    try std_testing.expectEqualSlices(u8, &.{ 0x37, 0xfa, 0x21, 0x3d }, &key);

    const hello = [_]u8{ 0x48, 0x65, 0x6c, 0x6c, 0x6f };
    var in_place = hello;
    apply(key, &in_place);
    try std_testing.expectEqualSlices(u8, &.{ 0x7f, 0x9f, 0x4d, 0x51, 0x58 }, &in_place);

    var copied: [hello.len]u8 = undefined;
    const written = try copy(key, &hello, &copied);
    try std_testing.expectEqualSlices(u8, &in_place, written);

    // And applying it a second time is the identity, which is the whole reason
    // this is one function rather than two.
    apply(key, &in_place);
    try std_testing.expectEqualSlices(u8, &hello, &in_place);
}

test "mask: a sweep of lengths, a zero key, and two keys that disagree" {
    // Every length from zero to three times the key, because the index wraps on
    // four and a bug there only shows on a payload that crosses a boundary.
    const key = ws_frame_types.fixedMaskKey();
    const other_key = MaskKey{ 0x12, 0x34, 0x56, 0x78 };
    var payload: [3 * mask_key_length]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @truncate(index *% 7 +% 3);

    for (0..payload.len + 1) |length| {
        const original = payload[0..length];
        var round_trip: [payload.len]u8 = undefined;
        @memcpy(round_trip[0..length], original);
        apply(key, round_trip[0..length]);
        // A bijection under one key is the identity under that key, and under
        // another key it is the payload XOR the two keys — so a transform that
        // leaked a byte of the index is caught here and not only by the RFC
        // example above, which has one payload of one length.
        var cross: [payload.len]u8 = undefined;
        @memcpy(cross[0..length], original);
        apply(other_key, cross[0..length]);
        apply(key, cross[0..length]);
        for (original, 0..) |byte, index| {
            const expected = byte ^ key[index % mask_key_length] ^
                other_key[index % mask_key_length];
            try std_testing.expectEqual(expected, cross[index]);
        }
        apply(key, round_trip[0..length]);
        try std_testing.expectEqualSlices(u8, original, round_trip[0..length]);
    }

    // A zero key leaves every byte alone, which is what makes a payload masked
    // under one indistinguishable from an unmasked one and is why the mask bit
    // rather than the key is what a role is checked against.
    var untouched: [mask_key_length]u8 = undefined;
    @memcpy(&untouched, payload[0..mask_key_length]);
    const before = untouched;
    apply(.{ 0, 0, 0, 0 }, &untouched);
    try std_testing.expectEqualSlices(u8, &before, &untouched);

    // An empty payload is a payload, and masking it is a no-op rather than a
    // divide by zero: the key index is never read.
    var none: [0]u8 = .{};
    apply(key, &none);
}

test "mask: copy refuses a short buffer and writes nothing" {
    const key = ws_frame_types.fixedMaskKey();
    var out: [4]u8 = undefined;
    @memset(&out, 0xaa);
    try std_testing.expectError(error.BufferFull, copy(key, &.{ 1, 2, 3, 4, 5 }, &out));
    for (out) |byte| try std_testing.expectEqual(@as(u8, 0xaa), byte);
    try std_testing.expectError(error.BufferFull, copy(key, &.{1}, &.{}));
    // And nothing to copy is nothing that will not fit, which is the same rule
    // read from the other side.
    try std_testing.expectEqual(@as(usize, 0), (try copy(key, &.{}, &.{})).len);
    // An exactly-sized buffer is not a short one.
    var exact: [5]u8 = undefined;
    try std_testing.expectEqual(@as(usize, 5), (try copy(key, &.{ 1, 2, 3, 4, 5 }, &exact)).len);
}
