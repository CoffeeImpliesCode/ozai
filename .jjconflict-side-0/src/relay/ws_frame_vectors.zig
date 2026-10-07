//! The bytes the RFC 6455 tests are pinned against.
//!
//! **Test support, and nothing else.** It sits under `relay/ws_frame_types.zig`,
//! `relay/ws_frame_header.zig`, `relay/ws_frame_decode.zig` and
//! `relay/ws_frame_encode.zig` so that none of them owns a golden and none of
//! them imports another, and it imports nothing from the relay except the module
//! whose vocabulary it spells out.
//!
//! Every vector here is a worked example printed in RFC 6455 itself, not
//! captured from a peer. That is a deliberate difference from
//! `relay/frame_vectors.zig`, whose hexdumps were copied out of upstream's own
//! snapshot tests: **no bytes from n0-computer/iroh exist for the WebSocket
//! layer, because upstream frames its messages inside a library rather than in
//! a port of its own, so a claim about what an iroh peer puts on the wire under
//! RFC 6455 framing is unverified here and is not made.** What these bytes do
//! hold is the standard, which is the thing this module implements.
//!
//! The two sources are RFC 6455 section 5.7 ("Examples") and section 1.3
//! ("Opening Handshake"), whose single masked-text frame is also the key to
//! `relay/http_upgrade.zig`'s accept computation.

const std = @import("std");

/// Section 5.7's first example: a single-frame unmasked text message carrying
/// "Hello".
///
/// ```text
/// 0x81 0x05 0x48 0x65 0x6c 0x6c 0x6f
/// ```
pub const unmasked_text_hex = "81 05 48 65 6c 6c 6f";

/// Section 5.7's second example: the same text, masked under the key
/// `37 fa 21 3d`.
///
/// ```text
/// 0x81 0x85 0x37 0xfa 0x21 0x3d 0x7f 0x9f 0x4d 0x51 0x58
/// ```
///
/// The last byte is `0x6f ^ 0x37` and not `0x6f ^ 0x7f`, which is what makes
/// this vector the one that catches a key index running one-based.
pub const masked_text_hex = "81 85 37 fa 21 3d 7f 9f 4d 51 58";

/// Section 5.7's fragmented example: "Hel" in one frame with FIN clear, then
/// "lo" in a continuation with FIN set.
pub const fragment_first_hex = "01 03 48 65 6c";
pub const fragment_last_hex = "80 02 6c 6f";

/// Section 5.7's ping and pong examples, both unmasked and both carrying
/// "Hello".
pub const ping_hex = "89 05 48 65 6c 6c 6f";
pub const pong_hex = "8a 05 48 65 6c 6c 6f";

/// Section 5.7's 256-byte binary example header, the smallest length that needs
/// the sixteen-bit form.
///
/// ```text
/// 0x82 0x7E 0x0100
/// ```
pub const binary_256_header_hex = "82 7e 01 00";

/// Section 5.7's 64-KiB binary example header, the smallest length that needs the
/// sixty-four-bit form.
///
/// ```text
/// 0x82 0x7F 0x0000000000010000
/// ```
pub const binary_64k_header_hex = "82 7f 00 00 00 00 00 01 00 00";

/// The text both the text and the control examples carry.
pub const hello = "Hello";

/// Section 1.3's `Sec-WebSocket-Key` and the `Sec-WebSocket-Accept` it produces.
///
/// These are the only two strings RFC 6455 quotes in full rather than deriving,
/// which is why they are the one place a handshake test can be right without
/// recomputing it — and why `relay/http_upgrade.zig` pins its accept against
/// this pair rather than against its own output.
pub const handshake_key = "dGhlIHNhbXBsZSBub25jZQ==";
pub const handshake_accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

/// The constant RFC 6455 sections 1.3 and 4.2.2 concatenate with the client's
/// key before hashing.
pub const handshake_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// The bytes a hexdump above stands for, decoded into `out`.
///
/// The same shape as `relay/frame_vectors.zig`'s `parseHex` and kept separate
/// because that file imports `base/key.zig` to derive the node id its own dumps
/// carry, and no WebSocket vector has a node id in it.
pub fn parseHex(out: []u8, hex: []const u8) ![]const u8 {
    var clean: [64]u8 = undefined;
    var length: usize = 0;
    for (hex) |c| {
        if (std.ascii.isWhitespace(c)) continue;
        if (length == clean.len) return error.HexdumpTooLong;
        clean[length] = c;
        length += 1;
    }
    if (length % 2 != 0) return error.OddHexLength;
    return std.fmt.hexToBytes(out, clean[0..length]);
}

/// `length` bytes of a repeating pattern, written into `out`.
///
/// The section 5.7 256-byte and 64-KiB examples print a header and then a body
/// whose content is irrelevant to the example. A test that has to hold a heap
/// buffer to check a header width is paying for a vector it does not check, so
/// the body goes in storage the caller already has.
pub fn fillPattern(out: []u8) void {
    const pattern = "0123456789abcdef";
    for (out, 0..) |*byte, index| byte.* = pattern[index % pattern.len];
}
