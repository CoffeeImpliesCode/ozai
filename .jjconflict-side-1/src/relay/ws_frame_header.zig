//! The RFC 6455 section 5.2 header, read out of bytes and written back into a
//! caller's buffer.
//!
//! The header is two bytes plus up to ten more, and it says five things: FIN,
//! three reserved bits, a four-bit opcode, the mask bit, and a payload length in
//! one of three widths. `relay/ws_frame_types.zig` holds the vocabulary and its
//! `headerLen` is the one place the width is derived; this file holds the order
//! the fields are checked in, which is the part a peer can attack.
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-------+-+-------------+-------------------------------+
//! |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
//! |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
//! |N|V|V|V|       |S|             |   (if payload len==126/127)   |
//! +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
//! ```
//!
//! # The order the checks run in is the contract
//!
//! **A header is refused for the first rule it breaks, in the order RFC 6455
//! gives them, and the width rules come before the size rule.** Every one is
//! decided from the bytes already in hand, so a header that breaks two is
//! answered by the earlier one and the caller never learns what the later one
//! would have said.
//!
//! The pair that matters most is last. A length spelled in a wider field than it
//! needs is `error.NonMinimalLength`, and a length with its top bit set is
//! `error.ReservedLengthBit`; **both are refused before `error.FrameTooLarge` is
//! considered, because both are claims about how the header was written rather
//! than about how big the frame is.** A peer that spells five bytes in a 64-bit
//! field, or a length of two to the sixty-third power, is told its header is
//! malformed and not that its frame is large — and it is told that before the
//! payload is asked for, so a header claiming a gigabyte with none behind it
//! gets the same answer as one that supplies it.
//!
//! The control-frame rules come before the width rules and are decided from the
//! first two bytes alone: a control opcode with a seven-bit length of 126 or 127
//! is `error.ControlFrameTooLong`, because both are over the 125 ceiling and the
//! extended length behind them is therefore never read; and a control frame with
//! FIN clear is `error.FragmentedControlFrame`, because the section forbids a
//! fragmented control frame outright.
//!
//! The mask bit is not checked here. It says what a frame is, not whether the
//! sender was allowed to say it, and that question belongs to the role — which
//! `relay/ws_frame_decode.zig` supplies and this file does not know.
//!
//! Nothing here allocates, reads a clock, or reaches for a global.

const std = @import("std");
const ws_frame_types = @import("ws_frame_types.zig");

const Error = ws_frame_types.Error;
const Frame = ws_frame_types.Frame;
const MaskKey = ws_frame_types.MaskKey;
const Opcode = ws_frame_types.Opcode;
const headerLen = ws_frame_types.headerLen;
const mask_key_length = ws_frame_types.mask_key_length;
const min_header_length = ws_frame_types.min_header_length;

/// The seven-bit length field value that means a 16-bit length follows, and the
/// smallest payload that length can spell: below this a wider field is not
/// minimal.
const length_16_bit: u64 = 126;
/// The seven-bit length field value that means a 64-bit length follows.
const length_64_bit: u64 = 127;
/// The largest payload the seven-bit field spells directly, and the control
/// frame ceiling, as the length type rather than the field type.
const length_7_bit_max: u64 = ws_frame_types.max_control_payload;
/// `max_frame_size` as a length, so the size rule compares two of a kind.
const max_frame_size: u64 = ws_frame_types.max_frame_size;

/// Reads one frame header from the start of `bytes`.
///
/// **Every refusal is `Error`, and every one is decided from the bytes the
/// header itself carries** — never from a payload behind it and never from a
/// buffer size the caller passed. The header is `header_length` bytes long and
/// the caller slices the payload from there; nothing is copied and nothing is
/// allocated, so the result borrows nothing and `bytes` may be reused the moment
/// the caller is done with the payload.
///
/// Bytes past the header are this function's business only in that a header
/// longer than `bytes` is `error.UnexpectedEnd`; what follows the frame it names
/// is the caller's.
pub fn read(bytes: []const u8) Error!Frame {
    if (bytes.len < min_header_length) return error.UnexpectedEnd;
    const first = bytes[0];
    const second = bytes[1];

    // The reserved bits first. RSV1 through RSV3 each mean "an extension
    // changed the meaning of this payload", and no extension was negotiated, so
    // a set one is a peer speaking a dialect this build has not agreed to.
    if ((first & 0b0111_0000) != 0) return error.ReservedBitSet;

    const opcode = Opcode.fromInt(first & 0b0000_1111) orelse
        return error.UnknownOpcode;

    // The two control rules, decided from the first two bytes. A control
    // frame's length is in the seven-bit field or it is over the ceiling
    // already, so there is no extended length to read before refusing it.
    if (opcode.isControl()) {
        if (@as(u64, second & 0b0111_1111) >= length_16_bit) {
            return error.ControlFrameTooLong;
        }
        if ((first & 0b1000_0000) == 0) return error.FragmentedControlFrame;
    }

    const masked = (second & 0b1000_0000) != 0;
    const payload_length = try readLength(bytes, second & 0b0111_1111);
    const header_length = headerLen(payload_length, masked);
    if (bytes.len < header_length) return error.UnexpectedEnd;

    // The size rule last. Everything above it is a claim about the bytes, and
    // this is the only claim about this relay: a payload over `max_frame_size`
    // is a frame that cannot exist here whatever buffer the caller holds. It is
    // a different answer from `error.BufferFull`, which is the caller's storage,
    // and a payload at exactly `max_frame_size` is that and not this.
    if (payload_length > max_frame_size) return error.FrameTooLarge;

    var mask_key: MaskKey = @splat(0);
    if (masked) {
        const at = header_length - mask_key_length;
        @memcpy(&mask_key, bytes[at..][0..mask_key_length]);
    }
    return .{
        .fin = (first & 0b1000_0000) != 0,
        .opcode = opcode,
        .masked = masked,
        .payload_length = payload_length,
        .mask_key = mask_key,
        .header_length = header_length,
    };
}

/// The payload length the seven-bit field and the bytes behind it spell, with
/// the two width rules applied before anything else may look at the value.
fn readLength(bytes: []const u8, short: u8) Error!u64 {
    if (@as(u64, short) < length_16_bit) return short;
    if (@as(u64, short) == length_16_bit) {
        if (bytes.len < 4) return error.UnexpectedEnd;
        const length = std.mem.readInt(u16, bytes[2..4], .big);
        // A 16-bit length exists to spell a length a seven-bit field cannot,
        // so one below 126 is the same length spelled two ways. Refused here,
        // before the size rule sees it.
        if (length < length_16_bit) return error.NonMinimalLength;
        return length;
    }
    if (bytes.len < 10) return error.UnexpectedEnd;
    const length = std.mem.readInt(u64, bytes[2..10], .big);
    // The top bit must be zero (RFC 6455 section 5.2), and what is left still
    // has to need sixty-four bits to be spelled in eight.
    if (length & (@as(u64, 1) << 63) != 0) return error.ReservedLengthBit;
    if (length <= 0xffff) return error.NonMinimalLength;
    return length;
}

/// Writes `header` into the front of `out`, and how many bytes that took.
///
/// `out` is the caller's buffer and is never grown: a header that does not fit
/// is `error.BufferFull`. `relay/ws_frame_encode.zig` writes a whole frame
/// through this and holds the frame's size rules; this function is the two to
/// fourteen bytes at the front of one.
///
/// **The width is derived from the length and never taken from the header**, so
/// a header this wrote cannot be refused by `read` with
/// `error.NonMinimalLength`. That fixed point is why `header.header_length` is
/// recomputed rather than trusted: a caller that filled the field in by hand
/// gets the width its length needs, not the one it wrote down.
pub fn write(out: []u8, header: Frame) Error!usize {
    const payload_length = header.payload_length;
    const header_length = headerLen(payload_length, header.masked);
    if (out.len < header_length) return error.BufferFull;

    out[0] = (if (header.fin) @as(u8, 0b1000_0000) else 0) |
        (header.opcode.toInt() & 0b0000_1111);
    const spelled: u64 = if (payload_length <= length_7_bit_max)
        payload_length
    else if (payload_length <= 0xffff)
        length_16_bit
    else
        length_64_bit;
    out[1] = (if (header.masked) @as(u8, 0b1000_0000) else 0) | @as(u8, @intCast(spelled));

    const extended_length = header_length - min_header_length -
        (if (header.masked) mask_key_length else 0);
    if (extended_length == 2) {
        std.mem.writeInt(u16, out[2..4], @intCast(payload_length), .big);
    } else if (extended_length == 8) {
        std.mem.writeInt(u64, out[2..10], payload_length, .big);
    }
    if (header.masked) {
        @memcpy(
            out[header_length - mask_key_length ..][0..mask_key_length],
            &header.mask_key,
        );
    }
    return header_length;
}
