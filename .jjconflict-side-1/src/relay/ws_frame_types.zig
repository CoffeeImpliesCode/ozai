//! The vocabulary an RFC 6455 frame is written and read in: the opcodes, which
//! end of a connection is speaking, the header as a value, and the two size
//! limits that are not the same number.
//!
//! This file is the layer `relay/ws_frame.zig` re-exports. The header codec is
//! `relay/ws_frame_header.zig`, the masking transform is
//! `relay/ws_frame_mask.zig`, the two directions are
//! `relay/ws_frame_decode.zig` and `relay/ws_frame_encode.zig`, and the
//! RFC 6455 goldens every test here is pinned against are
//! `relay/ws_frame_vectors.zig`.
//!
//! # This is the layer upstream's `MAX_FRAME_SIZE` applies to
//!
//! `relay/frame_types.zig` says in so many words that nothing in that codec
//! reads `max_frame_size` and names this one as the place it is used:
//! upstream needs it where a frame is framed — the WebSocket read — and
//! `relay/frame_decode.zig` measures the payload of one message instead. So
//! `max_frame_size` is re-exported here unchanged and it bounds the payload of
//! one WebSocket frame, which is one relay message.
//!
//! # A frame that is too large and a buffer that is too small
//!
//! **These are two different questions and they have two different answers.**
//!
//! `error.FrameTooLarge` is the claim that the frame itself cannot exist here:
//! its payload is over `max_frame_size`, and no buffer would have held it. It is
//! decided from the length alone, before anything is written, and it leaves the
//! caller's buffer untouched.
//!
//! `error.BufferFull` is the claim that the caller's buffer is too small for a
//! frame that is entirely legal. **A payload of exactly `max_frame_size` is
//! `error.BufferFull`, never `error.FrameTooLarge`:** the frame is the biggest
//! one this module admits, so a buffer that cannot take it is the buffer's
//! fault. A caller that sized a buffer below `max_frame_size + max_header_length`
//! has not made an illegal frame, it has made a small buffer, and the two
//! answers must not be confused — one is refused by the protocol and the other
//! by the caller.
//!
//! Nothing here reads a clock, opens a socket, or reaches for a global, and
//! nothing allocates.

const std = @import("std");
const frame_types = @import("frame_types.zig");

/// Every way an RFC 6455 frame can be refused.
///
/// The first two are the header's own rules, the third is the mask bit against
/// the end that sent the frame, and the last two are the two size answers the
/// header comment above separates.
pub const Error = error{
    /// The frame ran out before the header it declared was fully behind it.
    UnexpectedEnd,
    /// One of RSV1, RSV2 or RSV3 was set. No extension was negotiated, so a
    /// reserved bit is a peer speaking a dialect this build has not agreed to.
    ReservedBitSet,
    /// The opcode is not one of the six RFC 6455 defines. The three reserved
    /// opcodes and everything above `0xa` are named rather than defaulted: a
    /// decoder that invented an arm would read that peer as one it knows.
    UnknownOpcode,
    /// A control frame declared a length of 126 or 127, so it used an extended
    /// length field. RFC 6455 section 5.5 gives a control frame a 125-byte
    /// ceiling, and the seven-bit field says that on its own: 126 and 127 are
    /// both over it, so this is refused from the first two bytes and the
    /// extended length behind them is never read.
    ControlFrameTooLong,
    /// A control frame did not set FIN. RFC 6455 section 5.5: control frames
    /// must not be fragmented, and a fragmented one has no meaning a message
    /// assembler could act on.
    FragmentedControlFrame,
    /// The payload length was spelled in a wider field than it needed. RFC 6455
    /// section 5.2 requires the minimal number of bytes, and one value in one
    /// header is not two headers.
    NonMinimalLength,
    /// The most significant bit of a 64-bit extended payload length was set.
    /// RFC 6455 section 5.2 requires it to be zero, and this build has no use
    /// for a length of two to the sixty-third power.
    ReservedLengthBit,
    /// The peer is a client and did not mask the frame. RFC 6455 section 5.1.
    UnmaskedClientFrame,
    /// The peer is a server and masked the frame. RFC 6455 section 5.1.
    MaskedServerFrame,
    /// The payload is over `max_frame_size`, so the frame cannot exist here.
    /// See the header comment: this is not the same claim as `BufferFull`.
    FrameTooLarge,
    /// The caller's buffer could not hold a frame that is legal. See the header
    /// comment: this is not the same claim as `FrameTooLarge`, and a payload at
    /// exactly `max_frame_size` is refused here rather than above.
    BufferFull,
};

/// The four bytes of a masking key. RFC 6455 section 5.3.
pub const mask_key_length: usize = 4;

/// A masking key as a type rather than as four bytes in a row, so a signature
/// cannot take a payload length where it means a key.
pub const MaskKey = [mask_key_length]u8;

/// The most bytes a control frame may carry. RFC 6455 section 5.5.
pub const max_control_payload = 125;

/// The largest payload one WebSocket frame may carry here, which is upstream's
/// `MAX_FRAME_SIZE` (`relay.rs:29`).
///
/// Re-exported from `relay/frame_types.zig` because that file names this one as
/// its reader and holds the reasoning for the number. `relay/frame_decode.zig`
/// bounds a relay message by `max_packet_size` instead, which is a smaller
/// number about a different thing, and the two are deliberately not unified.
pub const max_frame_size: usize = frame_types.max_frame_size;

/// The most bytes a header may occupy with no payload: eight for a 64-bit
/// length, plus the first two bytes and a four-byte mask key.
pub const max_header_length: usize = 2 + 8 + mask_key_length;

/// The fewest bytes a header may occupy: a seven-bit length and no mask key.
pub const min_header_length: usize = 2;

/// The four RFC 6455 section 5.2 opcodes a peer may send, as the six values it
/// defines.
///
/// `continuation` is `0x0`, `text` `0x1`, `binary` `0x2`, and the three control
/// opcodes are `0x8`, `0x9` and `0xa`. The three reserved values `0x3` through
/// `0x7` and everything from `0xb` up are `error.UnknownOpcode`, so this is an
/// exhaustive table of what a peer may send rather than a range that happens to
/// be checked.
pub const Opcode = enum(u8) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xa,

    /// The opcode a byte names, or null for one RFC 6455 does not define.
    pub fn fromInt(value: u8) ?Opcode {
        return std.enums.fromInt(Opcode, value);
    }

    /// The byte, which is the discriminant itself.
    pub fn toInt(self: Opcode) u8 {
        return @intFromEnum(self);
    }

    /// Whether this is a control opcode, which RFC 6455 section 5.5 defines as
    /// the top of the four-bit field: `0x8` and above.
    ///
    /// The test is on the value rather than on a table of the three, because
    /// the rule the section states is the range and a new control opcode added
    /// to the enum would then be a control opcode by the section's own words.
    pub fn isControl(self: Opcode) bool {
        return @intFromEnum(self) >= 0x8;
    }
};

/// Which end of the connection this module is decoding for or encoding as.
///
/// **The value names this end, not the peer.** `.server` is a relay reading a
/// client's frames, and RFC 6455 section 5.1 makes those the frames that must
/// be masked; `.client` is a node reading a relay's, and those are the frames
/// that must not be. The mask bit is the only difference, and it is the whole
/// of the difference, so the two rules are two arms of one switch.
pub const Role = enum {
    server,
    client,
};

/// One frame's header, read out of the bytes or handed to the writer.
///
/// **A value, and nothing in it borrows.** `header_length` is carried rather
/// than recomputed so that a decoded frame can name its own payload without
/// re-deriving where the header ended, and `mask_key` is meaningful only when
/// `masked` is set — a zero key is not an absence, so nothing reads it then.
pub const Frame = struct {
    /// The FIN bit. A frame with FIN clear is one fragment of a message.
    fin: bool,
    opcode: Opcode,
    /// Whether the payload is masked, which is decided by the sender's role.
    masked: bool,
    /// The payload length the header declares, before any masking.
    payload_length: u64,
    /// The four-byte key, meaningful only when `masked`.
    mask_key: MaskKey,
    /// How many bytes the header occupies, the mask key included.
    header_length: usize,
};

/// A header with `header_length` derived from the rest, so the field and the
/// width it names cannot disagree.
///
/// The alternative is a caller filling six of the seven fields and computing the
/// seventh, and `headerLen` is the only rule for it — so it is applied here,
/// once, rather than asked of every writer.
pub fn header(
    fin: bool,
    opcode: Opcode,
    masked: bool,
    payload_length: u64,
    mask_key: MaskKey,
) Frame {
    return .{
        .fin = fin,
        .opcode = opcode,
        .masked = masked,
        .payload_length = payload_length,
        .mask_key = mask_key,
        .header_length = headerLen(payload_length, masked),
    };
}

/// How many bytes the header of a `payload_length`-byte frame occupies.
///
/// The width is fixed by the value and by nothing else, so this is the number a
/// caller sizes `max_frame_size` plus for: the widest header is
/// `max_header_length`, which is the mask key on top of a 64-bit length.
///
/// **It is not a limit.** A length over `max_frame_size` gets its header width
/// computed here and is then refused by the size rule, which is a different
/// answer from a buffer that cannot hold a legal frame's header.
pub fn headerLen(payload_length: u64, masked: bool) usize {
    const extended: usize = if (payload_length <= max_control_payload)
        0
    else if (payload_length <= 0xffff)
        2
    else
        8;
    return min_header_length + extended + if (masked) mask_key_length else 0;
}

/// The masking key a test or a deterministic peer writes with.
///
/// **Not a key and not a source of randomness.** A client masks with a key from
/// a cryptographic RNG, and the value is the caller's argument to `encode`;
/// this is the reproducible stand-in the tests and the RFC 6455 section 5.7
/// goldens need, and it is named so that no production call site can reach for
/// it by accident while believing it is drawing.
pub fn fixedMaskKey() MaskKey {
    return .{ 0x37, 0xfa, 0x21, 0x3d };
}
