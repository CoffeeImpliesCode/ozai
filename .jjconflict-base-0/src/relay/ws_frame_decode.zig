//! One RFC 6455 frame read out of a buffer, with the mask bit checked against
//! the end that is reading.
//!
//! `relay/ws_frame_header.zig` reads the header and holds every rule that is
//! about the bytes; this file is the one rule that is about the two ends
//! instead, and the slice of the caller's buffer that the payload occupies.
//!
//! # The role is an argument and not a global
//!
//! RFC 6455 section 5.1 says a server must close the connection on an unmasked
//! frame from a client and a client must close it on a masked frame from a
//! server. Which of the two applies is a fact about the connection, not about
//! the codec, so it arrives as `Role` and nothing here reads a global to decide
//! it. A relay and a node run the same code against the same bytes and get
//! opposite answers, which is the point.
//!
//! **The check is on the mask bit and not on the key.** A key of four zero bytes
//! masks a payload to itself, so a peer could send an unmasked frame with the
//! bit set and a zero key; the bit is the declaration and the key is the
//! transform, and only the declaration is a rule.
//!
//! # What comes back is the caller's own storage
//!
//! `Decoded.payload` is a slice of the buffer `decode` was handed, and it is
//! **still masked** when the frame is a masked one: unmasking in place would
//! change bytes every other `Decoded` borrowed from the same message buffer
//! still names. `relay/ws_frame_mask.zig`'s `copy` is the way to have the
//! plaintext, and the caller owns that buffer too. Nothing here allocates, and
//! nothing is retained after it returns.
//!
//! A frame is not a message. RFC 6455 section 5.4 lets a message be several
//! frames, so `fin` and `opcode` are on the result and the reassembly that turns
//! fragments into one message belongs to the transport above this, which is
//! also where the rule that a continuation carries no opcode of its own lives.

const ws_frame_header = @import("ws_frame_header.zig");
const ws_frame_types = @import("ws_frame_types.zig");

const Error = ws_frame_types.Error;
const Frame = ws_frame_types.Frame;
const Role = ws_frame_types.Role;

/// One frame: its header, and where its payload is.
pub const Decoded = struct {
    /// The header, as `relay/ws_frame_header.zig` read it.
    frame: Frame,
    /// The payload, borrowed from the buffer `decode` was handed, still masked
    /// when the frame was a masked one.
    payload: []const u8,
};

/// Reads the first frame in `bytes` as the end named by `role`.
///
/// `bytes` must hold the whole frame. A header that declares a payload longer
/// than what is behind it is `error.UnexpectedEnd` and not a short frame with
/// more to come, because a caller cannot tell a truncated frame from a peer that
/// stopped sending without deciding what a partial frame means, and that
/// decision is above this layer.
///
/// **`error.UnmaskedClientFrame` and `error.MaskedServerFrame` come after the
/// header is read and before the payload is measured**, so a peer that sends an
/// unmasked frame with nothing behind it is told about the mask rather than
/// about the missing payload: the mask is the rule it broke first.
pub fn decode(bytes: []const u8, role: Role) Error!Decoded {
    const frame = try ws_frame_header.read(bytes);
    switch (role) {
        .server => if (!frame.masked) return error.UnmaskedClientFrame,
        .client => if (frame.masked) return error.MaskedServerFrame,
    }
    const payload_length: usize = @intCast(frame.payload_length);
    const end = frame.header_length + payload_length;
    if (bytes.len < end) return error.UnexpectedEnd;
    return .{ .frame = frame, .payload = bytes[frame.header_length..end] };
}
