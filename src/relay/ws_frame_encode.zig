//! One RFC 6455 frame written into a buffer the caller owns.
//!
//! `relay/ws_frame_header.zig` writes the two to fourteen bytes at the front of
//! a frame and `relay/ws_frame_mask.zig` is the transform; this file is the two
//! rules about the frame as a whole and the append that joins them.
//!
//! # Every rule is decided before a byte is written
//!
//! A frame is refused for being over `max_frame_size`, for a control frame's
//! 125-byte ceiling, or for being a fragmented control frame, and **all three
//! are decided from the payload and the header the caller handed over, before
//! the writer exists**, so a refusal leaves `out` exactly as the caller passed
//! it. This is the rule `relay/frame_encode.zig` follows and for the same
//! reason: a caller that kept a partial header and lost the payload has bytes in
//! its buffer that no peer can read and this module cannot identify.
//!
//! # A frame that is too large and a buffer that is too small
//!
//! **These are two different questions and this module answers them with two
//! different errors, and which one a caller gets is the whole of the contract.**
//!
//! - `error.FrameTooLarge` says the frame cannot exist here. The payload is over
//!   `max_frame_size`, so no buffer would have held it, and it is decided before
//!   anything is written.
//! - `error.BufferFull` says the caller's buffer is too small for a frame that is
//!   entirely legal. **A payload of exactly `max_frame_size` is
//!   `error.BufferFull`**: it is the largest payload this module admits, so a
//!   buffer that cannot take it is short, and a caller that sized a buffer below
//!   `encodedLen(max_frame_size, .client)` has made a small buffer rather than an
//!   illegal frame. The two must never be confused, because one of them is the
//!   protocol refusing and the other is the caller.
//!
//! `error.BufferFull` leaves a partial frame in `out` — the header, and whatever
//! of the payload fitted — because it is found once bytes are down, the same as
//! `relay/frame_writer.zig`'s refusal. No error hands back a slice, so a caller
//! must discard `out` on any error rather than write what happens to be in it.
//!
//! Nothing here allocates, reads a clock, or reaches for a global.

const ws_frame_header = @import("ws_frame_header.zig");
const ws_frame_mask = @import("ws_frame_mask.zig");
const ws_frame_types = @import("ws_frame_types.zig");

const Error = ws_frame_types.Error;
const MaskKey = ws_frame_types.MaskKey;
const Opcode = ws_frame_types.Opcode;
const Role = ws_frame_types.Role;
const max_control_payload = ws_frame_types.max_control_payload;
const max_frame_size = ws_frame_types.max_frame_size;

/// What a caller asks to be written: the header bits, and the key a client
/// masks with.
///
/// **The role decides whether `key` is used at all.** RFC 6455 section 5.1 makes
/// the mask a client obligation, so `encode` masks for `.client` and not for
/// `.server` whatever `key` holds: the rule belongs to the connection rather
/// than to the caller's key, and a relay cannot be talked into masking by passing
/// one.
pub const Outgoing = struct {
    /// The FIN bit. A relay sends one message per frame, so this is true nearly
    /// always; it is false only for a caller deliberately emitting a fragment,
    /// which is what the RFC 6455 section 5.7 fragmented examples are.
    fin: bool,
    opcode: Opcode,
    /// The masking key, read only when `role` is `.client`.
    key: MaskKey,
};

/// How many bytes `encode` writes for a `payload_length`-byte frame as `role`.
///
/// A size a caller sizes a buffer from, and exact for every payload the other
/// rules admit. `encodedLen(max_frame_size, .client)` is the bound a caller that
/// never wants `error.BufferFull` should size one at.
///
/// **It is a lower bound for a payload the rules refuse.** A control frame over
/// the 125-byte ceiling and a payload over `max_frame_size` are both counted
/// here at their full width and refused afterwards, so a caller may treat this as
/// the number a buffer must hold even for a frame that will not be written.
pub fn encodedLen(payload_length: usize, role: Role) usize {
    const length: u64 = @intCast(payload_length);
    return ws_frame_types.headerLen(length, role == .client) + payload_length;
}

///
/// `out` is the caller's buffer and is never grown. The three refusals that leave
/// it untouched — `error.FrameTooLarge`, `error.ControlFrameTooLong` and
/// `error.FragmentedControlFrame` — are decided before the writer exists; see
/// the file comment for how `error.BufferFull` differs from them.
///
/// **What it borrows and what it keeps.** `payload` is read and copied, and
/// nothing in the result refers to it, so the caller's buffer may be reused the
/// moment this returns. The slice handed back is `out[0..written]` — the same
/// memory rather than a copy of it — so it aliases `out` and is invalidated by
/// whatever the caller writes there next.
pub fn encode(
    out: []u8,
    role: Role,
    outgoing: Outgoing,
    payload: []const u8,
) Error![]const u8 {
    try checkEncodable(outgoing, payload);
    const masked = role == .client;
    const header = ws_frame_types.header(
        outgoing.fin,
        outgoing.opcode,
        masked,
        payload.len,
        // A key is a client obligation, so a server's frame carries a zero one
        // that nothing reads: the mask bit is the declaration a peer checks.
        if (masked) outgoing.key else @splat(0),
    );
    const header_length = try ws_frame_header.write(out, header);
    // `BufferFull` is found once bytes are down, so what is written is what
    // fitted: the header, and as much of the payload as `out` still had room
    // for. An unchecked copy here would index past a short buffer instead of
    // refusing it.
    const written = @min(out.len - header_length, payload.len);
    @memcpy(out[header_length..][0..written], payload[0..written]);
    // A client's frames are masked on the wire, so the bytes just written are
    // the ones that carry it. Unmasking them here would put plain text on the
    // wire and make this a codec that does not read back what it emits.
    if (masked) ws_frame_mask.apply(header.mask_key, out[header_length..][0..written]);
    if (written < payload.len) return error.BufferFull;
    return out[0 .. header_length + payload.len];
}

/// Every rule a frame has to meet, checked before a byte of it is written.
///
/// Three refusals, in this order, each naming the first thing wrong with the
/// frame rather than whatever else also is. The order between the first two is
/// the contract: a control frame over the 125-byte ceiling is
/// `error.ControlFrameTooLong` even when its payload is also over
/// `max_frame_size`, because the ceiling is the rule about what a control frame
/// is and the size rule is about how much any frame may be.
fn checkEncodable(outgoing: Outgoing, payload: []const u8) Error!void {
    if (payload.len > max_frame_size) return error.FrameTooLarge;
    if (!outgoing.opcode.isControl()) return;
    if (payload.len > max_control_payload) return error.ControlFrameTooLong;
    if (!outgoing.fin) return error.FragmentedControlFrame;
}
