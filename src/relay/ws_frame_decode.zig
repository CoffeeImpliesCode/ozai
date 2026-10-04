//! RFC 6455 §5.1: one frame read out of a buffer — a header, and the payload
//! behind it unmasked where it already sits.
//!
//! **One relay message is one frame.** That is not a simplification, it is the
//! relay protocol: the relay frame codec reads a message as a frame type and that
//! type's payload to the end, with no length prefix and no frame count. So the
//! WebSocket header **is** the message boundary, and `max_frame_size` is enforced
//! there, against the declared length, before a payload byte is read or a buffer
//! byte is written — a peer that declares a gigabyte costs ten header bytes to
//! refuse and no memory at all.
//!
//! **There is no reassembly here.** Fragmentation is a WebSocket feature the
//! relay protocol does not use, so `fin` is validated and carried and joining
//! fragments is somebody else's problem; a caller that receives one must decide
//! what a `continuation` after a `binary` is, and this module will not guess.
//!
//! **The write is the whole cost of the mask.** RFC 6455 §5.3 defines masking
//! as an XOR against a repeating key, and an XOR is its own inverse, so undoing
//! it means writing to the bytes; copying instead would cost a second buffer on
//! a path that runs on every relayed datagram. `decode` therefore takes a mutable
//! `bytes` and hands back a `Frame` that borrows it, so the write is visible in
//! the type rather than hidden in a doc.
//!
//! Everything a header alone can say is said by `ws_header.zig`, and each of its
//! refusals is restated in `DecodeError` rather than forwarded: an arm added
//! there fails this file's build instead of being swallowed by a set that does
//! not name it.

const std = @import("std");
const header = @import("ws_header.zig");
const masker = @import("ws_mask.zig");

const Opcode = header.Opcode;
const Role = header.Role;
const std_testing = std.testing;

/// Every way `decode` can fail: anything a header can say, plus one rule this
/// module adds.
///
/// **The seven header arms are restated rather than imported.** That is what
/// keeps this set explicit, and it is checked rather than trusted: forwarding
/// `ws_header`'s error through a set that does not name it would not compile, so
/// an arm added there fails this module's build instead of being swallowed.
pub const DecodeError = error{
    UnexpectedEnd,
    ReservedBitSet,
    UnknownOpcode,
    BadLength,
    ControlFrameTooLong,
    FragmentedControlFrame,
    FrameTooLarge,
    MaskingDisagreesWithRole,
};

/// One frame's header and its payload, borrowed from the buffer `decode` read.
///
/// **The payload is unmasked in place, so this borrows a buffer `decode` has
/// already written to.** A `Frame` is therefore valid for exactly as long as
/// that buffer, a write anywhere in it changes the frame, and reusing it for the
/// next message invalidates every `Frame` still held from the last one — the
/// same borrow the relay frame codec's `decode` hands back, argued there at
/// greater length.
pub const Frame = struct {
    fin: bool,
    opcode: Opcode,
    payload: []const u8,
};

/// Reads one frame from the start of `bytes`, unmasking its payload in place.
///
/// **`bytes` is mutable because unmasking writes to it.** That is the whole cost
/// of RFC 6455 §5.3's mask, and it is paid here rather than behind a copy in
/// every caller: a caller reading from a socket owns a writable read buffer
/// already, and one scratch buffer per connection is the cost either way.
///
/// `role` is which end this connection is, and it is not optional: RFC 6455 §5.1
/// makes masking mandatory from a client and forbidden from a server, so
/// `header.masked` and `role` have to agree and a peer that breaks the rule is
/// `error.MaskingDisagreesWithRole` rather than a frame read on trust.
///
/// Nothing is allocated and nothing is retained: the payload is a slice into
/// `bytes`, the header is a value, and the borrow is freed by the caller.
pub fn decode(bytes: []u8, role: Role) DecodeError!Frame {
    const read = try header.decodeHeader(bytes);
    if (read.masked != (role == .server)) return error.MaskingDisagreesWithRole;
    // `decodeHeader` refused anything over `max_frame_size`, so this cast cannot
    // lose a bit on any target.
    const end = read.header_len + @as(usize, @intCast(read.payload_len));
    if (bytes.len < end) return error.UnexpectedEnd;
    const payload = bytes[read.header_len..end];
    if (read.masked) masker.maskInPlace(payload, read.mask_key);
    return .{ .fin = read.fin, .opcode = read.opcode, .payload = payload };
}

// ---------------------------------------------------------------------------
// Tests. RFC 6455 §5.2 and §5.5 are the sources of the bytes here; nothing is
// claimed to come from iroh, because upstream never writes these bytes itself.
// ---------------------------------------------------------------------------

/// One byte past `max_frame_size`: the only declared length that reaches
/// `error.FrameTooLarge`, since a payload exactly at the bound is under it.
const oversized_len: u64 = @as(u64, @intCast(header.max_frame_size)) + 1;

/// A header spelling `oversized_len`, written out from the constant rather than
/// pasted, so the vector cannot fall behind the bound it exists to exceed. The
/// length is truncated rather than cast because `@intCast` is checked and a
/// megabyte does not fit in a byte.
const oversized: [10]u8 = .{
    0x82,
    127,
    @truncate(oversized_len >> 24),
    @truncate(oversized_len >> 16),
    @truncate(oversized_len >> 8),
    @truncate(oversized_len),
    0,
    0,
    0,
    0,
};

test "error inventory: every declared arm is reached by concrete bytes" {
    // Checked against the types rather than trusted, so an arm added to the set
    // without a case here fails the build, and an arm listed that the set does
    // not declare fails the same way.
    const decode_arms = [_]DecodeError{
        error.UnexpectedEnd,
        error.ReservedBitSet,
        error.UnknownOpcode,
        error.BadLength,
        error.ControlFrameTooLong,
        error.FragmentedControlFrame,
        error.FrameTooLarge,
        error.MaskingDisagreesWithRole,
    };
    try std_testing.expectEqual(@typeInfo(DecodeError).error_set.?.len, decode_arms.len);

    var scratch: [16]u8 = undefined;
    // A header that is complete and a payload that is not. It goes through
    // `decodeFrom` like the rest, because `decode` writes to the buffer it is
    // handed and a literal is const.
    try std_testing.expectError(
        error.UnexpectedEnd,
        decodeFrom(&scratch, &.{ 0x82, 0x05, 0x00 }, .server),
    );
    // The seven header arms, each forwarded from `ws_header.zig`.
    try std_testing.expectError(
        error.ReservedBitSet,
        decodeFrom(&scratch, &.{ 0xc2, 0x00 }, .server),
    );
    try std_testing.expectError(
        error.UnknownOpcode,
        decodeFrom(&scratch, &.{ 0x83, 0x00 }, .server),
    );
    try std_testing.expectError(
        error.BadLength,
        decodeFrom(&scratch, &.{ 0x82, 126, 0x00, 125 }, .server),
    );
    try std_testing.expectError(
        error.ControlFrameTooLong,
        decodeFrom(&scratch, &.{ 0x89, 126 }, .server),
    );
    try std_testing.expectError(
        error.FragmentedControlFrame,
        decodeFrom(&scratch, &.{ 0x88, 0x00 }, .server),
    );
    try std_testing.expectError(error.FrameTooLarge, decodeFrom(&scratch, &oversized, .server));
    // The one rule this module adds: a masked frame where the role says
    // unmasked, and an unmasked one where it says masked.
    try std_testing.expectError(
        error.MaskingDisagreesWithRole,
        decodeFrom(&scratch, &.{ 0x82, 0x00 }, .server),
    );
    try std_testing.expectError(
        error.MaskingDisagreesWithRole,
        decodeFrom(&scratch, &.{ 0x82, 0x80, 1, 2, 3, 4 }, .client),
    );
}

/// Decodes a frame out of a literal.
///
/// `decode` writes to the buffer it is handed — it unmasks in place — and a
/// `&[_]u8{...}` literal is const, so the bytes are copied into `scratch`
/// first. The frame borrows `scratch`, which is the lifetime `decode` already
/// documents; a caller with a real read buffer hands that buffer over instead
/// and skips this copy entirely.
fn decodeFrom(scratch: []u8, bytes: []const u8, role: Role) DecodeError!Frame {
    @memcpy(scratch[0..bytes.len], bytes);
    return decode(scratch[0..bytes.len], role);
}