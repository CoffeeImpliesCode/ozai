//! RFC 6455 §5.2, §5.3 and §5.5: one frame written into a caller's buffer, and
//! the rules it has to obey before a byte of it is written.
//!
//! **The three rules are checked here rather than in the writer.** An
//! over-long control payload, a fragmented control frame and an oversized frame
//! are all refusals a caller can act on, and all three are decided from
//! `Outbound` before the writer exists — so they leave `out` exactly as it was
//! handed over, and a caller that retries with a smaller frame is not writing
//! into a buffer this one already dirtied.
//!
//! **Masking is applied by reading back the bytes just written.** The caller's
//! payload is not touched and no second buffer exists; the same key again would
//! undo it, which is the fixed point `ws_mask.zig`'s comment claims and
//! `ws_frame_decode.zig` relies on.
//!
//! `ws_header.zig` holds the constants this module writes against
//! (`max_short_payload`, `max_16_bit_payload`, `masking_key_length`) and reads
//! them back the other way, so a change to a bound is one edit rather than two
//! that could disagree.

const std = @import("std");
const header = @import("ws_header.zig");
const masker = @import("ws_mask.zig");

const std_testing = std.testing;

/// Every way `encode` can refuse to write a frame.
///
/// **`BufferFull` is the one arm that does not leave `out` untouched.** It is
/// found with the header already down, so a caller must discard `out` rather
/// than send what happens to be in it; the other three are found first.
pub const EncodeError = error{
    ControlFrameTooLong,
    FragmentedControlFrame,
    FrameTooLarge,
    BufferFull,
};

/// One frame to write.
pub const Outbound = struct {
    /// Clear on a frame that continues in a later one. A control frame may not
    /// clear it, and `encode` refuses rather than writing one.
    fin: bool = true,
    opcode: header.Opcode,
    /// The message bytes, borrowed for the call. `encode` copies them into `out`
    /// and masks them there, so nothing in the result refers to them and the
    /// caller's buffer may be reused the moment this returns.
    payload: []const u8,
    /// The four-byte key for a client frame, and absent for a server's
    /// (RFC 6455 §5.1). A client draws it from a CSPRNG; this module only
    /// applies it, and `ws_frame_decode.zig` is where a peer that broke the
    /// rule is refused, because a codec with no connection state cannot know
    /// the caller's role.
    mask_key: ?[header.masking_key_length]u8,
};

/// Writes one frame into `out` and hands back what it wrote.
///
/// `out` is the caller's buffer and is never grown, so one scratch buffer can
/// serve a whole connection; a frame that does not fit is `error.BufferFull`.
/// Every other refusal — an over-long control payload, a fragmented control
/// frame, a payload over `max_frame_size` — is decided before a byte is written,
/// so those leave `out` exactly as it was handed over. `error.BufferFull` does
/// not: it is found with the header already down, so a caller must discard `out`
/// rather than send what happens to be in it.
pub fn encode(out_frame: Outbound, out: []u8) EncodeError![]const u8 {
    if (out_frame.opcode.isControl()) {
        if (out_frame.payload.len > header.max_control_payload) return error.ControlFrameTooLong;
        if (!out_frame.fin) return error.FragmentedControlFrame;
    }
    if (out_frame.payload.len > header.max_frame_size) return error.FrameTooLarge;
    const payload_len: u64 = out_frame.payload.len;
    var writer = Writer.init(out);
    const fin_bit: u8 = if (out_frame.fin) 0x80 else 0x00;
    const mask_bit: u8 = if (out_frame.mask_key != null) 0x80 else 0x00;
    try writer.writeU8(@intFromEnum(out_frame.opcode) | fin_bit);
    if (payload_len <= header.max_short_payload) {
        try writer.writeU8(mask_bit | @as(u8, @intCast(payload_len)));
    } else if (payload_len <= header.max_16_bit_payload) {
        try writer.writeU8(mask_bit | 126);
        try writer.writeBig(u16, @intCast(payload_len));
    } else {
        try writer.writeU8(mask_bit | 127);
        try writer.writeBig(u64, payload_len);
    }
    if (out_frame.mask_key) |key| try writer.write(&key);
    // The payload's room is claimed before it is copied, so a buffer too small
    // for it is `error.BufferFull` and not a slice panic out of `rest()`.
    try writer.reserve(out_frame.payload.len);
    const written = writer.rest()[0..out_frame.payload.len];
    @memcpy(written, out_frame.payload);
    if (out_frame.mask_key) |key| masker.maskInPlace(written, key);
    writer.advance(out_frame.payload.len);
    return writer.finish();
}

/// Writes into a buffer the caller owns, and never grows it.
///
/// The same shape as `http_response.zig`'s private `Writer`, for the same reason:
/// one scratch buffer has to serve a whole connection, so the writer refuses
/// rather than allocates. Every method answers `error.BufferFull` rather than a
/// slice panic, because a WebSocket header is read from a socket and a short
/// read is routine, not a caller bug.
const Writer = struct {
    buf: []u8,
    at: usize = 0,

    fn init(buf: []u8) Writer {
        return .{ .buf = buf };
    }

    fn rest(self: *const Writer) []u8 {
        return self.buf[self.at..];
    }

    fn advance(self: *Writer, count: usize) void {
        self.at += count;
    }

    fn finish(self: *const Writer) []const u8 {
        return self.buf[0..self.at];
    }

    fn writeU8(self: *Writer, byte: u8) EncodeError!void {
        if (self.rest().len < 1) return error.BufferFull;
        self.buf[self.at] = byte;
        self.at += 1;
    }

    fn writeBig(self: *Writer, comptime T: type, value: T) EncodeError!void {
        if (self.rest().len < @sizeOf(T)) return error.BufferFull;
        std.mem.writeInt(T, self.rest()[0..@sizeOf(T)], value, .big);
        self.at += @sizeOf(T);
    }

    fn write(self: *Writer, bytes: []const u8) EncodeError!void {
        if (self.rest().len < bytes.len) return error.BufferFull;
        @memcpy(self.rest()[0..bytes.len], bytes);
        self.at += bytes.len;
    }

    /// Refuses a write of `count` bytes that would not fit, without writing.
    ///
    /// Separate from `write` because the payload is copied and then masked by
    /// reading back what was written, so the room has to be claimed before the
    /// copy rather than as part of it.
    fn reserve(self: *Writer, count: usize) EncodeError!void {
        if (self.rest().len < count) return error.BufferFull;
    }
};

// ---------------------------------------------------------------------------
// Tests. RFC 6455 §5.5 and §5.2 are the only sources of bytes here.
// ---------------------------------------------------------------------------

const hello = "Hello";
/// RFC 6455 §1.3: the one masking key the RFC prints.
const rfc_key = [_]u8{ 0x37, 0xfa, 0x21, 0x3d };

test "error inventory: every declared arm is reached by concrete bytes" {
    // Checked against the type rather than trusted, so an arm added to the set
    // without a case here fails the build, and an arm listed that the set does
    // not declare fails the same way.
    const encode_arms = [_]EncodeError{
        error.ControlFrameTooLong,
        error.FragmentedControlFrame,
        error.FrameTooLarge,
        error.BufferFull,
    };
    try std_testing.expectEqual(@typeInfo(EncodeError).error_set.?.len, encode_arms.len);

    var out: [16]u8 = undefined;
    // `ws_header.zig` refuses an oversized frame on the way in; a relay that
    // decided to write one anyway is refused here, before the writer exists,
    // and a mask key does not make room because it spends header bytes rather
    // than payload bytes — the payload has to be one byte past the bound.
    // Nothing here reads the payload, so it is left undefined rather than
    // written out: a megabyte of zeroes would cost more than the refusals do.
    const oversized: [header.max_frame_size + 1]u8 = undefined;
    try std_testing.expectError(error.FrameTooLarge, encode(.{
        .opcode = .binary,
        .payload = &oversized,
        .mask_key = null,
    }, &out));
    // A payload exactly at the bound is not over it, masked or not, and the
    // refusal it gets is the other one: the 16-byte buffer is too small for a
    // megabyte, so this is `BufferFull` and not `FrameTooLarge`. The two arms
    // are told apart by whether the bound or the buffer was reached first.
    try std_testing.expectError(error.BufferFull, encode(.{
        .opcode = .binary,
        .payload = &oversized[0..header.max_frame_size],
        .mask_key = rfc_key,
    }, &out));

    // The two control rules, at 126 bytes and with `fin` clear (RFC 6455 §5.5).
    const over: [header.max_control_payload + 1]u8 = @splat(0x5a);
    try std_testing.expectError(error.ControlFrameTooLong, encode(.{
        .opcode = .ping,
        .payload = &over,
        .mask_key = null,
    }, &out));
    try std_testing.expectError(error.FragmentedControlFrame, encode(.{
        .fin = false,
        .opcode = .close,
        .payload = "",
        .mask_key = null,
    }, &out));

    // Three `BufferFull`s: a header that does not fit, a payload that does not,
    // and the mask key that sits between them. These are the failures a caller's
    // buffer sizing actually hits.
    try std_testing.expectError(
        error.BufferFull,
        encode(.{ .opcode = .binary, .payload = hello, .mask_key = null }, out[0..1]),
    );
    try std_testing.expectError(
        error.BufferFull,
        encode(.{ .opcode = .binary, .payload = hello, .mask_key = null }, out[0..4]),
    );
    try std_testing.expectError(
        error.BufferFull,
        encode(.{ .opcode = .binary, .payload = hello, .mask_key = rfc_key }, out[0..7]),
    );
}