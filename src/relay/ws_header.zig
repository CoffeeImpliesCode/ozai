//! RFC 6455 §5.2: the header that precedes every WebSocket payload, and the
//! bounds every frame this tree reads obeys.
//!
//! Upstream `iroh-relay` reaches a client over `tokio-tungstenite`
//! (`http_server.rs`, `client.rs`), so the bytes between the socket and
//! `relay/frame.zig`'s `Message` are WebSocket frames written by a library and
//! not by iroh. Nothing upstream cites them, so nothing here claims a captured
//! vector from iroh; the bytes come from RFC 6455 itself and the vector below is
//! the one its §5.7 prints.
//!
//! **This module reads a header and nothing else.** That is the whole split:
//! `ws_frame.zig` turns a header plus a payload into a `Frame`, and
//! `ws_control.zig` gives the three control payloads their meaning. Everything
//! that can be decided from the header alone is decided here, before a single
//! payload byte is touched — the reserved bits, the opcode, the minimality of
//! the length, the control-frame bounds and `max_frame_size` — so a caller that
//! only wants to know how long a frame is pays no unmasking and no borrow, and a
//! peer declaring a gigabyte costs ten header bytes to refuse and no memory.

const std = @import("std");
const relay_frame = @import("frame_types.zig");

const std_testing = std.testing;

/// Every way a header can be refused.
///
/// `UnexpectedEnd` carries the same name as an arm of `relay/frame.zig`'s
/// `Error` and means the same rule there: the input ran out mid-value. The two
/// modules are separate error sets and a caller crossing both answers each in
/// its own place.
pub const Error = error{
    /// The header promised more bytes than the buffer holds.
    UnexpectedEnd,
    /// One of the three reserved bits was set (RFC 6455 §5.2). No extension has
    /// been negotiated on this connection, so a set bit is not one to ignore.
    ReservedBitSet,
    /// An opcode RFC 6455 §5.2 does not define: 3 through 7 and 11 through 15
    /// are reserved on the wire, and a named refusal is the only honest answer
    /// to a peer speaking one.
    UnknownOpcode,
    /// A length that is not minimally encoded, or a 64-bit length with its top
    /// bit set (RFC 6455 §5.2). Both name a header that cannot be what it says.
    BadLength,
    /// A control frame's payload over `max_control_payload` (RFC 6455 §5.5).
    ControlFrameTooLong,
    /// A control frame with `FIN` clear (RFC 6455 §5.5). A fragmented control
    /// frame would sit between the fragments of a message, and nothing here
    /// reassembles, so nothing here could place it.
    FragmentedControlFrame,
    /// A declared payload over `max_frame_size`.
    FrameTooLarge,
};

/// The bytes a masked frame's payload is XORed against (RFC 6455 §5.3).
pub const masking_key_length = 4;

/// The most bytes a control frame may carry (RFC 6455 §5.5).
///
/// One byte past this and the length could not be told from a data frame's, and
/// a control frame has to be interpretable from its header alone — that is the
/// whole reason §5.5 caps it.
pub const max_control_payload = 125;

/// The most bytes one frame's payload may declare.
///
/// **This is `relay/frame.zig`'s number, read here for the first time.** That
/// module measures a whole relay message against it and has nothing to say
/// about the WebSocket header in front of one; one relay message is one frame,
/// so the two are the same rule at two places — how large one message may be.
/// The frame header is charged on top, so a buffer for the largest frame this
/// tree will write is `max_frame_size + 10`.
pub const max_frame_size: usize = relay_frame.max_frame_size;

/// The largest payload a 7-bit length spells, and the smallest a 16-bit one may
/// (RFC 6455 §5.2 requires the minimal number of bytes).
pub const max_short_payload: usize = max_control_payload;

/// The largest payload a 16-bit length spells, and the smallest a 64-bit one
/// may.
pub const max_16_bit_payload: usize = 0xffff;

/// A WebSocket opcode, the low nibble of the first header byte (RFC 6455 §5.2).
///
/// **The enum's values are the wire numbers**, so `@intFromEnum` is the encoding
/// and no table exists to fall out of step with the standard — the same reason
/// `relay/frame.zig`'s `FrameType` numbers its arms directly. A caller writing
/// an `Opcode` should `switch` over all seven: this is a closed domain and a
/// default arm would answer a question about a future opcode silently.
pub const Opcode = enum(u8) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xa,

    /// Whether this is one of the three control opcodes (RFC 6455 §5.5).
    ///
    /// **Every arm is named and the switch has no `else`**, for the reason
    /// `relay/frame.zig`'s `FrameType.allowedIn` gives: an opcode added later
    /// has to say whether it is a control frame rather than inherit "no" from a
    /// default, because the two bounds this tree keeps apart — 125 bytes and no
    /// fragmentation — are exactly the two a data frame must not obey.
    pub fn isControl(opcode: Opcode) bool {
        return switch (opcode) {
            .close, .ping, .pong => true,
            .continuation, .text, .binary => false,
        };
    }
};

/// Which end of a connection this is, and so whose masking rule a frame obeys
/// (RFC 6455 §5.1).
///
/// The rule exists because a server must be able to reject a cache-poisoned
/// response aimed at a client, and the wire says which end sent a frame with the
/// mask bit and nothing else.
pub const Role = enum {
    /// Masks what it sends, and refuses a masked frame on the way in.
    client,
    /// Sends unmasked, and refuses an unmasked frame on the way in.
    server,
};

/// At most the ten bytes that precede a payload (RFC 6455 §5.2).
///
/// A value with no borrowed slice in it, so a `Header` outlives the buffer it
/// was read from and can be logged, compared and stored.
pub const Header = struct {
    /// Clear on a frame that continues in a later one.
    fin: bool,
    opcode: Opcode,
    /// Whether the payload is masked, which is how this protocol says a client
    /// sent it.
    masked: bool,
    /// The key. Zero when `masked` is false, so an absent key is a value rather
    /// than an optional — the header has a fixed width and reading it must not
    /// have to learn whether a key follows.
    mask_key: [masking_key_length]u8,
    payload_len: u64,
    /// How many bytes this header took, so the payload starts here.
    header_len: usize,
};

/// Reads the header at the start of `bytes`, and nothing else.
///
/// The reserved-bit check runs before the opcode check so a byte carrying both
/// complaints is named for the bit: no extension is negotiated on this
/// connection, and that is a fact about the connection rather than about the
/// message.
pub fn decodeHeader(bytes: []const u8) Error!Header {
    if (bytes.len < 2) return error.UnexpectedEnd;
    const first = bytes[0];
    if (first & 0x70 != 0) return error.ReservedBitSet;
    const opcode = std.enums.fromInt(Opcode, first & 0x0f) orelse
        return error.UnknownOpcode;
    const second = bytes[1];
    const masked = second & 0x80 != 0;
    const short = second & 0x7f;
    var payload_len: u64 = short;
    var at: usize = 2;
    if (short == 126) {
        if (bytes.len < 4) return error.UnexpectedEnd;
        payload_len = std.mem.readInt(u16, bytes[2..4], .big);
        at = 4;
        if (payload_len < max_short_payload) return error.BadLength;
    } else if (short == 127) {
        if (bytes.len < 10) return error.UnexpectedEnd;
        payload_len = std.mem.readInt(u64, bytes[2..10], .big);
        at = 10;
        // The top bit MUST be zero: without this a header spelling two to the
        // sixty-third is read as a length no bound can catch, because it is not
        // a length at all.
        if (payload_len > std.math.maxInt(u64) / 2) return error.BadLength;
        if (payload_len < max_16_bit_payload + 1) return error.BadLength;
    }
    // The control bounds before the general one, because a control frame that
    // declares 200 bytes is over its own bound and not merely over the largest
    // frame; the two numbers differ by three orders of magnitude and naming the
    // wrong one sends a caller looking in the wrong place.
    if (opcode.isControl()) {
        if (payload_len > max_control_payload) return error.ControlFrameTooLong;
        if (first & 0x80 == 0) return error.FragmentedControlFrame;
    } else if (payload_len > max_frame_size) {
        return error.FrameTooLarge;
    }
    var mask_key = [_]u8{0} ** masking_key_length;
    if (masked) {
        if (bytes.len < at + masking_key_length) return error.UnexpectedEnd;
        @memcpy(&mask_key, bytes[at..][0..masking_key_length]);
        at += masking_key_length;
    }
    return .{
        .fin = first & 0x80 != 0,
        .opcode = opcode,
        .masked = masked,
        .mask_key = mask_key,
        .payload_len = payload_len,
        .header_len = at,
    };
}

/// How many bytes the header for a payload of `payload_len` takes.
///
/// Computed from the same three rules `ws_frame.encode` writes and
/// `decodeHeader` reads, so a caller sizing a buffer for one frame does not have
/// to know which length width its payload will be spelled in — and cannot get it
/// wrong by guessing the short form for a large payload.
pub fn headerLen(payload_len: usize, masked: bool) usize {
    const length_bytes: usize = if (payload_len <= max_short_payload)
        2
    else if (payload_len <= max_16_bit_payload)
        4
    else
        10;
    return length_bytes + (if (masked) masking_key_length else 0);
}

// ---------------------------------------------------------------------------
// Tests. RFC 6455 §5.7 and §5.2 are the only sources of bytes here.
// ---------------------------------------------------------------------------

test "golden: RFC 6455 §5.7, the header of one unmasked text frame" {
    // §5.7's worked example: `0x81 0x05` then "Hello", and the length is in the
    // header because there is nowhere else for it to be.
    const header = try decodeHeader(&.{ 0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f });
    try std_testing.expect(header.fin);
    try std_testing.expectEqual(Opcode.text, header.opcode);
    try std_testing.expect(!header.masked);
    try std_testing.expectEqual(@as(u64, 5), header.payload_len);
    try std_testing.expectEqual(@as(usize, 2), header.header_len);
    // The bytes past the header are not this module's business, and reading them
    // is what makes the header the only place `max_frame_size` is enforced.
    try std_testing.expectEqual(header.header_len + 5, 7);
}

test "lengths: 7, 16 and 64 bits, and the minimality both widths require" {
    // 125 is the last payload the short form spells, 126 the first the 16-bit
    // form may, and 65536 the first the 64-bit form may (RFC 6455 §5.2).
    try std_testing.expectEqual(@as(usize, 2), headerLen(125, false));
    try std_testing.expectEqual(@as(usize, 4), headerLen(126, false));
    try std_testing.expectEqual(@as(usize, 10), headerLen(65_536, false));
    // A masked frame's header is four bytes longer, which is the whole cost of
    // the mask key.
    try std_testing.expectEqual(@as(usize, 6), headerLen(125, true));
    try std_testing.expectEqual(@as(usize, 8), headerLen(200, true));
    try std_testing.expectEqual(@as(usize, 14), headerLen(65_536, true));
    const short = try decodeHeader(&.{ 0x82, 126, 0x00, 126 });
    try std_testing.expectEqual(@as(u64, 126), short.payload_len);
    try std_testing.expectEqual(@as(usize, 4), short.header_len);
    const long = try decodeHeader(&.{ 0x82, 127, 0x00, 0x00, 0x00, 0x01, 0x11, 0x70 });
    try std_testing.expectEqual(@as(u64, 70_000), long.payload_len);
    try std_testing.expectEqual(@as(usize, 10), long.header_len);

    // A 16-bit length spelling less than 126, and a 64-bit length spelling less
    // than 65536: both name a header that could have been shorter, and a peer
    // that sends one is either confused or probing for a parser that is.
    try std_testing.expectError(error.BadLength, decodeHeader(&.{ 0x82, 126, 0x00, 125 }));
    try std_testing.expectError(
        error.BadLength,
        decodeHeader(&.{ 0x82, 127, 0, 0, 0, 0, 0, 0, 0xff, 0xff }),
    );
    // The top bit of a 64-bit length MUST be zero, and one that sets it is read
    // as a length no bound could catch if it were not caught here.
    try std_testing.expectError(
        error.BadLength,
        decodeHeader(&.{ 0x82, 127, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }),
    );
}

test "reserved bits and opcodes are named refusals, never defaults" {
    // No extension has been negotiated on a relay connection, so a set RSV bit
    // is not a bit to ignore, and an unassigned opcode is a peer speaking
    // something this build does not have.
    for ([_]u8{ 0x40, 0x50, 0x60, 0x70, 0xc1, 0xd2 }) |first| {
        try std_testing.expectError(error.ReservedBitSet, decodeHeader(&.{ first, 0x00 }));
    }
    for ([_]u8{ 0x03, 0x04, 0x05, 0x06, 0x07, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }) |low| {
        try std_testing.expectError(error.UnknownOpcode, decodeHeader(&.{ 0x80 | low, 0x00 }));
    }
    // A reserved bit alongside a reserved opcode is named for the bit: which is
    // a fact about the connection, and the opcode is not readable without it.
    try std_testing.expectError(error.ReservedBitSet, decodeHeader(&.{ 0xd3, 0x00 }));
}

test "control frames: 125 bytes and no fragmentation, both refused over" {
    // Refused at the header, so an over-long control frame costs two bytes to
    // reject and its payload is never touched.
    const at_bound = try decodeHeader(&.{ 0x89, max_control_payload });
    try std_testing.expectEqual(@as(u64, 125), at_bound.payload_len);
    try std_testing.expect(at_bound.fin);
    try std_testing.expectError(error.ControlFrameTooLong, decodeHeader(&.{ 0x89, 126 }));
    try std_testing.expectError(error.FragmentedControlFrame, decodeHeader(&.{ 0x09, 0x00 }));
}

test "max_frame_size is enforced at the message boundary" {
    // Ten header bytes are enough to refuse a frame declaring a gigabyte, and
    // that is the whole point of enforcing at the boundary: no payload has to
    // arrive for the refusal to be made.
    var header: [10]u8 = undefined;
    header[0] = 0x82;
    header[1] = 127;
    std.mem.writeInt(u64, header[2..10], std.math.maxInt(u64) / 4, .big);
    try std_testing.expectError(error.FrameTooLarge, decodeHeader(&header));

    // The bound is `relay/frame.zig`'s, so one relay message is one frame and
    // the two agree by construction rather than by two numbers kept in step.
    comptime std.debug.assert(max_frame_size == relay_frame.max_frame_size);
}

test "error inventory: every declared arm is reached by concrete bytes" {
    // Checked against the type rather than trusted, so an arm added to `Error`
    // without a case here fails the build, and an arm listed that `Error` does
    // not declare fails the same way.
    const arms = [_]Error{
        error.UnexpectedEnd,
        error.ReservedBitSet,
        error.UnknownOpcode,
        error.BadLength,
        error.ControlFrameTooLong,
        error.FragmentedControlFrame,
        error.FrameTooLarge,
    };
    try std_testing.expectEqual(@typeInfo(Error).error_set.?.len, arms.len);

    // Fewer than two bytes, then a header that has not finished arriving, then a
    // mask key that is not there yet: the three shapes a short socket read takes.
    try std_testing.expectError(error.UnexpectedEnd, decodeHeader(""));
    try std_testing.expectError(error.UnexpectedEnd, decodeHeader(&.{0x82}));
    try std_testing.expectError(error.UnexpectedEnd, decodeHeader(&.{ 0x82, 126 }));
    try std_testing.expectError(error.UnexpectedEnd, decodeHeader(&.{ 0x82, 127, 0, 0 }));
    try std_testing.expectError(error.UnexpectedEnd, decodeHeader(&.{ 0x82, 126, 0, 2, 0xaa }));
    try std_testing.expectError(error.UnexpectedEnd, decodeHeader(&.{ 0x82, 0x80, 1, 2 }));
    try std_testing.expectError(error.ReservedBitSet, decodeHeader(&.{ 0x41, 0x00 }));
    try std_testing.expectError(error.UnknownOpcode, decodeHeader(&.{ 0x83, 0x00 }));
    try std_testing.expectError(error.BadLength, decodeHeader(&.{ 0x82, 126, 0x00, 125 }));
    try std_testing.expectError(
        error.ControlFrameTooLong,
        decodeHeader(&.{ 0x88, 0x7e, 0x00, 0x7e }),
    );
    try std_testing.expectError(error.FragmentedControlFrame, decodeHeader(&.{ 0x88, 0x00 }));
}
