//! RFC 6455 §5.5 and §7.4: what the three control frames carry.
//!
//! `ws_frame.zig` bounds a control frame at 125 bytes and refuses it fragmented
//! (RFC 6455 §5.5) because a control frame must be interpretable from its header
//! alone. This module is the other half: given such a frame, what its bytes
//! mean. Close is the only one of the three with a payload shape of its own, so
//! close is the only one with a codec here, and `ping` and `pong` are borrowed
//! slices straight out of the frame.
//!
//! **The mask and the header bounds are not repeated here.** A `Frame` reaching
//! this module has already been unmasked and already met every bound, so a check
//! here would be a check of a value this module did not produce — the difference
//! between validating a boundary and validating your own arithmetic.
//!
//! Nothing is allocated and nothing is retained: `controlOf` borrows the frame's
//! payload, `parseClose` borrows the bytes it was handed, and `encodeClose` writes
//! into the caller's buffer.

const std = @import("std");
const frame_codec = @import("ws_frame.zig");
const header = @import("ws_header.zig");

const Frame = frame_codec.Frame;
const std_testing = std.testing;

/// Every way a control payload can be refused.
///
/// `InvalidUtf8` carries the same name as an arm of `relay/frame.zig`'s `Error`
/// and means the same rule there — bytes that are not text — and `BufferFull`
/// the same rule about a writer. The sets are separate and a caller crossing
/// both answers each in its own place.
pub const Error = error{
    /// A close payload that cannot hold a code and is not empty: one byte.
    InvalidClosePayload,
    /// Close reason text that is not UTF-8 (RFC 6455 §5.5.1).
    InvalidUtf8,
    /// A close code RFC 6455 §7.4.1 says an endpoint must never send.
    UnsendableCloseCode,
    /// A writer with no room left in the buffer it was handed.
    BufferFull,
};

/// A close code (RFC 6455 §7.4).
///
/// Modelled on `relay/frame.zig`'s `Status` on purpose: the registered codes are
/// named, a code outside the registry is kept as the number that was sent, and
/// `toBits(fromInt(bits)) == bits` for all 65536 — so a decoded close re-encodes
/// to the same two bytes, which is the round trip this union has to be a fixed
/// point of.
///
/// `no_status_received` and `abnormal_closure` are named rather than folded into
/// `unknown` because RFC 6455 §7.4.1 forbids sending either, and a code that
/// can be written is one whose `sendable` is true.
///
/// The tag type is `u16` because a close code is a two-byte field and these tags
/// are 1000 through 1015; a tagged union whose tags are not 0 through n-1 has to
/// say what it is tagging them with.
pub const CloseCode = union(enum(u16)) {
    normal_closure = 1000,
    going_away = 1001,
    protocol_error = 1002,
    unsupported_data = 1003,
    /// Reserved: RFC 6455 §7.4.1 says an endpoint MUST NOT put this on the wire.
    no_status_received = 1005,
    /// Reserved: RFC 6455 §7.4.1 says an endpoint MUST NOT put this on the wire.
    abnormal_closure = 1006,
    invalid_frame_payload = 1007,
    policy_violation = 1008,
    message_too_big = 1009,
    mandatory_extension = 1010,
    internal_error = 1011,
    service_restart = 1012,
    try_again_later = 1013,
    bad_gateway = 1014,
    tls_handshake = 1015,
    /// A code outside the registry, kept as it was sent.
    unknown: u16,

    /// The code a number names, keeping a number this build has no name for.
    ///
    /// Walked over the enum's own values rather than matched against a written
    /// table, so a code renamed in the declaration above is renamed here too.
    pub fn fromInt(bits: u16) CloseCode {
        for (std.enums.values(CloseCode)) |code| {
            switch (code) {
                .unknown => continue,
                else => if (code.toBits() == bits) return code,
            }
        }
        return .{ .unknown = bits };
    }

    /// The number, which is the discriminant itself and not the arm's index.
    pub fn toBits(self: CloseCode) u16 {
        return switch (self) {
            .unknown => |bits| bits,
            else => |code| @intFromEnum(code),
        };
    }

    /// Whether this code may go on the wire (RFC 6455 §7.4).
    ///
    /// **Anything at or above 1000 that the registry does not reserve is
    /// sendable**, including the private 3000-4999 range and codes a later
    /// revision adds; 0-999 is unassigned, and 1005 and 1006 are the two the RFC
    /// forbids outright. A decoder never asks this — it keeps whatever arrived,
    /// named or not — so an unsendable code can still be read.
    pub fn sendable(self: CloseCode) bool {
        return switch (self) {
            .no_status_received, .abnormal_closure => false,
            .unknown => |bits| bits >= 1000,
            else => true,
        };
    }
};

/// A close frame's payload: a code and a reason, or neither (RFC 6455 §5.5.1).
///
/// **The reason is borrowed** and is UTF-8, checked on the way in and on the way
/// out: a peer reads it as text, so a byte sequence that is not text has no
/// reading. An empty reason is legal for every code.
pub const Close = struct {
    /// Absent for the empty payload RFC 6455 §7.1.1 calls "no status code
    /// present", which is not the same as any code and does not get a default.
    code: ?CloseCode,
    reason: []const u8,
};

/// Reads a close frame's payload.
///
/// **An empty payload is a close with no code**, which RFC 6455 §7.1.1 defines
/// as "no status code present" and an implementation records as an abnormal
/// closure. One byte is refused: the code is two bytes big, so a payload that
/// cannot hold one holds none.
pub fn parseClose(payload: []const u8) Error!Close {
    if (payload.len == 0) return .{ .code = null, .reason = "" };
    if (payload.len < 2) return error.InvalidClosePayload;
    const reason = payload[2..];
    if (!std.unicode.utf8ValidateSlice(reason)) return error.InvalidUtf8;
    return .{
        .code = CloseCode.fromInt(std.mem.readInt(u16, payload[0..2], .big)),
        .reason = reason,
    };
}

/// The bytes `encodeClose` writes for a close: a code, then the reason.
pub fn closePayloadLen(close: Close) usize {
    if (close.code == null) return 0;
    return @sizeOf(u16) + close.reason.len;
}

/// Writes a close frame's payload into `out` and hands back what it wrote.
///
/// **An absent code writes nothing at all**, which is the empty close payload of
/// RFC 6455 §7.1.1 rather than a close with a zero code: 0 is unassigned, and a
/// peer reading `00 00` would be told a status the relay did not have.
///
/// Both refusals are decided before the writer exists, so `out` is unchanged when
/// either is returned.
pub fn encodeClose(close: Close, out: []u8) Error![]const u8 {
    if (close.code == null) return out[0..0];
    if (!std.unicode.utf8ValidateSlice(close.reason)) return error.InvalidUtf8;
    if (!close.code.?.sendable()) return error.UnsendableCloseCode;
    if (out.len < closePayloadLen(close)) return error.BufferFull;
    const written = out[0..closePayloadLen(close)];
    std.mem.writeInt(u16, written[0..2], close.code.?.toBits(), .big);
    @memcpy(written[2..], close.reason);
    return written;
}

/// A control frame's payload, borrowed from the buffer `decode` read.
pub const ControlFrame = union(enum) {
    close: Close,
    /// An application-defined value a `Pong` must echo (RFC 6455 §5.5.2 and
    /// §5.5.3). Up to `max_control_payload` bytes, and no more is a relay's ping
    /// payload than its node id.
    ping: []const u8,
    /// The bytes of the `Ping` being answered, which RFC 6455 requires be the
    /// same eight for iroh's own keepalive (`relay.rs:628`, `:632`).
    pong: []const u8,
};

/// The control frame `frame` is, or null when it is a data frame.
///
/// **Every arm is named and the switch has no `else`**, because `Opcode` is a
/// closed domain and a control opcode added later has to say which arm of this
/// union it produces. The data opcodes answer null rather than being `else`.
pub fn controlOf(frame: Frame) Error!?ControlFrame {
    return switch (frame.opcode) {
        .close => .{ .close = try parseClose(frame.payload) },
        .ping => .{ .ping = frame.payload },
        .pong => .{ .pong = frame.payload },
        .continuation, .text, .binary => null,
    };
}

// ---------------------------------------------------------------------------
// Tests. RFC 6455 §5.5, §5.5.1 and §7.4 are the sources of every rule here.
// ---------------------------------------------------------------------------

test "control frames: ping, pong and close are the three, and nothing else" {
    var out: [64]u8 = undefined;
    var ping_payload: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const ping = try decodeWritten(&out, try frame_codec.encode(.{
        .opcode = .ping,
        .payload = &ping_payload,
        .mask_key = null,
    }, &out));
    try std_testing.expectEqualSlices(u8, &ping_payload, (try controlOf(ping)).?.ping);

    // A Pong echoes the bytes of the Ping it answers, and iroh's own keepalive is
    // eight bytes of that (`relay.rs:628`, `:632`).
    const echo = (try controlOf(ping)).?.ping;
    const pong = try decodeWritten(&out, try frame_codec.encode(.{
        .opcode = .pong,
        .payload = echo,
        .mask_key = null,
    }, &out));
    try std_testing.expectEqualSlices(u8, echo, (try controlOf(pong)).?.pong);

    var close_payload: [8]u8 = undefined;
    const close = try encodeClose(
        .{ .code = .{ .unknown = 4321 }, .reason = "bye" },
        &close_payload,
    );
    try expectHex(&.{ 0x10, 0xe1, 0x62, 0x79, 0x65 }, close);
    const read = try decodeWritten(&out, try frame_codec.encode(.{
        .opcode = .close,
        .payload = close,
        .mask_key = null,
    }, &out));
    try std_testing.expectEqual(@as(u16, 4321), (try controlOf(read)).?.close.code.?.unknown);
    try std_testing.expectEqualStrings("bye", (try controlOf(read)).?.close.reason);

    // Every data opcode is not a control frame, and none of the three control
    // opcodes is missing.
    for ([_]header.Opcode{ .continuation, .text, .binary }) |opcode| {
        const data = try decodeWritten(&out, try frame_codec.encode(.{
            .opcode = opcode,
            .payload = "x",
            .mask_key = null,
        }, &out));
        try std_testing.expectEqual(@as(?ControlFrame, null), try controlOf(data));
    }
}

test "close: the code round-trips for all 65536, and the reserved two cannot be sent" {
    // `frame.Status`'s claim is `toBits(fromBits(bits)) == bits`; a close code is
    // the same claim over a wider type, so a decoded close re-encodes to the same
    // two bytes for every code that can arrive.
    for (0..@as(usize, 1) << 16) |bits| {
        try std_testing.expectEqual(bits, CloseCode.fromInt(@intCast(bits)).toBits());
    }
    // RFC 6455 §7.4.1 names two codes an endpoint must never send, and 0-999 is
    // unassigned, so a decoder keeps all of them and an encoder refuses them.
    var out: [8]u8 = undefined;
    for ([_]u16{ 0, 999, 1005, 1006 }) |bits| {
        try std_testing.expect(!CloseCode.fromInt(bits).sendable());
        try std_testing.expectError(
            error.UnsendableCloseCode,
            encodeClose(.{ .code = CloseCode.fromInt(bits), .reason = "" }, &out),
        );
    }
    for ([_]u16{ 1000, 1011, 1015, 3000, 4999 }) |bits| {
        try std_testing.expect(CloseCode.fromInt(bits).sendable());
    }
}

test "close: an empty payload has no code, one byte has no room for one" {
    var out: [8]u8 = undefined;
    const empty = try parseClose("");
    try std_testing.expectEqual(@as(?CloseCode, null), empty.code);
    try std_testing.expectEqualStrings("", empty.reason);
    // An absent code writes nothing, rather than `00 00` — a zero code is
    // unassigned and a peer reading it is told a status the relay did not have.
    try std_testing.expectEqual(@as(usize, 0), closePayloadLen(empty));
    try std_testing.expectEqualSlices(u8, "", try encodeClose(empty, &out));

    // Two bytes is a code with an empty reason, which is legal.
    const no_reason = try parseClose(&.{ 0x03, 0xe8 });
    try std_testing.expectEqual(@as(u16, 1000), no_reason.code.?.toBits());
    try std_testing.expectEqualStrings("", no_reason.reason);
    try std_testing.expectError(
        error.BufferFull,
        encodeClose(.{ .code = .normal_closure, .reason = "no room" }, &out),
    );
}

test "error inventory: every declared arm is reached by concrete bytes" {
    // Checked against the type rather than trusted, so an arm added to `Error`
    // without a case here fails the build, and an arm listed that `Error` does
    // not declare fails the same way.
    const arms = [_]Error{
        error.InvalidClosePayload,
        error.InvalidUtf8,
        error.UnsendableCloseCode,
        error.BufferFull,
    };
    try std_testing.expectEqual(@typeInfo(Error).error_set.?.len, arms.len);

    var out: [8]u8 = undefined;
    // A close payload one byte long, and reason text that is not text — refused
    // on the way in and again on the way out, because a peer reads it as text.
    try std_testing.expectError(error.InvalidClosePayload, parseClose(&.{0x00}));
    try std_testing.expectError(error.InvalidUtf8, parseClose(&.{ 0x03, 0xe8, 0xff }));
    try std_testing.expectError(
        error.InvalidUtf8,
        encodeClose(.{ .code = .normal_closure, .reason = &.{0xff} }, &out),
    );
    // A code RFC 6455 §7.4.1 forbids, and a writer with no room.
    try std_testing.expectError(
        error.UnsendableCloseCode,
        encodeClose(.{ .code = .abnormal_closure, .reason = "" }, &out),
    );
    try std_testing.expectError(
        error.BufferFull,
        encodeClose(.{ .code = .normal_closure, .reason = "no room" }, &out),
    );
    // And `controlOf` is the only reader here, so it is walked too: a close with
    // no payload is a close with no code, read back through a whole frame.
    var frame_bytes: [8]u8 = undefined;
    const empty_close = try decodeWritten(&frame_bytes, try frame_codec.encode(.{
        .opcode = .close,
        .payload = "",
        .mask_key = null,
    }, &frame_bytes));
    try std_testing.expectEqual(@as(?CloseCode, null), (try controlOf(empty_close)).?.close.code);
}

/// Decodes back what `ws_frame.encode` just wrote into `buffer`.
///
/// The slice `encode` returns is `[]const u8` because a caller must not write
/// through what a function handed back, and `decode` wants `[]u8` because it
/// unmasks in place. Both are the same memory, and the caller's array is where
/// the mutable view of it lives.
fn decodeWritten(buffer: []u8, written: []const u8) frame_codec.DecodeError!Frame {
    return frame_codec.decode(buffer[0..written.len], .server);
}

/// Fails with both hexdumps rather than a bare `false`, so a failing vector
/// names the byte that differs.
fn expectHex(expected: []const u8, actual: []const u8) !void {
    if (std.mem.eql(u8, expected, actual)) return;
    std.debug.print("expected {s}\n     got {s}\n", .{
        &std.fmt.fmtSliceHexLower(expected),
        &std.fmt.fmtSliceHexLower(actual),
    });
    return error.WireFormatMismatch;
}
