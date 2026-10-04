//! RFC 6455 framing: one WebSocket frame, its payload, and the mask.
//!
//! `ws_header.zig` reads the header, `ws_frame_decode.zig` turns a header and a
//! payload into a `Frame`, `ws_frame_encode.zig` writes one back out, and
//! `ws_mask.zig` is the XOR both directions share. This module is the name that
//! holds the four together: the codec a caller imports, and the tests that need
//! both directions at once to say a round trip is a round trip.
//!
//! **The split is by direction, and the public API does not move.** `decode`,
//! `encode`, `Frame`, `Outbound`, `DecodeError`, `EncodeError` and
//! `maskInPlace` are declared here exactly as they were when all of it lived in
//! this one file, as aliases of the sibling that owns each; `ws_control.zig`
//! imports this path and is untouched by where the code ended up.
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
//! **Masking is undone in place.** RFC 6455 §5.3 defines the mask as an XOR
//! against a repeating key, and an XOR is its own inverse, so undoing it means
//! writing to the bytes. Copying instead would cost a second buffer on a path
//! that runs on every relayed datagram. `decode` therefore writes to the buffer
//! it was handed, and `Frame` borrows that buffer so the write is visible in the
//! type rather than hidden in a doc.

const std = @import("std");
const header = @import("ws_header.zig");
const decode_frame = @import("ws_frame_decode.zig");
const encode_frame = @import("ws_frame_encode.zig");
const masker = @import("ws_mask.zig");

const Opcode = header.Opcode;
const std_testing = std.testing;

/// The refusals reading a frame can make, in `ws_frame_decode.zig`.
pub const DecodeError = decode_frame.DecodeError;

/// The refusals writing a frame can make, in `ws_frame_encode.zig`.
pub const EncodeError = encode_frame.EncodeError;

/// A frame read out of a buffer, borrowing it.
pub const Frame = decode_frame.Frame;

/// A frame to write.
pub const Outbound = encode_frame.Outbound;

/// Reads one frame from the start of `bytes`, unmasking its payload in place.
pub const decode = decode_frame.decode;

/// Writes one frame into `out` and hands back what it wrote.
pub const encode = encode_frame.encode;

/// XORs a payload against a repeating key, in place — both directions at once.
pub const maskInPlace = masker.maskInPlace;

// ---------------------------------------------------------------------------
// Tests. RFC 6455 §1.3 and §5.7 are the only sources of bytes here; nothing is
// claimed to come from iroh, because upstream never writes these bytes itself.
// Every test below crosses both directions, which is what is left to say once
// each direction's refusals moved next to the code that makes them.
// ---------------------------------------------------------------------------

const hello = "Hello";
/// RFC 6455 §1.3: the one masking key and one masked payload the RFC prints.
const rfc_key = [_]u8{ 0x37, 0xfa, 0x21, 0x3d };
const rfc_masked_hello = [_]u8{ 0x7f, 0x9f, 0x4d, 0x51, 0x58 };

test "golden: RFC 6455 §5.7, one unmasked text frame" {
    var out: [16]u8 = undefined;
    const frame = try encode(.{
        .opcode = .text,
        .payload = hello,
        .mask_key = null,
    }, &out);
    try expectHex(&.{ 0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f }, frame);

    const read = try decode(out[0..frame.len], .server);
    try std_testing.expect(read.fin);
    try std_testing.expectEqual(Opcode.text, read.opcode);
    try std_testing.expectEqualStrings(hello, read.payload);
}

test "golden: RFC 6455 §1.3, one masked text frame" {
    var out: [16]u8 = undefined;
    const frame = try encode(.{
        .opcode = .text,
        .payload = hello,
        .mask_key = rfc_key,
    }, &out);
    try expectHex(&.{
        0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58,
    }, frame);
    // The RFC's own five masked bytes, checked against the frame this tree
    // wrote rather than only against its own decoder.
    try expectHex(&rfc_masked_hello, frame[6..]);

    // The server unmasks in place, and "Hello" is what comes back — so the round
    // trip is proved against the RFC's own numbers and not only against this
    // tree's encoder.
    const read = try decode(out[0..frame.len], .server);
    try std_testing.expectEqualStrings(hello, read.payload);
    try expectHex(&.{
        0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58,
    }, frame);
}

test "masking: every key round-trips a payload of every length" {
    // The length the loop cannot prove — zero, where `payload` is a slice and
    // the loop body never runs — is proved after it, because an empty payload is
    // a real frame here (a ping with no value).
    var out: [300]u8 = undefined;
    for (0..256) |bits| {
        const mask = [header.masking_key_length]u8{
            @truncate(bits),
            @truncate(bits >> 8),
            @truncate(bits >> 16),
            @truncate(bits >> 24),
        };
        for (1..256) |len| {
            var payload: [256]u8 = undefined;
            for (payload[0..len], 0..) |*byte, index| byte.* = @truncate(index + bits);
            const frame = try encode(.{
                .opcode = .binary,
                .payload = payload[0..len],
                .mask_key = mask,
            }, &out);
            try std_testing.expectEqual(len + header.headerLen(len, true), frame.len);
            try std_testing.expectEqualSlices(
                u8,
                payload[0..len],
                (try decode(out[0..frame.len], .server)).payload,
            );
        }
    }
    const empty = try encode(.{ .opcode = .binary, .payload = "", .mask_key = sampleKey() }, &out);
    try std_testing.expectEqualSlices(u8, "", (try decode(out[0..empty.len], .server)).payload);
}

test "lengths: the three widths are written and read back whole" {
    var out: [70_014]u8 = undefined;
    const mid: [126]u8 = @splat(0xcd);
    const mid_frame = try encode(.{ .opcode = .binary, .payload = &mid, .mask_key = null }, &out);
    try expectHex(&.{ 0x82, 126, 0x00, 126 }, mid_frame[0..4]);

    const long: [70_000]u8 = @splat(0xef);
    const long_frame = try encode(.{ .opcode = .binary, .payload = &long, .mask_key = null }, &out);
    try expectHex(&.{ 0x82, 127, 0x00, 0x00, 0x00, 0x01, 0x11, 0x70 }, long_frame[0..8]);
    try std_testing.expectEqualSlices(
        u8,
        &long,
        (try decode(out[0..long_frame.len], .server)).payload,
    );
}

test "roles: the mask bit is how the wire says which end sent a frame" {
    var out: [16]u8 = undefined;
    const from_client = try encode(.{
        .opcode = .binary,
        .payload = hello,
        .mask_key = rfc_key,
    }, &out);
    const from_server = try encode(.{
        .opcode = .binary,
        .payload = hello,
        .mask_key = null,
    }, &out);
    // Each end accepts exactly what it should and refuses what it must not, and
    // the refusals are the same name in both directions because they are one
    // rule rather than two.
    try std_testing.expectEqualStrings(
        hello,
        (try decode(out[0..from_client.len], .server)).payload,
    );
    try std_testing.expectError(
        error.MaskingDisagreesWithRole,
        decode(out[0..from_client.len], .client),
    );
    try std_testing.expectEqualStrings(
        hello,
        (try decode(out[0..from_server.len], .client)).payload,
    );
    try std_testing.expectError(
        error.MaskingDisagreesWithRole,
        decode(out[0..from_server.len], .server),
    );
}

test "control frames: the 125-byte bound round-trips, and it is where §5.5 put it" {
    var out: [132]u8 = undefined;
    const at_bound: [header.max_control_payload]u8 = @splat(0x5a);
    const frame = try encode(.{
        .opcode = .ping,
        .payload = &at_bound,
        .mask_key = null,
    }, &out);
    // The frame is the payload plus the header, and `headerLen` is what a caller
    // sizing its buffer has to agree with, so the two are compared here rather
    // than each being trusted.
    const expected_len = header.max_control_payload +
        header.headerLen(header.max_control_payload, false);
    try std_testing.expectEqual(expected_len, frame.len);
    try std_testing.expectEqualSlices(
        u8,
        &at_bound,
        (try decode(out[0..frame.len], .server)).payload,
    );
}

/// A mask key for the one test that needs a key and does not care which.
fn sampleKey() [header.masking_key_length]u8 {
    return .{ 1, 2, 3, 4 };
}

/// Fails with both hexdumps rather than a bare `false`, so a failing golden
/// vector names the byte that differs.
fn expectHex(expected: []const u8, actual: []const u8) !void {
    if (std.mem.eql(u8, expected, actual)) return;
    std.debug.print("expected {s}\n     got {s}\n", .{
        &std.fmt.fmtSliceHexLower(expected),
        &std.fmt.fmtSliceHexLower(actual),
    });
    return error.WireFormatMismatch;
}
