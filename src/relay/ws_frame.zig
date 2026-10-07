//! The RFC 6455 carrier: the framing under one relay WebSocket message.
//!
//! This file is the facade every caller imports. It holds no logic of its own
//! and re-exports five siblings, which together are the whole carrier:
//!
//! - `ws_frame_types.zig` — the vocabulary: the opcodes, the role, the header as
//!   a value, the error set, and the two size limits that are not the same
//!   number.
//! - `ws_frame_header.zig` — the section 5.2 header in both directions, and the
//!   order its fields are checked in.
//! - `ws_frame_mask.zig` — the section 5.3 transform, which is its own inverse.
//! - `ws_frame_decode.zig` and `ws_frame_encode.zig` — one frame out of a buffer
//!   the caller owns, and one frame into it.
//! - `ws_frame_vectors.zig` — the RFC's own worked examples.
//!
//! # What is verified here and what is not
//!
//! Every golden in this tree's RFC 6455 tests is a byte string printed in the RFC
//! itself, and **no byte of an n0-computer/iroh WebSocket frame exists to pin
//! against**, because upstream hands its messages to a WebSocket library rather
//! than framing them in code this tree can read. So what these tests establish
//! is conformance to RFC 6455; interoperability with an iroh peer is a claim
//! this tree does not make and would need a captured trace to make.
//!
//! # A frame is not a message
//!
//! RFC 6455 section 5.2 frames a byte stream and section 5.4 lets one message be
//! several frames. What is here is the frame: FIN, an opcode, and a payload of
//! exactly the declared length. The reassembly that turns fragments into one
//! relay message belongs to the transport above this, which is also where the
//! rule that a continuation frame carries no opcode of its own lives.
//!
//! Nothing here opens a socket, reads a clock, or allocates. The one message a
//! relay sends is one frame carrying one `relay/frame.zig` message, so the two
//! sizes bound different things and are deliberately not the same number:
//! `relay/frame_types.zig`'s `max_packet_size` bounds a relay message's payload
//! and this module's `max_frame_size` bounds what is read off the socket.

const ws_frame_decode = @import("ws_frame_decode.zig");
const ws_frame_encode = @import("ws_frame_encode.zig");
const ws_frame_header = @import("ws_frame_header.zig");
const ws_frame_mask = @import("ws_frame_mask.zig");
const ws_frame_types = @import("ws_frame_types.zig");
const vectors = @import("ws_frame_vectors.zig");

// The vocabulary and the limits.

pub const Error = ws_frame_types.Error;
pub const Frame = ws_frame_types.Frame;
pub const MaskKey = ws_frame_types.MaskKey;
pub const Opcode = ws_frame_types.Opcode;
pub const Role = ws_frame_types.Role;
pub const mask_key_length = ws_frame_types.mask_key_length;
pub const max_control_payload = ws_frame_types.max_control_payload;
pub const max_frame_size = ws_frame_types.max_frame_size;
pub const max_header_length = ws_frame_types.max_header_length;
pub const min_header_length = ws_frame_types.min_header_length;
pub const headerLen = ws_frame_types.headerLen;
pub const fixedMaskKey = ws_frame_types.fixedMaskKey;

// The two directions, and the two transforms under them.

pub const Decoded = ws_frame_decode.Decoded;
pub const decode = ws_frame_decode.decode;
pub const Outgoing = ws_frame_encode.Outgoing;
pub const encodedLen = ws_frame_encode.encodedLen;
pub const encode = ws_frame_encode.encode;
pub const readHeader = ws_frame_header.read;
pub const writeHeader = ws_frame_header.write;
pub const mask = ws_frame_mask.apply;
pub const maskCopy = ws_frame_mask.copy;

// --- tests
const std = @import("std");
const std_testing = std.testing;

/// Writes a frame the way a client writes one: masked, under the section 5.7 key.
fn clientFrame(buf: []u8, opcode: Opcode, fin: bool, payload: []const u8) ![]const u8 {
    return encode(buf, .client, .{ .fin = fin, .opcode = opcode, .key = fixedMaskKey() }, payload);
}

/// Writes a frame the way a relay writes one, which is never masked.
fn serverFrame(buf: []u8, opcode: Opcode, fin: bool, payload: []const u8) ![]const u8 {
    return encode(buf, .server, .{ .fin = fin, .opcode = opcode, .key = fixedMaskKey() }, payload);
}

test "RFC 6455 section 5.7: every printed frame, read and written back" {
    // The worked examples the section prints, each in both directions and each
    // out of storage the other one did not touch. A golden that only decodes
    // would pass against a decoder that ignores half the header, and a golden
    // that only encodes would pass against a writer that invented its own bytes;
    // holding both, out of separate buffers, is what makes a byte string the
    // contract rather than a comment.

    // One buffer per golden. They share one only if every parse happens after
    // every read of the earlier one, and a test that depends on that ordering is
    // a test whose failure would be a buffer rather than a codec.
    var unmasked_buf: [16]u8 = undefined;
    var masked_buf: [16]u8 = undefined;
    var first_buf: [16]u8 = undefined;
    var last_buf: [16]u8 = undefined;
    var ping_buf: [16]u8 = undefined;
    var pong_buf: [16]u8 = undefined;
    var written: [64]u8 = undefined;

    // 0x81 0x05 "Hello", unmasked. A relay writes exactly this.
    const unmasked = try vectors.parseHex(&unmasked_buf, vectors.unmasked_text_hex);
    try std_testing.expectEqualSlices(u8, unmasked, try serverFrame(
        &written,
        .text,
        true,
        vectors.hello,
    ));
    const read_unmasked = try decode(unmasked, .client);
    try std_testing.expectEqual(Opcode.text, read_unmasked.frame.opcode);
    try std_testing.expect(read_unmasked.frame.fin);
    try std_testing.expect(!read_unmasked.frame.masked);
    try std_testing.expectEqualStrings(vectors.hello, read_unmasked.payload);

    // 0x81 0x85 37 fa 21 3d 7f 9f 4d 51 58: the same text masked. This is also
    // the frame RFC 6455 section 1.3 quotes in its opening handshake, so pinning
    // it here pins both sections at once — a mask key drawn from anywhere else
    // produces different bytes, and the section 1.3 pair that
    // `relay/http_upgrade.zig` holds would stop matching the same section.
    const key = fixedMaskKey();
    const masked = try vectors.parseHex(&masked_buf, vectors.masked_text_hex);
    try std_testing.expectEqualSlices(u8, masked, try clientFrame(
        &written,
        .text,
        true,
        vectors.hello,
    ));
    const read_masked = try decode(masked, .server);
    try std_testing.expect(read_masked.frame.masked);
    try std_testing.expectEqualSlices(u8, &key, &read_masked.frame.mask_key);
    // Still masked on the way out of `decode`: unmasking in place would change
    // bytes another decoded frame borrows from the same message buffer.
    var plain: [vectors.hello.len]u8 = undefined;
    try std_testing.expectEqualSlices(
        u8,
        vectors.hello,
        try maskCopy(read_masked.frame.mask_key, read_masked.payload, &plain),
    );

    // The fragmented pair: "Hel" with FIN clear, then a continuation with FIN
    // set. Two frames, one message, and this module stops at the frames.
    const first = try vectors.parseHex(&first_buf, vectors.fragment_first_hex);
    try std_testing.expectEqualSlices(u8, first, try serverFrame(&written, .text, false, "Hel"));
    const read_first = try decode(first, .client);
    try std_testing.expect(!read_first.frame.fin);
    try std_testing.expectEqual(Opcode.text, read_first.frame.opcode);
    try std_testing.expectEqualStrings("Hel", read_first.payload);

    const last = try vectors.parseHex(&last_buf, vectors.fragment_last_hex);
    try std_testing.expectEqualSlices(u8, last, try serverFrame(
        &written,
        .continuation,
        true,
        "lo",
    ));
    const read_last = try decode(last, .client);
    try std_testing.expect(read_last.frame.fin);
    try std_testing.expectEqual(Opcode.continuation, read_last.frame.opcode);
    try std_testing.expectEqualStrings("lo", read_last.payload);

    // The two control frames the section prints, which are the ones the ceiling
    // and the must-not-be-fragmented rule exist for.
    const ping = try vectors.parseHex(&ping_buf, vectors.ping_hex);
    try std_testing.expectEqualSlices(u8, ping, try serverFrame(
        &written,
        .ping,
        true,
        vectors.hello,
    ));
    const pong = try vectors.parseHex(&pong_buf, vectors.pong_hex);
    try std_testing.expectEqualSlices(u8, pong, try serverFrame(
        &written,
        .pong,
        true,
        vectors.hello,
    ));
    for ([_]struct { bytes: []const u8, control: Opcode }{
        .{ .bytes = ping, .control = .ping },
        .{ .bytes = pong, .control = .pong },
    }) |entry| {
        const read = try decode(entry.bytes, .client);
        try std_testing.expectEqual(entry.control, read.frame.opcode);
        try std_testing.expect(read.frame.opcode.isControl());
        try std_testing.expectEqual(@as(u64, vectors.hello.len), read.frame.payload_length);
        try std_testing.expectEqualStrings(vectors.hello, read.payload);
    }
}

test "RFC 6455 section 5.7: both extended length widths, at the boundary" {
    // 256 bytes is the smallest length the sixteen-bit form exists for, and
    // 64 KiB the smallest the sixty-four-bit form does. The section prints the
    // headers of both, and those four and ten bytes are what is pinned: what the
    // payloads hold is irrelevant to the examples.
    var header: [16]u8 = undefined;
    var written: [16]u8 = undefined;

    const binary_256 = try vectors.parseHex(&header, vectors.binary_256_header_hex);
    const width_256 = try writeHeader(&written, ws_frame_types.header(
        true,
        .binary,
        false,
        0x0100,
        @splat(0),
    ));
    try std_testing.expectEqual(binary_256.len, width_256);
    try std_testing.expectEqualSlices(u8, binary_256, written[0..width_256]);
    try std_testing.expectEqual(@as(u64, 256), (try readHeader(binary_256)).payload_length);

    const binary_64k = try vectors.parseHex(&header, vectors.binary_64k_header_hex);
    const width_64k = try writeHeader(&written, ws_frame_types.header(
        true,
        .binary,
        false,
        0x1_0000,
        @splat(0),
    ));
    try std_testing.expectEqual(binary_64k.len, width_64k);
    try std_testing.expectEqualSlices(u8, binary_64k, written[0..width_64k]);
    try std_testing.expectEqual(@as(u64, 0x1_0000), (try readHeader(binary_64k)).payload_length);

    // The seven-bit width ends where the sixteen-bit one begins, which is the
    // only place the two rules can be told apart by a number.
    try std_testing.expectEqual(
        @as(usize, 2),
        ws_frame_types.headerLen(ws_frame_types.max_control_payload, false),
    );
    try std_testing.expectEqual(
        @as(usize, 4),
        ws_frame_types.headerLen(ws_frame_types.max_control_payload + 1, false),
    );

    // A whole frame at each of the two extended widths, so `encodedLen` is held
    // to the bytes that came out rather than to a rule about them. The bodies
    // are on the heap because 64 KiB of stack in a Debug build is a test that
    // fails for a reason that has nothing to do with WebSockets.
    const body = try std_testing.allocator.alloc(u8, 0x1_0000);
    defer std_testing.allocator.free(body);
    vectors.fillPattern(body);
    for ([_]usize{ 0x0100, 0x1_0000 }) |length| {
        const buf = try std_testing.allocator.alloc(
            u8,
            encodedLen(length, .server),
        );
        defer std_testing.allocator.free(buf);
        const frame = try serverFrame(buf, .binary, true, body[0..length]);
        try std_testing.expectEqual(encodedLen(length, .server), frame.len);
        const read = try decode(frame, .client);
        try std_testing.expectEqual(@as(usize, length), read.payload.len);
        try std_testing.expectEqualSlices(u8, body[0..length], read.payload);
    }
}

test "masking: a sweep of lengths and both roles over one payload" {
    // Every length from nothing to three times the key, written both ways and
    // read back the way each role must read it. This is the sweep that would
    // catch a writer that masks a relay's frames anyway and a reader that lets a
    // relay mask them, which are the same bug seen from two ends.
    const key = fixedMaskKey();
    var payload: [3 * ws_frame_types.mask_key_length]u8 = undefined;
    vectors.fillPattern(&payload);

    for (0..payload.len + 1) |length| {
        var client_buf: [payload.len + ws_frame_types.max_header_length]u8 = undefined;
        const client_frame = try clientFrame(&client_buf, .binary, true, payload[0..length]);
        try std_testing.expectEqual(encodedLen(length, .client), client_frame.len);

        var server_buf: [payload.len + ws_frame_types.max_header_length]u8 = undefined;
        const server_frame = try serverFrame(&server_buf, .binary, true, payload[0..length]);
        try std_testing.expectEqual(encodedLen(length, .server), server_frame.len);

        // A relay's frame is four bytes shorter, because it carries no mask key,
        // and the mask bit in its second byte is clear where a client's is set.
        // Every length here is inside the seven-bit field, so that byte is the
        // mask bit over the length and nothing else.
        try std_testing.expectEqual(client_frame.len - 4, server_frame.len);
        try std_testing.expectEqual(@as(u8, 0x00), server_frame[1] & 0b1000_0000);
        try std_testing.expectEqual(@as(u8, 0b1000_0000), client_frame[1] & 0b1000_0000);
        try std_testing.expectEqual(@as(u8, @intCast(length)), client_frame[1] & 0b0111_1111);
        try std_testing.expectEqual(client_frame[1] & 0b0111_1111, server_frame[1]);

        // Each end refuses what the other would send it.
        try std_testing.expectError(error.MaskedServerFrame, decode(client_frame, .client));
        try std_testing.expectError(error.UnmaskedClientFrame, decode(server_frame, .server));

        const from_client = try decode(client_frame, .server);
        try std_testing.expectEqualSlices(u8, &key, &from_client.frame.mask_key);
        var plain: [payload.len]u8 = undefined;
        try std_testing.expectEqualSlices(
            u8,
            payload[0..length],
            try maskCopy(key, from_client.payload, &plain),
        );
        const from_server = try decode(server_frame, .client);
        try std_testing.expectEqualSlices(u8, payload[0..length], from_server.payload);
    }
}

test "the two size answers are different, and the boundary belongs to one" {
    // `max_frame_size` is the payload a frame may carry, so a payload of exactly
    // that is the largest legal one there is and the only question left is
    // whether the buffer holds it. It is `error.BufferFull`, never
    // `error.FrameTooLarge`, and this is the test that says so.
    const limit = max_frame_size;
    try std_testing.expectEqual(@as(usize, 1024 * 1024), limit);

    // The header alone is legal at the bound, so a caller that only wants to
    // know what a peer declared can read it without holding the payload behind
    // it. Fourteen bytes: two, an eight-byte length, and a mask key.
    var header: [ws_frame_types.max_header_length]u8 = undefined;
    const width = try writeHeader(&header, ws_frame_types.header(
        true,
        .binary,
        true,
        limit,
        fixedMaskKey(),
    ));
    try std_testing.expectEqual(@as(usize, 14), width);
    const at_bound = try readHeader(header[0..width]);
    try std_testing.expectEqual(@as(u64, limit), at_bound.payload_length);

    const payload = try std_testing.allocator.alloc(u8, limit);
    defer std_testing.allocator.free(payload);
    vectors.fillPattern(payload);
    const needed = encodedLen(limit, .client);
    try std_testing.expectEqual(limit + ws_frame_types.max_header_length, needed);

    // A buffer one byte too short for that frame is a small buffer.
    const short = try std_testing.allocator.alloc(u8, needed - 1);
    defer std_testing.allocator.free(short);
    const outgoing: Outgoing = .{ .fin = true, .opcode = .binary, .key = fixedMaskKey() };
    try std_testing.expectError(error.BufferFull, encode(short, .client, outgoing, payload));

    // A buffer exactly big enough is not short, which is the other half of the
    // claim: the bound is a frame this module admits and writes.
    const exact = try std_testing.allocator.alloc(u8, needed);
    defer std_testing.allocator.free(exact);
    try std_testing.expectEqual(
        needed,
        (try encode(exact, .client, outgoing, payload)).len,
    );

    // One byte over the bound is a different claim entirely, and it is decided
    // before the writer exists: the buffer one byte short above was a small
    // buffer, and this is a frame that cannot exist here at any size. The buffer
    // is big enough, so nothing but the rule can refuse it.
    const over = try std_testing.allocator.alloc(u8, needed + 1);
    defer std_testing.allocator.free(over);
    const too_big = try std_testing.allocator.alloc(u8, limit + 1);
    defer std_testing.allocator.free(too_big);
    @memset(over, 0xaa);
    try std_testing.expectError(error.FrameTooLarge, encode(over, .client, outgoing, too_big));
    for (over) |byte| try std_testing.expectEqual(@as(u8, 0xaa), byte);
}

test "a header's own rules come before the size it declares" {
    // Three orderings, all one ordering: the width rules answer a header before
    // `error.FrameTooLarge` is considered, and both answer it before the payload
    // behind it is asked for. A caller therefore never learns what a later rule
    // would have said about a header an earlier one already refused.
    //
    // The header that breaks two at once is the sixty-four-bit length with its
    // top bit set: it is over `error.ReservedLengthBit` and over
    // `max_frame_size` by an enormous margin, and it answers with the first. The
    // non-minimal spellings below cannot also be over the limit, because
    // `max_frame_size` is above the largest a sixteen-bit field spells, so the
    // overlap the ordering matters for is this one and the assertions beside it
    // fix where the boundary between the rules actually is.
    const top_bit = [_]u8{ 0x82, 0x7f, 0x80, 0, 0, 0, 0, 0, 0, 0 };
    try std_testing.expectError(error.ReservedLengthBit, readHeader(&top_bit));
    try std_testing.expectError(error.ReservedLengthBit, decode(&top_bit, .client));

    // Five bytes in a sixty-four-bit field and in a sixteen-bit field: over
    // nothing at all, and refused for the spelling rather than accepted as the
    // shorter header it duplicates.
    try std_testing.expectError(
        error.NonMinimalLength,
        readHeader(&[_]u8{ 0x82, 0x7f, 0, 0, 0, 0, 0, 0, 0, 5 }),
    );
    try std_testing.expectError(
        error.NonMinimalLength,
        readHeader(&[_]u8{ 0x82, 0x7e, 0, 5 }),
    );
    // The same five bytes spelled minimally are read, which is what makes the
    // two refusals above about the spelling rather than about the length.
    try std_testing.expectEqual(
        @as(u64, 5),
        (try readHeader(&[_]u8{ 0x82, 0x05 })).payload_length,
    );

    // `max_frame_size + 1` spelled minimally, with nothing behind it: the
    // header is well formed and one byte over the limit, so the size is the
    // answer, and it comes before the payload — which is what makes the two
    // refusals above about the header rather than about a missing body.
    const over_the_bound = [_]u8{ 0x82, 0x7f, 0, 0, 0, 0, 0, 0x10, 0, 1 };
    try std_testing.expectEqual(
        @as(u64, max_frame_size + 1),
        std.mem.readInt(u64, over_the_bound[2..10], .big),
    );
    try std_testing.expectError(error.FrameTooLarge, readHeader(&over_the_bound));
    try std_testing.expectError(error.FrameTooLarge, decode(&over_the_bound, .client));

    // The three width boundaries, each on the legal side and each one below it on
    // the non-minimal side, so the rule is fixed from both sides.
    try std_testing.expectEqual(
        @as(u64, 126),
        (try readHeader(&[_]u8{ 0x82, 0x7e, 0, 126 })).payload_length,
    );
    try std_testing.expectError(
        error.NonMinimalLength,
        readHeader(&[_]u8{ 0x82, 0x7e, 0, 125 }),
    );
    try std_testing.expectEqual(
        @as(u64, 0xffff),
        (try readHeader(&[_]u8{ 0x82, 0x7e, 0xff, 0xff })).payload_length,
    );
    try std_testing.expectError(
        error.NonMinimalLength,
        readHeader(&[_]u8{ 0x82, 0x7f, 0, 0, 0, 0, 0, 0, 0xff, 0xff }),
    );
    try std_testing.expectEqual(
        @as(u64, 0x1_0000),
        (try readHeader(&[_]u8{ 0x82, 0x7f, 0, 0, 0, 0, 0, 0x01, 0, 0 })).payload_length,
    );
}

test "the control-frame ceiling and the must-not-be-fragmented rule" {
    // 125 is a payload and 126 is not, and the seven-bit field says so on its
    // own: a control frame declaring 126 is refused from the first two bytes and
    // the two extended length bytes behind it are never read, which is why a
    // two-byte header is enough to provoke it.
    try std_testing.expectEqual(@as(usize, 125), max_control_payload);

    var at_ceiling: [max_control_payload]u8 = undefined;
    vectors.fillPattern(&at_ceiling);
    var out: [max_control_payload + ws_frame_types.max_header_length]u8 = undefined;
    const ping = try serverFrame(&out, .ping, true, &at_ceiling);
    try std_testing.expectEqual(
        @as(usize, ws_frame_types.min_header_length),
        ping.len - at_ceiling.len,
    );
    const read_ping = try decode(ping, .client);
    try std_testing.expectEqual(@as(usize, max_control_payload), read_ping.payload.len);
    try std_testing.expectEqualSlices(u8, &at_ceiling, read_ping.payload);

    // One byte over, spelled by hand twice over, because no writer here will
    // produce it.
    try std_testing.expectError(
        error.ControlFrameTooLong,
        readHeader(&[_]u8{ 0x89, 126 }),
    );
    try std_testing.expectError(
        error.ControlFrameTooLong,
        readHeader(&[_]u8{ 0x89, 127, 0, 0, 0, 0, 0, 0, 0, 1 }),
    );
    // And the writer refuses it before the writer exists, so the caller's buffer
    // is exactly as it was handed over.
    const too_long = try std_testing.allocator.alloc(u8, max_control_payload + 1);
    defer std_testing.allocator.free(too_long);
    vectors.fillPattern(too_long);
    var refused: [8]u8 = undefined;
    @memset(&refused, 0xbb);
    try std_testing.expectError(
        error.ControlFrameTooLong,
        serverFrame(&refused, .ping, true, too_long),
    );
    for (refused) |byte| try std_testing.expectEqual(@as(u8, 0xbb), byte);

    // A control frame with FIN clear, refused before its length is looked at.
    try std_testing.expectError(
        error.FragmentedControlFrame,
        readHeader(&[_]u8{ 0x09, 0x00 }),
    );
    try std_testing.expectError(
        error.FragmentedControlFrame,
        serverFrame(refused[0..2], .ping, false, ""),
    );
}

test "the reserved bits and the opcodes this build has no name for" {
    // RSV1 through RSV3 are one rule: an extension changed the meaning of this
    // payload and none was negotiated, so a set one is refused whichever bit it
    // was.
    for ([_]u8{ 0b0100_0000, 0b0010_0000, 0b0001_0000 }) |reserved| {
        try std_testing.expectError(
            error.ReservedBitSet,
            readHeader(&[_]u8{ 0x80 | reserved, 0x00 }),
        );
    }
    // Five opcodes RFC 6455 does not define, refused by name rather than read as
    // whichever value was nearest.
    for ([_]u8{ 0x03, 0x04, 0x07, 0x0b, 0x0f }) |opcode| {
        try std_testing.expectError(error.UnknownOpcode, readHeader(&[_]u8{
            0x80 | opcode,
            0x00,
        }));
        try std_testing.expectEqual(@as(?Opcode, null), Opcode.fromInt(opcode));
    }
    // The six it does define, with the control range exactly the top three.
    const table = [_]struct { opcode: Opcode, control: bool }{
        .{ .opcode = .continuation, .control = false },
        .{ .opcode = .text, .control = false },
        .{ .opcode = .binary, .control = false },
        .{ .opcode = .close, .control = true },
        .{ .opcode = .ping, .control = true },
        .{ .opcode = .pong, .control = true },
    };
    for (table) |entry| {
        const read = try readHeader(&[_]u8{ 0x80 | entry.opcode.toInt(), 0x00 });
        try std_testing.expectEqual(entry.opcode, read.opcode);
        try std_testing.expectEqual(entry.control, entry.opcode.isControl());
        try std_testing.expectEqual(entry.opcode, Opcode.fromInt(entry.opcode.toInt()).?);
    }
    try std_testing.expectEqual(@as(u8, 0x0a), Opcode.pong.toInt());
    try std_testing.expectEqual(@as(?Opcode, null), Opcode.fromInt(0xff));
}
