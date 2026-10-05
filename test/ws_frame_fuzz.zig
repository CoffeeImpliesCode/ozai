//! Fuzz target for the RFC 6455 carrier: `relay/ws_frame.zig` and the five
//! siblings under `relay/` that own its logic.
//!
//! One target file and one corpus directory per decoder: `zig build fuzz`
//! replays the corpus, and `zig build fuzz --fuzz=<N>` hands the same corpus
//! to Zig's coverage-guided fuzzer and lets it mutate for N iterations.
//!
//! The named refusals are a table of their own in `ws_frame_refusals.zig`, which
//! this entry point imports and whose every row the second test below walks.
//! The split is by responsibility: this file drives the fuzz and holds the
//! oracles a mutation is walked through, and that file holds the fixed byte
//! strings and the names they must be refused with.
//!
//! **The decoder is the production one, reached through the `ozai` module and
//! not re-derived here.** A fuzz target carrying its own header reader would
//! prove something about the copy, and the copy is what a mutation would be
//! mutating. Every call below is a call into `ozai.relay_ws_frame`.
//!
//! # What is checked
//!
//! 1. **Refusal, by name.** `decode` is offered every fuzz input in both roles
//!    and `readHeader` is offered it as well, and each refusal is held to the
//!    set that owns it. That is what makes the three refusal families
//!    distinguishable: a header rule reached through `decode` would mean the
//!    role check had run before the header, which is the order
//!    `relay/ws_frame_header.zig` says is the contract.
//! 2. **The mask transform, in both roles.** A relay's frame is its payload on
//!    the wire and a node's is the payload under the key, and the transform is
//!    only ever reached on the encode and decode path — which is exactly where a
//!    key index running one-based, or a role that masked the wrong way, or a
//!    writer that unmasked its own output would show. Every round trip here
//!    goes out as one role and comes back as the other.
//! 3. **The three length widths.** `headerLen` is a function of the length and
//!    the mask bit and of nothing else, so the width a header was written at is
//!    the width the reader found, on all three spellings and at each boundary
//!    between them.
//!
//! # What is not pinned
//!
//! No byte of an n0-computer/iroh WebSocket frame exists to pin against, because
//! upstream frames its messages inside a library rather than in code this tree
//! can read; `relay/ws_frame.zig` says so and `relay/ws_frame_vectors.zig` holds
//! the RFC's own worked examples instead. What these oracles establish is
//! conformance to RFC 6455. Interoperability with an iroh peer is not claimed
//! here and would need a captured trace.

const std = @import("std");
const ozai = @import("ozai");
const ws = ozai.relay_ws_frame;
const t = std.testing;
const cases = @import("ws_frame_refusals.zig");

/// Seeds are the bytes off a peer's socket, one frame at a time.
///
/// The first six are the worked examples RFC 6455 section 5.7 prints, so a
/// mutation starts from something the standard itself wrote and from the exact
/// frame section 1.3 quotes in its handshake. The rest are the shapes the
/// header has a rule for and no legal frame has: nothing at all, one byte of a
/// header, a masked header with no key behind it, a header with no payload
/// behind it, a length spelled in a wider field than it needs at each of the two
/// wider widths, and a length with the top bit of the sixty-four-bit field set.
///
/// They are held inline rather than as `@embedFile`s under
/// `test/corpus/ws_frame/`, because this slice was given exactly three files and
/// a corpus directory would be a fourth. The names on each line are the file
/// names a `test/corpus/ws_frame/` carries for them.
const corpus = [_][]const u8{
    &.{}, // empty: no header at all
    &.{ 0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f }, // unmasked_text: RFC 5.7
    &.{ 0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58 }, // masked_text: RFC 5.7
    &.{ 0x01, 0x03, 0x48, 0x65, 0x6c }, // fragment_first: RFC 5.7
    &.{ 0x80, 0x02, 0x6c, 0x6f }, // fragment_last: RFC 5.7
    &.{ 0x89, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f }, // ping: RFC 5.7
    &.{ 0x8a, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f }, // pong: RFC 5.7
    &.{ 0x82, 0x7e, 0x01, 0x00 }, // width_16_header: RFC 5.7, with no body behind it
    &.{ 0x82, 0x7f, 0, 0, 0, 0, 0, 0x01, 0, 0 }, // width_64_header: RFC 5.7, likewise
    &.{0x81}, // one_byte: half a header
    &.{ 0x81, 0x85 }, // masked_no_key: a mask bit with no key behind it
    &.{ 0x81, 0x05 }, // header_no_payload: a legal header and no body
    &.{ 0x81, 0x7e, 0x00, 0x7d }, // nonminimal_16: 125 in the sixteen-bit field
    &.{ 0x81, 0x7f, 0, 0, 0, 0, 0, 0, 0, 0x01 }, // reserved_length_bit: the top bit set
    &.{ 0xc1, 0x00 }, // rsv1_set: an extension nobody negotiated
    &.{ 0x83, 0x00 }, // reserved_opcode: 3 is one of the three RFC reserves
    &.{ 0x8b, 0x00 }, // undefined_opcode: 11 is above the six the RFC defines
    &.{ 0x09, 0x00 }, // fragmented_control: a ping with FIN clear
    &.{ 0x89, 0x7e, 0x00, 0x00 }, // control_too_long: 126 is over the 125 ceiling
};

/// Long enough for a seed and for a mutated input to still reach a check it was
/// not grown for, and short enough that one run is bounded by the window rather
/// than by the fuzzer.
const input_buffer_len = 128;

/// The widest payload a round trip carries here.
///
/// The seven-bit width ends at 125 and the sixteen-bit one begins there, so the
/// first two of RFC 6455's three widths are both reached inside this. The
/// sixty-four-bit one is reached on headers alone by `checkWidths`, because a
/// 64 KiB payload is a heap buffer a fuzz iteration would pay for to check ten
/// bytes of header rule.
const max_payload = 256;

/// The lengths at and either side of each boundary between RFC 6455's three
/// length widths, plus the two the rules are stated in terms of.
const width_lengths = [_]u64{ 0, 1, 124, 125, 126, 127, 128, 255, 256, 65_535, 65_536 };

/// The fuzzer keeps one of these by pointer for the whole run, so it is empty by
/// design: everything the oracle needs is comptime.
const Context = struct {};

test "ws frame decode" {
    // A fuzz test is a plain test to a plain build. Without `-ffuzz` the runner
    // walks the corpus instead of handing it to the fuzzer, which is what makes
    // a bare `zig build fuzz` a bounded gate rather than an empty step.
    try t.fuzz(Context{}, testOne, .{ .corpus = &corpus });
}

// The tables are read here rather than left as prose. They pin *which* name
// each refusal gets, and the fuzz oracle in `checkRefusal` below pins only
// which *set* a name belongs to — a header rule that started answering
// `UnknownOpcode` where RFC 6455 says `ReservedBitSet` would pass every
// mutation and fail nothing.
//
// It is a plain test and not part of the fuzz body because the rows are fixed
// byte strings rather than inputs to mutate: a fuzzer would rewrite the very
// bytes that make the expectation, and the expectation is the point. **Every
// row of both tables is walked on every run** — a table that compiles and is
// never read is a list of claims with nothing behind them, which is the one
// thing a fuzz target may not be.
test "each refusal is the name the RFC gives it, not another in its set" {
    for (cases.decode_cases) |case| {
        try t.expectError(case.expected, ws.decode(case.bytes, case.role));
    }
    for (cases.header_cases) |case| {
        try t.expectError(case.expected, ws.readHeader(case.bytes));
    }
}

fn testOne(_: Context, smith: *t.Smith) anyerror!void {
    var buffer: [input_buffer_len]u8 = undefined;
    // `in` is the corpus entry verbatim while the corpus is replayed, and null
    // when the fuzzer drives, in which case `slice` consumes its input.
    const bytes = if (smith.in) |replay| replay else buffer[0..smith.slice(&buffer)];
    var payload: [max_payload]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = bytesAt(bytes, index);
    try checkRefusal(bytes);
    try checkRoles(payload[0..seedLength(bytes, 0, max_payload + 1)]);
    // The key index wraps on four, so a length that crosses a wrap boundary is
    // the one a one-based index would get wrong. Three keys is twelve.
    try checkRoles(payload[0..seedLength(bytes, 1, 3 * ws.mask_key_length + 1)]);
    try checkWidths();
    try checkControlRules(payload[0..@min(payload.len, ws.max_control_payload + 1)]);
}

/// Every fuzz input offered to `decode` in both roles and to `readHeader`, and
/// each refusal held to the set that owns it.
fn checkRefusal(bytes: []const u8) !void {
    for ([_]ws.Role{ .server, .client }) |role| {
        if (ws.decode(bytes, role)) |decoded| {
            // A frame that decoded is a frame that holds together: the header it
            // found is the width `headerLen` gives that length and mask bit, the
            // payload is exactly as long as the header claimed, and the payload
            // really is there.
            try checkDecoded(decoded, role);
        } else |err| {
            // Oracle: ownership, and it is role-aware because the two role
            // refusals *belong to `decode`*: `ws_frame_types.Error` has eleven
            // names, the eight header rules are eight of them, and the ninth
            // `decode` can reach is the one this role is entitled to be
            // refused with. RFC 6455 section 5.1 puts the mask obligation on
            // the sender, so a reader is told about the frame the peer sent:
            // `UnmaskedClientFrame` from a `.server` reader and
            // `MaskedServerFrame` from a `.client` one, and `Role` names the
            // end that is *reading*. `BufferFull` is the eleventh and `decode`
            // can never answer with it — it belongs to the writer and is about
            // the caller's storage rather than about a frame.
            //
            // So a header rule answered with a role name, the *other* role's
            // name, or `BufferFull` all fail here, and a role name answered
            // through `readHeader` below fails there.
            try t.expect(switch (err) {
                error.UnmaskedClientFrame => role == .server,
                error.MaskedServerFrame => role == .client,
                else => isHeaderRefusal(err),
            });
        }
    }
    if (ws.readHeader(bytes)) |header| {
        // Oracle: the width, on the header alone. `headerLen` is derived from
        // the length and the mask bit and from nothing else, so a header that
        // names its own width twice cannot.
        try t.expectEqual(ws.headerLen(header.payload_length, header.masked), header.header_length);
    } else |err| {
        // Oracle: ownership again, from the other side. `readHeader` has no role
        // argument, so a refusal of either role's name here would mean the role
        // check had moved into the header codec.
        try t.expect(isHeaderRefusal(err));
    }
}

/// One frame read back: every claim the header makes about itself.
fn checkDecoded(decoded: ws.Decoded, role: ws.Role) !void {
    const width = ws.headerLen(decoded.frame.payload_length, decoded.frame.masked);
    try t.expectEqual(width, decoded.frame.header_length);
    try t.expectEqual(@as(u64, decoded.payload.len), decoded.frame.payload_length);
    try t.expect(decoded.frame.header_length <= decoded.payload.len + ws.max_header_length);
    // The mask bit is what a role is checked against, so the two must be the
    // same fact read twice. **The polarity is the other way round from the
    // name**, and this is where it goes wrong: RFC 6455 section 5.1 makes it a
    // client's frame that is masked and a server's that is not, and `Role`
    // names the end that is *reading* — `.server` is a relay reading a
    // client's frames — so a frame read as `.server` is masked and one read as
    // `.client` is not. `ws_frame_types.zig` says "the value names this end,
    // not the peer" in so many words, and this is the assertion that follows
    // from it.
    try t.expectEqual(role == .server, decoded.frame.masked);
    // A frame with the mask bit clear carries no key, so its four key bytes are
    // zero: a header that read them anyway would be reading bytes of its own
    // making, and a caller that trusted them would be trusting that.
    const zero_key: ws.MaskKey = @splat(0);
    try t.expect(decoded.frame.masked or std.meta.eql(decoded.frame.mask_key, zero_key));
}

/// One payload written both ways and read the way each role must read it.
///
/// This is where the mask transform is exercised, and it is exercised only on
/// the encode and decode path: nothing here writes an expected byte string by
/// hand, so a transform that was wrong would have to be wrong in the encoder and
/// the decoder in the same way to escape.
fn checkRoles(payload: []const u8) !void {
    const key = ws.fixedMaskKey();
    var client_buf: [ws.max_header_length + max_payload]u8 = undefined;
    var server_buf: [ws.max_header_length + max_payload]u8 = undefined;
    var plain: [max_payload]u8 = undefined;

    const client = try ws.encode(
        &client_buf,
        .client,
        .{ .fin = true, .opcode = .binary, .key = key },
        payload,
    );
    const server = try ws.encode(
        &server_buf,
        .server,
        .{ .fin = true, .opcode = .binary, .key = key },
        payload,
    );

    // Oracle: size. `encodedLen` is the byte count a caller sizes a buffer from,
    // and the two roles differ by the mask key and by nothing else.
    try t.expectEqual(ws.encodedLen(payload.len, .client), client.len);
    try t.expectEqual(ws.encodedLen(payload.len, .server), server.len);
    try t.expectEqual(client.len - ws.mask_key_length, server.len);

    // Oracle: the mask bit is the whole of the difference between the two ends.
    // The second byte of a frame is the mask bit over a seven-bit length here,
    // because every payload this round trip carries is inside that field.
    try t.expectEqual(@as(u8, 0b1000_0000), client_buf[1] & 0b1000_0000);
    try t.expectEqual(@as(u8, 0x00), server_buf[1] & 0b1000_0000);

    // Oracle: each end refuses what the other sends. This is RFC 6455 section
    // 5.1 and it is the only rule `Role` exists for.
    try t.expectError(error.MaskedServerFrame, ws.decode(client, .client));
    try t.expectError(error.UnmaskedClientFrame, ws.decode(server, .server));

    // Oracle: the transform, node side. What arrives is the payload under the
    // key, and the key is in the frame and not supplied by the reader.
    const from_client = try ws.decode(client, .server);
    try checkDecoded(from_client, .server);
    try t.expect(from_client.frame.masked);
    try t.expect(from_client.frame.fin);
    try t.expectEqual(ws.Opcode.binary, from_client.frame.opcode);
    try t.expectEqualSlices(u8, &key, &from_client.frame.mask_key);
    try t.expectEqualSlices(u8, payload, try ws.maskCopy(key, from_client.payload, &plain));

    // Oracle: the transform, relay side. A relay's frame is its payload on the
    // wire, so there is nothing to undo and the caller's bytes come back.
    const from_server = try ws.decode(server, .client);
    try checkDecoded(from_server, .client);
    try t.expect(!from_server.frame.masked);
    try t.expectEqualSlices(u8, payload, from_server.payload);

    // Oracle: the transform is its own inverse, checked on the bytes that came
    // off the wire rather than on a copy. The key wraps on four, so a payload
    // whose length is a multiple of four is where an index running one-based
    // shows up: it produces a last byte that is wrong rather than a frame of
    // the wrong length.
    @memcpy(plain[0..payload.len], from_client.payload);
    ws.mask(key, plain[0..payload.len]);
    try t.expectEqualSlices(u8, payload, plain[0..payload.len]);
}

/// The three length widths and the boundaries between them, on headers alone.
fn checkWidths() !void {
    var buf: [ws.max_header_length]u8 = undefined;
    const key = ws.fixedMaskKey();
    for ([_]bool{ false, true }) |masked| {
        for (width_lengths) |length| {
            const written = try ws.writeHeader(&buf, headerFor(.binary, masked, length));
            // Oracle: the width is a function of the length and the mask bit, so
            // it is the same number before the write and after the read.
            try t.expectEqual(ws.headerLen(length, masked), written);
            const read = try ws.readHeader(buf[0..written]);
            try t.expectEqual(length, read.payload_length);
            try t.expectEqual(written, read.header_length);
            try t.expectEqual(masked, read.masked);
            if (masked) try t.expectEqualSlices(u8, &key, &read.mask_key);
        }
    }

    // Oracle: the size rule, at its exact boundary. `max_frame_size` is the
    // largest payload a frame may carry here, so a header at the ceiling is
    // admitted by the size rule and one byte over it is `error.FrameTooLarge`,
    // and both are decided before the payload is asked for — which is why the
    // frame over the ceiling is refused here rather than being told its payload
    // is missing.
    const over = try ws.writeHeader(&buf, headerFor(.binary, false, ws.max_frame_size + 1));
    try t.expectError(error.FrameTooLarge, ws.readHeader(buf[0..over]));

    const at = try ws.writeHeader(&buf, headerFor(.binary, false, ws.max_frame_size));
    try t.expectError(error.UnexpectedEnd, ws.decode(buf[0..at], .client));
}

/// The two control-frame rules on the way out, which are the same two the reader
/// applies and are decided from the payload and the FIN bit before a byte is
/// written.
fn checkControlRules(payload: []const u8) !void {
    var buf: [ws.max_header_length + max_payload]u8 = undefined;
    const key = ws.fixedMaskKey();
    try t.expectError(error.ControlFrameTooLong, ws.encode(
        &buf,
        .server,
        .{ .fin = true, .opcode = .ping, .key = key },
        payload,
    ));
    try t.expectError(error.FragmentedControlFrame, ws.encode(
        &buf,
        .client,
        .{ .fin = false, .opcode = .pong, .key = key },
        payload[0..1],
    ));
    // And the ceiling itself is not too long: 125 bytes is the largest control
    // payload, so the refusal above is a refusal of one byte, not of a shape.
    if (payload.len == ws.max_control_payload) {
        try t.expectError(error.BufferFull, ws.encode(
            buf[0..0],
            .server,
            .{ .fin = true, .opcode = .ping, .key = key },
            payload,
        ));
    }
}

/// A header value for a `payload_length`-byte frame, with the width derived by
/// `headerLen` rather than written out, because a caller that filled the field
/// in by hand would be asserting the width instead of deriving it.
fn headerFor(opcode: ws.Opcode, masked: bool, payload_length: u64) ws.Frame {
    return .{
        .fin = true,
        .opcode = opcode,
        .masked = masked,
        .payload_length = payload_length,
        .mask_key = ws.fixedMaskKey(),
        .header_length = ws.headerLen(payload_length, masked),
    };
}

/// Whether `err` is one of the eight names the header codec owns.
fn isHeaderRefusal(err: ws.Error) bool {
    return switch (err) {
        error.UnexpectedEnd,
        error.ReservedBitSet,
        error.UnknownOpcode,
        error.ControlFrameTooLong,
        error.FragmentedControlFrame,
        error.NonMinimalLength,
        error.ReservedLengthBit,
        error.FrameTooLarge,
        => true,
        error.UnmaskedClientFrame,
        error.MaskedServerFrame,
        error.BufferFull,
        => false,
    };
}

/// A payload length the fuzz bytes chose out of `span`, as a count. The
/// conversion is spelled out because the seed byte is a `u8` and a length is a
/// `usize`, and the two meeting in a `%` is where the widths would otherwise be
/// left to a peer type resolution.
fn seedLength(bytes: []const u8, index: usize, span: usize) usize {
    return @as(usize, bytesAt(bytes, index)) % span;
}

/// `bytes` at `index`, or zero past its end. A seed shorter than a payload is a
/// case and not a fault, and zero is a value every table here has an entry for.
fn bytesAt(bytes: []const u8, index: usize) u8 {
    return if (index < bytes.len) bytes[index] else 0;
}
