//! Writing a relay frame: the size it will occupy, the bytes it is, and the
//! sweep that refuses it before a byte is written.
//!
//! The frame itself is `relay/frame_types.zig`, the bytes under it are
//! `relay/frame_writer.zig`, and the way back in is
//! `relay/frame_decode.zig`. `relay/frame.zig` re-exports the lot.
//!
//! Captured from n0-computer/iroh at commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8:
//!
//! - `iroh-relay/src/protos/relay.rs:263` — the fixed-width payload writers,
//!   all big-endian.
//! - `iroh-relay/src/protos/relay.rs:328` — upstream's `write_to`, which writes
//!   into a `BytesMut` that grows, and is the whole difference between the two
//!   ports.
//! - `iroh-relay/src/protos/handshake.rs:558-561` — the denial's postcard write.
//!
//! # A relay can always send what it decided to send
//!
//! `out` is the caller's buffer and is never grown: a frame that does not fit is
//! `error.BufferFull`, the same rule `wire/postcard.zig` follows and for the same
//! reason, that one scratch buffer can serve a whole connection. `encode`
//! appends into it and keeps no reference to the message it was given, so the
//! payload buffers a caller encoded from may be reused the moment it returns.
//! The slice it hands back is `out[0..written]` — the same memory, not a copy of
//! it — so it aliases the caller's buffer and is invalidated by whatever the
//! caller next writes there.
//!
//! **Every bound a frame has to meet is checked before the writer exists.** That
//! is what `checkEncodable` is: a sweep over the arms whose length their own type
//! does not fix, each refused by name, so a refusal leaves `out` exactly as the
//! caller handed it over rather than holding the frame type and no payload. A
//! caller that kept the frame type and lost the payload would find a partial
//! frame in its own buffer, and a partial denial is a denial whose reason stops
//! early.
//!
//! The two refusals the writer itself makes are different, and the difference is
//! what is in the buffer afterwards: **`error.BufferFull` and
//! `error.ZeroSegmentSize` leave a partial frame** — the frame type, and whatever
//! of the payload fitted before the writer ran out — because both are found once
//! bytes are down. Neither hands back a slice, so a caller must discard `out` on
//! any error rather than send what happens to be in it.
//!
//! Nothing is allocated, nothing is read from a global, and no clock or I/O is
//! touched, so the call is reentrant over distinct buffers and needs no
//! synchronization beyond the caller's own.

const std = @import("std");

const key = @import("../base/key.zig");
const postcard = @import("../wire/postcard.zig");
const frame_types = @import("frame_types.zig");
const frame_writer = @import("frame_writer.zig");
const vectors = @import("frame_vectors.zig");

const NodeId = key.NodeId;
const Signature = key.Signature;

const std_testing = std.testing;
const Datagrams = frame_types.Datagrams;
const DatagramFrame = frame_types.DatagramFrame;
const Error = frame_types.Error;
const FrameType = frame_types.FrameType;
const Message = frame_types.Message;
const ProtocolVersion = frame_types.ProtocolVersion;
const ServerDeniesAuth = frame_types.ServerDeniesAuth;
const max_packet_size = frame_types.max_packet_size;
const max_text_length = frame_types.max_text_length;
const Writer = frame_writer.Writer;

/// The bytes `encode` will write for `message`, exactly.
///
/// Upstream keeps an `encoded_len` beside every `write_to` and asserts the two
/// agree. A size that is a guess is a size a caller sizes a buffer from.
///
/// **Six of this union's fourteen arms carry a length their type does not fix**,
/// and `encode` bounds each before it writes: a denial's reason and a health
/// problem by `max_text_length`, and the four datagram frames' payload by
/// `max_packet_size`. That payload is every byte after the frame type and not
/// the contents, so the four are not bounded alike — 65503 bytes of contents in
/// a single datagram, 65501 in a batch, which spends two of the bound on its
/// segment size. **A caller sizing one buffer for every frame it sends sizes it
/// for the frame and not for the contents, and takes
/// `max_packet_size + FrameType.client_to_relay_datagram_batch.encodedLen()`,
/// which `ServerDeniesAuth.max_frame_length` does not come near.** The other
/// eight arms are fixed by their own type, and `checkEncodable` is where both
/// halves of that statement are kept.
///
/// **It is what a buffer is sized from, and for every message `encode` accepts it
/// is exactly the byte count.** For one `encode` refuses it is what the frame
/// would have been: text over `max_text_length` still counts its bytes, and a
/// batch with no segment size or a zero one still counts the two that would have
/// carried it. So `encodedLen` never understates a frame that can be written, and
/// a caller may treat it as a lower bound on a buffer for a message it has not
/// checked.
pub fn encodedLen(message: Message) usize {
    const payload: usize = switch (message) {
        .server_challenge => frame_types.ServerChallenge.challenge_length,
        .client_auth => NodeId.byte_length +
            frame_writer.postcardVarIntLen(Signature.byte_length) + Signature.byte_length,
        .server_confirms_auth => 0,
        .server_denies_auth => |denial| frame_writer.postcardVarIntLen(denial.reason.len) +
            denial.reason.len,
        .client_to_relay_datagram,
        .relay_to_client_datagram,
        => |frame| DatagramFrame.header_length + frame.datagrams.contents.len,
        .client_to_relay_datagram_batch,
        .relay_to_client_datagram_batch,
        => |frame| DatagramFrame.header_length + Datagrams.segment_size_length +
            frame.datagrams.contents.len,
        .endpoint_gone => NodeId.byte_length,
        .ping, .pong => 8,
        .health => |problem| problem.len,
        .restarting => 2 * @sizeOf(u32),
        .status => 1,
    };
    return std.meta.activeTag(message).encodedLen() + payload;
}

/// Writes `message` into `out` and hands back what it wrote.
///
/// `out` is the caller's buffer and is never grown: a frame that does not fit is
/// `error.BufferFull`, the same rule `wire/postcard.zig` follows and for the same
/// reason, that one scratch buffer can serve a whole connection.
///
/// `version` is what the connection negotiated, and a frame that version does not
/// define is `error.FrameNotAllowedInVersion` rather than bytes on the wire.
/// `Health` and `Status` are the two that differ, and refusing here is what keeps
/// both versions emittable without either one sending a frame the far end has
/// agreed not to understand.
///
/// `error.FrameNotAllowedInVersion`, `error.InvalidFrame`,
/// `error.InvalidUtf8`, `error.TextTooLong` and `error.FrameTooLarge` are
/// decided before the writer exists and leave `out` unchanged.
///
/// The two refusals the writer itself makes are different, and the difference is
/// what is in the buffer afterwards: **`error.BufferFull` and
/// `error.ZeroSegmentSize` leave a partial frame** — the frame type, and whatever
/// of the payload fitted before the writer ran out — because both are found once
/// bytes are down. Neither hands back a slice, so a caller must discard `out` on
/// any error rather than send what happens to be in it.
///
/// **What it borrows and what it keeps.** `message` is read and nothing in the
/// result refers to it: every arm is copied into `out`, so the payload buffers a
/// caller encoded from may be reused the moment this returns. The slice it returns
/// is `out[0..written]` — the same memory, not a copy of it — so it aliases the
/// caller's buffer and is invalidated by whatever the caller next writes there.
/// Nothing is allocated, nothing is read from a global, and no clock or I/O is
/// touched, so the call is reentrant over distinct buffers and needs no
/// synchronization beyond the caller's own.
pub fn encode(message: Message, version: ProtocolVersion, out: []u8) Error![]const u8 {
    const frame_type: FrameType = std.meta.activeTag(message);
    if (!frame_type.allowedIn(version)) return error.FrameNotAllowedInVersion;
    // Every bound this frame has to meet, before the writer exists. One pass
    // over the arms whose length the type does not fix, so a refusal leaves
    // `out` exactly as the caller handed it over rather than holding the frame
    // type and no payload.
    try checkEncodable(message);
    var writer = Writer.init(out);
    try writer.writeVarInt(@intFromEnum(frame_type));
    switch (message) {
        .server_challenge => |challenge| try writer.write(&challenge.challenge),
        .client_auth => |auth| {
            try writer.write(&auth.node_id.toBytes());
            var signature = postcard.Writer.init(writer.rest());
            signature.writeBytes(&auth.signature.toBytes()) catch return error.BufferFull;
            writer.advance(signature.finish().len);
        },
        .server_confirms_auth => {},
        .server_denies_auth => |denial| {
            var text = postcard.Writer.init(writer.rest());
            text.writeStr(denial.reason) catch return error.BufferFull;
            writer.advance(text.finish().len);
        },
        .client_to_relay_datagram,
        .relay_to_client_datagram,
        => |frame| {
            try writeDatagramHeader(&writer, frame);
            try writer.write(frame.datagrams.contents);
        },
        .client_to_relay_datagram_batch,
        .relay_to_client_datagram_batch,
        => |frame| {
            // A batch frame is chosen because `segment_size` is set, so this
            // cannot be null. The check is here because a zero is a value the
            // invariant forbids and a named error beats a frame that lies.
            const segment_size = frame.datagrams.segment_size orelse return error.ZeroSegmentSize;
            if (segment_size == 0) return error.ZeroSegmentSize;
            try writeDatagramHeader(&writer, frame);
            try writer.writeU16Be(segment_size);
            try writer.write(frame.datagrams.contents);
        },
        .endpoint_gone => |node_id| try writer.write(&node_id.toBytes()),
        .ping => |data| try writer.write(&data),
        .pong => |data| try writer.write(&data),
        // v1 only, and the other of the two frames whose length no field fixes.
        // Its bound is `max_text_length` and `checkEncodable` has already had it,
        // together with the check that it is text at all.
        .health => |problem| try writer.write(problem),
        .restarting => |restarting| {
            try writer.writeU32Be(restarting.reconnect_in_ms);
            try writer.writeU32Be(restarting.try_for_ms);
        },
        .status => |status| try writer.writeU8(status.toBits()),
    }
    return writer.finish();
}

fn writeDatagramHeader(writer: *Writer, frame: DatagramFrame) Error!void {
    try writer.write(&frame.node_id.toBytes());
    try writer.writeU8(if (frame.datagrams.ecn) |codepoint| codepoint.toBits() else 0);
}

/// Every bound `message` has to meet, checked before a byte of it is written.
///
/// **This is the sweep.** Six of the fourteen arms of `Message` carry a length
/// their own type does not fix, in three kinds, and each is refused here by
/// name: a `server_denies_auth` reason and a v1 `health` problem, both
/// relay-authored text, by `max_text_length`, and the four datagram frames'
/// payload by `max_packet_size`.
///
/// The other eight are the frame type's own width and cannot be anything else:
/// the challenge's sixteen bytes, the client auth's node id and signature, the
/// empty confirmation, the endpoint id, ping's and pong's eight bytes, the two
/// durations, and the status discriminant. **A fifteenth arm carrying a
/// peer-supplied length is the case this function exists to catch, and the
/// switch below is where it lands** — an arm with no bound here is an arm whose
/// length nothing checks.
///
/// The datagram bound is on the payload `decode` measures — every byte after the
/// frame type, and not the contents alone — so it is the rule `decode` already
/// applies to a payload it is handed (`relay.rs:404` and `:544`), now applied on
/// the way out too, and this module cannot emit a frame its own decoder refuses
/// for being too long. That is `max_packet_size` over a node id, an ECN byte and,
/// on a batch, a segment size: 65503 bytes of contents in a single datagram, 65501
/// in a batch. Upstream checks it on decode only, because its `write_to` writes
/// into a `BytesMut` that grows (`relay.rs:328`): a frame that is too large there
/// is a large allocation rather than a fault.
///
/// What is not a length is out of scope here, with one exception that is a real
/// hole: relay-authored text is written as it was handed, so a reason or a
/// problem that is not UTF-8 would be a frame this module emits and will not
/// read back. So this is the sweep that closes it — the two text arms check
/// `std.unicode.utf8ValidateSlice` and refuse `error.InvalidUtf8`, the name
/// `decode` already answers with, because a codec that refuses on the way in
/// and writes on the way out is not a codec.
///
/// It runs before the writer exists so that a refusal leaves `out` as the caller
/// handed it over. A caller that kept the frame type and lost the payload would
/// find a partial frame in its own buffer, and a partial denial is a denial
/// whose reason stops early.
fn checkEncodable(message: Message) Error!void {
    switch (message) {
        .server_denies_auth => |denial| {
            if (denial.reason.len > ServerDeniesAuth.max_reason_length) {
                return error.TextTooLong;
            }
            if (!std.unicode.utf8ValidateSlice(denial.reason)) return error.InvalidUtf8;
        },
        .health => |problem| {
            if (problem.len > max_text_length) return error.TextTooLong;
            if (!std.unicode.utf8ValidateSlice(problem)) return error.InvalidUtf8;
        },
        .client_to_relay_datagram,
        .relay_to_client_datagram,
        => |frame| {
            if (frame.datagrams.segment_size != null) return error.InvalidFrame;
            const contents_limit = max_packet_size - DatagramFrame.header_length;
            if (frame.datagrams.contents.len > contents_limit) return error.FrameTooLarge;
        },
        .client_to_relay_datagram_batch,
        .relay_to_client_datagram_batch,
        => |frame| {
            const contents_limit = max_packet_size - DatagramFrame.header_length -
                Datagrams.segment_size_length;
            if (frame.datagrams.contents.len > contents_limit) return error.FrameTooLarge;
        },
        .server_challenge,
        .client_auth,
        .server_confirms_auth,
        .endpoint_gone,
        .ping,
        .pong,
        .restarting,
        .status,
        => {},
    }
}

// --- tests

test "codec: text that is not UTF-8 is refused, because decode refuses it too" {
    // The one frame this module can write and cannot read back. Upstream's reason
    // is a `String`, so the bytes cannot be anything but text; here they are
    // `[]const u8` and `encode` writes what it is handed, while `decode` hands the
    // same bytes to postcard, which validates them and answers
    // `error.InvalidUtf8`. A relay that emits one has put a frame on the wire that
    // its own decoder refuses and that a peer cannot read as a `String` either.
    //
    // So `encode` refuses it under the name `decode` already uses, and it refuses
    // it in the sweep, before the writer exists, so the buffer is untouched the
    // way an over-long reason leaves it. `0xff` is never a UTF-8 byte, which is
    // what makes this the smallest input that says it.
    const not_text = [_]u8{ 0xff, 'n', 'o', ' ' };

    var out: [vectors.scratch_len]u8 = undefined;
    @memset(&out, 0xff);
    try std_testing.expectError(
        error.InvalidUtf8,
        encode(.{ .server_denies_auth = .{ .reason = &not_text } }, .v2, &out),
    );
    for (out) |byte| try std_testing.expectEqual(@as(u8, 0xff), byte);

    // v1's answer to the same question, over the same bytes and under the same
    // rule: both arms are relay-authored text with no field fixing its length.
    var v1_out: [vectors.scratch_len]u8 = undefined;
    @memset(&v1_out, 0xff);
    try std_testing.expectError(
        error.InvalidUtf8,
        encode(.{ .health = &not_text }, .v1, &v1_out),
    );
    for (v1_out) |byte| try std_testing.expectEqual(@as(u8, 0xff), byte);
}

test "codec: a datagram over max_packet_size is refused on the way out too" {
    // All four datagram arms go through the same check, so both directions and
    // both the batch and single form are covered by one case. These contents are
    // a whole packet over before the header they are written behind.
    const alloc = std_testing.allocator;
    const payload = try alloc.alloc(u8, max_packet_size + 1);
    defer alloc.free(payload);
    @memset(payload, 0x5a);
    const node_id = try vectors.captureId();
    const messages = [_]Message{
        .{ .client_to_relay_datagram = .{
            .node_id = node_id,
            .datagrams = .{ .ecn = null, .segment_size = null, .contents = payload },
        } },
        .{ .relay_to_client_datagram = .{
            .node_id = node_id,
            .datagrams = .{ .ecn = null, .segment_size = null, .contents = payload },
        } },
        .{ .client_to_relay_datagram_batch = .{
            .node_id = node_id,
            .datagrams = .{ .ecn = null, .segment_size = 6, .contents = payload },
        } },
        .{ .relay_to_client_datagram_batch = .{
            .node_id = node_id,
            .datagrams = .{ .ecn = null, .segment_size = 6, .contents = payload },
        } },
    };
    var out: [vectors.scratch_len]u8 = undefined;
    for (messages) |message| {
        try std_testing.expectError(error.FrameTooLarge, encode(message, .v2, &out));
    }
}

test "codec: a writer with no room is BufferFull, never a resize" {
    const ping: Message = .{ .ping = [_]u8{42} ** 8 };
    // Nine bytes: the header and the payload, exactly.
    var exact: [9]u8 = undefined;
    const written = try encode(ping, .v2, &exact);
    try std_testing.expectEqual(@as(usize, 9), written.len);
    try std_testing.expectEqual(@as(usize, 9), encodedLen(ping));

    var short: [8]u8 = undefined;
    try std_testing.expectError(error.BufferFull, encode(ping, .v2, &short));
    // A denial whose text does not fit takes the same path, through the postcard
    // writer it borrows.
    try std_testing.expectError(
        error.BufferFull,
        encode(.{ .server_denies_auth = .{ .reason = "too long for here" } }, .v2, &short),
    );
    // And a datagram frame whose header is one byte short of the node id it needs.
    try std_testing.expectError(
        error.BufferFull,
        encode(.{ .relay_to_client_datagram = .{
            .node_id = try vectors.captureId(),
            .datagrams = .{
                .ecn = null,
                .segment_size = null,
                .contents = vectors.hello_world,
            },
        } }, .v2, &short),
    );
}

test "codec: a single-datagram tag cannot discard a batch boundary" {
    const datagram_frame: DatagramFrame = .{
        .node_id = try vectors.captureId(),
        .datagrams = .{
            .ecn = .ect0,
            .segment_size = 6,
            .contents = "abcdefabcdef",
        },
    };
    inline for (.{
        FrameType.client_to_relay_datagram,
        FrameType.relay_to_client_datagram,
    }) |tag| {
        const message = @unionInit(Message, @tagName(tag), datagram_frame);
        for ([_]ProtocolVersion{ .v1, .v2 }) |version| {
            var out: [64]u8 = @splat(0xac);
            const untouched: [64]u8 = @splat(0xac);
            try std_testing.expectError(error.InvalidFrame, encode(message, version, &out));
            try std_testing.expectEqualSlices(u8, &untouched, &out);
        }
    }
}
