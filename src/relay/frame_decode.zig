//! Reading a relay frame: one WebSocket message into the value it stands for.
//!
//! The frame itself is `relay/frame_types.zig`, the bytes under it are
//! `relay/frame_writer.zig`, and the way out is `relay/frame_encode.zig`.
//! `relay/frame.zig` re-exports the lot.
//!
//! Captured from n0-computer/iroh at commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8:
//!
//! - `iroh-relay/src/protos/relay.rs:105` — upstream's `UnexpectedEnd`.
//! - `iroh-relay/src/protos/relay.rs:283` — the two bytes of segment size a
//!   batch payload carries before its datagrams.
//! - `iroh-relay/src/protos/relay.rs:293` — upstream drops the `NonZeroU16` here;
//!   this refuses the frame instead.
//! - `iroh-relay/src/protos/relay.rs:402`, `:404`, `:411`, `:423`, `:428`,
//!   `:434`, `:448` — the size and width rules a payload has to meet.
//! - `iroh-relay/src/protos/handshake.rs:561` — the denial's postcard read.
//!
//! # What comes back is the caller's own storage
//!
//! **What comes back is the caller's own storage, borrowed, on six of the
//! fourteen arms** — a denial's reason, a health problem, and the contents of the
//! four datagram frames are slices into `bytes`; the other eight arms are
//! fixed-width values copied out first, and the node ids and signatures among them
//! are independent of the buffer they were read from.
//!
//! So the borrow lasts exactly as long as the message buffer, and freeing it is
//! the caller's: this function allocates nothing and retains nothing after it
//! returns. Writing any byte of `bytes` changes the frame borrowing it, and
//! reusing the buffer for the next message invalidates every `Message` still held
//! from the last one. See `base/addr.zig` on `RelayUrl.hostSlice` for the same
//! borrow, argued at greater length.
//!
//! There is nothing to copy, nothing to free, and nothing to do with the message
//! but read it, so two threads may decode two messages out of two buffers at
//! once — and neither may decode from a buffer the other is writing.

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
const Ecn = frame_types.Ecn;
const Error = frame_types.Error;
const FrameType = frame_types.FrameType;
const Message = frame_types.Message;
const ProtocolVersion = frame_types.ProtocolVersion;
const ServerChallenge = frame_types.ServerChallenge;
const max_packet_size = frame_types.max_packet_size;

/// Reads one frame from the start of `bytes`.
///
/// `bytes` is one WebSocket message: a frame type and then that frame's payload to
/// the end. **What comes back is the caller's own storage, borrowed, on six of the
/// fourteen arms** — a denial's reason, a health problem, and the contents of the
/// four datagram frames are slices into `bytes`; the other eight arms are
/// fixed-width values copied out first, and the node ids and signatures among them
/// are independent of the buffer they were read from.
///
/// So the borrow lasts exactly as long as the message buffer, and freeing it is
/// the caller's: this function allocates nothing and retains nothing after it
/// returns. Writing any byte of `bytes` changes the frame borrowing it, and
/// reusing the buffer for the next message invalidates every `Message` still held
/// from the last one. See `base/addr.zig` on `RelayUrl.hostSlice` for the same
/// borrow, argued at greater length.
///
/// There is nothing to copy, nothing to free, and nothing to do with the message
/// but read it, so two threads may decode two messages out of two buffers at
/// once — and neither may decode from a buffer the other is writing.
///
/// `version` is what the connection negotiated, and it is checked before the
/// payload is read at all: a v2 connection sent a `Health` frame, the answer is
/// `error.FrameNotAllowedInVersion`, and nothing downstream learns what the
/// payload said.
/// Denial and Health text must be UTF-8; invalid text is `error.InvalidUtf8`.
pub fn decode(bytes: []const u8, version: ProtocolVersion) Error!Message {
    var offset: usize = 0;
    const tag = try frame_writer.readVarInt(bytes, &offset);
    const narrow = std.math.cast(u32, tag) orelse return error.UnknownFrameType;
    const frame_type = FrameType.fromInt(narrow) orelse return error.UnknownFrameType;
    if (!frame_type.allowedIn(version)) return error.FrameNotAllowedInVersion;
    const payload = bytes[offset..];
    if (payload.len > max_packet_size) return error.FrameTooLarge;
    return switch (frame_type) {
        .server_challenge => .{
            .server_challenge = .{
                .challenge = try readArray(ServerChallenge.challenge_length, payload),
            },
        },
        .client_auth => blk: {
            const node_id = try readNodeId(payload);
            const signature = Signature.fromBytes(
                try readExact(Signature.byte_length, payload[NodeId.byte_length..]),
            );
            break :blk .{ .client_auth = .{ .node_id = node_id, .signature = signature } };
        },
        .server_confirms_auth => if (payload.len == 0)
            .server_confirms_auth
        else
            error.InvalidFrame,
        .server_denies_auth => .{ .server_denies_auth = .{ .reason = try readStr(payload) } },
        .client_to_relay_datagram => try readDatagramFrame(payload, .client_to_relay_datagram),
        .client_to_relay_datagram_batch => try readDatagramFrame(
            payload,
            .client_to_relay_datagram_batch,
        ),
        .relay_to_client_datagram => try readDatagramFrame(payload, .relay_to_client_datagram),
        .relay_to_client_datagram_batch => try readDatagramFrame(
            payload,
            .relay_to_client_datagram_batch,
        ),
        .endpoint_gone => .{ .endpoint_gone = try readNodeIdExact(payload) },
        .ping => .{ .ping = try readExact(8, payload) },
        .pong => .{ .pong = try readExact(8, payload) },
        .health => blk: {
            if (!std.unicode.utf8ValidateSlice(payload)) return error.InvalidUtf8;
            break :blk .{ .health = payload };
        },
        .restarting => blk: {
            if (payload.len != 2 * @sizeOf(u32)) return error.InvalidFrame;
            break :blk .{ .restarting = .{
                .reconnect_in_ms = std.mem.readInt(u32, payload[0..4], .big),
                .try_for_ms = std.mem.readInt(u32, payload[4..8], .big),
            } };
        },
        .status => if (payload.len == 1)
            .{ .status = frame_types.Status.fromBits(payload[0]) }
        else
            error.InvalidFrame,
    };
}

/// A node id and a datagram payload, under the length rules the four datagram
/// types name between them.
fn readDatagramFrame(payload: []const u8, frame_type: FrameType) Error!Message {
    if (payload.len < DatagramFrame.header_length) return error.InvalidFrame;
    // The slice starts after the node id and not after the whole header: the ECN
    // byte belongs to the datagram payload and `readDatagrams` is what reads it.
    const frame: DatagramFrame = .{
        .node_id = try readNodeId(payload),
        .datagrams = try readDatagrams(
            payload[NodeId.byte_length..],
            FrameType.isDatagramBatch(frame_type),
        ),
    };
    return switch (frame_type) {
        .client_to_relay_datagram => .{ .client_to_relay_datagram = frame },
        .client_to_relay_datagram_batch => .{ .client_to_relay_datagram_batch = frame },
        .relay_to_client_datagram => .{ .relay_to_client_datagram = frame },
        .relay_to_client_datagram_batch => .{ .relay_to_client_datagram_batch = frame },
        else => error.UnknownFrameType,
    };
}

fn readNodeId(payload: []const u8) Error!NodeId {
    return NodeId.fromBytes(try readArray(NodeId.byte_length, payload)) catch
        return error.InvalidNodeId;
}

fn readNodeIdExact(payload: []const u8) Error!NodeId {
    if (payload.len != NodeId.byte_length) return error.InvalidFrame;
    return readNodeId(payload);
}

/// The datagram payload, with or without the segment size.
fn readDatagrams(payload: []const u8, is_batch: bool) Error!Datagrams {
    if (is_batch) {
        // One ECN byte and a two-byte segment size, which `relay.rs:283` insists
        // on before it reads either.
        if (payload.len < Datagrams.ecn_length + Datagrams.segment_size_length) {
            return error.InvalidFrame;
        }
        const segment_size = std.mem.readInt(u16, payload[1..3], .big);
        // A zero segment size names no datagram, so reading one as a single
        // datagram would hand back a `Datagrams` with no segment size out of a
        // batch frame and the two halves of rule 7 would no longer be one fact.
        // The frame is refused instead. Upstream drops the `NonZeroU16` here and
        // returns exactly that inconsistent value (`relay.rs:293`).
        if (segment_size == 0) return error.ZeroSegmentSize;
        return .{
            .ecn = Ecn.fromBits(payload[0]),
            .segment_size = segment_size,
            .contents = payload[Datagrams.ecn_length + Datagrams.segment_size_length ..],
        };
    }
    if (payload.len < Datagrams.ecn_length) return error.InvalidFrame;
    return .{
        .ecn = Ecn.fromBits(payload[0]),
        .segment_size = null,
        .contents = payload[Datagrams.ecn_length..],
    };
}

/// The postcard string in a `ServerDeniesAuth`.
///
/// The one field in a relay frame that is postcard: `handshake.rs:561` hands the
/// whole struct to `postcard::to_io`, and a `String` is a varint length and then
/// UTF-8. Every failure keeps the name `postcard` gave it, except trailing bytes,
/// which mean this is not the frame it claims to be.
fn readStr(payload: []const u8) Error![]const u8 {
    var reader = postcard.Reader.init(payload);
    const reason = reader.readStr() catch |err| return fromPostcard(err);
    reader.finish() catch return error.InvalidFrame;
    return reason;
}

fn fromPostcard(err: postcard.Error) Error {
    return switch (err) {
        error.UnexpectedEnd => error.UnexpectedEnd,
        error.BadVarint => error.BadVarint,
        error.ValueOutOfRange => error.ValueOutOfRange,
        error.BadLength => error.BadLength,
        error.InvalidUtf8 => error.InvalidUtf8,
        // `readStr` reads a length and a UTF-8 run and nothing else, so these are
        // the arms that make the mapping total rather than the arms a denial can
        // reach.
        error.BufferFull,
        error.BadBool,
        error.BadOptionTag,
        error.UnknownVariant,
        error.TrailingBytes,
        => error.InvalidFrame,
    };
}

/// Exactly `length` bytes, or `InvalidFrame`.
///
/// Upstream writes this check the same way for every fixed-width payload
/// (`relay.rs:423`, `428`, `434`, `448`): a payload that is not the width its
/// type names is not that type.
fn readExact(comptime length: usize, payload: []const u8) Error![length]u8 {
    if (payload.len != length) return error.InvalidFrame;
    return payload[0..length].*;
}

fn readArray(comptime length: usize, payload: []const u8) Error![length]u8 {
    if (payload.len < length) return error.InvalidFrame;
    return payload[0..length].*;
}

// --- tests

test "codec: invalid UTF-8 in a peer health frame is refused" {
    const wire = [_]u8{ @intFromEnum(FrameType.health), 0xff };
    try std_testing.expectError(error.InvalidUtf8, decode(&wire, .v1));
    try std_testing.expectError(error.FrameNotAllowedInVersion, decode(&wire, .v2));
}

test "codec: a payload over max_packet_size is refused" {
    const alloc = std_testing.allocator;
    const bytes = try alloc.alloc(u8, max_packet_size + 2);
    defer alloc.free(bytes);
    @memset(bytes, 0xff);
    bytes[0] = @intFromEnum(FrameType.ping);
    // The frame type is read, the payload is measured, and only then is it refused:
    // upstream takes the same order at `relay.rs:402`.
    try std_testing.expectError(error.FrameTooLarge, decode(bytes, .v2));
    // One byte less and the same frame is a ping whose payload is not eight bytes,
    // so the size rule really is what stopped it.
    try std_testing.expectError(
        error.InvalidFrame,
        decode(bytes[0 .. max_packet_size + 1], .v2),
    );
}

test "golden: a captured batch is two datagrams of six bytes" {
    // relay.rs:636, and upstream's own reason for choosing six: "Hello World!" is
    // twelve bytes.
    var scratch: [vectors.scratch_len]u8 = undefined;
    const decoded = try decode(
        try vectors.parseHex(
            &scratch,
            "07 " ++ vectors.id_hex ++ " 03 0006 48656c6c6f20576f726c6421",
        ),
        .v2,
    );
    const datagrams = try datagramsOf(decoded);
    try std_testing.expectEqual(@as(usize, 12), datagrams.contents.len);
    try std_testing.expectEqual(@as(usize, 2), vectors.datagramsIn(datagrams.contents, 6));
    try std_testing.expectEqual(
        @as(usize, 2),
        vectors.datagramsIn(datagrams.contents, datagrams.segment_size.?),
    );
}

/// The datagram payload of whichever of the four datagram frames this is.
fn datagramsOf(message: Message) error{NotADatagramFrame}!Datagrams {
    return switch (std.meta.activeTag(message)) {
        .client_to_relay_datagram => message.client_to_relay_datagram.datagrams,
        .client_to_relay_datagram_batch => message.client_to_relay_datagram_batch.datagrams,
        .relay_to_client_datagram => message.relay_to_client_datagram.datagrams,
        .relay_to_client_datagram_batch => message.relay_to_client_datagram_batch.datagrams,
        else => error.NotADatagramFrame,
    };
}
