//! Native iroh-relay 1.3 datagram/GRO message mapping.
//! The HTTP/WebSocket TCP drivers are `tcp_client.zig` and `tcp_server.zig`.
//! A relay message contains a destination/source identity, ECN, and optionally
//! a big-endian GRO segment size. QUIC bytes remain opaque; authentication belongs to QUIC.

const std = @import("std");
const key = @import("../base/key.zig");
const frame = @import("frame.zig");

const std_testing = std.testing;

/// The node id a datagram is for, or came from.
pub const NodeId = key.NodeId;

/// Which way the datagram is going. See `frame.Direction`.
pub const Direction = frame.Direction;

/// One datagram or a batch of them. See `frame.Datagrams`.
pub const Datagrams = frame.Datagrams;

/// A node id and its payload. See `frame.DatagramFrame`.
pub const DatagramFrame = frame.DatagramFrame;

/// The frame a payload becomes. See `frame.Message`.
pub const Message = frame.Message;

/// Every way a payload cannot be carried. The codec's own errors, because these
/// are the same two the codec would answer and a caller should not have to learn
/// a second name for one rule.
pub const Error = frame.Error;

/// The largest payload one relay message may carry, excluding the frame type.
///
/// **It is the protocol's bound and not a datagram size a node picks.** A relay
/// forwards datagrams of whatever length the core produced, and the ceiling on
/// one is `max_packet_size`; a node that has a tighter bound of its own
/// (`node_transport.max_datagram`, 1500) applies it before this one is reached,
/// and this one is what a relay refuses a peer with.
pub const max_payload = frame.max_packet_size;

/// The one relay message that carries `datagrams` for `peer`.
///
/// `peer` is the destination on a `.client_to_relay` payload and the source on a
/// `.relay_to_client` one; that difference is the frame type's and not this
/// function's, and `DatagramFrame` states it.
///
/// **Zero-length contents are carried and an empty batch is not.** A payload with
/// no segment size is one datagram of no bytes, which the protocol permits; a
/// batch frame whose segment size is zero names no datagram at all, and that is
/// `error.ZeroSegmentSize` here and in the codec.
pub fn carry(peer: NodeId, datagrams: Datagrams, direction: Direction) Error!Message {
    // The batch arm spends two more bytes on its segment size, which is why the
    // four datagram frames are not bounded alike (`frame_types.zig`). An absent
    // segment size is one datagram, and one datagram carries none.
    const segment_overhead: usize = if (datagrams.isBatch())
        Datagrams.segment_size_length
    else
        0;
    const overhead = DatagramFrame.header_length + segment_overhead;
    if (datagrams.contents.len + overhead > max_payload) return error.FrameTooLarge;
    if (datagrams.segment_size) |size| {
        if (size == 0) return error.ZeroSegmentSize;
    }
    // A tagged union's field is picked at compile time and `frameType` answers
    // with a value, so the one decision `Datagrams.frameType` makes is turned
    // back into a field name here. It names one of the four datagram arms and
    // never one of the ten that carry something else, which is what makes the
    // last arm unreachable rather than a second thing to check.
    const datagram_frame: DatagramFrame = .{ .node_id = peer, .datagrams = datagrams };
    return switch (datagrams.frameType(direction)) {
        .client_to_relay_datagram => .{ .client_to_relay_datagram = datagram_frame },
        .client_to_relay_datagram_batch => .{ .client_to_relay_datagram_batch = datagram_frame },
        .relay_to_client_datagram => .{ .relay_to_client_datagram = datagram_frame },
        .relay_to_client_datagram_batch => .{ .relay_to_client_datagram_batch = datagram_frame },
        else => unreachable,
    };
}

/// The datagram a message carries, or null for the ten frame types that carry
/// none.
///
/// **It answers the same question for both directions and returns the payload
/// whole**, so a caller that received a `relay_to_client_datagram_batch` hands the
/// bytes to the core without switching on the four arms itself. A caller holding
/// the batch may drain it with `Datagrams.takeSegments`, and rule 7 keeps that
/// honest: the tail comes back without a segment size and goes out as a single
/// datagram.
pub fn carried(message: Message) ?DatagramFrame {
    return switch (message) {
        .client_to_relay_datagram,
        .client_to_relay_datagram_batch,
        .relay_to_client_datagram,
        .relay_to_client_datagram_batch,
        => |datagram| datagram,
        else => null,
    };
}

// --- tests

const relay_test_ids = @import("relay_test_ids.zig");

/// The frame type a payload of this shape goes out under, for both directions.
///
/// The error is propagated rather than discarded: `carry` refuses a payload
/// over `max_payload` and a batch whose segment size is zero, and a fixture
/// that grew into either is a broken fixture this test should be told about
/// rather than a case to assert is unreachable.
fn frameTypeOf(
    peer: NodeId,
    datagrams: Datagrams,
    direction: Direction,
) Error!frame.FrameType {
    const message = try carry(peer, datagrams, direction);
    return std.meta.activeTag(message);
}

// A datagram goes out as a datagram and a batch as a batch, in both directions,
// which is the whole of rule 7 on this side.
test "one datagram is a datagram frame and a batch is a batch frame" {
    const single: Datagrams = .{ .ecn = null, .segment_size = null, .contents = "ozai" };
    const peer = try relay_test_ids.testNodeId(30);
    try std_testing.expectEqual(
        frame.FrameType.client_to_relay_datagram,
        try frameTypeOf(peer, single, .client_to_relay),
    );
    try std_testing.expectEqual(
        frame.FrameType.relay_to_client_datagram,
        try frameTypeOf(peer, single, .relay_to_client),
    );

    // Three equal datagrams, which is what a GSO send looks like on the core's
    // side and is the shape a relay must not flatten.
    const batch: Datagrams = .{ .ecn = .ce, .segment_size = 4, .contents = "abcdefghijkl" };
    try std_testing.expectEqual(
        frame.FrameType.client_to_relay_datagram_batch,
        try frameTypeOf(peer, batch, .client_to_relay),
    );
    try std_testing.expectEqual(
        frame.FrameType.relay_to_client_datagram_batch,
        try frameTypeOf(peer, batch, .relay_to_client),
    );
}

// The segmentation survives the round trip through the real codec, in both
// directions, including a short tail — which is what a relay forwarding a GSO
// burst depends on.
test "a batch keeps its segmentation and its codepoint across the codec" {
    const peer = try relay_test_ids.testNodeId(31);
    const src = try relay_test_ids.testNodeId(32);
    // Three datagrams of four bytes with a one byte tail: the shape upstream's
    // `Datagrams` is built for, where the last segment may be shorter.
    const burst: Datagrams = .{
        .ecn = .ect1,
        .segment_size = 4,
        .contents = "abcdefghijklm",
    };

    var out: [128]u8 = undefined;
    const to_relay = try carry(peer, burst, .client_to_relay);
    const read = try frame.decode(try frame.encode(to_relay, .v2, &out), .v2);
    const arrived = carried(read) orelse return error.TestUnexpectedResult;
    try std_testing.expectEqual(peer, arrived.node_id);
    try std_testing.expectEqual(@as(?frame.Ecn, .ect1), arrived.datagrams.ecn);
    try std_testing.expectEqual(@as(?u16, 4), arrived.datagrams.segment_size);
    try std_testing.expectEqualStrings(burst.contents, arrived.datagrams.contents);

    // And back the other way, which is the relay's egress rather than its
    // ingress: the same payload and a different node id in the same shape.
    const to_client = try carry(src, burst, .relay_to_client);
    const read_back = try frame.decode(try frame.encode(to_client, .v2, &out), .v2);
    const delivered = carried(read_back) orelse return error.TestUnexpectedResult;
    try std_testing.expectEqual(src, delivered.node_id);
    try std_testing.expectEqualStrings(burst.contents, delivered.datagrams.contents);

    // Draining it is how a client hands it to the core, and the tail comes back
    // without a segment size rather than as a batch of one — which is the half
    // of rule 7 that keeps `isBatch` and the frame type in step.
    var draining = arrived.datagrams;
    const first = draining.takeSegments(3);
    try std_testing.expectEqualStrings("abcdefghijkl", first.contents);
    try std_testing.expectEqual(@as(?u16, 4), first.segment_size);
    try std_testing.expectEqualStrings("m", draining.contents);
    try std_testing.expectEqual(@as(?u16, null), draining.segment_size);
    try std_testing.expectEqual(
        frame.FrameType.relay_to_client_datagram,
        try frameTypeOf(src, draining, .relay_to_client),
    );
}

// A payload the codec could not write is refused before a frame exists, and the
// two refusals are the codec's own names.
test "a payload the codec could not carry is refused, not truncated" {
    const peer = try relay_test_ids.testNodeId(33);
    const allocator = std.testing.allocator;
    // The payload that exactly fills the bound, and the one byte over it.
    const room = max_payload - DatagramFrame.header_length;
    const exact = try allocator.alloc(u8, room);
    defer allocator.free(exact);
    const over = try allocator.alloc(u8, room + 1);
    defer allocator.free(over);

    const exact_frame = try carry(
        peer,
        .{ .ecn = null, .segment_size = null, .contents = exact },
        .client_to_relay,
    );
    try std_testing.expectEqualStrings(exact, carried(exact_frame).?.datagrams.contents);
    try std_testing.expectError(
        error.FrameTooLarge,
        carry(peer, .{ .ecn = null, .segment_size = null, .contents = over }, .client_to_relay),
    );

    // The batch arm spends two more bytes of the bound on its segment size, so
    // the same payload is already over the bound for it — the four datagram
    // frames are not bounded alike, and this is the arithmetic behind that.
    try std_testing.expectError(
        error.FrameTooLarge,
        carry(peer, .{ .ecn = null, .segment_size = 1, .contents = exact }, .client_to_relay),
    );

    // A zero segment size names no datagram, and an empty payload is a datagram
    // of no bytes rather than an error.
    try std_testing.expectError(
        error.ZeroSegmentSize,
        carry(peer, .{ .ecn = null, .segment_size = 0, .contents = "" }, .client_to_relay),
    );
    const empty = try carry(
        peer,
        .{ .ecn = null, .segment_size = null, .contents = "" },
        .client_to_relay,
    );
    try std_testing.expect(carried(empty) != null);
}

// Ten of the fourteen frame types carry no datagram, and saying so is what stops
// a caller switching on four arms of its own.
test "carried names the ten frames that are not datagrams" {
    const peer = try relay_test_ids.testNodeId(34);
    const rest = [_]frame.Message{
        .{ .server_challenge = .{ .challenge = @splat(0x5a) } },
        .{ .client_auth = .{ .node_id = peer, .signature = undefined } },
        .server_confirms_auth,
        .{ .server_denies_auth = .{ .reason = "no" } },
        .{ .endpoint_gone = peer },
        .{ .ping = @splat(0) },
        .{ .pong = @splat(0) },
        .{ .health = "shedding load" },
        .{ .restarting = .{ .reconnect_in_ms = 1, .try_for_ms = 1 } },
        .{ .status = .rate_limited },
    };
    try std_testing.expectEqual(@as(usize, 10), rest.len);
    for (rest) |message| {
        try std_testing.expect(carried(message) == null);
    }

    // The other four of the fourteen do carry one, and counting the table at
    // compile time is what makes the two lists add up rather than assume it.
    var table: usize = 0;
    inline for (@typeInfo(frame.FrameType).@"enum".field_names) |_| table += 1;
    try std_testing.expectEqual(rest.len + 4, table);
}

// Cached iroh-relay 1.3.0 protos/relay.rs test_relay_client_frames_snapshot.
// This upstream snapshot is independent of this encoder's output.
test "iroh relay 1.3 GRO snapshot delivers exact native segments" {
    const bytes = [_]u8{
        0x07,
        0x19,
        0x7f,
        0x6b,
        0x23,
        0xe1,
        0x6c,
        0x85,
        0x32,
        0xc6,
        0xab,
        0xc8,
        0x38,
        0xfa,
        0xcd,
        0x5e,
        0xa7,
        0x89,
        0xbe,
        0x0c,
        0x76,
        0xb2,
        0x92,
        0x03,
        0x34,
        0x03,
        0x9b,
        0xfa,
        0x8b,
        0x3d,
        0x36,
        0x8d,
        0x61,
        0x03,
        0x00,
        0x06,
        0x48,
        0x65,
        0x6c,
        0x6c,
        0x6f,
        0x20,
        0x57,
        0x6f,
        0x72,
        0x6c,
        0x64,
        0x21,
    };
    var packet = carried(try frame.decode(&bytes, .v2)) orelse return error.TestUnexpectedResult;
    try std_testing.expectEqual(@as(?frame.Ecn, .ce), packet.datagrams.ecn);
    try std_testing.expectEqualStrings("Hello ", packet.datagrams.takeSegments(1).contents);
    try std_testing.expectEqualStrings("World!", packet.datagrams.takeSegments(1).contents);
    try std_testing.expectEqual(@as(usize, 0), packet.datagrams.contents.len);
    var output: [bytes.len]u8 = undefined;
    try std_testing.expectEqualSlices(u8, &bytes, try frame.encode(
        try carry(packet.node_id, .{
            .ecn = .ce,
            .segment_size = 6,
            .contents = "Hello World!",
        }, .relay_to_client),
        .v2,
        &output,
    ));
}

test "native datagram prefixes reject missing identity and GRO metadata" {
    const secret = try key.SecretKey.fromSeed(@splat(42));
    const peer = secret.nodeId();
    var output: [80]u8 = undefined;
    const encoded = try frame.encode(try carry(peer, .{
        .ecn = null,
        .segment_size = 6,
        .contents = "Hello World!",
    }, .client_to_relay), .v2, &output);
    // Type + node id + ECN + u16 segment size are required before any QUIC bytes.
    for (1..36) |length| {
        try std_testing.expectError(error.InvalidFrame, frame.decode(encoded[0..length], .v2));
    }
    output[34] = 0;
    output[35] = 0;
    try std_testing.expectError(error.ZeroSegmentSize, frame.decode(encoded, .v2));
}
