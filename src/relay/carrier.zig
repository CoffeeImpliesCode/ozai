//! One datagram, one relay message: the mapping between an inner QUIC payload
//! and the frame that carries it through a relay.
//!
//! # What is being carried
//!
//! **A datagram and its GSO segmentation, not a blob.** `batch.Send` — what the
//! core's `Conn.drain` hands over per socket write — is
//! `{ ecn, contents, segment_size }`, and `frame.Datagrams` is the same three
//! fields with the same rule attached (`batch_run.zig:48`,
//! `frame_types.zig:418`): a segment size is set exactly when the payload holds
//! more than one datagram, and the last one may be shorter. The two are the same
//! shape on purpose, so carrying a core payload through a relay is a field for
//! field move and not a re-segmentation. `carry` is that move.
//!
//! That matters in both directions. A node dialled over a relay route asks the
//! core for writes against a synthetic address (`transport/dial_route.zig`), and
//! the answer is a `batch.Send` the node would otherwise put on a socket; a
//! relay hands a client one `Packet` per datagram and has to turn each into a
//! `relay_to_client_datagram` (`node_relay_forward.zig:185`). Both are this
//! function with a different `Direction`, and neither has to decide the batch
//! question on its own.
//!
//! # The frame type is the segment size's own answer
//!
//! **One datagram goes out as `*_datagram` and several go out as
//! `*_datagram_batch`, decided by `Datagrams.frameType` and nowhere else.** It
//! is the right half of rule 7 in `docs/ARCHITECTURE.md`, and getting it wrong in
//! either direction produces a frame the peer cannot use: a single datagram
//! carrying a segment size names a batch of one, and a batch carrying no segment
//! size cannot be drained (`takeSegments` loses the size the moment one
//! datagram or fewer is left in it). `frame_encode.zig` refuses the first
//! combination as `error.InvalidFrame`; this file cannot produce it.
//!
//! # The bounds, checked before a frame exists
//!
//! `carry` refuses a zero segment size and a payload the codec could not write,
//! naming the codec's own errors, and it does so *before* it builds a message.
//! The codec would catch both at `encode` — but by then the caller has already
//! decided what to do with a datagram that is not going anywhere, and a relay
//! that counted a forwarded datagram it then failed to write would be reporting
//! something that did not happen. A zero-length payload is not an error: it is a
//! datagram of no bytes, which this protocol permits.
//!
//! **Nothing is copied and nothing is retained.** The returned `Message` borrows
//! `contents`, exactly as `Datagrams` documents, so the caller owns the payload
//! until `frame.encode` has written it and the peer's buffer must stay put until
//! the frame it produced is done with.
//!
//! # What this file does not do
//!
//! It does not open a connection, choose a version, authenticate anybody, or
//! decide where a datagram goes — `relay/conn_version.zig`, `relay/client.zig`
//! and `node/node_relay_route.zig` are those. And it adds no transport: a relay
//! connection in this tree is a QUIC stream to a relay that speaks
//! `iroh-relay`, not a WebSocket over a TCP socket, so nothing here needs
//! TLS-over-TCP and nothing here provides one. That listener stays the declared
//! debt of `docs/DECISIONS/0001` ("`std.crypto.tls` has a client-only driver
//! with no server"), and a relay reachable only over an unauthenticated TCP
//! socket would be a new debt rather than a cleared one. See the report for what
//! that leaves unpinned.

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
fn frameTypeOf(peer: NodeId, datagrams: Datagrams, direction: Direction) frame.FrameType {
    const message = carry(peer, datagrams, direction) catch unreachable;
    return std.meta.activeTag(message);
}

// A datagram goes out as a datagram and a batch as a batch, in both directions,
// which is the whole of rule 7 on this side.
test "one datagram is a datagram frame and a batch is a batch frame" {
    const single: Datagrams = .{ .ecn = null, .segment_size = null, .contents = "ozai" };
    const peer = try relay_test_ids.testNodeId(30);
    try std_testing.expectEqual(
        frame.FrameType.client_to_relay_datagram,
        frameTypeOf(peer, single, .client_to_relay),
    );
    try std_testing.expectEqual(
        frame.FrameType.relay_to_client_datagram,
        frameTypeOf(peer, single, .relay_to_client),
    );

    // Three equal datagrams, which is what a GSO send looks like on the core's
    // side and is the shape a relay must not flatten.
    const batch: Datagrams = .{ .ecn = .ce, .segment_size = 4, .contents = "abcdefghijkl" };
    try std_testing.expectEqual(
        frame.FrameType.client_to_relay_datagram_batch,
        frameTypeOf(peer, batch, .client_to_relay),
    );
    try std_testing.expectEqual(
        frame.FrameType.relay_to_client_datagram_batch,
        frameTypeOf(peer, batch, .relay_to_client),
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
    const arrived = carried(read).?;
    try std_testing.expectEqual(peer, arrived.node_id);
    try std_testing.expectEqual(@as(?frame.Ecn, .ect1), arrived.datagrams.ecn);
    try std_testing.expectEqual(@as(?u16, 4), arrived.datagrams.segment_size);
    try std_testing.expectEqualStrings(burst.contents, arrived.datagrams.contents);

    // And back the other way, which is the relay's egress rather than its
    // ingress: the same payload and a different node id in the same shape.
    const to_client = try carry(src, burst, .relay_to_client);
    const read_back = try frame.decode(try frame.encode(to_client, .v2, &out), .v2);
    const delivered = carried(read_back).?;
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
        frameTypeOf(src, draining, .relay_to_client),
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
    inline for (@typeInfo(frame.FrameType).@"enum".fields) |_| table += 1;
    try std_testing.expectEqual(rest.len + 4, table);
}
