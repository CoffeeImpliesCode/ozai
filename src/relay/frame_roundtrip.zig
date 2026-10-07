//! Whether two frames are the same frame, and every suite that holds the two
//! directions to each other.
//!
//! The frame itself is `relay/frame_types.zig`, the way out is
//! `relay/frame_encode.zig`, the way in is `relay/frame_decode.zig`, and the
//! bytes under all three are `relay/frame_writer.zig`. `relay/frame.zig`
//! re-exports the lot.
//!
//! Captured from n0-computer/iroh at commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8, out of the two snapshot tests in
//! `iroh-relay/src/protos/relay.rs`'s `mod tests`. `docs/ARCHITECTURE.md` rule 6
//! is the borrow every round trip here is about: `decode` hands back the caller's
//! own bytes, so a re-encode has to come out of a different buffer than the
//! message it came from, and the tests below are written so that it does.
//!
//! `eql` is the oracle all of them share: a round trip has to be a fixed point
//! of it, and it is the one place that says what "the same" is for a borrowed
//! payload — the bytes, not the buffer they were read from.

const std = @import("std");

const key = @import("../base/key.zig");
const postcard = @import("../wire/postcard.zig");
const frame_types = @import("frame_types.zig");
const frame_encode = @import("frame_encode.zig");
const frame_decode = @import("frame_decode.zig");
const frame_writer = @import("frame_writer.zig");
const vectors = @import("frame_vectors.zig");

const NodeId = key.NodeId;

const std_testing = std.testing;
const ClientAuth = frame_types.ClientAuth;
const Datagrams = frame_types.Datagrams;
const DatagramFrame = frame_types.DatagramFrame;
const Ecn = frame_types.Ecn;
const Error = frame_types.Error;
const FrameType = frame_types.FrameType;
const Message = frame_types.Message;
const ProtocolVersion = frame_types.ProtocolVersion;
const Restarting = frame_types.Restarting;
const ServerChallenge = frame_types.ServerChallenge;
const ServerDeniesAuth = frame_types.ServerDeniesAuth;
const Status = frame_types.Status;
const Writer = frame_writer.Writer;
const decode = frame_decode.decode;
const encode = frame_encode.encode;
const encodedLen = frame_encode.encodedLen;
const max_packet_size = frame_types.max_packet_size;
const max_text_length = frame_types.max_text_length;

/// Whether two frames are the same frame.
///
/// The comparison a round trip has to be a fixed point of, and the one place that
/// says what "the same" is for a borrowed payload: the bytes, not the buffer they
/// were read from.
pub fn eql(a: Message, b: Message) bool {
    const frame_type: FrameType = std.meta.activeTag(a);
    if (frame_type != std.meta.activeTag(b)) return false;
    return switch (a) {
        .server_challenge => |challenge| std.mem.eql(
            u8,
            &challenge.challenge,
            &b.server_challenge.challenge,
        ),
        .client_auth => |auth| nodeIdEql(auth.node_id, b.client_auth.node_id) and std.mem.eql(
            u8,
            &auth.signature.toBytes(),
            &b.client_auth.signature.toBytes(),
        ),
        .server_confirms_auth => true,
        .server_denies_auth => |denial| std.mem.eql(u8, denial.reason, b.server_denies_auth.reason),
        .client_to_relay_datagram => |frame| datagramFrameEql(frame, b.client_to_relay_datagram),
        .client_to_relay_datagram_batch => |frame| datagramFrameEql(
            frame,
            b.client_to_relay_datagram_batch,
        ),
        .relay_to_client_datagram => |frame| datagramFrameEql(frame, b.relay_to_client_datagram),
        .relay_to_client_datagram_batch => |frame| datagramFrameEql(
            frame,
            b.relay_to_client_datagram_batch,
        ),
        .endpoint_gone => |node_id| nodeIdEql(node_id, b.endpoint_gone),
        .ping => |data| std.mem.eql(u8, &data, &b.ping),
        .pong => |data| std.mem.eql(u8, &data, &b.pong),
        .health => |problem| std.mem.eql(u8, problem, b.health),
        .restarting => |restarting| restarting.reconnect_in_ms == b.restarting.reconnect_in_ms and
            restarting.try_for_ms == b.restarting.try_for_ms,
        // Compared by byte and not by arm: `Status` keeps a discriminant it has no
        // name for, and the name is the only thing that could differ.
        .status => |status| status.toBits() == b.status.toBits(),
    };
}

fn datagramFrameEql(a: DatagramFrame, b: DatagramFrame) bool {
    if (!nodeIdEql(a.node_id, b.node_id)) return false;
    if (a.datagrams.ecn != b.datagrams.ecn) return false;
    if (a.datagrams.segment_size != b.datagrams.segment_size) return false;
    return std.mem.eql(u8, a.datagrams.contents, b.datagrams.contents);
}

fn nodeIdEql(a: NodeId, b: NodeId) bool {
    return std.mem.eql(u8, &a.toBytes(), &b.toBytes());
}

/// Every hexdump below is copied out of `iroh-relay/src/protos/relay.rs` at commit
/// 187f59e8, out of the two snapshot tests in its `mod tests`:
/// `test_relay_client_frames_snapshot` at `relay.rs:612` for the frames the relay
/// sends and `test_client_relay_frames_snapshot` at `relay.rs:704` for the
/// frames a client sends. Upstream strips the whitespace out of its own hexdumps
/// before decoding them (`relay.rs:592`), so the spacing here is ours and the
/// bytes are theirs.
const captured = [_]struct {
    /// The frame type this hexdump is a frame of.
    frame_type: FrameType,
    /// The only version this frame may be sent in.
    version: ProtocolVersion,
    /// Where upstream wrote it.
    source: []const u8,
    hex: []const u8,
}{
    // RelayToClientMsg::Health { problem: "Hello? Yes this is dog." }
    .{
        .frame_type = .health,
        .version = .v1,
        .source = "relay.rs:614",
        .hex = "0b 48656c6c6f3f20596573207468697320697320646f672e",
    },
    // RelayToClientMsg::EndpointGone(client_key.public())
    .{
        .frame_type = .endpoint_gone,
        .version = .v2,
        .source = "relay.rs:622",
        .hex = "08 " ++ vectors.id_hex,
    },
    // RelayToClientMsg::Ping([42u8; 8])
    .{
        .frame_type = .ping,
        .version = .v2,
        .source = "relay.rs:628",
        .hex = "09 2a2a2a2a2a2a2a2a",
    },
    // RelayToClientMsg::Pong([42u8; 8])
    .{
        .frame_type = .pong,
        .version = .v2,
        .source = "relay.rs:632",
        .hex = "0a 2a2a2a2a2a2a2a2a",
    },
    // RelayToClientMsg::Datagrams { segment_size: NonZeroU16::new(6) }
    .{
        .frame_type = .relay_to_client_datagram_batch,
        .version = .v2,
        .source = "relay.rs:636",
        .hex = "07 " ++ vectors.id_hex ++ " 03 0006 48656c6c6f20576f726c6421",
    },
    // RelayToClientMsg::Datagrams { segment_size: None }
    .{
        .frame_type = .relay_to_client_datagram,
        .version = .v2,
        .source = "relay.rs:658",
        .hex = "06 " ++ vectors.id_hex ++ " 03 48656c6c6f20576f726c6421",
    },
    // RelayToClientMsg::Restarting { 10ms, 20ms }
    .{
        .frame_type = .restarting,
        .version = .v2,
        .source = "relay.rs:679",
        .hex = "0c 0000000a 00000014",
    },
    // RelayToClientMsg::Status(Status::SameEndpointIdConnected)
    .{
        .frame_type = .status,
        .version = .v2,
        .source = "relay.rs:687",
        .hex = "0d 01",
    },
    // RelayToClientMsg::Status(Status::RateLimited)
    .{
        .frame_type = .status,
        .version = .v2,
        .source = "relay.rs:691",
        .hex = "0d 02",
    },
    // ClientToRelayMsg::Datagrams { segment_size: NonZeroU16::new(6) }
    .{
        .frame_type = .client_to_relay_datagram_batch,
        .version = .v2,
        .source = "relay.rs:714",
        .hex = "05 " ++ vectors.id_hex ++ " 03 0006 48656c6c6f20576f726c6421",
    },
    // ClientToRelayMsg::Datagrams { segment_size: None }
    .{
        .frame_type = .client_to_relay_datagram,
        .version = .v2,
        .source = "relay.rs:737",
        .hex = "04 " ++ vectors.id_hex ++ " 03 48656c6c6f20576f726c6421",
    },
};

// --- tests

test "golden: the captured node id is seed [42]" {
    const node_id = try vectors.captureId();
    try std_testing.expectEqualStrings(
        vectors.id_hex,
        &std.fmt.bytesToHex(&node_id.toBytes(), .lower),
    );
}

test "golden: relay frame wire format, iroh-relay relay.rs" {
    var scratch: [vectors.scratch_len]u8 = undefined;
    var out: [vectors.scratch_len]u8 = undefined;
    for (captured) |vector| {
        const bytes = try vectors.parseHex(&scratch, vector.hex);
        const decoded = try decode(bytes, vector.version);
        const frame_type: FrameType = std.meta.activeTag(decoded);
        try std_testing.expectEqual(vector.frame_type, frame_type);

        // The captured bytes are the canonical spelling, so what came out goes
        // back in as what went in. That is the comparison a peer makes.
        const written = try encode(decoded, vector.version, &out);
        try vectors.expectHex(bytes, written);
        try std_testing.expectEqual(encodedLen(decoded), written.len);
    }
}

test "golden: the segment size is the whole difference between the pairs" {
    // Upstream's two datagram hexdumps in each direction differ by exactly the
    // frame type byte and the two segment-size bytes. Asserting the pairs against
    // each other is what says what the invariant is for: the type follows the
    // field, and the field is one optional `u16`.
    const node_id = try vectors.captureId();
    // Two buffers, because `decode` borrows the caller's bytes: parsing the
    // single frame into the same buffer would move the batch's contents under
    // the first decode's feet. `docs/ARCHITECTURE.md` rule 6 is about that.
    var batch_scratch: [vectors.scratch_len]u8 = undefined;
    var single_scratch: [vectors.scratch_len]u8 = undefined;
    var out: [vectors.scratch_len]u8 = undefined;
    const pairs = [_]struct { batch: []const u8, single: []const u8 }{
        .{
            .batch = "07 " ++ vectors.id_hex ++ " 03 0006 48656c6c6f20576f726c6421",
            .single = "06 " ++ vectors.id_hex ++ " 03 48656c6c6f20576f726c6421",
        },
        .{
            .batch = "05 " ++ vectors.id_hex ++ " 03 0006 48656c6c6f20576f726c6421",
            .single = "04 " ++ vectors.id_hex ++ " 03 48656c6c6f20576f726c6421",
        },
    };

    for (pairs) |pair| {
        const batch = try decode(try vectors.parseHex(&batch_scratch, pair.batch), .v2);
        const single = try decode(try vectors.parseHex(&single_scratch, pair.single), .v2);
        const batch_type: FrameType = std.meta.activeTag(batch);
        const single_type: FrameType = std.meta.activeTag(single);

        try std_testing.expect(FrameType.isDatagramBatch(batch_type));
        try std_testing.expect(!FrameType.isDatagramBatch(single_type));
        try std_testing.expectEqual(@as(?u16, 6), (try datagramsOf(batch)).segment_size);
        try std_testing.expectEqual(@as(?u16, null), (try datagramsOf(single)).segment_size);

        // Same id, same ECN, same contents, and the batch frame is two bytes
        // longer for the segment size and nothing else.
        try std_testing.expectEqual(node_id, try nodeOf(batch));
        try std_testing.expectEqual(@as(?Ecn, .ce), (try datagramsOf(batch)).ecn);
        try std_testing.expectEqual(@as(?Ecn, .ce), (try datagramsOf(single)).ecn);
        try std_testing.expectEqualStrings(vectors.hello_world, (try datagramsOf(batch)).contents);
        try std_testing.expectEqualStrings(vectors.hello_world, (try datagramsOf(single)).contents);
        const single_wire = try encode(single, .v2, &out);
        const batch_wire = try encode(batch, .v2, &out);
        try std_testing.expectEqual(single_wire.len + 2, batch_wire.len);
    }
}

test "golden: a captured restarting frame is two big-endian millisecond counts" {
    // relay.rs:679, written as `put_u32(reconnect_in.as_millis() as u32)`.
    var scratch: [16]u8 = undefined;
    var out: [vectors.scratch_len]u8 = undefined;
    const bytes = try vectors.parseHex(&scratch, "0c 0000000a 00000014");
    const decoded = try decode(bytes, .v2);
    try std_testing.expectEqual(
        Restarting{ .reconnect_in_ms = 10, .try_for_ms = 20 },
        decoded.restarting,
    );
    try vectors.expectHex(bytes, try encode(decoded, .v2, &out));
}

test "golden: a captured status frame is one byte" {
    for ([_]u8{ 1, 2 }) |bits| {
        const frame = [_]u8{ 0x0d, bits };
        const decoded = try decode(&frame, .v2);
        try std_testing.expectEqual(@as(FrameType, .status), std.meta.activeTag(decoded));
        try std_testing.expectEqual(bits, decoded.status.toBits());
        var out: [4]u8 = undefined;
        try vectors.expectHex(&frame, try encode(decoded, .v2, &out));
    }
}

test "golden: a captured health frame is its text" {
    // relay.rs:614. v1 only, so this is also the first half of the version test.
    var scratch: [64]u8 = undefined;
    var out: [64]u8 = undefined;
    const bytes = try vectors.parseHex(
        &scratch,
        "0b 48656c6c6f3f20596573207468697320697320646f672e",
    );
    const problem = try decode(bytes, .v1);
    try std_testing.expectEqual(@as(FrameType, .health), std.meta.activeTag(problem));
    try std_testing.expectEqualStrings("Hello? Yes this is dog.", problem.health);
    try vectors.expectHex(bytes, try encode(problem, .v1, &out));
}

test "golden: a captured ping and pong are the same eight bytes" {
    // relay.rs:628 and relay.rs:632: one payload, two frame types.
    var scratch: [16]u8 = undefined;
    var out: [16]u8 = undefined;
    const pairs = [_]struct { hex: []const u8, tag: FrameType }{
        .{ .hex = "09 2a2a2a2a2a2a2a2a", .tag = .ping },
        .{ .hex = "0a 2a2a2a2a2a2a2a2a", .tag = .pong },
    };
    for (pairs) |pair| {
        const bytes = try vectors.parseHex(&scratch, pair.hex);
        const message = try decode(bytes, .v2);
        try std_testing.expectEqual(pair.tag, std.meta.activeTag(message));
        try std_testing.expectEqual(@as([8]u8, [_]u8{42} ** 8), try payloadOf8(message));
        try vectors.expectHex(bytes, try encode(message, .v2, &out));
    }
}

test "version: Health is v1 only, Status is v2 only, both are emittable" {
    const health: Message = .{ .health = "the relay is full" };
    const status: Message = .{ .status = .rate_limited };
    var out: [vectors.scratch_len]u8 = undefined;

    try std_testing.expect(FrameType.health.allowedIn(.v1));
    try std_testing.expect(!FrameType.health.allowedIn(.v2));
    try std_testing.expect(FrameType.status.allowedIn(.v2));
    try std_testing.expect(!FrameType.status.allowedIn(.v1));
    // Every other type is in both, which is what makes "both versions must be
    // emittable" true for the twelve of thirteen that did not change.
    const shared = [_]FrameType{
        .server_challenge,
        .client_auth,
        .server_confirms_auth,
        .server_denies_auth,
        .client_to_relay_datagram,
        .client_to_relay_datagram_batch,
        .relay_to_client_datagram,
        .relay_to_client_datagram_batch,
        .endpoint_gone,
        .ping,
        .pong,
        .restarting,
    };
    for (shared) |frame_type| {
        try std_testing.expect(frame_type.allowedIn(.v1));
        try std_testing.expect(frame_type.allowedIn(.v2));
    }

    // Both reach a decoder, and each is refused by the version that removed it.
    // Two output buffers, because a frame borrows the one it was written into and
    // `status_bytes` would otherwise be written over `health_bytes`.
    var v1_out: [vectors.scratch_len]u8 = undefined;
    var v2_out: [vectors.scratch_len]u8 = undefined;
    const health_bytes = try encode(health, .v1, &v1_out);
    try std_testing.expectEqual(
        @as(FrameType, .health),
        std.meta.activeTag(try decode(health_bytes, .v1)),
    );
    const status_bytes = try encode(status, .v2, &v2_out);
    try std_testing.expectEqual(
        @as(FrameType, .status),
        std.meta.activeTag(try decode(status_bytes, .v2)),
    );
    try std_testing.expectError(error.FrameNotAllowedInVersion, encode(health, .v2, &v2_out));
    try std_testing.expectError(error.FrameNotAllowedInVersion, encode(status, .v1, &v1_out));
    try std_testing.expectError(error.FrameNotAllowedInVersion, decode(health_bytes, .v2));
    try std_testing.expectError(error.FrameNotAllowedInVersion, decode(status_bytes, .v1));

    // And the decoder refuses before it looks at the payload: a `Health` frame
    // with no payload at all and a `Status` frame with none give the same answer
    // as well-formed ones, so the version rule is not the length rule.
    var header: [1]u8 = undefined;
    var header_writer = Writer.init(&header);
    try header_writer.writeVarInt(@intFromEnum(FrameType.health));
    try std_testing.expectError(error.FrameNotAllowedInVersion, decode(&header, .v2));
    try std_testing.expectError(
        error.FrameNotAllowedInVersion,
        decode(try vectors.parseHex(&out, "0d"), .v1),
    );
}

test "batch invariant: a segment size is there if and only if the type is a batch" {
    const node_id = try vectors.captureId();
    var out: [vectors.scratch_len]u8 = undefined;

    for ([_]frame_types.Direction{ .client_to_relay, .relay_to_client }) |direction| {
        for ([_]?u16{ null, 1, 6, 1200, 65535 }) |segment_size| {
            const datagrams: Datagrams = .{
                .ecn = .ce,
                .segment_size = segment_size,
                .contents = vectors.hello_world,
            };
            const frame: DatagramFrame = .{ .node_id = node_id, .datagrams = datagrams };
            const tag = datagrams.frameType(direction);

            // The two halves of rule 7 as one fact about a frame that is about to
            // go on the wire.
            try std_testing.expectEqual(datagrams.isBatch(), FrameType.isDatagramBatch(tag));

            const bytes = try encode(try datagramMessage(tag, frame), .v2, &out);
            const decoded = try decode(bytes, .v2);
            try std_testing.expectEqual(tag, std.meta.activeTag(decoded));

            // And the half a decoder is trusted for: the payload agrees with the
            // type it arrived under, in both directions, every time.
            const back = try datagramsOf(decoded);
            try std_testing.expectEqual(back.isBatch(), FrameType.isDatagramBatch(tag));
            try std_testing.expectEqual(segment_size, back.segment_size);
            try std_testing.expectEqual(node_id, try nodeOf(decoded));
        }
    }
}

test "codec: frames 0 through 3, derived from the handshake structs" {
    // Upstream writes no hexdump for the handshake frames, so there is no captured
    // vector to copy and this test does not claim one. The bytes follow from the
    // struct definitions, including serde field attributes, and postcard's rules.
    var out: [vectors.scratch_len]u8 = undefined;

    // `ServerChallenge` (`handshake.rs:77`) is a `[u8; 16]`, and postcard writes a
    // fixed array inline with no length prefix, so a challenge is its header and
    // sixteen bytes.
    const challenge: ServerChallenge = .{ .challenge = [_]u8{0x01} ** 16 };
    const challenge_bytes = try encode(.{ .server_challenge = challenge }, .v2, &out);
    try std_testing.expectEqual(@as(usize, 17), challenge_bytes.len);
    try std_testing.expectEqual(@as(u8, 0), challenge_bytes[0]);
    try std_testing.expectEqualSlices(u8, &challenge.challenge, challenge_bytes[1..17]);
    try std_testing.expectEqual(challenge, (try decode(challenge_bytes, .v2)).server_challenge);
    try std_testing.expectError(error.InvalidFrame, decode(challenge_bytes[0..16], .v2));

    // Native ClientAuth has an inline public key and a serde_bytes signature.
    const expected_auth = try vectors.nativeClientAuth();
    const auth = (try decode(&expected_auth, .v2)).client_auth;
    const auth_bytes = try encode(.{ .client_auth = auth }, .v2, &out);
    try std_testing.expectEqual(@as(usize, 98), encodedLen(.{ .client_auth = auth }));
    try vectors.expectHex(&expected_auth, auth_bytes);

    // `ServerConfirmsAuth` (`handshake.rs:101`) is a unit struct, so the type is
    // the whole frame.
    const confirms = try encode(.{ .server_confirms_auth = {} }, .v2, &out);
    try vectors.expectHex(&.{0x02}, confirms);
    try std_testing.expectError(
        error.InvalidFrame,
        decode(try vectors.parseHex(&out, "02 00"), .v2),
    );

    // `ServerDeniesAuth` (`handshake.rs:105`) is a `String`, so a varint length
    // and then UTF-8. Two bytes of reason is one length byte; two hundred is two,
    // which is the one case where a reader and a writer disagree about width.
    for ([_][]const u8{ "no", "x" ** 200 }) |reason| {
        const message: Message = .{ .server_denies_auth = .{ .reason = reason } };
        const denial = try encode(message, .v2, &out);
        try std_testing.expectEqual(@as(u8, 0x03), denial[0]);
        try std_testing.expectEqual(denial.len, encodedLen(message));
        var reader = postcard.Reader.init(denial[1..]);
        try std_testing.expectEqualStrings(reason, try reader.readStr());
        const decoded = try decode(denial, .v2);
        try std_testing.expectEqualStrings(reason, decoded.server_denies_auth.reason);
    }
}

test "golden: native ClientAuth encode matches the source-derived postcard fixture" {
    var secret = try vectors.captureKey();
    defer secret.deinit();
    const auth: ClientAuth = .{
        .node_id = secret.nodeId(),
        .signature = secret.sign("a message no peer has sent"),
    };
    const expected = try vectors.nativeClientAuth();
    var out: [98]u8 = undefined;
    try std_testing.expectEqual(@as(usize, 98), encodedLen(.{ .client_auth = auth }));
    try vectors.expectHex(&expected, try encode(.{ .client_auth = auth }, .v2, &out));
    try std_testing.expectError(
        error.BufferFull,
        encode(.{ .client_auth = auth }, .v2, out[0..97]),
    );
}

test "golden: native ClientAuth decode reads public key and length-prefixed signature" {
    const expected = try vectors.nativeClientAuth();
    const auth = (try decode(&expected, .v2)).client_auth;
    try std_testing.expectEqualSlices(u8, expected[1..33], &auth.node_id.toBytes());
    try std_testing.expectEqualSlices(u8, expected[34..98], &auth.signature.toBytes());
}

test "codec: native ClientAuth rejects obsolete raw signature wire and malformed lengths" {
    const expected = try vectors.nativeClientAuth();
    var malformed: [99]u8 = undefined;
    @memcpy(malformed[0..33], expected[0..33]);
    @memcpy(malformed[33..97], expected[34..98]);
    // The obsolete 97-byte encoding has no postcard signature length.
    if (decode(malformed[0..97], .v2)) |_| {
        return error.ObsoleteAuthAccepted;
    } else |_| {}

    @memcpy(malformed[0..98], &expected);
    malformed[98] = 0;
    for ([_]u8{ 0, 1, 63, 65 }) |length| {
        malformed[33] = length;
        try std_testing.expectError(error.InvalidFrame, decode(&malformed, .v2));
    }
    malformed[33] = 0x7f;
    try std_testing.expectError(error.BadLength, decode(&malformed, .v2));
    malformed[33] = 0x40;
    try std_testing.expectError(error.InvalidFrame, decode(&malformed, .v2));
    for (1..33) |length| {
        try std_testing.expectError(error.InvalidFrame, decode(expected[0..length], .v2));
    }
    // No length byte is UnexpectedEnd; a claimed 64 bytes that do not fit is BadLength.
    try std_testing.expectError(error.UnexpectedEnd, decode(expected[0..33], .v2));
    for (34..98) |length| {
        try std_testing.expectError(error.BadLength, decode(expected[0..length], .v2));
    }
    malformed[33] = 0x80;
    try std_testing.expectError(error.UnexpectedEnd, decode(malformed[0..34], .v2));
    @memset(malformed[33..43], 0x80);
    try std_testing.expectError(error.BadVarint, decode(malformed[0..43], .v2));
}

test "codec: malformed frames are named errors" {
    var scratch: [vectors.scratch_len]u8 = undefined;
    var out: [vectors.scratch_len]u8 = undefined;

    // No bytes at all: no header, so no frame type.
    try std_testing.expectError(error.UnexpectedEnd, decode("", .v2));

    // A header naming a two-, four- or eight-byte varint with fewer bytes behind
    // it. This is upstream's `UnexpectedEnd` at `relay.rs:105`.
    for ([_][]const u8{ "40", "c0 00", "80 00 00" }) |hex| {
        try std_testing.expectError(
            error.UnexpectedEnd,
            decode(try vectors.parseHex(&scratch, hex), .v2),
        );
    }

    // A well-formed header naming a type this build has no arm for. `0e` is 14,
    // one past the table; `3f` is 63, the largest value a one-byte QUIC varint
    // can hold; `40 0e` is 14 in the two-byte form; the last is 14 in the
    // eight-byte form.
    const unknown = [_][]const u8{
        "0e 00",
        "3f",
        "40 0e",
        "c0 00 00 00 00 00 00 0e",
    };
    for (unknown) |hex| {
        try std_testing.expectError(
            error.UnknownFrameType,
            decode(try vectors.parseHex(&scratch, hex), .v2),
        );
    }

    // A type spelled in four bytes when one would do. The value is a real frame
    // type, so this is a valid header with an empty payload and the type's own
    // length rule rejects it. It is the case QUIC and postcard disagree on, and a
    // postcard reader would have called the whole four bytes a number far outside
    // 0 through 13.
    try std_testing.expectError(
        error.InvalidFrame,
        decode(try vectors.parseHex(&scratch, "80 00 00 09"), .v2),
    );

    // A ping or pong whose payload is not eight bytes, in both directions of
    // wrong.
    const short_payloads = [_][]const u8{
        "09",
        "09 2a2a2a2a2a2a2a2a2a",
        "0a 00",
        "0a 2a2a2a2a2a2a2a2a2a",
    };
    for (short_payloads) |hex| {
        try std_testing.expectError(
            error.InvalidFrame,
            decode(try vectors.parseHex(&scratch, hex), .v2),
        );
    }

    // A datagram frame with no room for a node id and a half. This is the
    // regression upstream wrote `regression_client_to_relay_undersized_datagram_rejected`
    // (`relay.rs:766`) for: a frame that is nothing but its type used to panic
    // while it sliced the id out.
    for ([_]FrameType{ .client_to_relay_datagram, .client_to_relay_datagram_batch }) |frame_type| {
        var header: [1]u8 = undefined;
        var header_writer = Writer.init(&header);
        try header_writer.writeVarInt(@intFromEnum(frame_type));
        try std_testing.expectError(error.InvalidFrame, decode(&header, .v2));
        var short: [DatagramFrame.header_length]u8 = undefined;
        @memset(&short, 0);
        short[0] = header[0];
        try std_testing.expectError(error.InvalidFrame, decode(&short, .v2));
    }

    // 32 bytes that are not a canonical ed25519 point. Upstream's
    // `InvalidPublicKey` (`relay.rs:411`), and a different rule from "too short",
    // so a different error. The datagram frame carries an ECN byte after the id,
    // so that its payload is long enough to reach the key at all.
    const bad_ids = [_][]const u8{
        "06 " ++ vectors.non_canonical_id_hex ++ " 03",
        "08 " ++ vectors.non_canonical_id_hex,
    };
    for (bad_ids) |hex| {
        try std_testing.expectError(
            error.InvalidNodeId,
            decode(try vectors.parseHex(&scratch, hex), .v2),
        );
    }

    // A batch frame with an ECN byte but not the two bytes of segment size after
    // it, which is upstream's `ensure!(bytes.len() >= 3)` at `relay.rs:283`.
    try std_testing.expectError(
        error.InvalidFrame,
        decode(try vectors.parseHex(&scratch, "07 " ++ vectors.id_hex ++ " 03 00"), .v2),
    );

    // A batch frame whose segment size is zero. Upstream drops the `NonZeroU16`
    // and hands back a `Datagrams` with no segment size out of a batch frame; rule
    // 7 says the two halves of the invariant are one fact, so the frame is refused
    // instead, on the way in and on the way out.
    try std_testing.expectError(
        error.ZeroSegmentSize,
        decode(try vectors.parseHex(&scratch, "07 " ++ vectors.id_hex ++ " 03 0000 00"), .v2),
    );
    try std_testing.expectError(
        error.ZeroSegmentSize,
        encode(.{ .relay_to_client_datagram_batch = .{
            .node_id = try vectors.captureId(),
            .datagrams = .{ .ecn = null, .segment_size = 0, .contents = vectors.hello_world },
        } }, .v2, &out),
    );

    // An endpoint-gone frame that is not exactly 32 bytes. Upstream is exact here
    // (`relay.rs:423`) where it is a lower bound for a datagram frame.
    try std_testing.expectError(
        error.InvalidFrame,
        decode(try vectors.parseHex(&scratch, "08 " ++ vectors.id_hex ++ " ff"), .v2),
    );

    // A status frame with anything other than one byte. Upstream reads the first
    // byte and ignores the rest, which lets two different messages share one
    // encoding; the length is the type's own.
    for ([_][]const u8{ "0d", "0d 01 ff", "0d 0000" }) |hex| {
        try std_testing.expectError(
            error.InvalidFrame,
            decode(try vectors.parseHex(&scratch, hex), .v2),
        );
    }

    // A restarting frame that is not two u32s.
    for ([_][]const u8{ "0c 0000000a", "0c 0000000a 00000014 00" }) |hex| {
        try std_testing.expectError(
            error.InvalidFrame,
            decode(try vectors.parseHex(&scratch, hex), .v2),
        );
    }

    // A denial whose postcard length runs past the frame, one whose length
    // varint never stops, one whose length varint is wider than a `u64` can
    // carry, and one whose text is not UTF-8. Each is `postcard.Error`'s own name,
    // carried across unchanged.
    const denials = [_]struct { hex: []const u8, expected: Error }{
        .{ .hex = "03 7f", .expected = error.BadLength },
        .{ .hex = "03 80808080808080808080 00", .expected = error.BadVarint },
        .{ .hex = "03 ffffffffffffffffff 7f", .expected = error.ValueOutOfRange },
        .{ .hex = "03 01 ff", .expected = error.InvalidUtf8 },
        .{ .hex = "03 04 6e6f6d65 ff", .expected = error.InvalidFrame },
    };
    for (denials) |denial| {
        try std_testing.expectError(
            denial.expected,
            decode(try vectors.parseHex(&scratch, denial.hex), .v2),
        );
    }
}

test "codec: encodedLen is the length, for every variant" {
    var secret = try vectors.captureKey();
    defer secret.deinit();
    const node_id = secret.nodeId();
    var other = try key.SecretKey.fromSeed([_]u8{7} ** key.SecretKey.seed_length);
    defer other.deinit();
    const batched: DatagramFrame = .{
        .node_id = node_id,
        .datagrams = .{ .ecn = .ce, .segment_size = 6, .contents = vectors.hello_world },
    };
    const single: DatagramFrame = .{
        .node_id = node_id,
        .datagrams = .{ .ecn = .ce, .segment_size = null, .contents = vectors.hello_world },
    };

    const messages = [_]Message{
        .{ .server_challenge = .{ .challenge = [_]u8{7} ** 16 } },
        .{ .client_auth = .{ .node_id = node_id, .signature = secret.sign("m") } },
        .{ .server_confirms_auth = {} },
        .{ .server_denies_auth = .{ .reason = "no" } },
        // At the bound rather than above it, and still the case this entry is
        // here for: a reason long enough to need a two-byte postcard length
        // prefix, which is the one width where a reader and a writer disagree.
        // `encode` refuses a longer one, so 300 is no longer a value this codec
        // can write — see `max_text_length`.
        .{ .server_denies_auth = .{ .reason = "x" ** ServerDeniesAuth.max_reason_length } },
        .{ .client_to_relay_datagram = single },
        .{ .client_to_relay_datagram_batch = batched },
        .{ .relay_to_client_datagram = single },
        .{ .relay_to_client_datagram_batch = batched },
        .{ .endpoint_gone = node_id },
        .{ .endpoint_gone = other.nodeId() },
        .{ .ping = [_]u8{42} ** 8 },
        .{ .pong = [_]u8{0} ** 8 },
        .{ .health = "" },
        .{ .health = "a problem long enough to be worth a frame of its own" },
        .{ .restarting = .{ .reconnect_in_ms = 0, .try_for_ms = 0 } },
        .{ .status = .healthy },
        .{ .status = .same_endpoint_id_connected },
        .{ .status = .rate_limited },
        .{ .status = .{ .unknown = 200 } },
    };
    var out: [vectors.scratch_len]u8 = undefined;
    for (messages) |message| {
        const version: ProtocolVersion = if (std.meta.activeTag(message) == .health) .v1 else .v2;
        const bytes = try encode(message, version, &out);
        try std_testing.expectEqual(encodedLen(message), bytes.len);
        try std_testing.expect(eql(message, try decode(bytes, version)));
    }
}

test "codec: a reason at the bound round-trips, and one byte over is refused" {
    // The bound is a value in the type, and this is the two sides of it: the
    // longest reason the codec will write goes out whole and comes back whole,
    // and the next byte up is a named refusal rather than a shorter sentence.
    const at_bound: Message = .{
        .server_denies_auth = .{ .reason = "x" ** ServerDeniesAuth.max_reason_length },
    };
    var out: [vectors.scratch_len]u8 = undefined;
    const written = try encode(at_bound, .v2, &out);
    try std_testing.expectEqual(encodedLen(at_bound), written.len);
    // The frame a caller must make room for is the reason at its bound plus the
    // type byte and the prefix, which is what `max_frame_length` says it is.
    try std_testing.expectEqual(ServerDeniesAuth.max_frame_length, written.len);
    try std_testing.expect(eql(at_bound, try decode(written, .v2)));

    // One byte over, and refused rather than cut: the reason that goes on the
    // wire is never a prefix of the reason the caller chose.
    const over: Message = .{
        .server_denies_auth = .{ .reason = "x" ** (ServerDeniesAuth.max_reason_length + 1) },
    };
    var refusal: [vectors.scratch_len]u8 = undefined;
    @memset(&refusal, 0xff);
    try std_testing.expectError(error.TextTooLong, encode(over, .v2, &refusal));
    // Nothing was written, so a caller cannot find a partial denial in its own
    // buffer and mistake it for one.
    for (refusal) |byte| try std_testing.expectEqual(@as(u8, 0xff), byte);
    // And the refusal is the bound, not the buffer: a roomy buffer does not turn
    // an over-long reason back into an encodable one.
    var roomy: [ServerDeniesAuth.max_frame_length]u8 = undefined;
    try std_testing.expectError(error.TextTooLong, encode(over, .v2, &roomy));
}

test "codec: the health problem is bounded by the same number as the reason" {
    // v1's answer to the same question the denial answers, and the same rule:
    // relay-authored text with no field fixing its length. Both are refused
    // past `max_text_length` and neither is shortened.
    const at_bound: Message = .{ .health = "x" ** max_text_length };
    var out: [vectors.scratch_len]u8 = undefined;
    const written = try encode(at_bound, .v1, &out);
    try std_testing.expectEqual(encodedLen(at_bound), written.len);
    try std_testing.expect(eql(at_bound, try decode(written, .v1)));

    const over: Message = .{ .health = "x" ** (max_text_length + 1) };
    var refusal: [vectors.scratch_len]u8 = undefined;
    @memset(&refusal, 0xff);
    try std_testing.expectError(error.TextTooLong, encode(over, .v1, &refusal));
    for (refusal) |byte| try std_testing.expectEqual(@as(u8, 0xff), byte);
}

test "codec: a datagram at the payload bound round-trips, and one byte over is refused" {
    // The bound is on the payload, which is every byte after the frame type: the
    // node id and the ECN byte all four of these types carry, plus the two bytes
    // of segment size on a batch, and not the contents alone. 65536 bytes of
    // payload is 65503 bytes of contents in a single-datagram frame and 65501 in
    // a batch one.
    const single_limit = max_packet_size - DatagramFrame.header_length;
    const batch_limit = single_limit - Datagrams.segment_size_length;

    const alloc = std_testing.allocator;
    const contents = try alloc.alloc(u8, max_packet_size);
    defer alloc.free(contents);
    @memset(contents, 0x5a);
    const node_id = try vectors.captureId();
    // Room for the frame at the bound and not one byte more, so `BufferFull`
    // cannot be the answer to the round trip, and a byte to spare, so the
    // refusal below is the bound and not the buffer.
    const out = try alloc.alloc(u8, max_packet_size + 1);
    defer alloc.free(out);
    const roomy = try alloc.alloc(u8, max_packet_size + 2);
    defer alloc.free(roomy);

    for ([_]FrameType{
        .client_to_relay_datagram,
        .relay_to_client_datagram,
        .client_to_relay_datagram_batch,
        .relay_to_client_datagram_batch,
    }) |frame_type| {
        const is_batch = FrameType.isDatagramBatch(frame_type);
        const segment_size: ?u16 = if (is_batch) 6 else null;
        const limit = if (is_batch) batch_limit else single_limit;

        // At the bound: the payload is `max_packet_size` and not a byte over, so
        // the datagram goes out whole and comes back whole.
        const at_bound = try datagramMessage(frame_type, .{
            .node_id = node_id,
            .datagrams = .{
                .ecn = null,
                .segment_size = segment_size,
                .contents = contents[0..limit],
            },
        });
        const written = try encode(at_bound, .v2, out);
        try std_testing.expectEqual(max_packet_size + 1, written.len);
        try std_testing.expectEqual(encodedLen(at_bound), written.len);
        try std_testing.expect(eql(at_bound, try decode(written, .v2)));

        // One byte over, and refused before the writer exists: the buffer comes
        // back holding what the caller put in it.
        const over = try datagramMessage(frame_type, .{
            .node_id = node_id,
            .datagrams = .{
                .ecn = null,
                .segment_size = segment_size,
                .contents = contents[0 .. limit + 1],
            },
        });
        @memset(out, 0xff);
        try std_testing.expectError(error.FrameTooLarge, encode(over, .v2, out));
        for (out) |byte| try std_testing.expectEqual(@as(u8, 0xff), byte);
        // And with a byte of room to spare it is still refused, which is what
        // says the frame is too large and not the buffer too small.
        try std_testing.expectError(error.FrameTooLarge, encode(over, .v2, roomy));
    }
}

test "codec: a health frame may be empty, and an unknown status is kept" {
    // `Health` is the rest of the message, so an empty one is a frame with no
    // problem text, which upstream's `Health { problem: String }` allows.
    var out: [4]u8 = undefined;
    try vectors.expectHex(&.{0x0b}, try encode(.{ .health = "" }, .v1, &out));

    // A status discriminant this build has no name for is kept, not rejected:
    // upstream's `Unknown(u8)` arm (`relay.rs:142`) exists so a relay that grows
    // a fourth condition does not break a client that is only reading it.
    for ([_]u8{ 3, 4, 200, 255 }) |bits| {
        const frame = [_]u8{ 0x0d, bits };
        const decoded = try decode(&frame, .v2);
        try std_testing.expectEqual(Status{ .unknown = bits }, decoded.status);
        var out_again: [4]u8 = undefined;
        try vectors.expectHex(&frame, try encode(decoded, .v2, &out_again));
    }
}

test "codec: an ECN byte of four is no ECN, and the re-encode says so" {
    // Upstream masks with `0b11` (`shared.rs:193`), so 4 reads as none, and writes
    // none as 0. A byte of 4 is therefore not a fixed point, and the canonical
    // spelling of what it meant is what a re-encode produces. The second decode is
    // the one compared, for the same reason the postcard fuzz target takes its
    // fixed point from the second decode.
    var scratch: [64]u8 = undefined;
    var out: [64]u8 = undefined;
    var again_out: [64]u8 = undefined;
    const decoded = try decode(
        try vectors.parseHex(&scratch, "06 " ++ vectors.id_hex ++ " 04 ff"),
        .v2,
    );
    try std_testing.expectEqual(@as(?Ecn, null), (try datagramsOf(decoded)).ecn);

    const canonical = try encode(decoded, .v2, &out);
    const ecn_at = 1 + NodeId.byte_length;
    try std_testing.expectEqual(@as(u8, 0x00), canonical[ecn_at]);
    const again = try decode(canonical, .v2);
    try std_testing.expectEqual(@as(?Ecn, null), (try datagramsOf(again)).ecn);
    try vectors.expectEqualStringsSlices(
        canonical[ecn_at + 1 ..],
        (try encode(again, .v2, &again_out))[ecn_at + 1 ..],
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

/// The `Message` for a datagram frame under a frame type chosen at runtime.
/// `@unionInit` needs a comptime field name, and the invariant test chooses the
/// tag from the direction it is looping over.
fn datagramMessage(frame_type: FrameType, frame: DatagramFrame) error{UnknownFrameType}!Message {
    return switch (frame_type) {
        .client_to_relay_datagram => .{ .client_to_relay_datagram = frame },
        .client_to_relay_datagram_batch => .{ .client_to_relay_datagram_batch = frame },
        .relay_to_client_datagram => .{ .relay_to_client_datagram = frame },
        .relay_to_client_datagram_batch => .{ .relay_to_client_datagram_batch = frame },
        else => error.UnknownFrameType,
    };
}

/// The node id of whichever of the four datagram frames this is.
fn nodeOf(message: Message) error{NotADatagramFrame}!NodeId {
    return switch (std.meta.activeTag(message)) {
        .client_to_relay_datagram => message.client_to_relay_datagram.node_id,
        .client_to_relay_datagram_batch => message.client_to_relay_datagram_batch.node_id,
        .relay_to_client_datagram => message.relay_to_client_datagram.node_id,
        .relay_to_client_datagram_batch => message.relay_to_client_datagram_batch.node_id,
        else => error.NotADatagramFrame,
    };
}

fn payloadOf8(message: Message) error{NotAnEightBytePayload}![8]u8 {
    return switch (std.meta.activeTag(message)) {
        .ping => message.ping,
        .pong => message.pong,
        else => error.NotAnEightBytePayload,
    };
}
