//! The gossip codec, exercised over bytes.
//!
//! **Every byte sequence asserted below is a declared vector, not a captured
//! one.** They are what the upstream declarations in `codec/tags.zig` have to
//! produce, written out so that a later edit to a table or a field order cannot
//! move them silently. `AGENTS.md` §2 asks for bytes captured from the Rust
//! implementation before any interoperability claim, `codec.zig` says what is
//! still missing, and this file is where those vectors go when they exist.
//!
//! The oracle for a round trip is the fixed point: `encode(decode(bytes))` is
//! `bytes` again. It is stronger than comparing fields, because a field that was
//! dropped, reordered or defaulted cannot produce the same bytes back, and it is
//! what `AGENTS.md` §2 asks of a decoder boundary.

const std = @import("std");

const codec = @import("codec.zig");
const gossip = @import("hyparview.zig");
const key = @import("../base/key.zig");
const limits = @import("codec/limits.zig");
const plumtree = @import("plumtree.zig");
const postcard = @import("../wire/postcard.zig");
const test_node_id = @import("plumtree/test_node_id.zig");

const NodeId = key.NodeId;
const testNodeId = test_node_id.testNodeId;
const t = std.testing;

/// A buffer every frame in these tests fits in: the body is at most the byte
/// budget and the prefix in front of it is at most `max_prefix_size`.
const room = limits.max_message_size + limits.max_prefix_size;

/// One declared byte sequence, and the message that has to produce it.
const Vector = struct {
    name: []const u8,
    message: codec.Message,
    head: []const u8,
};

fn vector(name: []const u8, message: codec.Message, head: []const u8) Vector {
    return .{ .name = name, .message = message, .head = head };
}

/// The bytes after a frame's length prefix, read with the reader the frame's own
/// decoder uses rather than by counting a prefix by hand.
fn bodyOf(frame: []const u8) ![]const u8 {
    if (frame.len < 4) return error.UnexpectedEnd;
    const length = std.mem.readInt(u32, frame[0..4], .big);
    if (length != frame.len - 4) return error.BadLength;
    return frame[4..];
}

/// A frame this codec must not read back, whatever the error is.
///
/// The error is not named because it is not one error: a prefix that runs past
/// the buffer is `BadLength` and a body that runs out is `UnexpectedEnd`, and a
/// test that pinned one of them would only be pinning where the cut landed.
fn expectRefused(frame: []const u8) !void {
    if (codec.decode(frame)) |message| {
        std.debug.print("a frame that should not decode came back as layer {d}\n", .{
            @intFromEnum(std.meta.activeTag(message)),
        });
        return error.RefusedFrameDecoded;
    } else |_| {}
}

test "every message type round-trips, and the round trip is a fixed point" {
    const peer = try testNodeId(1);
    const infos = try gossip.PeerInfos.init(&.{
        .{ .id = peer, .data = null },
        .{ .id = peer, .data = "contact bytes" },
    });
    const ihaves = try plumtree.IHaves.init(&.{
        .{ .id = plumtree.MessageId.fromContent("one"), .round = .{ .value = 0 } },
        .{ .id = plumtree.MessageId.fromContent("two"), .round = .{ .value = 300 } },
    });
    // Six membership arms, four broadcast arms, both priorities, both scopes, an
    // absent and a present option in each of the places one appears, an empty
    // and a non-empty byte string, and a one-, two- and three-byte varint in
    // each of the three widths the protocol uses.
    const messages = [_]codec.Message{
        .{ .swarm = .{ .join = null } },
        .{ .swarm = .{ .join = "peer data" } },
        .{ .swarm = .{ .forward_join = .{
            .peer = .{ .id = peer, .data = "contact" },
            .ttl = .{ .value = 300 },
        } } },
        .{ .swarm = .{ .shuffle = .{ .origin = peer, .nodes = infos, .ttl = .{ .value = 7 } } } },
        .{ .swarm = .{ .shuffle_reply = .{ .nodes = infos } } },
        .{ .swarm = .{ .neighbor = .{ .priority = .high, .data = null } } },
        .{ .swarm = .{ .neighbor = .{ .priority = .low, .data = "mine" } } },
        .{ .swarm = .{ .disconnect = .{ .alive = true } } },
        .{ .gossip = .{ .prune = {} } },
        .{ .gossip = .{ .gossip = .{
            .id = plumtree.MessageId.fromContent("payload"),
            .content = "hello",
            .scope = .{ .swarm = .{ .value = 0 } },
        } } },
        .{ .gossip = .{ .gossip = .{
            .id = plumtree.MessageId.fromContent("payload"),
            .content = "",
            .scope = .neighbors,
        } } },
        .{ .gossip = .{ .graft = .{ .id = null, .round = .{ .value = 2 } } } },
        .{
            .gossip = .{
                .graft = .{
                    .id = plumtree.MessageId.fromContent("asked for"),
                    // A round past the two-byte varint boundary and inside the `u16`
                    // `Round` wraps at, so the three-byte spelling of the round is what
                    // goes on the wire here.
                    .round = .{ .value = 60_000 },
                },
            },
        },
        .{ .gossip = .{ .i_have = ihaves } },
    };
    var frame_buf: [room]u8 = undefined;
    var again_buf: [room]u8 = undefined;
    for (messages) |message| {
        const frame = try codec.encode(message, &frame_buf);
        // `encodedLen` is what a caller sizes a buffer from, so it has to be the
        // byte count and not an upper bound.
        try t.expectEqual(codec.encodedLen(message), (try bodyOf(frame)).len);
        const decoded = try codec.decode(frame);
        try t.expectEqual(codec.encodedLen(message), codec.encodedLen(decoded));
        try t.expectEqualSlices(u8, frame, try codec.encode(decoded, &again_buf));
    }
}

test "a decoded message carries the fields it was sent with" {
    const peer = try testNodeId(2);
    const id = plumtree.MessageId.fromContent("carried");
    var buf: [room]u8 = undefined;

    const payload: codec.Message = .{ .gossip = .{ .gossip = .{
        .id = id,
        .content = "the payload",
        .scope = .{ .swarm = .{ .value = 5 } },
    } } };
    const carried = (try codec.decode(try codec.encode(payload, &buf))).gossip.gossip;
    try t.expect(carried.id.eql(id));
    try t.expectEqualStrings("the payload", carried.content);
    try t.expectEqual(@as(u16, 5), carried.scope.swarm.value);

    const shuffle: codec.Message = .{ .swarm = .{ .shuffle = .{
        .origin = peer,
        .nodes = try gossip.PeerInfos.init(&.{.{ .id = peer, .data = "contact" }}),
        .ttl = .{ .value = 300 },
    } } };
    const walked = (try codec.decode(try codec.encode(shuffle, &buf))).swarm.shuffle;
    try t.expectEqualSlices(u8, &peer.toBytes(), &walked.origin.toBytes());
    try t.expectEqual(@as(u16, 300), walked.ttl.value);
    try t.expectEqual(@as(u8, 1), walked.nodes.count);
    const info = walked.nodes.slice()[0];
    try t.expect(info.data != null);
    try t.expectEqualStrings("contact", info.data.?);
    try t.expectEqualSlices(u8, &peer.toBytes(), &info.id.toBytes());

    const leaving: codec.Message = .{ .swarm = .{ .disconnect = .{ .alive = true } } };
    const gone = (try codec.decode(try codec.encode(leaving, &buf))).swarm.disconnect;
    try t.expect(gone.alive);
}

test "the tags are upstream's declaration order, byte for byte" {
    // Declared, not captured: see the file header. Each head is the layer tag,
    // the arm tag, and whatever of the payload's own tags follow with no
    // variable-length field in between.
    const peer = try testNodeId(3);
    const id = plumtree.MessageId.fromContent("vector");
    const forward: codec.Message = .{ .swarm = .{ .forward_join = .{
        .peer = .{ .id = peer, .data = null },
        .ttl = .{ .value = 1 },
    } } };
    const empty_infos = try gossip.PeerInfos.init(&.{});
    const shuffle: codec.Message = .{ .swarm = .{ .shuffle = .{
        .origin = peer,
        .nodes = empty_infos,
        .ttl = .{ .value = 1 },
    } } };
    const reply: codec.Message = .{ .swarm = .{ .shuffle_reply = .{ .nodes = empty_infos } } };
    const payload: codec.Message = .{ .gossip = .{ .gossip = .{
        .id = id,
        .content = "",
        .scope = .neighbors,
    } } };
    const graft_none: codec.Message = .{ .gossip = .{ .graft = .{
        .id = null,
        .round = .{ .value = 2 },
    } } };
    const graft_some: codec.Message = .{ .gossip = .{ .graft = .{
        .id = id,
        .round = .{ .value = 1 },
    } } };
    const ihaves = try plumtree.IHaves.init(&.{.{ .id = id, .round = .{ .value = 0 } }});
    const vectors = [_]Vector{
        vector("swarm.join", .{ .swarm = .{ .join = "x" } }, &.{ 0x00, 0x00, 0x01, 0x01, 'x' }),
        vector("swarm.join", .{ .swarm = .{ .join = null } }, &.{ 0x00, 0x00, 0x00 }),
        vector("swarm.forward_join", forward, &.{ 0x00, 0x01 }),
        vector("swarm.shuffle", shuffle, &.{ 0x00, 0x02 }),
        vector("swarm.shuffle_reply", reply, &.{ 0x00, 0x03, 0x00 }),
        vector(
            "swarm.neighbor",
            .{ .swarm = .{ .neighbor = .{ .priority = .high, .data = null } } },
            &.{ 0x00, 0x04, 0x00, 0x00 },
        ),
        vector(
            "swarm.neighbor",
            .{ .swarm = .{ .neighbor = .{ .priority = .low, .data = null } } },
            &.{ 0x00, 0x04, 0x01, 0x00 },
        ),
        // The fourth byte is the obsolete `respond` field, written false: see
        // `codec.respond_byte` for why it is on the wire at all.
        vector(
            "swarm.disconnect",
            .{ .swarm = .{ .disconnect = .{ .alive = true } } },
            &.{ 0x00, 0x05, 0x01, 0x00 },
        ),
        vector("tree.gossip", payload, &.{ 0x01, 0x00 }),
        vector("tree.prune", .{ .gossip = .{ .prune = {} } }, &.{ 0x01, 0x01 }),
        vector("tree.graft", graft_none, &.{ 0x01, 0x02, 0x00, 0x02 }),
        vector("tree.graft", graft_some, &.{ 0x01, 0x02, 0x01 }),
        vector("tree.i_have", .{ .gossip = .{ .i_have = ihaves } }, &.{ 0x01, 0x03, 0x01 }),
    };
    var buf: [room]u8 = undefined;
    for (vectors) |item| {
        const body = try bodyOf(try codec.encode(item.message, &buf));
        if (!std.mem.startsWith(u8, body, item.head)) {
            std.debug.print("{s}: body {x}, head {x}\n", .{ item.name, body, item.head });
            return error.BodyIsNotTheDeclaredVector;
        }
    }
}

test "the scope tag is 0 for the swarm and 1 for neighbours" {
    // The one place `test/protocol_codec.zig` disagrees, and `codec.zig` says
    // why: that file numbers the two the other way round, and upstream declares
    // `Swarm` first.
    const id = plumtree.MessageId.fromContent("scope");
    const to_swarm: codec.Message = .{ .gossip = .{ .gossip = .{
        .id = id,
        .content = "",
        .scope = .{ .swarm = .{ .value = 0 } },
    } } };
    const to_neighbors: codec.Message = .{ .gossip = .{ .gossip = .{
        .id = id,
        .content = "",
        .scope = .neighbors,
    } } };
    // Two buffers, because both bodies are slices of what `encode` wrote: a
    // second encode into the same one would leave the first slice reading the
    // second message.
    var swarm_buf: [room]u8 = undefined;
    var neighbor_buf: [room]u8 = undefined;
    const swarm_body = try bodyOf(try codec.encode(to_swarm, &swarm_buf));
    const neighbor_body = try bodyOf(try codec.encode(to_neighbors, &neighbor_buf));
    // The scope tag and then, for the swarm only, the round it carries.
    try t.expectEqualSlices(u8, &.{ 0x00, 0x00 }, swarm_body[swarm_body.len - 2 ..]);
    try t.expectEqualSlices(u8, &.{0x01}, neighbor_body[neighbor_body.len - 1 ..]);
}

test "a truncated frame is refused rather than half-decoded" {
    const message: codec.Message = .{ .gossip = .{ .gossip = .{
        .id = plumtree.MessageId.fromContent("truncate me"),
        .content = "a payload long enough to cut in several places",
        .scope = .{ .swarm = .{ .value = 2 } },
    } } };
    var buf: [room]u8 = undefined;
    const frame = try codec.encode(message, &buf);
    // Every shorter frame is refused, from nothing at all to one byte short. The
    // length prefix is what rules out the one cut that could otherwise land on a
    // shorter valid message: a body this codec would accept is the body the
    // prefix declared, and a cut leaves fewer bytes than it declared.
    var cut: usize = 0;
    while (cut < frame.len) : (cut += 1) {
        try expectRefused(frame[0..cut]);
    }
}

test "an unknown tag is refused instead of skipped" {
    // A layer this build does not have, and the same number spelled as a
    // two-byte varint: neither is a tag, and neither is a truncated one.
    try t.expectError(error.UnknownVariant, codec.decodeBody(&[_]u8{0x02}));
    try t.expectError(error.UnknownVariant, codec.decodeBody(&[_]u8{ 0x80, 0x01 }));
    // One past the end of each arm table.
    try t.expectError(error.UnknownVariant, codec.decodeBody(&[_]u8{ 0x00, 0x06 }));
    try t.expectError(error.UnknownVariant, codec.decodeBody(&[_]u8{ 0x01, 0x04 }));
    // A `Neighbor` whose priority is 2.
    try t.expectError(error.UnknownVariant, codec.decodeBody(&[_]u8{ 0x00, 0x04, 0x02, 0x00 }));
    // A `Gossip` whose scope is 2. The 32 id bytes are zero and the codec reads
    // them: any 32 bytes are a well-formed id, and whether they name a real
    // message is `Gossip.validate`'s question on the layer above.
    var scope: [1 + 1 + plumtree.id_length + 1 + 1]u8 = undefined;
    @memset(&scope, 0x00);
    scope[0] = 0x01;
    scope[1] = 0x00;
    scope[2 + plumtree.id_length] = 0x00;
    scope[3 + plumtree.id_length] = 0x02;
    try t.expectError(error.UnknownVariant, codec.decodeBody(&scope));
}

test "a frame prefix that does not match the bytes present is refused" {
    // `gossip/prune` is the smallest frame: two tags and a four-byte length.
    var buf: [room]u8 = undefined;
    const frame = try codec.encode(.{ .gossip = .{ .prune = {} } }, &buf);
    try t.expectEqualSlices(u8, &.{ 0, 0, 0, 2, 1, 1 }, frame);
    var longer: [room]u8 = undefined;
    var shorter: [room]u8 = undefined;
    @memcpy(longer[0..frame.len], frame);
    @memcpy(shorter[0..frame.len], frame);
    // One byte more than the frame carries: the buffer is short of its own
    // declaration, which is not the same as a frame that is merely cut.
    longer[3] = 0x03;
    try t.expectError(error.BadLength, codec.decode(longer[0..frame.len]));
    // One byte fewer: the body is a message and the frame has a byte left over,
    // which a decoder that returned it would be handing back unread.
    shorter[3] = 0x01;
    try t.expectError(error.TrailingBytes, codec.decode(shorter[0..frame.len]));
    // A declared body of nothing at all is not a message.
    try t.expectError(error.UnexpectedEnd, codec.decode(&[_]u8{ 0, 0, 0, 0 }));
    // A correct frame with one byte appended.
    var extended: [room]u8 = undefined;
    @memcpy(extended[0..frame.len], frame);
    extended[frame.len] = 0x00;
    try t.expectError(error.TrailingBytes, codec.decode(extended[0 .. frame.len + 1]));
}

test "the stream header round-trips, and a body that is not a topic id is refused" {
    const topic = gossip.TopicId.fromBytes([_]u8{0x5a} ** gossip.topic_id_length);
    var buf: [limits.max_header_size]u8 = undefined;
    const frame = try codec.encodeStreamHeader(codec.StreamHeader.init(topic), &buf);
    try t.expect(frame.len <= limits.max_header_size);
    try t.expectEqual(gossip.topic_id_length, std.mem.readInt(u32, frame[0..4], .big));
    try t.expectEqual(gossip.topic_id_length + 4, frame.len);
    try t.expect((try codec.decodeStreamHeader(frame)).topic_id.eql(topic));

    // One byte short: a header has no length of its own to trust and no second
    // field to skip to, so a body of any other size is not a header.
    var chopped: [limits.max_header_size]u8 = undefined;
    @memcpy(chopped[0..frame.len], frame);
    chopped[3] = @intCast(gossip.topic_id_length - 1);
    try t.expectError(error.BadHeaderSize, codec.decodeStreamHeader(chopped[0 .. frame.len - 1]));
    // One byte long: the body is 33 bytes and the prefix has to say so, or the
    // refusal would be about the bytes left over rather than about the size.
    const longer_len = frame.len + 1;
    var longer: [limits.max_header_size + 1]u8 = undefined;
    @memcpy(longer[0..frame.len], frame);
    longer[frame.len] = 0x5a;
    longer[3] = @intCast(gossip.topic_id_length + 1);
    try t.expectError(error.BadHeaderSize, codec.decodeStreamHeader(longer[0..longer_len]));
}

test "upstream write rejects the exact budget while read admits it" {
    const id = plumtree.MessageId.fromContent("budget");
    const round: u16 = std.math.maxInt(u16);
    // Everything in a `Gossip` body that is not its content: the layer tag, the
    // arm tag, the id, two bytes of length for a content under 4096, the scope
    // tag and three bytes of round.
    const overhead = 1 + 1 + plumtree.id_length + 2 + 1 + 3;
    const content_len = codec.max_message_size - overhead;
    const content = try t.allocator.alloc(u8, content_len + 1);
    defer t.allocator.free(content);
    @memset(content, 0x61);
    const at_budget: codec.Message = .{ .gossip = .{ .gossip = .{
        .id = id,
        .content = content[0..content_len],
        .scope = .{ .swarm = .{ .value = round } },
    } } };
    const over_budget: codec.Message = .{ .gossip = .{ .gossip = .{
        .id = id,
        .content = content,
        .scope = .{ .swarm = .{ .value = round } },
    } } };
    try t.expectEqual(codec.max_message_size, codec.encodedLen(at_budget));
    try t.expectEqual(codec.max_message_size + 1, codec.encodedLen(over_budget));

    var frame_buf: [room]u8 = undefined;
    try t.expectError(error.FrameTooLarge, codec.encode(over_budget, &frame_buf));
    try t.expectError(error.FrameTooLarge, codec.encode(at_budget, &frame_buf));
    var at_writer = postcard.Writer.init(frame_buf[4..]);
    try codec.encodeBody(at_budget, &at_writer);
    std.mem.writeInt(u32, frame_buf[0..4], codec.max_message_size, .big);
    const decoded = (try codec.decode(frame_buf[0 .. 4 + at_writer.finish().len])).gossip.gossip;
    try t.expectEqual(content_len, decoded.content.len);
    try t.expectEqualSlices(u8, content[0..content_len], decoded.content);

    // The same refusal on the way in, against a body this codec would otherwise
    // read: what is refused is the size and not the shape.
    var body_buf: [codec.max_message_size + 1]u8 = undefined;
    var body_writer = postcard.Writer.init(&body_buf);
    try codec.encodeBody(over_budget, &body_writer);
    const body = body_writer.finish();
    try t.expectEqual(codec.max_message_size + 1, body.len);
    const read = (try codec.decodeBody(body)).gossip.gossip;
    try t.expectEqual(content.len, read.content.len);
    var framed: [room]u8 = undefined;
    std.mem.writeInt(u32, framed[0..4], @intCast(body.len), .big);
    @memcpy(framed[4..][0..body.len], body);
    try t.expectError(error.FrameTooLarge, codec.decode(framed[0 .. 4 + body.len]));
}

test "a peer id that is not a canonical point is refused" {
    // A `ShuffleReply` carrying one peer whose id is a y-coordinate at or above
    // the field modulus, which has no curve point. The layer, the arm, the
    // count and the absent contact data are all well formed, so what refuses
    // this is the id and not the framing. Thirty-two zero bytes would not do:
    // that is a point, and `NodeId.fromBytes` accepts it.
    var id_bytes: [NodeId.byte_length]u8 = @splat(0xff);
    id_bytes[31] = 0x7f;
    id_bytes[0] = 0xed;
    var body: [1 + 1 + 1 + NodeId.byte_length + 1]u8 = undefined;
    @memset(&body, 0x00);
    body[0] = 0x00;
    body[1] = 0x03;
    body[2] = 0x01;
    @memcpy(body[3..][0..NodeId.byte_length], &id_bytes);
    try t.expectError(error.NotOnCurve, codec.decodeBody(&body));
}

test "the largest peer list and the largest IHave list round-trip" {
    const peer = try testNodeId(4);
    var infos: [gossip.max_shuffle_nodes]gossip.PeerInfo = undefined;
    for (&infos) |*info| info.* = .{ .id = peer, .data = null };
    var ihaves: [plumtree.max_ihaves_per_message]plumtree.IHave = undefined;
    for (&ihaves, 0..) |*have, index| {
        have.* = .{
            .id = plumtree.MessageId.fromContent("have"),
            .round = .{ .value = @intCast(index) },
        };
    }
    const messages = [_]codec.Message{
        .{ .swarm = .{ .shuffle_reply = .{ .nodes = try gossip.PeerInfos.init(&infos) } } },
        .{ .gossip = .{ .i_have = try plumtree.IHaves.init(&ihaves) } },
    };
    var buf: [room]u8 = undefined;
    var again_buf: [room]u8 = undefined;
    for (messages) |message| {
        const frame = try codec.encode(message, &buf);
        const decoded = try codec.decode(frame);
        try t.expectEqualSlices(u8, frame, try codec.encode(decoded, &again_buf));
    }
    // One entry past each bound is refused by name, on the way in, before a
    // single element of the list is read. The bodies carry a full record per
    // claimed entry, because `readLen` refuses a count the buffer cannot satisfy
    // first and the bound is the rule under test rather than that one.
    const peer_count = gossip.max_shuffle_nodes + 1;
    var too_many: [1 + 1 + 1 + peer_count * (NodeId.byte_length + 1)]u8 = undefined;
    @memset(&too_many, 0x00);
    too_many[0] = 0x00;
    too_many[1] = 0x03;
    too_many[2] = peer_count;
    try t.expectError(error.ShuffleNodeListTooLong, codec.decodeBody(&too_many));
    const ihave_count = plumtree.max_ihaves_per_message + 1;
    var too_many_ihaves: [1 + 1 + 1 + ihave_count * (plumtree.id_length + 1)]u8 = undefined;
    @memset(&too_many_ihaves, 0x00);
    too_many_ihaves[0] = 0x01;
    too_many_ihaves[1] = 0x03;
    too_many_ihaves[2] = ihave_count;
    try t.expectError(error.IHaveListTooLong, codec.decodeBody(&too_many_ihaves));
}

test "maximum owned bytes match the upstream receive frame budget" {
    const data = [_]u8{0x01} ** gossip.peer_data_max;
    const join: codec.Message = .{ .swarm = .{ .join = &data } };
    try t.expectEqual(codec.max_message_size, codec.encodedLen(join));
    const broadcast: codec.Message = .{ .gossip = .{ .gossip = .{
        .id = plumtree.MessageId.fromContent("big"),
        .content = &([_]u8{0x02} ** plumtree.max_content),
        .scope = .neighbors,
    } } };
    try t.expectEqual(codec.max_message_size, codec.encodedLen(broadcast));
}

test "varintLen is the length postcard writes for the same value" {
    const values = [_]u64{ 0, 1, 126, 127, 128, 16_383, 16_384, 65_535, 1 << 21 };
    var buf: [postcard.varintMax(u64)]u8 = undefined;
    for (values) |value| {
        var writer = postcard.Writer.init(&buf);
        try writer.writeLen(@intCast(value));
        try t.expectEqual(writer.finish().len, limits.varintLen(value));
    }
}

test "pinned upstream frames use fixed four-byte big-endian lengths" {
    // Source-derived, not captured: pinned net/util.rs read_lp/write_frame
    // read_u32/write_u32 frame the nested topic message and StreamHeader.
    const prune = [_]u8{ 0, 0, 0, 2, 1, 1 };
    var out: [64]u8 = undefined;
    try t.expectEqualSlices(u8, &prune, try codec.encode(.{ .gossip = .{ .prune = {} } }, &out));
    try t.expectEqualSlices(u8, &prune, try codec.encode(try codec.decode(&prune), &out));
    var header: [36]u8 = @splat(0);
    header[3] = 32;
    const topic = gossip.TopicId.fromBytes(@splat(0));
    try t.expectEqualSlices(u8, &header, try codec.encodeStreamHeader(.{ .topic_id = topic }, &out));
    try t.expect((try codec.decodeStreamHeader(&header)).topic_id.eql(topic));
}

test "frame-fitting upstream vectors and payloads exceed old local capacities" {
    const peer = try testNodeId(5);
    var infos: [9]gossip.PeerInfo = undefined;
    for (&infos) |*info| info.* = .{ .id = peer, .data = null };
    var ihaves: [17]plumtree.IHave = undefined;
    for (&ihaves) |*have| have.* = .{
        .id = plumtree.MessageId.fromContent("wide"),
        .round = .{ .value = 65535 },
    };
    const contact = [_]u8{0x42} ** 257;
    const content = [_]u8{0x43} ** 1025;
    const messages = [_]codec.Message{
        .{ .swarm = .{ .shuffle_reply = .{ .nodes = try gossip.PeerInfos.init(&infos) } } },
        .{ .gossip = .{ .i_have = try plumtree.IHaves.init(&ihaves) } },
        .{ .swarm = .{ .join = &contact } },
        .{ .gossip = .{ .gossip = .{
            .id = plumtree.MessageId.fromContent(&content),
            .content = &content,
            .scope = .neighbors,
        } } },
    };
    var out: [room]u8 = undefined;
    var again: [room]u8 = undefined;
    for (messages) |message| {
        const bytes = try codec.encode(message, &out);
        try t.expectEqualSlices(u8, bytes, try codec.encode(try codec.decode(bytes), &again));
    }
    const owned_contact = try gossip.PeerData.fromBytes(&contact);
    try t.expectEqualSlices(u8, &contact, owned_contact.slice());
    try t.expect(content.len <= plumtree.max_content);
}

test "all ten pinned upstream state serializer variants decode and reencode exactly" {
    // Generated by interop/iroh-peer/src/gossip_vectors.rs from actual public
    // State OutEvent::SendMessage, not hand-built enum payloads or packet capture.
    const fixtures = .{
        @embedFile("fixtures/iroh-2885dd9/join.bin"),
        @embedFile("fixtures/iroh-2885dd9/forward_join.bin"),
        @embedFile("fixtures/iroh-2885dd9/shuffle.bin"),
        @embedFile("fixtures/iroh-2885dd9/shuffle_reply.bin"),
        @embedFile("fixtures/iroh-2885dd9/neighbor.bin"),
        @embedFile("fixtures/iroh-2885dd9/disconnect.bin"),
        @embedFile("fixtures/iroh-2885dd9/gossip.bin"),
        @embedFile("fixtures/iroh-2885dd9/prune.bin"),
        @embedFile("fixtures/iroh-2885dd9/graft.bin"),
        @embedFile("fixtures/iroh-2885dd9/ihave.bin"),
    };
    var out: [room]u8 = undefined;
    inline for (fixtures, 0..) |bytes, index| {
        const decoded = try codec.decode(bytes);
        const layer: u8 = if (index < 6) 0 else 1;
        const arm: u8 = @intCast(if (index < 6) index else index - 6);
        const body = try bodyOf(bytes);
        try t.expectEqual(layer, body[0]);
        try t.expectEqual(arm, body[1]);
        try t.expectEqualSlices(u8, bytes, try codec.encode(decoded, &out));
        if (index == 6) try t.expect(decoded.gossip.gossip.validate());
    }
    const header = @embedFile("fixtures/iroh-2885dd9/header.bin");
    const decoded_header = try codec.decodeStreamHeader(header);
    try t.expectEqualSlices(u8, &([_]u8{0x74} ** 32), &decoded_header.topic_id.bytes);
    try t.expectEqualSlices(u8, header, try codec.encodeStreamHeader(decoded_header, &out));
}

test "actual upstream boundary vectors retain contact content and long vectors" {
    const contact = try codec.decode(@embedFile("fixtures/iroh-2885dd9/peer_data_300.bin"));
    try t.expectEqual(@as(usize, 300), contact.swarm.join.?.len);
    const shuffle = try codec.decode(@embedFile("fixtures/iroh-2885dd9/shuffle_large.bin"));
    try t.expect(shuffle.swarm.shuffle.nodes.count >= 9);
    const ihave = try codec.decode(@embedFile("fixtures/iroh-2885dd9/ihave_large.bin"));
    try t.expect(ihave.gossip.i_have.count >= 17);
    const payload = try codec.decode(@embedFile("fixtures/iroh-2885dd9/gossip_large.bin"));
    try t.expectEqual(@as(usize, 2048), payload.gossip.gossip.content.len);
    try t.expect(payload.gossip.gossip.validate());
}

test "decoded PeerData is copied before receive storage is reused" {
    const original = [_]u8{0x42} ** 300;
    var frame: [room]u8 = undefined;
    const encoded = try codec.encode(.{ .swarm = .{ .join = &original } }, &frame);
    const borrowed = (try codec.decode(encoded)).swarm.join.?;
    var contacts: @import("hyparview/peer_data.zig").PeerDataMap = .{};
    const peer = try testNodeId(6);
    try contacts.put(peer, borrowed);
    @memset(&frame, 0xa5);
    const stored = contacts.get(peer) orelse return error.MissingContactData;
    try t.expectEqualSlices(u8, &original, stored.slice());
}
