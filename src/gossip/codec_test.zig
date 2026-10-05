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
    var reader = postcard.Reader.init(frame);
    return reader.readBytes();
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
    // `gossip/prune` is the smallest frame there is: a layer tag, an arm tag and
    // a one-byte length.
    var buf: [room]u8 = undefined;
    const frame = try codec.encode(.{ .gossip = .{ .prune = {} } }, &buf);
    try t.expectEqualSlices(u8, &.{ 0x02, 0x01, 0x01 }, frame);
    var longer: [room]u8 = undefined;
    var shorter: [room]u8 = undefined;
    @memcpy(longer[0..frame.len], frame);
    @memcpy(shorter[0..frame.len], frame);
    // One byte more than the frame carries: the buffer is short of its own
    // declaration, which is not the same as a frame that is merely cut.
    longer[0] = 0x03;
    try t.expectError(error.BadLength, codec.decode(longer[0..frame.len]));
    // One byte fewer: the body is a message and the frame has a byte left over,
    // which a decoder that returned it would be handing back unread.
    shorter[0] = 0x01;
    try t.expectError(error.TrailingBytes, codec.decode(shorter[0..frame.len]));
    // A declared body of nothing at all is not a message.
    try t.expectError(error.UnexpectedEnd, codec.decode(&[_]u8{0x00}));
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
    // The first byte is the length of everything behind it, and a topic id is
    // all of that: one prefix octet plus the id, and the two cases below are
    // this one taken apart by a byte at each end.
    try t.expectEqual(gossip.topic_id_length, @as(usize, frame[0]));
    try t.expectEqual(gossip.topic_id_length + 1, frame.len);
    try t.expect((try codec.decodeStreamHeader(frame)).topic_id.eql(topic));

    // One byte short: a header has no length of its own to trust and no second
    // field to skip to, so a body of any other size is not a header.
    var chopped: [limits.max_header_size]u8 = undefined;
    @memcpy(chopped[0..frame.len], frame);
    chopped[0] = @intCast(frame.len - 2);
    try t.expectError(error.BadHeaderSize, codec.decodeStreamHeader(chopped[0 .. frame.len - 1]));
    // One byte long: the body is 33 bytes and the prefix has to say so, or the
    // refusal would be about the bytes left over rather than about the size.
    const longer_len = frame.len + 1;
    var longer: [limits.max_header_size]u8 = undefined;
    @memcpy(longer[0..frame.len], frame);
    longer[frame.len] = 0x5a;
    longer[0] = @intCast(longer_len - 1);
    try t.expectError(error.BadHeaderSize, codec.decodeStreamHeader(longer[0..longer_len]));
}

test "a body at the byte budget is written and one byte over is refused" {
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
    const frame = try codec.encode(at_budget, &frame_buf);
    const decoded = (try codec.decode(frame)).gossip.gossip;
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
    var framed_writer = postcard.Writer.init(&framed);
    try framed_writer.writeBytes(body);
    try t.expectError(error.FrameTooLarge, codec.decode(framed_writer.finish()));
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
    for (&infos) |*info| info.* = .{ .id = peer, .data = "data" };
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
    var too_many: [1 + 1 + 1 + 9 * (NodeId.byte_length + 1)]u8 = undefined;
    @memset(&too_many, 0x00);
    too_many[0] = 0x00;
    too_many[1] = 0x03;
    too_many[2] = 0x09;
    try t.expectError(error.ShuffleNodeListTooLong, codec.decodeBody(&too_many));
    var too_many_ihaves: [1 + 1 + 1 + 17 * (plumtree.id_length + 1)]u8 = undefined;
    @memset(&too_many_ihaves, 0x00);
    too_many_ihaves[0] = 0x01;
    too_many_ihaves[1] = 0x03;
    too_many_ihaves[2] = 0x11;
    try t.expectError(error.IHaveListTooLong, codec.decodeBody(&too_many_ihaves));
}

test "the floor carries a full membership message and not a full broadcast" {
    const data = [_]u8{0x01} ** gossip.peer_data_max;
    const join: codec.Message = .{ .swarm = .{ .join = &data } };
    try t.expect(codec.encodedLen(join) <= codec.min_message_size);
    const broadcast: codec.Message = .{ .gossip = .{ .gossip = .{
        .id = plumtree.MessageId.fromContent("big"),
        .content = &([_]u8{0x02} ** plumtree.max_content),
        .scope = .{ .swarm = .{ .value = 0 } },
    } } };
    // A `max_content` payload does not fit the floor, which is upstream's floor
    // too, and is why upstream's default is four times it. The default has to
    // carry one: a configuration that did not would refuse every full broadcast.
    try t.expect(codec.encodedLen(broadcast) > codec.min_message_size);
    try t.expect(codec.encodedLen(broadcast) <= codec.max_message_size);
}

test "varintLen is the length postcard writes for the same value" {
    const values = [_]u64{ 0, 1, 126, 127, 128, 16_383, 16_384, 65_535, 1 << 21 };
    var buf: [limits.max_prefix_size]u8 = undefined;
    for (values) |value| {
        var writer = postcard.Writer.init(&buf);
        try writer.writeLen(@intCast(value));
        try t.expectEqual(writer.finish().len, limits.varintLen(value));
    }
}
