//! Fuzz target for the gossip wire codec: `gossip/codec.zig` and the five
//! files under `gossip/codec/` that own its logic.
//!
//! One target file and one corpus directory per decoder: `zig build fuzz`
//! replays the corpus, and `zig build fuzz --fuzz=<N>` hands the same corpus
//! to Zig's coverage-guided fuzzer and lets it mutate for N iterations.
//!
//! **The decoders are the production ones, reached through the `ozai` module
//! and not re-derived here.** A fuzz target carrying its own copy of the codec
//! would prove something about the copy, and the copy is what a mutation would
//! be mutating. Every call below is a call into `ozai.gossip_codec`.
//!
//! # What this target adds to `gossip/codec_test.zig`
//!
//! That file holds the wire format down with fixed literals and declared byte
//! sequences, and it is where the tags and the field order are pinned, down to
//! the name of every refusal a tag past a table gets. What it cannot do is let
//! a fuzzer choose what goes *inside* a message, and that is where a length
//! that disagrees with its content would show. So this file builds the same
//! fifteen messages with the payloads, the counts and the lengths the fuzz
//! bytes spell, and asks four questions of each one:
//!
//! 1. **Refusal.** A frame and a body are the two entry points `codec.zig`
//!    publishes, and both are offered every input. A peer controls the bytes
//!    and nothing else, so the codec must reach a decision about all of them.
//! 2. **The borrow.** Every slice a decoded message carries is a slice of the
//!    frame it was read from — the rule `codec/frame.zig` states three times —
//!    so a caller may hold one exactly as long as it holds the frame and not a
//!    byte longer. This is the one property of a decode that no field
//!    comparison catches, because a message assembled from borrowed slices and
//!    one assembled from copies compare equal either way.
//! 3. **The tag.** The first byte of a body is the layer, and `codec/tags.zig`
//!    says the numbering is upstream's declaration order. That is read off the
//!    declared table here rather than off the encoder, so an encoder and a
//!    decoder that agreed on the wrong number would still be caught.
//! 4. **The value, fixed point and extent.** Decoding an encoded message keeps
//!    its fields; re-encoding is stable and never grows past the input.
//!
//! # What is not pinned
//!
//! The pinned upstream serializer vectors and live interoperability checks are
//! separate evidence. These oracles check totality, semantic preservation and
//! canonicalization, not interoperability by themselves.

const std = @import("std");
const ozai = @import("ozai");
const codec = ozai.gossip_codec;
const gossip = ozai.gossip_hyparview;
const plumtree = ozai.gossip_plumtree;
const t = std.testing;

const Message = codec.Message;
const NodeId = ozai.NodeId;

/// Seeds are the bytes a peer would send as one frame.
///
/// They are the shapes the codec has a rule for and no valid frame has: no
/// frame at all, a prefix with no body, a prefix naming more bytes than are
/// behind it, a prefix naming fewer, a layer tag no arm names and the same one
/// spelled two groups long, an arm tag one past each of the two tables, a
/// `Priority` past its table, a `bool` that is neither 0 nor 1, an arm tag with
/// nothing behind it, and two whole frames — a `Prune` and a `Disconnect` —
/// because a seed that decodes is a seed a mutation can go somewhere from.
///
/// They are here as *inputs*, not as assertions. The names a tag past a table
/// gets are `codec_test.zig`'s to hold and this file does not repeat them; what
/// it needs from those seeds is somewhere for the fuzzer to start.
///
/// Inline seeds keep ordinary replay and coverage-guided mutation on the same
/// fixed-width frame inputs.
const corpus = [_][]const u8{
    &.{}, // No prefix at all.
    &.{0x02}, // A short fixed-width prefix; also the retained crash input.
    &.{ 0x00, 0x00, 0x00, 0x40 }, // Length past the end.
    &.{ 0x00, 0x00, 0x00, 0x02, 0x01, 0x01, 0x00 }, // Trailing byte.
    &.{ 0x00, 0x00, 0x00, 0x01, 0x02 }, // Unknown layer.
    &.{ 0x00, 0x00, 0x00, 0x02, 0x80, 0x01 }, // Wide layer varint.
    &.{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x06 }, // Unknown swarm arm.
    &.{ 0x00, 0x00, 0x00, 0x02, 0x01, 0x04 }, // Unknown tree arm.
    &.{ 0x00, 0x00, 0x00, 0x04, 0x00, 0x04, 0x02, 0x00 }, // Unknown priority.
    &.{ 0x00, 0x00, 0x00, 0x04, 0x00, 0x05, 0x02, 0x00 }, // Bad bool.
    &.{ 0x00, 0x00, 0x00, 0x01, 0x00 }, // Truncated arm tag.
    &.{ 0x00, 0x00, 0x00, 0x02, 0x01, 0x01 }, // Whole Prune.
    &.{ 0x00, 0x00, 0x00, 0x04, 0x00, 0x05, 0x01, 0x00 }, // Whole Disconnect.
};

/// Long enough for a seed and for a mutated input to still reach a check it was
/// not grown for, and short enough that one run is bounded by the window rather
/// than by the fuzzer.
const input_buffer_len = 128;

/// A buffer every frame and every body this file writes fits in: a body is at
/// most the byte budget, with a fixed four-byte big-endian length prefix.
const room = codec.max_message_size + codec.max_prefix_size;

/// How many ids a run derives from seeds, and so how many messages can name
/// more than one peer.
///
/// A `NodeId` cannot be built from arbitrary bytes — `fromBytes` refuses a
/// non-point — so the pool draws from seeds, which is what
/// `gossip/plumtree/test_node_id.zig` does for the codec's own tests. Two is
/// enough for every arm: a `Shuffle` names an origin and a list, and a list of
/// two is where a count stops being the only element in it.
const pool = 2;

/// The fuzzer keeps one of these by pointer for the whole run, so it is empty by
/// design: everything the oracle needs is comptime.
const Context = struct {};

test "gossip codec decode" {
    // A fuzz test is a plain test to a plain build. Without `-ffuzz` the runner
    // walks the corpus instead of handing it to the fuzzer, which is what makes
    // a bare `zig build fuzz` a bounded gate rather than an empty step.
    try t.fuzz(Context{}, testOne, .{ .corpus = &corpus });
}

test "gossip codec fuzz oracle reads fixed-width frames" {
    // A postcard byte-string reader would see the first zero as an empty body.
    const frame = &[_]u8{ 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00 };
    try t.expectEqualSlices(u8, &.{ 0x00, 0x00, 0x00 }, try bodyOf(frame));
    try t.expectEqual(@as(usize, frame.len), try checkMessage(try codec.decode(frame)));
    try t.expectError(error.UnexpectedEnd, bodyOf(&.{0x02}));
    try t.expectError(error.BadLength, bodyOf(&.{ 0x00, 0x00, 0x00, 0x03 }));
    try t.expectError(error.TrailingBytes, bodyOf(&.{ 0x00, 0x00, 0x00, 0x00, 0x00 }));
}

fn testOne(_: Context, smith: *t.Smith) anyerror!void {
    var buffer: [input_buffer_len]u8 = undefined;
    // `in` is the corpus entry verbatim while the corpus is replayed, and null
    // when the fuzzer drives, in which case `slice` consumes its input.
    const bytes = if (smith.in) |replay| replay else buffer[0..smith.slice(&buffer)];
    var peers: [pool]NodeId = undefined;
    for (&peers, 0..) |*peer, index| peer.* = try peerId(index);
    try checkRefusal(bytes);
    try checkRoundTrip(bytes, peers);
    try checkStreamHeader(bytes);
}

/// Every fuzz input offered to both entry points, and each refusal held to the
/// codec's own error set.
fn checkRefusal(bytes: []const u8) !void {
    // A frame is what arrives on a stream and a body is what arrives behind a
    // split one. A decoder that had only ever been shown one of them has not
    // been shown the other, and `codec.zig` publishes both.
    if (codec.decode(bytes)) |message| {
        try t.expect(borrowsFrom(bytes, message));
        // A frame that decoded is a message this codec can write, which is what
        // the value oracle asks about, and its canonical spelling is never
        // longer than the frame it was read from.
        const canonical = try checkMessage(message);
        try t.expect(canonical <= bytes.len);
    } else |err| {
        try expectRefusal(err);
    }
    if (codec.decodeBody(bytes)) |message| {
        try t.expect(borrowsFrom(bytes, message));
        const canonical = try checkMessage(message);
        // The body arrived without a prefix, so the only claim available is that
        // the framed spelling of what came out is no longer than the body plus
        // the widest prefix a frame can carry.
        try t.expect(canonical <= bytes.len + codec.max_prefix_size);
    } else |err| {
        try expectRefusal(err);
    }
}

/// The fifteen arms, with the payloads, the counts and the lengths the fuzz
/// bytes spell rather than fixed ones.
fn checkRoundTrip(bytes: []const u8, peers: [pool]NodeId) !void {
    const messages = try buildMessages(bytes, peers);
    for (messages) |message| _ = try checkMessage(message);
}

/// One message: its own spelling and what came back out of it.
///
/// This answers every question in the file comment except the extent, which is
/// the caller's to state because only the caller knows which of the two entry
/// points the bytes arrived at. It returns the length of the canonical frame,
/// which is the number the extent oracle is stated against.
fn checkMessage(message: Message) !usize {
    var frame_buf: [room]u8 = undefined;
    var again_buf: [room]u8 = undefined;
    const frame = try codec.encode(message, &frame_buf);

    // Oracle: size. `encodedLen` is what a caller sizes every buffer from, so it
    // has to be the byte count `encode` wrote and not an upper bound.
    const body = try bodyOf(frame);
    try t.expectEqual(codec.encodedLen(message), body.len);

    const decoded = try codec.decode(frame);
    try expectMessageEqual(message, decoded);
    try expectMessageEqual(message, try codec.decodeBody(body));

    // Oracle: the borrow. Every slice the decoded message carries is a slice of
    // the frame it was read from, so a caller may hold one exactly as long as
    // it holds the frame. A message assembled from copies compares equal and
    // still fails this.
    try t.expect(borrowsFrom(frame, decoded));

    // Oracle: the tag, off the byte and not off the encoder. `codec/tags.zig`
    // says the first byte of a body is the layer and that the numbering is
    // upstream's declaration order, so that byte is the tag value the table
    // gives this layer. An encoder and a decoder that agreed on a different
    // number would pass a round trip and fail here.
    const layer: u8 = switch (decoded) {
        .swarm => @backingInt(codec.Layer.swarm),
        .gossip => @backingInt(codec.Layer.gossip),
    };
    try t.expectEqual(layer, body[0]);

    // Oracle: the fixed point. postcard does not enforce canonicalization, so
    // the encoding that comes back is the codec's own spelling rather than the
    // one that was sent, and the fixed point is taken from it either way.
    const again = try codec.encode(decoded, &again_buf);
    try t.expectEqualSlices(u8, frame, again);

    // Oracle: every generated or admitted message here is below the write
    // budget. Receiving exactly the budget is legal but writing it is not;
    // the bounded input window never generates that boundary.
    try t.expect(codec.encodedLen(decoded) <= codec.max_message_size);
    return frame.len;
}

/// The header a stream opens with, and the bytes that are not one.
fn checkStreamHeader(bytes: []const u8) !void {
    var frame_buf: [codec.max_header_size]u8 = undefined;
    var again_buf: [codec.max_header_size]u8 = undefined;
    const topic = gossip.TopicId.fromBytes(taken(gossip.topic_id_length, bytes, 0));
    const frame = try codec.encodeStreamHeader(codec.StreamHeader.init(topic), &frame_buf);
    // Oracle: size. A header body is a topic id and nothing else, so its length
    // is the one the type declares, behind a fixed four-byte big-endian prefix.
    try t.expectEqual(codec.StreamHeader.encoded_size, (try bodyOf(frame)).len);
    try t.expect(frame.len <= codec.max_header_size);

    // Oracle: the fixed point, over a topic the fuzzer chose rather than one
    // written out by hand. `decodeStreamHeader` copies the id out, so nothing in
    // the result borrows the frame and the two may be separate buffers.
    const decoded = try codec.decodeStreamHeader(frame);
    try t.expect(decoded.topic_id.eql(topic));
    const again = try codec.encodeStreamHeader(decoded, &again_buf);
    try t.expectEqualSlices(u8, frame, again);

    // Oracle: refusal. A header frame is a length prefix and a topic id and
    // nothing else, so arbitrary bytes are refused or they are a header — and
    // a header that was read must read back as the same topic.
    if (codec.decodeStreamHeader(bytes)) |header| {
        const spelled = try codec.encodeStreamHeader(header, &frame_buf);
        try t.expect(header.topic_id.eql(
            (try codec.decodeStreamHeader(spelled)).topic_id,
        ));
    } else |err| {
        try expectRefusal(err);
    }
}

/// Every arm of both layers, with a fuzz-derived payload in each of the four
/// places one appears: a `Join`, a `ForwardJoin`'s peer, a `Neighbor`, and a
/// `Gossip`'s content.
///
/// Both priorities, both scopes, an absent and a present option in each of the
/// places one appears, an empty and a non-empty byte string, and a peer list
/// and an `IHave` list with more than one entry, because a list of one has no
/// count a decoder could get wrong.
fn buildMessages(bytes: []const u8, peers: [pool]NodeId) ![15]Message {
    const infos = try gossip.PeerInfos.init(&.{
        .{ .id = peers[0], .data = null },
        .{ .id = peers[1], .data = bytes },
    });
    const ihaves = try plumtree.IHaves.init(&.{
        .{
            .id = plumtree.MessageId.fromBytes(taken(plumtree.id_length, bytes, 0)),
            .round = roundOf(bytes, 1),
        },
        .{
            .id = plumtree.MessageId.fromBytes(taken(plumtree.id_length, bytes, 2)),
            .round = roundOf(bytes, 3),
        },
    });
    const payload_id = plumtree.MessageId.fromBytes(taken(plumtree.id_length, bytes, 4));
    const round = roundOf(bytes, 5);
    return .{
        .{ .swarm = .{ .join = null } },
        .{ .swarm = .{ .join = bytes } },
        .{ .swarm = .{ .forward_join = .{
            .peer = .{ .id = peers[0], .data = bytes },
            .ttl = .{ .value = round.value },
        } } },
        .{ .swarm = .{ .shuffle = .{
            .origin = peers[1],
            .nodes = infos,
            .ttl = .{ .value = round.value },
        } } },
        .{ .swarm = .{ .shuffle_reply = .{ .nodes = infos } } },
        .{ .swarm = .{ .neighbor = .{ .priority = .high, .data = null } } },
        .{ .swarm = .{ .neighbor = .{ .priority = .low, .data = bytes } } },
        .{ .swarm = .{ .disconnect = .{ .alive = true } } },
        .{ .swarm = .{ .disconnect = .{ .alive = false } } },
        .{ .gossip = .{ .prune = {} } },
        .{ .gossip = .{ .gossip = .{
            .id = payload_id,
            .content = bytes,
            .scope = .{ .swarm = round },
        } } },
        .{ .gossip = .{ .gossip = .{
            .id = payload_id,
            .content = "",
            .scope = .neighbors,
        } } },
        .{ .gossip = .{ .graft = .{ .id = null, .round = round } } },
        .{ .gossip = .{ .graft = .{ .id = payload_id, .round = round } } },
        .{ .gossip = .{ .i_have = ihaves } },
    };
}

/// The bytes after the fixed big-endian frame length, checked independently
/// against the actual extent rather than parsed as a postcard byte string.
fn bodyOf(frame: []const u8) ![]const u8 {
    if (frame.len < codec.max_prefix_size) return error.UnexpectedEnd;
    const length = std.mem.readInt(u32, frame[0..4], .big);
    const body = frame[codec.max_prefix_size..];
    if (length > body.len) return error.BadLength;
    if (length < body.len) return error.TrailingBytes;
    return body;
}

/// Compare active values, not the undefined spare capacity of inline lists.
fn expectMessageEqual(expected: Message, actual: Message) !void {
    try t.expectEqual(std.meta.activeTag(expected), std.meta.activeTag(actual));
    switch (expected) {
        .swarm => |inner| {
            try t.expectEqual(std.meta.activeTag(inner), std.meta.activeTag(actual.swarm));
            switch (inner) {
                .shuffle => |shuffle| {
                    const decoded = actual.swarm.shuffle;
                    try t.expectEqualDeep(shuffle.origin, decoded.origin);
                    try t.expectEqualDeep(shuffle.ttl, decoded.ttl);
                    try t.expectEqualDeep(shuffle.nodes.slice(), decoded.nodes.slice());
                },
                .shuffle_reply => |reply| {
                    try t.expectEqualDeep(
                        reply.nodes.slice(),
                        actual.swarm.shuffle_reply.nodes.slice(),
                    );
                },
                else => try t.expectEqualDeep(expected, actual),
            }
        },
        .gossip => |inner| {
            try t.expectEqual(std.meta.activeTag(inner), std.meta.activeTag(actual.gossip));
            switch (inner) {
                .i_have => |ihaves| {
                    try t.expectEqualDeep(ihaves.slice(), actual.gossip.i_have.slice());
                },
                else => try t.expectEqualDeep(expected, actual),
            }
        },
    }
}

/// Whether every byte string the message carries lies inside `frame`.
///
/// An empty borrow is not checked: postcard writes no bytes for a length of
/// zero, so the slice a reader hands back for one may point anywhere, and the
/// rule has nothing to say about a byte string of no bytes.
fn borrowsFrom(frame: []const u8, message: Message) bool {
    return switch (message) {
        .swarm => |inner| switch (inner) {
            .join => |data| borrowed(frame, data),
            .forward_join => |forward| borrowed(frame, forward.peer.data),
            .shuffle => |shuffle| infosBorrow(frame, shuffle.nodes),
            .shuffle_reply => |reply| infosBorrow(frame, reply.nodes),
            .neighbor => |neighbor| borrowed(frame, neighbor.data),
            .disconnect => true,
        },
        .gossip => |inner| switch (inner) {
            .gossip => |payload| borrowed(frame, payload.content),
            .prune => true,
            .graft => true,
            .i_have => true,
        },
    };
}

/// The same for a peer list, whose entries are inline arrays rather than slices.
fn infosBorrow(frame: []const u8, list: gossip.PeerInfos) bool {
    for (list.slice()) |info| {
        if (!borrowed(frame, info.data)) return false;
    }
    return true;
}

/// Whether one optional byte string is a slice of `frame`.
fn borrowed(frame: []const u8, data: ?[]const u8) bool {
    const bytes = data orelse return true;
    if (bytes.len == 0) return true;
    const base = @intFromPtr(frame.ptr);
    const at = @intFromPtr(bytes.ptr);
    return at >= base and at + bytes.len <= base + frame.len;
}

/// That `err` is a rule the codec broke and not something else.
///
/// `codec.decode` is typed `Error!Message`, so this catch binds a member of the
/// set `codec/limits.zig` composes out of postcard's, the key module's and both
/// layers', plus the three the codec adds. The one member that would mean
/// something other than a rule was broken is `error.OutOfMemory`, and this path
/// allocates nothing at all — a codec over caller buffers with no allocator of
/// its own — so a decode that failed for it is a finding about the codec rather
/// than a fact about the input.
fn expectRefusal(err: codec.Error) !void {
    try t.expect(err != error.OutOfMemory);
}

/// The `index`-th peer of the pool, from a seed.
fn peerId(index: usize) !NodeId {
    var seed: [ozai.SecretKey.seed_length]u8 = undefined;
    @memset(&seed, 0xa5);
    seed[0] = @intCast(index + 1);
    return (try ozai.SecretKey.fromSeed(seed)).nodeId();
}

/// A round the fuzz bytes chose, taken over the whole `u16` its type spans so
/// that the one-, two- and three-byte varint widths all get written.
fn roundOf(bytes: []const u8, index: usize) plumtree.Round {
    return .{ .value = @as(u16, bytesAt(bytes, index)) *% 257 };
}

/// `length` bytes out of the fuzz bytes, offset by `index` so that two ids in
/// one message are not the same id. The length is the module's own, which is
/// what makes this usable for a `MessageId` and for a `TopicId` alike.
fn taken(comptime length: usize, bytes: []const u8, index: usize) [length]u8 {
    var out: [length]u8 = undefined;
    for (&out, 0..) |*byte, at| byte.* = bytesAt(bytes, at + index);
    // zbc does not prove that iterating over &out assigns every fixed-array element.
    // zbc-disable-next-line: use-undefined
    return out;
}

/// `bytes` at `index`, or zero past its end. A seed shorter than a table index
/// is a case and not a fault, and zero is a value every table here has an entry
/// for.
fn bytesAt(bytes: []const u8, index: usize) u8 {
    return if (index < bytes.len) bytes[index] else 0;
}
