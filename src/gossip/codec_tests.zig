//! The wire codec's tests: the frames upstream produced, and the rules the
//! frames themselves could not carry.
//!
//! # Why this file exists
//!
//! `codec.zig` and its two layers hold production code with no tests of its
//! own, because the assertions belong to the evidence rather than to the
//! modules: every vector below is a frame `n0-computer/iroh-gossip` 0.101.0
//! emitted, captured in `vector-captures/gossip-upstream-gaps` (run_seed 1)
//! and named after the file it came from. A test that asserted a byte string
//! this project invented would assert nothing about interoperation; a test that
//! replays upstream's own output asserts that the two implementations read the
//! same wire.
//!
//! All 1373 captured frames decode under this codec with no byte left over.
//! Fifteen are pinned here — one per shape, plus the two rules a
//! reimplementation gets wrong and the types cannot show: the obsolete
//! `_respond` byte behind `Disconnect.alive`, and `Swarm` before `Neighbors`.
//!
//! # The rest of the assertions
//!
//! The `StreamHeader` frame and the `u32` length prefix are the two shapes the
//! capture could not emit, both private to upstream's `net::util`; the tests
//! for those check the rules from `src/net/util.rs:359,365,384,390` directly,
//! including the asymmetry between the write side and the read side at
//! `max_message_size`. The chunk arithmetic is pinned the same way: with a
//! 512-byte budget upstream emitted 13-entry `IHave` frames, so that is what
//! `ihaveChunkLen(512)` has to return.
//!
//! Reached exactly once, through the native unit root `src/unit_test.zig`, the
//! way `node/node_tests.zig` and `node/node_retirement_tests.zig` are.

const std = @import("std");
const postcard = @import("../wire/postcard.zig");
const key = @import("../base/key.zig");
const plumtree = @import("plumtree.zig");
const hyparview = @import("hyparview.zig");
const codec = @import("codec.zig");
const tree_codec = @import("tree_codec.zig");

const testing = std.testing;
const NodeId = key.NodeId;

/// One captured frame: what it is, where it came from, and its bytes.
const Golden = struct {
    shape: []const u8,
    file: []const u8,
    hex: []const u8,
};

/// Long enough for every vector in `goldens`; the longest is 70 bytes. A fixed
/// buffer rather than an allocation, because a codec that needs a heap to be
/// tested is a codec that will need one in production.
const golden_room = 128;

const goldens = [_]Golden{
    .{
        .shape = "Swarm(Join(None))",
        .file = "no_data/00000.wire.bin",
        .hex = "000000",
    },
    .{
        .shape = "Swarm(Join(Some(boundary-0)))",
        .file = "boundary/00000.wire.bin",
        .hex = "0000010a626f756e646172792d30",
    },
    .{
        .shape = "Swarm(ForwardJoin{ttl 6})",
        .file = "chunk_probe/00008.wire.bin",
        .hex = "000191911a511b83a8f59c1adc1124afc90ff190cdd8627763c22495c94a86ccd5b6" ++
            "01076368756e6b2d6106",
    },
    .{
        .shape = "Swarm(Shuffle{ttl 6, one peer})",
        .file = "membership/00010.wire.bin",
        .hex = "00020039c2fbc3645537d5e9e8a0a09343cbeebd45498b390ff8c876fd78fd41abfa" ++
            "010039c2fbc3645537d5e9e8a0a09343cbeebd45498b390ff8c876fd78fd41abfa" ++
            "010006",
    },
    .{
        .shape = "Swarm(ShuffleReply([one peer, empty data]))",
        .file = "membership/00015.wire.bin",
        .hex = "0003010039c2fbc3645537d5e9e8a0a09343cbeebd45498b390ff8c876fd78fd41abfa" ++
            "0100",
    },
    .{
        .shape = "Swarm(Neighbor{high, empty data})",
        .file = "boundary/00001.wire.bin",
        .hex = "0004000100",
    },
    .{
        .shape = "Swarm(Neighbor{low, membership-node-2})",
        .file = "membership/00017.wire.bin",
        .hex = "00040101116d656d626572736869702d6e6f64652d32",
    },
    .{
        .shape = "Swarm(Disconnect{alive, _respond false})",
        .file = "membership/00070.wire.bin",
        .hex = "00050100",
    },
    .{
        .shape = "Swarm(Disconnect{gone, _respond false})",
        .file = "membership/00050.wire.bin",
        .hex = "00050000",
    },
    .{
        .shape = "Gossip(Gossip{swarm 0, chunk-warmup})",
        .file = "chunk_probe/00012.wire.bin",
        .hex = "010065134ae95cd83c4e98e68dba751e23b42f8c3739fe4e769b92971db472fd89eb" ++
            "0c6368756e6b2d7761726d7570000",
    },
    .{
        .shape = "Gossip(Gossip{neighbors, pt-neighbors-only})",
        .file = "plumtree/00018.wire.bin",
        .hex = "01009d0b2585cfafc34e2036e91953581c00d73a52cc0b12081517b57dfb940d7dba" ++
            "1270742d6e65696768626f7572732d6f6e6c7901",
    },
    .{
        .shape = "Gossip(Prune)",
        .file = "chunk_probe/00016.wire.bin",
        .hex = "0101",
    },
    .{
        .shape = "Gossip(Graft{some id, round 0})",
        .file = "graft/00024.wire.bin",
        .hex = "010201d934f4190d051cc7f0263637d90a33150ee68a4d01a1b583a700933c6d3274b" ++
            "a00",
    },
    .{
        .shape = "Gossip(Graft{none, round 0})",
        .file = "optimization/00021.wire.bin",
        .hex = "01020000",
    },
    .{
        .shape = "Gossip(IHave([round 107]))",
        .file = "chunk_probe/00020.wire.bin",
        .hex = "010301fb928202fd793912007a98e8943669fec4d2b0c59acbe641659240d6f10a71" ++
            "eb00",
    },
};

/// Decode one captured payload and write it back, byte for byte: one assertion
/// per vector that this codec both reads a peer and speaks to one.
fn expectGoldenRoundTrip(golden: Golden) !void {
    var bytes: [golden_room]u8 = undefined;
    const length = try std.fmt.hexToBytes(bytes[0 .. golden.hex.len / 2], golden.hex);

    var reader = postcard.Reader.init(bytes[0..length]);
    const message = try codec.decodeMessage(&reader);
    try reader.finish();

    var buffer: [codec.max_message_size]u8 = undefined;
    var writer = postcard.Writer.init(&buffer);
    try codec.encodeMessage(&writer, message);
    testing.expectEqualSlices(u8, bytes[0..length], writer.finish()) catch |err| {
        std.debug.print("{s} ({s}): {s}\n", .{
            golden.shape,
            golden.file,
            @errorName(err),
        });
        return err;
    };
}

fn expectMessageError(bytes: []const u8, want: anyerror) !void {
    var reader = postcard.Reader.init(bytes);
    try testing.expectError(want, codec.decodeMessage(&reader));
}

test "golden: every captured shape reads and re-encodes to its own bytes" {
    for (goldens) |golden| try expectGoldenRoundTrip(golden);
}

test "golden: the decoded fields are the ones the capture describes" {
    var bytes: [golden_room]u8 = undefined;

    // `IHave` with one entry at round 107: a round that needs two varint
    // bytes, which is what the byte budget in `ihaveChunkLen` is sized for.
    const listed_hex = goldens[goldens.len - 1].hex;
    const listed_length = try std.fmt.hexToBytes(bytes[0..36], listed_hex);
    var listed_reader = postcard.Reader.init(bytes[0..listed_length]);
    const listed = (try codec.decodeMessage(&listed_reader)).gossip.i_have;
    try testing.expectEqual(@as(u16, 1), listed.count);
    try testing.expectEqual(@as(u16, 107), listed.items[0].round.value);

    // `Neighbor` carries a priority before its optional data, and the data is
    // what the capture says it is.
    const neighbor_hex = goldens[6].hex;
    const neighbor_length = try std.fmt.hexToBytes(bytes[0..22], neighbor_hex);
    var neighbor_reader = postcard.Reader.init(bytes[0..neighbor_length]);
    const neighbor = (try codec.decodeMessage(&neighbor_reader)).swarm.neighbor;
    try testing.expectEqual(hyparview.Priority.low, neighbor.priority);
    try testing.expectEqualStrings("membership-node-2", neighbor.data.?);

    // The `Graft` that carries no id, and the round beside it.
    var graft_reader = postcard.Reader.init(&.{ 1, 2, 0, 0 });
    const graft = (try codec.decodeMessage(&graft_reader)).gossip.graft;
    try testing.expect(graft.id == null);
    try testing.expectEqual(@as(u16, 0), graft.round.value);
}

test "a frame is a big-endian u32 in front, and nothing else" {
    var buffer: [codec.max_message_size + codec.frame_prefix_length]u8 = undefined;
    const frame = try codec.encodeFrame(&buffer, .{ .gossip = .prune });
    // `Prune` is the two bytes `01 01`, and the prefix is the length 2.
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 2, 1, 1 }, frame);

    // The same message without the prefix is what `encodeMessage` writes, so
    // the prefix belongs to the frame and not to postcard.
    var body: [16]u8 = undefined;
    var body_writer = postcard.Writer.init(&body);
    try codec.encodeMessage(&body_writer, .{ .gossip = .prune });
    try testing.expectEqualSlices(u8, frame[codec.frame_prefix_length..], body_writer.finish());
}

test "the write side refuses a frame of max bytes and the read side takes it" {
    var prefix: [codec.max_message_size + codec.frame_prefix_length]u8 = undefined;
    var writer = postcard.Writer.init(&prefix);
    try testing.expectError(
        error.FrameTooLarge,
        codec.writeFramePrefix(&writer, codec.max_message_size),
    );
    try codec.writeFramePrefix(&writer, 258);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 1, 2 }, writer.finish());

    // 4096 zero bytes are `Swarm(Join(None))`, the cheapest frame there is, and
    // the reader takes the length `writeFramePrefix` will not write.
    var full: [codec.frame_prefix_length + codec.max_message_size]u8 = undefined;
    std.mem.writeInt(u32, full[0..codec.frame_prefix_length], codec.max_message_size, .big);
    @memset(full[codec.frame_prefix_length..], 0);
    const decoded = try codec.decodeFrame(&full);
    try testing.expectEqual(@as(?[]const u8, null), decoded.swarm.join);

    // One byte past the budget is refused on the read side too.
    std.mem.writeInt(u32, full[0..codec.frame_prefix_length], codec.max_message_size + 1, .big);
    try testing.expectError(error.FrameTooLarge, codec.decodeFrame(&full));
    // A prefix the buffer cannot back is short, not over budget.
    try testing.expectError(error.UnexpectedEnd, codec.decodeFrame(&.{ 0, 0, 0, 8, 1 }));
    // A byte behind the message is two messages sharing one length.
    std.mem.writeInt(u32, full[0..codec.frame_prefix_length], 3, .big);
    full[codec.frame_prefix_length + 2] = 0;
    try testing.expectError(error.TrailingBytes, codec.decodeFrame(&full));
}

test "a stream opens with the topic it carries, framed" {
    const topic: hyparview.TopicId = .{ .bytes = [_]u8{0x5a} ** hyparview.topic_id_length };
    var stream: [codec.frame_prefix_length + hyparview.topic_id_length + 16]u8 = undefined;
    const header = try codec.encodeStreamHeader(stream[0..], topic);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 32, 0x5a, 0x5a }, header[0..6]);

    // The frames that follow share the buffer, and reading the header must not
    // consume them.
    const rest = try codec.encodeFrame(stream[header.len..], .{ .gossip = .prune });
    const decoded_header = try codec.decodeStreamHeader(stream[0 .. header.len + rest.len]);
    try testing.expect(topic.eql(decoded_header.topic_id));
    const decoded_rest = try codec.decodeFrame(stream[header.len..][0..rest.len]);
    try testing.expect(decoded_rest.gossip == .prune);

    // A header frame whose payload is not exactly a topic id is not one.
    try testing.expectError(error.TrailingBytes, codec.decodeStreamHeader(&.{ 0, 0, 0, 33 }));
    try testing.expectError(error.UnexpectedEnd, codec.decodeStreamHeader(&.{ 0, 0, 0, 31 }));
}

test "the IHave chunk length is the arithmetic the capture shows" {
    // 13 at the budget the capture ran a swarm on, 116 at the default.
    try testing.expectEqual(@as(usize, 13), codec.ihaveChunkLen(512));
    try testing.expectEqual(@as(usize, 116), codec.ihaveChunkLen(codec.max_message_size));
    // A budget too small for the header and one entry still cuts one, never
    // zero: a zero-length chunk would not drain the queue.
    try testing.expectEqual(@as(usize, 1), codec.ihaveChunkLen(0));
    try testing.expectEqual(@as(usize, 1), codec.ihaveChunkLen(hyparview.topic_id_length + 1 + 3));

    // What one message may actually carry is the smaller of the two bounds.
    try testing.expectEqual(
        plumtree.max_ihaves_per_message,
        codec.ihaveBatchLimit(codec.max_message_size),
    );
    try testing.expectError(error.MessageSizeTooSmall, codec.validateMaxMessageSize(511));
    try codec.validateMaxMessageSize(codec.min_max_message_size);
}

test "a decode refuses what the rules say it must" {
    // An arm no build names, at either layer, and a scope that is neither.
    try expectMessageError(&.{ 2, 0 }, error.UnknownVariant);
    try expectMessageError(&.{ 0, 6 }, error.UnknownVariant);
    try expectMessageError(&.{ 1, 4 }, error.UnknownVariant);
    try expectMessageError(&.{ 0, 4, 2, 0 }, error.UnknownVariant);
    try expectMessageError(&([_]u8{ 1, 0 } ++ [_]u8{0} ** 33 ++ [_]u8{2}), error.UnknownVariant);

    // An `Option` tag and a `bool` byte that are neither.
    try expectMessageError(&.{ 0, 0, 2 }, error.BadOptionTag);
    try expectMessageError(&.{ 0, 5, 1, 2 }, error.BadBool);

    // Counts the inline lists cannot hold, whatever the frame could.
    try expectMessageError(&.{ 0, 3, 9 }, error.ShuffleNodeListTooLong);
    try expectMessageError(
        &.{ 1, 3, plumtree.max_ihaves_per_message + 1 },
        error.IHaveListTooLong,
    );

    // A node id that is 32 bytes and not a point.
    const not_a_point = [_]u8{ 0, 1 } ++ [_]u8{0xff} ** NodeId.byte_length ++ [_]u8{ 0, 0 };
    try expectMessageError(&not_a_point, error.NotANodeId);
}

test "the constants are the ones the format is built from" {
    try testing.expectEqual(@as(usize, 4096), codec.max_message_size);
    try testing.expectEqual(@as(usize, 512), codec.min_max_message_size);
    try testing.expectEqual(@as(usize, 4), codec.frame_prefix_length);
    try testing.expectEqual(@as(usize, 32), hyparview.topic_id_length);
    // The payload ceiling is the frame budget, and 35 is upstream's
    // `IHave::POSTCARD_MAX_SIZE` with 33 the header its chunk arithmetic
    // subtracts. `tree_codec` cannot import `codec`, so this is what holds the
    // two numbers together.
    try testing.expectEqual(codec.max_message_size, tree_codec.max_content);
    try testing.expectEqual(@as(usize, 35), plumtree.id_length + 3);
    try testing.expectEqual(@as(usize, 33), hyparview.topic_id_length + 1);
}
