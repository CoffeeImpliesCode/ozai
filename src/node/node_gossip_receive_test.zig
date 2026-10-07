const std = @import("std");
const receive = @import("node_gossip_receive.zig");
const codec = @import("../gossip/codec.zig");
const TopicId = @import("../gossip/hyparview.zig").TopicId;
const t = std.testing;

// Source-derived transport shapes, not captured upstream schema vectors.
const header = [_]u8{ 0, 0, 0, 32 } ++ [_]u8{7} ** 32;
const prune = [_]u8{ 0, 0, 0, 2, 1, 1 };

test "gossip receive assembles fragmented fixed4 header and consecutive frames" {
    var parser: receive.Assembly = .{};
    for (header) |byte| {
        const progress = try parser.push(&.{byte});
        try t.expectEqual(@as(usize, 1), progress.consumed);
    }
    const topic = try parser.takeHeader();
    try t.expect(topic.eql(TopicId.fromBytes([_]u8{7} ** 32)));
    const pair = prune ++ prune;
    const first = try parser.push(&pair);
    try t.expectEqual(prune.len, first.consumed);
    try t.expectEqualSlices(u8, &prune, parser.frame());
    parser.release();
    const second = try parser.push(pair[first.consumed..]);
    try t.expectEqual(prune.len, second.consumed);
    parser.release();
    try parser.finish();
}

test "gossip receive rejects oversize before body and truncated frame at FIN" {
    var parser: receive.Assembly = .{};
    try t.expectError(error.FrameTooLarge, parser.push(&.{ 0, 0, 16, 1 }));
    parser = .{};
    _ = try parser.push(header[0..3]);
    try t.expectError(error.Truncated, parser.finish());
    parser = .{};
    _ = try parser.push(&header);
    _ = try parser.takeHeader();
    _ = try parser.push(prune[0..5]);
    try t.expectError(error.Truncated, parser.finish());
}

test "gossip receive admits the upstream reader's exact max and rejects larger bodies" {
    var parser: receive.Assembly = .{};
    var max_frame: [codec.max_message_size + 4]u8 = undefined;
    std.mem.writeInt(u32, max_frame[0..4], @intCast(codec.max_message_size), .big);
    @memset(max_frame[4..], 0);
    const progress = try parser.push(&max_frame);
    try t.expectEqual(max_frame.len, progress.consumed);
    try t.expectEqual(max_frame.len, parser.frame().len);
}

test "gossip receive topic mismatch and transport echo are not accepted as gossip" {
    var parser: receive.Assembly = .{};
    _ = try parser.push(&header);
    const topic = try parser.takeHeader();
    try t.expect(!topic.eql(TopicId.fromBytes([_]u8{8} ** 32)));
    parser = .{};
    _ = try parser.push(&.{ 0, 0, 0, 17 });
    _ = try parser.push("transport-echo-17");
    try t.expectError(error.BadHeader, parser.takeHeader());
}
