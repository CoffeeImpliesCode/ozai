//! A `TopicId` is 32 bytes the application chose, and nothing derives it.

const std = @import("std");
const bounds = @import("bounds.zig");
const topic_id = @import("topic_id.zig");

const t = std.testing;

const topic_id_length = bounds.topic_id_length;
const TopicId = topic_id.TopicId;

// A `TopicId` is 32 bytes the application chose. There is no derivation and no
// scope, and a test that pinned a derived one would be pinning a scheme this
// module deliberately does not have.
test "a topic id is 32 opaque bytes and nothing more" {
    try t.expectEqual(@as(usize, 32), topic_id_length);
    try t.expectEqual(@as(usize, 32), @sizeOf(TopicId));
    const zero = [_]u8{0} ** topic_id_length;
    var one = [_]u8{0} ** topic_id_length;
    one[0] = 1;
    const left = TopicId.fromBytes(one);
    const right = TopicId.fromBytes(zero);
    try t.expect(left.eql(TopicId.fromBytes(one)));
    try t.expect(!left.eql(right));
    try t.expectEqual(std.math.Order.gt, left.order(right));
    try t.expectEqualStrings("0100000000", &left.shortHex());
}
