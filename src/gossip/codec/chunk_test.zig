//! The byte-budget cut of an `IHave` list, and what a cut list puts on the wire.
//!
//! The oracle is the reassembly: chunks that come back off the wire, in order,
//! have to be the list that went in, entry for entry. A cut that dropped an
//! entry, reordered two or doubled one would not reassemble, and neither would a
//! chunk whose frame was not the size the cut measured.

const std = @import("std");

const codec = @import("../codec.zig");
const limits = @import("limits.zig");
const plumtree = @import("../plumtree.zig");

const IHave = plumtree.IHave;
const t = std.testing;

const room = limits.max_message_size + limits.max_prefix_size;

/// Entries whose ids and rounds are all distinct, so a reassembly that loses one
/// or swaps two is visible rather than invisible.
fn fill(list: []IHave) void {
    for (list, 0..) |*have, index| {
        var bytes: [plumtree.id_length]u8 = @splat(0x00);
        bytes[0] = @intCast(index);
        have.* = .{
            .id = plumtree.MessageId.fromBytes(bytes),
            .round = .{ .value = @intCast(index) },
        };
    }
}

/// The budget that holds exactly `count` of `list`'s entries: the body of the
/// `Message::IHave` that carries them, which is the number `chunkLen` measures.
fn budgetFor(list: []const IHave, count: usize) !usize {
    const cut = try plumtree.IHaves.init(list[0..count]);
    return codec.encodedLen(.{ .gossip = .{ .i_have = cut } });
}

test "a budget over the payload splits it into more than one chunk" {
    var list: [plumtree.max_ihaves_per_message]IHave = undefined;
    fill(&list);
    const budget = try budgetFor(&list, 5);
    // Five entries fit and the sixth does not, which is the whole claim: the cut
    // is measured in bytes, and it is measured exactly.
    try t.expectEqual(@as(usize, 5), try codec.chunkLen(&list, budget));
    try t.expectEqual(@as(usize, 4), try codec.chunkLen(&list, budget - 1));

    var frame_buf: [room]u8 = undefined;
    var offset: usize = 0;
    var frames: usize = 0;
    while (offset < list.len) {
        const take = try codec.chunkLen(list[offset..], budget);
        const cut = try plumtree.IHaves.init(list[offset..][0..take]);
        const frame = try codec.encode(.{ .gossip = .{ .i_have = cut } }, &frame_buf);
        // The cut was made against a body, and what goes on the wire is that
        // body and the prefix in front of it.
        try t.expect(frame.len <= budget + limits.max_prefix_size);
        const decoded = (try codec.decode(frame)).gossip.i_have;
        try t.expectEqual(@as(u16, @intCast(take)), decoded.count);
        for (decoded.slice(), 0..) |have, index| {
            try t.expect(list[offset + index].id.eql(have.id));
            try t.expectEqual(list[offset + index].round.value, have.round.value);
        }
        offset += take;
        frames += 1;
    }
    try t.expectEqual(@divFloor(list.len + 4, 5), frames);
}

test "a payload exactly at the budget is one chunk" {
    var list: [plumtree.max_ihaves_per_message]IHave = undefined;
    fill(&list);
    const whole = try plumtree.IHaves.init(&list);
    const budget = codec.encodedLen(.{ .gossip = .{ .i_have = whole } });
    try t.expectEqual(@as(usize, list.len), try codec.chunkLen(&list, budget));
    // One byte under, and the last entry is the one that does not fit: the same
    // boundary `limits.max_message_size` has, on the same side.
    try t.expectEqual(@as(usize, list.len - 1), try codec.chunkLen(&list, budget - 1));
    // The default budget carries the whole list in one frame, so a lazy-push
    // queue this size is never cut on a link that allows it.
    try t.expectEqual(@as(usize, list.len), try codec.chunkLen(&list, codec.max_message_size));
}

test "a budget too small for one entry is refused" {
    var list: [plumtree.max_ihaves_per_message]IHave = undefined;
    fill(&list);
    // Nothing to cut is nothing to send, and it is not a refusal.
    try t.expectEqual(@as(usize, 0), try codec.chunkLen(&.{}, codec.max_message_size));
    // A caller advancing by a zero does not advance, so a budget that cannot
    // hold one entry is named rather than answered with one.
    try t.expectEqual(@as(usize, 38), codec.min_chunk_size);
    try t.expectError(error.ChunkBudgetTooSmall, codec.chunkLen(&list, 0));
    try t.expectError(error.ChunkBudgetTooSmall, codec.chunkLen(&list, 37));
    try t.expectEqual(@as(usize, 1), try codec.chunkLen(&list, 38));
}

test "a chunk never holds more entries than one IHaves value can" {
    // Even an unbounded caller list is split at the frame-fitting capacity.
    var list: [plumtree.max_ihaves_per_message + 4]IHave = undefined;
    fill(&list);
    const take = try codec.chunkLen(&list, codec.max_message_size);
    try t.expectEqual(@as(usize, plumtree.max_ihaves_per_message), take);
    try t.expectEqual(@as(usize, 4), try codec.chunkLen(list[take..], codec.max_message_size));
}

test "every chunk the cutter produces is a frame the codec writes and reads" {
    // The same `encodedLen` decided the cut and the frame, so a cut under any
    // budget this codec accepts encodes inside that budget. One byte a frame is
    // the tightest case, and the loop walks it.
    var list: [plumtree.max_ihaves_per_message]IHave = undefined;
    fill(&list);
    var frame_buf: [room]u8 = undefined;
    var offset: usize = 0;
    var budget = codec.min_chunk_size;
    while (offset < list.len) : (budget += 1) {
        const take = try codec.chunkLen(list[offset..], budget);
        const cut = try plumtree.IHaves.init(list[offset..][0..take]);
        const message: codec.Message = .{ .gossip = .{ .i_have = cut } };
        try t.expect(codec.encodedLen(message) <= budget);
        const decoded = (try codec.decode(try codec.encode(message, &frame_buf))).gossip;
        try t.expectEqual(@as(u16, @intCast(take)), decoded.i_have.count);
        offset += take;
    }
    try t.expectEqual(@as(usize, list.len), offset);
}

test "a chunk at the upstream send ceiling is split even with a larger budget" {
    var list: [plumtree.max_ihaves_per_message]IHave = undefined;
    fill(&list);
    // 124 minimal entries occupy 4095 bytes; one two-byte round reaches 4096.
    list[0].round.value = 128;
    try t.expectEqual(codec.max_message_size, try budgetFor(&list, list.len));
    const take = try codec.chunkLen(&list, codec.max_message_size + 100);
    try t.expectEqual(@as(usize, list.len - 1), take);
    var frame: [room]u8 = undefined;
    const cut = try plumtree.IHaves.init(list[0..take]);
    const bytes = try codec.encode(.{ .gossip = .{ .i_have = cut } }, &frame);
    try t.expectEqual(@as(u16, @intCast(take)), (try codec.decode(bytes)).gossip.i_have.count);
}
