// Receive-inclusive framing and causal Neighbor contact setup for membership budgets.
const std = @import("std");
const swarm = @import("../hyparview.zig");
const codec = @import("../codec.zig");
const NodeId = @import("../../base/key.zig").NodeId;
const t = std.testing;

pub fn receiveIncoming(message: codec.Message, buffer: []u8) !codec.Message {
    // Receive permits the inclusive boundary that the strict sender cannot write.
    const length = codec.encodedLen(message);
    try t.expect(length <= codec.max_message_size);
    std.mem.writeInt(u32, buffer[0..4], @intCast(length), .big);
    var writer = @import("../../wire/postcard.zig").Writer.init(buffer[4..]);
    try codec.encodeBody(message, &writer);
    try t.expectEqual(length, writer.finish().len);
    return codec.decode(buffer[0 .. 4 + length]);
}

pub fn seedNeighbor(
    state: *swarm.State,
    id: NodeId,
    data: ?[]const u8,
    out: *swarm.Actions(swarm.SwarmOutEvent),
) !void {
    try state.handle(.{ .recv_message = .{
        .from = id, .message = .{ .neighbor = .{ .priority = .high, .data = data } },
    } }, out);
    try t.expect(state.active_view.contains(id));
    out.clear();
}
