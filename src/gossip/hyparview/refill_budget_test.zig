const std = @import("std");
const swarm = @import("../hyparview.zig");
const testNodeId = @import("../plumtree/test_node_id.zig").testNodeId;
const budget_peer = @import("budget_test_peer.zig");
const t = std.testing;
const NodeId = @import("../../base/key.zig").NodeId;

fn refillContacts() !swarm.PeerInfos {
    return swarm.PeerInfos.init(&.{
        .{ .id = try testNodeId(3), .data = "three" },
        .{ .id = try testNodeId(4), .data = "four" },
        .{ .id = try testNodeId(5), .data = "five" },
    });
}

fn acceptContacts(
    state: *swarm.State,
    out: *swarm.Actions(swarm.SwarmOutEvent),
) !void {
    var input: [4100]u8 = undefined;
    const decoded = try budget_peer.receiveIncoming(.{ .swarm = .{ .shuffle_reply = .{
        .nodes = try refillContacts(),
    } } }, &input);
    try state.handle(.{ .recv_message = .{
        .from = try testNodeId(6),
        .message = decoded.swarm,
    } }, out);
}

fn expectContacts(state: *const swarm.State, excluded: ?NodeId) !void {
    const contacts = try refillContacts();
    var retained: usize = 0;
    for (contacts.slice()) |contact| {
        const removed = if (excluded) |id|
            std.mem.eql(u8, &contact.id.toBytes(), &id.toBytes())
        else
            false;
        try t.expectEqual(!removed, state.passive_view.contains(contact.id));
        // Timeout removes eligibility, not the contact record.
        try t.expectEqualSlices(u8, contact.data.?, state.peer_data.get(contact.id).?.slice());
        if (!removed) retained += 1;
    }
    try t.expectEqual(retained, state.passiveView().len);
}

fn expectNoRefill(out: *const swarm.Actions(swarm.SwarmOutEvent)) !void {
    for (out.slice()) |action| {
        switch (action) {
            .send_message => try t.expect(false),
            .schedule_timer => |timer| try t.expect(timer.timer == .do_shuffle),
            else => {},
        }
    }
}

fn pendingTimer(
    state: *const swarm.State,
    out: *const swarm.Actions(swarm.SwarmOutEvent),
) !swarm.SwarmTimer {
    try t.expectEqual(@as(usize, 1), state.pending_neighbor_requests.count());
    const pending = state.pending_neighbor_requests.slice()[0];
    try t.expect(state.passive_view.contains(pending));
    var timer: ?swarm.SwarmTimer = null;
    var neighbors: usize = 0;
    for (out.slice()) |action| {
        if (action == .schedule_timer and
            action.schedule_timer.timer == .pending_neighbor_request)
        {
            try t.expect(timer == null);
            timer = action.schedule_timer.timer;
            try t.expectEqual(pending, timer.?.pending_neighbor_request);
        }
        if (action == .send_message and action.send_message.message == .neighbor) {
            try t.expectEqual(pending, action.send_message.to);
            neighbors += 1;
        }
    }
    try t.expectEqual(@as(usize, 1), neighbors);
    try t.expect(timer != null);
    return timer.?;
}

test "ShuffleReply retains three contacts when own Neighbor4096 cannot fit" {
    const own: [4090]u8 = @splat(0x92);
    var state = try swarm.State.init(try testNodeId(1), try swarm.PeerData.fromBytes(&own), .{}, .init(42));
    var out: swarm.Actions(swarm.SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    var rng_before = state.rng;
    const result = acceptContacts(&state, &out);
    try expectContacts(&state, null);
    try t.expectEqual(@as(usize, 3), state.peer_data.count());
    try t.expectEqual(@as(usize, 0), state.activeView().len);
    try t.expectEqual(@as(usize, 0), state.pending_neighbor_requests.count());
    try expectNoRefill(&out);
    var rng_after = state.rng;
    for (0..4) |_| try t.expectEqual(rng_before.next(), rng_after.next());
    try result;
}

test "pending timeout removes failed target without unwritable replacement" {
    var state = try swarm.State.init(try testNodeId(1), null, .{}, .init(42));
    var out: swarm.Actions(swarm.SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    try acceptContacts(&state, &out);
    const timer = try pendingTimer(&state, &out);
    try expectContacts(&state, null);
    const own: [4090]u8 = @splat(0x93);
    try state.handle(.{ .update_peer_data = try swarm.PeerData.fromBytes(&own) }, &out);
    out.clear();
    var rng_before = state.rng;
    const result = state.handle(.{ .timer_expired = timer }, &out);
    try t.expectEqual(@as(usize, 0), state.pending_neighbor_requests.count());
    try t.expectEqual(@as(usize, 0), state.activeView().len);
    try expectContacts(&state, timer.pending_neighbor_request);
    try expectNoRefill(&out);
    try t.expectEqual(@as(usize, 0), out.count());
    var rng_after = state.rng;
    for (0..4) |_| try t.expectEqual(rng_before.next(), rng_after.next());
    try result;
}

test "departure preserves pending contacts and required down actions" {
    var state = try swarm.State.init(try testNodeId(1), null, .{}, .init(42));
    var out: swarm.Actions(swarm.SwarmOutEvent) = .init(t.allocator);
    defer out.deinit();
    try budget_peer.seedNeighbor(&state, try testNodeId(2), "two", &out);
    // Complete the real Neighbor exchange so peer2 is not an outstanding request.
    try state.handle(.{ .recv_message = .{
        .from = try testNodeId(2),
        .message = .{ .neighbor = .{ .priority = .high, .data = "two" } },
    } }, &out);
    out.clear();
    try t.expectEqual(@as(usize, 0), state.pending_neighbor_requests.count());
    try acceptContacts(&state, &out);
    const timer = try pendingTimer(&state, &out);
    try expectContacts(&state, null);
    const own: [4090]u8 = @splat(0x94);
    try state.handle(.{ .update_peer_data = try swarm.PeerData.fromBytes(&own) }, &out);
    out.clear();
    var rng_before = state.rng;
    const result = state.handle(.{ .peer_disconnected = try testNodeId(2) }, &out);
    try t.expect(!state.active_view.contains(try testNodeId(2)));
    try t.expectEqual(@as(usize, 0), state.activeView().len);
    try t.expectEqual(@as(usize, 1), state.pending_neighbor_requests.count());
    try t.expect(state.pending_neighbor_requests.contains(timer.pending_neighbor_request));
    try expectContacts(&state, null);
    try expectNoRefill(&out);
    var down: usize = 0;
    var disconnects: usize = 0;
    for (out.slice()) |action| {
        if (action == .emit_event) {
            try t.expect(action.emit_event == .neighbor_down);
            try t.expectEqual(try testNodeId(2), action.emit_event.neighbor_down);
            down += 1;
        }
        if (action == .disconnect_peer) {
            try t.expectEqual(try testNodeId(2), action.disconnect_peer);
            disconnects += 1;
        }
    }
    try t.expectEqual(@as(usize, 1), down);
    try t.expectEqual(@as(usize, 1), disconnects);
    try t.expectEqual(@as(usize, 2), out.count());
    var rng_after = state.rng;
    for (0..4) |_| try t.expectEqual(rng_before.next(), rng_after.next());
    try result;
}
