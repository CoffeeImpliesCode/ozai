//! Deep-copying a queued event's payloads into the simulator's arena.
//!
//! A queued message must not point into the state that emitted it, so every
//! slice an `InEvent` or a `Message` carries is copied here before it goes on
//! the queue. This is the only place in `src/gossip/` where a borrowed slice
//! is outlived by copying rather than by a caller keeping its own copy.
const std = @import("std");
const bounds = @import("bounds.zig");
const peers = @import("peer_data.zig");
const wire = @import("message.zig");
const harness = @import("sim_harness.zig");
const topic = @import("topic.zig");

const Allocator = std.mem.Allocator;
const Message = topic.Message;
const max_shuffle_nodes = bounds.max_shuffle_nodes;
const PeerInfo = peers.PeerInfo;
const PeerInfos = peers.PeerInfos;
const SwarmMessage = wire.SwarmMessage;
const HarnessError = harness.HarnessError;

pub fn parkMessage(a: Allocator, message: Message) HarnessError!Message {
    return switch (message) {
        .swarm => |swarm| .{ .swarm = try parkSwarm(a, swarm) },
        .gossip => |gossip| switch (gossip) {
            .gossip => |inner| .{ .gossip = .{ .gossip = .{
                .id = inner.id,
                .content = try a.dupe(u8, inner.content),
                .scope = inner.scope,
            } } },
            else => .{ .gossip = gossip },
        },
    };
}

fn parkSwarm(a: Allocator, message: SwarmMessage) HarnessError!SwarmMessage {
    return switch (message) {
        .join => |data| .{ .join = try parkData(a, data) },
        .neighbor => |neighbor| .{ .neighbor = .{
            .priority = neighbor.priority,
            .data = try parkData(a, neighbor.data),
        } },
        .forward_join => |forward| .{ .forward_join = .{
            .peer = try parkInfo(a, forward.peer),
            .ttl = forward.ttl,
        } },
        .shuffle => |shuffle| .{ .shuffle = .{
            .origin = shuffle.origin,
            .nodes = try parkInfos(a, shuffle.nodes),
            .ttl = shuffle.ttl,
        } },
        .shuffle_reply => |reply| .{ .shuffle_reply = .{
            .nodes = try parkInfos(a, reply.nodes),
        } },
        .disconnect => |disconnect| .{ .disconnect = disconnect },
    };
}

fn parkData(a: Allocator, data: ?[]const u8) HarnessError!?[]const u8 {
    const held = data orelse return null;
    const parked = try a.dupe(u8, held);
    return parked;
}

fn parkInfo(a: Allocator, info: PeerInfo) HarnessError!PeerInfo {
    return .{ .id = info.id, .data = try parkData(a, info.data) };
}

fn parkInfos(a: Allocator, list: PeerInfos) HarnessError!PeerInfos {
    var parked: [max_shuffle_nodes]PeerInfo = undefined;
    const items = list.slice();
    for (items, 0..) |info, index| parked[index] = try parkInfo(a, info);
    return PeerInfos.init(parked[0..items.len]);
}
