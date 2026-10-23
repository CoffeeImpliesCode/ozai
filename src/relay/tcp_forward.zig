const std = @import("std");
const NodeId = @import("../base/key.zig").NodeId;
const frame = @import("frame.zig");
const session = @import("tcp_session.zig");
const processor = @import("tcp_processor.zig");

pub const Peer = struct {
    connection: session.Session,
    state: processor.ServerState = .upgrade,
    challenge: frame.ServerChallenge = .{ .challenge = .{0} ** 16 },
    identity: ?NodeId = null,
    pending: ?frame.DatagramFrame = null,
};

pub fn register(peers: []?Peer, index: usize, peer: *Peer, identity: NodeId) void {
    for (peers, 0..) |*other, other_index| {
        if (other_index == index) continue;
        if (other.*) |*active| {
            if (active.identity) |previous| {
                if (std.meta.eql(previous, identity)) {
                    active.connection.close();
                    other.* = null;
                }
            }
        }
    }
    // The servicing borrow survives replacement because the loop skips its own slot.
    peer.identity = identity;
}

pub fn forward(peers: []?Peer, source: NodeId, datagram: frame.DatagramFrame) session.Error!bool {
    for (peers) |*destination| {
        if (destination.*) |*active| {
            if (active.state != .ready) continue;
            // Only authenticated peers advance through confirming to ready.
            const identity = active.identity orelse
                @panic("ready destination requires an authenticated identity");
            if (!std.meta.eql(identity, datagram.node_id)) continue;
            if (active.connection.busy()) return false;
            const forwarded: frame.DatagramFrame = .{
                .node_id = source,
                .datagrams = datagram.datagrams,
            };
            try active.connection.relay(if (datagram.datagrams.isBatch())
                .{ .relay_to_client_datagram_batch = forwarded }
            else
                .{ .relay_to_client_datagram = forwarded });
            return true;
        }
    }
    // No registered destination is available; report the actual missing route.
    for (peers) |*candidate| {
        if (candidate.*) |*active| {
            if (active.state != .ready) continue;
            // Only authenticated peers advance through confirming to ready.
            const identity = active.identity orelse
                @panic("ready source requires an authenticated identity");
            if (!std.meta.eql(identity, source)) continue;
            if (active.connection.busy()) return false;
            try active.connection.relay(.{ .endpoint_gone = datagram.node_id });
            return true;
        }
    }
    return true;
}
