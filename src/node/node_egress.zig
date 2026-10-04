const std = @import("std");
const node_mod = @import("node.zig");
const Error = @import("node_error.zig").Error;
const node_stats = @import("node_stats.zig");
const node_dispatch = @import("node_dispatch.zig");
const node_gossip = @import("node_gossip.zig");
const Instant = @import("../transport/quic_conn.zig").Instant;

/// Write the bounded output the core builds into the node's reusable buffers.
pub fn drain(io: std.Io, self: *node_mod.Node, at: Instant, random: std.Random) Error!bool {
    var moved = false;
    var index: usize = 0;
    while (self.bridge.connectionAt(index)) |conn| : (index += 1) {
        for (try conn.drain(self.egress, self.out, at, random)) |egress| {
            // Counted after the send and not before it, because the counter
            // says the datagrams went on the wire and a `try` that raises
            // never says they did. `send` returns no sent-prefix, so a batch
            // that raises is not counted at all rather than counted in full:
            // under the number rather than over it.
            node_stats.note(&self.stats, try self.socket.send(io, egress.to, egress.send));
            self.stats.datagrams_out += egress.send.datagramCount();
            moved = true;
        }
    }
    return moved;
}

/// Report finished connections to their accept tasks and the gossip layer.
pub fn expire(io: std.Io, self: *node_mod.Node, at: Instant, random: std.Random) Error!bool {
    var moved = false;
    var index: usize = 0;
    while (self.bridge.connectionAt(index)) |conn| {
        if (self.bridge.tick(conn, at, random) == .live) {
            index += 1;
            continue;
        }
        // Tick swap-removes the entry, so the former last entry is now at index.
        // Its storage remains valid until the outer driver's next sweep.
        self.stats.connections_finished += 1;
        // Reaped in pairs: one connection, one entry in each of the two tables
        // that track it, and a half-reaped connection is the leak the pairing
        // exists to stop. The peer comes out with the entry, because it is the
        // only thing that knew both.
        _ = self.offered.remove(conn.id());
        const gone = self.connections.forget(conn.id());
        moved = true;
        if (self.accept.task(conn.id()) != null) {
            try node_dispatch.feed(self, io, .{
                .reaped = .{ .id = conn.id(), .ended = .finished },
            }, at, random);
        }
        // **By the core's own id, not by address.** A direct path's socket is
        // in no map — it is the peer's real address — so an address-keyed
        // lookup answers null for every dialled gossip peer, and the peer the
        // connection was entered under, which is the one that is always there.
        // A connection with no entry is one this node refused itself or one
        // that arrived as an accept, and upstream reports a peer's departure
        // only to the peers that did not ask for it.
        const peer = gone orelse continue;
        self.stats.gossip_routes_dropped += self.topics.routeForgetPeer(peer);
        try node_gossip.peerGone(self, peer, at);
    }
    return moved;
}
