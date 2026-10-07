//! The transport underneath the loop: what the socket has queued, what the core
//! wants sent, and the core's timers.
//!
//! A pass reads and writes through here and nowhere else. `take` moves datagrams
//! in, `drain` moves them out, and `expire` runs the core's timers and reports
//! every connection they finished. The bounds live here rather than in a table
//! of constants because each of them sizes something this module hands the
//! core, and a bound that is not next to the allocation it sizes is a number
//! nobody can check.

const std = @import("std");

const node_mod = @import("node.zig");
const node_config = @import("node_config.zig");
const node_accept = @import("node_accept.zig");
const node_gossip = @import("node_gossip.zig");
const node_holepunch = @import("node_holepunch.zig");

const batch = @import("../transport/batch.zig");
const bridge_mod = @import("../transport/quic_bridge.zig");
const dial_mod = @import("../transport/dial.zig");
const socket_mod = @import("../transport/socket.zig");
const base_key = @import("../base/key.zig");

const Node = node_mod.Node;
const Error = node_config.Error;
const Conn = bridge_mod.Conn;
const Instant = bridge_mod.Instant;
const NodeId = base_key.NodeId;

/// The largest datagram a path is expected to carry, the same bound
/// `quic_bridge.zig` and the vendored lossy-link test use.
pub const max_datagram = 1500;

/// How many socket writes one drain may hand back before the room is too
/// small.
pub const max_egress = 8;

/// Room for every datagram one drain may produce.
pub const send_room: usize = max_egress * max_datagram;

/// The core's own buffer: a datagram is copied into its front and a stateless
/// reply is written behind it.
pub const scratch_room: usize = 2 * max_datagram;

/// Room for the largest list the kernel may coalesce into one read. A receive
/// buffer too small for it truncates a coalesced read, which arrives at this
/// seam as `error.MessageTooLarge` rather than as a short datagram.
pub const receive_room: usize = @as(usize, max_datagram) * batch.max_gro_segments_linux;

/// Take everything the kernel has queued and hand it to the core.
pub fn take(self: *Node, io: std.Io, at: Instant, random: std.Random) Error!bool {
    var moved = false;
    // The datagram `wait` took goes first: the kernel gave it over and
    // `tryReceive` will never see it again.
    if (self.held) |got| {
        self.held = null;
        try deliver(self, io, got, at, random);
        moved = true;
    }
    while (true) {
        const got = self.socket.tryReceive(
            io,
            self.buf,
            &self.control,
        ) catch |err| switch (err) {
            // Non-blocking from the moment the socket existed, so an empty
            // queue is a fact the loop acts on rather than a stall.
            error.WouldBlock => break,
            else => return err,
        };
        try deliver(self, io, got, at, random);
        moved = true;
    }
    return moved;
}

/// One read, which may be a burst coalesced by `UDP_GRO`, through the core.
pub fn deliver(
    self: *Node,
    io: std.Io,
    got: socket_mod.Received,
    at: Instant,
    random: std.Random,
) Error!void {
    // A read is not one datagram: `UDP_GRO` may have coalesced a burst into
    // one buffer, so the stride is what says how many packets there are and
    // the core is handed them one at a time. `Bridge.recv` takes a single
    // datagram because the core's reply borrows the buffer it was written
    // into.
    const recv = try got.toRecv();
    self.stats.datagrams_in += recv.datagramCount();
    // The walk ends where `datagram` answers null, which is the same place
    // `datagramCount` would have ended it: the accessor goes null at
    // `divCeil(len, stride)` and that is what the count is. One fact about
    // the buffer, asked once, and no assertion that the accessor and the
    // count still agree.
    var position: usize = 0;
    while (recv.datagram(position)) |datagram| : (position += 1) {
        node_holepunch.prepare(&self.holepunch, self.bridge);
        const ingress = try self.bridge.recv(&self.map, .{
            .bytes = datagram,
            .from = got.from,
            .local = self.socket.address,
            .ecn = recv.ecn,
        }, self.scratch, at, random);
        node_holepunch.received(&self.holepunch, self.bridge, got.from, datagram);
        switch (ingress.outcome) {
            // A connection this datagram made or advanced is in the core's
            // table, and `admit` and `drive` both walk that table.
            .processed => {},
            // A stateless reply is a send, back out of the same socket to
            // the address the datagram came from.
            .reply => |reply| {
                self.stats.datagrams_out += reply.datagramCount();
                note(self, try self.socket.send(io, ingress.source.socket, reply));
            },
            .dropped, .foreign => {},
        }
    }
}

/// Write out everything the core wants sent, then run its timers.
pub fn drain(self: *Node, io: std.Io, at: Instant, random: std.Random) Error!bool {
    var moved = false;
    var index: usize = 0;
    while (self.bridge.connectionAt(index)) |conn| : (index += 1) {
        for (try conn.drain(self.egress, self.out, at, random)) |egress| {
            self.stats.datagrams_out += egress.send.datagramCount();
            note(self, try self.socket.send(io, egress.to, egress.send));
            moved = true;
        }
    }
    return moved;
}

/// Run the core's timers, and report every connection they finished.
///
/// A connection that ended is two things: a `join_next` upstream's loop
/// reads for a task it holds, and a `peer_disconnected` for the gossip
/// layer, which is how membership hears about it at all.
pub fn expire(self: *Node, io: std.Io, at: Instant, random: std.Random) Error!bool {
    var moved = false;
    var index: usize = 0;
    while (self.bridge.connectionAt(index)) |conn| {
        if (self.bridge.tick(conn, at, random) == .live) {
            index += 1;
            continue;
        }
        // `tickEntry` swap-removed the entry it was given
        // (`connection_manager.zig:711-713`), so whatever was last is now
        // at `index` and the walk must not step past it.
        self.stats.connections_finished += 1;
        moved = true;
        if (self.accept.task(conn.id()) != null) {
            try node_accept.feed(self, io, .{
                .reaped = .{ .id = conn.id(), .ended = .finished },
            }, at, random);
        }
        // Which peer this was. A synthetic address names the node it stands
        // for and the map remembers which, while a direct path names nobody
        // (`dial_mod.ownerOf`'s own doc), so a relayed peer reaches the
        // gossip layer as `peer_disconnected` and a direct one does not.
        // That is a limit on what this module knows and not a claim about
        // what membership needs.
        const peer = conn.peer() orelse continue;
        const key = dial_mod.ownerOf(&self.map, peer) orelse continue;
        const owner: NodeId = switch (key) {
            .any_path => |node| node,
            .relay => |via| via.node,
            // A custom key is a node id and its own bytes, and the map
            // allocates it from the node it belongs to
            // (`addr_map.CustomKey`'s own doc) — but the id is not stored,
            // so the owner is not recoverable from it.
            .custom => continue,
        };
        try node_gossip.peerGone(self, owner, at);
    }
    node_holepunch.prepare(&self.holepunch, self.bridge);
    return moved;
}

/// The connection the core holds for `id`, or null when it has finished
/// with it. Found by the same index walk an accepted connection is found
/// by, which is what makes the accept path and the dial path the same
/// machinery rather than two of them.
pub fn connFor(self: *Node, id: u64) ?Conn {
    var index: usize = 0;
    while (self.bridge.connectionAt(index)) |conn| : (index += 1) {
        if (conn.id() == id) return conn;
    }
    return null;
}

/// Record what a send cost. A `Report` is the socket's own account of the
/// codepoint and of whether a batch went out as one `sendmsg`, and reading
/// it is what keeps a degradation from being silent.
pub fn note(self: *Node, report: batch.Report) void {
    if (report.degraded) self.stats.sends_degraded += 1;
    if (!report.ecnSurvived()) self.stats.ecn_lost += 1;
}

/// Close the descriptor, once.
///
/// `close_endpoint` and `deinit` both owe it and only the first of them
/// reaches it in an orderly shutdown. A second `close` on a descriptor the
/// kernel has already released closes whatever took its number in between,
/// so the flag is the whole of the guarantee.
pub fn shutdownSocket(self: *Node) void {
    if (!self.socket_open) return;
    self.socket_open = false;
    self.socket.close();
}
