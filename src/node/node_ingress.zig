const std = @import("std");
const node_mod = @import("node.zig");
const node_error = @import("node_error.zig");
const node_stats = @import("node_stats.zig");
const quic_conn = @import("../transport/quic_conn.zig");
const socket_mod = @import("../transport/socket.zig");

/// Take everything the kernel has queued and hand it to the core.
pub fn take(
    io: std.Io,
    self: *node_mod.Node,
    at: quic_conn.Instant,
    random: std.Random,
) node_error.Error!bool {
    var moved = false;
    // The datagram `wait` took goes first: the kernel gave it over and
    // `tryReceive` will never see it again.
    if (self.held) |got| {
        self.held = null;
        try deliver(io, self, got, at, random);
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
        try deliver(io, self, got, at, random);
        moved = true;
    }
    return moved;
}

/// One read, which may be a burst coalesced by `UDP_GRO`, through the core.
pub fn deliver(
    io: std.Io,
    self: *node_mod.Node,
    got: socket_mod.Received,
    at: quic_conn.Instant,
    random: std.Random,
) node_error.Error!void {
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
        const ingress = try self.bridge.recv(&self.map, .{
            .bytes = datagram,
            .from = got.from,
            .local = self.socket.address,
            .ecn = recv.ecn,
        }, self.scratch, at, random);
        switch (ingress.outcome) {
            // A connection this datagram made or advanced is in the core's
            // table, and `admit` and `drive` both walk that table.
            .processed => {},
            // A stateless reply is a send, back out of the same socket to
            // the address the datagram came from.
            .reply => |reply| {
                // After the send, for the reason `node_egress.drain` gives:
                // the counter means the socket took the datagrams, and a send
                // that raises reports no sent-prefix to count from.
                node_stats.note(&self.stats, try self.socket.send(io, ingress.source.socket, reply));
                self.stats.datagrams_out += reply.datagramCount();
            },
            .dropped, .foreign => {},
        }
    }
}
