const std = @import("std");
const node_mod = @import("node.zig");
const node_stats = @import("node_stats.zig");
const Error = @import("node_error.zig").Error;
const quic_conn = @import("../transport/quic_conn.zig");
const Conn = quic_conn.Conn;
const Instant = quic_conn.Instant;

pub fn closeConnections(io: std.Io, self: *node_mod.Node, at: Instant, random: std.Random) Error!void {
    var index: usize = 0;
    while (self.bridge.connectionAt(index)) |conn| : (index += 1) {
        conn.close(0, "", at);
        const drained = try conn.drain(self.egress, self.out, at, random);
        for (drained) |egress| {
            // Counted after the send: a CONNECTION_CLOSE that raised did not
            // go out, and `main.shut` measures this pass by how far
            // `datagrams_out` moved across it.
            node_stats.note(&self.stats, try self.socket.send(io, egress.to, egress.send));
            self.stats.datagrams_out += egress.send.datagramCount();
        }
    }
}

pub fn closeOne(io: std.Io, self: *node_mod.Node, conn: Conn, at: Instant) Error!void {
    conn.close(0, "", at);
    for (try conn.drain(self.egress, self.out, at, node_mod.generator(self))) |egress| {
        // After the send, as in `closeConnections`: the counter means the
        // socket took it, and a raise here reaches the lane's cancel only
        // after the state changes around it are already performed.
        node_stats.note(&self.stats, try self.socket.send(io, egress.to, egress.send));
        self.stats.datagrams_out += egress.send.datagramCount();
    }
}
