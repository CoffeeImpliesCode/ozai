//! Exact application payload evidence and final transport counters.
const std = @import("std");
const ozai = @import("ozai");
const Node = ozai.node.Node;

pub const Holding = struct { connections: usize };
pub const Close = struct { connections: usize, datagrams: u64 };

pub const GossipEvidence = struct {
    writer: *std.Io.Writer,
    failure: ?std.Io.Writer.Error = null,

    pub fn receive(
        context: ?*anyopaque,
        topic: ozai.gossip_hyparview.TopicId,
        peer: ozai.NodeId,
        payload: []const u8,
    ) void {
        const self: *GossipEvidence = @ptrCast(@alignCast(context.?));
        if (self.failure != null) return;
        self.write(topic, peer, payload) catch |err| { self.failure = err; };
    }

    fn write(
        self: *GossipEvidence,
        topic: ozai.gossip_hyparview.TopicId,
        peer: ozai.NodeId,
        payload: []const u8,
    ) std.Io.Writer.Error!void {
        try self.writer.print("gossip received topic {x} peer {f} bytes {d} payload {x}\n",
            .{ topic.bytes, peer, payload.len, payload });
        try self.writer.flush();
    }
};

pub fn report(
    text: *std.Io.Writer,
    node: *const Node,
    holding: Holding,
    close: Close,
) std.Io.Writer.Error!void {
    const stats = node.stats;
    try text.print(
        "stopped: {d} passes, {d} datagrams in, {d} out\n" ++
            "accept loop: {d} attempts, {d} spawned, {d} handler connections\n" ++
            "dials: {d} of {d} refused; {d} connections finished\n" ++
            "gossip: neighbour up {d}, down {d}; broadcasts received {d}\n" ++
            "held: connections up {d}, at the stop\n" ++
            "close: {d} connections owed, {d} close datagrams written, 0 acknowledged by any peer\n",
        .{ stats.steps, stats.datagrams_in, stats.datagrams_out,
            stats.attempts, stats.spawned, stats.handler_connections,
            stats.dials, stats.dials_refused, stats.connections_finished,
            stats.neighbor_up, stats.neighbor_down, stats.broadcasts_received,
            holding.connections, close.connections, close.datagrams },
    );
    try text.print(
        "shutdown: {t}, {d} handler shutdowns, {d} accepts cancelled, socket {s}\n",
        .{ node.accept.shutdown.phase, stats.handler_shutdowns, stats.accepts_cancelled,
            if (node.socket_open) "still open" else "closed" },
    );
}

test "gossip evidence preserves complete binary payload" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var evidence: GossipEvidence = .{ .writer = &out.writer };
    var secret = try ozai.SecretKey.fromSeed(@splat(7));
    defer secret.deinit();
    GossipEvidence.receive(&evidence, .{ .bytes = @splat(1) }, secret.nodeId(), "\x00a\xff\n");
    try std.testing.expect(evidence.failure == null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "bytes 4 payload 0061ff0a\n") != null);
}

