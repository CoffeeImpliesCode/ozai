//! Live state for a supervisor that must observe a transition before stopping a node.
//! Captured between passes; no clock, allocation, or I/O outside the supplied writer.

const std = @import("std");
const Node = @import("ozai").node.Node;

pub const Snapshot = struct {
    dials: u64,
    refused: u64,
    accepted: u64,
    finished: u64,
    up: usize,
    admitted: u64,
    established: u64,
    registered: usize,
    sent: u64,
    received: u64,
    forwarded: u64,
    attempts: u64,
    spawned: u64,
    disconnected: u64,
    closed: u64,

    pub fn capture(node: *const Node) Snapshot {
        const stats = &node.stats;
        return .{
            .dials = stats.dials,
            .refused = stats.dials_refused,
            .accepted = stats.handler_connections,
            .finished = stats.connections_finished,
            .up = node.establishedCount(),
            .admitted = stats.relay_admitted,
            .established = stats.relay_established,
            .registered = if (node.config.relay.role == .serve) node.clientCount() else 0,
            .sent = stats.relay_sent,
            .received = stats.relay_datagrams_out,
            .forwarded = stats.relay_forwarded,
            .attempts = stats.attempts,
            .spawned = stats.spawned,
            .disconnected = stats.relay_disconnects,
            .closed = stats.relay_closed,
        };
    }

    pub fn format(self: *const Snapshot, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print(
            "progress: dials {d}, refused {d}, accepted {d}, finished {d}, up {d}, " ++
                "admitted {d}, established {d}, registered {d}, sent {d}, received {d}, " ++
                "forwarded {d}, attempts {d}, spawned {d}, disconnected {d}, closed {d}\n",
            .{
                self.dials,
                self.refused,
                self.accepted,
                self.finished,
                self.up,
                self.admitted,
                self.established,
                self.registered,
                self.sent,
                self.received,
                self.forwarded,
                self.attempts,
                self.spawned,
                self.disconnected,
                self.closed,
            },
        );
    }
};
