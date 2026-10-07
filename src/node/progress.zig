//! Live transport and application counters; not peer-delivery evidence.
const std = @import("std");
const Node = @import("ozai").node.Node;

pub const Snapshot = struct {
    dials: u64,
    refused: u64,
    attempts: u64,
    spawned: u64,
    accepted: u64,
    finished: u64,
    up: usize,
    neighbor_up: u64,
    received: u64,
    blobs_completed: u64,
    blob_sent_bytes: u64,
    blob_received_bytes: u64,

    pub fn capture(node: *const Node) Snapshot {
        const stats = &node.stats;
        return .{
            .dials = stats.dials,
            .refused = stats.dials_refused,
            .attempts = stats.attempts,
            .spawned = stats.spawned,
            .accepted = stats.handler_connections,
            .finished = stats.connections_finished,
            .up = node.establishedCount(),
            .neighbor_up = stats.neighbor_up,
            .received = stats.broadcasts_received,
            .blobs_completed = node.blobs.completed,
            .blob_sent_bytes = node.blobs.sent_bytes,
            .blob_received_bytes = node.blobs.received_bytes,
        };
    }

    pub fn format(self: *const Snapshot, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print(
            "progress: dials {d}, refused {d}, accepted {d}, finished {d}, up {d}, " ++
                "attempts {d}, spawned {d}, neighbour up {d}, broadcasts received {d}, " ++
                "blob transfers completed {d}, blob sent bytes {d}, blob received bytes {d}\n",
            .{ self.dials, self.refused, self.accepted, self.finished, self.up,
                self.attempts, self.spawned, self.neighbor_up, self.received,
                self.blobs_completed, self.blob_sent_bytes, self.blob_received_bytes },
        );
    }
};
