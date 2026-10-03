//! Live state for a supervisor that must observe a transition before stopping a node.
//! Captured between passes; no clock, allocation, or I/O outside the supplied writer.

const std = @import("std");
const Node = @import("ozai").node.Node;

/// **One reading, taken between passes.** A value rather than a live view, so a
/// supervisor can keep two of them, compare them with `std.meta.eql` and print
/// only the pass that changed something. Nothing here retains the node: every
/// field is a number copied at `capture` time, and a snapshot is stale the
/// moment the next pass runs.
///
/// The fields are three groups, and they are not the same kind of fact:
///
/// - *Dialing* — `dials`, `refused`.
/// - *Accepting* — `attempts`, `spawned`, `accepted`, `finished`, `up`.
///   `up` is the only live count on the node, and it is asked of the core
///   rather than counted here, so it can fall while every other field only
///   rises.
/// - *Relaying* — `admitted`, `established`, `registered`, `sent`, `received`,
///   `forwarded`, `closed`. `registered` is zero for a node that is not a
///   serving relay, because such a node builds no registry to count.
pub const Snapshot = struct {
    /// Peers `Node.start` dialled, and peers it recorded a refused attempt for.
    dials: u64,
    refused: u64,
    /// Attempts the accept loop was offered, tasks it spawned, handler
    /// connections that ran, and connections the core has finished with.
    attempts: u64,
    spawned: u64,
    accepted: u64,
    finished: u64,
    /// Connections the core holds right now, asked of it rather than counted
    /// here. The one field that can go down inside a run.
    up: usize,
    /// Clients the relay admitted, handshakes a client finished, node ids the
    /// registry holds, datagrams sent and received through the relay, and
    /// datagrams a relay forwarded between two of its clients.
    admitted: u64,
    established: u64,
    registered: usize,
    sent: u64,
    received: u64,
    forwarded: u64,
    /// Disconnections the relay reported, and closes a client ended.
    disconnected: u64,
    closed: u64,

    /// Read every field off `node` in one pass. Takes `*const Node` and changes
    /// nothing, so a closed node may still be read; what it may not be is a
    /// node past `deinit`, and what a snapshot may not be is a live count,
    /// because the next pass moves every field of it.
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

    /// One line naming every field, for a supervisor writing plain text. Writes
    /// into the caller's `writer` and owns nothing, so two snapshots may be
    /// formatted as they are compared.
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
