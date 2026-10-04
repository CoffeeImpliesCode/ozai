//! Live state for a supervisor that must observe a transition before stopping a node.
//! Captured between passes; no clock, allocation, or I/O outside the supplied writer.

const std = @import("std");
const ozai = @import("ozai");
const Node = ozai.node.Node;

/// **One reading, taken between passes.** A value rather than a live view, so a
/// supervisor can keep two of them, compare them with `std.meta.eql` and print
/// only the pass that changed something. Nothing here retains the node: every
/// field is a number copied at `capture` time, and a snapshot is stale the
/// moment the next pass runs.
///
/// The fields are three groups, and they are not the same kind of fact:
///
/// - *Dialing* — `dials`, `refused`. Both are counted in `node_runtime.start`, so
///   every role has them.
/// - *Accepting* — `attempts`, `spawned`, `accepted`, `finished`, `up`.
///   `up` is the only live count on the node, and it is asked of the core
///   rather than counted here, so it can fall while every other field only
///   rises. These are the endpoint's own counters and no relay role changes
///   what they count: a serving relay's clients arrive through the same accept
///   loop as any other connection, so they are in these numbers too.
/// - *Relaying* — `admitted`, `established`, `registered`, `sent`, `received`,
///   `forwarded`, `disconnected`, `closed`. **Each of these is moved by one
///   half of the relay handshake or the other, and never by both**, so a zero
///   on the wrong half is the role rather than a fact. `registered`,
///   `admitted`, `forwarded` and `disconnected` move only on a serving relay:
///   a node that does not serve admits no client, forwards nothing and reports
///   no disconnection. `established`, `sent`, `received` and `closed` move only
///   on a relay client — the client handshake reaching `.established`,
///   `node_relay_client.sendThrough` writing a datagram, a datagram the relay handed over,
///   and the client handshake asking for its stream to be closed.
pub const Snapshot = struct {
    /// Peers `node_runtime.start` dialled, and peers it recorded a refused attempt for.
    dials: u64,
    refused: u64,
    /// Attempts the accept loop was offered, tasks it spawned, handler
    /// connections that ran, and connections the core has finished with.
    attempts: u64,
    spawned: u64,
    accepted: u64,
    finished: u64,
    /// Connections the core holds right now, asked of it rather than counted
    /// here, so a relay's clients and a client's relay connection are in it
    /// along with everything else. The one field that can go down inside a run.
    up: usize,
    /// Clients a serving relay put in its registry. Counted where the registry
    /// admits one, so zero on every other role.
    admitted: u64,
    /// Relay-client handshakes that reached `.established`. Counted on the
    /// client half, so zero on every other role.
    established: u64,
    /// Node ids a serving relay's registry holds, asked of it rather than
    /// counted here. Zero for a node that does not serve, because such a node
    /// builds no registry to count.
    registered: usize,
    /// Datagrams `node_relay_client.sendThrough` wrote to the relay, a client-half
    /// call that answers `error.NoRelay` elsewhere. Zero on every other role.
    sent: u64,
    /// Datagrams a relay handed this node and it retained. Counted on the
    /// client half, so zero on every other role.
    received: u64,
    /// Datagrams a serving relay forwarded from one client to another. Counted
    /// where a datagram is queued for its destination, so zero on every other
    /// role.
    forwarded: u64,
    /// Clients a serving relay reported as gone, whether their connection ended
    /// or was displaced. Counted on the serve side only.
    ///
    /// **This is not the mirror of `closed`, and the asymmetry is the shape of
    /// the protocol rather than a gap.** A serving relay that ends a client
    /// answers the handshake's `.close` by closing the connection at the core
    /// and counts nothing; a relay client that is refused counts `closed`. So
    /// each role reports the other half's work and neither moves the other's.
    disconnected: u64,
    /// Closes this node's relay client asked for, counted where the client
    /// handshake answers `.close`. Zero on every other role, a serving relay's
    /// included — see `disconnected`.
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
            .up = ozai.node.establishedCount(node),
            .admitted = stats.relay_admitted,
            .established = stats.relay_established,
            .registered = ozai.node_relay_client.clientCount(node),
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
