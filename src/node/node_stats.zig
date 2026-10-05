//! What the node did, counted.
//!
//! Every field is an answer a caller of `Node` could not get any other way:
//! either a seam below it keeps that fact and publishes nothing, or the fact
//! is a gap this project has named rather than closed. `node.zig`'s module doc
//! names the counters that stop at a count, and this is where they are read.

/// What the node did, counted.
///
/// Every arm here is something a caller would otherwise have to ask the stack
/// about and get no answer to. The two gossip counters that stop at a count
/// are `node.zig`'s module doc's named gap.
pub const Stats = struct {
    /// Passes of `step` this node has run.
    steps: u64 = 0,
    /// Datagrams the kernel handed over, and datagrams put on the wire.
    datagrams_in: u64 = 0,
    datagrams_out: u64 = 0,
    /// Sends the socket could not batch, and sends that lost a codepoint.
    sends_degraded: u64 = 0,
    ecn_lost: u64 = 0,
    /// Peers `start` dialled, and peers it could not reach.
    dials: u64 = 0,
    dials_refused: u64 = 0,
    /// Accept-loop actions performed. `attempts` is an `Event.arrived` fed,
    /// and the rest are the actions that answered it.
    attempts: u64 = 0,
    spawned: u64 = 0,
    handler_connections: u64 = 0,
    handler_shutdowns: u64 = 0,
    accepts_cancelled: u64 = 0,
    refusals: u64 = 0,
    ignores: u64 = 0,
    /// Connections the core finished with.
    connections_finished: u64 = 0,
    /// Events handed to the gossip layer, and timers it asked for and saw.
    gossip_events: u64 = 0,
    gossip_timers_scheduled: u64 = 0,
    gossip_timers_fired: u64 = 0,
    /// Messages membership asked to be sent, split by layer. **Nothing is
    /// done with them**: see `node.zig`'s module doc.
    gossip_membership_asked: u64 = 0,
    gossip_broadcast_asked: u64 = 0,
    /// Peers membership asked to be disconnected, for the same reason.
    gossip_disconnects_asked: u64 = 0,
    /// What membership reported upwards.
    neighbor_up: u64 = 0,
    neighbor_down: u64 = 0,
    broadcasts_received: u64 = 0,
    peer_data_seen: u64 = 0,
    /// What the relay did, counted.
    ///
    /// Split by what was asked of it rather than folded together, because a
    /// relay that forwards nothing and a relay that forwards nothing *useful*
    /// produce the same counter and need not produce the same log.
    relay_admitted: u64 = 0,
    relay_replaced: u64 = 0,
    relay_promoted: u64 = 0,
    /// Accepted connections this relay had no room for. Upstream refuses
    /// rather than drops, for the reason `endpoint.zig` gives.
    relay_refused: u64 = 0,
    /// Connections this pass could not be admitted **although a client slot was
    /// free**, because the peer had granted no more bidi streams than this end
    /// has already opened on that connection. **Not a refusal** — the
    /// connection is re-offered on the next pass, and `MAX_STREAMS` raises the
    /// grant — and it is counted apart from `relay_refused` because the two
    /// answer opposite questions: that one is a client this relay has no room
    /// for, this one is a client it had room for and no stream to speak on. A
    /// counter that added them together could not say which relay it had.
    relay_stream_deferred: u64 = 0,
    /// Streams a peer finished in the middle of a frame, and the partial frame
    /// dropped with them. See `discardTail`.
    relay_stream_truncated: u64 = 0,
    /// Datagrams forwarded, read off clients, and handed to this node's own
    /// relay client.
    relay_forwarded: u64 = 0,
    relay_datagrams_in: u64 = 0,
    relay_datagrams_out: u64 = 0,
    relay_sent: u64 = 0,
    /// Disconnects reported, and connections that had already been displaced.
    /// The sum is what access control was told, and it is once per connection.
    relay_disconnects: u64 = 0,
    relay_duplicates: u64 = 0,
    /// Queues that were full when something had to go on one, split by what
    /// the full queue could not take: a datagram for a client, a message for
    /// anybody.
    relay_queue_full: u64 = 0,
    relay_unknown_target: u64 = 0,
    /// Datagrams too long for the slot they would be queued into.
    relay_oversized: u64 = 0,
    /// Dials of a relay, and relays that were not there.
    relay_dials: u64 = 0,
    relay_dials_refused: u64 = 0,
    /// The client half: where its handshake got to.
    relay_auth_sent: u64 = 0,
    relay_established: u64 = 0,
    /// `endpoint_gone` frames this node's relay client was handed: the peer it
    /// tried to reach is not at the relay.
    relay_peer_gone: u64 = 0,
    /// A relay told this client it had been displaced by a later connection
    /// for its own node id.
    relay_displaced: u64 = 0,
    relay_closed: u64 = 0,
    /// Reports that found nothing to report. A registry holds a connection once
    /// and `unregister` answers only for one it still holds, so this is the
    /// counter a double report would move.
    relay_double_reports: u64 = 0,
    /// Connections a later one displaced, and that this node managed to tell
    /// over a control queue.
    relay_told_displaced: u64 = 0,
};
