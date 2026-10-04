const batch = @import("../transport/batch.zig");

/// What the node did, counted.
///
/// Every arm here is something a caller would otherwise have to ask the stack
/// about and get no answer to, and `node_report` prints every one of them: an
/// arm nothing publishes is the gap below going invisible again rather than
/// staying visible. The gossip counters come in pairs for that reason: what
/// the state machine *asked* for, and what `node_gossip` went and did about
/// it, because one without the other cannot say whether a message left.
pub const Stats = struct {
    /// Passes of `step` this node has run.
    steps: u64 = 0,
    /// Datagrams the kernel handed over, and datagrams put on the wire. The
    /// latter is counted where `socket.send` returned: `send` reports no
    /// sent-prefix, so a send that raises counts none of its batch rather than
    /// counting an attempt as a delivery.
    datagrams_in: u64 = 0,
    datagrams_out: u64 = 0,
    /// Sends the socket could not batch, and sends that lost a codepoint.
    sends_degraded: u64 = 0,
    ecn_lost: u64 = 0,
    /// Peers `start` dialled, and peers it could not reach.
    dials: u64 = 0,
    dials_refused: u64 = 0,
    /// Accept-loop events fed and the actions that answered them. `attempts` is
    /// an `Event.arrived` fed and `tasks_routed` an `Event.routed` that a
    /// configured protocol claimed; the rest are the actions that answered one.
    /// Both events are the caller's to feed, which is why they are here rather
    /// than counted inside the loop that cannot produce them.
    attempts: u64 = 0,
    spawned: u64 = 0,
    /// Connections a handler was given and let go, and handlers' shutdowns run.
    handler_connections: u64 = 0,
    handler_shutdowns: u64 = 0,
    /// Connections dropped because **no configured protocol was serving them**,
    /// counted for both reasons that arrives. Either the handshake selected a
    /// protocol no registration claims, which is what a peer that connects
    /// after this node's last protocol was retired gets; or it selected none
    /// at all, which is what a peer whose ClientHello carried no ALPN
    /// extension gets. **Both reach this counter as established connections
    /// with no lane behind them**, because the core's own
    /// `no_application_protocol` refuses an empty intersection of an offer
    /// that *was* made and lives inside the extension's parse
    /// (`vendor/quic/src/quic/tls13.zig:3115-3178`), which a ClientHello
    /// carrying no extension never reaches. The refusal is the accept
    /// path's to make (`node_accept.zig:144-202`) and this is where it is
    /// counted.
    protocols_refused: u64 = 0,
    /// Accept tasks whose negotiated ALPN a configured protocol claimed, which
    /// is what puts a `Task.protocol` on them and makes `laneCount` and
    /// `laneIds` answer for one protocol rather than for the window.
    ///
    /// **A claim and not a report.** A connection that negotiated an ALPN no
    /// configured protocol claims leaves the task unrouted and owes the caller
    /// nothing (`endpoint.Routed`), so it is counted by `spawned` and not by
    /// this — which is the difference a reader wants rather than a number that
    /// agrees with `spawned` for the wrong reason.
    tasks_routed: u64 = 0,
    accepts_cancelled: u64 = 0,
    refusals: u64 = 0,
    ignores: u64 = 0,
    /// Connections the core finished with.
    connections_finished: u64 = 0,
    /// Events handed to the gossip layer, and timers it asked for and saw.
    gossip_events: u64 = 0,
    gossip_timers_scheduled: u64 = 0,
    gossip_timers_fired: u64 = 0,
    /// Messages membership asked to be sent, split by layer. Each was then
    /// performed or dropped; see `gossip_sends_written` and
    /// `gossip_sends_dropped`.
    gossip_membership_asked: u64 = 0,
    gossip_broadcast_asked: u64 = 0,
    /// Peers membership asked to be disconnected, and how many that were acted
    /// on rather than counted.
    gossip_disconnects_asked: u64 = 0,
    gossip_disconnects_acted: u64 = 0,
    /// Frames written onto a topic's stream, and requests that reached nothing
    /// to write on. **The drop is split from the write on purpose**: a peer
    /// with no connection, a frame the codec will not cut and a spent
    /// flow-control window are three different facts, and a caller told only
    /// that "something was not sent" cannot tell a busy node from a broken
    /// one. Every drop is also logged at debug level beside the counter.
    gossip_sends_written: u64 = 0,
    gossip_sends_dropped: u64 = 0,
    /// Streams closed because the connection they were on went away.
    gossip_routes_dropped: u64 = 0,
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
    /// Datagrams for a client this relay does not hold. The sender is told
    /// with a `.peer_gone` pushed onto its control queue
    /// (`node_relay_serve.zig:75-81`), so **this moves only once that
    /// notice is queued**: the same site counts `relay_queue_full` and
    /// returns when the control queue refuses it, losing notice and count
    /// together. **Not a count of full queues** — the distinction is the
    /// whole of why it is a field beside `relay_queue_full` rather than a
    /// term in it, and `node_report` printing the two in one split does not
    /// make them one number.
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

/// Record the socket's send degradation and lost ECN codepoints.
pub fn note(stats: *Stats, report: batch.Report) void {
    if (report.degraded) stats.sends_degraded += 1;
    if (!report.ecnSurvived()) stats.ecn_lost += 1;
}
