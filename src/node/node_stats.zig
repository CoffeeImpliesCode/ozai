//! Runtime counters. Protocol-owned reports remain on their protocol states.
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
    /// Messages requested by each gossip layer.
    gossip_membership_asked: u64 = 0,
    gossip_broadcast_asked: u64 = 0,
    /// Peers membership asked to be disconnected, for the same reason.
    gossip_disconnects_asked: u64 = 0,
    /// What membership reported upwards.
    neighbor_up: u64 = 0,
    neighbor_down: u64 = 0,
    broadcasts_received: u64 = 0,
    peer_data_seen: u64 = 0,
    /// What discovery did, counted on the side that succeeded. The refusals
    /// are `Node.discovery`'s own `Refused`, one field per non-success name,
    /// because they are not the same question: `discovery_lookups` counts
    /// questions asked and `Refused` says what became of each, and a node
    /// whose asks grow while nothing leaves is a finding rather than an
    /// absence.
    discovery_lookups: u64 = 0,
    /// Answers that carried records, and the items the resolution path made of
    /// them. `discovery_answers - discovery_lookups` is every question that did
    /// not come back with records, counted apart per name in `Refused`.
    discovery_answers: u64 = 0,
    /// Items the node's own resolution path produced, and the addresses they
    /// carried.
    discovery_items: u64 = 0,
    discovery_addresses: u64 = 0,
    /// Signed packets a pkarr relay stored. The only publish counter: what an
    /// attempt became is `discovery.Refused`.
    discovery_publishes: u64 = 0,
};
