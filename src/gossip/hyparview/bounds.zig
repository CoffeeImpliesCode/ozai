//! Every fixed capacity in HyParView, and the one error set they raise.
//!
//! They live together because they are the same contract stated twice: a
//! message is not obliged to be short, a view is not obliged to be empty, and
//! every bound below is what happens when one of them says no. `Config`
//! validates against these at `init` rather than twenty messages into a run.
//! The protocol-wide story — the `Neighbor` deviation, the `TopicId` privacy
//! note and the purity rules — is in `../hyparview.zig`, which is the module
//! callers import. This file is one piece of it.

/// 32 bytes an application chose. Upstream `TopicId([u8; 32])`, `proto/state.rs:21`.
pub const topic_id_length = 32;

/// The largest `PeerData` a node will hold or carry. Upstream's is a
/// `Bytes` with no bound; a bound is what "no allocator" costs, and a node
/// address with a couple of paths on it fits.
pub const peer_data_max = 256;

/// How many peers a node remembers contact data for.
pub const max_known_peers = 32;

/// The largest `Shuffle` or `ShuffleReply` node list. The default config
/// already fills it: three active, four passive, and ourselves.
pub const max_shuffle_nodes = 8;

/// The largest active view. A node keeps five by default; thirty-two is the
/// bound at which a test can drive a swarm wider than the default without
/// making every state machine in a test enormous.
pub const max_active = 32;

/// The largest passive view. Thirty by default; sixty-four is the bound.
pub const max_passive = 64;

/// The largest bootstrap list a `Command.join` may carry.
pub const max_bootstrap = 8;

/// Every way membership refuses to do what it was asked.
pub const Error = error{
    /// The active view is at `max_active` and the request may not be denied.
    ActiveViewFull,
    /// The passive view is at `max_passive` and nothing may be dropped to make
    /// room for the new peer.
    PassiveViewFull,
    /// The pending-`Neighbor` table is full.
    NeighborRequestTableFull,
    /// The contact-data table is at `max_known_peers`.
    PeerDataFull,
    /// Contact data longer than `peer_data_max`.
    PeerDataTooLong,
    /// A shuffle node list longer than `max_shuffle_nodes`.
    ShuffleNodeListTooLong,
    /// A bootstrap list longer than `max_bootstrap`.
    BootstrapListTooLong,
};
