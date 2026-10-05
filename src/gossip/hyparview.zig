//! HyParView: swarm membership, and the deterministic simulator that decides
//! whether this module agrees with the reference.
//!
//! Ported from `n0-computer/iroh-gossip`, `src/proto/hyparview.rs`, `proto.rs`,
//! `proto/topic.rs`, `proto/state.rs` and `proto/sim.rs`, at commit
//! `2885dd9f1120e46aca5acbcd7f212e4c64e278b9`, fetched 2026-09-30.
//!
//! # The deviation that decides whether two implementations agree
//!
//! Paper rule 7 says a node that receives a `ForwardJoin` at the end of its
//! time-to-live "will add the new node to its active view". Upstream does not.
//! It sends a `Neighbor` and does **not** insert, and the peer enters the
//! active view only when it answers with a `Neighbor` of its own — see
//! `onForwardJoin`, where the comment upstream carries is quoted in full.
//!
//! The two rules differ in one observable way and it is a large one. Eager
//! insertion puts a peer in the active view on the strength of a message that
//! peer may be unable to answer, so the view fills with nodes that are
//! unreachable, the `active_view_capacity` is spent on them, and the honest
//! ones are dropped to make room. The two halves also stop agreeing, and not
//! briefly: the inserting node believes it has a neighbour, and nothing in
//! either node ever asks the other. Under the deviation the two halves agree
//! at every instant, because the insertion *is* the reply.
//!
//! That is what makes this the one behaviour in this module that a second
//! implementation gets wrong while still passing every byte-level test, and
//! it is why `sim` exists at all: an implementation that inserts eagerly is
//! indistinguishable from this one until two of its nodes are run against
//! each other. `Config.neighbor_request_timeout` exists for the same reason —
//! a `Neighbor` that is never answered has to time out, and that timer is
//! the only thing standing between a lost reply and a permanently spent slot.
//!
//! The other half of the same invariant is in `onNeighbor`. A `Neighbor` that
//! answers one of ours is a *reply*, and a reply is what makes the insertion
//! happen; one that answers nothing is a fresh request and is answered in
//! turn. `pending_neighbor_requests` is the set that tells the two apart, and
//! removing the peer from it — not adding the peer to the view — is what
//! marks the transition.
//!
//! # What is in this file and why
//!
//! Three layers, in dependency order:
//!
//! 1. `State`, the membership state machine. Two views, a pending-request set,
//!    a table of peers' contact data, and a caller-seeded generator.
//! 2. `TopicState`, the composition: HyParView for membership and
//!    `plumtree.State` for broadcast, with the event ordering that couples
//!    them. This is upstream's `proto/topic.rs`.
//! 3. `sim`, a discrete-event in-process network that runs both. This is
//!    upstream's `proto/sim.rs`, and it is the first test of the module rather
//!    than an afterthought: a membership layer that only ever exchanges bytes
//!    has not been tested at all.
//!
//! `TopicId` lives here rather than in `plumtree.zig` because it is the outer
//! of the two concepts: it names a swarm, and a swarm is a membership view
//! plus a broadcast tree.
//!
//! # `TopicId` is 32 opaque bytes, and there is no privacy story
//!
//! Upstream `TopicId([u8; 32])` is supplied by the application. Nothing derives
//! it, nothing checks it, nothing scopes it, and nothing encrypts the traffic
//! under it. A peer learns a topic id by being told one, and can then read
//! every message on it.
//!
//! ozai keeps that and says it plainly rather than inventing a scheme here.
//! A topic scheme invented in this module would be one nobody else
//! implements, so it would protect nothing while looking like protection, and a
//! reader would have to work out whether it was on. Privacy belongs above:
//! `iroh-relay`'s encrypted datagrams already cover a gossip message in
//! transit, and application-level confidentiality over a topic is a
//! key-agreement and a membership question, not a broadcast question. A
//! future milestone that answers it should add it here with a vector for the
//! scheme, not a plausible-looking default now.
//!
//! # Purity
//!
//! No clock, no environment, no global, no global RNG, no allocator, no I/O.
//! Time is the `now` argument of `handle`; the generator is a value the caller
//! seeds and the state carries; the allocator belongs to the `Actions`
//! container the caller hands in. The simulator allocates, because a test
//! harness is allowed to, and it takes its allocator as an argument like
//! everything else here.

//! # What is in `hyparview/`, and why
//!
//! This file is the module callers import and the whole public surface: every
//! name below is re-exported from the file that owns it, so nothing outside
//! `src/gossip/` changes. The split is by responsibility:
//!
//! - `bounds.zig` — every fixed capacity and the one error set. A message is
//!   not obliged to be short and a view is not obliged to be empty; these are
//!   what happens when one says no.
//! - `topic_id.zig` — the name of a swarm.
//! - `node_id.zig` — `sameNode` and `containsNode`, the identity comparison
//!   every peer-keyed structure below is built on.
//! - `peer_data.zig` — contact data, the peer lists a `Shuffle` carries, and
//!   the bounded table that holds it.
//! - `message.zig` — the membership wire vocabulary.
//! - `rng.zig` — the caller's seeded generator, carried as state.
//! - `index_set.zig` — upstream's insertion-ordered set.
//! - `config.zig` — what a caller configures membership with and what it
//!   reports.
//! - `state.zig` — the membership state machine.
//! - `topic.zig` — membership and broadcast composed, upstream's
//!   `proto/topic.rs`.
//! - `sim.zig` and the four files it names — the discrete-event network, which
//!   is the first test of the module rather than an afterthought.
//! - `*_test.zig` — the tests, beside the code they exercise.

const plumtree = @import("plumtree.zig");
const bounds = @import("hyparview/bounds.zig");
const config = @import("hyparview/config.zig");
const index_set = @import("hyparview/index_set.zig");
const message = @import("hyparview/message.zig");
const peer_data = @import("hyparview/peer_data.zig");
const rng = @import("hyparview/rng.zig");
const state = @import("hyparview/state.zig");
const topic = @import("hyparview/topic.zig");
const topic_id = @import("hyparview/topic_id.zig");

/// Simulated time, in nanoseconds, handed in by the caller. See
/// `plumtree.Nanos`.
pub const Nanos = plumtree.Nanos;

pub const nanos_per_milli = plumtree.nanos_per_milli;
pub const nanos_per_second = plumtree.nanos_per_second;

/// The output container. The same shape as the broadcast layer's, over this
/// module's events, because both are "a list the caller owns and the state
/// machine appends to".
pub const Actions = plumtree.Actions;

pub const topic_id_length = bounds.topic_id_length;

pub const peer_data_max = bounds.peer_data_max;
pub const max_known_peers = bounds.max_known_peers;
pub const max_shuffle_nodes = bounds.max_shuffle_nodes;
pub const max_active = bounds.max_active;
pub const max_passive = bounds.max_passive;
pub const max_bootstrap = bounds.max_bootstrap;

pub const Error = bounds.Error;

pub const TopicId = topic_id.TopicId;

pub const PeerData = peer_data.PeerData;
pub const PeerInfo = peer_data.PeerInfo;
pub const PeerInfos = peer_data.PeerInfos;

pub const Ttl = message.Ttl;
pub const Priority = message.Priority;
pub const Neighbor = message.Neighbor;
pub const Disconnect = message.Disconnect;
pub const ForwardJoin = message.ForwardJoin;
pub const Shuffle = message.Shuffle;
pub const ShuffleReply = message.ShuffleReply;
pub const SwarmMessage = message.SwarmMessage;
pub const SwarmTimer = message.SwarmTimer;
pub const Event = message.Event;
pub const SwarmInEvent = message.SwarmInEvent;
pub const SwarmOutEvent = message.SwarmOutEvent;

pub const Rng = rng.Rng;

pub const IndexSet = index_set.IndexSet;

pub const Peers = config.Peers;
pub const Config = config.Config;
pub const SwarmStats = config.SwarmStats;

pub const State = state.State;

pub const Message = topic.Message;
pub const Command = topic.Command;
pub const Timer = topic.Timer;
pub const InEvent = topic.InEvent;
pub const AppEvent = topic.AppEvent;
pub const OutEvent = topic.OutEvent;
pub const TopicConfig = topic.TopicConfig;
pub const Stats = topic.Stats;
pub const TopicState = topic.TopicState;

pub const sim = @import("hyparview/sim.zig");

test {
    _ = @import("hyparview/state_test.zig");
    _ = @import("hyparview/topic_id_test.zig");
    _ = @import("hyparview/peer_data_test.zig");
    _ = @import("hyparview/config_test.zig");
    _ = @import("hyparview/sim_test.zig");
}
