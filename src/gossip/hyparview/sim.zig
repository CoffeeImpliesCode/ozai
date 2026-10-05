//! A deterministic in-process network. Upstream `proto/sim.rs`.
//!
//! # Why it is here and not in a test
//!
//! Upstream's own comment on the module is that the gossip protocol is
//! I/O-free and `sim.rs` is the way to test it. That is right, and the reason
//! is sharper than "it is convenient": HyParView is a protocol about
//! *agreement*, and a state machine tested only by feeding it messages never
//! checks that two of them agree. The convergence of two nodes' active views
//! is a property of the network, not of either node, and there is no way to
//! observe it without one.
//!
//! # Determinism, and where upstream's is not
//!
//! Time is a counter this module owns, so there is no clock. Every random
//! choice comes from a generator the caller seeds, and every per-node
//! generator is drawn from the network's, so one seed fixes the whole run.
//! The event queue breaks ties by insertion order, not by a sort.
//!
//! Upstream's simulator is *not* reproducible across processes, and cannot be:
//! `pending_neighbor_requests` and `alive_disconnect_peers` are `HashSet`s
//! built on `RandomState`, whose seed is per-process and per-instance, and
//! `refill_active_from_passive` iterates one of them. Two runs of the same
//! binary with the same `SEED` take different paths. Every such set here is a
//! bounded array, so `zig build test` gives the same answer on every machine
//! and in CI, which is the property a simulator has to have to be a test.
//! That is a deliberate divergence and it is the reason the `Zig` port's
//! numbers are not comparable to upstream's event-for-event.
//!
//! The bits are not comparable anyway: upstream seeds `ChaCha12` and this
//! seeds `xoshiro256`, so even with identical control flow the two would
//! draw different peers. What *is* comparable, and what the tests here pin, is
//! the outcome: the same neighbour sets, the same `NeighborUp` events, the
//! same number of broadcast deliveries, the same synchrony. Those come from
//! the reference's own test expectations, captured from its source at the
//! commit named at the top of this file.

//! # What is in this directory, and why
//!
//! This is the namespace upstream's `proto/sim.rs` is one `mod` for. It is
//! split by what each piece is for, and nothing about the run changes:
//!
//! - `sim_harness.zig` — the fixed sizes, the harness's own error set, the
//!   minted node identities, the latency model and how a swarm is configured.
//! - `sim_network.zig` — the event queue, the links and `Network` itself.
//! - `sim_park.zig` — the arena copies that let a queued message outlive the
//!   state that emitted it.
//! - `sim_simulator.zig` — `Simulator` and `RoundStats`.

const harness = @import("sim_harness.zig");
const network = @import("sim_network.zig");
const runner = @import("sim_simulator.zig");

pub const max_peers = harness.max_peers;
pub const max_neighbour_events = harness.max_neighbour_events;
pub const topic = harness.topic;

pub const SimError = harness.SimError;
pub const HarnessError = harness.HarnessError;
pub const nodeIdFor = harness.nodeIdFor;

pub const LatencyConfig = harness.LatencyConfig;
pub const NetworkConfig = harness.NetworkConfig;
pub const SimulatorConfig = harness.SimulatorConfig;
pub const BootstrapMode = harness.BootstrapMode;

pub const SimEvent = harness.SimEvent;
pub const NeighbourEvent = harness.NeighbourEvent;

pub const Network = network.Network;
pub const Simulator = runner.Simulator;
pub const RoundStats = runner.RoundStats;
