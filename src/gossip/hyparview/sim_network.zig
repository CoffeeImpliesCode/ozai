//! The discrete-event network the simulator runs on.
//!
//! Upstream `proto/sim.rs`'s `Network`: nodes in fixed slots, an event queue
//! ordered by `(time, insertion order)`, the open links and one drawn latency
//! per link. It copies every payload that outlives the state that produced it
//! into its arena, which is the one place the borrow rule both gossip layers
//! document is discharged.
//!
//! This file is the facade; `sim.zig` and the tests name it, and the machine is
//! split across the files beside it by responsibility:
//!
//! - `sim_harness.zig` (sizes, errors, latency) — the pieces every file here
//!   reads.
//! - `sim_swarm.zig` — the nodes: the fixed slots, their occupancy and their
//!   views, and the `Network` type whose fields they are.
//! - `sim_run.zig` — the run: the ordered queue, one event step, the link table
//!   and the arena copies that make a queued message safe.
//! - `sim_park.zig` — the deep copy itself, for a message of either layer.
//! - `sim_report.zig` — reading a run back: synchrony, one-sided links,
//!   orphans, active extent, neighbour events.
//! - `sim_simulator.zig` (what drives a run) — `Simulator` and `RoundStats`.
//!
//! The split is not "the simulator" against "the thing simulated": a `Peer`
//! holds a whole `TopicState` inline, so the two halves are one struct and
//! separating them would change what the code allocates. See `sim_swarm.zig`.
const swarm = @import("sim_swarm.zig");

pub const Network = swarm.Network;