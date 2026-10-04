//! Running the gate on what a probe round measured: the join between
//! `net/report.zig` and `net/holepunch.zig`.
//!
//! Three modules sit around a hole in the tree. `probe_run.zig` runs a round
//! and files every answer into a `probe.Results`. `probe.zig` folds those
//! into a `report.Report`. `holepunch.zig` decides whether to ask the QUIC
//! stack for a NAT-traversal round, from a candidate set, an instant and a
//! connection. This file is the producer's other half: it turns a folded
//! report and a peer's published record into the gate's inputs, hands the
//! gate's answer back, and restates none of the three modules above it.
//!
//! The three live in the three modules that own them, and this file is their
//! surface: a caller has one import and does not learn which module a producer
//! came from.
//!
//! - `holepunch_run_set.zig` — one candidate set: a fixed-capacity inline
//!   buffer that counts what does not fit rather than dropping it.
//! - `holepunch_run_table.zig` — the per-peer path table: where a candidate
//!   is filed, and what the ceiling leaves behind.
//! - `holepunch_run_join.zig` — the value that owns both, and the producers
//!   that write them.
//!
//! # The seven inputs, and where each one comes from
//!
//! A probe round measures **this node**, from the inside, over QUIC. The gate
//! asks about **one connection**, from the outside. Three of its seven inputs
//! have a producer here and four do not, and each of the four is named below
//! with what would close it. A reader without this section reads a gap as a
//! rule, and then wonders why the gap is never closed.
//!
//! ```text
//! gate input                          | where it comes from
//! -------------------------------------|----------------------------------
//! local: where this node is reachable | `observeReport`
//! the mapping verdict                  | `observeReport`
//! remote: where the peer is reachable | `observePeer`
//! the connection to punch on          | gap: the transport's table
//! what the stack said about a round   | gap: no QNT in the vendored core
//! whether a path carried traffic      | gap: no multipath layer
//! the socket's interface addresses    | gap: no interface enumeration
//! ```
//!
//! **The connection.** `holepunch.selectPunchConnection` turns a table into
//! the one connection a round runs on, and `Join.selectConnection` is its
//! pass-through. The table belongs to the transport — it is
//! `transport/quic_bridge.Bridge.manager.entries`, one layer above this one
//! (`docs/ARCHITECTURE.md`) — and nothing under `src/net/` imports
//! `src/transport/`, which is what keeps this layer drivable with no QUIC
//! substrate at all. `probe_run.Transport` is how the layer reaches the
//! transport when it has to: a vtable the transport side fills, never an
//! import, and no implementation of one for a connection table exists on the
//! other side of it yet.
//!
//! The side is one field away for whoever writes that implementation:
//! `quic_bridge.Conn.entry` is public and `conn.entry.conn.is_server`
//! (`vendor/quic/src/quic/connection.zig:608`) is what `transport/dial.zig`
//! and the node already read — `src/node/node_accept.zig` filters on it, and
//! the pass that does it is one `src/node/node_runtime.zig` drives. What this
//! layer could not do with it is narrow the table to one peer, because the
//! table holds every connection this node has and a `Join` is one peer's.
//!
//! **The stack's answer.** `initiate_nat_traversal_round` is
//! `draft-seemann-quic-nat-traversal-02`, and the vendored core has no QNT:
//! `qnt`, `traversal` and `path_id` appear nowhere under `vendor/quic/src`,
//! and `docs/DECISIONS/0001` gives the reason — iroh's QUIC is n0's own fork
//! and this is endel/quic-zig. So `holepunch.Outcome` is a value the caller
//! brings back from a call this project cannot make, `settle` is where it
//! arrives, and `holepunch.classify` stays the only thing that reads it.
//!
//! **A path's status.** Nothing in this tree watches traffic per path. The
//! core keeps `paths: [2]NetworkPath` under one `active_path_idx`
//! (`vendor/quic/src/quic/connection.zig:626`) — an active/candidate register
//! rather than a path set, which `DECISIONS/0001` measured and recorded — and
//! `Conn.drain` sends every datagram at the one peer address it holds. So
//! `observe` is handed its status and `holepunch_run_table.file` files
//! `unknown`, and no rule about which status follows which is written here.
//!
//! **The socket's interface addresses.** The half of the local set no round
//! measures, and the one argument of `observeReport` a caller has to find.
//! The socket knows a single address and it is not one of these:
//! `transport/socket.zig:885` reads it back with `getsockname`, which on a
//! wildcard bind is `0.0.0.0` or `::` with the ephemeral port — where this
//! node is *bound*, not where a peer may reach it, and advertising it would
//! be worse than advertising nothing. The addresses behind it need
//! `getifaddrs` or a netlink route dump, and neither appears anywhere under
//! `src/`: there is no netwatcher here to call one.
//!
//! # The two mappings
//!
//! `global_v4` and `global_v6` are the addresses a relay saw this node come
//! from, and they are the only form of "where am I reachable" a round can
//! produce. The local set is those, then the caller's interface addresses.
//! Order is not a rule — `holepunch.hasNewAddress` compares sets, and
//! `holepunch.decide` cannot tell which of the two sources a candidate came
//! from.
//!
//! The peer's candidates come the other way round: from the record the peer
//! published, and only from its `.ip` entries. A relay is the fallback path
//! rather than a way in, and a custom transport is not an IP socket, so
//! neither is something to punch at and both are counted rather than dropped
//! in silence. Every direct address is filed twice — once in the advertised
//! set the gate compares, once in the path table the caller learns from —
//! because upstream those are one record (`PathEntry` in
//! `iroh/src/socket/remote_map/remote_state/path_state.rs`) and this file
//! keeps them apart: the gate borrows a set while the table owns one.
//!
//! The verdict is carried and consulted by nothing here, and that is not an
//! omission. `holepunch.decide` takes no verdict, and a rule that consulted
//! one would be invented: a destination-dependent mapping makes hole punching
//! *harder* and does not make it pointless, because the round itself opens
//! the mapping it needs. The verdict is here for the caller deciding whether
//! this node may be published as directly reachable, and only two probes to
//! *different* relays can produce it.
//!
//! # Three buffers, because the gate compares against the last round
//!
//! `holepunch.decide` compares this round's candidate sets against the ones
//! the last round was started with, so those have to outlive the round that
//! produced them. One buffer would be rewritten under the comparison, and a
//! slice into storage the caller owns would make the caller's bookkeeping
//! part of the gate's invariant. So each set this file keeps is its own
//! buffer: live local, recorded local, and the peer's. `settle` copies the
//! live local set into the recorded one and only an accepted round does so,
//! because it is the only outcome that records a set at all. The copy is a
//! few hundred bytes once a round.
//!
//! The recorded buffer is storage this file owns and nothing points into it.
//! `ready` re-slices it on each turn and hands the slice to the gate as
//! `holepunch.Candidates.previous_local`; the gate reads it and stores
//! nothing. That is the whole point of the arrangement, and the earlier
//! arrangement — handing the gate a slice of the recorded buffer and letting
//! it keep that slice in `PunchState.last` — made a copy of a settled `Join`
//! read the *original's* bytes, silently, with nothing to tell the two apart.
//! A value that borrows from itself is not a value.
//!
//! # A value, and what that costs
//!
//! `Join` is a value: no pointer to the transport, no task, no allocator, and
//! every set in it is its own storage. Copying or moving one carries all of
//! it — including the recorded candidate set, which is why that set is
//! re-sliced per turn rather than pointed at once. A copy is a snapshot: the
//! two then answer independently, and acting on both means two nodes punching
//! for one peer.
//!
//! One slice in a settled `Join` is still borrowed, and it is not one of the
//! three buffers: `punch.last.remote` names the candidate list the QUIC stack
//! returned, which arrives in `holepunch.Outcome.accepted` and belongs to the
//! caller. The caller keeps it alive for as long as it reads `punch`, and a
//! copy names the same caller buffer. The stack is one of the gaps above, so
//! there is no producer here to hold anyone to that.
//!
//! # What the gate already decides, and what this file adds
//!
//! Timing is the gate's: `holepunch.decide` answers when a round is due,
//! `holepunch.settle` answers what a refusal means, and `holepunch.prune`
//! answers what a changed path table keeps. This file adds three questions
//! none of them is asked:
//!
//! - **Whether the candidate set may be handed over at all.** A set past
//!   `holepunch.max_qnt_addresses` is answered `too_many_addresses`, which
//!   is fatal rather than slow, so `ready` asks `holepunch.mayAdvertise`
//!   before the gate is consulted at all and refuses the round itself.
//! - **Where the gate's borrowed slices live.** `Join` owns them, so a
//!   caller cannot hand the gate a buffer it is about to rewrite.
//! - **What the burst did.** `absorb` and `observePeer` file candidates and
//!   prune as they go, and hand back what the prune dropped, so the plan's
//!   rule — a burst of untested address-lookup results must not evict the
//!   paths that work — is observable from the caller's side of the seam
//!   rather than only from `holepunch.prune`'s own tests.
//!
//! Freshness is deliberately absent from that list. `report.ProbeResult`
//! carries the instant it was observed and `report.fold` ages it against
//! `report.max_report_age` for the preferred-relay window, but nothing here
//! ages the candidate sets: a caller holding an old report or an old record
//! is a caller that has already decided it is worth handing over.
//!
//! # No clock, no thread, no socket, no allocator
//!
//! Every instant is an argument — `ready(now)` and `settle(now, outcome)` —
//! and a test drives the whole chain on one, from a probe round that opened
//! no socket to a punch decision nobody acted on. Nothing here reads a clock,
//! allocates, or touches a thread: see "A value, and what that costs" for what
//! a `Join` owns and what it borrows.
//!
//! Upstream at n0-computer/iroh commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8 — the pin `net/holepunch.zig`
//! carries — for the two things this file joins: `Report` with its
//! `mapping_varies_by_dest`, from `iroh/src/net_report/`, and `PathState`
//! with its `prune_non_relay_paths`, from
//! `iroh/src/socket/remote_map/remote_state/path_state.rs`.

const path_table = @import("holepunch_run_table.zig");
const run_join = @import("holepunch_run_join.zig");
const run_set = @import("holepunch_run_set.zig");

/// How many paths one peer may carry between prunes.
pub const max_paths = path_table.max_paths;

/// One set of candidate addresses, in this file's own storage.
pub const Set = run_set.Set;

/// What one turn of the join decided.
pub const Action = run_join.Action;

/// What recording one path did to the table.
pub const Filed = path_table.Filed;

/// What one burst of candidates cost.
pub const Absorbed = path_table.Absorbed;

/// What one peer's published record did to the join.
pub const Peered = run_join.Peered;

/// One peer's NAT traversal as this file keeps it.
pub const Join = run_join.Join;