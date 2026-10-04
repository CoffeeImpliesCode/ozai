//! Holepunching: the gate around one call into the QUIC stack.
//!
//! Holepunching is not a protocol. It is `initiate_nat_traversal_round` on a
//! QUIC connection, and relay and direct are two paths on that one connection.
//! What ozai owns is everything around that call: when to make it, what to do
//! with the answer, and which paths to forget.
//!
//! All three are pure over state, so all three are here, and all three are
//! testable before the QUIC stack exists. Nothing under this name reads a clock
//! — the elapsed time arrives as `now` — and the call leaves as an `Action`
//! value that names it rather than as a call. `docs/DECISIONS/0001` is why the
//! call leaves at all: the substrate is a fork of someone else's QUIC and is
//! not in this tree yet.
//!
//! The three live in the three modules that own them, and this file is their
//! surface: a caller has one import and does not learn which module a decision
//! came from.
//!
//! - `holepunch_gate.zig` — the machine: `PunchState`, the connection a round
//!   runs on, the candidate comparison, and `decide`.
//! - `holepunch_refusal.zig` — what an answer means: `classify`, and `settle`
//!   folding that answer back into the state.
//! - `holepunch_path.zig` — what a changed path table keeps: `prune`.
//!
//! Every function here takes plain slices and returns plain values, which is
//! what makes them fuzzable: `decide`, `settle`, `classify` and `prune`
//! allocate nothing and reach nothing a test cannot hand them, so a
//! `std.testing.fuzz` target can drive them from bytes against fixed oracles —
//! every prune keeps every `open` path, keeps the
//! `max_inactive_non_relay_paths` most recently closed `inactive` paths, and
//! drops no relay. No target is registered yet; those are its oracles.
//!
//! Upstream, captured 2026-09-30 at n0-computer/iroh commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8:
//!
//! - `HOLEPUNCH_ATTEMPTS_INTERVAL`, `trigger_holepunching`, `do_holepunching`
//!   and `HolepunchAttempt` from `iroh/src/socket/remote_map/remote_state.rs`.
//! - `MAX_QNT_ADDRESSES` from `iroh/src/socket.rs:145`.
//! - `MAX_NON_RELAY_PATHS`, `MAX_INACTIVE_NON_RELAY_PATHS`, `PathStatus`,
//!   `PathState` and `prune_non_relay_paths` from
//!   `iroh/src/socket/remote_map/remote_state/path_state.rs`.
//!
//! The error arms are `noq_proto::n0_nat_traversal::Error`, fetched from
//! n0-computer/noq at commit 89ed00c31297c2127d1697a7b63983d60fd02ecb,
//! `noq-proto/src/n0_nat_traversal.rs:114`.

const gate = @import("holepunch_gate.zig");
const path = @import("holepunch_path.zig");
const refusal = @import("holepunch_refusal.zig");
const report = @import("report.zig");

/// Nanoseconds on a monotonic timeline the caller owns.
///
/// `net/report.zig` already defines it for the fold from probe results, and two
/// definitions of "an instant" in one layer would only invite a conversion
/// nobody wants.
pub const Nanos = report.Nanos;

/// How long to wait before repeating a round that changed nothing.
pub const punch_interval = gate.punch_interval;

/// How long to wait before repeating a round the stack refused.
pub const retry_interval = refusal.retry_interval;

/// How many non-relay paths one peer may carry before anything is pruned.
pub const max_non_relay_paths = path.max_non_relay_paths;

/// How many previously-successful paths may survive a prune.
pub const max_inactive_non_relay_paths = path.max_inactive_non_relay_paths;

/// How many addresses one connection may advertise to its peer.
pub const max_qnt_addresses = gate.max_qnt_addresses;

/// Whether `count` addresses fit under `max_qnt_addresses`.
pub const mayAdvertise = gate.mayAdvertise;

/// The `stable_id` the QUIC stack gives a connection.
pub const ConnId = gate.ConnId;

/// Which end of the handshake a connection is.
pub const Side = gate.Side;

/// One connection to the peer, as far as the punch gate is concerned.
pub const Connection = gate.Connection;

/// The connection a round runs on: the client connection with the lowest id.
pub const selectPunchConnection = gate.selectPunchConnection;

/// Whether `current` names an address `previous` does not.
pub const hasNewAddress = gate.hasNewAddress;

/// One round the stack accepted: when it started, and what the stack found.
pub const Attempt = gate.Attempt;

/// One remote's NAT-traversal state.
pub const PunchState = gate.PunchState;

/// One instruction for whoever drives the QUIC stack.
pub const Action = gate.Action;

/// What one turn of the machine produced.
pub const Step = gate.Step;

/// The three candidate sets one turn of the gate reads.
pub const Candidates = gate.Candidates;

/// The gate. One wakeup in, one decision out.
pub const decide = gate.decide;

/// What the stack said about a round.
pub const Outcome = refusal.Outcome;

/// Fold a round's answer back into the state.
pub const settle = refusal.settle;

/// Why a round could not start.
pub const NatTraversalError = refusal.NatTraversalError;

/// What to do about a refused round.
pub const Verdict = refusal.Verdict;

/// What a refused round means.
pub const classify = refusal.classify;

/// How usable a path to the peer is.
pub const PathStatus = path.PathStatus;

/// One path to the peer and everything known about it.
pub const Path = path.Path;

/// What one prune dropped.
pub const Pruned = path.Pruned;

/// Enforce the per-peer path ceiling, in place.
pub const prune = path.prune;