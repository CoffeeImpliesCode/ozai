//! The accept loop: attempts arriving from the QUIC core, offered to the filter
//! and then dispatched by ALPN to the router, with every long-lived `accept`
//! held as a value and torn down in the router's enforced order.
//!
//! The whole surface is re-exported here, so `src/router/` and `src/node/` keep
//! importing one name and no caller changes. The declarations themselves live
//! in three modules named for what they are responsible for, and the split is
//! by responsibility rather than by size:
//!
//! - `accept_events.zig` — what happened, and what the loop owes for it.
//! - `accept_machine.zig` — the machine: one event in, one action out.
//! - `accept_fixture.zig` — the stand-ins a caller supplies.
//!
//! # The original module doc, unchanged
//!
// The accept loop: attempts arriving from the QUIC core, offered to the
// filter and then dispatched by ALPN to the router, with every long-lived
// `accept` held as a value and torn down in the router's enforced order.
//
// Captured 2026-09-30 from n0-computer/iroh commit
// 187f59e80afdae6bd9866002b33d3365c00b06d8: the `select!` body of
// `Router::spawn` at `iroh/src/protocol.rs:531-606`; the filter block at
// `:573-596`; the spawn at `:601-603`; the three shutdown statements at
// `:609-613`; the final reap at `:617-622`; `handle_connection` at `:636-670`;
// the four ways out of the loop at `:541`, `:551-556` and `:569-571`; the
// `ProtocolMap` the shutdown counts from at `:375-407`; and
// `EndpointInner`'s drop report at `iroh/src/socket.rs:220-230`. Each is
// named where it is reproduced.
//
// Upstream's loop is a tokio `select!` and its `accept` futures are tasks on a
// `JoinSet`. Both are what `docs/ARCHITECTURE.md` and `docs/DECISIONS/0002`
// rule out: a machine that needs a scheduler to be tested has its boundary in
// the wrong place, and this project reaches about half of iroh without a
// network. So the loop here is a function of `(state, event)` and a task is a
// struct the caller drives. Everything the upstream loop decides is reproduced
// as a value: which of the four verdicts ends an attempt and which continues
// it, that a `retry` is address validation on a direct path and a cost on a
// relay, that a second `retry` on a flow that has already proved itself is a
// *refusal* rather than a token, that an `accept` which fails is a drop and not
// an error code, and that a shutdown is handlers, then cancel, then close.
//
// Nothing here opens a socket, reads a clock, or takes a runtime, and that is
// the reason the file has this shape rather than a limitation of it. The two
// operations that do need a runtime are the caller's: spawning a task and
// cancelling it. The loop names them — `Action.spawn`, and `cancel_accepts`
// inside `Action.shutdown` — and the caller performs them with the
// `io: std.Io` it already holds for the socket. No function here takes an
// `Io`, because a function here that wanted one would want it to spawn or to
// sleep, and a loop that can spawn is a loop that cannot be tested. The filter
// callback is the caller's for the same reason: it is application code, so
// `step` names the call (`Action.offer`) instead of making it, exactly as
// `router.dispatchStep` names `on_accepting` instead of calling it.
//
// One divergence from upstream is load-bearing and belongs in the
// `docs/ARCHITECTURE.md` list. Upstream's `Incoming::retry()`
// (`connection.rs:183-189`) is a per-attempt call into the QUIC core. The
// vendored core has no such call: it decides Retry from two manager-wide
// fields, `require_retry` and `retry_threshold`, inside the same call that
// accepts the connection and hands it the ClientHello
// (`vendor/quic/src/quic/connection_manager.zig:606-647`, `:662`), so a
// decision made by application code arrives after the point at which RFC 9000
// §17.2.5 permits a Retry at all. A retry verdict is therefore **refused**
// here, which is what upstream does when `incoming.retry()` fails: `if let
// Err(err) = incoming.retry() { err.into_incoming().refuse() }`
// (`protocol.rs:583-586`). Closing the gap is a change in `vendor/quic/` — the
// core has to grow a hook that runs before `acceptConnection` — so the token
// is not a thing this endpoint names.

const accept_events = @import("accept_events.zig");
const accept_machine = @import("accept_machine.zig");

/// See `accept_events.Task`.
pub const Task = accept_events.Task;
/// See `accept_events.Reaped`.
pub const Reaped = accept_events.Reaped;
/// See `accept_events.Ended`.
pub const Ended = accept_events.Ended;
/// See `accept_events.Event`.
pub const Event = accept_events.Event;
/// See `accept_events.Action`.
pub const Action = accept_events.Action;
/// See `accept_events.ShutdownStep`.
pub const ShutdownStep = accept_events.ShutdownStep;
/// See `accept_events.Step`.
pub const Step = accept_events.Step;

/// See `accept_machine.Loop`.
pub const Loop = accept_machine.Loop;
/// See `accept_machine.handlerCount`.
pub const handlerCount = accept_machine.handlerCount;
