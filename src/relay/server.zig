//! The relay server's pure half: the handshake it authenticates a client
//! with, the registry that holds the clients it admitted, and the two queues
//! each connection writes from.
//!
//! This file is the facade every caller imports. It holds no logic of its own
//! and re-exports three siblings, which together are the whole relay server:
//!
//! - `server_handshake.zig` — the machine a client is authenticated with, and
//!   the one action the caller must take after every step.
//! - `server_registry.zig` — the table of admitted clients, the connection ids
//!   they are known by, and the one exit each admitted connection has.
//! - `server_queue.zig` — the two bounded queues each connection writes from,
//!   and the item types behind them.
//!
//! Nothing here opens a socket, reads a clock, or allocates. The frames come
//! from `relay/frame.zig`; the key material and the challenge come in as
//! arguments. That is the only way the fallback in the handshake can be
//! tested: upstream reaches it through a TLS session where the exporter
//! happens to disagree across a proxy, and it is a branch that has to work on
//! the first try of a real deployment.
//!
//! Captured 2026-09-30 from n0-computer/iroh commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8; each sibling names the upstream
//! lines it reproduces.

const server_handshake = @import("server_handshake.zig");
const server_queue = @import("server_queue.zig");
const server_registry = @import("server_registry.zig");

// The handshake: what a client proved, what access control decided, and the one
// action the caller owes after every step.

pub const default_denial = server_handshake.default_denial;
pub const invalid_signature_reason = server_handshake.invalid_signature_reason;
pub const Mechanism = server_handshake.Mechanism;
pub const Proof = server_handshake.Proof;
pub const Credential = server_handshake.Credential;
pub const Offer = server_handshake.Offer;
pub const Access = server_handshake.Access;
pub const Failure = server_handshake.Failure;
pub const Challenged = server_handshake.Challenged;
pub const State = server_handshake.State;
pub const Action = server_handshake.Action;
pub const Step = server_handshake.Step;
pub const Event = server_handshake.Event;
pub const step = server_handshake.step;

// The registry: who this relay has admitted, and how a connection ends.

pub const ConnectionId = server_registry.ConnectionId;
pub const Disconnection = server_registry.Disconnection;
pub const Unregister = server_registry.Unregister;
pub const Registry = server_registry.Registry;

// The queues: what one connection has not been told yet.

pub const Packet = server_queue.Packet;
pub const Control = server_queue.Control;
pub const Queue = server_queue.Queue;
pub const per_client_send_queue_depth = server_queue.per_client_send_queue_depth;
pub const Connection = server_queue.Connection;