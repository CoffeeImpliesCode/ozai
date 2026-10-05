//! The broadcast tree of one node for one topic. Upstream `plumtree::State`.
//!
//! This file is the facade: `../plumtree.zig`, `topic.zig` and the tests name
//! `state.zig`, and the machine itself is split across the files beside it by
//! what each is responsible for:
//!
//! - `state_tree.zig` — `State` itself: its fields, the doors in (`init`,
//!   `leave`, `handle`, `broadcast`, `eagerPeers`, `lazyPeers`) and the three
//!   that moved out and are called from here as methods.
//! - `state_push.zig` — the payload paths: what a `Gossip` does on arrival, the
//!   eager push, the lazy push and the queue the dispatch timer flushes.
//! - `state_control.zig` — the control messages — `Prune`, `IHave`, `Graft` —
//!   and the tree optimisation they drive.
//! - `state_claims.zig` — the claim table: who claims a message, at which
//!   round, and when a graft is owed.
//!
//! The pieces that are separable — the sets, the caches, the claims, the wire
//! values — were already the files beside this one; what moved here is the
//! machine's own code, split so that each file answers one question about it.
//!
//! Zig makes a struct one declaration and cannot reopen one from another file,
//! so what moved is free functions on `*State` rather than methods. Every arm
//! of `handle` still reads and writes the same fields in the order `handle`'s
//! own doc calls the contract, and nothing here reorders it.
//!
//! `init`, `leave`, `eagerPeers` and `lazyPeers` are the doors in. Everything
//! past `handle` is private to the machine, and the handful widened to `pub`
//! are widened because the tests beside this file — and `topic.zig` — assert
//! on them directly.
//!
//! The protocol-wide story — the `MessageId` rule, re-validation, the iTree,
//! purity, bounds and divergences — is in `../plumtree.zig`, which is the module
//! callers import. This file is one piece of it.

const tree = @import("state_tree.zig");

pub const State = tree.State;