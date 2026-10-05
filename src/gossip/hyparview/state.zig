//! The membership state machine of one node. Upstream `hyparview::State`.
//!
//! `active_view` is the set of peers this node believes it is connected to,
//! and — because of the `Neighbor` exchange — those peers hold the same belief
//! about it. That is what "the active view is bidirectional" means in code: not
//! a symmetric data structure, but two nodes that reach the same view by each
//! asking the other and waiting.
//!
//! This file is the facade: `../hyparview.zig`, `topic.zig` and the tests name
//! `state.zig`, and the machine itself is split across the files beside it by
//! what each is responsible for:
//!
//! - `state_machine.zig` — `State` itself: its fields, the doors in (`init`,
//!   `activeView`, `passiveView`, `myData`, `handle`) and the contact table it
//!   keeps. `myData` is widened to `pub` for one reason: `state_test.zig` reads
//!   it through `@call` to prove the borrow survives the frame it was read in.
//! - `state_arms.zig` — what a received membership message makes the node do.
//! - `state_shuffle.zig` — the random walk that mixes the two views.
//! - `state_views.zig` — the active and passive views: what joins them, what
//!   evicts from them and what refills them.
//! - `state_departure.zig` — a peer, or this node, going away.
//!
//! Zig makes a struct one declaration and cannot reopen one from another file,
//! so the arms live beside `State` as functions taking `*State`. That is why
//! every arm of `handle` still reads and writes the same fields in the order
//! `handle`'s own doc calls the contract: the order is in the code, and the
//! code is the machine.
//!
//! The protocol-wide story — the `Neighbor` deviation, the `TopicId` privacy
//! note and the purity rules — is in `../hyparview.zig`, which is the module
//! callers import. This file is one piece of it.

const machine = @import("state_machine.zig");

pub const State = machine.State;