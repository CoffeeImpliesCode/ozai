//! What a discovery result is, which service produced it, and how two results
//! compare.
//!
//! Captured from n0-computer/iroh, `iroh/src/address_lookup.rs`, commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8 — the `iroh` 1.3.0 crate as
//! published, fetched 2026-09-30.
//!
//! Upstream has no `DiscoveryItem` enum any more. `Item` (that file's lines
//! 372–385) is a plain struct of three fields, deriving only `Debug, Clone,
//! Eq, PartialEq`: the `EndpointInfo` a service discovered, a `&'static str`
//! naming the service, and `Option<u64>` microseconds since the unix epoch.
//! All three are here. So is the absence of an ordering: the `last_updated`
//! field carries a `TODO(ramfox)` at line 383 saying it is unused, and
//! nothing in the tree sorts an `Item`. The order below is therefore ozai's,
//! and it is the reason this module exists.
//!
//! Two divergences from upstream. The first is already recorded in
//! `docs/ARCHITECTURE.md`, under "No `DiscoveryItem` enum":
//!
//! * `Provenance` is a closed enum. Upstream types the tag `&'static str` and
//!   lets `MemoryLookup::with_provenance` and every test double invent one, so
//!   a typo is a value that matches nothing. The *set* is upstream's: the
//!   three strings its shipped services pass, at
//!   `iroh/src/address_lookup/dns.rs:130`, `pkarr.rs:546` and `memory.rs:102`.
//!
//! The second has no upstream counterpart at all and wants a bullet of its own
//! in the same list:
//!
//! * The tiebreak is `base/addr.zig`'s value order — `TransportAddr.order`,
//!   the order a `NodeAddr` list is kept in and a ticket canonicalizes its
//!   addresses by — and not a wire format. The wire formats are another
//!   module's business and they change; an order that moved when a ticket
//!   encoding moved would reorder zones for a reason nobody could see, and
//!   one that read a different order than the address lists would pick a
//!   different relay than the list it was handed. Nothing here is ever sent
//!   to a peer.
//!
//! The stream plumbing — the `AddressLookup` trait, the resolvers implementing
//! it, the handle whose drop cancels them — is a later slice. What is here is
//! the part that does not need it: the result, its origin, the order, and the
//! difference between "cannot resolve" and "resolved to nothing".
//!
//! # This file is the facade
//!
//! The four questions above were one file, and they are now four modules under
//! `src/discovery/`, with the boundaries between the questions rather than
//! between the declarations. Every public name this file has ever had is still
//! reachable through it, so `discovery/resolve.zig`, `discovery/dns.zig`,
//! `discovery/dial_source_walk.zig` and `src/root.zig` import this file and get
//! exactly what they got before:
//!
//! | name | home | question it answers |
//! | --- | --- | --- |
//! | `Item`, `Provenance` | `item_record.zig` | what one result *is* |
//! | `EncodeError`, `max_encoded_addr_length` | `item_encode.zig` | what it looks like in bytes |
//! | `merge`, `winner` | `item_merge.zig` | what a *set* of them comes to |
//! | `Resolution` | `item_resolution.zig` | what one attempt came to |
//!
//! `item_fixture.zig` holds the seed pool the property tests share. It is not
//! re-exported here: it is reached only from the test regions of the modules
//! above, and `src/root.zig` names it so those blocks run.

const record = @import("item_record.zig");
const encode = @import("item_encode.zig");
const set_answer = @import("item_merge.zig");
const resolution = @import("item_resolution.zig");

/// One discovery result. See `discovery/item_record.zig`.
pub const Item = record.Item;

/// Which lookup service produced an `Item`. See `discovery/item_record.zig`.
pub const Provenance = record.Provenance;

/// Why an item cannot be written in its canonical encoding. See
/// `discovery/item_encode.zig`.
pub const EncodeError = encode.EncodeError;

/// Longest record the canonical encoding writes. See
/// `discovery/item_encode.zig`.
pub const max_encoded_addr_length = encode.max_encoded_addr_length;

/// The best item of a set, or null when there is none. See
/// `discovery/item_merge.zig`.
pub const winner = set_answer.winner;

/// Every distinct item of a set, best first. See `discovery/item_merge.zig`.
pub const merge = set_answer.merge;

/// What one resolve attempt came to. See `discovery/item_resolution.zig`.
pub const Resolution = resolution.Resolution;
