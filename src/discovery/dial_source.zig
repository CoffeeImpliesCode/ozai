//! Ask every address lookup this node is configured with, and dial what the
//! network said.
//!
//! This file is the facade. The design record for the walk — why every source
//! is asked, why the order the caller listed them in is not consulted, why a
//! refusal ends the run and an empty answer does not, and what the retrieval
//! seam is that this milestone does not build — is
//! `discovery/dial_source_walk.zig`'s module doc, which is where
//! `dialFromSources` now lives.
//!
//! # What is where
//!
//! * `Error`, `Request`, `Selector`, `Outcome`, `Result`, `Dialed` and
//!   `dialFromSources` live in `dial_source_walk.zig`, with the walk.
//! * The QUIC rig, the service doubles and the five tests live in
//!   `dial_source_harness.zig`, with the apparatus.
//!
//! The boundary is the one the file already drew: the walk reaches `item`,
//! `resolve`, `addr`, `addr_map` and `dial` and no socket, while the rig reaches
//! `quic_bridge`, `batch` and the vendored `quic` core. Splitting them keeps the
//! shipped `ozai` module as pure as the walk's own doc claims, which the single
//! file could only do by virtue of never referencing anything below its first
//! `test`.
//!
//! # Every public name is still here
//!
//! Nothing outside `src/discovery/` changed. `src/root.zig` and
//! `src/portable_test.zig` still import this file and still get `Error`,
//! `Request`, `Selector`, `Outcome`, `Result`, `Dialed` and `dialFromSources`,
//! spelled and typed exactly as before.
//!
//! `dial_source_harness.zig` is deliberately *not* re-exported here. It has no
//! public declarations, a bare `@import` does not make Zig collect the test
//! blocks in a file, and re-exporting a test rig would widen the shipped
//! module's surface for no caller. It is reached by `std.testing.refAllDecls`
//! from `src/root.zig` and `src/portable_test.zig` instead.

const walk = @import("dial_source_walk.zig");

/// What a run refuses. See `discovery/dial_source_walk.zig`.
pub const Error = walk.Error;

/// One run's inputs, as a value. See `discovery/dial_source_walk.zig`.
pub const Request = walk.Request;

/// Which of a winning item's addresses this node dials. See
/// `discovery/dial_source_walk.zig`.
pub const Selector = walk.Selector;

/// What a run of the sources came to. See `discovery/dial_source_walk.zig`.
pub const Outcome = walk.Outcome;

/// The four answers a run can come to. See `discovery/dial_source_walk.zig`.
pub const Result = walk.Result;

/// The connection a run opened, and where its address came from. See
/// `discovery/dial_source_walk.zig`.
pub const Dialed = walk.Dialed;

/// Ask every source, merge what they answered, and dial the winner. See
/// `discovery/dial_source_walk.zig`, whose module doc is the design record.
pub const dialFromSources = walk.dialFromSources;
