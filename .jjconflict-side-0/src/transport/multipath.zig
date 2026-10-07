//! One connection's paths, as the vendored core holds them: the pair of
//! addresses each path runs between, the state of its validation, the round
//! trip observed on it, and the bytes the core has moved on it.
//!
//! `net/path_table.zig` owns the paths a node *believes* it has to one peer —
//! candidates from a peer's record and from probes, keyed on a
//! `TransportAddr`. This file owns the paths one *connection* has, keyed on the
//! two addresses the core is actually running between. The two tables answer
//! different questions and neither reads the other: a candidate this file has
//! never heard of is not a path, and a path the core has abandoned is not a
//! candidate.
//!
//! Nothing here opens a socket, reads a clock or allocates. `at` is an argument
//! to every call that stamps anything, the table is inline storage, and a whole
//! `Table` is a value a test holds on the stack.
//!
//! # What the read-only vendored core means for this file
//!
//! `vendor/quic/src/quic/` is third-party code and is not edited. That single
//! fact decides the whole design, and it decides it by subtraction.
//!
//! `docs/DECISIONS/0001` measured the gap and did not enjoy it. What the core
//! has, quoted: "**Native multipath.** quic-zig has `paths: [2]NetworkPath`
//! (`src/quic/connection.zig:608`) with a single `active_path_idx` (`:609`) and
//! RFC 9000 migration; it does not implement `draft-ietf-quic-multipath`, and
//! iroh wants up to 8 concurrent paths per connection" — and, of the remedy it
//! names, "**Congestion, RTT and ECN state would have to become per-path.**
//! Today a migration *discards* them (`connection.zig:3461-3468`) precisely
//! because there was only one live path to move them to. With N live paths they
//! must be retained per path; if they are not, every path change still costs a
//! fresh Cubic and the 6% is the ceiling rather than the current state."
//!
//! So, precisely:
//!
//! - **This file delivers the observation.** Which address pairs the core
//!   currently holds for a connection, what each one's validation state is, what
//!   the core's own ledger says it has moved on it, and a per-path round trip
//!   measured by the caller. All of that is readable out of a core that is not
//!   modified, and `Table.mirror` is where it is read.
//! - **This file cannot deliver a third path.** `DECISIONS/0001` names the
//!   change that would, and none of it is in `src/transport/`: "**Widening the
//!   array is the mechanical half.** Making those per-path instead of
//!   per-active-path is the other half." Every one of those sites is in the
//!   vendored tree.
//! - **This file cannot deliver a path id.** `DECISIONS/0001` records the
//!   dependency that wants one — "iroh 1.3.0 depends on `noq` / `noq-proto` /
//!   `noq-udp`, n0's own fork of QUIC carrying multipath `PathId` and QNT" — and
//!   the maintainer's own statement that this core has none: "**Multipath**:
//!   not implemented, by the maintainer's own statement in `SPEC/STATUS.md`
//!   ("Multipath QUIC (draft-ietf-quic-multipath) — **Status: Not
//!   implemented**")." See the decision below.
//! - **This file cannot deliver per-path congestion.** The core holds one `cc`,
//!   one `rtt_stats` and one ECN validator per *connection*
//!   (`connection.zig:4265-4270` is where a migration throws them away), so
//!   there is nothing per-path to mirror. What this file records per path is the
//!   round trip *this project* measures on that address pair, which the core
//!   does not keep.
//!
//! Everything below is written so that a future patch to the core makes it wrong
//! loudly: the fold over the core's two validation fields is one named function,
//! the slot count is one named constant, and the one fact this file reads the core
//! for — that `acceptInto` leaves the second slot `undefined` (`:1537`) and every
//! later write promotes the slot it wrote — is stated at the read, with the four
//! write sites it rests on.
//!
//! # Decision: a path is its two addresses, and the core names nothing else
//!
//! `Key` is the ordered pair `(local, peer)` — the same two values
//! `NetworkPath.init` copies into `local_addr` and `peer_addr`
//! (`connection.zig:217`). Three reasons, read out of the core rather than
//! assumed:
//!
//! 1. **The core has no path identifier to reuse.** `NetworkPath` (`:188`)
//!    carries two addresses, three counters, a flag and a validator. There is
//!    no id field, `draft-ietf-quic-multipath`'s `PathId` is not implemented,
//!    and a number minted in this file would be a second name for something the
//!    core never produces — one that would have to be reconciled against the
//!    core on every datagram and would name the wrong path the first time the
//!    core rewrote a slot.
//! 2. **The core's own equality is this pair.** A migration is triggered by
//!    comparing a datagram's source against the active path with
//!    `info.from.eql(active_path.peer_addr)` (`:2259`), and `Address.eql`
//!    compares family, octets, port and scope. Two paths are the same path to
//!    the core exactly when both addresses match, so the pair is the identity
//!    and not a convenient proxy for one.
//! 3. **A slot index is not an identity.** `handleMigration` overwrites the
//!    candidate slot outright (`:4246`) and promotes it (`:4255`), so index 1
//!    is one path before a migration and a different one after. An index that
//!    changes what it names is provenance. `Entry.slot` records it, and the doc
//!    on that field says why it is not the key.
//!
//! The connection itself is named by the core's own id: `mirror` copies
//! `Conn.id()` (`bridge_conn.zig`, which is `ConnEntry.id`, "unique per manager,
//! never reused"). There is no connection id minted here either.
//!
//! **There is no per-path CID to record, and that is a finding.** The core sends
//! on one peer CID at a time — `ConnectionIdPool` carries a single `in_use` mark
//! and one `consumeUnused` (`:332`) — so `draft-ietf-quic-multipath`'s "a
//! distinct CID per path" has nothing here to mirror, and a CID field would be
//! the feature rather than a record of it.
//!
//! # Decision: validation, and the five things that produce it
//!
//! The core keeps **two** fields: `NetworkPath.is_validated` (`:206`) and
//! `PathValidator.state` (`:91`), a four-value enum whose own doc warns that
//! "`idle` is both 'never tried' and 'finished', so this field alone cannot tell
//! a path that was never challenged from one that is proved". This file folds
//! the two into one `Validation`, and the fold is `advance`.
//!
//! `is_validated` wins, and that is not a preference. It is the only one of the
//! two the core's single path-dependent policy reads: `NetworkPath.canSend`
//! (`:231`) asks `self.is_validated` and nothing else. A path the core will send
//! on without an amplification limit is validated here, whatever its validator
//! is doing.
//!
//! Five things set `is_validated` in the core, and all five reach this table:
//!
//! | what | where |
//! |---|---|
//! | a Retry proved the address | `:1531` |
//! | a Handshake-epoch packet on a server's active path | `:2105` |
//! | a PATH_RESPONSE matched the challenge | `:3007` |
//! | the client confirmed the handshake | `:3281` |
//! | a port-only migration, where the IP is unchanged | `:4275` |
//!
//! The fifth is why the fold is not a straight read of `validator.state`: a NAT
//! rebinding writes a *fresh* `NetworkPath` (`:4246`), challenges it (`:4258`)
//! and then marks it validated (`:4275`), so the core really does hold
//! `is_validated == true` beside `state == .pending`. `advance` reports
//! `.validated` for that pair, and the test pins it.
//!
//! **A validated path does not return to unvalidated, and that is a property of
//! this file rather than a claim about the core.** `is_validated` is assigned
//! `true` in five places and `false` in none; what a migration does is write a
//! *different* pair into a slot, which this table retires and refiles.
//! `advance` refuses the demotion anyway: a mirror's job is to be usable when
//! the core is right and obviously wrong when the core is not, and a table that
//! dropped a validated path on a fact the core cannot produce would fail in the
//! direction of closing a working path.
//!
//! **A path this node has never been told about is not invented here.**
//! `sample` and `used` both refuse a pair the table does not hold live, because
//! a measurement of a path the core has left would have to be attributed to
//! something else, and the figure would then be a round trip nobody measured.
//!
//! # Decision: the bound is eight, and at the bound the table refuses
//!
//! `max_paths` is 8 for the number `DECISIONS/0001` records — "iroh wants up to 8
//! concurrent paths per connection" — restated rather than imported from
//! `net/path_table.zig`. The two bounds are the same number over two different
//! tables, and importing one from the other would tie a per-connection mirror to
//! a per-peer selection policy; that module says the same about itself, that its
//! rules are its own.
//!
//! Eight is four times what the core can hold today (`core_slots` is 2), and the
//! difference is history. A path the core migrates away from is *retired*, not
//! forgotten: it keeps its addresses, its figures and the instant it was last
//! live, because `DECISIONS/0001`'s measurement of what a migration throws away
//! is only legible if the table remembers what was thrown.
//!
//! At the bound the answer is a refusal, and the one exception is the same one
//! `net/path_table.zig` takes and for the same reason: a `.failed` path is the
//! only entry here that is a *recorded* failure, so freeing its slot sheds
//! nothing a caller is relying on. A validated path, a challenging one and a
//! retired one all still carry history and none of them may be displaced. With
//! nothing displaceable, `observe` answers `.refused` and the table does not
//! grow, and `mirror` counts the refusal in `Mirror.refused` rather than
//! dropping it.
//!
//! # What this file deliberately does not own
//!
//! - **Per-path congestion, RTT or ECN state.** One per connection in the core;
//!   see the module doc.
//! - **Which path to send on.** `net/path_select.zig` owns selection, over
//!   candidates, and this table is not a substitute for it.
//! - **Idleness.** `Entry.last_active` is a stamp and a comparison; how long a
//!   quiet path stays usable is a selection policy, and a second timeout here
//!   would be a second opinion. Only `rtt_max_age` is declared, because a figure
//!   this file hands out as current when it is stale is this file's own error,
//!   not a policy call.
//! - **The wire.** No bytes are read or written here. `Conn.drain` and
//!   `Bridge.recv` are where the core's ledger is fed by real traffic; this file
//!   is told what the core holds.
//!
//! Line references into the vendored tree are to the tree as it stands in this
//! repository, which is patched relative to the revision `DECISIONS/0001` cites.

const std = @import("std");
const quic = @import("quic");
const base_addr = @import("../base/addr.zig");
const bridge_address = @import("bridge_address.zig");
const bridge_config = @import("bridge_config.zig");
const bridge_conn = @import("bridge_conn.zig");

const SocketAddr = base_addr.SocketAddr;
const Conn = bridge_conn.Conn;
const fromCoreAddress = bridge_address.fromCoreAddress;
const CorePath = quic.connection.NetworkPath;

/// The instant the core is driven at, on the core's own timeline: `i64`
/// nanoseconds, and the same type `Conn.drain` and `Bridge.recv` take. Named
/// here rather than restated as a local alias so a caller naming an instant for
/// a path and an instant for a connection has one clock and not two.
pub const Instant = bridge_config.Instant;

/// A duration on that timeline — a round trip, or a maximum age for one.
pub const Nanos = u64;

/// How many paths one connection's mirror carries, retired ones included.
///
/// See the module doc under "the bound" for the number and the refusal.
pub const max_paths: usize = 8;

/// How many slots the core's path array has: `paths: [2]NetworkPath`
/// (`vendor/quic/src/quic/connection.zig:1148`).
///
/// Named rather than written into a comparison because it is the one place this
/// file's shape is the core's shape, and a core that widened its array is a
/// change this file should have to answer for.
pub const core_slots: usize = 2;

/// How old a latency sample may be and still be believed.
///
/// The same figure `net/path_table.zig` names, and the same reasoning from the
/// same paragraph of `DECISIONS/0001`: a worst-case NAT rebinding took eight
/// path challenges at 109 RTTs, so a sample younger than that describes a
/// mapping that has not been disturbed since it was taken. Restated rather than
/// imported, because that constant is a per-peer selection policy and this is a
/// per-connection mirror; the two can be retuned apart, and this file's only
/// claim is that a stale figure is not handed out as a current one.
pub const rtt_max_age: Nanos = 5 * std.time.ns_per_s;

/// The core's own `PathValidationState`, re-exported so a caller reporting on a
/// path names one module and not two.
///
/// It is in the public surface for one reason: `Report.state` is this, and
/// `advance` takes it, because a re-spelling of a core enum would be a second
/// vocabulary for the same four facts and a mapping nobody would read.
pub const CoreValidation = quic.connection.PathValidationState;

/// What a path is: the two addresses it runs between, in the core's order.
///
/// `local` first because that is the order `NetworkPath.init` takes them and the
/// order `Connection.localAddress` and `Connection.peerAddress` name them. The
/// pair is ordered on purpose: a path from A to B is not the path from B to A,
/// and a table that could not tell them apart would hold a loop as a path.
pub const Key = struct {
    /// This node's address on the path.
    local: SocketAddr,
    /// The peer's address on the path.
    peer: SocketAddr,

    /// Whether `other` names the same path.
    ///
    /// `std.meta.eql` rather than a hand-written field walk, because
    /// `SocketAddr` is a plain struct over a union of octet arrays and carries
    /// no borrow — the reason `net/path_table.zig` needs `TransportAddr.order`
    /// and this does not.
    pub fn eql(self: Key, other: Key) bool {
        return std.meta.eql(self, other);
    }
};

/// What is known about a path's addresses at one instant.
///
/// One enum for the core's two fields, folded by `advance`. `.challenging` is
/// this file's word for the core's `.pending`; the other three are the core's
/// own words, kept so a reader holding the vendored tree open is not
/// translating.
pub const Validation = enum {
    /// Nothing has proved the addresses. A server may not send more than three
    /// times what it received on such a path (`NetworkPath.canSend`, `:231`).
    unvalidated,
    /// A PATH_CHALLENGE is outstanding. The core retries it three times and
    /// then fails it (`PathValidator.checkTimeout`, `:143`).
    challenging,
    /// The addresses are proved, and the core will send on the path without an
    /// amplification limit.
    validated,
    /// A challenge spent its retries and its PTO and was never answered.
    failed,
};

/// Fold the core's two validation fields into one state.
///
/// `advance` rather than a plain fold because validation is monotone within one
/// address pair: `current == .validated` is returned unchanged whatever the core
/// reports. See the module doc — `is_validated` is assigned `true` five times in
/// the core and `false` never, and this file refuses the demotion even so.
///
/// The `validated` flag wins over `state`, because `NetworkPath.canSend` reads
/// only the flag, so a path the core will send on without a limit is validated
/// here whatever its validator is doing. That combination is not hypothetical:
/// a port-only migration challenges the fresh path (`:4258`) and then marks it
/// validated (`:4275`).
pub fn advance(current: Validation, validated: bool, state: CoreValidation) Validation {
    if (current == .validated) return current;
    if (validated) return .validated;
    return switch (state) {
        .idle => .unvalidated,
        .pending => .challenging,
        .validated => .validated,
        .failed => .failed,
    };
}

/// What the core says about one path, in this file's fields.
///
/// The translation, and named as one value so `observe` is a pure function of a
/// report and an instant, and a test can hand it a report the core cannot
/// currently produce — which is the only way to pin the bound and the fold.
pub const Report = struct {
    /// Which of the core's `core_slots` slots described this path. Provenance,
    /// never identity; see `Entry.slot`.
    slot: u8,
    /// `NetworkPath.is_validated`.
    validated: bool,
    /// `PathValidator.state`.
    state: CoreValidation,
    /// `NetworkPath.bytes_sent` — the core's own ledger, not a count this file
    /// keeps. Anti-amplification reads it (`:231`).
    sent: u64,
    /// `NetworkPath.bytes_received`, the other half of the same ledger.
    received: u64,
};

/// What one path's entry became.
pub const Outcome = enum {
    /// The table already carried this pair, live, in the slot the report names.
    /// Only its figures and its validation moved.
    kept,
    /// The table carried this pair but it was not live — the core had written
    /// that slot for another pair — and it is live again.
    revived,
    /// A pair the table did not carry. The entry it displaced is in
    /// `Applied.evicted`, and is null when nothing had to move.
    filed,
    /// The table is full and holds nothing that may be displaced. It did not
    /// grow; whatever the named slot used to hold is still retired out of the
    /// running, because the core moved that slot either way.
    refused,
    /// The report named a slot at or above `core_slots`, which is not a slot the
    /// core has. Nothing in the table changed.
    foreign_slot,
};

/// What one `observe` call did, including the two things that happened to
/// *other* entries.
///
/// Counted rather than returned as a bare arm because a caller driving a
/// migration needs three separate facts: that a new path appeared, that the old
/// one went out of the running, and what — if anything — was displaced to make
/// room. Collapsing them would lose whichever two are least expected.
pub const Applied = struct {
    outcome: Outcome,
    retired: usize,
    evicted: ?Key,
};

/// One path this connection has had, and everything observed about it.
pub const Entry = struct {
    /// The two addresses. The identity; see the module doc.
    key: Key,
    /// Where validation stood at the last `observe`.
    validation: Validation,
    /// The round trip measured on this pair, or null until `sample` supplies
    /// one. Never read from the core: the core's RTT is per *connection*
    /// (`connection.zig:5195` reads one `rtt_stats`) and is discarded outright
    /// when the IP changes (`:4267`), so the figure here is this project's
    /// measurement on this pair and the caller's to take.
    rtt: ?Nanos = null,
    /// When that sample was taken. Meaningless, and never read, while `rtt` is
    /// null.
    rtt_at: Instant = 0,
    /// When the table first filed this pair. Never rewritten — not by a
    /// validation change, not by a revival — so it is how long this connection
    /// has known of the pair, which is the only clock available for a pair
    /// nothing has ever been sent on.
    since: Instant = 0,
    /// When bytes last moved on the pair, or null if none ever has. Stamped by
    /// `used`, never by `observe`: the core counts bytes but says nothing about
    /// when it moved them, and an instant the core does not keep is not one this
    /// file may invent.
    last_active: ?Instant = null,
    /// The core's `bytes_sent` for this pair as of the last `observe`. It is
    /// replaced rather than accumulated, because the core zeroes it when it
    /// writes a slot for a new path (`:4246`).
    tx_bytes: u64 = 0,
    /// The core's `bytes_received` for this pair, on the same terms.
    rx_bytes: u64 = 0,
    /// Which of the core's slots last described this pair, or null while it is
    /// not live.
    ///
    /// **Provenance, not identity.** `handleMigration` writes the candidate slot
    /// outright (`:4246`) and promotes it (`:4255`), so slot 1 is one path before
    /// a migration and another after. `Key` is the identity for exactly that
    /// reason; this field records only which array element last held the pair,
    /// which is what lets `retire` know what a slot has moved off.
    slot: ?u8 = null,
    /// When the core stopped holding this pair, or null while it holds it.
    retired_at: ?Instant = null,

    /// Whether the core holds this pair right now, as of the last `observe`.
    ///
    /// Never more than `core_slots` entries answer true, and that is the core's
    /// limit rather than this table's.
    pub fn live(self: *const Entry) bool {
        return self.slot != null;
    }

    /// The round trip to make a decision on at `now`, or null when there is none
    /// worth trusting: never sampled, or sampled so long ago that it may
    /// describe a mapping the pair no longer has.
    ///
    /// A sample stamped after `now` is not stale, it is not yet stale, and the
    /// age saturates rather than wrapping into the far past.
    pub fn latency(self: *const Entry, now: Instant) ?Nanos {
        const measured = self.rtt orelse return null;
        const age = now -| self.rtt_at;
        if (age > 0 and @as(u64, @intCast(age)) > rtt_max_age) return null;
        return measured;
    }
};

/// Where a free slot came from. Private because it is one function's
/// intermediate and not a decision any caller makes.
const Slot = union(enum) {
    free,
    evicted: Key,
    full,
};

/// What one `mirror` pass cost.
///
/// Every field is a distinct fact about the pass, and a table that dropped any of
/// them in silence would leave a caller unable to tell a connection that moved
/// paths from one that refused to.
pub const Mirror = struct {
    /// Paths the core holds now, counted after this pass.
    live: usize,
    /// Pairs this pass filed that the table did not carry.
    filed: usize,
    /// Pairs this pass brought back that the table was carrying retired.
    revived: usize,
    /// Entries this pass retired because a slot no longer described them.
    retired: usize,
    /// Reports the table did not take: no room for one, or one naming a slot the
    /// core does not have.
    refused: usize,
    /// Entries a newly filed pair displaced to make room.
    evicted: usize,
};

/// Every path one connection has had, bounded by `max_paths`.
///
/// Inline storage and no allocator, so a whole table is a value a test holds on
/// the stack and a `Table` copied into another is independent of the original.
/// Entries past `len` are never written and never read, so a default `Table` is
/// a valid empty table and not a broken one — read it through `slice` rather
/// than by indexing.
pub const Table = struct {
    /// The core's own id for the connection last mirrored: `Conn.id()`, which is
    /// `ConnEntry.id`, "unique per manager, never reused". Zero until the first
    /// `mirror`. A table mints no connection id and there is nowhere else for one
    /// to come from.
    conn: u64 = 0,
    entries: [max_paths]Entry = undefined,
    /// How many entries are held, live and retired together. Never above
    /// `entries.len`.
    len: usize = 0,

    /// Every entry, retired ones included, for a caller reading what the
    /// connection has had: exactly `entries[0..len]`.
    ///
    /// The order is filing order except after `forget` and after a displacement,
    /// both of which move the last entry into the gap. Nothing depends on it.
    pub fn slice(self: *const Table) []const Entry {
        return self.entries[0..self.len];
    }

    /// How many of `slice` the core holds right now. At most `core_slots`.
    pub fn live(self: *const Table) usize {
        var held: usize = 0;
        for (self.slice()) |entry| {
            if (entry.live()) held += 1;
        }
        return held;
    }

    /// The entry for `key`, by value, or null when the table does not hold the
    /// pair — which is not the same as saying it is not in `slice`. A retired
    /// pair is still there, with its history, and is not a path.
    pub fn get(self: *const Table, key: Key) ?Entry {
        const index = self.indexOf(key) orelse return null;
        return self.entries[index];
    }

    /// Fold one path the core reported into the table, at `at`.
    ///
    /// The whole of the write, and a pure function of `self`, `key`, `report`
    /// and `at`: no clock, no allocator, no socket. `mirror` is two calls to this
    /// and is named for the fact that the core's half of it is two slots.
    ///
    /// Whatever else the named slot described is retired first, so a caller
    /// cannot file a path and leave the previous occupant of its slot still
    /// claiming to be live — and so a report the table then refuses still leaves
    /// the table agreeing with the core about what that slot holds.
    ///
    /// A pair the table already carries keeps its `since` and its sample and has
    /// its figures and its validation replaced. A pair coming back after having
    /// gone is `.revived`: its history is real and its slot is claimed again, and
    /// its figures are the core's fresh ones, which the core zeroes when it
    /// writes a slot for a new path.
    pub fn observe(self: *Table, key: Key, report: Report, at: Instant) Applied {
        if (@as(usize, report.slot) >= core_slots) {
            return .{ .outcome = .foreign_slot, .retired = 0, .evicted = null };
        }
        const retired = self.retire(report.slot, key, at);
        if (self.find(key)) |held| {
            const was_live = held.live();
            held.validation = advance(held.validation, report.validated, report.state);
            held.tx_bytes = report.sent;
            held.rx_bytes = report.received;
            held.slot = report.slot;
            held.retired_at = null;
            return .{
                .outcome = if (was_live) .kept else .revived,
                .retired = retired,
                .evicted = null,
            };
        }
        const evicted: ?Key = switch (self.takeSlot()) {
            .free => null,
            .evicted => |gone| gone,
            .full => return .{ .outcome = .refused, .retired = retired, .evicted = null },
        };
        self.entries[self.len] = .{
            .key = key,
            .validation = advance(.unvalidated, report.validated, report.state),
            .since = at,
            .tx_bytes = report.sent,
            .rx_bytes = report.received,
            .slot = report.slot,
        };
        self.len += 1;
        return .{ .outcome = .filed, .retired = retired, .evicted = evicted };
    }

    /// Take out of the running every entry the core's slot `slot` no longer
    /// describes, and answer how many left.
    ///
    /// `keep` is the pair the slot now holds, or null when the core left the
    /// slot with no address — `NetworkPath` starts `.unset` on both, which is
    /// how a candidate nobody has proposed is spelled. A retired entry keeps its
    /// addresses, its figures, its sample and the instant it was filed; only
    /// `slot` and `retired_at` move.
    ///
    /// `observe` calls this, so a caller never has to. It is `pub` because
    /// `mirror` needs the count, and because a caller may want it on its own when
    /// the core dropped a slot rather than moved one.
    pub fn retire(self: *Table, slot: u8, keep: ?Key, at: Instant) usize {
        var left: usize = 0;
        for (self.entries[0..self.len]) |*held| {
            const claimed = held.slot orelse continue;
            if (claimed != slot) continue;
            if (keep) |wanted| {
                if (held.key.eql(wanted)) continue;
            }
            held.slot = null;
            held.retired_at = at;
            left += 1;
        }
        return left;
    }

    /// Record a round trip measured on `key` at `at`. False for a pair the table
    /// does not hold live.
    ///
    /// Refused for a retired pair as well as an unknown one: a measurement of a
    /// path the core has left would have to be attributed to something else, and
    /// the figure would then be a round trip nobody measured.
    pub fn sample(self: *Table, key: Key, rtt: Nanos, at: Instant) bool {
        const held = self.find(key) orelse return false;
        if (!held.live()) return false;
        held.rtt = rtt;
        held.rtt_at = at;
        return true;
    }

    /// Stamp `key` as carrying at `at`. False for a pair the table does not hold
    /// live.
    ///
    /// No byte counts: those are the core's own and `observe` is how they
    /// arrive, so one field has one writer. This is the stamp the core does not
    /// keep — `last_active` is when bytes moved, and the core counts bytes
    /// without saying when.
    pub fn used(self: *Table, key: Key, at: Instant) bool {
        const held = self.find(key) orelse return false;
        if (!held.live()) return false;
        held.last_active = at;
        return true;
    }

    /// Drop `key` and answer whether it was there.
    ///
    /// The last entry moves into the gap, so `len` holds and the order `slice`
    /// reports is no longer the order it had. This is the only operation that
    /// removes an entry outright, and it is not the mirror's decision to make:
    /// `DECISIONS/0001` measures what a migration throws away, so the table that
    /// records it keeps the history rather than deciding to lose it. A caller
    /// pruning for its own reasons calls this.
    pub fn forget(self: *Table, key: Key) bool {
        const index = self.indexOf(key) orelse return false;
        self.entries[index] = self.entries[self.len - 1];
        self.len -= 1;
        return true;
    }

    /// Where `key` is, or null. A scan, for `net/path_table.zig`'s reason: the
    /// table is `max_paths` entries and the walk is bounded by the storage it
    /// walks.
    fn find(self: *Table, key: Key) ?*Entry {
        const index = self.indexOf(key) orelse return null;
        return &self.entries[index];
    }

    fn indexOf(self: *const Table, key: Key) ?usize {
        var index: usize = 0;
        while (index < self.len) : (index += 1) {
            if (self.entries[index].key.eql(key)) return index;
        }
        return null;
    }

    /// A slot to write into, or the reason there is none.
    ///
    /// The eviction scan takes the last `.failed` entry, and `.failed` is the
    /// only validation state here that is a recorded failure, which is the same
    /// rule and the same reason `net/path_table.zig` displaces an `.unusable`
    /// path and nothing else. The key comes back in `Applied.evicted`, so which
    /// one it was is reported rather than chosen silently.
    fn takeSlot(self: *Table) Slot {
        if (self.len < self.entries.len) return .free;
        var victim: ?usize = null;
        var index: usize = 0;
        while (index < self.len) : (index += 1) {
            if (self.entries[index].validation == .failed) victim = index;
        }
        const at = victim orelse return .full;
        const gone = self.entries[at].key;
        self.entries[at] = self.entries[self.len - 1];
        self.len -= 1;
        return .{ .evicted = gone };
    }

    /// Fold the core's active path into the table, at `at`.
    ///
    /// The whole of this file's read of the core, and the reason the rest of it
    /// is pure: everything the core knows about a connection's paths is on
    /// `conn.entry.conn`, and this is the one function that reads it.
    ///
    /// **Only the slot the core names active is read, and that is every slot
    /// the core writes.** `acceptInto` builds the array as
    /// `.{ initial_path, undefined }` (`:1537`) — the second slot holds *no*
    /// `NetworkPath` at all, not an empty one — and every later write targets
    /// the slot that is, or is about to become, active: `handleDatagram` writes
    /// `paths[active_path_idx]` (`:2251`), and both migration arms write
    /// `paths[candidate_idx]` and promote it on the next line (`:3443`/`:3450`,
    /// `:4246`/`:4255`). So the core holds one path it is using and one it left
    /// behind, and the left-behind one cannot change until it is active again.
    /// This table therefore carries that second pair forward from the pass that
    /// saw it active — which is what the core still holds — rather than reading
    /// it a second time out of a slot that may hold no value at all. A core
    /// that wrote a slot while it was *not* active would break that reasoning,
    /// and the write sites named above are where to look first.
    ///
    /// A slot the core left with no address is not a path and retires whatever
    /// that slot held. A slot the core holds for a pair the table does not have
    /// files it, displacing a `.failed` entry or being refused; `Mirror` says
    /// which, because a pass that quietly dropped a path would leave a caller
    /// believing the connection has fewer than it does.
    ///
    /// A second call over an unmoved connection is `.kept` and changes no
    /// figure, so a caller may mirror on every turn.
    pub fn mirror(self: *Table, conn: Conn, at: Instant) Mirror {
        var result: Mirror = .{
            .live = 0,
            .filed = 0,
            .revived = 0,
            .retired = 0,
            .refused = 0,
            .evicted = 0,
        };
        self.conn = conn.id();
        const core = conn.entry.conn;
        const slot: u8 = core.active_path_idx;
        // The core cannot disagree with itself about which slot is active, and
        // `paths` is `core_slots` long, so this refuses only an index the core
        // would index out of its own array. Nothing is read and nothing is
        // retired: a pass that took a path from an index that is not a path
        // would hand the caller a figure it did not get.
        if (@as(usize, slot) >= core_slots) {
            result.refused += 1;
        } else {
            const core_path: *const CorePath = &core.paths[@as(usize, slot)];
            if (pairOf(core_path)) |key| {
                const applied = self.observe(key, reportOf(core_path, slot), at);
                result.retired += applied.retired;
                if (applied.evicted != null) result.evicted += 1;
                switch (applied.outcome) {
                    .kept => {},
                    .filed => result.filed += 1,
                    .revived => result.revived += 1,
                    // A foreign slot is the core disagreeing with itself, which
                    // it cannot do; it is counted with a refusal because the
                    // effect on this table is the same — the report was not
                    // taken.
                    .refused, .foreign_slot => result.refused += 1,
                }
            } else {
                result.retired += self.retire(slot, null, at);
            }
        }
        result.live = self.live();
        return result;
    }
};

/// The pair a core path names, or null for a slot the core has not been given an
/// address for.
///
/// Either address unset is null, not a half-path: `NetworkPath.init` copies both
/// and `Connection.connectInto` leaves both unset until the first datagram
/// (`:2251`), so a path with one address and no other is a value no caller could
/// send on — and `Egress` carries one address, so half a path has nothing to hand
/// the socket.
///
/// **The slot must be one the core has written.** `acceptInto` puts `undefined`
/// in the array's second element (`:1537`), so that slot's `local_addr` and
/// `peer_addr` are not an `Address` at all, and switching on one reads a value
/// that was never made. `mirror` reads the slot the core names active and no
/// other; that is the precondition assumed here, and this is what breaks first.
fn pairOf(slot: *const CorePath) ?Key {
    const local = fromCoreAddress(&slot.local_addr) orelse return null;
    const peer = fromCoreAddress(&slot.peer_addr) orelse return null;
    return .{ .local = local, .peer = peer };
}

/// A core path as a `Report`, which is the whole of this file's reading of it.
fn reportOf(slot: *const CorePath, slot_index: u8) Report {
    return .{
        .slot = slot_index,
        .validated = slot.is_validated,
        .state = slot.validator.state,
        .sent = slot.bytes_sent,
        .received = slot.bytes_received,
    };
}

// --- tests

const t = std.testing;
const base_key = @import("../base/key.zig");
const base_ula = @import("../base/ula.zig");
const addr_map = @import("addr_map.zig");
const bridge_manager = @import("bridge_manager.zig");
const peer_mod = @import("bridge_peer.zig");

const Bridge = bridge_manager.Bridge;
const SecretKey = base_key.SecretKey;

const alpn = peer_mod.alpn;
const client_addr = peer_mod.client_addr;
const server_addr = peer_mod.server_addr;
const start = peer_mod.start;
const Prng = peer_mod.Prng;
const max_datagram = peer_mod.max_datagram;
const Client = peer_mod.Client;
const exchange = peer_mod.exchange;

/// The path a freshly accepted connection runs on: this node at `server_addr`,
/// the peer at `client_addr`. Named because every mirror assertion below reads
/// the pair rather than either address alone.
fn directKey() Key {
    return .{ .local = server_addr, .peer = client_addr };
}

/// A second peer address on the same IP and a different port — a NAT rebinding,
/// and the one migration for which the core carries validation over.
fn reboundKey() Key {
    return .{ .local = server_addr, .peer = .{ .ip = client_addr.ip, .port = 4444 } };
}

/// A peer address on another subnet, so the migration is an IP change and the
/// core discards its congestion, RTT, MTU and ECN state.
fn otherSubnetKey() Key {
    return .{
        .local = server_addr,
        .peer = base_ula.socketAddrFor(.custom, .{ 1, 1, 1, 1, 1, 1, 1, 1 }),
    };
}

/// A documentation-range IPv4 peer address on `port`, for a report no handshake
/// is behind.
fn v4Key(port: u16) Key {
    return .{ .local = server_addr, .peer = .{ .ip = .{ .v4 = .{ 192, 0, 2, 1 } }, .port = port } };
}

/// A report as the core would build it for a path in `slot`, with both counters
/// at zero because a report is about the path, not about the traffic on it.
fn bareReport(slot: u8, validated: bool, state: CoreValidation) Report {
    return .{ .slot = slot, .validated = validated, .state = state, .sent = 0, .received = 0 };
}

/// Whether two keys name the same one, with null handling, so an assertion can
/// name what an operation displaced without naming it twice.
fn sameKey(left: ?Key, right: ?Key) bool {
    const one = left orelse return right == null;
    const other = right orelse return false;
    return one.eql(other);
}

/// One accepted connection and the peer half of the handshake it came from, so a
/// mirror test runs against a live core rather than a hand-built one.
const Rig = struct {
    server: SecretKey,
    bridge: *Bridge,
    map: addr_map.MappedAddrs,
    client: Client,

    fn init(client_seed: u64, engine_seed: u64) !Rig {
        var server = try SecretKey.fromSeed(peer_mod.server_seed);
        errdefer server.deinit();
        var peer = try SecretKey.fromSeed(peer_mod.client_seed);
        defer peer.deinit();
        var engine = Prng.init(engine_seed);
        const bridge = try Bridge.create(t.allocator, t.io, .{
            .secret = server,
            .expect_peer = peer.nodeId(),
            .alpn = alpn,
        }, engine.random());
        errdefer bridge.destroy();
        var map = addr_map.MappedAddrs.init();
        errdefer map.deinit(t.allocator);
        var client: Client = undefined;
        try client.init(peer, server.nodeId(), client_seed, start);
        errdefer client.deinit();
        try exchange(&client, bridge, &map, start);
        return .{ .server = server, .bridge = bridge, .map = map, .client = client };
    }

    fn deinit(self: *Rig) void {
        self.client.deinit();
        self.map.deinit(t.allocator);
        self.bridge.destroy();
        self.server.deinit();
        self.* = undefined;
    }

    /// The one connection this rig holds.
    fn conn(self: *Rig) !Conn {
        return self.bridge.connectionAt(0) orelse error.TestUnexpectedResult;
    }

    /// Hand the client one 1-RTT datagram claiming to have come from `from`.
    ///
    /// The bytes are the client's own and the core decrypts them the same way it
    /// decrypts any other — the addresses are not part of packet protection — so
    /// the only thing this call changes is what the core believes about where
    /// they came from. An address the connection has never heard of is exactly
    /// what RFC 9000 §9 migration is.
    fn clientSaysFrom(self: *Rig, from: SocketAddr) !void {
        var scratch: [2 * max_datagram]u8 = undefined;
        const stream = try self.client.conn.openStream();
        try stream.send.writeData("the frames that make this a non-probing packet");
        stream.send.close();
        var rounds: usize = 0;
        while (rounds < 8) : (rounds += 1) {
            const len = self.client.conn.sendAt(
                &self.client.buffer,
                start,
                self.client.random(),
            ) catch break;
            if (len == 0) break;
            _ = try self.bridge.recv(&self.map, .{
                .bytes = self.client.buffer[0..len],
                .from = from,
                .local = server_addr,
                .ecn = null,
            }, scratch[0..], start, self.client.random());
        }
    }
};

test "a path is its two addresses and the connection is the core's own id" {
    // The pair is ordered: a path from A to B is not the path from B to A, and a
    // table that could not tell them apart would hold a loop as a path.
    const forward: Key = .{ .local = server_addr, .peer = client_addr };
    const backward: Key = .{ .local = client_addr, .peer = server_addr };
    try t.expect(forward.eql(directKey()));
    try t.expect(!forward.eql(backward));
    try t.expect(!forward.eql(reboundKey()));
    try t.expect(!forward.eql(otherSubnetKey()));

    var rig = try Rig.init(2, 1);
    defer rig.deinit();
    const conn = try rig.conn();
    try t.expect(conn.established());

    var table: Table = .{};
    const first = table.mirror(conn, start);
    // One accepted connection, one path. The core's second slot is `undefined`,
    // not `.unset` (`acceptInto`, `:1537`): it holds no `NetworkPath` at all, so
    // it is a candidate nobody proposed *and* a slot this table may not read.
    // `mirror` reads the one slot the core names active, and a second read of
    // the candidate is what the three aborting tests were doing.
    try t.expectEqual(@as(usize, 1), first.live);
    try t.expectEqual(@as(usize, 1), first.filed);
    try t.expectEqual(@as(usize, 0), first.retired);
    try t.expectEqual(@as(usize, 0), first.refused);
    try t.expectEqual(@as(usize, 0), first.evicted);
    try t.expectEqual(@as(usize, 1), table.live());

    // The identity is the core's pair, read through the bridge's own address
    // translation rather than spelled a second time here.
    try t.expectEqual(client_addr, conn.peer().?);
    try t.expectEqual(server_addr, conn.local().?);
    const entry = table.get(directKey()).?;
    try t.expect(entry.key.eql(directKey()));
    try t.expectEqual(@as(?u8, 0), entry.slot);
    try t.expect(entry.live());
    try t.expectEqual(start, entry.since);
    try t.expectEqual(@as(?Instant, null), entry.last_active);

    // The connection is named by the core, not by a counter here.
    try t.expectEqual(conn.id(), table.conn);

    // A handshake completed, so both ends proved the addresses: the client
    // lifted its amplification limit at `connection.zig:3281`, and this table
    // read that rather than assuming it.
    try t.expectEqual(Validation.validated, entry.validation);
    try t.expect(entry.tx_bytes > 0);
    try t.expect(entry.rx_bytes > 0);

    // And the second pass over an unmoved connection is the same answer, so a
    // caller may mirror on every turn.
    const again = table.mirror(conn, start);
    try t.expectEqual(@as(usize, 1), again.live);
    try t.expectEqual(@as(usize, 0), again.filed);
    try t.expectEqual(@as(usize, 0), again.retired);
    try t.expectEqual(@as(usize, 1), table.slice().len);
    try t.expectEqual(entry.tx_bytes, table.get(directKey()).?.tx_bytes);
    try t.expectEqual(entry.since, table.get(directKey()).?.since);
}

test "every combination of the core's two validation fields folds to one state" {
    // The flag wins over the state, because `NetworkPath.canSend` (`:231`) reads
    // only the flag. The pair that proves it is not hypothetical: a port-only
    // migration challenges the fresh path (`:4258`) and marks it validated
    // (`:4275`), so the core really does hold `true` beside `.pending`.
    try t.expectEqual(Validation.validated, advance(.unvalidated, true, .pending));
    try t.expectEqual(Validation.validated, advance(.unvalidated, true, .idle));
    try t.expectEqual(Validation.validated, advance(.unvalidated, true, .failed));

    // With the flag clear, the validator's own four states are the answer, and
    // this file's `.challenging` is the core's `.pending`.
    try t.expectEqual(Validation.unvalidated, advance(.unvalidated, false, .idle));
    try t.expectEqual(Validation.challenging, advance(.unvalidated, false, .pending));
    try t.expectEqual(Validation.validated, advance(.unvalidated, false, .validated));
    try t.expectEqual(Validation.failed, advance(.unvalidated, false, .failed));

    // Nothing demotes a validated path, in either direction. The core cannot
    // report one of these combinations — `is_validated` is assigned true five
    // times and false never — so this is the mirror refusing to act on a fact,
    // not a case the core produces.
    for ([_]CoreValidation{ .idle, .pending, .validated, .failed }) |state| {
        for ([_]bool{ false, true }) |flag| {
            try t.expectEqual(Validation.validated, advance(.validated, flag, state));
        }
    }
    // And the other three still move among themselves, so the guard is not a
    // field that has stopped changing.
    try t.expectEqual(Validation.failed, advance(.challenging, false, .failed));
    try t.expectEqual(Validation.unvalidated, advance(.failed, false, .idle));
    try t.expectEqual(Validation.challenging, advance(.unvalidated, false, .pending));
}

test "a migration fills the second slot, retires what the next overwrites, revives the way back" {
    var rig = try Rig.init(6, 3);
    defer rig.deinit();
    const conn = try rig.conn();
    var table: Table = .{};
    _ = table.mirror(conn, start);
    try t.expectEqual(@as(usize, 1), table.live());

    // First migration: the peer rebinds to a second port on the same address.
    // `handleMigration` writes the *candidate* slot (`:4246`) and promotes it
    // (`:4255`), and the slot the connection started on still holds the address
    // it started on — so the core now holds two paths and this table says so
    // rather than reporting a switch as a loss.
    try rig.clientSaysFrom(reboundKey().peer);
    const first = table.mirror(conn, start);
    try t.expectEqual(@as(usize, 2), first.live);
    try t.expectEqual(@as(usize, 1), first.filed);
    try t.expectEqual(@as(usize, 0), first.retired);
    try t.expectEqual(@as(usize, 0), first.revived);

    const started = table.get(directKey()).?;
    try t.expect(started.live());
    try t.expectEqual(@as(?u8, 0), started.slot);
    try t.expect(started.tx_bytes > 0);

    const rebound = table.get(reboundKey()).?;
    try t.expect(rebound.live());
    try t.expectEqual(@as(?u8, 1), rebound.slot);
    // Same IP, so the core carries validation over (`:4275`) and this table
    // reports that rather than inferring it: a NAT rebinding is not a new
    // address to prove.
    try t.expectEqual(Validation.validated, rebound.validation);
    // A fresh slot starts with the core's counters at zero, and those counters
    // are the core's, so no figure from the path this one sits beside rides
    // along on it. What did arrive is the datagram that triggered the switch,
    // which the core credits to both (`:2146`, `:2264`).
    try t.expectEqual(@as(u64, 0), rebound.tx_bytes);
    try t.expect(rebound.rx_bytes > 0);

    // Second migration: the peer moves to another subnet, so the IP changed. The
    // candidate slot is now the one the connection started on, and writing it is
    // what retires the first path — which is the only way a path leaves this
    // table's running.
    try rig.clientSaysFrom(otherSubnetKey().peer);
    const second = table.mirror(conn, start);
    try t.expectEqual(@as(usize, 2), second.live);
    try t.expectEqual(@as(usize, 1), second.filed);
    try t.expectEqual(@as(usize, 1), second.retired);

    const gone = table.get(directKey()).?;
    try t.expect(!gone.live());
    try t.expectEqual(@as(?u8, null), gone.slot);
    try t.expectEqual(start, gone.retired_at.?);
    // A retired path keeps what it was: the addresses, the figures, the filing
    // instant. `DECISIONS/0001`'s measurement of what a migration throws away is
    // only legible if the table remembers what was thrown.
    try t.expect(gone.key.eql(directKey()));
    try t.expect(gone.tx_bytes > 0);
    try t.expectEqual(Validation.validated, gone.validation);

    // The core discards its congestion, RTT, MTU and ECN state on an IP change
    // (`:4265-4270`), so the path it arrives on is unvalidated with a challenge
    // outstanding, and the rebound path is still live beside it.
    try t.expectEqual(Validation.challenging, table.get(otherSubnetKey()).?.validation);
    try t.expect(table.get(otherSubnetKey()).?.live());
    try t.expect(table.get(reboundKey()).?.live());
    try t.expectEqual(@as(usize, 2), table.live());

    // Third migration, back to the address the connection started on. The
    // candidate slot is the one holding the rebound path, so that path leaves the
    // running and the first one comes back — a revival, not a second entry.
    try rig.clientSaysFrom(client_addr);
    const third = table.mirror(conn, start);
    try t.expectEqual(@as(usize, 2), third.live);
    try t.expectEqual(@as(usize, 0), third.filed);
    try t.expectEqual(@as(usize, 1), third.revived);
    try t.expectEqual(@as(usize, 1), third.retired);

    const returned = table.get(directKey()).?;
    try t.expect(returned.live());
    // Its history is real and its `since` is still the first time the table filed
    // it, because a path returning is one path returning rather than a new one.
    try t.expectEqual(start, returned.since);
    try t.expectEqual(@as(u64, 0), returned.tx_bytes);
    try t.expect(!table.get(reboundKey()).?.live());
    try t.expect(table.get(otherSubnetKey()).?.live());
    // Three pairs, three entries: a returning path was refiled, not duplicated.
    try t.expectEqual(@as(usize, 3), table.slice().len);
    // And the table agrees with the core about which slot is active.
    try t.expectEqual(conn.entry.conn.active_path_idx, returned.slot.?);
}

test "a round trip is the caller's, and it stops being believed when it is stale" {
    var rig = try Rig.init(8, 5);
    defer rig.deinit();
    const conn = try rig.conn();
    var table: Table = .{};
    _ = table.mirror(conn, start);

    // The core holds one RTT per connection and no per-path figure at all, so the
    // number here is one this project measured on this pair.
    const rtt: Nanos = 20 * std.time.ns_per_ms;
    const age: Instant = @intCast(rtt_max_age);
    try t.expect(table.sample(directKey(), rtt, start));
    const entry = table.get(directKey()).?;
    try t.expectEqual(@as(?Nanos, rtt), entry.latency(start));
    try t.expectEqual(@as(?Nanos, rtt), entry.latency(start + age));
    try t.expectEqual(@as(?Nanos, null), entry.latency(start + age + 1));
    // Still in the entry, and simply no longer an answer.
    try t.expectEqual(@as(?Nanos, rtt), entry.rtt);
    // A sample stamped after the instant asked about is not stale.
    try t.expectEqual(@as(?Nanos, rtt), entry.latency(start - age));

    // `used` stamps liveness and nothing else: the byte counts are the core's and
    // arrive through `observe`, so one field has one writer.
    try t.expect(table.used(directKey(), start + 1));
    try t.expectEqual(@as(?Instant, start + 1), table.get(directKey()).?.last_active.?);
    const before = table.get(directKey()).?.tx_bytes;
    try t.expect(table.used(directKey(), start + 2));
    try t.expectEqual(before, table.get(directKey()).?.tx_bytes);

    // A pair this connection has never been told about is refused both ways: a
    // measurement of it would be a round trip nobody measured.
    try t.expect(!table.sample(reboundKey(), rtt, start));
    try t.expect(!table.used(reboundKey(), start));
    try t.expect(table.get(reboundKey()) == null);
    try t.expectEqual(@as(usize, 1), table.slice().len);

    // And a retired pair is refused too, which is the rule the migration test
    // earns its right to: the path is still in the table and is not a path.
    // Two migrations, because the first one fills the core's second slot and
    // leaves the first path live beside it.
    try rig.clientSaysFrom(reboundKey().peer);
    try rig.clientSaysFrom(otherSubnetKey().peer);
    _ = table.mirror(conn, start);
    try t.expect(table.get(directKey()) != null);
    try t.expect(!table.get(directKey()).?.live());
    try t.expect(!table.sample(directKey(), rtt, start));
    try t.expect(!table.used(directKey(), start));
    // The refusals changed nothing, and a retired path keeps its sample and
    // its stamp: `retire` moves `slot` and `retired_at` and nothing else, and
    // a figure dropped with the path would be a figure nobody could check the
    // migration against. These two read as `null` in the shape a reader
    // expects, but the values were recorded before the path retired, and a
    // retired entry is not a blank one.
    try t.expectEqual(@as(?Nanos, rtt), table.get(directKey()).?.rtt);
    try t.expectEqual(@as(?Instant, start + 2), table.get(directKey()).?.last_active.?);
}

test "at the bound the table refuses a report and only a failure may be displaced" {
    var full: Table = .{};
    // Eight pairs through the core's two slots, alternating, which is what a
    // migrating peer makes this table look like: the two the core holds now and
    // the history of the six it wrote over. All eight are proved, so none of
    // them is disposable.
    var keys: [max_paths]Key = undefined;
    for (0..max_paths) |index| {
        keys[index] = v4Key(@intCast(1000 + index));
        _ = full.observe(keys[index], bareReport(@intCast(index % 2), true, .idle), start);
    }
    try t.expectEqual(@as(usize, 8), max_paths);
    try t.expectEqual(@as(usize, 8), full.slice().len);
    // Only the last report on each slot is still live, and the core has two.
    try t.expectEqual(@as(usize, 2), full.live());
    try t.expectEqual(@as(usize, 2), core_slots);

    // The ninth pair: nothing here may be displaced, and the slot the report
    // names is emptied of its occupant either way, because the core moved that
    // slot whatever this table did with what moved into it.
    const ninth = v4Key(2000);
    const refused = full.observe(ninth, bareReport(0, true, .idle), start + 1);
    try t.expectEqual(Outcome.refused, refused.outcome);
    try t.expectEqual(@as(usize, 1), refused.retired);
    try t.expect(sameKey(refused.evicted, null));
    try t.expectEqual(@as(usize, 8), full.slice().len);
    try t.expect(full.get(ninth) == null);
    try t.expectEqual(@as(usize, 1), full.live());
    // Nothing was displaced, so all eight are still here at the pairs they were
    // filed with.
    for (keys) |key| try t.expect(full.get(key) != null);

    // A report naming a slot the core does not have is refused too, and moves
    // nothing: `paths` is `[2]NetworkPath` and index 2 is not a path.
    const phantom = v4Key(2001);
    const outside = full.observe(
        phantom,
        bareReport(@intCast(core_slots), true, .idle),
        start + 2,
    );
    try t.expectEqual(Outcome.foreign_slot, outside.outcome);
    try t.expectEqual(@as(usize, 0), outside.retired);
    try t.expect(full.get(phantom) == null);
    try t.expectEqual(@as(usize, 8), full.slice().len);

    // The one disposable entry: a path whose challenge was spent and never
    // answered is a recorded failure, and freeing its slot sheds nothing a
    // caller is relying on. A table holding one of those is not full of them.
    var table: Table = .{};
    var doomed: Key = undefined;
    for (0..max_paths) |index| {
        const key = v4Key(@intCast(3000 + index));
        const failed = index == 1;
        if (failed) doomed = key;
        const state: CoreValidation = if (failed) .failed else .idle;
        _ = table.observe(key, bareReport(@intCast(index % 2), !failed, state), start);
    }
    try t.expectEqual(@as(usize, 8), table.slice().len);
    try t.expectEqual(Validation.failed, table.get(doomed).?.validation);

    const applied = table.observe(ninth, bareReport(1, true, .idle), start + 3);
    try t.expectEqual(Outcome.filed, applied.outcome);
    try t.expect(sameKey(applied.evicted, doomed));
    try t.expectEqual(@as(usize, 8), table.slice().len);
    try t.expect(table.get(doomed) == null);
    try t.expect(table.get(ninth).?.live());

    // `forget` is the caller's decision to lose history, and it is the only
    // operation that removes an entry outright.
    try t.expect(table.forget(ninth));
    try t.expect(table.get(ninth) == null);
    try t.expectEqual(@as(usize, 7), table.slice().len);
    try t.expect(!table.forget(ninth));
}
