//! Historical observations and actuators for the two supported native paths.
//! The eight-entry mirror retains retired address-pair history; it is not an
//! eight-path transport capability. Initialized slots are read through the
//! bridge snapshot API, never by inspecting an undefined native array element.
//! Policy lives in net/path_action.zig. Time and randomness are lifted into the
//! actuator, and planned slot IDs are rechecked against their address pairs.

const std = @import("std");
const quic = @import("quic");
const base_addr = @import("../base/addr.zig");
const path_action = @import("../net/path_action.zig");
const bridge_config = @import("bridge_config.zig");
const bridge_conn = @import("bridge_conn.zig");

const SocketAddr = base_addr.SocketAddr;
const Conn = bridge_conn.Conn;

pub const ActionError = bridge_conn.PathError || error{StalePath};

/// Copies only initialized bridge snapshots; there is no native-array read.
pub fn actionSlots(conn: Conn) path_action.Slots {
    var slots: path_action.Slots = .{ null, null };
    for (0..core_slots) |index| {
        const snapshot = conn.pathSnapshot(@intCast(index)) orelse continue;
        const local = snapshot.local orelse continue;
        const peer = snapshot.peer orelse continue;
        slots[index] = .{
            .key = .{ .local = local, .peer = peer },
            .validated = snapshot.validated,
            .selected = snapshot.selected,
            .probing = snapshot.state == .pending,
        };
    }
    return slots;
}

/// Applies one bounded policy action. The caller owns the candidate provenance,
/// connection lifetime, clock and random source; none are acquired here.
pub fn applyAction(
    conn: Conn,
    action: path_action.Action,
    at: Instant,
    random: std.Random,
) ActionError!?u8 {
    switch (action) {
        .none => return null,
        .open => |key| return try conn.openPath(key.local, key.peer, at, random),
        .probe, .select, .revalidate => |target| {
            const slots = actionSlots(conn);
            if (!path_action.matches(target, &slots)) return error.StalePath;
            switch (action) {
                .select => {
                    if (path_action.planSelect(target.key, &slots) == .none) return null;
                    try conn.selectPath(target.id);
                },
                .probe, .revalidate => {
                    if (path_action.planProbe(target.key, &slots) == .none) return null;
                    try conn.probePath(target.id, at, random);
                },
                .none, .open => unreachable,
            }
            return null;
        },
    }
}

/// The instant the core is driven at, on the core's own timeline: `i64`
/// nanoseconds, and the same type `Conn.drain` and `Bridge.recv` take. Named
/// here rather than restated as a local alias so a caller naming an instant for
/// a path and an instant for a connection has one clock and not two.
pub const Instant = bridge_config.Instant;

/// A duration on that timeline — a round trip, or a maximum age for one.
pub const Nanos = u64;

/// Historical mirror capacity, including retired pairs. Full history refuses
/// new entries unless a recorded failure can be displaced.
pub const max_paths: usize = 8;

/// Actual supported native capability, separate from historical capacity.
pub const core_slots: usize = path_action.supported_paths;

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

pub const Observation = struct { key: Key, report: Report };
pub const Observations = [core_slots]?Observation;

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
    /// Caller-measured round trip on this pair, separate from the core's
    /// congestion-control estimator.
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

    /// Snapshot every initialized slot, including a non-selected candidate.
    pub fn mirror(self: *Table, conn: Conn, at: Instant) Mirror {
        // Only the bridge can distinguish an unopened slot from an address.
        self.conn = conn.id();
        var observations: Observations = .{ null, null };
        for (0..core_slots) |index| {
            const id: u8 = @intCast(index);
            const snapshot = conn.pathSnapshot(id) orelse continue;
            const local = snapshot.local orelse continue;
            const peer = snapshot.peer orelse continue;
            observations[index] = .{
                .key = .{ .local = local, .peer = peer },
                .report = .{
                    .slot = id,
                    .validated = snapshot.validated,
                    .state = snapshot.state,
                    .sent = snapshot.sent,
                    .received = snapshot.received,
                },
            };
        }
        return self.mirrorObservations(&observations, at);
    }

    /// Pure snapshot fold. A null slot retires its previous address pair.
    pub fn mirrorObservations(self: *Table, observations: *const Observations, at: Instant) Mirror {
        var result: Mirror = .{
            .live = 0, .filed = 0, .revived = 0, .retired = 0, .refused = 0, .evicted = 0,
        };
        for (observations, 0..) |observation, index| {
            const slot: u8 = @intCast(index);
            const path = observation orelse {
                result.retired += self.retire(slot, null, at);
                continue;
            };
            var report = path.report;
            report.slot = slot;
            const applied = self.observe(path.key, report, at);
            result.retired += applied.retired;
            if (applied.evicted != null) result.evicted += 1;
            switch (applied.outcome) {
                .kept => {},
                .filed => result.filed += 1,
                .revived => result.revived += 1,
                .refused, .foreign_slot => result.refused += 1,
            }
        }
        result.live = self.live();
        return result;
    }
};


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
    // The unopened slot is absent from the bridge snapshot; it is never read.
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

test "historical snapshots retire missing pairs and revive history without duplication" {
    // Synthetic observations exercise retained history, not native path admission.
    var table: Table = .{};
    const initial: Observations = .{
        .{ .key = directKey(), .report = bareReport(0, true, .idle) },
        null,
    };
    _ = table.mirrorObservations(&initial, start);
    const next: Observations = .{
        initial[0],
        .{ .key = reboundKey(), .report = bareReport(1, false, .pending) },
    };
    const added = table.mirrorObservations(&next, start + 1);
    try t.expectEqual(@as(usize, 2), added.live);
    try t.expectEqual(@as(usize, 1), added.filed);
    try t.expectEqual(@as(usize, 0), added.retired);
    try t.expectEqual(Validation.challenging, table.get(reboundKey()).?.validation);

    const remaining: Observations = .{ null, next[1] };
    const retired = table.mirrorObservations(&remaining, start + 2);
    try t.expectEqual(@as(usize, 1), retired.live);
    try t.expectEqual(@as(usize, 1), retired.retired);
    const gone = table.get(directKey()).?;
    try t.expect(!gone.live());
    try t.expectEqual(@as(?u8, null), gone.slot);
    try t.expectEqual(@as(?Instant, start + 2), gone.retired_at);

    const returned = table.mirrorObservations(&next, start + 3);
    try t.expectEqual(@as(usize, 2), returned.live);
    try t.expectEqual(@as(usize, 0), returned.filed);
    try t.expectEqual(@as(usize, 1), returned.revived);
    try t.expectEqual(@as(usize, 0), returned.retired);
    try t.expectEqual(@as(usize, 2), table.slice().len);
    try t.expectEqual(start, table.get(directKey()).?.since);
    try t.expectEqual(@as(?Instant, null), table.get(directKey()).?.retired_at);
}

test "a round trip is the caller's, and it stops being believed when it is stale" {
    var rig = try Rig.init(8, 5);
    defer rig.deinit();
    const conn = try rig.conn();
    var table: Table = .{};
    _ = table.mirror(conn, start);

    // This sample is supplied by the caller rather than a congestion estimator.
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

    // A missing snapshot retires the measured pair without discarding history.
    const absent: Observations = .{ null, null };
    _ = table.mirrorObservations(&absent, start + 3);
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

test "a mirror pass observes both initialized slots and retires abandoned slots" {
    var table: Table = .{};
    const observations: Observations = .{
        .{ .key = directKey(), .report = bareReport(0, true, .idle) },
        .{ .key = reboundKey(), .report = bareReport(1, false, .pending) },
    };
    const first = table.mirrorObservations(&observations, start);
    try t.expectEqual(@as(usize, 2), first.live);
    try t.expectEqual(@as(usize, 2), first.filed);
    const remaining: Observations = .{ null, observations[1] };
    const next = table.mirrorObservations(&remaining, start + 1);
    try t.expectEqual(@as(usize, 1), next.live);
    try t.expectEqual(@as(usize, 1), next.retired);
    try t.expect(!table.get(directKey()).?.live());
    try t.expectEqual(@as(usize, 2), core_slots);
    try t.expectEqual(@as(usize, 8), max_paths);
}

test "actuator refuses actions whose native slot no longer holds the planned pair" {
    var rig = try Rig.init(12, 9);
    defer rig.deinit();
    const conn = try rig.conn();
    const snapshot = conn.pathSnapshot(0) orelse return error.TestUnexpectedResult;
    const slots = actionSlots(conn);
    const selected = slots[0] orelse return error.TestUnexpectedResult;
    try t.expect(selected.key.eql(.{
        .local = snapshot.local orelse return error.TestUnexpectedResult,
        .peer = snapshot.peer orelse return error.TestUnexpectedResult,
    }));
    try t.expectEqual(snapshot.validated, selected.validated);
    try t.expect(selected.selected);
    try t.expect(slots[1] == null);
    try t.expect(conn.pathSnapshot(@intCast(core_slots)) == null);
    try t.expectEqual(@as(?u8, null), try applyAction(conn, .{
        .select = .{ .id = 0, .key = selected.key },
    }, start, rig.client.random()));
    try t.expectError(error.StalePath, applyAction(conn, .{
        .select = .{
            .id = 0,
            .key = .{ .local = server_addr, .peer = reboundKey().peer },
        },
    }, start, rig.client.random()));
    try t.expectError(error.StalePath, applyAction(conn, .{
        .select = .{ .id = @intCast(core_slots), .key = selected.key },
    }, start, rig.client.random()));
    try t.expectError(error.StalePath, applyAction(conn, .{
        .probe = .{
            .id = 1,
            .key = .{ .local = server_addr, .peer = client_addr },
        },
    }, start, rig.client.random()));
    try t.expectEqual(@as(?u8, null), try applyAction(
        conn, .none, start, rig.client.random(),
    ));
    try t.expectEqualDeep(snapshot, conn.pathSnapshot(0).?);
}
