//! Per-path state for one peer, and the ceiling that keeps it finite.
//!
//! `holepunch_path.zig` owns the *candidate* table: every address a peer's
//! record or a probe round produced, bounded at
//! `holepunch_run_peer.max_paths` so that a burst is absorbed before the prune
//! judges it. This owns the *live* table: the paths a connection is actually
//! running on, each carrying the three figures only a caller holding a socket
//! can supply — how fast it answered, when bytes last moved on it, and how
//! many have.
//!
//! Nothing here opens a socket or reads a clock: `now` is an argument to every
//! call that needs one, and the whole table is a value a test holds on the
//! stack. There is no allocator and so no allocator to forget and no failure
//! path to inject: `max_paths` is the only bound and it is a constant below.
//!
//! # What is borrowed and what is new
//!
//! `Entry.addr` and `Entry.status` are `holepunch.Path`'s two fields verbatim.
//! One vocabulary for how usable a path to a peer is, and one place to read it:
//! a second status enum in this directory would be a second opinion about
//! `iroh/src/socket/remote_map/remote_state/path_state.rs`'s `PathStatus`.
//!
//! What this adds is everything downstream of a status: a latency sample and
//! the instant it was taken, when bytes last moved, and how many bytes moved in
//! each direction. None of that is invented policy — it is the input
//! `path_select.zig` needs and the thing that makes a status checkable.
//!
//! **This table is not the one invariant 16 bounds.** That invariant is the
//! candidate table's: prune `Unusable` first, always, and cap `Inactive` at ten
//! of thirty non-relay paths per peer, which is `holepunch.prune` and the
//! ceiling `holepunch.max_non_relay_paths` names. The rule below is a different
//! one over a different table with a different bound, and it is stated here
//! rather than borrowed.
//!
//! # Pruning marks; forgetting removes
//!
//! Two operations, named apart on purpose, because they answer different
//! questions:
//!
//! - `mark(now)` **marks**. An `.open` path that has moved nothing for
//!   `idle_timeout` becomes `.inactive(now)`. The entry stays, with its latency
//!   and its counters, because a path that has gone quiet has not failed, and
//!   its history is exactly what would make it worth choosing again. Marking
//!   is also idempotent, so a caller may run it on every turn.
//! - `forget(address)` **removes**. One named address leaves. Nothing does this
//!   on its own — `node/conn_index.zig`'s `remove` is the precedent, and its
//!   reason is the same one: a peer that stops receiving without the caller
//!   having said so is a peer nobody can dial any more.
//!
//! # What "inactive" means here, and a path that never carried anything
//!
//! Inactive is measured from `Entry.activeAt`, which is the instant bytes last
//! moved **or, if none ever has, the instant the entry arrived**. So a path the
//! multipath layer called `.open` and that has never had a byte on it is idle
//! from the moment it was filed, and `mark` will take it off `.open` once
//! `idle_timeout` has passed with nothing said about it.
//!
//! That is the deliberate answer to "does a path that has never carried
//! traffic count", and it is *yes, if the layer called it open*. The layer's
//! `.open` is a claim that the path is live; a live path that has moved nothing
//! since it opened has told us exactly one thing, which is that nothing has
//! noticed its death yet. Waiting for traffic that may never come would leave
//! a dead path as the incumbent forever, and the incumbent is the path
//! everything else is sent on. The cost of a wrong mark is that the entry drops
//! a status rank and keeps its address, its latency and its counters, so the
//! layer can put it back on `.open` the moment it speaks.
//!
//! A path whose status is `.unknown` is **never** marked, however old it is. An
//! untried path has carried no traffic and has failed at nothing, and recording
//! that as idleness would report a failure nobody observed.
//!
//! # At the bound
//!
//! `max_paths` is a refusal, not an eviction — with one exception, and the
//! exception is narrow on purpose. Filing an address the table does not carry
//! when the table is full takes the slot of a path whose status is `.unusable`,
//! and hands that address back in `Filed.evicted` so the caller learns which
//! path lost. `.unusable` is the only status that is a recorded failure, so
//! freeing its slot sheds nothing the caller is relying on, and it is what
//! stops a table of eight from wedging shut on paths nobody may use. No other
//! status is ever displaced: not `.open`, which carries, not `.inactive`, which
//! worked, not `.unknown`, which is untried. With no `.unusable` path to take,
//! the file is refused and counted in `Filed.stored` and `Absorbed.refused`,
//! and nothing in the table moves.

const std = @import("std");
const addr = @import("../base/addr.zig");
const report = @import("report.zig");
const holepunch = @import("holepunch.zig");

const SocketAddr = addr.SocketAddr;
const TransportAddr = addr.TransportAddr;
const PathStatus = holepunch.PathStatus;

/// Nanoseconds on the caller's own monotonic timeline: `report.Nanos` under the
/// name this module's callers need it, so spelling a `now` here does not mean
/// importing `report.zig` for a type alias.
pub const Nanos = report.Nanos;

/// How many live paths one peer may carry.
///
/// `docs/DECISIONS/0001` records the number upstream works to: "iroh wants up
/// to 8 concurrent paths per connection", against a core that holds two
/// `NetworkPath`s behind one `active_path_idx` (`vendor/quic/src/quic/
/// connection.zig:626`). Eight is therefore the ceiling this tree is aiming at
/// rather than one picked for this table, and a table that outgrows it is a
/// substrate that has arrived rather than a bug in the bound.
///
/// It is also the memory: `Entry` is dominated by the 253-byte `RelayUrl` a
/// `TransportAddr` holds inline, so eight entries are a couple of kilobytes of
/// stack per peer. That is why the bound is a constant and the storage is an
/// inline array — see the module doc.
pub const max_paths: usize = 8;

/// How long an open path may move nothing before `mark` calls it inactive.
///
/// It has to clear the longest event this tree has measured, and
/// `docs/DECISIONS/0001` records that one: a NAT rebinding, port only, on a
/// saturated link cost 109 RTTs at 20 ms, about 2.2 s. A timeout shorter than
/// that would mark a path inactive while the network was busy changing its
/// mapping underneath it. Thirty seconds clears it by more than an order of
/// magnitude and is short enough that a path that has died stops being the
/// incumbent before a caller notices the peer has gone quiet.
pub const idle_timeout: Nanos = 30 * std.time.ns_per_s;

/// How old a latency sample may be and still be believed.
///
/// Younger than the slowest event recorded in `DECISIONS/0001` — a worst-case
/// rebinding taking eight path challenges at 109 RTTs each — so a sample that
/// survives this age describes a mapping that has not been disturbed since it
/// was taken. A sample older than that is treated as no sample at all, which
/// is what `Entry.latency` does and what stops selection acting on a figure
/// measured across a network that has since changed shape.
pub const rtt_max_age: Nanos = 5 * std.time.ns_per_s;

/// One path to a peer, and everything observed on it.
pub const Entry = struct {
    /// Where the path goes. A `.custom` address borrows its payload from
    /// whoever built it, exactly as it does everywhere else in ozai, so the
    /// borrow outlives the table it is filed in.
    addr: TransportAddr,
    /// What the multipath layer last said about the path. This module never
    /// writes a status it was not handed except in `mark`, and that one is
    /// `holepunch.PathStatus.inactive` — a status the vocabulary already has.
    status: PathStatus,
    /// The smoothed round trip, or null until a sample lands. A minimum is not
    /// stored: `sample` records what it is given, and smoothing is the
    /// caller's, because only the caller knows whether a sample came from a
    /// handshake or from a packet that was already queued.
    rtt: ?Nanos = null,
    /// When that sample was taken. Meaningless — and never read — while `rtt`
    /// is null.
    rtt_at: Nanos = 0,
    /// When the entry was filed. Never rewritten, including by a status change:
    /// it is how long this table has known of the path, which is the only
    /// clock available for a path nothing has ever been sent on.
    since: Nanos = 0,
    /// When bytes last moved on the path, or null if none ever has. The
    /// distinction is the point: null is "never carried", which is not the same
    /// fact as "carried long ago" and is what `activeAt` exists to collapse
    /// only where it is safe to.
    last_active: ?Nanos = null,
    /// Bytes sent on this path. Saturating, because a counter that wraps is a
    /// counter that reports a small number on a path that carried a large one,
    /// and nothing downstream would notice.
    tx_bytes: u64 = 0,
    /// Bytes received. Saturating, as above.
    rx_bytes: u64 = 0,

    /// The instant idleness is measured from: the last byte, or the arrival
    /// when no byte has ever moved.
    pub fn activeAt(self: *const Entry) Nanos {
        return self.last_active orelse self.since;
    }

    /// Whether this path is plausibly the one traffic is on at `now`.
    ///
    /// By pointer, not by value: `Entry` is `TransportAddr` plus six fields, so
    /// it is a couple of hundred bytes, and `RelayUrl.socketAddr` is the
    /// precedent for refusing to copy one of those by value
    /// (`src/base/relay.zig`). Saturating, so a caller whose timeline runs
    /// past the ceiling gets a path that reads as carrying rather than a
    /// subtraction that wraps into the far past and reports a path as idle.
    pub fn carrying(self: *const Entry, now: Nanos) bool {
        return now -| self.activeAt() <= idle_timeout;
    }

    /// The latency to make a decision on now, or null when there is none worth
    /// trusting: never sampled, or sampled so long ago that it may describe a
    /// mapping the path no longer has.
    ///
    /// Null here and `rtt` null are different facts and both reach selection:
    /// one is "nobody measured", the other is "nobody measured lately". Both
    /// mean the same thing to a decision and are deliberately not told apart.
    pub fn latency(self: *const Entry, now: Nanos) ?Nanos {
        const measured = self.rtt orelse return null;
        if (now -| self.rtt_at > rtt_max_age) return null;
        return measured;
    }

    /// Whether this path may be handed to a dialer at all, which is one status
    /// and one only: a path recorded as unusable is the sole kind this table
    /// knows to have failed.
    pub fn dialable(self: *const Entry) bool {
        return self.status != .unusable;
    }
};

/// What one file did to the table.
pub const Filed = struct {
    /// Whether the table carries the address once this call returns. False
    /// means the table was full of paths none of which may be displaced, and
    /// the status that came with the address is dropped with it: a path nobody
    /// can see is a path nobody may claim to have tried.
    stored: bool,
    /// The address that lost its slot to this one, or null. Never anything but
    /// an `.unusable` path — see the module doc under "At the bound".
    evicted: ?TransportAddr,
};

/// What one burst of candidates cost.
///
/// Counted rather than dropped in silence, because a caller that files thirty
/// addresses and is told nothing cannot tell a table that absorbed them from
/// one that refused them.
pub const Absorbed = struct {
    /// Addresses the table did not already carry.
    added: usize,
    /// Addresses the table had no room for and no `.unusable` path to make room
    /// with.
    refused: usize,
    /// Addresses that took a slot from a path recorded as unusable.
    evicted: usize,
};

/// Where a free slot came from. Private because it is one function's
/// intermediate, not a decision any caller makes.
const Slot = union(enum) {
    /// Room in the table as it stands.
    free,
    /// The bound was reached and this address was taken instead.
    evicted: TransportAddr,
    /// The bound was reached and nothing in the table may be displaced.
    full,
};

/// Every live path one peer has, bounded by `max_paths`.
///
/// Inline storage and no allocator, so a whole table is a value a test holds on
/// the stack and a `Table` copied into another is independent of the original.
/// Entries past `len` are never written and never read, so a default `Table` is
/// a valid empty table and not a broken one — read it through `slice` rather
/// than by indexing.
pub const Table = struct {
    /// The paths, first `len` of them in the order they were filed, with one
    /// exception: `forget` moves the last entry into the gap it leaves, so the
    /// order is not the filing order after a removal. Nothing depends on the
    /// order except the tie-break in `path_select.zig`, which prefers the
    /// earlier entry, so it makes removal order visible rather than wrong.
    entries: [max_paths]Entry = undefined,
    /// How many entries are live. Zero by default and never above
    /// `entries.len`.
    len: usize = 0,

    /// The paths, for a caller reading what the table holds: exactly
    /// `entries[0..len]`.
    pub fn slice(self: *const Table) []const Entry {
        return self.entries[0..self.len];
    }

    /// The slot holding `address`, for a caller that is about to write to it.
    /// Null when the table does not carry it.
    pub fn find(self: *Table, address: TransportAddr) ?*Entry {
        const index = self.indexOf(address) orelse return null;
        return &self.entries[index];
    }

    /// The entry for `address`, by value. For a caller that only reads, which
    /// `find` cannot serve because it hands out a mutable pointer.
    pub fn get(self: *const Table, address: TransportAddr) ?Entry {
        const index = self.indexOf(address) orelse return null;
        return self.entries[index];
    }

    /// Record `status` for `address` as of `now`, and enforce the ceiling.
    ///
    /// An address the table already carries has its status replaced and nothing
    /// else touched: the latency and the counters stay, because a status change
    /// is a report about the path and not a new path, and the history is the
    /// reason the entry is still here. An address it does not carry is filed
    /// fresh, with `rtt` and both counters at zero and `last_active` null —
    /// the table does not claim a path carried something because it was filed.
    ///
    /// This is the only call that writes a status the caller named. `absorb`
    /// files `.unknown`, which is the one status that says nothing went wrong
    /// and nothing went right either.
    pub fn observe(
        self: *Table,
        address: TransportAddr,
        status: PathStatus,
        now: Nanos,
    ) Filed {
        if (self.find(address)) |held| {
            held.status = status;
            return .{ .stored = true, .evicted = null };
        }
        const evicted: ?TransportAddr = switch (self.takeSlot()) {
            .free => null,
            .evicted => |gone| gone,
            .full => return .{ .stored = false, .evicted = null },
        };
        self.entries[self.len] = .{ .addr = address, .status = status, .since = now };
        self.len += 1;
        return .{ .stored = true, .evicted = evicted };
    }

    /// File a burst of candidates as `.unknown`, and answer what the burst
    /// cost.
    ///
    /// One filed per entry rather than one at the end, because the bound is
    /// enforced by `observe` and a burst is a run of changes rather than one
    /// change: a single ceiling check at the end would let a burst's
    /// `.unusable` paths sit in the table for the whole of it.
    pub fn absorb(self: *Table, addresses: []const TransportAddr, now: Nanos) Absorbed {
        var result: Absorbed = .{ .added = 0, .refused = 0, .evicted = 0 };
        for (addresses) |address| {
            // Read before the change: `added` counts addresses the table did
            // not already carry, and one it does carry is not filed again.
            const known = self.find(address) != null;
            const filed = self.observe(address, .unknown, now);
            if (!filed.stored) {
                result.refused += 1;
            } else {
                if (!known) result.added += 1;
                if (filed.evicted != null) result.evicted += 1;
            }
        }
        return result;
    }

    /// Record a latency sample taken at `now`. False for an address the table
    /// does not carry.
    ///
    /// A refused sample is refused rather than filed, because a measurement of
    /// a path this table does not hold would have to be attributed to some
    /// other path, and the figure it produced would then be a latency nobody
    /// measured.
    pub fn sample(self: *Table, address: TransportAddr, rtt: Nanos, now: Nanos) bool {
        const held = self.find(address) orelse return false;
        held.rtt = rtt;
        held.rtt_at = now;
        return true;
    }

    /// Fold bytes that moved on `address` into its counters, and stamp it as
    /// carrying at `now`. False for an address the table does not carry.
    ///
    /// A call with both counts zero is still an event: it is the caller's
    /// statement that the path was used, and `last_active` is what a path that
    /// has never carried anything is distinguished by.
    pub fn account(
        self: *Table,
        address: TransportAddr,
        sent: u64,
        received: u64,
        now: Nanos,
    ) bool {
        const held = self.find(address) orelse return false;
        held.tx_bytes +|= sent;
        held.rx_bytes +|= received;
        held.last_active = now;
        return true;
    }

    /// Take every open path that has moved nothing for `idle_timeout` off
    /// `.open`, and answer with how many changed.
    ///
    /// Runs on any turn a caller likes: a path already marked is not `.open`,
    /// so a second call over the same table marks nothing and reports zero. A
    /// path that is not `.open` is never touched, which is what keeps this from
    /// recording a failure on a path nobody has tried.
    pub fn mark(self: *Table, now: Nanos) usize {
        var marked: usize = 0;
        for (self.entries[0..self.len]) |*entry| {
            if (entry.status != .open) continue;
            if (entry.carrying(now)) continue;
            entry.status = .{ .inactive = now };
            marked += 1;
        }
        return marked;
    }

    /// Drop `address` and answer whether it was there.
    ///
    /// The last entry moves into the gap, so the table keeps its bound and the
    /// order `slice` reports is no longer the order it had. That is the only
    /// operation here that moves an entry, and a caller holding an index into
    /// `slice` across one is reading the wrong path.
    pub fn forget(self: *Table, address: TransportAddr) bool {
        const index = self.indexOf(address) orelse return false;
        // indexOf returns only live indices; ZBC cannot carry its scan proof to this swap.
        // zbc-disable-next-line: index-minus-one-without-zero-guard
        self.entries[index] = self.entries[self.len - 1];
        self.len -= 1;
        return true;
    }

    /// A slot to write into, or the reason there is none.
    ///
    /// The eviction scan takes the last `.unusable` entry because `unusable`
    /// carries no instant to order by — `holepunch.PathStatus.inactive` does,
    /// which is why `holepunch_path.zig`'s top-k can keep the *most recently*
    /// closed and this cannot keep anything in particular. The address comes
    /// back to the caller in `Filed.evicted`, so which one it was is reported
    /// rather than chosen silently.
    fn takeSlot(self: *Table) Slot {
        if (self.len < self.entries.len) return .free;
        var victim: ?usize = null;
        var index: usize = 0;
        while (index < self.len) : (index += 1) {
            if (self.entries[index].status == .unusable) victim = index;
        }
        const victim_at = victim orelse return .full;
        const gone = self.entries[victim_at].addr;
        // victim is set only by the live scan; ZBC cannot carry the orelse guard to this swap.
        // zbc-disable-next-line: index-minus-one-without-zero-guard
        self.entries[victim_at] = self.entries[self.len - 1];
        self.len -= 1;
        return .{ .evicted = gone };
    }

    /// Where `address` is, or null. A scan and not a hash, for
    /// `node/conn_index.zig`'s reason: the table is `max_paths` entries and a
    /// lookup is a handful of comparisons, so the loop is bounded by the
    /// storage it walks and cannot run away.
    fn indexOf(self: *const Table, address: TransportAddr) ?usize {
        var index: usize = 0;
        while (index < self.len) : (index += 1) {
            if (self.entries[index].addr.order(address) == .eq) return index;
        }
        return null;
    }
};

// --- tests

const t = std.testing;

/// A direct address on `port` from one documentation range, so a test that
/// prints one is never mistaken for a routable host.
fn ip(port: u16) SocketAddr {
    return .{ .ip = .{ .v4 = .{ 192, 0, 2, 1 } }, .port = port };
}

/// `ip(port)` as the address the table keys on.
fn at(port: u16) TransportAddr {
    return .{ .ip = ip(port) };
}

/// Whether two addresses name the same one. `TransportAddr` holds a
/// `CustomAddr` with a slice in it, so `==` is not defined on it and every
/// comparison in this tree goes through `order`.
fn sameAddress(left: ?TransportAddr, right: ?TransportAddr) bool {
    const one = left orelse return right == null;
    const other = right orelse return false;
    return one.order(other) == .eq;
}

/// Every port the table carries, ascending, so an assertion can name the whole
/// table without depending on its order.
fn ports(table: *const Table) [max_paths]u16 {
    var out: [max_paths]u16 = undefined;
    for (table.slice()) |entry| {
        switch (entry.addr) {
            .ip => |socket| out[socket.port - 1000] = socket.port,
            else => {},
        }
    }
    // The sole caller fills all eight ports; ZBC cannot follow this test helper's inputs.
    // zbc-disable-next-line: use-undefined
    return out;
}

test "one address filed twice is one path" {
    var table: Table = .{};
    try t.expectEqual(@as(usize, 0), table.slice().len);
    try t.expect(table.find(at(1000)) == null);

    const first = table.absorb(&.{ at(1000), at(1001) }, 0);
    try t.expectEqual(Absorbed{ .added = 2, .refused = 0, .evicted = 0 }, first);

    // The same burst again: nothing is added, nothing is refused, and neither
    // path is given a second entry.
    const again = table.absorb(&.{ at(1000), at(1001) }, 0);
    try t.expectEqual(Absorbed{ .added = 0, .refused = 0, .evicted = 0 }, again);
    try t.expectEqual(@as(usize, 2), table.slice().len);
    // The filing instant is the first one's: a re-filing is not a new path.
    const entry = table.get(at(1001)) orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(Nanos, 0), entry.since);
}

test "a status replaces the status and keeps every figure" {
    var table: Table = .{};
    try t.expect(table.observe(at(1000), .unknown, 0).stored);
    try t.expect(table.sample(at(1000), 20 * std.time.ns_per_ms, 100));
    try t.expect(table.account(at(1000), 900, 1_800, 200));
    _ = table.observe(at(1000), .open, 300);
    _ = table.observe(at(1000), .{ .inactive = 400 }, 500);

    const entry = table.get(at(1000)) orelse return error.TestUnexpectedResult;
    // The path is one path, and the four figures it accumulated outlived two
    // status changes — which is the whole reason a status change is not a new
    // entry.
    try t.expectEqual(@as(usize, 1), table.slice().len);
    try t.expectEqual(PathStatus{ .inactive = 400 }, entry.status);
    try t.expectEqual(@as(?Nanos, 20 * std.time.ns_per_ms), entry.rtt);
    try t.expectEqual(@as(?Nanos, 200), entry.last_active);
    try t.expectEqual(@as(u64, 900), entry.tx_bytes);
    try t.expectEqual(@as(u64, 1_800), entry.rx_bytes);
    // `since` is still the arrival, not the last status change.
    try t.expectEqual(@as(Nanos, 0), entry.since);
}

test "at the bound the table refuses a file and moves nothing" {
    var table: Table = .{};
    try t.expectEqual(@as(usize, 8), max_paths);
    for (0..max_paths) |offset| {
        _ = table.observe(at(1000 + @as(u16, @intCast(offset))), .open, 0);
    }
    try t.expectEqual(@as(usize, 8), table.slice().len);

    // Every path is open, so there is no failure to take a slot from.
    const filed = table.observe(at(2000), .open, 0);
    try t.expect(!filed.stored);
    try t.expect(sameAddress(filed.evicted, null));
    try t.expectEqual(@as(usize, 8), table.slice().len);
    try t.expect(table.find(at(2000)) == null);

    // Nothing was displaced: all eight are still here, at the ports they were
    // filed at.
    const held = ports(&table);
    for (0..max_paths) |offset| {
        try t.expectEqual(@as(u16, @intCast(1000 + offset)), held[offset]);
    }

    // And the refusal is counted rather than silent.
    const burst = table.absorb(&.{at(2000)}, 0);
    try t.expectEqual(Absorbed{ .added = 0, .refused = 1, .evicted = 0 }, burst);
}

test "a refused file takes the slot of a failed path and names it" {
    // Seven open paths and one failure: a full table whose only disposable
    // entry is a path recorded as having failed.
    var table: Table = .{};
    for (0..max_paths - 1) |offset| {
        _ = table.observe(at(1000 + @as(u16, @intCast(offset))), .open, 0);
    }
    try t.expect(table.observe(at(1500), .unusable, 0).stored);
    try t.expectEqual(@as(usize, 8), table.slice().len);

    const filed = table.observe(at(2000), .unknown, 0);
    try t.expect(filed.stored);
    try t.expect(sameAddress(filed.evicted, at(1500)));
    // The bound still holds, the failed path is gone, and the seven open ones
    // are all still here, because none of them may be displaced.
    try t.expectEqual(@as(usize, 8), table.slice().len);
    try t.expect(table.find(at(1500)) == null);
    try t.expect(table.get(at(1500)) == null);
    try t.expect(table.find(at(2000)) != null);
    for (0..max_paths - 1) |offset| {
        try t.expect(table.find(at(1000 + @as(u16, @intCast(offset)))) != null);
    }

    // The slot the failure gave up is the one the new path has, and it is
    // counted rather than spent in silence.
    const burst = table.absorb(&.{at(2001)}, 0);
    try t.expectEqual(Absorbed{ .added = 0, .refused = 1, .evicted = 0 }, burst);
}

test "marking is idempotent and reports what it changed" {
    var table: Table = .{};
    _ = table.observe(at(1000), .open, 0);
    _ = table.observe(at(1001), .open, 0);
    try t.expect(table.account(at(1000), 1, 1, idle_timeout));
    // `at(1000)` carried at the instant `mark` runs and `at(1001)` never had a
    // byte on it, so it is idle from when it was filed: at `idle_timeout` both
    // are still inside the timeout, and a nanosecond later only the second is
    // outside it.
    try t.expectEqual(@as(usize, 0), table.mark(idle_timeout));
    try t.expectEqual(@as(usize, 1), table.mark(idle_timeout + 1));

    const marked = table.get(at(1001)) orelse return error.TestUnexpectedResult;
    try t.expectEqual(PathStatus{ .inactive = idle_timeout + 1 }, marked.status);
    // Nothing was removed, and the figures came through the mark untouched.
    try t.expectEqual(@as(usize, 2), table.slice().len);
    try t.expectEqual(@as(?Nanos, null), marked.last_active);
    const active = table.get(at(1000)) orelse return error.TestUnexpectedResult;
    try t.expectEqual(PathStatus.open, active.status);

    // Second turn over the same table: a path already marked is not `.open`,
    // so nothing changes and nothing is reported.
    try t.expectEqual(@as(usize, 0), table.mark(idle_timeout + 2));
    const unchanged = table.get(at(1001)) orelse return error.TestUnexpectedResult;
    try t.expectEqual(PathStatus{ .inactive = idle_timeout + 1 }, unchanged.status);
}

test "a path nobody has tried is never marked" {
    var table: Table = .{};
    _ = table.observe(at(1000), .unknown, 0);
    // Long past any timeout, and nothing has said this path failed — nothing
    // has said anything about it at all.
    try t.expectEqual(@as(usize, 0), table.mark(idle_timeout * 1000));
    const unknown = table.get(at(1000)) orelse return error.TestUnexpectedResult;
    try t.expectEqual(PathStatus.unknown, unknown.status);
    // The same for a path that worked and closed: it is already marked, and a
    // later mark must not re-stamp it with a different instant.
    _ = table.observe(at(1001), .{ .inactive = 7 }, 0);
    try t.expectEqual(@as(usize, 0), table.mark(idle_timeout * 1000));
    const inactive = table.get(at(1001)) orelse return error.TestUnexpectedResult;
    try t.expectEqual(PathStatus{ .inactive = 7 }, inactive.status);
}

test "an old sample stops being believed without being forgotten" {
    var table: Table = .{};
    _ = table.observe(at(1000), .open, 0);
    try t.expect(table.sample(at(1000), 20 * std.time.ns_per_ms, 1_000));
    const entry = table.get(at(1000)) orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(?Nanos, 20 * std.time.ns_per_ms), entry.latency(1_000));
    // Just inside the age, and then past it: the figure is still in the entry,
    // and it is simply no longer an answer.
    try t.expectEqual(
        @as(?Nanos, 20 * std.time.ns_per_ms),
        entry.latency(1_000 + rtt_max_age),
    );
    try t.expectEqual(@as(?Nanos, null), entry.latency(1_000 + rtt_max_age + 1));
    try t.expectEqual(@as(?Nanos, 20 * std.time.ns_per_ms), entry.rtt);
    // A sample stamped after `now` is not old, it is not yet stale: the age
    // saturates rather than wrapping round into the far past.
    try t.expectEqual(@as(?Nanos, 20 * std.time.ns_per_ms), entry.latency(0));
}

test "a figure for a path the table does not carry is refused" {
    var table: Table = .{};
    _ = table.observe(at(1000), .open, 0);
    try t.expect(!table.sample(at(2000), 5 * std.time.ns_per_ms, 10));
    try t.expect(!table.account(at(2000), 1, 1, 10));
    // Nothing was filed to hold them, so nothing grew and nothing moved.
    try t.expectEqual(@as(usize, 1), table.slice().len);
    try t.expectEqual(@as(?Nanos, null), table.get(at(1000)).?.rtt);
    try t.expect(!table.forget(at(2000)));
}

test "forget takes one path out and leaves the rest in the table" {
    var table: Table = .{};
    for (0..4) |offset| {
        _ = table.observe(at(1000 + @as(u16, @intCast(offset))), .open, 0);
    }
    try t.expect(table.forget(at(1002)));
    try t.expectEqual(@as(usize, 3), table.slice().len);
    try t.expect(table.find(at(1002)) == null);
    // The last entry moved into the gap rather than everything shifting down,
    // so the other three are still here.
    for ([_]u16{ 1000, 1001, 1003 }) |port| {
        try t.expect(table.find(at(port)) != null);
    }
}
