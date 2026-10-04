//! What a changed path table keeps: `prune`, and the two ceilings it enforces.
//!
//! A path table is a per-peer map from a `TransportAddr` to what is known
//! about it. It churns — a burst of address-lookup results files dozens of
//! candidates at once — and this is the one rule about what a burst may take
//! with it: a path nobody has tried is not a path that does not work, so a
//! burst of untried candidates cannot displace anything that has been tried and
//! has held.
//!
//! `holepunch_gate.zig` decides when a round runs and `holepunch_refusal.zig`
//! what its answer means; neither looks at a path.
//! `holepunch_run_table.zig` is the producer that files into a table and
//! re-runs this rule on every change. `holepunch.zig` re-exports all three as
//! the layer's one surface.

const std = @import("std");
const addr = @import("../base/addr.zig");
const base_relay_url = @import("../base/relay_url.zig");
const report = @import("report.zig");
const transport_addr = @import("../base/transport_addr.zig");

const Nanos = report.Nanos;
const SocketAddr = addr.SocketAddr;
const TransportAddr = transport_addr.TransportAddr;

/// How many non-relay paths one peer may carry before anything is pruned.
///
/// Upstream's `MAX_NON_RELAY_PATHS`, a `usize`. It is the point at which
/// pruning starts, not a bound on the table: paths that are open, and paths
/// nobody has tried, are never dropped however many there are. A relay path is
/// neither counted nor dropped — it is the fallback, and a ceiling that can
/// evict the fallback is not a ceiling.
pub const max_non_relay_paths: usize = 30;

/// How many previously-successful paths may survive a prune.
///
/// Upstream's `MAX_INACTIVE_NON_RELAY_PATHS`, read as the cap its own doc
/// comment gives it rather than as its code reads it:
/// `split_off(inactive.len() - MAX)` prunes the oldest `MAX` and leaves the
/// newest `len - MAX`, so the survivors number `len - MAX` and not `MAX`. At
/// twenty inactive paths the two readings agree and at fifteen they differ by
/// five, which is the difference between a cap that bounds the working set and
/// one that spends it. These are the paths that have demonstrably worked, and
/// capping them is also what the plan asks for. See the divergence note in
/// `docs/ARCHITECTURE.md`.
pub const max_inactive_non_relay_paths: usize = 10;

/// How usable a path to the peer is. Upstream's `PathStatus`.
///
/// `inactive` carries the instant the path was abandoned, because the prune
/// keeps the most recently closed of them and cannot do that from a bare tag.
pub const PathStatus = union(enum) {
    /// Open and carrying traffic.
    open,
    /// Opened once and closed at this instant: punched, and it worked.
    inactive: Nanos,
    /// Punched, and it did not work.
    unusable,
    /// Never punched, or a punch is in flight. Nothing is known about it, which
    /// is not the same as it having failed.
    unknown,
};

/// One path to the peer and everything known about it.
///
/// `addr` is the destination, borrowed in the `custom` arm, so the caller keeps
/// that storage alive for as long as the path is in the table.
pub const Path = struct {
    addr: TransportAddr,
    status: PathStatus,
};

/// What one prune dropped. `paths[0..kept]` are the survivors; the tail is left
/// untouched, so the caller can keep appending to the same storage.
pub const Pruned = struct {
    kept: usize,
    unusable_dropped: usize,
    inactive_dropped: usize,
};

/// Enforce the per-peer path ceiling, in place.
///
/// Upstream's `prune_non_relay_paths`, and the order is the whole point:
///
/// 1. `unusable` goes first and always. A path that was punched and failed is
///    the only kind that has been shown not to work.
/// 2. Of the rest, at most `max_inactive_non_relay_paths` survive, and they are
///    the ones closed most recently, because those are the ones that worked.
/// 3. `open` and `unknown` are never candidates for eviction. A path nobody has
///    tried is not a path that does not work, so a burst of address-lookup
///    results cannot displace anything that has been tried and has held.
///
/// Relay paths are outside all three, for the reason `max_non_relay_paths`
/// gives.
pub fn prune(paths: []Path) Pruned {
    var result: Pruned = .{
        .kept = paths.len,
        .unusable_dropped = 0,
        .inactive_dropped = 0,
    };
    var non_relay: usize = 0;
    var unusable: usize = 0;
    var top: TopInactive = .{};
    for (paths, 0..) |path, index| {
        if (isRelay(path.addr)) continue;
        non_relay += 1;
        switch (path.status) {
            .unusable => unusable += 1,
            .inactive => |closed| top.offer(closed, index),
            .open, .unknown => {},
        }
    }
    // Upstream tests the total count and then the non-relay count; the first
    // test is implied by the second, so only the second is here.
    if (non_relay < max_non_relay_paths) return result;

    // Every path is one that failed. Upstream's guard against pruning a peer's
    // whole table, except that it compares the unusable count against the total,
    // which counts the relay path — so it never fires on exactly the peers that
    // always have one. Compared against the non-relay count it fires as its
    // comment says it should. Which of the survivors is kept is upstream's
    // `HashMap` iteration order and therefore arbitrary; the caller's order is a
    // rule, so this pins one and the test names it.
    const keep_unusable = if (non_relay == unusable) max_non_relay_paths else 0;

    // Compact in place. The write cursor trails the read cursor, so nothing a
    // later iteration reads has been overwritten.
    var seen: usize = 0;
    var out: usize = 0;
    for (paths, 0..) |path, index| {
        const why: ?Why = if (isRelay(path.addr))
            null
        else switch (path.status) {
            .unusable => blk: {
                seen += 1;
                break :blk if (seen > keep_unusable) .unusable else null;
            },
            .inactive => |closed| if (!top.keeps(closed, index)) .inactive else null,
            .open, .unknown => null,
        };
        if (why) |reason| {
            switch (reason) {
                .unusable => result.unusable_dropped += 1,
                .inactive => result.inactive_dropped += 1,
            }
            continue;
        }
        paths[out] = path;
        out += 1;
    }
    result.kept = out;
    return result;
}

/// Why one path was dropped. Private because it is a tally, not a decision.
const Why = enum { unusable, inactive };

fn isRelay(value: TransportAddr) bool {
    return std.meta.activeTag(value) == .relay;
}

/// The `max_inactive_non_relay_paths` most recently closed inactive paths.
///
/// A fixed-size top-k rather than a sort, because a sort needs storage the
/// caller would have to hand over and the bound is a constant. Keyed on the
/// closing instant and the index together, so two paths abandoned at the same
/// nanosecond still order — upstream sorts by the instant alone over a
/// `FxHashMap`, which leaves the tie to an iteration order that is not stable
/// between runs.
const TopInactive = struct {
    const Entry = struct { closed: Nanos, index: usize };

    items: [max_inactive_non_relay_paths]Entry = undefined,
    len: usize = 0,

    fn offer(self: *TopInactive, closed: Nanos, index: usize) void {
        if (self.len == self.items.len and
            laterThan(closed, index, self.items[0].closed, self.items[0].index) != .gt)
        {
            return;
        }
        var at = self.len;
        if (at == self.items.len) at -= 1;
        // The walk stops at the first entry under the cursor that the
        // candidate does not beat, and at zero there is no entry under the
        // cursor at all — which is why the bound is stated on the cursor
        // itself rather than on the slot it reads. Naming the entry also
        // costs one read per step instead of three.
        while (at > 0) {
            const below = self.items[at - 1];
            if (laterThan(closed, index, below.closed, below.index) != .gt) break;
            self.items[at] = below;
            at -= 1;
        }
        self.items[at] = .{ .closed = closed, .index = index };
        if (self.len < self.items.len) self.len += 1;
    }

    fn keeps(self: *const TopInactive, closed: Nanos, index: usize) bool {
        for (self.items[0..self.len]) |entry| {
            if (entry.closed == closed and entry.index == index) return true;
        }
        return false;
    }
};

/// Orders two inactive paths: most recently closed first, later index first on
/// a tie, so the order is total over indices that are themselves unique.
fn laterThan(closed_a: Nanos, index_a: usize, closed_b: Nanos, index_b: usize) std.math.Order {
    return switch (std.math.order(closed_a, closed_b)) {
        .eq => std.math.order(index_a, index_b),
        else => |ordering| ordering,
    };
}

const t = std.testing;

/// A direct address on port `port`, all from one documentation range so a test
/// that prints one is never mistaken for a routable host.
fn ip(port: u16) SocketAddr {
    return .{ .ip = .{ .v4 = .{ 192, 0, 2, 1 } }, .port = port };
}

/// Fill `paths` with direct paths on consecutive ports, starting at `first`.
fn fillIp(paths: []Path, first: u16, status: PathStatus) void {
    for (paths, 0..) |*path, index| {
        path.* = .{
            .addr = .{ .ip = ip(first + @as(u16, @intCast(index))) },
            .status = status,
        };
    }
}

/// Whether `paths` still carries a direct path on `port`.
fn carries(paths: []const Path, port: u16) bool {
    for (paths) |path| {
        switch (path.addr) {
            .ip => |socket| if (socket.port == port) return true,
            else => {},
        }
    }
    return false;
}

/// How many of `paths` are relay paths.
fn countRelays(paths: []const Path) usize {
    var count: usize = 0;
    for (paths) |path| {
        if (isRelay(path.addr)) count += 1;
    }
    return count;
}

test "nothing is pruned below the ceiling" {
    var paths: [max_non_relay_paths - 1]Path = undefined;
    fillIp(&paths, 1_000, .unknown);
    for (0..5) |index| paths[index].status = .{ .inactive = @intCast(index) };
    for (0..5) |index| paths[10 + index].status = .unusable;

    const result = prune(&paths);
    try t.expectEqual(@as(usize, paths.len), result.kept);
    try t.expectEqual(@as(usize, 0), result.unusable_dropped);
    try t.expectEqual(@as(usize, 0), result.inactive_dropped);
}

test "unusable paths are pruned before inactive ones" {
    var paths: [35]Path = undefined;
    fillIp(&paths, 1_000, .open);
    for (0..15) |index| paths[15 + index].status = .{ .inactive = @intCast(index) };
    for (0..5) |index| paths[30 + index].status = .unusable;

    const result = prune(&paths);
    try t.expectEqual(@as(usize, 5), result.unusable_dropped);
    // The ten most recently closed of the fifteen: ports 1_020..1_029.
    try t.expectEqual(@as(usize, 5), result.inactive_dropped);
    try t.expectEqual(@as(usize, 25), result.kept);
    const alive = paths[0..result.kept];
    for (0..15) |index| try t.expect(carries(alive, 1_000 + @as(u16, @intCast(index))));
    for (0..5) |index| {
        try t.expect(!carries(alive, 1_030 + @as(u16, @intCast(index))));
    }
    for (5..15) |index| {
        try t.expect(carries(alive, 1_015 + @as(u16, @intCast(index))));
    }
    for (0..5) |index| {
        try t.expect(!carries(alive, 1_015 + @as(u16, @intCast(index))));
    }
}

test "at most ten previously-successful paths survive" {
    var paths: [50]Path = undefined;
    fillIp(&paths, 2_000, .unknown);
    for (0..20) |index| paths[index].status = .{ .inactive = @intCast(index) };

    const result = prune(&paths);
    try t.expectEqual(@as(usize, 10), result.inactive_dropped);
    // The twenty most recently closed are ports 2_010..2_019.
    const alive = paths[0..result.kept];
    for (0..10) |index| {
        try t.expect(!carries(alive, 2_000 + @as(u16, @intCast(index))));
    }
    for (10..20) |index| {
        try t.expect(carries(alive, 2_000 + @as(u16, @intCast(index))));
    }
    // The thirty untried paths are not candidates for eviction at all.
    for (20..50) |index| {
        try t.expect(carries(alive, 2_000 + @as(u16, @intCast(index))));
    }
}

test "a burst of untested results does not evict the paths that work" {
    // The ten working paths sit at the cap and were closed first; the burst
    // arrives afterwards, forty addresses long, and every one of them is
    // untried. An eviction ordered by freshness rather than by what is known
    // drops all ten working paths and keeps thirty never-tried ones.
    var paths: [55]Path = undefined;
    for (0..10) |index| {
        paths[index] = .{
            .addr = .{ .ip = ip(3_000 + @as(u16, @intCast(index))) },
            .status = .{ .inactive = @intCast(index) },
        };
    }
    fillIp(paths[10..15], 3_100, .unusable);
    fillIp(paths[15..], 4_000, .unknown);

    const result = prune(&paths);
    try t.expectEqual(@as(usize, 5), result.unusable_dropped);
    try t.expectEqual(@as(usize, 0), result.inactive_dropped);
    try t.expectEqual(@as(usize, 50), result.kept);

    const alive = paths[0..result.kept];
    for (0..10) |index| {
        try t.expect(carries(alive, 3_000 + @as(u16, @intCast(index))));
    }
    for (0..5) |index| {
        try t.expect(!carries(alive, 3_100 + @as(u16, @intCast(index))));
    }
    for (0..40) |index| {
        try t.expect(carries(alive, 4_000 + @as(u16, @intCast(index))));
    }
}

test "a table that is entirely unusable keeps the ceiling worth keeping" {
    var paths: [40]Path = undefined;
    fillIp(&paths, 5_000, .unusable);

    const result = prune(&paths);
    try t.expectEqual(@as(usize, 10), result.unusable_dropped);
    try t.expectEqual(@as(usize, max_non_relay_paths), result.kept);
    // Upstream's guard does not fire once a relay path is present, and drops
    // every path instead of any; this keeps the paths the caller listed first.
    const alive = paths[0..result.kept];
    try t.expect(carries(alive, 5_000));
    try t.expect(!carries(alive, 5_030));
}

test "relay paths are neither counted nor pruned" {
    const relay_url = try base_relay_url.RelayUrl.parse("https://use1-1.relay.iroh.network./");

    // Thirty-five direct paths against four relay ones, so the non-relay count
    // is over the ceiling on its own and the prune has something to do.
    var over: [39]Path = undefined;
    fillIp(&over, 6_000, .open);
    for (0..5) |index| over[30 + index].status = .unusable;
    for (0..4) |index| {
        over[35 + index] = .{ .addr = .{ .relay = relay_url }, .status = .unusable };
    }
    const pruned = prune(&over);
    try t.expectEqual(@as(usize, 5), pruned.unusable_dropped);
    try t.expectEqual(@as(usize, 34), pruned.kept);
    try t.expectEqual(@as(usize, 4), countRelays(over[0..pruned.kept]));

    // The same relays beside twenty-five direct paths: under the ceiling, and
    // nothing is dropped however many of the paths are unusable.
    var under: [29]Path = undefined;
    fillIp(&under, 7_000, .unusable);
    for (0..4) |index| {
        under[25 + index] = .{ .addr = .{ .relay = relay_url }, .status = .unusable };
    }
    const held = prune(&under);
    try t.expectEqual(@as(usize, 29), held.kept);
    try t.expectEqual(@as(usize, 0), held.unusable_dropped);
}