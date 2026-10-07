//! The per-peer path table and the ceiling that prunes it.
//!
//! `holepunch.zig` is the facade for this module; this half holds everything
//! about paths rather than about punching: what a path to the peer is, how
//! usable it is, and which of them survive a prune. Relay paths are outside the
//! ceiling for the reason `max_non_relay_paths` gives.
//!
//! The module doc `holepunch.zig` carries is the argument for the whole file
//! and is not repeated here.

const std = @import("std");
const addr = @import("../base/addr.zig");
const report = @import("report.zig");

const TransportAddr = addr.TransportAddr;
const Nanos = report.Nanos;

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

// Widened only so the counting helper in `holepunch.zig`'s tests can ask the
// same question `prune` asks. `holepunch.zig` does not re-export it.
// ziglint-ignore: Z012
pub fn isRelay(value: TransportAddr) bool {
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
