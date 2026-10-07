//! Closed ranges of packet numbers, and the descending set that merges them.
//!
//! `RangeSet` is how this tree remembers which packet numbers it has seen:
//! it keeps one allocator it was given and borrows nothing from its caller,
//! and one `deinit` releases every byte it holds. It is reached through
//! `ack_handler.ReceivedPacketTracker.received`, which builds an ACK frame
//! from the ranges it returns.
//!
//! The slice `getRanges` hands out points into the set's own storage. `add`,
//! `addRange` and `removeBelow` all move it, so a slice is valid only until
//! the next call on the same set.

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

/// One closed span of packet numbers or stream offsets. Both ends are
/// members: `size` counts `end - start + 1` values, and
/// `.{ .start = 5, .end = 5 }` is the single value 5 rather than an empty
/// span. A pair with `start > end` never reaches this struct — `RangeSet`
/// treats it as an empty addition and stores nothing — so the ordering
/// holds for any `Range` a caller can construct by hand.
pub const Range = struct {
    start: u64,
    end: u64,

    /// Whether `val` is `start`, `end`, or between them.
    pub fn contains(self: Range, val: u64) bool {
        return val >= self.start and val <= self.end;
    }

    /// How many values the span holds. Never zero for a stored range, so a
    /// caller testing for emptiness asks `RangeSet.len` instead.
    pub fn size(self: Range) u64 {
        return self.end - self.start + 1;
    }
};

/// A set of non-overlapping, non-adjacent ranges stored in descending order
/// (largest first). This is the core data structure for tracking received
/// packet numbers, ACK ranges, and byte ranges.
///
/// Following quic-go's approach of maintaining ranges in descending order
/// for efficient ACK frame generation.
///
/// The set owns every range it holds and borrows nothing: it retains the
/// allocator given to `init` and `deinit` frees the array with it. Neither
/// copying the struct nor moving it invalidates the ranges, so a `RangeSet`
/// may be returned by value from a constructor; the two copies then name one
/// owner and exactly one of them must be `deinit`'d.
pub const RangeSet = struct {
    /// Retained at `init` for the set's whole life. Every allocation `add`
    /// and `addRange` make comes from it, `deinit` returns them with it, and
    /// the set never frees it itself. Writing to this field after `init`
    /// makes `deinit` release through a different allocator than the one
    /// that allocated.
    allocator: Allocator,

    /// Owned by the set, ordered by descending `start`, so `items[0]` always
    /// holds the largest value and the last item the smallest. `init` leaves
    /// it as a static empty slice with no capacity, so a set that never
    /// receives an addition allocates nothing at all.
    ranges: std.ArrayList(Range),

    /// A set holding no values. The allocator is retained immediately; one
    /// `deinit` is owed whether or not the set ever grew.
    pub fn init(allocator: Allocator) RangeSet {
        return .{
            .allocator = allocator,
            .ranges = .{ .items = &.{}, .capacity = 0 },
        };
    }

    /// Releases the range array. Does not free `allocator`, which the caller
    /// still owns. The set is unusable afterwards and a second call frees
    /// the same bytes twice.
    pub fn deinit(self: *RangeSet) void {
        self.ranges.deinit(self.allocator);
    }

    /// How many ranges the set holds, not how many values: a set of ten
    /// disjoint packet numbers is one range here. Use `getRanges` and sum
    /// `Range.size` when a count of values is what the bound is on.
    pub fn len(self: *const RangeSet) usize {
        return self.ranges.items.len;
    }

    /// The largest value held, or `null` when the set is empty. `null` is how
    /// emptiness is spelled: value 0 is a member like any other and is never
    /// reported as the absent answer.
    pub fn largest(self: *const RangeSet) ?u64 {
        if (self.ranges.items.len == 0) return null;
        return self.ranges.items[0].end;
    }

    /// The smallest value held, or `null` when the set is empty, for the same
    /// reason `largest` reports `null`.
    pub fn smallest(self: *const RangeSet) ?u64 {
        if (self.ranges.items.len == 0) return null;
        return self.ranges.items[self.ranges.items.len - 1].start;
    }

    /// Whether any range holds `val`. A value this set has dropped through
    /// `removeBelow` is reported absent, so a caller that prunes to bound
    /// memory cannot use this to tell "never seen" from "no longer
    /// remembered".
    pub fn contains(self: *const RangeSet, val: u64) bool {
        const items = self.ranges.items;
        if (items.len == 0) return false;
        // Lower-bound short-circuit: ranges are descending, the original loop
        // already exits when val > largest, but had no guard for val < smallest.
        // Adds one compare in the common case, eliminates an O(n) scan when the
        // peer references packet numbers older than anything we still track.
        if (val < items[items.len - 1].start) return false;
        for (items) |r| {
            if (val > r.end) return false;
            if (r.contains(val)) return true;
        }
        return false;
    }

    /// Adds `val`, merging it into whichever ranges touch it.
    ///
    /// `error.OutOfMemory` leaves the set exactly as it was: the append and
    /// the merge are one step, and the step that can fail runs before
    /// anything is written. `len` may not grow at all, since a value
    /// adjacent to an existing range extends it instead.
    pub fn add(self: *RangeSet, val: u64) !void {
        try self.addRange(val, val);
    }

    /// Adds every value in `[start, end]`, merging with any range that
    /// touches or abuts it. `start > end` is an empty span and succeeds
    /// without touching the set; the same `error.OutOfMemory` leaves the set
    /// unchanged.
    pub fn addRange(self: *RangeSet, start: u64, end: u64) !void {
        if (start > end) return;

        const items = self.ranges.items;

        if (items.len == 0) {
            try self.ranges.append(self.allocator, .{ .start = start, .end = end });
            return;
        }

        // Find insertion point (ranges are in descending order by start)
        var insert_idx: usize = items.len;
        for (items, 0..) |r, i| {
            if (end >= r.start) {
                insert_idx = i;
                break;
            }
        }

        // Check if we can extend an existing range or need to insert new
        var merge_start = insert_idx;
        var merge_end = insert_idx; // exclusive
        var new_start = start;
        var new_end = end;

        // Look for ranges to merge with
        for (items[insert_idx..], insert_idx..) |r, i| {
            if (new_start > r.end + 1) break; // gap too large, no more merges
            merge_end = i + 1;
            if (r.start < new_start) new_start = r.start;
            if (r.end > new_end) new_end = r.end;
        }

        // Also check the range before insert_idx for adjacency
        if (merge_start > 0) {
            const prev = items[merge_start - 1];
            if (new_end + 1 >= prev.start) {
                merge_start -= 1;
                if (prev.end > new_end) new_end = prev.end;
                if (prev.start < new_start) new_start = prev.start;
            }
        }

        // Replace merged ranges with the new combined range
        if (merge_start < merge_end) {
            items[merge_start] = .{ .start = new_start, .end = new_end };
            // Remove extra merged ranges
            if (merge_end - merge_start > 1) {
                const remove_count = merge_end - merge_start - 1;
                const rest = items[merge_start + 1 + remove_count ..];
                @memmove(items[merge_start + 1 ..][0..rest.len], rest);
                self.ranges.shrinkRetainingCapacity(items.len - remove_count);
            }
        } else {
            // Insert new range at the right position
            try self.ranges.insert(self.allocator, insert_idx, .{ .start = new_start, .end = new_end });
        }
    }

    /// Drops every value strictly below `val`; `val` itself and everything
    /// above it are kept. Shrinks the backing array without releasing it, so
    /// the memory a large set held stays with the set until `deinit`.
    pub fn removeBelow(self: *RangeSet, val: u64) void {
        const items = self.ranges.items;
        if (items.len == 0) return;

        // Ranges are in descending order. Iterate from the end (smallest first)
        // and remove/trim as needed.
        var new_len: usize = items.len;
        var i: usize = items.len;
        while (i > 0) {
            i -= 1;
            if (items[i].end < val) {
                // Entirely below val - remove
                new_len = i;
            } else if (items[i].start < val) {
                // Partially overlapping - trim and stop
                items[i].start = val;
                break;
            } else {
                // Entirely above val - stop
                break;
            }
        }

        if (new_len < items.len) {
            self.ranges.shrinkRetainingCapacity(new_len);
        }
    }

    /// The ranges, descending, largest first. The slice points into the set's
    /// own array and is invalidated by `add`, `addRange` and `removeBelow`;
    /// it is not invalidated by any read.
    pub fn getRanges(self: *const RangeSet) []const Range {
        return self.ranges.items;
    }
};

// Tests

test "RangeSet: add single values" {
    var rs = RangeSet.init(testing.allocator);
    defer rs.deinit();

    try rs.add(5);
    try testing.expectEqual(@as(usize, 1), rs.len());
    try testing.expectEqual(@as(u64, 5), rs.largest().?);

    try rs.add(3);
    try testing.expectEqual(@as(usize, 2), rs.len());

    // Add adjacent - should merge
    try rs.add(4);
    try testing.expectEqual(@as(usize, 1), rs.len());
    try testing.expectEqual(@as(u64, 3), rs.smallest().?);
    try testing.expectEqual(@as(u64, 5), rs.largest().?);
}

test "RangeSet: add merges overlapping" {
    var rs = RangeSet.init(testing.allocator);
    defer rs.deinit();

    try rs.addRange(1, 3);
    try rs.addRange(7, 9);
    try testing.expectEqual(@as(usize, 2), rs.len());

    // Bridge the gap
    try rs.addRange(4, 6);
    try testing.expectEqual(@as(usize, 1), rs.len());
    try testing.expectEqual(@as(u64, 1), rs.smallest().?);
    try testing.expectEqual(@as(u64, 9), rs.largest().?);
}

test "RangeSet: contains" {
    var rs = RangeSet.init(testing.allocator);
    defer rs.deinit();

    try rs.addRange(3, 7);
    try rs.addRange(10, 15);

    try testing.expect(rs.contains(3));
    try testing.expect(rs.contains(5));
    try testing.expect(rs.contains(7));
    try testing.expect(!rs.contains(8));
    try testing.expect(!rs.contains(9));
    try testing.expect(rs.contains(10));
    try testing.expect(rs.contains(15));
    try testing.expect(!rs.contains(16));
    try testing.expect(!rs.contains(2));
}

test "RangeSet: removeBelow" {
    var rs = RangeSet.init(testing.allocator);
    defer rs.deinit();

    try rs.addRange(1, 3);
    try rs.addRange(5, 8);
    try rs.addRange(10, 15);

    rs.removeBelow(6);
    // Range [1,3] removed entirely, [5,8] trimmed to [6,8], [10,15] unchanged
    try testing.expectEqual(@as(usize, 2), rs.len());
    try testing.expectEqual(@as(u64, 6), rs.smallest().?);
}

test "RangeSet: ascending inserts (packet number pattern)" {
    var rs = RangeSet.init(testing.allocator);
    defer rs.deinit();

    // Simulate receiving packets 0, 1, 2, 3, 4 in order
    try rs.add(0);
    try rs.add(1);
    try rs.add(2);
    try rs.add(3);
    try rs.add(4);

    try testing.expectEqual(@as(usize, 1), rs.len());
    try testing.expectEqual(@as(u64, 0), rs.smallest().?);
    try testing.expectEqual(@as(u64, 4), rs.largest().?);
}

test "RangeSet: out-of-order with gaps" {
    var rs = RangeSet.init(testing.allocator);
    defer rs.deinit();

    // Simulate out-of-order: 0, 2, 4 (gaps at 1, 3)
    try rs.add(0);
    try rs.add(2);
    try rs.add(4);
    try testing.expectEqual(@as(usize, 3), rs.len());

    // Fill gap at 1
    try rs.add(1);
    try testing.expectEqual(@as(usize, 2), rs.len());

    // Fill gap at 3
    try rs.add(3);
    try testing.expectEqual(@as(usize, 1), rs.len());
}
