//! The answer over a *set* of discovery results: which one wins, and what the
//! distinct ones are once every service has answered.
//!
//! This is the third question `discovery/item.zig` used to answer in one file.
//! `discovery/item_record.zig` asks what one result is and how two compare;
//! this module asks what a pile of them comes to. The split is the difference
//! between a comparator and a merge, and it matters because those change for
//! different reasons — `Item.order` has to track what a service reports, while
//! the deduplication below has to track what "the same fact said twice" means.
//!
//! # One comparator, and this is its only caller-facing half
//!
//! `winner` is the one place the tree asks which of two results wins, and
//! `merge` is the one place a list of them is sorted and deduplicated. Both
//! read `Item.order` and neither has an opinion of its own: the docs on the
//! two say so, and the tests below are the evidence. A caller that reached for
//! `merged[0]` instead of `winner` would be stating the sort direction a second
//! time, which is exactly what `discovery/dial_source_walk.zig`'s doc refuses
//! to do.
//!
//! # Where the tests moved and why
//!
//! The two order tests that also drive `winner` and `merge` — "the tiebreak is
//! the address value order, not the encoded record" and "two items differing
//! only in provenance order deterministically" — live here rather than beside
//! `Item.order`, because they are the tests that would catch `winner` and
//! `merge` disagreeing with the comparator they call. `Item.order`'s own
//! properties stayed with the type in `discovery/item_record.zig`.

const std = @import("std");
const addr = @import("../base/addr.zig");
const record = @import("item_record.zig");
const fixture = @import("item_fixture.zig");
const resolution = @import("item_resolution.zig");
const t = std.testing;

/// The best item of `items`, or null when there is none. The one place a merge
/// asks which of two results wins, so nothing else needs an opinion of its own.
///
/// Returns a copy of that item, not a reference to it, and the copy is as
/// shallow as `Item` is: it borrows the winner's address list, so reading it
/// after the list is released reads freed memory.
pub fn winner(items: []const record.Item) ?record.Item {
    var best: ?record.Item = null;
    for (items) |item| {
        const held = best orelse {
            best = item;
            continue;
        };
        best = if (item.order(held) == .gt) item else held;
    }
    return best;
}

/// Every distinct item of `items`, best first, in storage this call allocates
/// from `alloc` and the caller releases with `alloc.free`.
///
/// Not a second precedence rule: this is the input sorted and deduplicated
/// under `Item.order`, so it is the same answer whatever order the sources
/// answered in. Two items that compare `.eq` are equal in every field, which
/// is what makes dropping one of them drop nothing.
///
/// Only the array is new. Every `Item` in it is a shallow copy of an input, so
/// the merged list owns no address and releases none: `alloc.free` hands back
/// the array alone, and the merged list is dead as soon as the addresses behind
/// its items are — which for items out of a resolve is when that stream is
/// closed. A caller that wants the merge to outlive them copies each address
/// list out first.
///
/// `error.OutOfMemory` allocates nothing that survives: the sorted copy is
/// released before the error leaves, and the output array was never built.
pub fn merge(
    alloc: std.mem.Allocator,
    items: []const record.Item,
) std.mem.Allocator.Error![]record.Item {
    const sorted = try alloc.dupe(record.Item, items);
    defer alloc.free(sorted);
    std.mem.sort(record.Item, sorted, {}, bestFirst);

    var distinct: usize = 0;
    for (sorted, 0..) |item, at| {
        if (at == 0 or !sorted[at - 1].eql(item)) distinct += 1;
    }
    const merged = try alloc.alloc(record.Item, distinct);
    var at: usize = 0;
    for (sorted) |item| {
        if (at == 0 or !merged[at - 1].eql(item)) {
            merged[at] = item;
            at += 1;
        }
    }
    return merged;
}

/// `std.mem.sort` takes a free function, not a method, and a merged list is
/// read from the front, so the best item has to sort first. Descending is not
/// a second opinion about precedence: it is the same total order, pointed the
/// way the caller reads it.
fn bestFirst(_: void, a: record.Item, b: record.Item) bool {
    return a.order(b) == .gt;
}

test "the tiebreak is the address value order, not the encoded record" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const addresses = try fixture.pool();
    const id = (try fixture.corpusIds())[0];

    // The last four pool entries are two pairs whose length order and
    // lexical order disagree, one of relays and one of custom addresses: in
    // each pair the longer value is the lexically lower one. A record writes
    // the length before the bytes, so a comparator that reads records ranks
    // each pair the other way round from `TransportAddr.order` — the order
    // `NodeAddr.insert` sorts a list with and a ticket writes its addresses
    // in. A merge that picked the other one would hand a caller a relay that
    // every other sorted list in ozai ranks below its rival.
    inline for (.{ 11, 13 }) |index| {
        const lower = addresses[index];
        const higher = addresses[index + 1];
        try t.expectEqual(std.math.Order.lt, lower.order(higher));

        const first = try fixture.single(alloc, id, lower, .pkarr, 5);
        const second = try fixture.single(alloc, id, higher, .pkarr, 5);
        try t.expectEqual(std.math.Order.lt, first.order(second));
        try t.expectEqual(std.math.Order.gt, second.order(first));

        // Both ways round: the two entry points a caller reaches for are
        // handed the answers in whatever order its services replied, and a
        // winner that depended on that would be a flap waiting for a retry.
        try t.expect(second.eql(winner(&.{ first, second }).?));
        try t.expect(second.eql(winner(&.{ second, first }).?));

        const merged = try merge(alloc, &.{ first, second });
        defer alloc.free(merged);
        try t.expectEqual(@as(usize, 2), merged.len);
        try t.expect(merged[0].eql(second));
        try t.expectEqual(std.math.Order.gt, merged[0].order(merged[1]));

        // The list a caller sorts with `insert` agrees, because it is the same
        // order: the address the merge picked is the one that lands last.
        var both = addr.NodeAddr.init(id);
        if (try both.insert(alloc, lower)) |next| both = next;
        if (try both.insert(alloc, higher)) |next| both = next;
        try t.expectEqual(@as(usize, 2), both.addrs.len);
        try t.expectEqual(std.math.Order.lt, both.addrs[0].order(both.addrs[1]));
        try t.expectEqual(std.math.Order.eq, both.addrs[1].order(higher));
    }
}

test "two items differing only in provenance order deterministically" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const addresses = try fixture.pool();
    const id = (try fixture.corpusIds())[0];
    const dns = try fixture.single(alloc, id, addresses[3], .dns, 42);
    const pkarr = try fixture.single(alloc, id, addresses[3], .pkarr, 42);
    const memory = try fixture.single(alloc, id, addresses[3], .memory_lookup, 42);

    try t.expectEqual(std.math.Order.lt, dns.order(pkarr));
    try t.expectEqual(std.math.Order.lt, pkarr.order(memory));
    try t.expectEqual(std.math.Order.lt, dns.order(memory));
    // Not a tie: same address, same stamp, different source is a different
    // item, and every permutation of the three has to pick the same one.
    try t.expect(!dns.eql(pkarr));
    try t.expect(!pkarr.eql(memory));
    // Every pair, in both directions, and through a merge, so the choice is
    // the same one whichever of the two sources a caller happens to list
    // first.
    inline for (record.Provenance.all) |left| {
        inline for (record.Provenance.all) |right| {
            const first = try fixture.single(alloc, id, addresses[3], left, 42);
            const second = try fixture.single(alloc, id, addresses[3], right, 42);
            const better = @max(left.rank(), right.rank());
            try t.expectEqual(better, winner(&.{ first, second }).?.provenance.rank());
            try t.expectEqual(better, winner(&.{ second, first }).?.provenance.rank());
        }
    }
}

test "merge keeps the winner and does not care what order the sources answered in" {
    const items = try fixture.corpus(t.allocator, 24);
    defer fixture.freeItems(t.allocator, items);

    const expected = try merge(t.allocator, items);
    defer t.allocator.free(expected);
    try t.expect(expected.len > 0);
    // Best first, and the best is the one `winner` names.
    try t.expect(expected[0].eql(winner(items).?));
    var at: usize = 1;
    while (at < expected.len) : (at += 1) {
        try t.expectEqual(std.math.Order.gt, expected[at - 1].order(expected[at]));
    }
    // The corpus holds a guaranteed equal pair, so the deduplication below is
    // doing something the permutation check can then be said to preserve.
    try t.expect(expected.len < items.len);

    var prng = std.Random.DefaultPrng.init(0x7065_726d);
    const random = prng.random();
    var round: usize = 0;
    while (round < 16) : (round += 1) {
        const shuffled = try t.allocator.dupe(record.Item, items);
        defer t.allocator.free(shuffled);
        var pick = shuffled.len;
        while (pick > 1) {
            pick -= 1;
            const swap = random.intRangeLessThan(usize, 0, pick + 1);
            std.mem.swap(record.Item, &shuffled[pick], &shuffled[swap]);
        }
        const again = try merge(t.allocator, shuffled);
        defer t.allocator.free(again);
        try t.expectEqual(expected.len, again.len);
        for (expected, again) |left, right| try t.expect(left.eql(right));
    }
}

test "an empty result set has an answer, and the answer is none" {
    const merged = try merge(t.allocator, &.{});
    defer t.allocator.free(merged);
    try t.expectEqual(@as(usize, 0), merged.len);
    try t.expect(winner(&.{}) == null);
    const empty: resolution.Resolution = .{ .resolved = &.{} };
    try t.expectEqual(@as(?usize, 0), empty.itemCount());
}
