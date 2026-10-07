//! What one resolve attempt came to, with "cannot resolve at all" and
//! "resolved to nothing" kept apart.
//!
//! `docs/ARCHITECTURE.md` invariant 13 is the authority on why the two are
//! different arms, and `discovery/resolve.zig` builds the handle this is
//! yielded through. It is its own module rather than part of
//! `discovery/item_record.zig` because it is not a property of a result: it is
//! a fact about one attempt, and the record it carries is borrowed from
//! whoever produced it. A caller holding a `Resolution` has been told something
//! about the *lookup*, not about a node.
//!
//! # The conflation this exists to stop
//!
//! There is deliberately no `items` accessor, and the doc on `itemCount` says
//! why: handing back an empty slice for `cannot_resolve` would collapse "this
//! service will not answer for this node id at all" into "the service was
//! asked and the world had nothing in it". The test below is the guard on that
//! — it checks both accessors, both arms, and a third state that is neither.

const std = @import("std");
const record = @import("item_record.zig");
const fixture = @import("item_fixture.zig");
const t = std.testing;

/// What one resolve attempt came to.
///
/// The arms are different facts about the world and must not be collapsed.
/// `cannot_resolve` is "this service will not answer for this node id at all":
/// no work started, nothing to cancel, no error either. `resolved` is "the
/// service was asked and finished", and its items may be empty, because a
/// node that has published nothing is a fact about the network rather than a
/// failure to go looking.
///
/// The later stream carries the same distinction in the same shape. `resolve`
/// hands back an optional owning handle: null for `cannot_resolve`, otherwise
/// a stream of items that ends by yielding this value. A stream that ends with
/// an empty `resolved` resolved to nothing; a null stream never resolved at
/// all. Dropping either cancels the service's work, which is invariant 13 and
/// the reason the handle owns its stream instead of handing out an iterator.
pub const Resolution = union(enum) {
    cannot_resolve,
    /// The items the attempt produced, borrowed from whoever produced them.
    resolved: []const record.Item,

    /// How many items came back, or null when nothing was ever asked. There
    /// is deliberately no `items` accessor here: handing back an empty slice
    /// for `cannot_resolve` is exactly the conflation this type exists to
    /// stop, and one accessor is all it takes to bring it back.
    pub fn itemCount(self: Resolution) ?usize {
        return switch (self) {
            .cannot_resolve => null,
            .resolved => |items| items.len,
        };
    }

    /// True only for a service that answered and had nothing to say. A
    /// service that would not answer at all is not an empty result.
    pub fn isEmptyResult(self: Resolution) bool {
        return switch (self) {
            .cannot_resolve => false,
            .resolved => |items| items.len == 0,
        };
    }
};

test "cannot resolve is not resolved to nothing" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const addresses = try fixture.pool();
    const cannot: Resolution = .cannot_resolve;
    const nothing: Resolution = .{ .resolved = &.{} };

    // Both are "no items" to a caller that only counts, and the type is the
    // only thing telling them apart. That is the entire reason it exists.
    try t.expectEqual(@as(?usize, null), cannot.itemCount());
    try t.expectEqual(@as(?usize, 0), nothing.itemCount());
    try t.expect(!cannot.isEmptyResult());
    try t.expect(nothing.isEmptyResult());
    try t.expect(std.meta.activeTag(cannot) != std.meta.activeTag(nothing));

    // A service that answered with something is neither of those.
    const item = try fixture.single(alloc, (try fixture.corpusIds())[0], addresses[0], .dns, 1);
    const answered: Resolution = .{ .resolved = try alloc.dupe(record.Item, &.{item}) };
    try t.expectEqual(@as(?usize, 1), answered.itemCount());
    try t.expect(!answered.isEmptyResult());
}
