//! Merging what several address lookups answered into one answer.
//!
//! This is the merge `discovery/resolve.zig`'s module doc names as the one
//! thing that file leaves out: upstream's `AddressLookupServices`
//! (`iroh/src/address_lookup.rs:565`), a list of services and a merge over
//! whatever they answer. `discovery/dial_source_walk.zig` runs the sources and
//! holds the walk's four answers; this module is what a run comes to once
//! every source has reported. It starts nothing, stops nothing and opens
//! nothing, so it is a function over two lists.
//!
//! Nothing here is wired into the walk yet. The walk carries its own tally of
//! `first_failure` and its own `Result`, and this module is the answer for a
//! caller that wants the merged set, the disagreement in it and the count of
//! sources that produced nothing to say, all in one value.
//!
//! # A source that failed is not a source that had nothing
//!
//! **They stay apart, and the merge is the place that keeps them apart.**
//!
//! `item.Resolution` already holds "will not resolve at all" apart from
//! "resolved to nothing", and `lookup_io.zig`'s module doc holds a third fact
//! apart from both: `lookup_answer.Answer.timeout`, the question that went out
//! and nothing answered in time. Three facts, three arms, and the reason is in
//! `discovery/dns_live.zig`'s words — a single failing service must not hide
//! results from the sources still in flight (`iroh/src/address_lookup.rs:584`).
//!
//! Collapsing a failure onto "nothing" is what that sentence forbids, and it
//! is not a type error: both arrive with an empty item list, so a merge that
//! counted items would report a node that published nothing for a node nobody
//! managed to ask. So:
//!
//! * `Report.failed` is its own arm and carries the `lookup.Failure` that says
//!   which source and why.
//! * `Tally` counts `empty` and `failed` separately, and `Tally.unresolved` is
//!   the sum that separates `Outcome.nothing` from `Outcome.incomplete`.
//! * `Outcome.incomplete` is reported for a merge that found no item while any
//!   source was unresolved, so "found nothing" and "could not find out" reach
//!   a caller as different answers.
//!
//! **The merge never inspects the reason.** That is what makes the rule hold
//! for a reason the tree does not have an arm for yet: `lookup_io.zig` records
//! that a timeout needs `resolve.Reason.TimedOut` and does not own it, so a
//! slow nameserver currently has no `Reason` to travel under. This module keys
//! on *whether a fact arrived*, not on which fact failed, so it is correct for
//! a timeout today and stays correct when `Reason` grows the arm.
//!
//! # Two sources that disagree are a fact about one of the two
//!
//! **Neither preference, nor recency, nor refusal: the merge reports it and
//! keeps both.**
//!
//! An address a peer published in two places that disagree is a fact about one
//! of the two publishers. Whichever it is, nothing here knows which, and each
//! of the three available answers picks a side without evidence:
//!
//! * **By preference.** `item.Provenance.rank` is the *last* tiebreak of
//!   `Item.order`, for the pair that differs in nothing else. Using it to pick
//!   between two different address lists would promote "which relay carried
//!   this" into "which address is true", and `discovery/dial_source_walk.zig`
//!   refuses exactly that: a second comparator is a second answer to a
//!   question `discovery/item.zig` has already answered, and the two disagree
//!   the first time a service reports a stale address.
//! * **By recency.** `last_updated` is the *first* component of `Item.order`,
//!   and both upstream services pass `None` to `AddressLookupItem::new`
//!   (`iroh/src/address_lookup/pkarr.rs:546` and `address_lookup/dns.rs:130`),
//!   which `discovery/dial_source_walk.zig`'s doc records. A recency rule is
//!   therefore dead in production and live only in tests, where a stamped item
//!   would win for a reason no shipped source can produce. Null is
//!   infinitely old (`Item.order`), so an unstamped pair falls through to the
//!   address value order and the winner is whichever relay URL sorts lower.
//! * **By refusing.** Two publishers disagreeing is not "cannot resolve at
//!   all". Returning an error would abandon a node that one of the two named
//!   correctly, and `invariant 13`'s whole content is that those two answers
//!   are not the same answer.
//!
//! So a disagreement becomes a value: `Conflict` names the node, how many
//! distinct address lists were published for it, and the two ends of
//! `Item.order` over that node's reports. The caller dials, logs or retries as
//! its policy says, and the merge stays the one place that decides nothing.
//!
//! **Agreement is not a conflict.** Two services reporting one address is the
//! ordinary case — `discovery/dial_source_walk.zig`'s doc calls it agreement
//! rather than a conflict, and `merge` keeps both items because provenance is
//! not a dedup key. The conflict test is the *address list*, so a disagreement
//! about freshness alone is not a conflict either: that is `Item.order`'s
//! question and its answer, not this module's.
//!
//! # Order independence, by construction
//!
//! The sort and the deduplication are `discovery/item_merge.zig`'s, reached
//! through `item.merge`, and the best item is `item.winner`. This module holds
//! no comparator of its own, so the merged set does not depend on which source
//! spoke first — the property `discovery/item_merge.zig` already tests and the
//! one a caller re-asks here with the reports in a different order.
//!
//! # Ownership
//!
//! `items` and `conflicts` are this call's arrays, allocated from `alloc` and
//! released by `Fanin.deinit` with the same allocator. Every `Item` in them is
//! a shallow copy of an input, so a merged set owns no address and releases
//! none; it is dead as soon as the streams behind the reports are closed, which
//! is `resolve.Stream`'s contract. `alloc` may be an arena.

const std = @import("std");
const addr = @import("../base/addr.zig");
const item = @import("item.zig");
const lookup = @import("lookup.zig");
const fixture = @import("item_fixture.zig");

const t = std.testing;

/// What one source came to, as a fact about that source.
///
/// The arms are the facts `discovery/lookup_io.zig` and
/// `discovery/item_resolution.zig` hold apart, at the level of a whole source
/// rather than a whole attempt: `refused` is "will not resolve for this node at
/// all", `empty` is "asked, ran, had nothing to say", `failed` is "asked, and
/// produced answers that were not items", and `answered` is the rest.
pub const Report = union(enum) {
    /// The source will not resolve for this node id at all. `null` from
    /// `resolve.AddressLookup.resolve`, which is upstream's trait default
    /// (`iroh/src/address_lookup.rs:343`) and what `PkarrPublisher` returns.
    ///
    /// **A claim about the configuration rather than about the node**, and not
    /// an error to report: `discovery/dial_source_walk.zig` stops the walk on
    /// it for exactly that reason. This merge runs after every source has
    /// reported, so there is nothing left to abandon, and it keeps the refusal
    /// visible through `Tally.refused` and `Outcome.incomplete` instead.
    refused,
    /// Asked, ran, and had nothing to say. A fact about the world: every
    /// source that could answer had a node that published nothing.
    empty,
    /// Asked, and produced one or more answers that were not items. The
    /// failure names the source and the reason, and the stream carried on past
    /// it (`iroh/src/address_lookup.rs:584`).
    failed: lookup.Failure,
    /// Asked, and produced these items. **Non-empty**: an answer with nothing
    /// in it is `.empty`, and `fromResolution` is what keeps the two apart.
    /// The items belong to whoever produced them and are borrowed here.
    answered: []const item.Item,

    /// How many items this source produced, or null when it was never asked to
    /// produce any. Null and zero are different answers, and `Report` has no
    /// accessor that would hand back an empty slice for the first — that is
    /// `item.Resolution`'s rule and it is copied here whole, not re-derived.
    pub fn itemCount(self: Report) ?usize {
        return switch (self) {
            .refused => null,
            .empty => 0,
            .failed => 0,
            .answered => |items| items.len,
        };
    }

    /// The failure this source recorded, or null when it produced an answer.
    ///
    /// One failure and not a list, because a source's answers are its own and
    /// a merge cannot put them in a better order; `Fanin.first_failure` is the
    /// first across the sources, in the order they were reported.
    pub fn failure(self: Report) ?lookup.Failure {
        return switch (self) {
            .failed => |value| value,
            else => null,
        };
    }
};

/// What a whole attempt came to, turned into what one source came to.
///
/// The mapping is the whole of the function, and it is where `cannot_resolve`
/// stops being a missing value and becomes an arm: a caller that merged
/// reports by counting items would read a refusal as "had nothing", which is
/// the conflation `discovery/item_resolution.zig` exists to stop.
pub fn fromResolution(value: item.Resolution) Report {
    return switch (value) {
        .cannot_resolve => .refused,
        .resolved => |items| if (items.len == 0) .empty else .{ .answered = items },
    };
}

/// How many sources said what, as the merge counts them.
///
/// Four counts and no list, because the whole question this table answers is
/// which arm of `Outcome` the merge lands on, and that is a count of sources
/// rather than a record of them.
pub const Tally = struct {
    /// Sources that produced at least one item.
    answered: usize,
    /// Sources that were asked and had nothing to say.
    empty: usize,
    /// Sources that will not resolve for this node id at all.
    refused: usize,
    /// Sources that were asked and produced no item because an answer was not
    /// one. A timeout, a packet that would not decode, an unexpected signer.
    failed: usize,

    /// Sources that produced no fact about the node: everything except an
    /// answer and an emptiness. Zero is what makes `Outcome.nothing` honest,
    /// and any other value is what makes it `incomplete`.
    pub fn unresolved(self: Tally) usize {
        return self.refused + self.failed;
    }

    /// How many sources reported at all, for the arithmetic a caller does when
    /// it logs one line per merge.
    pub fn reported(self: Tally) usize {
        return self.answered + self.empty + self.refused + self.failed;
    }
};

/// Which answer a merge came to. Three arms and no fourth.
pub const Outcome = enum {
    /// At least one item was found. Whether other sources failed is not lost:
    /// it is in `Tally` and in `Fanin.first_failure`, and it does not change
    /// that an address is in hand.
    answered,
    /// No item was found and every source that could answer had nothing to
    /// say. A fact about the world.
    nothing,
    /// No item was found and at least one source was unresolved — it refused,
    /// or it never produced an item. **Not "the node published nothing"**:
    /// nobody established that, and `Tally` says who to ask again.
    incomplete,
};

/// One node id that two sources described differently.
pub const Conflict = struct {
    /// The node both sources were talking about.
    node_id: addr.NodeId,
    /// How many different address lists were published for it. At least two,
    /// which is what makes this a conflict rather than agreement.
    distinct: usize,
    /// How many reports carried it, agreement included. Greater than `distinct`
    /// when a third source agreed with one of the two.
    reports: usize,
    /// The report that wins `Item.order` for this node, and the one that loses
    /// it. Shallow copies of inputs, so they die with the reports' streams.
    ///
    /// **The ends of a total order and not "the right answer and the wrong
    /// answer"**, because the merge does not know which is which. They differ in
    /// their address lists whenever exactly two address lists were published,
    /// and their `provenance` fields then name the two publishers the
    /// disagreement is about. A third source that agreed with one of them and
    /// carries a stamp of its own is an end like any other, so the extremes
    /// are over every report on the node rather than over the disagreeing pair.
    best: item.Item,
    worst: item.Item,
};

/// What several sources came to, as one value.
pub const Fanin = struct {
    /// Which answer the merge came to. See `Outcome`.
    outcome: Outcome,
    /// Every distinct item, best first, as `item.merge` leaves it. Owned
    /// array; the items themselves are borrows.
    items: []item.Item,
    /// Every node id the sources described differently, in the order the best
    /// item for each was met. Owned array; the items inside are borrows.
    conflicts: []Conflict,
    /// How many sources said what.
    tally: Tally,
    /// The first answer that was not an item, in the order the sources were
    /// reported. The first and not a summary, so a merge that dialled after a
    /// bad packet is distinguishable from one that did not.
    first_failure: ?lookup.Failure,

    /// The best item of the merged set, or null when there is none.
    /// `item.winner` and not `items[0]`: the sort direction is stated once.
    pub fn best(self: Fanin) ?item.Item {
        return item.winner(self.items);
    }

    /// How many items the merge found.
    pub fn itemCount(self: Fanin) usize {
        return self.items.len;
    }

    /// True only for a merge in which every source that could answer had
    /// nothing to say. A merge that found nothing and does not know why is
    /// `incomplete`, and this accessor is what keeps the two apart.
    pub fn isEmptyResult(self: Fanin) bool {
        return self.outcome == .nothing;
    }

    /// The conflict on `node_id`, or null when the sources agreed on it. A
    /// lookup and not an allocation, so a caller can ask about one node after
    /// deciding what to do with the set.
    pub fn conflict(self: Fanin, node_id: addr.NodeId) ?Conflict {
        for (self.conflicts) |value| {
            if (value.node_id.order(node_id) == .eq) return value;
        }
        return null;
    }

    /// Hand back the two arrays this call allocated. Every item in them is a
    /// shallow copy, so nothing else is released here.
    pub fn deinit(self: Fanin, alloc: std.mem.Allocator) void {
        alloc.free(self.items);
        alloc.free(self.conflicts);
    }
};

/// Merge what every source reported into one answer.
///
/// `alloc` may be an arena. Every allocation is the two arrays in `Fanin`, and
/// `error.OutOfMemory` leaves neither behind.
///
/// The reports are borrowed, and their items stay borrowed: the merged set is
/// dead when the streams behind them are closed, which is
/// `resolve.Stream`'s contract and not this function's to extend.
pub fn merge(
    alloc: std.mem.Allocator,
    reports: []const Report,
) std.mem.Allocator.Error!Fanin {
    var tally: Tally = .{ .answered = 0, .empty = 0, .refused = 0, .failed = 0 };
    var first_failure: ?lookup.Failure = null;
    // Flattened first because `item.merge` is handed one set, and held in an
    // `ArrayList` rather than counted twice so a source with many items costs
    // one growth and not one allocation per item.
    var found: std.ArrayList(item.Item) = .empty;
    defer found.deinit(alloc);

    for (reports) |report| switch (report) {
        .refused => tally.refused += 1,
        .empty => tally.empty += 1,
        .failed => |failure| {
            tally.failed += 1;
            // The first and not the last: the reports arrive in the order the
            // walk asked the sources, and that order is the whole of what is
            // known about which failure a caller saw first.
            if (first_failure == null) first_failure = failure;
        },
        .answered => |items| {
            tally.answered += 1;
            try found.appendSlice(alloc, items);
        },
    };

    // The one sort and the one deduplication in the tree, reached through the
    // facade rather than copied, so a merge here cannot disagree with
    // `discovery/dial_source_walk.zig`'s.
    const items = try item.merge(alloc, found.items);
    errdefer alloc.free(items);
    const conflicts = try findConflicts(alloc, items);
    errdefer alloc.free(conflicts);

    return .{
        .outcome = outcomeFor(items.len, tally),
        .items = items,
        .conflicts = conflicts,
        .tally = tally,
        .first_failure = first_failure,
    };
}

/// The one place the three outcomes are told apart.
///
/// `items` and not `tally.answered`, because the items are the evidence: a
/// report written as `.answered` with nothing in it contributes no fact and
/// must not be read as an answer.
fn outcomeFor(item_count: usize, tally: Tally) Outcome {
    if (item_count > 0) return .answered;
    if (tally.unresolved() > 0) return .incomplete;
    return .nothing;
}

/// Every node id the sources described differently, and what they said about
/// it.
///
/// One pass over the merged set and a nested walk per node id, because the set
/// is one node in production — `dial_source_walk.Request.node_id` is a single
/// `addr.NodeId` — and an allocation per node would cost more than the scan it
/// saves.
fn findConflicts(
    alloc: std.mem.Allocator,
    items: []const item.Item,
) std.mem.Allocator.Error![]Conflict {
    var found: std.ArrayList(Conflict) = .empty;
    errdefer found.deinit(alloc);
    for (items, 0..) |value, index| {
        // One place per node id, and the node's first item in the merged order
        // is where its conflict is recorded, so the array is ordered by the
        // same total order the items are.
        if (!isFirstOfNode(items, index)) continue;
        const node_id = value.endpoint.node_id;
        const distinct = distinctEndpoints(items, node_id);
        if (distinct < 2) continue;
        const ends = extremesOfNode(items, node_id) orelse continue;
        try found.append(alloc, .{
            .node_id = node_id,
            .distinct = distinct,
            .reports = reportsOfNode(items, node_id),
            .best = ends.best,
            .worst = ends.worst,
        });
    }
    return found.toOwnedSlice(alloc);
}

/// Whether `items[index]` is the first report of its node id.
fn isFirstOfNode(items: []const item.Item, index: usize) bool {
    const node_id = items[index].endpoint.node_id;
    for (items[0..index]) |one| {
        if (one.endpoint.node_id.order(node_id) == .eq) return false;
    }
    return true;
}

/// How many different address lists `node_id` was published under. Agreement
/// does not add one: two services naming one address is one endpoint said
/// twice, which is why the test is the address list and not the item.
fn distinctEndpoints(items: []const item.Item, node_id: addr.NodeId) usize {
    var count: usize = 0;
    for (items, 0..) |value, index| {
        if (value.endpoint.node_id.order(node_id) != .eq) continue;
        if (!repeatsEndpoint(items[0..index], value)) count += 1;
    }
    return count;
}

/// How many reports carried `node_id`, agreement included.
fn reportsOfNode(items: []const item.Item, node_id: addr.NodeId) usize {
    var count: usize = 0;
    for (items) |value| {
        if (value.endpoint.node_id.order(node_id) == .eq) count += 1;
    }
    return count;
}

/// Whether any earlier report named the same node with the same address list.
///
/// `TransportAddr.order` and not `==`: an address list built in two different
/// buffers is the same list, and `discovery/dial_source_walk.zig` depends on
/// that spelling already.
fn repeatsEndpoint(earlier: []const item.Item, value: item.Item) bool {
    for (earlier) |one| {
        if (one.endpoint.node_id.order(value.endpoint.node_id) != .eq) continue;
        if (sameAddresses(one, value)) return true;
    }
    return false;
}

/// The two ends of `Item.order` over one node's reports. Null when the node is
/// not in the set, which cannot happen for a node the caller found there and is
/// still handled rather than assumed.
fn extremesOfNode(items: []const item.Item, node_id: addr.NodeId) ?Extremes {
    var best: ?item.Item = null;
    var worst: ?item.Item = null;
    for (items) |value| {
        if (value.endpoint.node_id.order(node_id) != .eq) continue;
        const held = best orelse {
            best = value;
            worst = value;
            continue;
        };
        // The extremes are over every report on the node, not over the
        // disagreeing pair: a third source that agreed with one of them and
        // carries a fresher stamp can be either end.
        if (value.order(held) == .gt) best = value;
        if (value.order(held) == .lt) worst = value;
    }
    const top = best orelse return null;
    return .{ .best = top, .worst = worst orelse top };
}

/// One node's two ends under the one order the tree has.
const Extremes = struct { best: item.Item, worst: item.Item };

/// Whether two reports named the same node with the same paths.
fn sameAddresses(left: item.Item, right: item.Item) bool {
    if (left.endpoint.addrs.len != right.endpoint.addrs.len) return false;
    for (left.endpoint.addrs, right.endpoint.addrs) |one, other| {
        if (one.order(other) != .eq) return false;
    }
    return true;
}

test "a failed source and an empty source are not the same report" {
    // The one conflation this module exists to stop, driven through the arms a
    // caller actually holds. Two reports, one that had nothing and one that
    // failed, and a merge that cannot report "this node published nothing"
    // because one of its two sources never answered the question.
    // No items are built here: the two reports under test are the arms and not
    // the arithmetic, so this merge allocates no address list to release.
    const empty: Report = .empty;

    const failed: Report = .{ .failed = .{
        .provenance = .dns,
        .reason = error.MalformedPacket,
    } };

    // With both reports, nothing was found and not everything was asked: the
    // two facts the merge keeps apart, in one value.
    const merged = try merge(t.allocator, &.{ empty, failed });
    defer merged.deinit(t.allocator);
    try t.expectEqual(Outcome.incomplete, merged.outcome);
    try t.expectEqual(@as(usize, 0), merged.itemCount());
    try t.expect(!merged.isEmptyResult());
    try t.expectEqual(@as(usize, 2), merged.tally.reported());
    try t.expectEqual(@as(usize, 1), merged.tally.empty);
    try t.expectEqual(@as(usize, 1), merged.tally.failed);
    try t.expectEqual(@as(usize, 1), merged.tally.unresolved());
    // The failure is named and not summarised: which source, and why.
    const named = merged.first_failure orelse return error.TestUnexpectedResult;
    try t.expectEqual(item.Provenance.dns, named.provenance);
    try t.expectEqual(error.MalformedPacket, named.reason);

    // The same two reports with the failure dropped. Now every source that
    // could answer had nothing to say, which is a fact about the world, and it
    // is a different answer from the one above rather than a quieter one.
    const quiet = try merge(t.allocator, &.{empty});
    defer quiet.deinit(t.allocator);
    try t.expectEqual(Outcome.nothing, quiet.outcome);
    try t.expect(quiet.isEmptyResult());
    try t.expectEqual(@as(usize, 0), quiet.tally.unresolved());
    try t.expect(quiet.first_failure == null);

    // And the source that refused is a third fact, not a failure to report: it
    // is counted apart, it is not in `first_failure`, and it still stops the
    // merge claiming emptiness.
    const refused = try merge(t.allocator, &.{ empty, .refused });
    defer refused.deinit(t.allocator);
    try t.expectEqual(Outcome.incomplete, refused.outcome);
    try t.expectEqual(@as(usize, 1), refused.tally.refused);
    try t.expectEqual(@as(usize, 0), refused.tally.failed);
    try t.expect(refused.first_failure == null);
}

test "cannot resolve and resolved to nothing arrive as different reports" {
    // `fromResolution` is the seam, so the distinction survives the trip from
    // one attempt to one source. A missing item count is what a refused source
    // has and an empty one does not, exactly as `item.Resolution` says.
    const refused: Report = fromResolution(.cannot_resolve);
    const empty: Report = fromResolution(.{ .resolved = &.{} });
    try t.expectEqual(@as(?usize, null), refused.itemCount());
    try t.expectEqual(@as(?usize, 0), empty.itemCount());
    try t.expect(std.meta.activeTag(refused) != std.meta.activeTag(empty));
    // A refusal is not a failure to report, so it has none to hand back.
    try t.expect(refused.failure() == null);
    try t.expect(empty.failure() == null);
    // A refused source contributes no failure, so merging one leaves the
    // failure count at zero. The merge is released rather than dropped: it
    // owns the two arrays, and `t.allocator` names a leak at the end of the
    // test if a caller forgets.
    const refused_merge = try merge(t.allocator, &.{ refused, empty });
    defer refused_merge.deinit(t.allocator);
    try t.expectEqual(@as(usize, 0), refused_merge.tally.failed);
    try t.expectEqual(@as(usize, 1), refused_merge.tally.refused);
}

test "one source failing does not hide what another answered" {
    // Upstream's rule in as many words: a single failing service must not hide
    // results from the others still in flight
    // (`iroh/src/address_lookup.rs:584`). The merge holds the item and the
    // failure together rather than choosing between them, because both
    // happened.
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const id = (try fixture.corpusIds())[0];
    const addresses = try fixture.pool();
    const found = try fixture.single(alloc, id, addresses[3], .dns, 5);

    const answered: Report = .{ .answered = &.{found} };
    const failed: Report = .{ .failed = .{
        .provenance = .pkarr,
        .reason = error.UnexpectedSigner,
    } };

    const merged = try merge(t.allocator, &.{ failed, answered });
    defer merged.deinit(t.allocator);
    try t.expectEqual(Outcome.answered, merged.outcome);
    try t.expectEqual(@as(usize, 1), merged.itemCount());
    const best = merged.best() orelse return error.TestUnexpectedResult;
    try t.expect(best.eql(found));
    // The failure survives the answer. A merge that dropped it would report a
    // clean resolve over a source that handed back somebody else's packet.
    try t.expect(merged.first_failure != null);
    try t.expectEqual(@as(usize, 1), merged.tally.failed);
    try t.expectEqual(@as(usize, 1), merged.tally.answered);
}

test "two services naming one address are agreeing, not in conflict" {
    // The ordinary case, and the one `discovery/dial_source_walk.zig`'s doc
    // calls agreement: provenance is not a dedup key, so both items survive,
    // and neither disagreement nor an error is reported.
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const id = (try fixture.corpusIds())[0];
    const addresses = try fixture.pool();

    const dns = try fixture.single(alloc, id, addresses[0], .dns, 7);
    const pkarr = try fixture.single(alloc, id, addresses[0], .pkarr, 7);
    const merged = try merge(t.allocator, &.{
        .{ .answered = &.{dns} },
        .{ .answered = &.{pkarr} },
    });
    defer merged.deinit(t.allocator);

    try t.expectEqual(Outcome.answered, merged.outcome);
    try t.expectEqual(@as(usize, 2), merged.itemCount());
    try t.expectEqual(@as(usize, 0), merged.conflicts.len);
    try t.expect(merged.conflict(id) == null);
    // The same address under two stamps is a freshness claim and not a
    // disagreement about the address, so it is not a conflict either.
    const later = try fixture.single(alloc, id, addresses[0], .pkarr, 99);
    const restamped = try merge(t.allocator, &.{
        .{ .answered = &.{dns} },
        .{ .answered = &.{later} },
    });
    defer restamped.deinit(t.allocator);
    try t.expectEqual(@as(usize, 0), restamped.conflicts.len);
}

test "two sources naming different addresses are reported, not resolved" {
    // The decision the module doc makes: neither preference, nor recency, nor
    // refusal. Both items survive, the disagreement is a value that names the
    // two publishers, and the answer is the same whichever source spoke first.
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const id = (try fixture.corpusIds())[0];
    const addresses = try fixture.pool();

    // Unstamped on both sides, so a recency rule would have had nothing to say
    // and the winner would have been whichever relay URL sorts lower. Both
    // records are `relay`, which is what makes the tiebreak visible below.
    const first = try fixture.single(alloc, id, addresses[11], .dns, null);
    const second = try fixture.single(alloc, id, addresses[12], .pkarr, null);

    const forwards = try merge(t.allocator, &.{
        .{ .answered = &.{first} },
        .{ .answered = &.{second} },
    });
    defer forwards.deinit(t.allocator);
    const backwards = try merge(t.allocator, &.{
        .{ .answered = &.{second} },
        .{ .answered = &.{first} },
    });
    defer backwards.deinit(t.allocator);

    for ([_]Fanin{ forwards, backwards }) |merged| {
        try t.expectEqual(Outcome.answered, merged.outcome);
        // Both survive. A merge that picked one would have halved this.
        try t.expectEqual(@as(usize, 2), merged.itemCount());
        try t.expectEqual(@as(usize, 1), merged.conflicts.len);
        const conflict = merged.conflict(id) orelse return error.TestUnexpectedResult;
        try t.expectEqual(@as(usize, 2), conflict.distinct);
        try t.expectEqual(@as(usize, 2), conflict.reports);
        // The two ends differ in their address lists, which is the whole
        // condition, and they name the two publishers the disagreement is
        // about. Which one the merge calls "best" is `Item.order`'s answer and
        // not a judgement about which publisher is right.
        try t.expect(!sameAddresses(conflict.best, conflict.worst));
        const ends = [_]item.Provenance{ conflict.best.provenance, conflict.worst.provenance };
        var seen_dns = false;
        var seen_pkarr = false;
        for (ends) |one| switch (one) {
            .dns => seen_dns = true,
            .pkarr => seen_pkarr = true,
            .memory_lookup => return error.TestUnexpectedResult,
        };
        try t.expect(seen_dns);
        try t.expect(seen_pkarr);
    }

    // And the two orders agree, because the answer is a function of the set of
    // reports rather than of the sequence they arrived in.
    try t.expectEqual(forwards.conflicts.len, backwards.conflicts.len);
    try t.expect(forwards.conflicts[0].node_id.order(backwards.conflicts[0].node_id) == .eq);
    try t.expectEqual(forwards.conflicts[0].distinct, backwards.conflicts[0].distinct);
    try t.expect(forwards.conflicts[0].best.order(backwards.conflicts[0].best) == .eq);
    try t.expect(forwards.conflicts[0].worst.order(backwards.conflicts[0].worst) == .eq);

    // A third source agreeing with one of the two is not a new endpoint and
    // does not change the count of distinct address lists.
    const agreeing = try fixture.single(alloc, id, addresses[11], .memory_lookup, 4);
    const three = try merge(t.allocator, &.{
        .{ .answered = &.{first} },
        .{ .answered = &.{second} },
        .{ .answered = &.{agreeing} },
    });
    defer three.deinit(t.allocator);
    try t.expectEqual(@as(usize, 1), three.conflicts.len);
    try t.expectEqual(@as(usize, 2), three.conflicts[0].distinct);
    try t.expectEqual(@as(usize, 3), three.conflicts[0].reports);
    try t.expectEqual(@as(usize, 3), three.itemCount());
}

test "the merged set does not depend on the order the sources reported in" {
    // The property `discovery/item_merge.zig` proves for items, asked again
    // over whole reports: sources report in whatever order their streams
    // finish, and a zone that reorders when two answers swap is a zone that
    // flaps. A seeded corpus and sixteen permutations, so the check is over
    // reports this file did not write by hand.
    const items = try fixture.corpus(t.allocator, 24);
    defer fixture.freeItems(t.allocator, items);

    var reports: [24]Report = undefined;
    for (items, 0..) |value, index| reports[index] = .{ .answered = &.{value} };

    const expected = try merge(t.allocator, &reports);
    defer expected.deinit(t.allocator);
    try t.expect(expected.itemCount() > 0);
    try t.expectEqual(Outcome.answered, expected.outcome);

    var prng = std.Random.DefaultPrng.init(0x7265_706f_7274);
    const random = prng.random();
    var round: usize = 0;
    while (round < 16) : (round += 1) {
        const shuffled = try t.allocator.dupe(Report, &reports);
        defer t.allocator.free(shuffled);
        var pick = shuffled.len;
        while (pick > 1) {
            pick -= 1;
            const swap = random.intRangeLessThan(usize, 0, pick + 1);
            std.mem.swap(Report, &shuffled[pick], &shuffled[swap]);
        }
        const again = try merge(t.allocator, shuffled);
        defer again.deinit(t.allocator);
        try t.expectEqual(expected.itemCount(), again.itemCount());
        try t.expectEqual(expected.outcome, again.outcome);
        for (expected.items, again.items) |left, right| try t.expect(left.eql(right));
    }
}

test "an allocator that refuses leaves nothing behind" {
    // Three allocations stand between the reports and a merged set: the flat
    // list of items, `item.merge`'s own two, and the conflict array. The first
    // one refused is enough to show the path is wired to an `errdefer` at all;
    // the success afterwards is what shows the successful path owns what it
    // builds, and `t.allocator` names a leak at the end of the test either way.
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const id = (try fixture.corpusIds())[0];
    const addresses = try fixture.pool();
    const one = try fixture.single(arena.allocator(), id, addresses[3], .dns, 1);
    const reports = [_]Report{.{ .answered = &.{one} }};

    var recording = t.FailingAllocator.init(t.allocator, .{ .fail_index = 0 });
    try t.expectError(error.OutOfMemory, merge(recording.allocator(), &reports));

    const merged = try merge(t.allocator, &reports);
    defer merged.deinit(t.allocator);
    try t.expectEqual(@as(usize, 1), merged.itemCount());
    try t.expectEqual(Outcome.answered, merged.outcome);
}
