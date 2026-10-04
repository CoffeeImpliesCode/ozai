//! The accept task table: the bounded storage the accept loop holds its
//! long-lived `accept`s in, and the per-protocol routing that says which
//! configured protocol each held task is under.
//!
//! Split out of `endpoint/endpoint.zig` by runtime responsibility. That file is
//! the *machine* — which of its four verdicts ends an attempt, what a shutdown
//! owes next, when a slot is taken or freed. This file is the *storage* those
//! decisions land in: a dense, caller-sized window of live tasks, and the
//! questions a caller asks about it. Neither half needs a runtime, and the split
//! is what lets a caller check the window's invariants — dense, no duplicates,
//! bounded, per-protocol counts — without driving a loop.
//!
//! Upstream's counterpart is a tokio `JoinSet` on which every `accept` future
//! is spawned (`protocol.rs:601-603`) and from which every finished one is taken
//! back (`:545-566`). That store is unbounded and this one is not: `hold` is
//! the point where the difference is decided, and the answer there is the
//! caller's to act on (see `endpoint.zig`'s `spawn`).

const std = @import("std");
const router = @import("../router/router.zig");

/// One long-lived `accept`, held as a value.
///
/// Upstream spawns `token.run_until_cancelled(handle_connection(...))` onto a
/// `JoinSet` (`protocol.rs:601-603`), and that future may outlive the handshake
/// and the connection with it (`protocol.rs:258-261`). That is the whole reason
/// the shutdown has an ordering, and it is why a task here is a value with an
/// explicit lifetime rather than a thread: the caller drives `state` with the
/// dispatch module's own `dispatchStep` and reports what happened, and the loop
/// counts what is running so the cancel knows what it is cancelling.
pub const Task = struct {
    /// The core's connection id, which is what a reaped task is named by, and
    /// never reused (`transport/quic_bridge.zig:230-233`).
    id: u64,
    /// The router's per-connection machine, running on this task. The caller
    /// drives it while the task is held; the loop only ever reads the id.
    state: router.ConnState,
    /// The configured protocol this task is under, as the `Claim.index` of the
    /// ALPN its handshake produced, and null until the caller has reported it
    /// (`endpoint.Loop`'s `Event.routed`).
    ///
    /// **This is per-protocol task routing, and it is what a protocol's own
    /// close counts.** One protocol can be retired while the others keep
    /// serving, and what has to be cancelled with it is exactly the tasks whose
    /// `protocol` names it — `laneCount` and `laneIds` are how a caller finds
    /// them. The endpoint-wide shutdown counts the whole window instead, which
    /// is upstream's all-or-nothing close (`protocol.rs:609-611`).
    ///
    /// Null is a real answer and not an unfinished task: a caller that never
    /// drove a handshake reports nothing, and the task is then in no lane. The
    /// endpoint-wide close still counts it, because that count is the window's
    /// and not a protocol's.
    protocol: ?usize,
};

/// Whether the window has room for one more task, which is what `hold` decides
/// and what a full window turns into a refusal.
pub fn room(slots: []const Task, live: usize) bool {
    return live < slots.len;
}

/// The slot `id` is held in, or null when it is not held: before it was
/// spawned, after it was reaped, or because it was never the loop's.
///
/// Bounded by `live` and not by `slots.len`, so a stale slot above the count is
/// never returned.
pub fn indexOf(slots: []const Task, live: usize, id: u64) ?usize {
    var index: usize = 0;
    while (index < live) : (index += 1) {
        if (slots[index].id == id) return index;
    }
    return null;
}

/// The task `id` names, for the caller to drive. Null when there is none, for
/// the same reason `indexOf` returns null.
pub fn at(slots: []Task, live: usize, id: u64) ?*Task {
    const index = indexOf(slots, live, id) orelse return null;
    return &slots[index];
}

/// Take a slot for `id` and return it, or null when the window is full.
///
/// **A full window is refused, not silently skipped.** Upstream's `JoinSet` is
/// unbounded and cannot run out (`protocol.rs:601-603`); a window that is has to
/// answer, and the answer is null so the caller can refuse the connection
/// rather than accept one it has nowhere to hold — a peer that believed it was
/// connected and was not.
///
/// A task is born `.negotiating` with no protocol: that is the state upstream's
/// spawned future starts in, awaiting the handshake before anything knows which
/// protocol the connection is for.
pub fn hold(slots: []Task, live: usize, id: u64) ?*Task {
    if (!room(slots, live)) return null;
    slots[live] = .{ .id = id, .state = .negotiating, .protocol = null };
    return &slots[live];
}

/// One task's slot, freed, and how many are live now.
///
/// The window is dense, so the last task fills the hole: a bounded scan per reap
/// and no free list to keep in step with the count. A shift instead of a swap
/// would renumber every task after the hole, and the count alone cannot tell the
/// two apart — which is why a task is named by id and never by index.
///
/// An id the window never held changes nothing: the id is the core's and never
/// reused, so a reap for one the loop did not take is a caller's bookkeeping
/// error and the honest answer is the count it already has.
pub fn forget(slots: []Task, live: usize, id: u64) usize {
    const index = indexOf(slots, live, id) orelse return live;
    slots[index] = slots[live - 1];
    return live - 1;
}

/// Route a held task to the protocol its negotiated ALPN names, and say what
/// the table made of it.
///
/// A claim writes that protocol's index onto the task, so from here the task is
/// counted by `laneCount` and named by `laneIds` under that protocol and no
/// other. A refusal leaves the task unrouted and hands the caller the reason: no
/// configured protocol claims that ALPN, so there is no lane to put it in.
///
/// Null when the id is not one the window holds, which is the same answer
/// `forget` gives and for the same reason — the caller named a task this window
/// never took, so the table has declined nothing.
///
/// **The refusal is the caller's to act on.** At this point the connection
/// exists and the layer that owns it is the caller's, so this returns a value
/// rather than performing anything; `endpoint.Loop`'s `Event.routed` owes
/// nothing for it, which is stated there too.
pub fn route(
    slots: []Task,
    live: usize,
    table: *const router.Router,
    id: u64,
    alpn: []const u8,
) ?router.Route {
    const task = at(slots, live, id) orelse return null;
    switch (table.dispatch(alpn)) {
        .protocol => |found| {
            task.protocol = found.index;
            return .{ .protocol = found };
        },
        // **A refusal clears the protocol, and that is what "unrouted" means
        // here.** The task arrived carrying whatever a previous handshake routed
        // it under; leaving it would keep the task counted by `laneCount` and
        // named by `laneIds` under a protocol it no longer negotiated, so a
        // close that retires that protocol would cancel a connection that now
        // belongs to no lane at all. Nothing here negotiated anything, so the
        // honest answer is no lane.
        .refused => |refusal| {
            task.protocol = null;
            return .{ .refused = refusal };
        },
    }
}

/// How many held tasks are under the protocol at `index`.
///
/// This is the count a protocol's own `Lifetime` close cancels, and it is
/// bounded by the window: this is the only place that count exists, and a
/// second one kept by the machine would be a second answer to the same question.
pub fn laneCount(slots: []const Task, live: usize, index: usize) usize {
    var held: usize = 0;
    for (slots[0..live]) |task| {
        if (task.protocol == index) held += 1;
    }
    return held;
}

/// The ids of the held tasks under the protocol at `index`, into storage the
/// caller sizes, and how many were written.
///
/// A caller retiring one protocol needs the names of exactly its tasks, because
/// those are the ones a `Lifetime` close owes cancelling. `out` is bounded, so
/// an under-sized array is a short count rather than an index panic; a caller
/// that needs every id sizes it from `laneCount` or from the window it declared.
pub fn laneIds(slots: []const Task, live: usize, index: usize, out: []u64) usize {
    var written: usize = 0;
    for (slots[0..live]) |task| {
        if (task.protocol != index) continue;
        if (written == out.len) break;
        out[written] = task.id;
        written += 1;
    }
    return written;
}

const t = std.testing;

/// A task in the window, with a state and no protocol yet.
fn born(id: u64) Task {
    return .{ .id = id, .state = .negotiating, .protocol = null };
}

/// A handler that does nothing, for a table this file only routes by. Which
/// handler a connection reaches is the router's business and its tests; what is
/// checked here is which registration a task is routed to.
fn inert(_: *anyopaque, _: router.Connection) router.AcceptError!void {}

fn handler(ptr: *anyopaque) router.ProtocolHandler {
    return .{ .ptr = ptr, .on_accepting = null, .accept = inert, .shutdown = null };
}

/// A two-protocol table — gossip first, then blobs — so the claim indexes are 0
/// and 1 and a test can say which is which by number.
fn twoProtocols(entries: []router.Entry) !router.Router {
    var builder = router.Builder.init(entries);
    _ = try builder.accept("/gossip", handler(entries.ptr));
    _ = try builder.accept("/blobs", handler(entries.ptr));
    return builder.build();
}

test "the window is dense, and a reaped slot is filled by the last task" {
    var slots: [3]Task = undefined;
    slots[0] = born(1);
    slots[1] = born(2);
    slots[2] = born(3);
    var live: usize = 3;
    try t.expect(!room(&slots, live));

    // The middle one comes back and the last task fills its hole. A shift would
    // renumber the survivor, and only the ids say which task survived.
    live = forget(&slots, live, 2);
    try t.expectEqual(@as(usize, 2), live);
    try t.expectEqual(@as(?usize, null), indexOf(&slots, live, 2));
    try t.expectEqual(@as(u64, 1), slots[0].id);
    try t.expectEqual(@as(u64, 3), slots[1].id);

    // Each id is held once and the survivors are where the hole was: a removal
    // that copied the last task into the hole and left the count alone would
    // show one id twice and lose the other. A per-protocol count cannot say
    // that — nothing here has been routed — so it is the ids that are looked
    // up.
    try t.expectEqual(@as(?usize, 0), indexOf(&slots, live, 1));
    try t.expectEqual(@as(?usize, 1), indexOf(&slots, live, 3));
    try t.expectEqual(@as(?usize, null), indexOf(&slots, live, 2));
    // And the task the hole was filled with kept its own protocol, which is
    // still none: filling a slot is a move, not a routing.
    try t.expectEqual(@as(?usize, null), slots[1].protocol);
    try t.expectEqual(@as(usize, 0), laneCount(&slots, live, 0));

    // A reap for a task the window never held changes nothing.
    live = forget(&slots, live, 99);
    try t.expectEqual(@as(usize, 2), live);
    // And down to empty one reap at a time, where the last removal takes the
    // last task: what is left is the count, and it is zero.
    live = forget(&slots, live, 1);
    live = forget(&slots, live, 3);
    try t.expectEqual(@as(usize, 0), live);
    try t.expectEqual(@as(?usize, null), indexOf(&slots, live, 3));
    // A reap against an empty window is the one place `live - 1` would
    // underflow if the removal ran anyway.
    live = forget(&slots, live, 3);
    try t.expectEqual(@as(usize, 0), live);
}

test "a full window has no room and takes nothing" {
    var slots: [2]Task = undefined;
    try t.expect(hold(&slots, 0, 1) != null);
    try t.expect(hold(&slots, 1, 2) != null);
    try t.expect(!room(&slots, 2));

    // The refusal leaves the window exactly as it was: the two held tasks are
    // untouched and the third is nowhere in it.
    try t.expectEqual(@as(?*Task, null), hold(&slots, 2, 3));
    try t.expectEqual(@as(?usize, null), indexOf(&slots, 2, 3));
    try t.expectEqual(@as(u64, 1), slots[0].id);
    try t.expectEqual(@as(u64, 2), slots[1].id);

    // A task is born negotiating with no protocol, and the lookup hands back the
    // very slot `hold` wrote.
    try t.expectEqual(router.ConnState.negotiating, slots[1].state);
    try t.expectEqual(@as(?usize, null), slots[1].protocol);
    try t.expectEqual(slots[1], at(&slots, 2, 2).?.*);
}

test "a task is routed to the protocol its ALPN names, and only that one" {
    var entries: [2]router.Entry = undefined;
    const table = try twoProtocols(&entries);

    var slots: [2]Task = undefined;
    _ = hold(&slots, 0, 1);
    _ = hold(&slots, 1, 2);

    // Each handshake names its own protocol, and the claim's index is what the
    // task is routed to — the same number a lifetime lane is addressed by.
    const first = route(&slots, 2, &table, 1, "/gossip").?;
    try t.expectEqual(@as(usize, 0), first.protocol.index);
    try t.expectEqual(@as(?usize, 0), slots[0].protocol);
    const second = route(&slots, 2, &table, 2, "/blobs").?;
    try t.expectEqual(@as(usize, 1), second.protocol.index);
    try t.expectEqual(@as(?usize, 1), slots[1].protocol);

    // So each lane counts only its own tasks and names only their ids, and an
    // under-sized output is a short count rather than an index panic.
    try t.expectEqual(@as(usize, 1), laneCount(&slots, 2, 0));
    try t.expectEqual(@as(usize, 1), laneCount(&slots, 2, 1));
    try t.expectEqual(@as(usize, 0), laneCount(&slots, 2, 2));
    var ids: [2]u64 = undefined;
    try t.expectEqual(@as(usize, 1), laneIds(&slots, 2, 1, &ids));
    try t.expectEqual(@as(u64, 2), ids[0]);
    try t.expectEqual(@as(usize, 1), laneIds(&slots, 2, 0, &ids));
    try t.expectEqual(@as(u64, 1), ids[0]);
    var one: [1]u64 = undefined;
    try t.expectEqual(@as(usize, 1), laneIds(&slots, 2, 1, &one));
    try t.expectEqual(@as(usize, 0), laneIds(&slots, 2, 2, &one));

    // Re-routing a held task moves it: the protocol is read off the handshake,
    // so a connection that negotiated something else belongs to another lane
    // and stops being counted by the first.
    _ = route(&slots, 2, &table, 1, "/blobs");
    try t.expectEqual(@as(?usize, 1), slots[0].protocol);
    try t.expectEqual(@as(usize, 2), laneCount(&slots, 2, 1));
    try t.expectEqual(@as(usize, 0), laneCount(&slots, 2, 0));
}

test "an ALPN nothing claims leaves the task unrouted and says why" {
    var entries: [2]router.Entry = undefined;
    const table = try twoProtocols(&entries);

    var slots: [1]Task = undefined;
    _ = hold(&slots, 0, 1);

    // The refusal is the answer the caller acts on, and the task is in no lane:
    // there is no protocol to count it under and none to cancel it with.
    const refused = route(&slots, 1, &table, 1, "/docs").?;
    try t.expectEqual(
        router.Refusal{ .alpn = "/docs", .configured = 2 },
        refused.refused,
    );
    try t.expectEqual(@as(?usize, null), slots[0].protocol);
    try t.expectEqual(@as(usize, 0), laneCount(&slots, 1, 0));

    // **The refusal also clears a lane the task was already in**, which is the
    // case the doc line above is about: a task that was routed and is then
    // re-routed to an ALPN nothing claims negotiated nothing, so it is in no
    // lane. Leaving the first protocol on it keeps the task counted there and
    // named for a cancellation under a protocol it no longer speaks for.
    _ = route(&slots, 1, &table, 1, "/gossip");
    try t.expectEqual(@as(usize, 1), laneCount(&slots, 1, 0));
    const second = route(&slots, 1, &table, 1, "/docs").?;
    try t.expectEqual(
        router.Refusal{ .alpn = "/docs", .configured = 2 },
        second.refused,
    );
    try t.expectEqual(@as(?usize, null), slots[0].protocol);
    try t.expectEqual(@as(usize, 0), laneCount(&slots, 1, 0));

    // A task the window never took has nothing to route, and the answer is null
    // rather than a refusal: the table was never asked about a task it does not
    // hold, so it has declined nothing.
    try t.expectEqual(@as(?router.Route, null), route(&slots, 1, &table, 99, "/gossip"));
}

test "a lane names exactly the tasks it counts" {
    var entries: [2]router.Entry = undefined;
    const table = try twoProtocols(&entries);

    // Two tasks under the first protocol, one under the second, and one whose
    // handshake never reported: a lane that named another lane's task, or the
    // unrouted one, would show up below.
    var slots: [4]Task = undefined;
    try t.expect(hold(&slots, 0, 10) != null);
    try t.expect(hold(&slots, 1, 11) != null);
    try t.expect(hold(&slots, 2, 12) != null);
    try t.expect(hold(&slots, 3, 13) != null);
    const live: usize = 4;
    _ = route(&slots, live, &table, 10, "/gossip");
    _ = route(&slots, live, &table, 11, "/gossip");
    _ = route(&slots, live, &table, 12, "/blobs");

    var ids: [4]u64 = undefined;
    // Every id a lane names is that lane's, and how many it names is how many
    // it counts: the count and the names are one question asked twice, so they
    // cannot answer differently.
    for ([_]usize{ 0, 1, 2 }) |lane| {
        const named = laneIds(&slots, live, lane, &ids);
        try t.expectEqual(laneCount(&slots, live, lane), named);
        var seen: usize = 0;
        while (seen < named) : (seen += 1) {
            try t.expectEqual(@as(?usize, lane), at(&slots, live, ids[seen]).?.protocol);
        }
    }

    // Named in window order, which is what makes the list a cancellation list
    // rather than a set, and a lane with one task gets that one task rather
    // than the three that are not its own.
    try t.expectEqual(@as(usize, 2), laneIds(&slots, live, 0, &ids));
    try t.expectEqual(@as(u64, 10), ids[0]);
    try t.expectEqual(@as(u64, 11), ids[1]);
    try t.expectEqual(@as(usize, 1), laneIds(&slots, live, 1, &ids));
    try t.expectEqual(@as(u64, 12), ids[0]);

    // An under-sized output truncates the lane's own names rather than filling
    // it with another's.
    var one: [1]u64 = undefined;
    try t.expectEqual(@as(usize, 1), laneIds(&slots, live, 0, &one));
    try t.expectEqual(@as(u64, 10), one[0]);

    // And the task no handshake reported belongs to no lane, for the count as
    // much as for the names.
    try t.expectEqual(@as(usize, 0), laneCount(&slots, live, 2));
    try t.expectEqual(@as(usize, 0), laneIds(&slots, live, 2, &ids));
}
