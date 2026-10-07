//! Which path carries traffic, and which paths are prunable.
//!
//! Pure over what `path_table.zig` already holds. `now` is an argument to
//! every call that needs one, nothing here reads a clock, opens a socket or
//! takes an allocator, and the whole answer is a value. The two questions this
//! file asks — who carries, and who is out — are asked over statuses and
//! latencies it does not own; `path_table.Table` owns those and this file
//! restates none of them.
//!
//! # The order is the tree's, not a second one
//!
//! Ranking is fastest-first, and the tree already has that rule twice:
//! `report_fold.zig`'s `beats` orders observations by latency before anything
//! else, and its `choosePreferredRelay` refuses to leave the incumbent unless a
//! challenger beats it by more than two thirds. Both are reused here rather
//! than re-derived, because a second latency order in this tree is a second
//! opinion about which path is faster and nothing would say which is right.
//! `displaces` is the two-thirds margin and `faster` is the plain comparison;
//! they are separate on purpose, because the margin belongs to *switching* and
//! using it to pick an argmax would stop at a path that is barely quicker.
//!
//! # Pruning marks, it does not remove
//!
//! **Pruning marks.** `prune` delegates idleness to `Table.mark`, which turns
//! an `.open` path that has moved nothing for `idle_timeout` into
//! `.inactive(now)` and leaves the entry, its latency and its counters where
//! they are. Removing is `Table.forget`, and nothing in this file calls it:
//! a path that has gone quiet has not failed, and its history is exactly what
//! would make it worth choosing again. A path recorded `.unusable` is the one
//! kind this tree knows to have failed, so `prune` counts those as well — but
//! counting is not evicting, and the slot of a failed path is taken by
//! `path_table`'s own rule, not by this one.
//!
//! `Pruned` reports both counts so a caller can tell a table where marking
//! did work from one where everything was already prunable.
//!
//! # A path that has never carried traffic is not "inactive"
//!
//! Two different questions, and this file keeps them apart. "Is it carrying?"
//! is `Entry.carrying(now)` and is about bytes. "Is it inactive?" is a status,
//! and `.inactive` is only ever written from `.open` — by `Table.mark` here,
//! or by the multipath layer that said the path closed. A path nobody has ever
//! sent a byte on is not inactive for that reason: if the layer called it
//! `.open`, it is `.open` and `Entry.activeAt` falls back to the filing
//! instant, so it *becomes* `.inactive` after `idle_timeout` has passed with
//! nothing said about it. An `.unknown` path is never marked at all, however
//! old it is: it has failed at nothing, and recording idleness there would
//! report a failure nobody observed.
//!
//! The cost of that answer is one status rank and no history: the entry keeps
//! its address, its latency and its counters, so the layer can put it back on
//! `.open` the moment it speaks.
//!
//! # What selection returns when nothing has been measured
//!
//! **It returns a path.** Concretely: with no trustworthy latency anywhere in
//! the table, `select` answers the earliest `.open` entry and `switchTo` holds
//! whatever it was told is carrying.
//!
//! The alternative — returning null until somebody measures something — fails
//! in a way nothing can recover from, and the failure is silent. A fresh
//! connection has exactly one path, that path has no sample because no packet
//! has come back on it yet, and refusing to select it means no packet is ever
//! sent, so the sample never arrives. The caller cannot tell that null from
//! "this peer has no usable path", and both would be answered the same way.
//!
//! Fail-closed is not violated by this, because what it refuses is a *recorded
//! failure*: a `.unusable` path is never selectable, whatever it was measured
//! at. There is a status that says a path does not work and a missing figure
//! that says nobody asked; only the first is a refusal.
//!
//! What is refused is `.unknown` too, and that is a separate decision. An
//! untried path has never been selected onto, and choosing one is a dial, not a
//! selection — so with no `.open` path at all, `select` answers null and
//! `.none`, and the caller is left to decide what to try. When no path is
//! selectable that is a fact about the table, and a caller that wants a path
//! anyway wants a rule this file deliberately does not have.

const std = @import("std");
const addr = @import("../base/addr.zig");
const holepunch = @import("holepunch.zig");
const path_table = @import("path_table.zig");

const TransportAddr = addr.TransportAddr;

pub const Nanos = path_table.Nanos;
pub const Entry = path_table.Entry;
pub const Table = path_table.Table;
pub const PathStatus = holepunch.PathStatus;

/// Borrowed from the table this file reads, so a caller spelling a `now` here
/// does not mean importing `report.zig` for a type alias.
pub const idle_timeout = path_table.idle_timeout;
/// How old a sample may be and still be ranked. Older is treated as no sample
/// at all, which is `Entry.latency`'s rule rather than a second one.
pub const rtt_max_age = path_table.rtt_max_age;

/// The margin a challenger must clear to take traffic off an incumbent: two
/// thirds of the incumbent's latency, floored, compared strictly.
///
/// Upstream's own figure for the same decision, from
/// `report_fold.choosePreferredRelay` — `(latency / 3) * 2` and a strict `>`,
/// so a challenger at exactly two thirds does not move it. Spelled with a
/// name rather than copied so this file's rule is traceable to that one.
pub const switch_numerator: Nanos = 2;
pub const switch_denominator: Nanos = 3;

/// Whether this path may be selected onto for traffic at all.
///
/// Narrower than `Entry.dialable`, which asks whether a path may be *tried*:
/// that one refuses a recorded failure, this one refuses anything that is not
/// currently open. A dialer chooses among paths it may try; a selector chooses
/// among paths already carrying, and the difference is every status that is
/// not `.open` — a path nobody has tried and a path that has closed are both
/// dialable and both unselectable.
pub fn selectable(entry: *const Entry) bool {
    return entry.status == .open;
}

/// What one `prune` found.
///
/// Both counts are of paths already in the table, never of addresses offered
/// to it: this file files nothing and forgets nothing.
pub const Pruned = struct {
    /// Paths `Table.mark` took off `.open` for having moved nothing for
    /// `idle_timeout`. Marking is idempotent, so a second call over the same
    /// table reports zero.
    marked: usize,
    /// Paths recorded `.unusable`. Counted because a table where every path
    /// failed and one where every path is still open are different tables,
    /// and `select` answers them differently.
    unusable: usize,
};

/// Take every open path that has moved nothing for `idle_timeout` off
/// `.open`, and count what the table already held.
///
/// **Marking, not removal** — see the module doc. The mark is `Table.mark`'s
/// and is not restated: one place decides what idleness means, and this file
/// asks it rather than reimplementing it. Nothing here writes a status, so a
/// path stays exactly as the layer or `observe` left it unless that one rule
/// fires.
///
/// Idempotent, so a caller may run it on every turn.
pub fn prune(table: *Table, now: Nanos) Pruned {
    var result: Pruned = .{ .marked = table.mark(now), .unusable = 0 };
    for (table.slice()) |entry| {
        if (entry.status == .unusable) result.unusable += 1;
    }
    return result;
}

/// Why one answer came out the way it did.
///
/// A reason rather than a bare path, because the three ways of returning
/// nothing-else differ for the caller: `.held` means a decision was made and
/// kept, `.faster` means one was made and changed, `.adopted` means the
/// incumbent named by the caller is not selectable and the fastest open path
/// took the traffic, and `.none` means the table holds no path that may carry.
pub const Reason = enum {
    /// Nothing beat the incumbent by the switch margin.
    held,
    /// A challenger was faster by more than the margin.
    faster,
    /// The named incumbent was not selectable, so the fastest open path took
    /// the traffic.
    adopted,
    /// No path in the table is selectable.
    none,
};

/// One selection: the path that carries, and why.
pub const Switch = struct {
    /// The path traffic goes on, or null when `reason` is `.none`. The address
    /// is a copy of the entry's, and it is the table's own inline address, so
    /// the caller keeps the table alive for as long as it reads this.
    path: ?TransportAddr,
    /// Why that path, read above.
    reason: Reason,
};

/// The path traffic goes on, with no incumbent to hold.
///
/// Equivalent to `switchTo(table, now, null)`, and the reason it reports is
/// `.adopted` whenever there is one: without an incumbent there is nothing to
/// be faster than. Kept as its own name because "which path" is the question
/// a caller asks first and spelling it as a switch with a null incumbent asks
/// it in the vocabulary of the second question.
pub fn select(table: *const Table, now: Nanos) Switch {
    return switchTo(table, now, null);
}

/// The path traffic goes on, given what is carrying now.
///
/// `incumbent` is the path the caller is already sending on, or null when it
/// has none. Holding it is the point: a connection that re-picks its path on
/// every turn oscillates between two paths that are nearly equal, and every
/// move is a lost packet on each of them.
///
/// Pure, and it stays that way — the table is read through `*const`, so
/// nothing here can move a status or touch a counter. `prune` is the writer
/// and this is the reader; a caller that selects without pruning has not lost
/// anything, it has just not asked whether an open path has gone quiet.
pub fn switchTo(table: *const Table, now: Nanos, incumbent: ?TransportAddr) Switch {
    var best: ?*const Entry = null;
    var held: ?*const Entry = null;
    for (table.slice()) |*entry| {
        if (!selectable(entry)) continue;
        // Strictly faster, so an equal or unmeasured later entry leaves the
        // earlier one standing: the table's filing order is the tie-break,
        // which is what `path_table`'s own doc says this file does.
        if (best == null or faster(entry, best.?, now)) best = entry;
        if (incumbent) |address| {
            if (entry.addr.order(address) == .eq) held = entry;
        }
    }
    const winner = best orelse return .{ .path = null, .reason = .none };
    const staying = held orelse return .{ .path = winner.addr, .reason = .adopted };
    if (staying == winner) return .{ .path = winner.addr, .reason = .held };
    if (displaces(winner, staying, now)) return .{ .path = winner.addr, .reason = .faster };
    return .{ .path = staying.addr, .reason = .held };
}

/// Whether `challenger` answers faster than `incumbent`, on latency alone.
///
/// Strictly, and neither path has to be selectable: this is the comparison the
/// switch margin is applied to, not the switch itself.
///
/// A path with no trustworthy sample never answers faster. It was never
/// measured, or its sample is older than `rtt_max_age` and describes a mapping
/// that may no longer exist; either way there is no figure to compare, and
/// inventing one from "it has not been ruled out" is how a path nobody has
/// tested displaces the path that has been carrying.
fn faster(challenger: *const Entry, incumbent: *const Entry, now: Nanos) bool {
    const mine = challenger.latency(now) orelse return false;
    const theirs = incumbent.latency(now) orelse return true;
    return mine < theirs;
}

/// Whether `challenger` takes traffic off `incumbent`.
///
/// Two thirds of the incumbent's latency, floored, compared strictly — the
/// margin `report_fold.choosePreferredRelay` uses to hold a preferred relay,
/// reused for the same reason and spelled the same way. A challenger at
/// exactly two thirds does not move it.
///
/// An unmeasured incumbent is displaced by any measured challenger, because
/// there is no figure for the margin to protect. An unmeasured challenger
/// displaces nothing, which is `faster`'s rule and the conservative half of
/// it: a path with no latency is not better, and churning onto one costs a
/// packet on every path involved.
fn displaces(challenger: *const Entry, incumbent: *const Entry, now: Nanos) bool {
    const mine = challenger.latency(now) orelse return false;
    const theirs = incumbent.latency(now) orelse return true;
    return mine < @divFloor(theirs, switch_denominator) * switch_numerator;
}

// --- tests

const t = std.testing;

const SocketAddr = addr.SocketAddr;
const millis = std.time.ns_per_ms;

/// A direct address on `port_number` from one documentation range, so a test
/// that prints one is never mistaken for a routable host.
fn ip(port_number: u16) SocketAddr {
    return .{ .ip = .{ .v4 = .{ 192, 0, 2, 1 } }, .port = port_number };
}

/// `ip(port_number)` as the address a path is keyed on.
fn at(port_number: u16) TransportAddr {
    return .{ .ip = ip(port_number) };
}

/// The port a selection names, or null when it named none. Matches on the
/// `.ip` variant rather than reading bytes out of the union, because the
/// answer is a copy of an entry's address and the test must not depend on how
/// that address happens to be spelled.
fn chosenPort(answer: Switch) ?u16 {
    const chosen = answer.path orelse return null;
    return switch (chosen) {
        .ip => |socket| socket.port,
        else => null,
    };
}

/// A table holding one open path per port from `first`, none sampled.
fn openTable(first: u16, count: usize) Table {
    var table: Table = .{};
    for (0..count) |offset| {
        _ = table.observe(at(first + @as(u16, @intCast(offset))), .open, 0);
    }
    return table;
}

test "the fastest open path carries and nothing else is offered" {
    var table = openTable(1000, 3);
    try t.expect(table.sample(at(1000), 30 * millis, 0));
    try t.expect(table.sample(at(1001), 10 * millis, 0));
    try t.expect(table.sample(at(1002), 20 * millis, 0));

    const answer = select(&table, 0);
    try t.expectEqual(@as(?u16, 1001), chosenPort(answer));
    try t.expectEqual(Reason.adopted, answer.reason);

    // Naming the fastest as the incumbent changes nothing, which is the whole
    // of `.held`: there was nothing faster to be faster than.
    const held = switchTo(&table, 0, at(1001));
    try t.expectEqual(@as(?u16, 1001), chosenPort(held));
    try t.expectEqual(Reason.held, held.reason);
}

test "with no latency anywhere the earliest open path carries" {
    var table = openTable(1000, 3);
    // Two of the three carry traffic and none has been sampled, so the table
    // answers a ranking question with no figures in it. Traffic is not a
    // latency: `account` stamps `last_active` and nothing else.
    try t.expect(table.account(at(1001), 10, 20, 0));
    try t.expect(table.account(at(1002), 10, 20, 0));
    try t.expectEqual(@as(?Nanos, null), table.get(at(1000)).?.latency(0));
    try t.expectEqual(@as(?Nanos, null), table.get(at(1001)).?.latency(0));

    // A path, not nothing: refusing here would mean the first packet is never
    // sent, so the sample this is waiting for could never arrive.
    try t.expectEqual(@as(?u16, 1000), chosenPort(select(&table, 0)));
    // And it is the earliest one, not the newest: with no figure to rank on,
    // the tie-break is the table's own order and nothing outranks it.
    try t.expectEqual(@as(?u16, 1000), chosenPort(switchTo(&table, 0, null)));
}

test "the incumbent holds unless a challenger clears two thirds" {
    var table = openTable(1000, 3);
    try t.expect(table.sample(at(1000), 30 * millis, 0));
    try t.expect(table.sample(at(1001), 20 * millis, 0));
    // 1002 is open and unsampled for the first turn, so the only challenger is
    // 1001 and the boundary is what this turn is about.

    // 20 ms against 30 ms is exactly two thirds. The comparison is strict, so
    // the incumbent keeps the traffic and nothing on that path is lost.
    const held = switchTo(&table, 0, at(1000));
    try t.expectEqual(@as(?u16, 1000), chosenPort(held));
    try t.expectEqual(Reason.held, held.reason);

    // 12 ms is decisively under the line, and the traffic moves.
    try t.expect(table.sample(at(1002), 12 * millis, 0));
    const moved = switchTo(&table, 0, at(1000));
    try t.expectEqual(@as(?u16, 1002), chosenPort(moved));
    try t.expectEqual(Reason.faster, moved.reason);

    // The new incumbent is then held in turn, which is what stops a selection
    // running every turn from oscillating between two near-equal paths.
    const again = switchTo(&table, 0, at(1002));
    try t.expectEqual(@as(?u16, 1002), chosenPort(again));
    try t.expectEqual(Reason.held, again.reason);
}

test "an unmeasured path never displaces a measured one" {
    var table = openTable(1000, 2);
    try t.expect(table.sample(at(1000), 30 * millis, 0));

    // 1001 has no sample at all. Not being ruled out is not being faster, and
    // churning onto it would cost a packet on both paths.
    const held = switchTo(&table, 0, at(1000));
    try t.expectEqual(@as(?u16, 1000), chosenPort(held));
    try t.expectEqual(Reason.held, held.reason);

    // But an unmeasured *incumbent* is displaced by any measured challenger:
    // there is no figure for the margin to protect. It is still `.open`, so
    // this is the displacement and not `.adopted`, which means an incumbent
    // that is not selectable at all.
    const displaced = switchTo(&table, 0, at(1001));
    try t.expectEqual(@as(?u16, 1000), chosenPort(displaced));
    try t.expectEqual(Reason.faster, displaced.reason);
}

test "an incumbent that is not selectable hands over with no margin" {
    var table = openTable(1000, 2);
    try t.expect(table.sample(at(1000), 30 * millis, 0));
    try t.expect(table.sample(at(1001), 29 * millis, 0));

    // 29 against 30 is nothing like two thirds and it still moves: the named
    // incumbent has closed, so there is no traffic on it to protect.
    try t.expect(table.observe(at(1001), .{ .inactive = 0 }, 0).stored);
    const moved = switchTo(&table, 0, at(1001));
    try t.expectEqual(@as(?u16, 1000), chosenPort(moved));
    try t.expectEqual(Reason.adopted, moved.reason);

    // An address the table does not carry is not an incumbent either, and the
    // answer is the same as for a closed one rather than an error.
    try t.expectEqual(Reason.adopted, switchTo(&table, 0, at(9999)).reason);
}

test "a recorded failure is never selectable, however fast it was" {
    var table = openTable(1000, 3);
    try t.expect(table.sample(at(1000), 30 * millis, 0));
    try t.expect(table.sample(at(1001), 1 * millis, 0));
    try t.expect(table.observe(at(1001), .unusable, 0).stored);

    // One millisecond is the fastest sample in the table, and the path still
    // carries nothing: failing is a recorded fact, not a slow one.
    try t.expectEqual(@as(?u16, 1000), chosenPort(select(&table, 0)));
    try t.expect(!selectable(&table.get(at(1001)).?));
    // Dialable and unselectable are different questions, and both refuse this
    // one: `.unusable` is the one status that is a recorded failure, so no
    // dialer may retry it and no traffic may go on it.
    try t.expect(!table.get(at(1001)).?.dialable());
    try t.expectEqual(@as(?u16, 1000), chosenPort(switchTo(&table, 0, at(1001))));
}

test "no open path at all is answered as none rather than as a guess" {
    var table = openTable(1000, 3);
    try t.expect(table.sample(at(1000), 10 * millis, 0));
    // Nothing the table knows is open. Choosing an untried path would be a
    // dial, and this is not where a dial is decided.
    for ([_]u16{ 1000, 1001, 1002 }) |port_number| {
        _ = table.observe(at(port_number), .unknown, 0);
    }
    const answer = select(&table, 0);
    try t.expect(answer.path == null);
    try t.expectEqual(Reason.none, answer.reason);

    // And a table holding nothing at all answers the same way.
    const empty: Table = .{};
    try t.expectEqual(Reason.none, select(&empty, 0).reason);
    try t.expectEqual(@as(?u16, null), chosenPort(select(&empty, 0)));
}

test "a sample older than the age stops being ranked without being forgotten" {
    var table = openTable(1000, 2);
    try t.expect(table.sample(at(1000), 40 * millis, 1_000));
    try t.expect(table.sample(at(1001), 20 * millis, 1_000));
    try t.expectEqual(@as(?u16, 1001), chosenPort(select(&table, 1_000)));

    // Both samples go stale at once, and the answer falls back to the filing
    // order rather than to whichever figure is now older: the figures are
    // still in the entries, they have simply stopped being answers.
    const stale = 1_000 + rtt_max_age + 1;
    try t.expectEqual(@as(?u16, 1000), chosenPort(select(&table, stale)));
    try t.expectEqual(@as(Nanos, 40 * millis), table.get(at(1000)).?.rtt);
    try t.expectEqual(@as(?Nanos, null), table.get(at(1000)).?.latency(stale));
}

test "pruning marks a quiet path, counts the failed, and removes nothing" {
    var table = openTable(1000, 3);
    // 1000 carried at `idle_timeout`, so it is still inside the timeout one
    // nanosecond later; nothing has said anything about it since.
    try t.expect(table.account(at(1000), 10, 10, idle_timeout));
    _ = table.observe(at(1002), .unusable, 0);
    // The other two have never carried a byte and have said nothing about
    // themselves, so both have been idle since the instant they were filed.
    try t.expectEqual(Pruned{ .marked = 0, .unusable = 1 }, prune(&table, idle_timeout));
    try t.expectEqual(Pruned{ .marked = 1, .unusable = 1 }, prune(&table, idle_timeout + 1));

    // Marked, not gone: every entry is still here, the one that was marked
    // reads as closed rather than as failed, and the one carrying still carries.
    try t.expectEqual(@as(usize, 3), table.slice().len);
    try t.expectEqual(@as(?u16, 1000), chosenPort(select(&table, idle_timeout + 1)));
    try t.expectEqual(PathStatus{ .inactive = idle_timeout + 1 }, table.get(at(1001)).?.status);
    try t.expectEqual(PathStatus.unusable, table.get(at(1002)).?.status);
    // The failed path was not evicted to make room for anything: nothing was
    // filed, and the count is a count.
    try t.expectEqual(@as(usize, 3), table.slice().len);
    try t.expect(table.find(at(1002)) != null);

    // A second pass over the marked table marks nothing and does not re-stamp
    // the instants the first pass wrote.
    try t.expectEqual(Pruned{ .marked = 0, .unusable = 1 }, prune(&table, idle_timeout + 2));
    try t.expectEqual(PathStatus{ .inactive = idle_timeout + 1 }, table.get(at(1001)).?.status);
}

test "a path that never carried is marked, and an untried one is not" {
    var table: Table = .{};
    _ = table.observe(at(1000), .open, 0);
    _ = table.observe(at(1001), .unknown, 0);

    // The open one is idle from the instant it was filed — it never had a
    // byte — so it is marked. The untried one is never marked however old it
    // gets: it has failed at nothing, and nothing here has tried it.
    try t.expectEqual(@as(usize, 1), prune(&table, idle_timeout + 1).marked);
    try t.expectEqual(PathStatus{ .inactive = idle_timeout + 1 }, table.get(at(1000)).?.status);
    try t.expectEqual(PathStatus.unknown, table.get(at(1001)).?.status);
    try t.expectEqual(@as(?Nanos, null), table.get(at(1000)).?.last_active);
    // An untried path is also never selectable, and that is a separate answer
    // from the one the mark gives.
    try t.expect(!selectable(&table.get(at(1001)).?));

    // A layer that says the path is open again puts the traffic back on it,
    // with the figures it accumulated still attached.
    try t.expect(table.observe(at(1000), .open, idle_timeout * 2).stored);
    try t.expectEqual(@as(?u16, 1000), chosenPort(select(&table, idle_timeout * 2)));
    try t.expectEqual(@as(?Nanos, null), table.get(at(1000)).?.rtt);
}

test "select reads and never writes" {
    var table = openTable(1000, 2);
    try t.expect(table.sample(at(1000), 5 * millis, 0));
    const before = table.slice();

    // Three selections — one that would move the traffic, two that would not —
    // leave every status and every figure exactly where they were.
    _ = select(&table, 0);
    _ = switchTo(&table, 0, at(1001));
    _ = select(&table, 0);

    for (table.slice(), before) |after, prior| {
        try t.expect(std.meta.eql(after.status, prior.status));
        try t.expectEqual(prior.rtt, after.rtt);
        try t.expectEqual(prior.rtt_at, after.rtt_at);
        try t.expectEqual(prior.tx_bytes, after.tx_bytes);
        try t.expectEqual(prior.rx_bytes, after.rx_bytes);
        try t.expectEqual(prior.last_active, after.last_active);
    }
    try t.expectEqual(@as(usize, 2), table.slice().len);
}
