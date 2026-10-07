//! Whether the evidence behind a chosen path is still an answer, and what a
//! fresh figure of that path means once one lands.
//!
//! `path_select.zig` ranks on `Entry.latency(now)`, and every figure it ranks
//! on was measured earlier. Nothing else in this directory notices that the
//! world moved underneath one: the figure stays in the entry, correct as of the
//! instant it was taken and describing a mapping that may no longer exist. This
//! module is the one that notices. Given a path's recorded state and an instant
//! it says whether the recorded figure is still fresh enough to keep making the
//! choice it was made for; given a figure that has just been measured it says
//! what that figure means against the record.
//!
//! Pure: no socket, no clock, no allocator, no global. `now` is an argument and
//! every answer is a value. Nothing here writes an `Entry` — `path_table.zig`
//! owns every figure and `path_select.zig` owns every choice — so the caller
//! that wants a new measurement kept calls `Table.sample` and then reads
//! `classify` on the figure it just took.
//!
//! This module is about evidence and never about status. It does not read
//! `Entry.status` and does not write one: whether a path may carry traffic at
//! all is `path_select.selectable`'s question, and a stale figure is not a
//! reason to answer it differently.
//!
//! # What makes evidence stale, and what was done with `rtt_max_age`
//!
//! `rtt_max_age` is five seconds and it answers a narrower question: may *this
//! figure* still be ranked? `Entry.latency` asks it on every read and answers
//! with a null, and `path_select` acts on the null. A bound on the age of a
//! figure is enforced by making the figure stop ranking, which is a decision
//! `path_select` has already made. A revalidation rule at that same instant
//! would be a second mechanism for one decision, so this module does not reuse
//! the number.
//!
//! What `rtt_max_age` does not answer is the question here: not *may the figure
//! be ranked* but *how long may the choice stand on a figure that has stopped
//! being ranked*. Those come apart in one state, and the state is reachable in
//! this tree on a timer. `Entry.latency` past five seconds returns null, so the
//! path drops out of the ranking; `switchTo` then keeps it as `best` only when
//! nothing in the table is measured, because an unmeasured incumbent is
//! displaced by any measured challenger and `faster` needs a figure of its own.
//! A **single-path connection** is exactly that state: its one handshake sample
//! ages out at five seconds and from then on the incumbent is ranked by
//! nothing. Nothing retires it either, because `Table.mark` retires on *bytes*
//! and this path's bytes are moving. It can carry for an hour on a
//! five-second-old figure and be questioned again by nobody.
//!
//! So the bound here starts at the same instant and stops somewhere else:
//! `revalidate_after` is one third of `idle_timeout`, which puts it strictly
//! after `rtt_max_age` — a verdict that fired while the figure was still a
//! ranking input would be second-guessing a live figure — and puts the whole
//! cycle, the window plus the grace, at twenty seconds inside a thirty second
//! idle window. So the answer always arrives before silence would have retired
//! the path, and always arrives for a path silence cannot reach.
//!
//! # A stale path keeps carrying
//!
//! A stale figure is not a recorded failure, and the tree already says which is
//! which. `holepunch.PathStatus.unusable` is a path observed to fail and
//! `Entry.dialable` refuses exactly that; there is no status for *we do not
//! know*, and `path_select`'s module doc is explicit that an unknown is not a
//! refusal — with no trustworthy latency anywhere, `select` answers with a path,
//! because refusing means no packet is sent, so the sample can never arrive.
//!
//! Withdrawing on the stale verdict would put that failure on a timer. A
//! one-path connection loses its figure at five seconds and is withdrawn at
//! ten; a withdrawn path carries nothing, so nothing is sent on it, so nothing
//! is ever measured on it, so it can never be shown good again. That is a
//! connection that dies ten seconds after it is established with no failure
//! recorded anywhere — the one failure mode in this tree that nothing recovers
//! from. So `.stale` keeps the traffic and asks for a measurement. The cost is
//! bounded on purpose: while the figure is stale the path is ranked by nothing,
//! which is why the window is a third of the idle timeout rather than longer.
//!
//! # What a worse figure means: record it at once, move nothing at once
//!
//! Both obvious answers are wrong for the same reason — each trusts something.
//!
//! - **Revert at once**, and two near-equal paths flap: traffic moves on one
//!   noisy figure, the next figure says the opposite, and every move is a lost
//!   packet on each path. `switchTo`'s two-thirds margin cannot absorb this,
//!   because after the sample lands the regressed path *is* the incumbent, and
//!   that margin protects an incumbent against a challenger rather than against
//!   its own figure changing underneath it.
//! - **Never revert**, and the entry keeps a figure the tree knows to be wrong:
//!   every later `latency` read, every ranking and every switch is computed
//!   from a number that is false in the one direction that keeps this path on
//!   traffic. That is worse than the flap, because a flap costs packets and
//!   this costs every decision taken after it.
//!
//! So the two are split by what is updated. **The record changes at once**:
//! `Table.sample` overwrites `rtt` and `rtt_at` unconditionally, nothing here
//! vetoes it, and a measurement is a measurement. **The traffic does not move on
//! a regression alone**: `.regressed` is reported so the caller re-asks
//! `switchTo` on this turn with the new figure in the entries, and the
//! two-thirds margin decides there. That margin is `report_fold`'s, restated
//! once in `path_select`, and a second one here would be a second opinion about
//! when to move traffic.
//!
//! A regression is worse than the record by more than three halves — the exact
//! mirror of `path_select.displaces`, which is *better than* two thirds: same
//! floor, same strict comparison, and a figure at exactly one and a half times
//! the record is not a regression for the same reason a challenger at exactly
//! two thirds does not take traffic.
//!
//! Two corroborating measurements were considered and are deliberately absent.
//! They would need per-path state that `Entry` has no field for and that this
//! module does not add, and they would guard nothing: a regression never moves
//! traffic on its own, so there is no oscillation for a second opinion to
//! suppress.

const std = @import("std");
const addr = @import("../base/addr.zig");
const path_table = @import("path_table.zig");

const Nanos = path_table.Nanos;
const Entry = path_table.Entry;
const TransportAddr = addr.TransportAddr;
const SocketAddr = addr.SocketAddr;

/// Borrowed from the table this reads, so a caller spelling a `now` or an age
/// here does not mean importing `report.zig` for a type alias. Both are
/// arguments to the arithmetic below and neither is restated.
pub const rtt_max_age = path_table.rtt_max_age;
pub const idle_timeout = path_table.idle_timeout;

/// How long a chosen path's recorded figure keeps making its choice: one third
/// of `idle_timeout`, and strictly longer than `rtt_max_age`.
///
/// See the module doc. Ten seconds is twice the age at which the figure stops
/// ranking, so the first revalidation is asked for after selection has already
/// stopped using the figure and not before, and it leaves a third of the idle
/// window for the answer to arrive in before silence could retire the path.
pub const revalidate_after: Nanos = @divExact(idle_timeout, 3);

/// How long the measurement `revalidate_after` asked for may go unanswered
/// before the path is called unverified: two sample ages.
///
/// One age is the round trip and the turn in which the caller notices the
/// verdict; two covers a sample that was lost or a turn with nothing to send.
/// Nothing extends it.
pub const probe_grace: Nanos = 2 * rtt_max_age;

/// How old a figure may be before the path stops carrying on it.
///
/// Below `idle_timeout` on purpose. `Table.mark` also retires a quiet path, and
/// for a path that has moved nothing the two overlap with this one first:
/// twenty seconds is inside thirty, so the verdict that arrives is the one that
/// knows the figure has no answer behind it. They are not the same decision,
/// and the case only this reaches is a path that carried a byte a nanosecond
/// ago — `mark` will never touch that one.
pub const unverified_after: Nanos = revalidate_after + probe_grace;

/// The mirror of `path_select.switch_numerator` and `switch_denominator`, for
/// the other direction: a challenger at two thirds may take traffic, and a
/// figure at three halves of the record is a regression.
pub const regress_numerator: Nanos = 3;
pub const regress_denominator: Nanos = 2;

/// What one path's recorded figure supports at `now`.
pub const Verdict = enum {
    /// The figure is inside `revalidate_after`. The choice it was made for
    /// stands and nothing needs measuring.
    fresh,
    /// The figure is past `revalidate_after` but no later than
    /// `unverified_after`, or there is no figure at all: a fresh measurement is
    /// required and the path **keeps carrying** until one arrives.
    ///
    /// "Never measured" and "measured long ago" are one arm because
    /// `Entry.latency` already collapses them into one answer and says why:
    /// both mean nobody measured lately, and both mean the same thing to a
    /// decision. Splitting them here would be a second distinction that nothing
    /// downstream could act on differently.
    stale,
    /// The figure is older than `unverified_after`: the measurement that was
    /// asked for has itself gone unanswered, so nothing on this path is keeping
    /// it honest and it stops carrying.
    ///
    /// This is reachable for a path that carried a byte a nanosecond ago, which
    /// `Table.mark` will never touch — see the test that pins it.
    unverified,
};

/// What a figure just measured against this path's record means.
pub const Reading = enum {
    /// There was no record: this is the path's first figure, and there is
    /// nothing for it to regress from however large it is.
    first,
    /// The figure does not regress the record by more than the margin. It may
    /// be slower — inside the margin that is noise, and absorbing it here is
    /// what stops a single odd sample from being read as a change.
    confirmed,
    /// The figure is worse than the record by more than three halves. The
    /// record is known to be wrong and must be replaced; the traffic does not
    /// move on this alone, and the caller re-asks `path_select` this turn.
    regressed,
};

/// What one path's recorded figure supports at `now`.
///
/// A function of the entry and the instant and of nothing else: the age runs
/// from `rtt_at`, the newest figure in the entry, so a path re-measured this
/// turn reads `fresh` this turn without anything here being told about the
/// measurement. Saturating, so an instant before the figure was taken reads as
/// age zero rather than as an age that wrapped into the far past.
pub fn verdict(entry: *const Entry, now: Nanos) Verdict {
    if (entry.rtt == null) return .stale;
    const age = now -| entry.rtt_at;
    if (age <= revalidate_after) return .fresh;
    if (age <= unverified_after) return .stale;
    return .unverified;
}

/// What a figure just measured means against what the entry recorded.
///
/// Takes the entry rather than a `?Nanos` so the caller cannot pass a record
/// from one path with a figure from another, and takes no `now` because
/// comparing two figures needs no clock: the caller has just measured and knows
/// when.
pub fn classify(entry: *const Entry, fresh: Nanos) Reading {
    const recorded = entry.rtt orelse return .first;
    const ceiling = @divFloor(recorded, regress_denominator) * regress_numerator;
    if (fresh > ceiling) return .regressed;
    return .confirmed;
}

comptime {
    // Every window this module defines is ordered against the two the table
    // already owns, and the order is the design rather than a coincidence of the
    // numbers. Stated here so a reader who changes one constant is stopped at
    // the build instead of by a verdict that quietly contradicts the doc.
    std.debug.assert(rtt_max_age < revalidate_after);
    std.debug.assert(revalidate_after < unverified_after);
    std.debug.assert(unverified_after < idle_timeout);
}

// --- tests

const t = std.testing;

/// The sibling whose two-thirds margin this module mirrors, imported for the
/// tests only so that the mirror is held against the file it mirrors.
const path_select = @import("path_select.zig");

const millis = std.time.ns_per_ms;

/// A direct address on `port` from one documentation range, so a test that
/// prints one is never mistaken for a routable host.
fn ip(port: u16) SocketAddr {
    return .{ .ip = .{ .v4 = .{ 192, 0, 2, 1 } }, .port = port };
}

/// `ip(port)` as the address a path is keyed on.
fn at(port: u16) TransportAddr {
    return .{ .ip = ip(port) };
}

/// One open path whose figure is `rtt`, taken at `rtt_at`.
fn path(rtt: ?Nanos, rtt_at: Nanos) Entry {
    return .{ .addr = at(1000), .status = .open, .rtt = rtt, .rtt_at = rtt_at };
}

test "the figure is fresh to its last nanosecond and stale one past it" {
    const entry = path(20 * millis, 1_000);
    try t.expectEqual(Verdict.fresh, verdict(&entry, 1_000));
    // The window is inclusive at its end, like `Entry.carrying` and unlike a
    // strict comparison: an age of exactly the bound is still inside it.
    try t.expectEqual(Verdict.fresh, verdict(&entry, 1_000 + revalidate_after));
    try t.expectEqual(Verdict.stale, verdict(&entry, 1_000 + revalidate_after + 1));
    // And the answer is monotone in age, one boundary at a time.
    try t.expectEqual(Verdict.stale, verdict(&entry, 1_000 + unverified_after));
    try t.expectEqual(Verdict.unverified, verdict(&entry, 1_000 + unverified_after + 1));
    try t.expectEqual(Verdict.unverified, verdict(&entry, 1_000 + unverified_after * 1000));
}

test "no verdict is stale while the figure can still be ranked" {
    const entry = path(20 * millis, 1_000);
    // `rtt_max_age` is the age past which `Entry.latency` answers null and
    // `path_select` stops ranking the figure. A revalidation asked for before
    // then would be second-guessing a figure that is still an answer, so the
    // two windows do not touch, and this walks the whole gap between them.
    try t.expectEqual(Verdict.fresh, verdict(&entry, 1_000));
    try t.expectEqual(Verdict.fresh, verdict(&entry, 1_000 + rtt_max_age));
    var now: Nanos = 0;
    while (now <= rtt_max_age) : (now += millis) {
        try t.expectEqual(Verdict.fresh, verdict(&entry, 1_000 + now));
    }
    // The far end of the gap agrees with the table: rankable right up to
    // `rtt_max_age` and not one nanosecond past it.
    try t.expect(entry.latency(1_000 + rtt_max_age) != null);
    try t.expect(entry.latency(1_000 + rtt_max_age + 1) == null);
}

test "a path nobody measured is stale for ever and is never withdrawn" {
    const entry = path(null, 0);
    // No figure at all: there is nothing that could have gone stale, so the only
    // honest answer is that a measurement is required — and the path keeps
    // carrying, because a withdrawn path would send nothing and so could never
    // be measured. It stays that way however long it lives, which is what keeps
    // a fresh connection from wedging shut at a bound.
    try t.expectEqual(Verdict.stale, verdict(&entry, 0));
    try t.expectEqual(Verdict.stale, verdict(&entry, unverified_after));
    try t.expectEqual(Verdict.stale, verdict(&entry, unverified_after * 1000));
    // And the figure stays absent rather than being invented from the fact that
    // the path is open.
    try t.expectEqual(@as(?Nanos, null), entry.rtt);
}

test "the window runs from the newest figure and a refresh rearms it" {
    var table: path_table.Table = .{};
    _ = table.observe(at(1000), .open, 0);
    try t.expect(table.sample(at(1000), 20 * millis, 1_000));
    const stale_at = 1_000 + unverified_after + 1;
    const stale = table.get(at(1000)) orelse return error.TestUnexpectedResult;
    try t.expectEqual(Verdict.unverified, verdict(&stale, stale_at));

    // A second measurement replaces the first, and the path is fresh again from
    // the instant of the second rather than from the instant of the first: the
    // age is read out of `rtt_at`, so revalidation is repeatable rather than a
    // one-shot countdown to a connection that can never be trusted again.
    try t.expect(table.sample(at(1000), 24 * millis, stale_at));
    const entry = table.get(at(1000)) orelse return error.TestUnexpectedResult;
    try t.expectEqual(Verdict.fresh, verdict(&entry, stale_at));
    try t.expectEqual(Verdict.fresh, verdict(&entry, stale_at + revalidate_after));
    try t.expectEqual(Verdict.stale, verdict(&entry, stale_at + revalidate_after + 1));
    // And the second figure is the record the new one is read against, which is
    // what `classify` sees below: 30 ms against a 24 ms record is inside three
    // halves of it and is noise, not a regression.
    try t.expectEqual(@as(?Nanos, 24 * millis), entry.rtt);
    try t.expectEqual(Reading.confirmed, classify(&entry, 30 * millis));
}

test "a path carrying right now is still unverified on a dead figure" {
    var table: path_table.Table = .{};
    _ = table.observe(at(1000), .open, 0);
    try t.expect(table.sample(at(1000), 20 * millis, 0));
    const now = unverified_after + 1;
    try t.expect(table.account(at(1000), 1_400, 90_000, now));

    // Bytes moved on this path one nanosecond ago, so `mark` leaves it alone and
    // would leave it alone for ever: idleness is the only thing that retires a
    // path, and this path is not idle. This is the case the verdict exists for
    // and the case `mark` structurally cannot reach.
    const entry = table.get(at(1000)) orelse return error.TestUnexpectedResult;
    try t.expect(entry.carrying(now));
    try t.expectEqual(@as(usize, 0), table.mark(now));
    try t.expectEqual(Verdict.unverified, verdict(&entry, now));
}

test "three halves is not a regression and a nanosecond past it is" {
    const entry = path(20 * millis, 1_000);
    // The mirror of `path_select.displaces`, which will not move traffic for a
    // challenger at exactly two thirds. This will not call three halves a
    // regression either, and the floor is the same one.
    try t.expectEqual(Reading.confirmed, classify(&entry, 30 * millis));
    try t.expectEqual(Reading.confirmed, classify(&entry, 30 * millis - 1));
    try t.expectEqual(Reading.regressed, classify(&entry, 30 * millis + 1));

    // Slower inside the margin is noise and is absorbed here, which is where a
    // single odd sample stops being read as a change: the record is replaced
    // either way, and only the margin decides that the path got worse.
    try t.expectEqual(Reading.confirmed, classify(&entry, 29 * millis));
    try t.expectEqual(Reading.confirmed, classify(&entry, 1));
    // And faster is never a regression, however far.
    try t.expectEqual(Reading.confirmed, classify(&entry, 1 * millis));
}

test "a path with no record cannot regress and one with a record reads it" {
    // Any figure at all is the first one, including one far past the margin: the
    // margin compares a figure with a record, and there is no record here to
    // compare against.
    const never = path(null, 0);
    try t.expectEqual(Reading.first, classify(&never, 20 * millis));
    const far = unverified_after * 1000;
    try t.expectEqual(Reading.first, classify(&never, far));

    // With a record the same figure is a regression, which is the difference
    // between "first" and "worse" being two facts about a path rather than one.
    const measured = path(20 * millis, 0);
    try t.expectEqual(Reading.regressed, classify(&measured, far));
    // A figure far better than the record is not a regression but a
    // confirmation, and it is not `first` either: `first` means there is no
    // record, and one nanosecond is nowhere near three halves of a millisecond.
    const slowest_record = path(1_000_000, 0);
    try t.expectEqual(Reading.confirmed, classify(&slowest_record, 1));
}

test "a reading is a value and the entry it read is unchanged" {
    const before = path(20 * millis, 1_000);
    var entry = before;

    // Two readings against a const copy and a mutable one, one of which would
    // have been a regression, and one verdict: neither the record nor the
    // instant it was taken moves, because `Table.sample` is the only writer of
    // a figure in this directory.
    try t.expectEqual(Reading.confirmed, classify(&before, 30 * millis));
    try t.expectEqual(Reading.regressed, classify(&entry, 90 * millis));
    try t.expectEqual(Verdict.fresh, verdict(&entry, 1_000));
    try t.expectEqual(@as(?Nanos, 20 * millis), entry.rtt);
    try t.expectEqual(@as(Nanos, 1_000), entry.rtt_at);
    try t.expect(entry.status == .open);
    try t.expect(entry.addr.order(before.addr) == .eq);
}

test "an instant before the figure was taken is age zero" {
    const entry = path(20 * millis, 1_000);
    // Saturating, the same rule `Entry.latency` and `Entry.carrying` use: a
    // sample stamped after `now` is not old, it is not yet stale. A wrap here
    // would read a figure as decades old and withdraw a path on it.
    try t.expectEqual(Verdict.fresh, verdict(&entry, 0));
    try t.expectEqual(Verdict.fresh, verdict(&entry, 1_000));
}

test "the windows are the ones the module doc claims" {
    // The order is the design: a verdict never fires while the figure can still
    // be ranked, and always fires before silence could have retired the path.
    try t.expect(rtt_max_age < revalidate_after);
    try t.expect(revalidate_after < unverified_after);
    try t.expect(unverified_after < idle_timeout);
    try t.expectEqual(@as(Nanos, @divExact(idle_timeout, 3)), revalidate_after);
    try t.expectEqual(@as(Nanos, 2 * rtt_max_age), probe_grace);

    // And the regression margin is the switch margin transposed, not a copy of
    // it: three halves against two thirds. Held against `path_select` itself so
    // a change to either file that breaks the mirror fails here.
    try t.expectEqual(@as(Nanos, 3), regress_numerator);
    try t.expectEqual(@as(Nanos, 3), path_select.switch_denominator);
    try t.expectEqual(@as(Nanos, 2), regress_denominator);
    try t.expectEqual(@as(Nanos, 2), path_select.switch_numerator);
    try t.expect(regress_numerator != regress_denominator);
}
