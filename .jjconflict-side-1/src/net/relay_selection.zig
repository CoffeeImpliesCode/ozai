//! The bounded, ordered list of relays a node should try, and the deadline each
//! attempt on it carries.
//!
//! `preferred_relay.zig` answers which relay to *home* on; this file answers
//! which ones to *try* when the home-on relay has stopped answering. Those are
//! different questions with different inputs, and the difference is why they
//! are two modules: a preference is a function of one folded report, and a try
//! list is a function of a report, a pool, the failures recorded against it and
//! an instant.
//!
//! Nothing here opens a socket, reads a clock or takes an allocator. `now` is
//! an argument, `pool` is the caller's slice and every answer is a value with
//! inline storage, so a whole plan is a thing a test holds on the stack and a
//! caller copies without an allocator behind it.
//!
//! # The order: home, then measured, then everything else
//!
//! Three tiers, and the tier is compared before any figure:
//!
//! 1. **The relay the node is homed on.** `preferred_relay.prefer` names it, and
//!    it leads because a node that just lost its connection tries the relay it
//!    was on first: every other thing it knows about that relay — the RTT it
//!    has measured, the peer it last reached through it — is evidence about
//!    *this* relay and no evidence at all about the others.
//! 2. **The pooled relays this report measured**, fastest first, then lowest by
//!    `RelayUrl.order`. The figure is `report_measure.RelayLatencies.get`, the
//!    fold's own table and the same minimum-over-every-family rule upstream's
//!    `RelayLatencies::get` uses, so this file defines no latency of its own.
//! 3. **Everything else in the pool**, lowest by `RelayUrl.order`.
//!
//! An unmeasured relay is tried, and it is last. `path_select.select`'s module
//! doc argues the shape of that decision once and at greater length: returning
//! nothing until something has been measured fails silently and
//! unrecoverably, because the measurement only ever arrives over a connection
//! somebody was willing to open. Here the consequence is smaller — a relay with
//! no figure is simply the weakest evidence there is — and the direction is the
//! same. **Fail-closed is not violated by trying an unmeasured relay, because
//! "nobody asked" is not a recorded failure.** A relay this node has *decided*
//! against is the one that is refused, and it is refused through a `Hold`.
//!
//! # The bound refuses and never evicts
//!
//! `max_attempts` is `report_measure.max_relays`, reused rather than restated:
//! upstream's probe fan-out is bounded at `MAX_RELAYS = 5`
//! (`reportgen.rs:497`), so a sixth relay is never probed and there is nothing
//! for a try list to have an opinion about. A pool longer than the bound has
//! its surplus counted in `Plan.refused` and **not** filed. Which relays get the
//! slots is therefore decided by the order they arrive in — the caller's pool
//! order, which for n0 is `discovery/preset.relay_urls_prod`, four entries, so
//! the production bound is never reached. The cost of refusing rather than
//! evicting is real and is the reason it is the house rule: evicting a relay
//! that is already in the list would drop a ranked attempt to admit an unranked
//! one, and the ranked attempt is the evidence-backed one.
//!
//! # The list is re-derived on every attempt
//!
//! **`plan` is called once per dial, never cached and never carried across a
//! failure.** The alternative — compute the list once and consume it — is
//! refused for the reason the failure memory exists: a list computed at `T` and
//! read at `T + 30s` still leads with whatever led at `T`, which after a
//! failure is the relay that just failed. Correcting that afterwards means
//! storing the list somewhere and mutating it, which is the same state this
//! file refuses to hold.
//!
//! The cost of re-deriving is on the caller's path, and that is the point rather
//! than a concession to it: the inputs that must be fresh — the holds and
//! `now` — are exactly the ones a caller waiting on a dial is holding. What the
//! caller does *not* pay is any I/O. `plan` is a walk over a caller-owned slice
//! into an inline array of five entries, bounded by `pool.len * max_attempts`
//! comparisons and allocating nothing, so the derivation is orders of magnitude
//! cheaper than the socket it precedes. One call per dial attempt, never per
//! packet.
//!
//! # Deadlines are consecutive slots from `now`
//!
//! Attempt *k* may be dialled no earlier than `now + k * attempt_timeout` and
//! stops counting at `now + (k+1) * attempt_timeout`. Sequential and absolute,
//! for the reason `holepunch_trigger`'s module doc gives for a round: the two
//! facts are about one node's patience for one attempt, and a list whose
//! deadlines overlap is a list describing two nodes. The attempt timeout is
//! `reconnect.Config.attempt_timeout`'s default — one dial that has produced no
//! traffic in ten seconds is the failure `relay/reconnect.zig` already names —
//! and it is spelled here rather than imported so a reader of the two files can
//! see they agree without the dependency.
//!
//! # A failed relay is retried, and the hold is what says when
//!
//! **`failure_hold` is the answer, and it is longer than a peer's.** A relay
//! that failed is not retried by this file — it is not retried by anything, and
//! this file owns no retry, no backoff and no budget. `relay/reconnect.zig`
//! owns the retry: it redials one relay under one budget and reports
//! `Action.give_up` with a `Cause`. What this file owns is the *expiry*, and the
//! interaction with `reconnect` runs one way:
//!
//! - While `reconnect` is still inside a budget for a relay, the caller passes
//!   no `Hold`. The relay is being retried, not failed, and putting it back at
//!   the head of a fresh list is not wrong — it is the same dial.
//! - Once `reconnect` hands back `.give_up`, the caller records a `Hold` and the
//!   relay leaves the list. This file does not read `reconnect.State`, does not
//!   name its `Cause`, and cannot: a second copy of a give-up instant is a
//!   second opinion about when a relay died.
//! - A relay that answers clears its `Hold` outright, the same rule
//!   `holepunch_failure_memory.Memory.forget` applies on a `.connected`, because
//!   a relay that works is a relay with nothing remembered about it.
//!
//! **Why the constant differs from a peer's.** `holepunch_failure_memory`
//! holds a failed *address* for `failure_hold`, which is two
//! `holepunch.punch_interval`s, and its module doc says why a permanent record
//! is its own bug: a NAT rebinding is not a failure of the address, and one was
//! measured at 2.2 s. The rule is the same here — one record per thing, held
//! for a bounded time, expiry is the only thing that brings it back — and the
//! value is not. A relay URL is a name and a relay has no mapping to rebuild, so
//! the 2.2 s figure has nothing to say about it; what does bound a relay is this
//! client's own patience, and re-offering a relay on the next plan before the
//! patience that gave up on it has run would put a dead relay back in the list
//! every few seconds. `failure_hold` is therefore the default
//! `reconnect.Config.gone_budget`, 300 s, spelled as a named constant here: the
//! same patience, applied again, and named once so a reader who has learned one
//! has learned both.
//!
//! **What is reused from `holepunch_failure_memory` and what is not.** The
//! rule above is reused, and it is the whole of what a failure record is: an
//! identity, the instant it was recorded, and `live` as an age against a `now`
//! that saturates, which is `Failure.live`'s exact expression. The *storage*
//! is not reused, and cannot be: `Memory` is keyed on `SocketAddr`, and a relay
//! is not a socket address — it is a 253-byte inline array with a
//! three-part comparison that `SocketAddr.order` cannot express. Sharing the
//! type would mean a union or a generic parameter, and neither earns itself for
//! two records of a key and an instant. So `Hold` is this file's own type and
//! `mayTry` asks the caller's slice, which means the memory for the records
//! stays with whoever decided to record one.

const std = @import("std");
const addr = @import("../base/addr.zig");
const report_mod = @import("report.zig");
const preferred = @import("preferred_relay.zig");

const RelayUrl = addr.RelayUrl;

/// Nanoseconds on the caller's timeline. See `preferred_relay.Nanos`, and
/// `relay/reconnect.zig`'s: `report_measure` is where all three reach the same
/// `u64`.
pub const Nanos = preferred.Nanos;

/// How many relays one plan may name.
///
/// `report_measure.max_relays` whole, and for `max_relays`'s own reason: the
/// probe fan-out is bounded at five, so a report can carry evidence about at
/// most five relays and a sixth attempt could not have evidence behind it.
pub const max_attempts: usize = report_mod.max_relays;

/// How long one dial has to produce traffic before its attempt is over.
///
/// The default `relay/reconnect.zig` gives one redial
/// (`Config.attempt_timeout`), which is the deadline that file already calls a
/// relay gone. The same number here means a plan's slots and `reconnect`'s
/// attempts time out together, so a caller running both sees one deadline
/// rather than two that disagree.
pub const attempt_timeout: Nanos = 10 * std.time.ns_per_s;

/// How long a recorded failure keeps a relay out of the plan.
///
/// The default `reconnect.Config.gone_budget`, and the difference from a peer's
/// `holepunch_failure_memory.failure_hold` is argued in the module doc: a relay
/// has no mapping to rebind, so what bounds it is this client's patience rather
/// than a round interval.
pub const failure_hold: Nanos = 300 * std.time.ns_per_s;

/// One relay this client has stopped expecting to answer.
pub const Hold = struct {
    /// The relay held. Compared through `RelayUrl.order` wherever it is
    /// matched, because two `RelayUrl` values parsed from one text differ in
    /// the padding `parse` leaves unwritten; see `base/relay.zig`'s `host`.
    relay: RelayUrl,
    /// When the failure was recorded. The record is live while this is younger
    /// than `failure_hold`, and nothing here rewrites it: re-recording is the
    /// caller's decision, and a caller that re-records at a later instant is
    /// saying the failure is current again.
    at: Nanos,

    /// Whether this record still keeps its relay out of a plan at `now`.
    ///
    /// Saturating and strict, and both matter. Saturating so a `now` past the
    /// end of the timeline reads a record as expired rather than as one whose
    /// age wrapped into the far past; strict so a record is live at
    /// `failure_hold - 1` and expired at exactly `failure_hold`, which makes the
    /// expiry instant checkable to the nanosecond. The expression is
    /// `holepunch_failure_memory.Failure.live`'s, reused for the reason the
    /// module doc gives.
    pub fn live(self: Hold, now: Nanos) bool {
        return now -| self.at < failure_hold;
    }
};

/// One relay to try, and the window it has.
pub const Attempt = struct {
    /// The relay to dial. A by-value copy that borrows nothing, as every
    /// `RelayUrl` in `src/net/` is.
    relay: RelayUrl,
    /// Its position in the plan, zero-based. The same number its deadlines are
    /// built from, and exposed so a caller logging a timeout can say which
    /// slot ran out without counting the slice itself.
    slot: u8,
    /// The earliest instant this attempt may go out: the end of the slot
    /// before it. Never in the past relative to the `now` the plan was built
    /// from, so a plan handed to a caller late cannot claim a relay was skipped.
    earliest: Nanos,
    /// When this attempt stops counting if it has produced no traffic.
    deadline: Nanos,
};

/// What one plan did, and every reason a relay is not in it.
///
/// Three counts and one of them is a refusal. All three are reported rather
/// than folded into `len`, because a caller whose pool of four came back with
/// two attempts needs to know whether two relays were held, repeated or
/// unrankable — those are three different situations with three different
/// fixes, and a count that only said "two" could not tell them apart.
pub const Plan = struct {
    /// The attempts, first `len` of them, best first. Never written past
    /// `max_attempts`.
    attempts: [max_attempts]Attempt = undefined,
    /// How many entries of `attempts` are live. Zero is a real plan: a pool
    /// whose every relay is held leaves nothing to try, and the caller is told
    /// so by `held` rather than by an empty slice it has to interpret.
    len: usize = 0,
    /// Pool relays skipped because a live `Hold` covers them.
    held: usize = 0,
    /// Pool relays that named one already in the plan. A pool is a set —
    /// `discovery/preset`'s own test says no preset names one relay twice — so
    /// this counts a caller that broke that rule, and two attempts on one relay
    /// would spend two slots proving one thing.
    duplicate: usize = 0,
    /// Pool relays that got no slot under `max_attempts`. See the module doc:
    /// the bound refuses and never evicts, so this is decided by pool order.
    refused: usize = 0,

    /// The attempts, exactly `attempts[0..len]`.
    pub fn slice(self: *const Plan) []const Attempt {
        return self.attempts[0..self.len];
    }

    /// When the first attempt may go out, or null when the plan is empty.
    ///
    /// Null rather than zero, and for the reason `holepunch_trigger.Planner`
    /// gives: zero is an instant on the caller's timeline and an empty plan has
    /// no business inventing one.
    pub fn nextDue(self: *const Plan) ?Nanos {
        const first = self.slice();
        if (first.len == 0) return null;
        return first[0].earliest;
    }

    /// When the last attempt stops counting, or null when the plan is empty.
    ///
    /// The whole of the plan's patience as one instant, which is what a caller
    /// arms a timeout on rather than reading every slot.
    pub fn giveUpAt(self: *const Plan) ?Nanos {
        const tries = self.slice();
        if (tries.len == 0) return null;
        return tries[tries.len - 1].deadline;
    }
};

/// What a plan is built from.
pub const Input = struct {
    /// The instant the plan is built at. Every deadline is measured from it and
    /// every `Hold` is aged against it, so one caller cannot be handed a plan
    /// whose slots and whose failures were read off two different clocks.
    now: Nanos,
    /// The relays this node may dial: a `discovery/preset`'s `relays`, parsed.
    /// Borrowed, not copied, and never reordered — the order is the pool's and
    /// this file imposes an order on top of it, so a caller's list is a list
    /// this file did not mutate.
    pool: []const RelayUrl,
    /// The report the last probe round folded. Read for the home-on relay and
    /// for the measured latencies, and for nothing else.
    report: report_mod.Report,
    /// The failures recorded against this pool. A caller that has been given up
    /// on a relay by `relay/reconnect.zig` puts it here; a caller that has not
    /// passed nothing. Read-only, so the memory for the records is the
    /// caller's; see the module doc.
    holds: []const Hold = &.{},
};

/// Whether `relay` may be dialled at `now`: nothing live holds it.
///
/// Exported because it is the question `plan` asks per pool entry, and a caller
/// logging why a relay was skipped wants the same answer without re-deriving
/// it. It is a question about what this client still believes, and it says
/// nothing about whether the relay works.
pub fn mayTry(relay: RelayUrl, holds: []const Hold, now: Nanos) bool {
    for (holds) |hold| {
        if (!hold.live(now)) continue;
        if (hold.relay.order(relay) == .eq) return false;
    }
    return true;
}

/// The bounded, ordered plan.
pub fn plan(input: Input) Plan {
    var out: Plan = .{};
    const home = homeRelay(&input.report, input.pool);
    var ranked: [max_attempts]Ranked = undefined;
    var filled: usize = 0;
    for (input.pool) |relay| {
        if (!mayTry(relay, input.holds, input.now)) {
            out.held += 1;
            continue;
        }
        if (carries(ranked[0..filled], relay)) {
            out.duplicate += 1;
            continue;
        }
        if (filled == max_attempts) {
            // Refused, not evicted. See the module doc under "the bound".
            out.refused += 1;
            continue;
        }
        const candidate: Ranked = .{
            .relay = relay,
            .rank = rankOf(relay, home, &input.report),
        };
        // Insertion sort by rank, walking down from the end. The list is at
        // most five entries and the walk stops at the first entry the candidate
        // beats, so an append — the common case, since `home` leads and the
        // pool is usually already close to ordered — costs one comparison.
        var at = filled;
        while (at > 0 and beats(&candidate, &ranked[at - 1])) : (at -= 1) {
            ranked[at] = ranked[at - 1];
        }
        ranked[at] = candidate;
        filled += 1;
    }
    out.len = filled;
    for (ranked[0..filled], 0..) |entry, index| {
        const slot: Nanos = @intCast(index);
        out.attempts[index] = .{
            .relay = entry.relay,
            .slot = @intCast(slot),
            // Saturating on all three, because a caller whose `now` is already
            // near the end of the timeline gets a plan whose deadlines sit at
            // the ceiling rather than a slot that wraps into the past and
            // reads as already overdue.
            .earliest = input.now +| attempt_timeout *| slot,
            .deadline = input.now +| attempt_timeout *| (slot + 1),
        };
    }
    return out;
}

/// Where a relay sits: the home-on relay first, then the measured ones fastest
/// first, then the rest by URL. Compared as an integer so the order is the
/// declaration's order and no `else` can reorder it.
const Tier = enum(u8) { home = 0, measured = 1, unmeasured = 2 };

/// A relay and the place it sorts into the plan.
const Ranked = struct {
    relay: RelayUrl,
    rank: Place,
};

/// The tier a relay falls in and the latency that settles it inside it.
///
/// Named rather than written inline in `Ranked`, because `rankOf` hands one
/// back and a function's return type has to be spelled. While the type was
/// anonymous, `rankOf` returned the whole `Ranked` pair and `plan` wrote that
/// pair into the `rank` field, which is the relay stored twice.
const Place = struct {
    tier: Tier,
    latency: Nanos,
};

/// Whether `challenger` belongs ahead of `incumbent`.
///
/// Tier first, then latency, then the URL. A tier's latency is zero for every
/// entry in it except `.measured` — there is one home-on relay and no figure
/// for an unmeasured one — so the latency comparison decides only inside the one
/// tier where it means something, and `RelayUrl.order` settles a full tie
/// wherever it is asked. **A full tie resolves to the lowest URL, never to
/// arrival order**, which is the property `report_measure.RelayList` is sorted
/// for and the reason two calls with equal arguments give equal plans.
fn beats(challenger: *const Ranked, incumbent: *const Ranked) bool {
    if (challenger.rank.tier != incumbent.rank.tier) {
        return @intFromEnum(challenger.rank.tier) < @intFromEnum(incumbent.rank.tier);
    }
    if (challenger.rank.latency != incumbent.rank.latency) {
        return challenger.rank.latency < incumbent.rank.latency;
    }
    return challenger.relay.order(incumbent.relay) == .lt;
}

/// Where `relay` sits, given the home-on relay and the report's measurements.
fn rankOf(relay: RelayUrl, home: ?RelayUrl, report: *const report_mod.Report) Place {
    if (home) |favourite| {
        if (favourite.order(relay) == .eq) return rank(.home, 0);
    }
    const measured = report.relay_latency.get(relay) orelse
        return rank(.unmeasured, 0);
    return rank(.measured, measured);
}

fn rank(tier: Tier, latency: Nanos) Place {
    return .{ .tier = tier, .latency = latency };
}

/// The relay a plan leads with, or null when the report names none this node
/// dials.
///
/// `preferred_relay.prefer` is asked rather than `Report.preferred_relay` read
/// directly, so the pool rule — a relay outside the pool is not home-on — has
/// one owner. Both of its refusals land here as null, and both mean the same
/// thing to a plan: this node has no relay it is homed on, so the plan leads
/// with the best measured relay instead. The reason a caller recovers from each
/// differently is `prefer`'s own argument and is not restated.
fn homeRelay(report: *const report_mod.Report, pool: []const RelayUrl) ?RelayUrl {
    const chosen = preferred.prefer(.{ .report = report.*, .pool = pool });
    return switch (chosen) {
        .selected => |one| one.relay,
        .outside_pool, .unmeasured => null,
    };
}

/// Whether `list` already holds `relay`.
fn carries(list: []const Ranked, relay: RelayUrl) bool {
    for (list) |entry| {
        if (entry.relay.order(relay) == .eq) return true;
    }
    return false;
}

// --- tests

const t = std.testing;

/// The instant every plan below is built at. Late on the timeline so a hold's
/// age and a slot's deadline are both far from zero and the arithmetic reads.
const test_now: Nanos = 600 * std.time.ns_per_s;

fn millis(n: u64) Nanos {
    return n * std.time.ns_per_ms;
}

/// One relay and the latency a test gave it. A tuple-shaped struct so the call
/// sites read as pairs rather than as a signature a reader has to look up.
const Measured = struct { RelayUrl, Nanos };

/// The relay the fold names, with a per-relay latency table.
fn homeOn(wanted: RelayUrl, latencies: []const Measured) report_mod.Report {
    var table = report_mod.RelayLatencies{};
    for (latencies) |entry| {
        _ = table.update(entry[0], entry[1], .https);
    }
    return .{ .preferred_relay = wanted, .relay_latency = table };
}

/// The relay a plan's slot zero names, or null when the plan is empty.
fn lead(built: Plan) ?RelayUrl {
    const tries = built.slice();
    if (tries.len == 0) return null;
    return tries[0].relay;
}

// The order is the one the module doc states: the home-on relay, then the
// measured ones fastest first, then the rest by URL.
test "the home-on relay leads, then the measured ones by latency, then the rest" {
    const home = try RelayUrl.parse("https://home.example./");
    const slow = try RelayUrl.parse("https://slow.example./");
    const quick = try RelayUrl.parse("https://quick.example./");
    const blind_a = try RelayUrl.parse("https://aaa.example./");
    const blind_b = try RelayUrl.parse("https://bbb.example./");

    const pool = [_]RelayUrl{ blind_b, slow, blind_a, quick, home };
    const built = plan(.{
        .now = test_now,
        // Offered worst-first on purpose: a plan that echoed pool order would
        // answer `blind_b` here.
        .pool = &pool,
        .report = homeOn(home, &.{
            .{ quick, millis(9) },
            .{ slow, millis(40) },
        }),
    });

    // Every pooled relay is in the plan: five in, five out, and the bound is
    // not reached because the pool is exactly `max_attempts` long.
    try t.expectEqual(pool.len, built.len);
    try t.expectEqual(max_attempts, built.len);
    try t.expectEqual(@as(usize, 0), built.held);
    try t.expectEqual(@as(usize, 0), built.duplicate);
    try t.expectEqual(@as(usize, 0), built.refused);
    const tried = built.slice();
    for (tried, 0..) |attempt, index| {
        const slot: Nanos = @intCast(index);
        try t.expectEqual(@as(u8, @intCast(slot)), attempt.slot);
        try t.expectEqual(
            test_now +| attempt_timeout *| (slot + 1),
            attempt.deadline,
        );
        try t.expectEqual(test_now +| attempt_timeout *| slot, attempt.earliest);
    }
    try t.expectEqual(std.math.Order.eq, tried[0].relay.order(home));
    try t.expectEqual(std.math.Order.eq, tried[1].relay.order(quick));
    try t.expectEqual(std.math.Order.eq, tried[2].relay.order(slow));
    // Unmeasured relays sort by URL, not by pool order: `aaa` before `bbb`
    // though `bbb` was offered first.
    try t.expectEqual(std.math.Order.eq, tried[3].relay.order(blind_a));
    try t.expectEqual(std.math.Order.eq, tried[4].relay.order(blind_b));

    try t.expectEqual(test_now, built.nextDue().?);
    try t.expectEqual(test_now +| attempt_timeout *| @as(Nanos, tried.len), built.giveUpAt().?);
}

// A hold is a refusal and it moves everything after it up a slot, because the
// slots are consecutive rather than per-relay deadlines.
test "a held relay leaves the plan and the rest close up over its slot" {
    const home = try RelayUrl.parse("https://home.example./");
    const second = try RelayUrl.parse("https://second.example./");
    const held = try RelayUrl.parse("https://held.example./");

    const report = homeOn(home, &.{
        .{ home, millis(5) },
        .{ second, millis(6) },
        .{ held, millis(7) },
    });
    const with_all = plan(.{ .now = test_now, .pool = &.{ home, second, held }, .report = report });
    try t.expectEqual(@as(usize, 3), with_all.len);

    const record: Hold = .{ .relay = held, .at = test_now };
    const without = plan(.{
        .now = test_now,
        .pool = &.{ home, second, held },
        .report = report,
        .holds = &.{record},
    });
    try t.expectEqual(@as(usize, 2), without.len);
    try t.expectEqual(@as(usize, 1), without.held);
    try t.expectEqual(@as(usize, 0), without.duplicate);
    try t.expectEqual(@as(usize, 0), without.refused);
    const tried = without.slice();
    try t.expectEqual(std.math.Order.eq, tried[0].relay.order(home));
    try t.expectEqual(std.math.Order.eq, tried[1].relay.order(second));
    // Slot 1 now carries the relay that was slot 2, so its deadline moved up by
    // one attempt_timeout: closing up is what keeps the plan's total patience
    // equal to `len * attempt_timeout`.
    try t.expectEqual(@as(u8, 1), tried[1].slot);
    try t.expectEqual(test_now +| attempt_timeout * 2, tried[1].deadline);
    try t.expectEqual(test_now +| attempt_timeout * 2, without.giveUpAt().?);

    // The plan is not a failure: `mayTry` is the same question, asked directly.
    try t.expect(mayTry(home, &.{record}, test_now));
    try t.expect(!mayTry(held, &.{record}, test_now));
}

// The hold's expiry is a real boundary: live one nanosecond earlier, expired at
// exactly the hold, and the relay is back in the plan at that instant.
test "a hold expires at its age and the relay comes back with no other change" {
    const home = try RelayUrl.parse("https://home.example./");
    const down = try RelayUrl.parse("https://down.example./");
    const pool = [_]RelayUrl{ home, down };
    const report = homeOn(home, &.{ .{ home, millis(5) }, .{ down, millis(6) } });
    // Recorded at the same instant the plan is built, so its age is exactly
    // zero at `test_now` and the expiry instant is exactly `test_now + hold`.
    const record: Hold = .{ .relay = down, .at = test_now };

    try t.expect(record.live(test_now));
    try t.expect(record.live(test_now + failure_hold - 1));
    try t.expect(!record.live(test_now + failure_hold));
    // A `now` before the record is not a record from the future: the saturated
    // age is zero and the record is live, which is what keeps a clock that went
    // backwards from inventing an expiry.
    try t.expect(record.live(0));

    const held = plan(.{ .now = test_now, .pool = &pool, .report = report, .holds = &.{record} });
    try t.expectEqual(@as(usize, 1), held.len);
    try t.expectEqual(@as(usize, 1), held.held);

    const expired = plan(.{
        .now = test_now + failure_hold,
        .pool = &pool,
        .report = report,
        .holds = &.{record},
    });
    try t.expectEqual(@as(usize, 2), expired.len);
    try t.expectEqual(@as(usize, 0), expired.held);
    try t.expectEqual(std.math.Order.eq, lead(expired).?.order(home));
    try t.expectEqual(
        std.math.Order.eq,
        expired.slice()[1].relay.order(down),
    );
}

// The bound is `max_relays`, a refusal, and never an eviction.
test "a pool longer than the bound is refused, and nothing already in it is dropped" {
    // One scratch buffer for the whole loop: `RelayUrl.parse` copies the host
    // into the value it returns, so nothing borrows this and the next iteration
    // may overwrite it. Local rather than a file-scope buffer because a mutable
    // global is exactly what `base` forbids.
    var scratch: [64]u8 = undefined;
    var pool: [max_attempts + 3]RelayUrl = undefined;
    var latencies = report_mod.RelayLatencies{};
    // Latency in milliseconds for pool entry `index`, ascending. The five kept
    // are then the five fastest and the three refused are the three slowest,
    // which is what the assertions below claim about them; the fastest relay
    // is also the one the plan leads with, so the home-on relay is the best
    // evidence in the pool rather than the worst.
    const fastest_ms: u64 = 43;
    for (&pool, 0..) |*text, offset| {
        const index: u64 = @intCast(offset);
        // Ascending by URL, so the refusals at the end are the highest URLs and
        // an eviction would be visible as the lowest URL going missing.
        text.* = try RelayUrl.parse(
            try std.fmt.bufPrint(scratch[0..], "https://r{d}.example./", .{index}),
        );
        _ = latencies.update(text.*, millis(fastest_ms + index), .https);
    }
    const report: report_mod.Report = .{
        .preferred_relay = pool[0],
        .relay_latency = latencies,
    };

    const built = plan(.{ .now = test_now, .pool = &pool, .report = report });
    try t.expectEqual(@as(usize, max_attempts), built.len);
    try t.expectEqual(@as(usize, 3), built.refused);
    try t.expectEqual(@as(usize, 0), built.held);
    try t.expectEqual(@as(usize, 0), built.duplicate);
    // The five kept are the five fastest, and the fastest is the home-on relay.
    // The three refused are the three slowest, which is what "refuses the
    // newest" means here: the pool is offered in URL order and the ranks are
    // decided as the pool is read.
    const tried = built.slice();
    for (tried, 0..) |attempt, want| {
        try t.expectEqual(std.math.Order.eq, attempt.relay.order(pool[want]));
    }
    try t.expectEqual(std.math.Order.eq, lead(built).?.order(pool[0]));
}

// A pool is a set: naming one relay twice spends one attempt and says so.
test "a relay named twice in the pool costs one attempt and one count" {
    const home = try RelayUrl.parse("https://home.example./");
    const other = try RelayUrl.parse("https://other.example./");
    // The same text parsed twice, so the two values differ in the padding
    // `RelayUrl.parse` leaves unwritten and only `order` can call them one.
    const home_again = try RelayUrl.parse("https://home.example./");

    const built = plan(.{
        .now = test_now,
        .pool = &.{ home, other, home_again },
        .report = homeOn(home, &.{ .{ home, millis(5) }, .{ other, millis(6) } }),
    });
    try t.expectEqual(@as(usize, 2), built.len);
    try t.expectEqual(@as(usize, 1), built.duplicate);
    try t.expectEqual(std.math.Order.eq, lead(built).?.order(home));
}

// Every input equal gives the same plan, whatever order the pool was written
// in. The table is sorted by rank rather than by arrival for exactly this.
test "the plan is a function of its inputs and not of the pool's order" {
    const home = try RelayUrl.parse("https://home.example./");
    const a = try RelayUrl.parse("https://aaa.example./");
    const b = try RelayUrl.parse("https://bbb.example./");
    const c = try RelayUrl.parse("https://ccc.example./");
    const report = homeOn(home, &.{
        .{ a, millis(20) },
        .{ b, millis(20) },
        .{ c, millis(10) },
    });

    const forwards = plan(.{ .now = test_now, .pool = &.{ home, a, b, c }, .report = report });
    const backwards = plan(.{ .now = test_now, .pool = &.{ c, b, a, home }, .report = report });
    try t.expectEqual(forwards.len, backwards.len);

    // `a` and `b` are tied on latency, so this walk also holds the tie-break:
    // the lower URL wins regardless of which was offered first.
    const one = forwards.slice();
    const two = backwards.slice();
    for (one, two) |left, right| {
        try t.expectEqual(std.math.Order.eq, left.relay.order(right.relay));
        try t.expectEqual(left.earliest, right.earliest);
        try t.expectEqual(left.deadline, right.deadline);
    }
    try t.expectEqual(std.math.Order.eq, one[0].relay.order(home));
    try t.expectEqual(std.math.Order.eq, one[1].relay.order(c));
    try t.expectEqual(std.math.Order.eq, one[2].relay.order(a));
    try t.expectEqual(std.math.Order.eq, one[3].relay.order(b));
}

// The two refusals `preferred_relay` has are the same to a plan — no relay to
// be homed on — and neither of them empties a plan that has a pool.
test "a report naming no homed relay still produces a try list" {
    const one = try RelayUrl.parse("https://one.example./");
    const two = try RelayUrl.parse("https://two.example./");
    const pool = [_]RelayUrl{ one, two };

    // Nothing measured at all: `.unmeasured`.
    const blind = plan(.{ .now = test_now, .pool = &pool, .report = .{} });
    try t.expectEqual(@as(usize, 2), blind.len);
    try t.expectEqual(@as(usize, 0), blind.held);
    try t.expectEqual(@as(usize, 0), blind.refused);
    try t.expectEqual(std.math.Order.eq, lead(blind).?.order(one));

    // A report about a relay this node does not dial: `.outside_pool`. The pool
    // is unchanged and so is the plan, because a preference this node cannot
    // act on is not a relay it should try first.
    const foreign = try RelayUrl.parse("https://elsewhere.example./");
    const strayed = plan(.{
        .now = test_now,
        .pool = &pool,
        .report = homeOn(foreign, &.{
            .{ one, millis(5) },
            .{ two, millis(6) },
        }),
    });
    try t.expectEqual(@as(usize, 2), strayed.len);
    try t.expectEqual(std.math.Order.eq, lead(strayed).?.order(one));
}

// An empty plan is an answer and not a shrug: the caller is told every relay
// was held and is given no instant to wait on.
test "a pool whose relays are all held is an empty plan with nothing due" {
    const one = try RelayUrl.parse("https://one.example./");
    const two = try RelayUrl.parse("https://two.example./");
    const holds = [_]Hold{
        .{ .relay = one, .at = test_now },
        .{ .relay = two, .at = test_now },
    };
    const built = plan(.{
        .now = test_now,
        .pool = &.{ one, two },
        .report = .{},
        .holds = &holds,
    });
    try t.expectEqual(@as(usize, 0), built.len);
    try t.expectEqual(@as(usize, 2), built.held);
    try t.expectEqual(@as(?Nanos, null), built.nextDue());
    try t.expectEqual(@as(?Nanos, null), built.giveUpAt());
}

// A `now` near the end of the timeline saturates rather than wrapping into the
// past, where a deadline would read as already overdue.
test "deadlines at the end of the timeline saturate and do not wrap" {
    const one = try RelayUrl.parse("https://one.example./");
    const two = try RelayUrl.parse("https://two.example./");
    const near_end: Nanos = std.math.maxInt(Nanos) - millis(1);
    const built = plan(.{ .now = near_end, .pool = &.{ one, two }, .report = .{} });

    const tried = built.slice();
    // Slot zero is due at `now` itself, which is still below the ceiling and is
    // said as such rather than being pushed up to it.
    try t.expectEqual(near_end, tried[0].earliest);
    try t.expectEqual(near_end, built.nextDue().?);
    // Every deadline is one `attempt_timeout` past that and would overflow, so
    // each one sits at the ceiling. Wrapped instead, they would land in the
    // past and a caller would read a plan whose every attempt is already
    // overdue.
    try t.expectEqual(std.math.maxInt(Nanos), tried[0].deadline);
    try t.expectEqual(std.math.maxInt(Nanos), tried[1].deadline);
    try t.expectEqual(std.math.maxInt(Nanos), built.giveUpAt().?);
}
