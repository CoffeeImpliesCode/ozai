//! When the whole resolution stops: a bounded stagger of the sources, a
//! deadline, and what a resolve reports when the deadline arrives with nothing.
//!
//! `discovery/dial_source_walk.zig` asks every source and merges what they
//! answered. It is sequential, so on a slow nameserver it pays the slow
//! nameserver's full timeout before it asks the source that would have
//! answered. This module is the schedule that question needs, as data: the
//! caller supplies the elapsed time, and this file decides which sources are
//! due, how long until the next one is, and whether the resolve is over.
//!
//! # No clock, and no second table
//!
//! Every function here is a function of `elapsed_ms` and of values the caller
//! holds. Nothing reads a clock, an allocator or a global, for the reason
//! `discovery/lookup_io.zig`'s module doc gives: a module that reads a clock
//! cannot be driven at a fixed one, and `docs/DECISIONS/0002-async-substrate.md`
//! says a struct holding an `Io` cannot be driven twice with different
//! runtimes. A caller with an `Io` and a deadline drives this; a test with a
//! list of instants drives the same code.
//!
//! # This is not `discovery/host_io.zig`'s schedule, and the reason is the
//! axis
//!
//! `host_io.zig` has `staggering_ms`, `attemptsDue` and `walkDeadlineMs`, and
//! none of the three is reused here. They look like the same question and they
//! are not:
//!
//! * **The axis is one question, not a set of sources.** `staggering_ms` is
//!   RFC 1035 §7.2's "the client should try other servers before repeating a
//!   query" applied to *one* question asked repeatedly: `attemptsDue` answers
//!   "how many copies of this query have gone out by now", and upstream's own
//!   doc says the first is done immediately. Here each entry is a *different
//!   source* — a DNS query, a pkarr HTTPS GET, an in-process memory lookup —
//!   and asking it twice would be a second question, not a retry.
//! * **The numbers are upstream's for a different question.** The six values
//!   in `staggering_ms` are `iroh/src/address_lookup/dns.rs:18`'s, read from
//!   the DNS resolver's retry policy, and `query_timeout_ms` is
//!   `iroh-dns`'s per-query `DNS_TIMEOUT`. They are quoted there as captured
//!   facts about a DNS walk. A resolve over a pkarr HTTPS relay has a different
//!   latency profile and a different cost per attempt, and no captured
//!   upstream file on this machine gives numbers for it, so this module takes
//!   its offsets and its budget as parameters rather than inventing constants
//!   it cannot cite.
//! * **The unit of the deadline differs.** `walkDeadlineMs` is the last offset
//!   plus one query's wait, because the last query is *also* answered. Here the
//!   budget bounds the whole resolve, and `Deadline.remaining` reports what is
//!   left of it, so a caller can hand a source the time that is actually left
//!   rather than a per-source constant.
//!
//! The shape — offsets from the start of the run, the first due at zero, a
//! deadline derived from the last offset — is the same shape, and that is
//! because `iroh-dns` wrote it down for DNS and it happens to be the right
//! shape for a set of sources too. Reusing the *values* would be a claim about
//! two different questions; the shared part is stated here and the two tables
//! are separate.
//!
//! # A deadline that expires is an ordinary outcome, not a failure
//!
//! **Expiry is its own arm of `Decision`, and it is not an error.** A resolve
//! that ran out of time having found nothing and one that found a wrong answer
//! are different reports, and the difference runs the other way from what
//! "expired" usually means: an expiry is not a fault in anything.
//!
//! * **Nothing went wrong.** No source refused, no packet failed to decode, no
//!   answer contradicted another. The budget is a policy the caller set, and a
//!   policy running out is the policy working. `Decision.expired` carries no
//!   reason and `Deadline.spent` is not an `error`, so a caller cannot
//!   accidentally route an expiry through a `catch` that treats it like a
//!   malformed answer.
//! * **It is still not "nothing found".** A source that has not been asked yet
//!   has not reported emptiness, so a resolve that expires after one empty
//!   source and one unasked source did *not* establish that the node published
//!   nothing. `discovery/lookup_io.zig`'s module doc is the authority: a
//!   timeout is a fact about the deadline and not about the world, and mapping
//!   it onto `nothing` is the collapse that ends a walk early. `Decision`'s
//!   arms keep them apart, and a caller that wants a single line reports the
//!   sources never asked — `Deadline.outstanding` — beside the answer it got.
//! * **The merge already knows the difference.**
//!   `discovery/resolve_fanin.zig`'s `Outcome.incomplete` is what a merge of a
//!   source that failed and a source that was never asked comes to, and this
//!   module never produces that answer itself: it produces `expired`, and the
//!   merge consumes the reports. That separation is why this file imports
//!   nothing from the fan-in and the fan-in imports nothing from this file.
//!
//! A source that is *skipped* by the budget is a fourth fact beside the three
//! in `lookup_io.zig`: it is not a timeout of one question, it is a question
//! that never went out. `Decision.pending` is the caller spelling out, and
//! `Schedule.due` is what says a source is owed.

const std = @import("std");

// Named so the last test can hold this module's separation from
// `discovery/host_io.zig`'s schedule to that module's values rather than to a
// comment. No production code below reaches into it: the two schedules are
// deliberately not the same question, and a test-only import is the honest
// shape of that.
const host_io = @import("host_io.zig");

const t = std.testing;

/// When each source is asked, as offsets from the start of the resolve.
///
/// Non-decreasing, with the first entry 0 for the source that goes out
/// immediately — the requirement `init` enforces, and the reason `due` counts
/// the first entry without looking at it. See the module doc for why these
/// offsets are not `discovery/host_io.zig`'s.
pub const Schedule = struct {
    /// Offset from the start of the resolve at which each source is asked, in
    /// milliseconds. Borrowed for the life of the schedule. Empty is a valid
    /// schedule and means a resolve with no sources, which expires at once.
    starts: []const u64,
    /// The whole resolve may take this long, in milliseconds from its start.
    /// A budget below the last start is refused by `init`, because a schedule
    /// that cannot finish what it starts is not a schedule.
    budget_ms: u64,
    /// The time one source may take once it has been asked, in milliseconds.
    ///
    /// A parameter and not a constant, for the reason the offsets are: this is
    /// `iroh-dns`'s `DNS_TIMEOUT` for a DNS walk and something else for a
    /// relay, and no captured file on this machine gives the second number.
    /// Zero is refused: a source asked with no time to answer is a source that
    /// will expire, and saying so at construction beats discovering it later.
    source_budget_ms: u64,

    /// What this module refuses.
    ///
    /// Four arms because each names a different mistake a caller can make in
    /// a table, and `init` is the one place all four are caught: a caller that
    /// got one wrong would otherwise find out by watching a resolve that asks
    /// its sources in the wrong order, or never asks the first one at all.
    pub const Error = error{
        /// `starts` is empty. A resolve with no sources has nothing to wait
        /// for and would report a merge of nothing, which is a configuration
        /// that should be written down rather than discovered.
        NoSources,
        /// `starts[0]` is not zero, so the table asks for its first source
        /// later than the start of the resolve it describes.
        FirstStartNotZero,
        /// `starts` is not non-decreasing, so a source's offset says it comes
        /// after a later source's.
        UnorderedStart,
        /// A start is after `budget_ms`, or `source_budget_ms` is zero.
        StartAfterBudget,
    };

    /// A checked schedule from an offset table and a budget.
    ///
    /// The checks are what make the rest of this file total: `Schedule` can be
    /// built as a literal with an unordered table or a late first source, and
    /// `due` on such a table answers a question about a schedule nobody would
    /// run.
    pub fn init(
        starts: []const u64,
        budget_ms: u64,
        source_budget_ms: u64,
    ) Error!Schedule {
        if (starts.len == 0) return error.NoSources;
        if (source_budget_ms == 0) return error.StartAfterBudget;
        if (starts[0] != 0) return error.FirstStartNotZero;
        var previous: u64 = 0;
        for (starts, 0..) |offset, index| {
            if (index > 0 and offset < previous) return error.UnorderedStart;
            if (offset > budget_ms) return error.StartAfterBudget;
            previous = offset;
        }
        return .{ .starts = starts, .budget_ms = budget_ms, .source_budget_ms = source_budget_ms };
    }

    /// How many sources are due at `elapsed_ms`: every source whose offset has
    /// arrived. The first is counted without looking at it, because `init`
    /// refuses a table whose first entry is not zero, so a schedule this file
    /// accepted always owes its first source at the start.
    ///
    /// A count and not an index, for `host_io.attemptsDue`'s reason: the
    /// sources are independent, so a caller that arrives late owes every ask it
    /// missed rather than only the most recent one. Saturates at the table's
    /// length, because a caller that is very late still owes every source and
    /// not `elapsed_ms / step` of them.
    ///
    /// Never zero: the first source is due at the start of a resolve whatever
    /// its offset says, and a resolve that had asked nobody would ask nobody.
    /// An empty table is zero, because a resolve with no sources has nothing
    /// due and `init` refuses one anyway.
    pub fn due(self: Schedule, elapsed_ms: u64) usize {
        if (self.starts.len == 0) return 0;
        var count: usize = 1;
        for (self.starts[1..]) |offset| {
            if (elapsed_ms < offset) break;
            count += 1;
        }
        return count;
    }

    /// The instant at which the whole resolve is over, in milliseconds from its
    /// start: the budget the caller set.
    ///
    /// `host_io.walkDeadlineMs` derives its six seconds as the last offset plus
    /// one query's wait, and the same arithmetic is offered here as
    /// `derivedBudgetMs` for a caller who wants that derivation rather than a
    /// number of their own. A caller that supplies the budget directly gets a
    /// value this tree cannot check against upstream, which is why it is a
    /// parameter.
    pub fn deadlineMs(self: Schedule) u64 {
        return self.budget_ms;
    }

    /// The budget `host_io.walkDeadlineMs` would derive for this table: the
    /// last offset plus one source's whole allowance.
    ///
    /// Offered so a caller can see the shape it is choosing against, and so a
    /// test can hold the arithmetic to `discovery/host_io.zig`'s rule without
    /// this module taking the number over.
    pub fn derivedBudgetMs(self: Schedule) u64 {
        const last = self.starts[self.starts.len - 1];
        return std.math.add(u64, last, self.source_budget_ms) catch
            std.math.maxInt(u64);
    }

    /// What is left of the budget at `elapsed_ms`, or zero when it is gone.
    ///
    /// Saturating rather than wrapping: a resolve that has been running for
    /// longer than its budget has no negative remainder, and a wrapped
    /// `u64` would read as a fresh budget.
    pub fn remainingMs(self: Schedule, elapsed_ms: u64) u64 {
        if (elapsed_ms >= self.budget_ms) return 0;
        return self.budget_ms - elapsed_ms;
    }

    /// Whether the budget is spent at `elapsed_ms`.
    pub fn spent(self: Schedule, elapsed_ms: u64) bool {
        return elapsed_ms >= self.budget_ms;
    }
};

/// What a caller does next, given the elapsed time and how many sources have
/// already been asked.
///
/// Three arms and no error: see the module doc's third section. `expired` is a
/// result, not a fault, and a type that could return an error for it would
/// invite a `catch` that logs it as one.
pub const Decision = union(enum) {
    /// The resolve is over, and this is why.
    done: Stop,
    /// Sources are still owed and the budget has time left. `due` is how many
    /// are owed, and `wait_ms` is how long until the next one is due, or zero
    /// when one is due now.
    pending: Pending,
};

/// Why a resolve stopped, or that it has not.
pub const Stop = enum {
    /// Every source in the schedule has been asked and answered within its
    /// allowance. The ordinary end of a resolve, and the only one that says
    /// the sources were heard from.
    complete,
    /// The budget ran out with `outstanding` sources still owed.
    ///
    /// **Not a failure and not an absence.** Nothing failed; the sources the
    /// caller had not asked yet were never asked, which is a fact about the
    /// schedule and the clock rather than about the node. See the module doc.
    expired,
};

/// What a caller still owes the resolve, and how long it has.
pub const Pending = struct {
    /// How many sources are due to have been asked at this instant.
    due: usize,
    /// Milliseconds until the next source is due. Zero when one is due now,
    /// which is what makes a caller that arrives late ask everything it missed
    /// rather than the one it would have asked on time.
    wait_ms: u64,
};

/// What the resolve should do at `elapsed_ms`, having asked `asked` sources.
///
/// `asked` is a count and not a set because the schedule is non-decreasing, so
/// the sources asked so far are the first `asked` of the table and the next one
/// is `starts[asked]`. That is what lets this function be a function of two
/// numbers rather than a callback over a list of state.
///
/// `Stop.expired` carries nothing about *why* a source has not answered, and
/// that is deliberate: this module knows nothing about the answers, and
/// `discovery/resolve_fanin.zig` knows nothing about the clock. A caller
/// composes the two — a source that expired unasked and a source that failed
/// are the same merge outcome, and only the caller can say which it had.
pub fn step(schedule: Schedule, elapsed_ms: u64, asked: usize) Decision {
    const total = schedule.starts.len;
    // Asked more than the table has means the caller is counting a source
    // twice; clamp rather than index past the end, because a caller with a
    // miscount deserves a finished resolve and not a panic in its scheduler.
    const count = @min(asked, total);
    if (count == total) return .{ .done = .complete };
    if (schedule.spent(elapsed_ms)) return .{ .done = .expired };

    const next_due: u64 = schedule.starts[count];
    return .{ .pending = .{
        .due = schedule.due(elapsed_ms),
        .wait_ms = if (elapsed_ms >= next_due) 0 else next_due - elapsed_ms,
    } };
}

/// How many sources a resolve has not asked yet, given that it has asked
/// `asked`.
///
/// `total - min(asked, total)`, and the clock does not enter it. The schedule
/// is non-decreasing, so the sources asked so far are the first `asked` of the
/// table and the rest are owed whatever the elapsed time says — including at
/// an expiry, where a source whose offset had arrived and was never asked is
/// the very thing the caller reports beside its answer. `Schedule.due` is
/// where the clock does appear.
pub fn outstanding(schedule: Schedule, asked: usize) usize {
    const total = schedule.starts.len;
    return total - @min(asked, total);
}

/// A node's own table, three sources and a budget, for the tests.
///
/// Hand-written and not a corpus: the point of these tests is the arithmetic
/// at named instants, and a seeded table would move the instants under the
/// assertions.
const test_starts = [_]u64{ 0, 100, 400 };
const test_budget_ms: u64 = 700;
const test_source_budget_ms: u64 = 300;

fn testSchedule() !Schedule {
    return Schedule.init(&test_starts, test_budget_ms, test_source_budget_ms);
}

test "the first source is due at zero and the rest by their offsets" {
    const schedule = try testSchedule();
    try t.expectEqual(@as(usize, 3), schedule.starts.len);
    try t.expectEqual(@as(usize, 1), schedule.due(0));
    try t.expectEqual(@as(usize, 1), schedule.due(99));
    try t.expectEqual(@as(usize, 2), schedule.due(100));
    try t.expectEqual(@as(usize, 2), schedule.due(399));
    try t.expectEqual(@as(usize, 3), schedule.due(400));
    // Saturates at the table's length rather than growing with elapsed time,
    // so a caller that is very late still owes three asks.
    try t.expectEqual(@as(usize, 3), schedule.due(700));
    try t.expectEqual(@as(usize, 3), schedule.due(1_000_000));
    // And never zero: a resolve that had asked nobody would ask nobody. The
    // one exception is a table with no sources, which `init` refuses.
    for (test_starts) |offset| {
        try t.expect(schedule.due(offset) >= 1);
    }
    // The one case that yields zero, built as a literal rather than through
    // `init`: the empty table is the shape `init` refuses, and `due` still has
    // to answer it rather than read past the end of nothing.
    const empty: Schedule = .{
        .starts = &.{},
        .budget_ms = test_budget_ms,
        .source_budget_ms = test_source_budget_ms,
    };
    try t.expectEqual(@as(usize, 0), empty.due(0));
    try t.expectEqual(@as(usize, 0), empty.due(1_000_000));
    try t.expectEqual(@as(usize, 0), outstanding(empty, 0));
}

test "a budget that expires is an outcome and not an error" {
    const schedule = try testSchedule();
    // Three hundred milliseconds into the resolve with two sources asked: the
    // third is not due until 400, so the caller waits exactly the gap. A
    // caller holding one asked instead owes the second, whose offset of 100
    // has passed, and waits zero rather than the gap — that is the late
    // caller, and the fourth test drives it. Read through a `switch` rather
    // than by comparing the union, so a test cannot pass on a tag while
    // reading the payload of the other arm.
    const waiting: Pending = switch (step(schedule, 300, 2)) {
        .pending => |owed| owed,
        .done => return error.TestUnexpectedResult,
    };
    try t.expectEqual(@as(usize, 2), waiting.due);
    try t.expectEqual(@as(u64, 100), waiting.wait_ms);

    // The instant the budget runs out with a source still unasked: done, and
    // `expired`. Not an error, not `complete`, and not a claim that the node
    // published nothing — `outstanding` says who was never asked.
    const over: Stop = switch (step(schedule, test_budget_ms, 1)) {
        .done => |why| why,
        .pending => return error.TestUnexpectedResult,
    };
    try t.expectEqual(Stop.expired, over);
    try t.expectEqual(@as(usize, 2), outstanding(schedule, 1));
    // Long past the budget the answer is the same, and the wait never wraps
    // into a fresh budget.
    try t.expectEqual(
        Stop.expired,
        switch (step(schedule, 1_000_000, 1)) {
            .done => |why| why,
            .pending => return error.TestUnexpectedResult,
        },
    );
    try t.expectEqual(@as(u64, 0), schedule.remainingMs(1_000_000));
}

test "a resolve ends complete only when every source answered" {
    const schedule = try testSchedule();
    // All three asked: complete, whatever the clock says, because the sources
    // were heard from and the budget is no longer the question. Read through a
    // `switch` so the assertion is on the arm that carries the payload.
    inline for (.{ @as(u64, 500), @as(u64, 9_000) }) |at| {
        try t.expectEqual(
            Stop.complete,
            switch (step(schedule, at, 3)) {
                .done => |why| why,
                .pending => return error.TestUnexpectedResult,
            },
        );
    }
    // A source that answered in time did not stop answering because the budget
    // later ran out, so a resolve past its budget with nothing owed is still
    // complete rather than expired.
    try t.expectEqual(@as(usize, 0), outstanding(schedule, 3));
    // A caller that over-counts is finished rather than indexing past the end
    // of the table, which is what makes `step` total over a miscounted caller.
    try t.expectEqual(
        Stop.complete,
        switch (step(schedule, 0, 4)) {
            .done => |why| why,
            .pending => return error.TestUnexpectedResult,
        },
    );
    // And an unasked source is not owed once the resolve is over.
    try t.expectEqual(@as(usize, 0), outstanding(schedule, 3));
}

test "a source due now is asked now and a missed one is still owed" {
    const schedule = try testSchedule();
    // A caller that arrives at the last offset having asked one source owes
    // both the second and the third: the wait is zero because a source is due,
    // and `due` says how far behind the caller is. Collapsing the missed ask
    // into one is `attemptsDue`'s rule read the wrong way round — a late
    // caller owes every ask it missed.
    const late: Pending = switch (step(schedule, 400, 1)) {
        .pending => |owed| owed,
        .done => return error.TestUnexpectedResult,
    };
    try t.expectEqual(@as(usize, 3), late.due);
    try t.expectEqual(@as(u64, 0), late.wait_ms);

    // On time, the first source is due at zero and the wait is zero rather
    // than a gap to nothing.
    const on_time: Pending = switch (step(schedule, 0, 0)) {
        .pending => |owed| owed,
        .done => return error.TestUnexpectedResult,
    };
    try t.expectEqual(@as(usize, 1), on_time.due);
    try t.expectEqual(@as(u64, 0), on_time.wait_ms);

    // And the gap is measured to the source the caller has not asked yet.
    const between: Pending = switch (step(schedule, 50, 1)) {
        .pending => |owed| owed,
        .done => return error.TestUnexpectedResult,
    };
    try t.expectEqual(@as(u64, 50), between.wait_ms);
    // The budget has time throughout, which is what makes these three the
    // `pending` arm rather than `expired`.
    try t.expect(!schedule.spent(400));
    try t.expectEqual(@as(u64, 300), schedule.remainingMs(400));
}

test "a schedule that cannot finish what it starts is refused" {
    // The four mistakes a table can hold, caught once here so `due` and
    // `step` can assume the table is one a caller would run.
    try t.expectError(error.NoSources, Schedule.init(&.{}, 700, 300));
    try t.expectError(error.FirstStartNotZero, Schedule.init(&.{ 100, 400 }, 700, 300));
    try t.expectError(error.UnorderedStart, Schedule.init(&.{ 0, 400, 100 }, 700, 300));
    try t.expectError(error.StartAfterBudget, Schedule.init(&.{ 0, 900 }, 700, 300));
    // A source allowance of zero is refused: a source asked with no time to
    // answer is a source that will expire, and `init` says so rather than
    // letting the schedule report it later as a fact about the clock.
    try t.expectError(error.StartAfterBudget, Schedule.init(&test_starts, 700, 0));
    // A table that holds only the one source every resolve has is accepted,
    // so the check is about a late first source and not about a short table.
    const alone = try Schedule.init(&.{0}, 700, test_source_budget_ms);
    try t.expectEqual(@as(usize, 1), alone.due(0));
    try t.expectEqual(@as(usize, 1), alone.due(1_000_000));
    // The table this file's own tests run on is one `init` accepts.
    try t.expectEqual(@as(usize, 3), (try testSchedule()).starts.len);
}

test "the derived budget is the last offset plus one source's allowance" {
    // `host_io.walkDeadlineMs`'s arithmetic, offered here as a shape a caller
    // can take rather than a number this module claims: 400 + 300 = 700, the
    // same derivation `discovery/host_io.zig` derives its 3000 + 3000 from.
    const schedule = try testSchedule();
    try t.expectEqual(@as(u64, 700), schedule.derivedBudgetMs());
    try t.expectEqual(schedule.derivedBudgetMs(), schedule.deadlineMs());
    // A caller that sets its own budget gets it, because no captured upstream
    // file gives a resolve over a relay and a DNS walk the same number.
    const longer = try Schedule.init(&test_starts, 2_000, test_source_budget_ms);
    try t.expectEqual(@as(u64, 2_000), longer.deadlineMs());
    try t.expectEqual(@as(u64, 700), longer.derivedBudgetMs());
    try t.expect(!longer.spent(700));
    // And the sum saturates rather than wrapping, so a table with an enormous
    // last offset does not produce a budget that reads as a fresh one.
    const huge = try Schedule.init(&.{ 0, std.math.maxInt(u64) - 10 }, std.math.maxInt(u64), 300);
    try t.expectEqual(std.math.maxInt(u64), huge.derivedBudgetMs());
}

test "this schedule and host_io's are two questions, not one table" {
    // The module doc's second section, checked against the real module rather
    // than against a comment. Both are offsets from the start of a run and a
    // deadline, and four facts say they are different questions.
    const schedule = try testSchedule();

    // 1. The unit. `attemptsDue` answers "how many copies of one question have
    //    gone out", saturating at seven for upstream's six-offset table. `due`
    //    answers "how many sources are owed", and a source is asked once.
    try t.expectEqual(@as(usize, 7), host_io.attempts);
    try t.expectEqual(host_io.attempts, host_io.attemptsDue(1_000_000));
    try t.expectEqual(@as(usize, 3), schedule.due(1_000_000));
    // And the table that produces it is not this one, held as values rather
    // than asserted in prose.
    try t.expect(host_io.staggering_ms.len != schedule.starts.len);

    // 2. The first instant. Upstream's table starts at 200 because its first
    //    query is due at zero outside the table, so `attemptsDue` cannot
    //    answer zero. This module carries the zero in the table itself, which
    //    is why `due` counts the first entry unconditionally.
    try t.expectEqual(@as(usize, 1), host_io.attemptsDue(0));
    try t.expectEqual(@as(usize, 1), schedule.due(0));
    try t.expectEqual(@as(u64, 0), test_starts[0]);

    // 3. The deadline. `walkDeadlineMs` is *derived* — the last offset plus
    //    one query's wait, because the last query is also answered. This
    //    module's budget is a parameter and `derivedBudgetMs` is offered as
    //    that shape rather than taken over, so a caller may set any budget.
    try t.expectEqual(@as(u64, 6_000), host_io.walkDeadlineMs());
    try t.expectEqual(@as(u64, 700), schedule.derivedBudgetMs());
    const caller_budget = try Schedule.init(&test_starts, 3_000, test_source_budget_ms);
    try t.expectEqual(@as(u64, 3_000), caller_budget.deadlineMs());

    // 4. The allowance. `host_io`'s is a constant, so no caller can ask a
    //    source it will never answer. Here it is a parameter and zero is
    //    refused, which is the difference visible in the two types.
    try t.expectEqual(@as(u64, 3_000), host_io.query_timeout_ms);
    try t.expectError(error.StartAfterBudget, Schedule.init(&test_starts, 700, 0));
}
