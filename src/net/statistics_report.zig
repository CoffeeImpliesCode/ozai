//! Turning a `statistics.Table` into something a caller can act on.
//!
//! `statistics.zig` accumulates; this reads. Nothing here observes, decides or
//! mutates: `build` is a function of a table, an instant and a scratch buffer,
//! and it reads nothing else. No socket, no clock, no environment, no global,
//! no allocator — the two buffers are the caller's, so a test drives the whole
//! report with a table a test filled by hand.
//!
//! # Absent is not zero
//!
//! **A figure the report did not measure is absent, and the shape of this
//! module makes saying otherwise impossible rather than merely discouraged.**
//! Every latency and every instant in a `Row` is `?Nanos`; a zero latency is a
//! claim that something was instant, a zero age is a claim that an observation
//! happened this very nanosecond, and a report that measured nothing has made
//! both claims by printing a `0`. The counts are the exception and the reason
//! they are not: `attempted` is zero on a subject nobody measured *because
//! none were attempted*, and a count of zero is a fact about the run rather
//! than a stand-in for a missing measurement. The distinction the tree already
//! draws is `Varying.classify`'s null — "not measured", never "measured, and
//! symmetric" — and this module refuses to blur it.
//!
//! Three things follow, and each is a figure the report declines to state:
//!
//! - **A percentile.** The window holds `statistics.max_samples` samples and
//!   the report prints that count beside the median. A p95 over sixteen
//!   samples is the maximum wearing a distribution's name, and a reader who
//!   saw "p95" would believe a resolution the accumulator does not have.
//! - **A mean.** Same reason and one more: a mean over a window the report has
//!   already said it partly discarded is a mean of an unspecified sample.
//! - **A choice.** `Report.best` and `Report.worst` are null unless some row
//!   holds a `slowest`, so a table of filed-but-unmeasured subjects produces no
//!   preferred peer. Ranking needs a figure, and there is none.
//!
//! # Derived figures carry their operands
//!
//! `Row.failed` and `Row.dropped` are methods, not fields: each is a
//! subtraction of two stored counts, and a stored copy is a number that can
//! disagree with the two it came from. The subtraction is checked rather than
//! saturating, so a report that underflowed traps rather than printing a
//! plausible small figure — `statistics.Entry.failed` guarantees the ordering,
//! and the tests pin it.
//!
//! # The bound is inherited, not restated
//!
//! `max_rows` is `statistics.max_subjects`. The report carries one row per
//! entry the table holds and cannot carry more, so a second bound here would be
//! a number nothing could reach.
//!
//! # Row order
//!
//! Rows come out in `SocketAddr.order`, because `statistics.Table` keeps its
//! entries in that order and the report does not re-sort. That order is
//! load-bearing twice: a reader scans the rows in address order, and a tie on
//! `worst` keeps the earliest row, which is the lowest address, so the choice
//! does not depend on filing order either.

const std = @import("std");
const addr = @import("../base/addr.zig");
const stats = @import("statistics.zig");

const SocketAddr = addr.SocketAddr;

/// Nanoseconds on the caller's own monotonic timeline, under the name this
/// module's callers need it: `statistics.Nanos`, restated so a report reader
/// does not have to import the accumulators for a type alias.
pub const Nanos = stats.Nanos;

/// How many rows one report carries. `statistics.max_subjects`, and never
/// more: the report cannot hold a subject its table refused.
pub const max_rows: usize = stats.max_subjects;

/// One subject's figures as they are reported.
pub const Row = struct {
    /// What was measured. Never compared with `==`; `report_fold`'s reason
    /// applies and `node/node_relay_route.zig`'s `SocketAddr.order` is the
    /// spelling.
    subject: SocketAddr,
    /// How many measurements were started, answered or not. A count, so zero
    /// is an honest value.
    attempted: u64,
    /// How many round trips came back, including any the window has since
    /// overwritten.
    recorded: u64,
    /// How many samples the median was taken over. Printed beside the median
    /// because a median without its denominator is not a figure.
    held: u32,
    /// The fastest round trip ever measured, or null when none ever was.
    fastest: ?Nanos,
    /// The slowest round trip ever measured, or null when none ever was. This
    /// is the figure a peer choice is made on, and it is exact over the whole
    /// history rather than over the window.
    slowest: ?Nanos,
    /// The median of the recent window, or null when the window is empty. The
    /// lower of the two middles, so it is a round trip somebody measured.
    median: ?Nanos,
    /// When the last round trip came back, or null when none ever did.
    last_at: ?Nanos,
    /// How long ago that was as of the instant the report was built, or null
    /// when nothing was ever recorded.
    age: ?Nanos,

    /// How many attempts produced no measurement: `attempted - recorded`.
    ///
    /// Checked, not saturating. Every attempt either produced a sample or did
    /// not, so the subtraction cannot underflow and an underflow is a bug that
    /// should stop the build rather than become a plausible figure.
    pub fn failed(self: Row) u64 {
        return self.attempted - self.recorded;
    }

    /// How many samples the window no longer holds: `recorded - held`. The
    /// report's statement that the median is not a figure about the whole run.
    pub fn dropped(self: Row) u64 {
        return self.recorded - self.held;
    }
};

/// What this node has observed, at one instant, about every subject it is
/// measuring.
///
/// A value: every figure is copied out of the table at `build`, so a report
/// taken before a measurement still reads the way it did, and no report borrows
/// a buffer it might be holding on to.
pub const Report = struct {
    /// The rows, first `len` of them in `SocketAddr.order`.
    rows: [max_rows]Row = undefined,
    /// How many rows are live. Zero by default and never above `max_rows`.
    len: usize = 0,
    /// The subject to home on: the lowest `slowest` among the subjects that
    /// have one, or null when none does.
    ///
    /// Latency, for `report_fold.choosePreferredRelay`'s reason — the question
    /// is which peer to try first, and the answer is the one that has been
    /// fastest in its worst case rather than on average.
    best: ?SocketAddr = null,
    /// The subject with the highest `slowest`, or null when none has one. The
    /// one a caller reads when it is deciding whether to stop using a peer.
    worst: ?SocketAddr = null,

    /// The rows, exactly `rows[0..len]`.
    pub fn slice(self: *const Report) []const Row {
        return self.rows[0..self.len];
    }

    /// The row for `subject`, by value, or null for a subject this report does
    /// not carry.
    ///
    /// A scan and not a second index: `max_rows` is eight, so the walk costs
    /// less than the index would have to be kept in step with.
    pub fn row(self: *const Report, subject: SocketAddr) ?Row {
        for (self.rows[0..self.len]) |held| {
            if (held.subject.order(subject) == .eq) return held;
        }
        return null;
    }

    /// The report as text, one line per row.
    ///
    /// **Every figure that is absent is left out, label and all**, so a line
    /// with no latency on it does not read as a latency of zero. Counts are
    /// printed even at zero, because a count of zero is a fact; the module doc
    /// says why that is a different thing from a missing measurement.
    pub fn format(self: Report, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        for (self.rows[0..self.len]) |held| {
            try writer.print("{f} attempts={d} measured={d} failed={d} dropped={d}", .{
                held.subject,
                held.attempted,
                held.recorded,
                held.failed(),
                held.dropped(),
            });
            if (held.fastest) |figure| try writer.print(" fastest={d}ns", .{figure});
            if (held.slowest) |figure| try writer.print(" slowest={d}ns", .{figure});
            if (held.median) |figure| {
                try writer.print(" median={d}ns held={d}", .{ figure, held.held });
            }
            if (held.age) |age| try writer.print(" age={d}ns", .{age});
            try writer.writeAll("\n");
        }
    }
};

/// Read `table` as it stood at `now`.
///
/// `scratch` is where each subject's window is sorted on the way past, and it
/// is the caller's buffer because this module allocates nothing: the whole
/// report is built in `Report`'s inline array, and a caller that wants the
/// report on the heap asks for it.
///
/// Pure over its three arguments. It reads no clock — `now` is an argument, and
/// `age` is the only figure that depends on it — no environment, no global and
/// no allocator, and it writes to `scratch` and to the report it returns. Two
/// calls with equal arguments produce equal reports whatever order the table's
/// subjects were filed in.
pub fn build(
    table: *const stats.Table,
    now: Nanos,
    scratch: *[stats.max_samples]Nanos,
) Report {
    var report: Report = .{};
    var best: ?usize = null;
    var worst: ?usize = null;

    for (table.slice(), 0..) |entry, index| {
        const summary = entry.latency.summary(scratch);
        report.rows[index] = .{
            .subject = entry.subject,
            .attempted = entry.attempted.value,
            .recorded = summary.recorded,
            .held = summary.held,
            .fastest = summary.fastest,
            .slowest = summary.slowest,
            .median = summary.median,
            .last_at = entry.last.at,
            .age = entry.last.since(now),
        };
        report.len += 1;

        // A row with no `slowest` is not ranked: it says nothing about how slow
        // anything was, and a choice made over it would be a choice over
        // nothing.
        const figure = summary.slowest orelse continue;
        // Strict, so a tie keeps the earliest row, and the rows are in
        // `SocketAddr.order` — so the tie is broken by the lower address rather
        // than by whoever was measured first.
        if (worst) |held| {
            if (figure > report.rows[held].slowest.?) worst = index;
        } else {
            worst = index;
        }
        if (best) |held| {
            if (figure < report.rows[held].slowest.?) best = index;
        } else {
            best = index;
        }
    }

    if (best) |index| report.best = report.rows[index].subject;
    if (worst) |index| report.worst = report.rows[index].subject;
    return report;
}

// --- tests

const t = std.testing;

/// An instant the tests hand to `build`, ten minutes in on the caller's
/// timeline.
const test_now: Nanos = 600 * std.time.ns_per_s;

/// A subject named by its last octet, on one port.
fn testSubject(tag: u8) SocketAddr {
    return .{ .ip = .{ .v4 = .{ 198, 51, 100, tag } }, .port = 41234 };
}

/// A round trip in the units the assertions read.
fn millis(n: u64) Nanos {
    return n * std.time.ns_per_ms;
}

/// A table with one answered and two unanswered attempts against one subject.
fn mixedTable() !stats.Table {
    var table: stats.Table = .{};
    _ = try table.open(testSubject(1));
    const entry = table.find(testSubject(1)).?;
    entry.attempt(null, test_now);
    entry.attempt(millis(15), test_now);
    entry.attempt(null, test_now);
    return table;
}

test "a report of an empty table names nothing" {
    const table: stats.Table = .{};
    var scratch: [stats.max_samples]Nanos = undefined;
    const report = build(&table, test_now, &scratch);

    try t.expectEqual(@as(usize, 0), report.len);
    try t.expectEqual(@as(usize, 0), report.slice().len);
    try t.expectEqual(@as(?SocketAddr, null), report.best);
    try t.expectEqual(@as(?SocketAddr, null), report.worst);
    try t.expectEqual(@as(?Row, null), report.row(testSubject(1)));

    // An empty report says nothing at all rather than saying zero of things.
    var buffer: [512]u8 = undefined;
    var out = std.Io.Writer.fixed(&buffer);
    try report.format(&out);
    try t.expectEqual(@as(usize, 0), out.buffered().len);
}

test "a subject nobody measured reports no latency rather than a zero one" {
    var table: stats.Table = .{};
    _ = try table.open(testSubject(1));
    var scratch: [stats.max_samples]Nanos = undefined;
    const report = build(&table, test_now, &scratch);

    const row = report.row(testSubject(1)).?;
    try t.expectEqual(@as(u64, 0), row.attempted);
    try t.expectEqual(@as(u64, 0), row.recorded);
    try t.expectEqual(@as(u32, 0), row.held);
    try t.expectEqual(@as(u64, 0), row.failed());
    try t.expectEqual(@as(u64, 0), row.dropped());
    // Every latency and every instant is absent. A zero here would claim that
    // something round-tripped instantly.
    try t.expectEqual(@as(?Nanos, null), row.fastest);
    try t.expectEqual(@as(?Nanos, null), row.slowest);
    try t.expectEqual(@as(?Nanos, null), row.median);
    try t.expectEqual(@as(?Nanos, null), row.last_at);
    try t.expectEqual(@as(?Nanos, null), row.age);

    // And nothing is ranked, because no row holds a latency to rank on.
    try t.expectEqual(@as(?SocketAddr, null), report.best);
    try t.expectEqual(@as(?SocketAddr, null), report.worst);

    // The text carries the counts — a count of zero is a fact about the run —
    // and not one label of an absent figure.
    var buffer: [512]u8 = undefined;
    var out = std.Io.Writer.fixed(&buffer);
    try report.format(&out);
    const text = out.buffered();
    try t.expect(std.mem.indexOf(u8, text, "attempts=0") != null);
    try t.expect(std.mem.indexOf(u8, text, "fastest=") == null);
    try t.expect(std.mem.indexOf(u8, text, "slowest=") == null);
    try t.expect(std.mem.indexOf(u8, text, "median=") == null);
    try t.expect(std.mem.indexOf(u8, text, "age=") == null);
}

test "a refused subject reaches no report at all" {
    // The table's bound is the report's bound, so a subject the table never
    // filed cannot be a row with zeros in it.
    var table: stats.Table = .{};
    var tag: usize = 1;
    while (tag <= stats.max_subjects) : (tag += 1) {
        _ = try table.open(testSubject(@intCast(tag)));
    }
    const stranger = testSubject(stats.max_subjects + 1);
    try t.expectError(error.NoFreeSubject, table.open(stranger));

    var scratch: [stats.max_samples]Nanos = undefined;
    const report = build(&table, test_now, &scratch);
    try t.expectEqual(@as(usize, stats.max_subjects), report.len);
    try t.expectEqual(@as(usize, stats.max_subjects), report.slice().len);
    try t.expectEqual(@as(?Row, null), report.row(stranger));
}

test "a failed attempt is a count and never a latency" {
    var table = try mixedTable();
    var scratch: [stats.max_samples]Nanos = undefined;
    const report = build(&table, test_now, &scratch);

    const row = report.row(testSubject(1)).?;
    try t.expectEqual(@as(u64, 3), row.attempted);
    try t.expectEqual(@as(u64, 1), row.recorded);
    try t.expectEqual(@as(u64, 2), row.failed());
    try t.expectEqual(@as(u32, 1), row.held);
    try t.expectEqual(@as(u64, 0), row.dropped());
    // One measurement, so one latency. The two refusals left no sample behind.
    try t.expectEqual(millis(15), row.fastest.?);
    try t.expectEqual(millis(15), row.slowest.?);
    try t.expectEqual(millis(15), row.median.?);
    try t.expectEqual(@as(Nanos, 0), row.age.?);

    var buffer: [512]u8 = undefined;
    var out = std.Io.Writer.fixed(&buffer);
    try report.format(&out);
    const text = out.buffered();
    try t.expect(std.mem.indexOf(u8, text, "attempts=3") != null);
    try t.expect(std.mem.indexOf(u8, text, "measured=1") != null);
    try t.expect(std.mem.indexOf(u8, text, "failed=2") != null);
    try t.expect(std.mem.indexOf(u8, text, "median=15000000ns") != null);
}

test "the window size and what it discarded are reported beside the median" {
    var table: stats.Table = .{};
    _ = try table.open(testSubject(1));
    const entry = table.find(testSubject(1)).?;
    var step: u64 = 1;
    while (step <= stats.max_samples + 3) : (step += 1) entry.attempt(millis(step), step);

    var scratch: [stats.max_samples]Nanos = undefined;
    const report = build(&table, test_now, &scratch);

    const row = report.row(testSubject(1)).?;
    try t.expectEqual(@as(u64, stats.max_samples + 3), row.recorded);
    try t.expectEqual(@as(u32, stats.max_samples), row.held);
    try t.expectEqual(@as(u64, 3), row.dropped());
    // The window is the sixteen most recent — 4 ms through 19 ms — so the
    // median is the lower of its two middles, and the all-time extrema are
    // the ones no overwrite took.
    try t.expectEqual(millis(11), row.median.?);
    try t.expectEqual(millis(1), row.fastest.?);
    try t.expectEqual(millis(19), row.slowest.?);

    var buffer: [512]u8 = undefined;
    var out = std.Io.Writer.fixed(&buffer);
    try report.format(&out);
    const text = out.buffered();
    try t.expect(std.mem.indexOf(u8, text, "dropped=3") != null);
    try t.expect(std.mem.indexOf(u8, text, "held=16") != null);
}

test "best and worst rank on the slowest latency and break a tie by address" {
    var table: stats.Table = .{};
    _ = try table.open(testSubject(1));
    _ = try table.open(testSubject(2));
    _ = try table.open(testSubject(3));
    _ = try table.open(testSubject(4));
    table.find(testSubject(1)).?.attempt(millis(40), test_now);
    table.find(testSubject(2)).?.attempt(millis(10), test_now);
    table.find(testSubject(2)).?.attempt(millis(40), test_now);
    table.find(testSubject(3)).?.attempt(millis(90), test_now);
    // subject(4) is filed and never measured, so it is a row and not a rank.

    var scratch: [stats.max_samples]Nanos = undefined;
    const report = build(&table, test_now, &scratch);

    try t.expectEqual(@as(usize, 4), report.len);
    // 1 and 2 tie on a worst case of 40 ms and the lower address wins.
    try t.expect(testSubject(1).order(report.best.?) == .eq);
    try t.expect(testSubject(3).order(report.worst.?) == .eq);
    // The unmeasured row is present and ranked nowhere: it holds no slowest
    // latency, and ranking needs one.
    const unmeasured = report.row(testSubject(4)).?;
    try t.expectEqual(@as(?Nanos, null), unmeasured.slowest);
    try t.expect(testSubject(4).order(report.best.?) != .eq);
    try t.expect(testSubject(4).order(report.worst.?) != .eq);
}

test "a report is a value of the table and of the instant, not a view" {
    var table: stats.Table = .{};
    _ = try table.open(testSubject(1));
    table.find(testSubject(1)).?.attempt(millis(10), test_now - millis(30));
    var scratch: [stats.max_samples]Nanos = undefined;
    const before = build(&table, test_now, &scratch);
    try t.expectEqual(millis(10), before.slice()[0].slowest.?);
    try t.expectEqual(millis(30), before.slice()[0].age.?);

    // Recording more moves the table and not the report, so a caller holding
    // an earlier report is holding the figures it was built with.
    const entry = table.find(testSubject(1)).?;
    entry.attempt(millis(90), test_now);
    entry.attempt(null, test_now);
    try t.expectEqual(@as(u64, 3), entry.attempted.value);
    try t.expectEqual(@as(u64, 2), entry.failed());
    try t.expectEqual(@as(u64, 1), before.slice()[0].attempted);
    try t.expectEqual(millis(10), before.slice()[0].slowest.?);
    try t.expect(testSubject(1).order(before.best.?) == .eq);

    // And the same table at the same instant reports the same figures, so the
    // scratch buffer is not an input to anything.
    const again = build(&table, test_now, &scratch);
    try t.expectEqual(@as(u64, 3), again.slice()[0].attempted);
    try t.expectEqual(@as(u64, 1), again.slice()[0].failed());
    try t.expectEqual(millis(90), again.slice()[0].slowest.?);
}

test "time is an argument, so a later report is an older age" {
    var table: stats.Table = .{};
    _ = try table.open(testSubject(1));
    table.find(testSubject(1)).?.attempt(millis(10), test_now - millis(10));
    var scratch: [stats.max_samples]Nanos = undefined;

    const later = build(&table, test_now, &scratch);
    const earlier = build(&table, test_now - millis(100), &scratch);
    const future = build(&table, test_now + millis(100), &scratch);

    // One measurement, three instants: the latencies are the same three times
    // and only the age moves, which is what "pure over its inputs" means for a
    // report whose caller owns the clock.
    try t.expectEqual(millis(10), later.slice()[0].age.?);
    try t.expectEqual(@as(Nanos, 0), earlier.slice()[0].age.?);
    try t.expectEqual(millis(110), future.slice()[0].age.?);
    try t.expectEqual(later.slice()[0].recorded, earlier.slice()[0].recorded);
    try t.expectEqual(later.slice()[0].median.?, earlier.slice()[0].median.?);
}
