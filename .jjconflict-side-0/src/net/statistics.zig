//! The measurement layer: what has been observed, accumulated.
//!
//! `node/node_stats.zig` counts events on a running node — one flat struct of
//! `u64`s a caller reads by field. This is the other half: the figures that
//! only exist once a caller says *for which subject*, and the rule for keeping
//! them finite. Nothing here opens a socket, reads a clock, or allocates. Time
//! arrives as the `now` argument of `Entry.attempt`, and every value in a
//! `Table` is a word or an inline array, so a whole table is a stack value a
//! test holds and a copy of one is independent of the original.
//!
//! # Three kinds, in three types
//!
//! A count, a length and an instant mixed in one row is how a median becomes
//! meaningless, so each kind has its own type and a caller cannot hand a
//! nanosecond figure to a field that expects occurrences. The kinds are told
//! apart by what may be done to them, not by what they look like:
//!
//! - **Counts** — `Counter`. How many times something happened. Additive,
//!   never subtracted, and stored in one word, so a count's memory cost is
//!   fixed by construction and needs no bound of its own. Saturating, for
//!   `path_table.Entry.tx_bytes`'s reason: a counter that wraps reports a small
//!   number on a node that saw a large one and nothing downstream notices.
//! - **Latencies** — `Latencies`. A length in `Nanos`. Not additive with
//!   counts, and the module's one composition proves why: a probe that never
//!   got an answer contributes an attempt and **no sample**, because a
//!   "failure latency" of zero would drag the median to zero, which is a claim
//!   that the failure was instant.
//! - **Instants** — `Last`. A position on the timeline, not a length. Never
//!   summed, never averaged, never in a sample window, and `?Nanos` because
//!   "never observed" and "observed at zero" are different facts, which
//!   `path_table.Entry.rtt_at` already has to keep apart.
//!
//! # Deliberately not here
//!
//! - **A gauge.** "How many probes are outstanding" is `attempted` minus
//!   `recorded`, and storing it as a third number that must be kept in step
//!   with two others is the "two tables and two ways to be wrong" that
//!   `topic_table.removePeer` declines. It is computed where it is read.
//! - **A ratio.** Derived, and every operand can change after it is written,
//!   so a stored ratio is a figure that is stale on arrival.
//! - **A percentile.** See the sample policy below.
//!
//! # The sample policy: most recent N, and the extrema survive
//!
//! A latency set must answer something at its bound, and the three answers
//! cost and lie differently:
//!
//! - **Worst N** never forgets, so it answers "the worst period this subject
//!   ever had" under the name "the recent window", and it is monotone: a node
//!   that recovered still carries one two-second stall forever.
//!   `report_measure.RelayLatency` already took the opposite call for the same
//!   reason — it keeps a *minimum* over everything ever seen, not the last
//!   reading.
//! - **A running estimate** — an EWMA, a streaming quantile — is O(1) and it
//!   is unfalsifiable: two nodes with the same samples in a different order
//!   get different figures, and no test can tell one estimate from another.
//!   This directory already made order-independence load-bearing
//!   (`report_fold`'s `beats` and its permutation test, `report_measure`'s
//!   sorted `RelayList`), and a smoothing constant gives that up to save
//!   memory this tree does not need: `max_samples` nanoseconds is 128 bytes.
//! - **Most recent N** forgets the old samples, and its lie is the honest one
//!   because the report can name it: `Summary.held` and `Summary.dropped`
//!   state the window's size and how much history sits behind it, so no caller
//!   can read a median as a figure about the whole run.
//!
//! So the window is most-recent-N, and **the extrema are not in the window at
//! all**: `fastest` and `slowest` are exact over every sample ever recorded and
//! are never overwritten, so a subject measured a thousand times still answers
//! "how bad did it ever get". At the bound the set forgets the recent past,
//! keeps the all-time record, and counts what it forgot.
//!
//! # Why a subject refuses and a sample overwrites
//!
//! Two bounds, two answers, and the difference is what each bound holds. A
//! *subject* is an identity the caller is relying on — a relay it is homing on
//! — so the table refuses a ninth one with `error.NoFreeSubject` and evicts
//! nothing, for `topic_table.zig`'s reason: nothing anywhere would report the
//! loss. A *sample* is not an identity; it is one measurement of something
//! already represented, and refusing it would mean a probe that answered goes
//! unrecorded because the last sixteen probes also answered. The overwrite is
//! therefore not silent — `Summary.dropped` is the count, and the report
//! prints it.
//!
//! No address is ever compared with `==`: `SocketAddr` is a tagged union over
//! byte arrays and this build forbids equality on aggregates, so every
//! comparison goes through `SocketAddr.order`, the spelling
//! `node/node_relay_route.zig` uses.

const std = @import("std");
const addr = @import("../base/addr.zig");
const measure = @import("report_measure.zig");

const SocketAddr = addr.SocketAddr;

/// Nanoseconds on the caller's own monotonic timeline, under the name this
/// module's callers need it, so spelling a `now` here does not mean importing
/// `report.zig` for a type alias. `path_table.zig`'s spelling, reused.
pub const Nanos = measure.Nanos;

/// How many subjects one table carries at once.
///
/// The probe fan-out is `report_measure.max_relays` (five) and a peer keeps
/// `path_table.max_paths` (eight) live paths, so eight subjects is the product
/// ceiling of what this tree measures at any moment and the table never needs
/// a ninth. It is also the memory: an `Entry` is dominated by `max_samples`
/// nanoseconds of window, so eight entries are a couple of kilobytes of stack.
///
/// **A bound is a refusal.** `open` past it is `error.NoFreeSubject` and
/// nothing is displaced, for the reason the module doc gives.
pub const max_subjects: usize = 8;

/// How many samples one subject's window holds.
///
/// Sixteen, and the reason is that the median has to still move. At four, one
/// probe in three changes the middle; at sixteen, one in eight does, which is
/// coarse enough to be a summary and fine enough to be a signal. It is also the
/// size at which the question of a percentile stops being interesting: with
/// sixteen samples a p95 *is* the maximum, so a report that named one would be
/// naming the slowest sample it holds and calling it a distribution.
///
/// The bound is the window's, not the subject's, and it is the one place this
/// module overwrites rather than refusing; see the module doc.
pub const max_samples: usize = 16;

/// A number of occurrences, saturating.
///
/// The one-word kind. It has no memory bound of its own — a `u64` is a `u64` —
/// and it is a separate type only so that "counts saturate, and here is where
/// that rule lives" is stated once rather than left to every call site.
pub const Counter = struct {
    /// How many. Never below zero and never wraps: `add` saturates at
    /// `std.math.maxInt(u64)`, because a wrapped count is a small number on a
    /// node that saw a large one.
    value: u64 = 0,

    /// Count `by` more occurrences. Saturating, so a node that outlives 2⁶⁴
    /// events reads as having seen a great many rather than as having seen
    /// almost none.
    pub fn add(self: *Counter, by: u64) void {
        self.value +|= by;
    }
};

/// The instant of the most recent observation, or null when there is none.
///
/// Not a latency and not a count, which is the whole reason it is its own
/// type: an instant subtracted from another is a length, and both of those
/// are already spoken for. It is never averaged, never summed, and never a
/// member of a `Latencies` window.
pub const Last = struct {
    /// When the last observation was made, or null when nothing ever was.
    at: ?Nanos = null,

    /// Mark an observation as having happened now. A later mark replaces an
    /// earlier one: "when was the last one" has one answer, and a table of
    /// instants would be a second kind of history to bound.
    pub fn mark(self: *Last, now: Nanos) void {
        self.at = now;
    }

    /// How long ago that was, or null when nothing was ever marked.
    ///
    /// Saturating, for `path_table.Entry.carrying`'s reason: a caller whose
    /// timeline runs behind the mark reads zero, not a subtraction that wraps
    /// into the far past and reports an observation as ancient.
    pub fn since(self: *const Last, now: Nanos) ?Nanos {
        const marked = self.at orelse return null;
        return now -| marked;
    }
};

/// What a `Latencies` holds, read once.
///
/// `recorded` and `held` are deliberately both here. A median beside no count
/// is a number with no denominator, and `held` says exactly how many samples
/// the median was taken over.
pub const Summary = struct {
    /// How many samples were ever recorded, including the ones the window no
    /// longer holds. Never decremented, so it is a total of `record` calls
    /// rather than of samples present.
    recorded: u64,
    /// How many samples the window holds. Never above `max_samples`.
    held: u32,
    /// The fastest sample ever recorded, or null when nothing ever was. Exact
    /// over the whole history and never overwritten; see the module doc.
    fastest: ?Nanos,
    /// The slowest sample ever recorded, or null when nothing ever was. Exact
    /// over the whole history and never overwritten.
    slowest: ?Nanos,
    /// The window's median, or null while the window is empty. The **lower** of
    /// the two middles for an even window, and never a midpoint: the mean of
    /// 10 ms and 20 ms is a 15 ms round trip nobody made, and a report that
    /// printed it would be stating a figure it did not measure.
    median: ?Nanos,

    /// How many samples the window no longer holds.
    ///
    /// A method rather than a field because it is `recorded` minus `held` and a
    /// stored copy is a third number that can disagree with the two it came
    /// from.
    pub fn dropped(self: Summary) u64 {
        return self.recorded - self.held;
    }
};

/// One subject's round trips: the recent window plus the all-time extremes.
///
/// A fixed ring of `max_samples` slots. No allocator, so there is nothing to
/// inject a failure into and nothing to forget releasing; the whole cost of
/// the type is `max_samples` nanoseconds plus three words.
///
/// **A slot past `len` is never written and never read**, so a default value is
/// an empty set of observations and not a broken one. Read it through
/// `window` or `summary`.
pub const Latencies = struct {
    /// The ring. `[0..len]` in the order it is written while it is still
    /// filling; oldest first once it wraps. Past `len` is `undefined`.
    samples: [max_samples]Nanos = undefined,
    /// How many slots hold a sample. Zero by default and never above
    /// `max_samples`.
    len: usize = 0,
    /// The slot the next sample goes into, and — once the ring is full — the
    /// slot the oldest sample is in. The two agree only before it wraps, which
    /// is why `oldest` exists.
    next: usize = 0,
    /// Every sample ever recorded. Saturating, like every count here.
    recorded: u64 = 0,
    /// The fastest sample ever recorded, or null when nothing ever was. Not
    /// derived from the window, and not overwritten by it.
    fastest: ?Nanos = null,
    /// The slowest sample ever recorded, or null when nothing ever was.
    slowest: ?Nanos = null,

    /// Record one round trip.
    ///
    /// At the bound this overwrites the oldest sample rather than refusing,
    /// for the reason the module doc gives: a sample is not an identity, and
    /// the loss is counted by `Summary.dropped` rather than hidden. The
    /// extrema are updated here and never lose anything, so "how slow did this
    /// subject ever get" survives every overwrite.
    pub fn record(self: *Latencies, value: Nanos) void {
        self.samples[self.next] = value;
        // A branch rather than a modulo: `next` is below the bound, so the
        // successor is either the next slot or the first one, and the tree
        // spells integer division explicitly everywhere else.
        self.next = if (self.next + 1 == max_samples) 0 else self.next + 1;
        if (self.len < max_samples) self.len += 1;
        self.recorded +|= 1;
        if (self.fastest == null or value < self.fastest.?) self.fastest = value;
        if (self.slowest == null or value > self.slowest.?) self.slowest = value;
    }

    /// Copy the window into `out`, oldest first, and hand back the part of
    /// `out` that was written.
    ///
    /// A copy because the window is a ring and a caller that wants it in
    /// order has to walk the wrap; a borrow would hand out the raw storage and
    /// leave the order to be rediscovered at every call site. `out` is the
    /// caller's, so this allocates nothing.
    pub fn window(self: *const Latencies, out: *[max_samples]Nanos) []Nanos {
        const start = self.oldest();
        var index: usize = 0;
        while (index < self.len) : (index += 1) {
            out[index] = self.samples[wrapForward(start, index)];
        }
        return out[0..self.len];
    }

    /// Read this subject's latencies: the exact figures, plus the median of
    /// the recent window. `scratch` is where the window is sorted, and it is
    /// the caller's buffer rather than an allocation this module hides.
    ///
    /// Pure: it reads the accumulator and writes `scratch` and nothing else.
    pub fn summary(self: *const Latencies, scratch: *[max_samples]Nanos) Summary {
        const held = self.window(scratch);
        var out: Summary = .{
            .recorded = self.recorded,
            .held = @intCast(held.len),
            .fastest = self.fastest,
            .slowest = self.slowest,
            .median = null,
        };
        if (held.len == 0) return out;
        sortAscending(held);
        // The lower middle: `@divFloor(len - 1, 2)`, never an interpolation
        // between two samples. See `Summary.median`.
        out.median = held[@divFloor(held.len - 1, 2)];
        return out;
    }

    /// The slot the oldest sample is in: the first one while the ring is still
    /// filling, and `next` once it has wrapped — which it is exactly when it is
    /// full, because `next` is only ever a slot that will be overwritten.
    fn oldest(self: *const Latencies) usize {
        return if (self.len == max_samples) self.next else 0;
    }
};

/// One subject's figures, in one row, and the only place the three kinds sit
/// beside each other.
///
/// **The row's order is a type, not a convention.** `attempt` is the only way
/// into it, and it takes the round trip as an optional: that is what makes
/// "attempted and never answered" expressible without inventing a length for
/// a probe that produced none.
pub const Entry = struct {
    /// What was measured. Owned by value and compared only through
    /// `SocketAddr.order`.
    subject: SocketAddr,
    /// How many measurements were started, answered or not.
    /// Zero by default, because filing is not a measurement: a subject `open`
    /// has just filed carries nothing until `attempt` is called. See
    /// `Opened.filed`.
    attempted: Counter = .{},
    /// The round trips that came back. Never holds a failure.
    latency: Latencies = .{},
    /// When the last round trip came back. Null while nothing has.
    last: Last = .{},

    /// How many attempts produced no measurement.
    ///
    /// `attempted` minus `recorded`, and the subtraction is checked rather
    /// than saturating: a report that underflowed here would be hiding a bug,
    /// and `attempt` is what guarantees `recorded <= attempted` holds.
    pub fn failed(self: *const Entry) u64 {
        return self.attempted.value - self.latency.recorded;
    }

    /// One probe: started at `now`, with the round trip it took or null for
    /// none.
    ///
    /// Total, and with no branch a caller must handle. An answer moves the
    /// count, the window and the instant together; a failure moves the count
    /// only, so there is no path by which a refusal becomes a latency.
    pub fn attempt(self: *Entry, round_trip: ?Nanos, now: Nanos) void {
        self.attempted.add(1);
        const measured = round_trip orelse return;
        self.latency.record(measured);
        self.last.mark(now);
    }
};

/// Every way the table refuses a subject.
pub const OpenError = error{
    /// The table holds `max_subjects` subjects and `subject` is not one of
    /// them.
    ///
    /// **Nothing is evicted.** A subject leaves only through `close`, which
    /// names it. Displacing one here would silently drop the figures for a
    /// relay the caller is still measuring — a weaker measurement, reported as
    /// a smaller table, with nothing to notice it happened.
    NoFreeSubject,
};

/// What an `open` did.
pub const Opened = union(enum) {
    /// The subject was filed by this call and holds nothing yet. Filing is not
    /// a measurement: `attempted` is zero and `latency.recorded` is zero, and
    /// the table never claims a subject carried something because it existed.
    filed,
    /// It was already carried and every figure is exactly as it was. A second
    /// open cannot grow the table, which is the duplicate delivery on every
    /// later round that a set has to refuse.
    already,
};

/// Where a subject is: in the table, or the slot it would be filed into.
///
/// One walk rather than two. `observed_reporter`'s table scans forward and
/// then walks back to find the insertion point, and at eight entries the second
/// walk costs less than the answer this replaces.
const Where = union(enum) {
    /// It is in the table, at this index.
    held: usize,
    /// It is not, and this is the index it would occupy.
    free: usize,
};

/// The subjects this node is measuring, bounded by `max_subjects`.
///
/// Kept sorted by `SocketAddr.order` and deduplicated by it, for the reason
/// `report_measure.RelayList` is sorted rather than hashed: the order is
/// load-bearing, because a table whose order depended on filing would make
/// every downstream tie-break depend on arrival too. Two tables filled in
/// opposite orders are the same table.
///
/// Inline storage and no allocator, so a `Table` is a value a test holds on the
/// stack and a copy is independent of the original. Entries past `len` are
/// never written and never read, so `.{}` is an empty table and not a broken
/// one — read it through `slice` rather than by indexing.
pub const Table = struct {
    /// The subjects, first `len` of them ascending by `SocketAddr.order`.
    entries: [max_subjects]Entry = undefined,
    /// How many entries of `entries` are live. Zero by default, and never
    /// above `max_subjects`: `open` past it refuses rather than displaces.
    len: usize = 0,

    /// How many subjects are being measured.
    ///
    /// `len` under the name a caller reads rather than the one the storage
    /// bound has, so the count is stated once and read two ways.
    pub fn count(self: *const Table) usize {
        return self.len;
    }

    /// The rows, exactly `entries[0..len]`, ascending by subject.
    pub fn slice(self: *const Table) []const Entry {
        return self.entries[0..self.len];
    }

    /// The entry for `subject` to write to, or null for a subject this table
    /// does not hold.
    ///
    /// A scan and not a hash, for `topic_table.indexOf`'s reason: the whole
    /// table is `max_subjects` entries of a couple of hundred bytes, so the
    /// walk costs less than the measurement the caller came to record.
    pub fn find(self: *Table, subject: SocketAddr) ?*Entry {
        return switch (self.whereOf(subject)) {
            .held => |index| &self.entries[index],
            .free => null,
        };
    }

    /// File `subject` if it is not already held, and enforce the ceiling.
    ///
    /// A refused subject leaves the table exactly as it was, and the answer
    /// says which of the two happened, so a caller filing eight relays can
    /// tell a full table from a table that already held them.
    pub fn open(self: *Table, subject: SocketAddr) OpenError!Opened {
        const place = self.whereOf(subject);
        const index = switch (place) {
            .held => return .already,
            .free => |slot| slot,
        };
        if (self.len == max_subjects) return error.NoFreeSubject;
        // `@memmove`, not a hand-written copy: the destination starts one
        // entry after the source, so the ranges overlap and a forward copy
        // reads back the entry it has already overwritten. Every byte the
        // destination ends up with is a byte a live entry already held, so
        // moving the tail whole is what keeps `subject` a tagged union a
        // reader may switch on.
        @memmove(self.entries[index + 1 .. self.len + 1], self.entries[index..self.len]);
        self.entries[index] = .{ .subject = subject };
        self.len += 1;
        return .filed;
    }

    /// Take `subject` out and answer whether it was there.
    ///
    /// One named subject leaves; nothing does this on its own. A caller that
    /// wanted to shed the oldest subject instead is evicting, and the module
    /// doc says why that is not this table's choice.
    pub fn close(self: *Table, subject: SocketAddr) bool {
        const index = switch (self.whereOf(subject)) {
            .held => |slot| slot,
            .free => return false,
        };
        @memmove(self.entries[index .. self.len - 1], self.entries[index + 1 .. self.len]);
        self.len -= 1;
        return true;
    }

    /// Where `subject` is, in one walk of the sorted entries.
    fn whereOf(self: *const Table, subject: SocketAddr) Where {
        var index: usize = 0;
        while (index < self.len) : (index += 1) {
            switch (self.entries[index].subject.order(subject)) {
                .eq => return .{ .held = index },
                .gt => return .{ .free = index },
                .lt => {},
            }
        }
        return .{ .free = self.len };
    }
};

/// The slot `index` positions past `start` in a ring of `max_samples`.
///
/// One subtraction, because `start` and `index` are both below the bound and so
/// their sum is below twice it.
fn wrapForward(start: usize, index: usize) usize {
    const sum = start + index;
    return if (sum < max_samples) sum else sum - max_samples;
}

/// Sort `values` ascending, in place.
///
/// Insertion sort, and deliberately: the longest array this is ever handed is
/// `max_samples` long, so the log factor buys nothing and the whole routine is
/// three lines of loop a reader can check.
fn sortAscending(values: []Nanos) void {
    var index: usize = 1;
    while (index < values.len) : (index += 1) {
        const held = values[index];
        var slot = index;
        while (slot > 0 and values[slot - 1] > held) : (slot -= 1) {
            values[slot] = values[slot - 1];
        }
        values[slot] = held;
    }
}

// --- tests

const t = std.testing;

/// A subject named by its last octet, on one port. Two subjects differ when
/// their addresses do, which is what `SocketAddr.order` reads.
fn testSubject(tag: u8) SocketAddr {
    return .{ .ip = .{ .v4 = .{ 198, 51, 100, tag } }, .port = 41234 };
}

/// A round trip in the units a test reads.
fn millis(n: u64) Nanos {
    return n * std.time.ns_per_ms;
}

test "a count saturates instead of wrapping" {
    var counter: Counter = .{};
    try t.expectEqual(@as(u64, 0), counter.value);

    counter.add(7);
    try t.expectEqual(@as(u64, 7), counter.value);

    // Past the ceiling the count holds, and it does not wrap round to a small
    // figure — which is the whole reason this is a type rather than a field.
    counter.add(std.math.maxInt(u64) - 1);
    try t.expectEqual(std.math.maxInt(u64), counter.value);
    counter.add(5);
    try t.expectEqual(std.math.maxInt(u64), counter.value);
}

test "an instant ages from when it was marked and is absent before it" {
    var last: Last = .{};
    try t.expectEqual(@as(?Nanos, null), last.at);
    try t.expectEqual(@as(?Nanos, null), last.since(100));

    last.mark(100);
    try t.expectEqual(@as(Nanos, 40), last.since(140).?);

    // A caller whose timeline runs behind the mark reads zero, not a
    // subtraction that wraps into the far past.
    try t.expectEqual(@as(Nanos, 0), last.since(40).?);

    // "Never observed" and "observed at zero" are different facts, and only
    // one of them survives the first mark.
    var at_origin: Last = .{};
    at_origin.mark(0);
    try t.expectEqual(@as(Nanos, 0), at_origin.since(0).?);
}

test "a ninth subject is refused and nothing is evicted" {
    var table: Table = .{};
    var tag: usize = 1;
    while (tag <= max_subjects) : (tag += 1) {
        try t.expectEqual(Opened.filed, try table.open(testSubject(@intCast(tag))));
    }
    try t.expectEqual(@as(usize, max_subjects), table.count());

    const stranger = testSubject(max_subjects + 1);
    try t.expectError(error.NoFreeSubject, table.open(stranger));

    // The refusal changed nothing: every subject taken before it is still here
    // and the one refused is not.
    try t.expectEqual(@as(usize, max_subjects), table.count());
    try t.expect(table.find(stranger) == null);
    var index: usize = 0;
    while (index < max_subjects) : (index += 1) {
        try t.expect(table.find(testSubject(@intCast(index + 1))) != null);
    }

    // And a slot freed by a close is a slot a ninth subject may take.
    try t.expect(table.close(testSubject(1)));
    try t.expectEqual(Opened.filed, try table.open(stranger));
    try t.expectEqual(@as(usize, max_subjects), table.count());
}

test "a subject already carried is already and keeps every figure" {
    var table: Table = .{};
    try t.expectEqual(Opened.filed, try table.open(testSubject(1)));
    table.find(testSubject(1)).?.attempt(millis(10), 100);

    try t.expectEqual(Opened.already, try table.open(testSubject(1)));
    try t.expectEqual(@as(usize, 1), table.count());

    // A repeated open cannot reset anything either: a duplicate filing on
    // every later round must not look like a fresh subject.
    const entry = table.find(testSubject(1)).?;
    try t.expectEqual(@as(u64, 1), entry.attempted.value);
    try t.expectEqual(@as(u64, 1), entry.latency.recorded);
    try t.expectEqual(@as(Nanos, 100), entry.last.at.?);
}

test "closing a subject frees its slot and an absent one frees nothing" {
    var table: Table = .{};
    _ = try table.open(testSubject(1));
    _ = try table.open(testSubject(2));

    try t.expect(!table.close(testSubject(9)));
    try t.expectEqual(@as(usize, 2), table.count());

    try t.expect(table.close(testSubject(1)));
    try t.expectEqual(@as(usize, 1), table.count());
    try t.expect(table.find(testSubject(1)) == null);
    try t.expect(table.find(testSubject(2)) != null);
    try t.expectEqual(Opened.filed, try table.open(testSubject(3)));
    try t.expectEqual(@as(usize, 2), table.count());
}

test "the table's order is the subjects' order and not the order they arrived" {
    var forward: Table = .{};
    var backward: Table = .{};
    var tag: usize = 1;
    while (tag <= 4) : (tag += 1) {
        _ = try forward.open(testSubject(@intCast(tag)));
        _ = try backward.open(testSubject(@intCast(5 - tag)));
    }
    try t.expectEqual(forward.count(), backward.count());

    var index: usize = 0;
    while (index < forward.count()) : (index += 1) {
        const mine = forward.slice()[index].subject;
        const theirs = backward.slice()[index].subject;
        try t.expect(mine.order(theirs) == .eq);
    }

    // Ascending, so a caller scanning the slice reads it in address order.
    index = 1;
    while (index < forward.count()) : (index += 1) {
        const earlier = forward.slice()[index - 1].subject;
        const later = forward.slice()[index].subject;
        try t.expect(earlier.order(later) == .lt);
    }
}

test "an attempt that never got an answer is a count and no sample" {
    var table: Table = .{};
    _ = try table.open(testSubject(1));
    const entry = table.find(testSubject(1)).?;
    var scratch: [max_samples]Nanos = undefined;

    entry.attempt(null, 500);
    try t.expectEqual(@as(u64, 1), entry.attempted.value);
    try t.expectEqual(@as(u64, 1), entry.failed());
    try t.expectEqual(@as(u64, 0), entry.latency.recorded);

    // No sample means no latency at all, rather than a latency of zero: a zero
    // round trip is a claim that the refusal was instant.
    const empty = entry.latency.summary(&scratch);
    try t.expectEqual(@as(?Nanos, null), empty.fastest);
    try t.expectEqual(@as(?Nanos, null), empty.slowest);
    try t.expectEqual(@as(?Nanos, null), empty.median);
    try t.expectEqual(@as(?Nanos, null), entry.last.since(500));

    // One that answered moves the window and the instant, and only those.
    entry.attempt(millis(7), 600);
    try t.expectEqual(@as(u64, 2), entry.attempted.value);
    try t.expectEqual(@as(u64, 1), entry.failed());
    try t.expectEqual(millis(7), entry.latency.summary(&scratch).median.?);
    try t.expectEqual(@as(Nanos, 0), entry.last.since(600).?);
}

test "the window forgets the oldest sample, counts it, and keeps the extremes" {
    var table: Table = .{};
    _ = try table.open(testSubject(1));
    const entry = table.find(testSubject(1)).?;
    var scratch: [max_samples]Nanos = undefined;

    // An empty set reports nothing measured, and has dropped nothing.
    const empty = entry.latency.summary(&scratch);
    try t.expectEqual(@as(u64, 0), empty.recorded);
    try t.expectEqual(@as(u32, 0), empty.held);
    try t.expectEqual(@as(u64, 0), empty.dropped());

    var step: u64 = 1;
    while (step <= max_samples + 4) : (step += 1) {
        entry.attempt(millis(step), step);
    }
    const summary = entry.latency.summary(&scratch);
    try t.expectEqual(@as(u64, max_samples + 4), summary.recorded);
    try t.expectEqual(@as(u32, max_samples), summary.held);
    try t.expectEqual(@as(u64, 4), summary.dropped());

    // The all-time extrema survive every overwrite. 1 ms is nowhere in the
    // window any more and is still the fastest ever seen.
    try t.expectEqual(millis(1), summary.fastest.?);
    try t.expectEqual(millis(max_samples + 4), summary.slowest.?);

    // The window is the most recent sixteen — 5 ms through 20 ms — and the
    // median is the lower of its two middles.
    try t.expectEqual(millis(12), summary.median.?);
}

test "the median of an even window is a sample and not a midpoint" {
    var table: Table = .{};
    _ = try table.open(testSubject(1));
    const entry = table.find(testSubject(1)).?;
    var scratch: [max_samples]Nanos = undefined;

    entry.attempt(millis(10), 1);
    entry.attempt(millis(20), 2);

    // 15 ms is a round trip nobody made. The lower of the two middles is one.
    try t.expectEqual(millis(10), entry.latency.summary(&scratch).median.?);
}

test "the window reads oldest first once the ring has wrapped" {
    var table: Table = .{};
    _ = try table.open(testSubject(1));
    const entry = table.find(testSubject(1)).?;

    var step: u64 = 1;
    while (step <= max_samples + 2) : (step += 1) entry.attempt(millis(step), step);

    var scratch: [max_samples]Nanos = undefined;
    const window = entry.latency.window(&scratch);
    try t.expectEqual(@as(usize, max_samples), window.len);
    // Samples three through eighteen, in the order they were recorded. The
    // ring's wrap is the whole reason `window` copies rather than borrows.
    var index: usize = 0;
    while (index < window.len) : (index += 1) {
        try t.expectEqual(millis(3 + @as(u64, @intCast(index))), window[index]);
    }
}
