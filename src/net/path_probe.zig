//! How a path whose evidence has gone stale gets a fresh measurement: which
//! measurement, how many may be outstanding, and what an answer or a silence
//! means.
//!
//! `path_revalidate.zig` says when a path's recorded figure stops being an
//! answer and that a stale path keeps carrying while it waits for one. It
//! names the waiting and not the waiting's shape: which wire a revalidation
//! goes out on, what may be in flight at once, and what a figure that lands —
//! or one that never does — is read to mean. That is this file, and it is
//! pure: no socket, no clock, no allocator, no global. `now` is an argument to
//! every call that needs one and every answer is a value.
//!
//! The two halves are deliberately apart. `plan` is the decision half and reads
//! only; `landed` and `silence` are the two ends of an attempt, and each is
//! named for what it closes. The socket work is nobody's here either:
//! `probe_run.zig` owns driving a transport, and this file hands it a value to
//! drive.
//!
//! # Which transport, and why neither of `probe_live`'s two arms
//!
//! **Neither arm applies, and the reason is not the clock.** A QAD round opens
//! a *new* QUIC connection to a *relay* and reports the address that relay saw;
//! an HTTPS probe is a TCP `GET` to a relay's own path. Both answer *how does a
//! relay look from this node right now*. A revalidation asks *does this path
//! still work* — and "this" is a source address, a source port and a peer
//! address inside a connection that **already exists**. A fresh connection to
//! the same relay is a different 4-tuple, may be answered from a different NAT
//! mapping, and may be answered at all where the old one is not. That is
//! precisely the change `path_revalidate` exists to notice having happened, so
//! measuring the new connection is measuring the wrong thing.
//!
//! The clocks make it unrecoverable rather than merely wrong. A figure becomes
//! `Entry.rtt` through `path_table.Table.sample`, which stamps `rtt_at = now`
//! on **the caller's** timeline, and `Entry.latency` then ages it against the
//! same `now` the caller passes to `verdict`, `classify` and `switchTo`. The
//! QAD arm's figure is the round's (`Open.at` to the `now` the answer is polled
//! at) and the HTTPS arm's is `std.Io.Clock.awake` across the exchange — two
//! timelines, either of which would write an instant from one clock into a
//! record that is aged by another.
//!
//! **What does apply** is the RFC 9000 §8.2.2 `PATH_CHALLENGE` /
//! `PATH_RESPONSE` pair, on the connection that already runs on the path,
//! timed by the caller with the `now` it already passes to everything else. One
//! wire, one clock, the path it names. `Method` has one arm for that reason and
//! it is a one-armed enum on purpose: the two arms above cannot be spelled
//! here, so a caller cannot reach for one by mistake. `net/qad.zig` is not the
//! alternative either — the `OBSERVED_ADDRESS` frame it encodes reports an
//! address, and a path challenge proves a path.
//!
//! # The record changes at once; the traffic moves only through `path_select`
//!
//! A figure that lands is written by the caller with `Table.sample`, which
//! overwrites `rtt` and `rtt_at` unconditionally, and nothing here vetoes it —
//! `path_revalidate`'s rule, kept because keeping it is the point. What
//! `landed` adds is `Landing.reselect`, and it is true in exactly two cases:
//!
//! - **The reading is `.regressed`.** The figure is worse than three halves of
//!   the record, so the record is known to be wrong and traffic must be
//!   re-asked. `path_revalidate` says the caller re-asks `path_select` on this
//!   turn and the two-thirds margin decides there; this file does not restate
//!   that margin and does not move a packet.
//! - **The record could not be ranked on when the figure arrived.** `Entry.
//!   latency` answered null for it: never measured, or older than
//!   `rtt_max_age`. That is a change of kind rather than of degree —
//!   `path_select.faster` and `.displaces` both answer false for a path with no
//!   figure and can do neither once it has one — so even a `.confirmed`
//!   figure moves the entry from unranked to ranked and the selection has to be
//!   asked again.
//!
//! A `.confirmed` figure against a figure that was still rankable answers
//! `reselect = false`, and that is `path_revalidate`'s "inside the margin that
//! is noise, and absorbing it here is what stops a single odd sample from being
//! read as a change". The record still absorbs it; a later `switchTo` reads it.
//!
//! # What a failed revalidation means, and how silence is told from a dead path
//!
//! Silence is the absence of a figure and **this module writes nothing when it
//! happens**. `silence` discharges the attempt and answers
//! `path_revalidate.verdict` for the entry, and that is all: no figure, no
//! `rtt_at`, and above all no status. Silence therefore cannot be mistaken for
//! a recorded failure, because a recorded failure is a write somebody else
//! made — `.unusable` from the layer that observed the path fail, or
//! `.inactive` from `Table.mark` for a path whose bytes stopped. Those are
//! `Entry.dialable` and `path_select.selectable`'s business and they are not
//! this file's to make.
//!
//! What silence *does* do is arithmetic, and it is worth being exact about it
//! because it is the whole of the difference. The figure is left where it was,
//! so it ages; once past `rtt_max_age` `Entry.latency` answers null; so
//! `path_select.faster` and `.displaces` treat the path as unmeasured, which
//! means any measured challenger displaces it and it wins nothing. That is how
//! silence costs a path its traffic **without a status write**, and it is why
//! the tree needed no new status to tell the two apart.
//!
//! # The bound: one attempt in flight per path
//!
//! `max_in_flight` is `path_table.max_paths`, not a number picked here: a
//! revalidation is keyed by path, so the widest the set can be is the widest
//! the table it belongs to. `InFlight.begin` refuses a second attempt on a path
//! that has one out, and refuses a path the set has no room for while
//! displacing nothing — and that refusal is not a wedge, because a set of
//! `max_paths` attempts means every path in the table already has one out, so
//! `plan` is answering `.in_flight` for all of them and nothing is owed.
//!
//! One per path is also the *right* number rather than merely the smallest. A
//! second challenge on a path that already has one travels the same 4-tuple and
//! is answered by the same peer, so it could only duplicate the first or be
//! lost with it; a path nobody ever measured asks once per `probe_grace` for
//! ever, which is the intended rate and is `path_revalidate`'s window doing
//! the pacing rather than a second timer here.
//!
//! In-flight state is keyed by address and not by table index, because
//! `Table.forget` moves the last entry into the gap and an index would name a
//! different path after one.
//!
//! ## The loop this is written for
//!
//! ```text
//! const ask = path_probe.challengeOf(path_probe.plan(entry, now, &outstanding));
//! if (ask) |c| {
//!     if (outstanding.begin(entry.addr)) connection.challenge(c);
//! }
//! // when a PATH_RESPONSE lands, or when c.deadline passes with nothing:
//! const end = path_probe.landed(&outstanding, entry, figure, now);
//! _ = path_probe.silence(&outstanding, entry, now);
//! ```
//!
//! Both `landed` and `silence` name an attempt and refuse to name one that is
//! not there: an outcome for a path with nothing outstanding is not this
//! module's to interpret, and refusing it stops a figure nobody asked for from
//! being filed against a record. A caller holding a figure from ordinary
//! traffic rather than from a challenge calls `path_revalidate.classify`
//! directly, which needs no attempt.
//!
//! # What is pinned, and what is not
//!
//! This file emits no bytes and encodes nothing, so there is nothing here for
//! `AGENTS.md` §2's "wire compatibility is a test" to bite on. What it rests
//! on is RFC 9000 §8.2.2, read as a written specification: no captured upstream
//! bytes exist on this machine, so what a peer's `PATH_RESPONSE` looks like on
//! the wire is not reproduced here and nothing here claims interoperability.
//! The numbers are the tree's own, borrowed rather than restated, and the
//! `comptime` block holds their order at the build.

const std = @import("std");
const addr = @import("../base/addr.zig");
const path_revalidate = @import("path_revalidate.zig");
const path_select = @import("path_select.zig");
const path_table = @import("path_table.zig");

const Reading = path_revalidate.Reading;
const Verdict = path_revalidate.Verdict;
const TransportAddr = addr.TransportAddr;

/// `Nanos` and `Entry` are the table's own, re-exported so a caller spelling an
/// instant or an entry here does not mean importing `path_table.zig` for a type
/// alias.
pub const Nanos = path_table.Nanos;
pub const Entry = path_table.Entry;

/// The three windows this file's arithmetic is ordered against, borrowed from
/// `path_revalidate` rather than restated: the attempt is given the same grace
/// a measurement has always been given, and it is given up at the instant the
/// answer would stop being wanted.
pub const probe_grace = path_revalidate.probe_grace;
pub const revalidate_after = path_revalidate.revalidate_after;
pub const unverified_after = path_revalidate.unverified_after;

/// Widest set of outstanding revalidations: one per path, over a table that
/// holds at most `path_table.max_paths` paths. See the module doc's last
/// section.
pub const max_in_flight: usize = path_table.max_paths;

/// Which wire one revalidation goes out on.
///
/// One arm, and the enum is one-armed on purpose. `probe_live`'s QAD and HTTPS
/// arms are the two arms this tree has for measuring a **relay**, and neither
/// can measure a path — see the module doc. Naming them here would make them
/// spellable by a caller who wanted one.
pub const Method = enum {
    /// An RFC 9000 §8.2.2 `PATH_CHALLENGE`, on the connection already running
    /// on this path, answered by a `PATH_RESPONSE` the caller times with the
    /// `now` it passes to everything else here.
    path_challenge,
};

/// One revalidation to attempt now.
pub const Challenge = struct {
    /// What to send.
    method: Method,
    /// The path to send it on: the entry's own address, so a caller cannot
    /// challenge one path on behalf of another's evidence.
    path: TransportAddr,
    /// When it goes out, which is the `now` `plan` was given.
    at: Nanos,
    /// When this attempt stops being worth waiting for, `at + probe_grace`.
    ///
    /// Advisory, and deliberately never a second deadline for the verdict: an
    /// attempt made at the first stale instant is given up one nanosecond after
    /// the entry reads `.unverified`, so a caller is never held hostage to a
    /// frame it sent ten seconds ago. Saturating, so a caller whose timeline
    /// runs past the ceiling gets an attempt that is given up rather than one
    /// that wraps into the far past and is overdue before it was sent.
    deadline: Nanos,
};

/// What one path owes at `now`. Four arms, and the order is the rule: nothing
/// owed, then an attempt already out, then no wire to send on, then the ask.
pub const Plan = union(enum) {
    /// The figure still supports the choice it was made for. No open path and
    /// no outstanding set are consulted, because nothing is owed.
    fresh,
    /// An attempt for this path is already out. This turn owes no second one,
    /// and the attempt is discharged by `landed` or `silence` — which is also
    /// how a path closed while its attempt was out drains its slot.
    in_flight,
    /// Nothing owed, and nothing possible: the path is not open, so there is no
    /// connection to carry a challenge and no answer could be attributed to
    /// anything. Asking again will not change it.
    no_path,
    /// Send this, on this path, now.
    challenge: Challenge,
};

/// What one figure that just landed means for the entry it was measured on.
pub const Landing = struct {
    /// `path_revalidate.classify`'s own reading of the figure against the
    /// record, taken against the record **as it is now** — which is why the
    /// caller reads this before it writes the figure. Filed afterwards, the
    /// same figure is read against itself and always confirms.
    reading: Reading,
    /// Whether the caller must re-ask `path_select.switchTo` on this turn with
    /// the figure written in. Never "move traffic now": the two-thirds margin
    /// is `path_select`'s, and this file does not hold a copy of it.
    reselect: bool,
};

/// The revalidations this peer has outstanding: at most one per path.
///
/// Inline and no allocator, so a whole set is a value a caller holds on its
/// stack and a copy is independent of the original. Entries past `len` are
/// never written and never read, so a default `InFlight` is a valid empty set
/// and not a broken one — read `len`, never the array.
///
/// It is `TransportAddr` and not an index into the table, because
/// `Table.forget` moves the last entry into the gap and an index would name a
/// different path after one.
pub const InFlight = struct {
    open: [max_in_flight]TransportAddr = undefined,
    len: usize = 0,

    /// How many attempts are outstanding.
    pub fn count(self: *const InFlight) usize {
        return self.len;
    }

    /// Whether an attempt for `path` is out.
    pub fn holds(self: *const InFlight, path: TransportAddr) bool {
        return self.indexOf(path) != null;
    }

    /// Record an attempt for `path`, or refuse.
    ///
    /// Two refusals and they are different: a path that already has one out,
    /// and a set with no room. Neither displaces anything, and the second is
    /// not a wedge — a set of `max_in_flight` attempts means every path in the
    /// table already has one out.
    pub fn begin(self: *InFlight, path: TransportAddr) bool {
        if (self.holds(path)) return false;
        if (self.len == self.open.len) return false;
        self.open[self.len] = path;
        self.len += 1;
        return true;
    }

    /// Discharge the attempt for `path`, and answer whether there was one.
    ///
    /// The last entry moves into the gap, as `Table.forget` does, so the order
    /// is not the order attempts were begun in and nothing depends on it.
    pub fn end(self: *InFlight, path: TransportAddr) bool {
        const index = self.indexOf(path) orelse return false;
        self.open[index] = self.open[self.len - 1];
        self.len -= 1;
        return true;
    }

    /// Where `path` is, or null. A scan and not a hash, for
    /// `path_table.indexOf`'s reason: the set is `max_paths` addresses and a
    /// lookup is a handful of comparisons.
    fn indexOf(self: *const InFlight, path: TransportAddr) ?usize {
        var index: usize = 0;
        while (index < self.len) : (index += 1) {
            if (self.open[index].order(path) == .eq) return index;
        }
        return null;
    }
};

/// What one path owes a measurement at `now`, given what is already out.
///
/// Reads the entry and the set and writes neither. The caller sends
/// `Plan.challenge` when `InFlight.begin` takes it, and the two are separate
/// because only this one is a decision: a caller may hold an `InFlight` for a
/// table whose paths it is not asking about, and must not lose that set
/// because it also wanted to know what was owed.
pub fn plan(entry: *const Entry, now: Nanos, outstanding: *const InFlight) Plan {
    switch (path_revalidate.verdict(entry, now)) {
        .fresh => return .fresh,
        .stale, .unverified => {},
    }
    // Checked before `.no_path`, deliberately: an attempt on a path the layer
    // has since closed is still the caller's outstanding debt, and it drains
    // through `silence` rather than being stranded by the closing. One more
    // turn is what discharges it.
    if (outstanding.holds(entry.addr)) return .in_flight;
    if (!path_select.selectable(entry)) return .no_path;
    return .{ .challenge = .{
        .method = .path_challenge,
        .path = entry.addr,
        .at = now,
        .deadline = now +| probe_grace,
    } };
}

/// One attempt's figure arrived: discharge it and say what it means.
///
/// Null when this path had no attempt out. An outcome has to name an attempt,
/// and an answer for a path nothing was asked about is a figure this module
/// cannot attribute; refusing it is `probe_run_wire.Error.Unattributable`'s
/// rule, for the same reason — filing it would put a latency in a record that
/// no outstanding revalidation measured.
///
/// The reading is taken against the record **before** the caller writes the
/// figure, so call this first. Nothing here writes the entry: `Table.sample`
/// is `path_table`'s and the caller's, and a measurement is a measurement.
pub fn landed(
    outstanding: *InFlight,
    entry: *const Entry,
    figure: Nanos,
    now: Nanos,
) ?Landing {
    if (!outstanding.end(entry.addr)) return null;
    const reading = path_revalidate.classify(entry, figure);
    return .{
        .reading = reading,
        // Unrankable before is what makes even a confirmed figure a change of
        // kind: `Entry.latency` answered null, so `path_select.faster` and
        // `.displaces` answered for a path with no figure and can do neither
        // now that it has one.
        .reselect = reading == .regressed or entry.latency(now) == null,
    };
}

/// One attempt went unanswered: discharge it and report what the entry's
/// evidence now supports.
///
/// Null when this path had no attempt out, for `landed`'s reason. Everything
/// else is the whole of what silence does here: the attempt is closed, the
/// record is untouched, and the caller is handed `path_revalidate`'s own word
/// for it. `.unverified` is the answer that costs the path its traffic, and it
/// costs it through `Entry.latency` answering null and `path_select` declining
/// to rank it — not through a status this module writes. See the module doc's
/// section on silence.
pub fn silence(outstanding: *InFlight, entry: *const Entry, now: Nanos) ?Verdict {
    if (!outstanding.end(entry.addr)) return null;
    return path_revalidate.verdict(entry, now);
}

comptime {
    // The attempt window is the answer window, and the two windows the
    // attempt lives inside are ordered against each other. Held here so a
    // reader who changes one constant is stopped at the build rather than by a
    // deadline that quietly contradicts the module doc.
    std.debug.assert(max_in_flight == path_table.max_paths);
    std.debug.assert(path_revalidate.unverified_after ==
        path_revalidate.revalidate_after + probe_grace);
}

// --- tests

const t = std.testing;

const holepunch = @import("holepunch.zig");
const PathStatus = holepunch.PathStatus;
const SocketAddr = addr.SocketAddr;

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

/// A relay-addressed path, because the arm decision has to hold for every
/// address a `TransportAddr` can spell and not only for the direct one.
fn relayPath() TransportAddr {
    var text: [64]u8 = undefined;
    const url = addr.RelayUrl.parse(
        std.fmt.bufPrint(&text, "https://relay.example./", .{}) catch unreachable,
    ) catch unreachable;
    return .{ .relay = url };
}

/// A registered non-IP transport's path, the third spelling of the same
/// question.
fn customPath() TransportAddr {
    return .{ .custom = .{ .id = 7, .data = "\x01\x02" } };
}

/// One open path whose figure is `rtt`, taken at `rtt_at`.
fn entryWith(rtt: ?Nanos, rtt_at: Nanos) Entry {
    return .{ .addr = at(1000), .status = .open, .rtt = rtt, .rtt_at = rtt_at };
}

/// Whether two addresses name the same one. `TransportAddr` holds a
/// `CustomAddr` with a slice in it, so `==` is not defined on it and every
/// comparison in this tree goes through `order`.
fn sameAddress(left: ?TransportAddr, right: ?TransportAddr) bool {
    const one = left orelse return right == null;
    const other = right orelse return false;
    return one.order(other) == .eq;
}

/// The challenge a plan asks for, or null when it asks for none.
fn challengeOf(answer: Plan) ?Challenge {
    return switch (answer) {
        .challenge => |one| one,
        else => null,
    };
}

/// The arm a plan answered with, by name, for an assertion that is about which
/// arm answered rather than about the values it carries.
fn armOf(answer: Plan) []const u8 {
    return switch (answer) {
        .fresh => "fresh",
        .in_flight => "in_flight",
        .no_path => "no_path",
        .challenge => "challenge",
    };
}

/// One figure answered on an attempt that is begun and discharged here, which
/// is the sequence the module doc's loop runs.
fn land(entry: *const Entry, figure: Nanos, now: Nanos) ?Landing {
    var outstanding: InFlight = .{};
    if (!outstanding.begin(entry.addr)) return null;
    return landed(&outstanding, entry, figure, now);
}

test "a fresh figure is owed nothing and a stale one is owed a challenge" {
    const entry = entryWith(20 * millis, 1_000);
    var none: InFlight = .{};

    try t.expectEqualStrings("fresh", armOf(plan(&entry, 1_000, &none)));
    // Inclusive at the end, like `Entry.carrying` and `verdict`: an age of
    // exactly the bound is still inside it.
    try t.expectEqualStrings("fresh", armOf(plan(&entry, 1_000 + revalidate_after, &none)));

    const now = 1_000 + revalidate_after + 1;
    const ask = challengeOf(plan(&entry, now, &none)).?;
    try t.expectEqual(Method.path_challenge, ask.method);
    // The path challenged is the entry's own address, and the attempt is timed
    // on the caller's timeline rather than on either of `probe_live`'s.
    try t.expect(sameAddress(ask.path, at(1000)));
    try t.expectEqual(@as(Nanos, now), ask.at);
    try t.expectEqual(now, ask.at);
    try t.expectEqual(now + probe_grace, ask.deadline);

    // And a path nobody ever measured is owed one for ever, which is what the
    // in-flight bound turns into one ask per grace.
    try t.expect(challengeOf(plan(&entryWith(null, 0), 0, &none)) != null);
    try t.expect(challengeOf(plan(&entryWith(null, 0), unverified_after * 100, &none)) != null);
}

test "the challenge travels the path the evidence is about, however it is spelled" {
    // The three arms of `TransportAddr` are three spellings of one question and
    // get one answer: a `PATH_CHALLENGE` is a frame inside a QUIC connection,
    // so it travels whatever transport carries that connection. This is what a
    // relay-keyed probe cannot do — there is no relay to key on for an `.ip`
    // path at all, and a `.custom` payload is opaque bytes no `RelayUrl.parse`
    // will accept.
    const cases = [_]TransportAddr{ at(1000), relayPath(), customPath() };
    var none: InFlight = .{};
    for (cases) |address| {
        var entry = entryWith(20 * millis, 0);
        entry.addr = address;
        const ask = challengeOf(plan(&entry, revalidate_after + 1, &none)).?;
        try t.expect(ask.path.order(address) == .eq);
        try t.expectEqual(Method.path_challenge, ask.method);
    }
    // And the three are three paths, not one: the set keys them apart.
    var outstanding: InFlight = .{};
    for (cases) |address| try t.expect(outstanding.begin(address));
    try t.expectEqual(@as(usize, 3), outstanding.count());
}

test "one attempt per path, and the bound is the table's bound" {
    try t.expectEqual(@as(usize, 8), max_in_flight);
    try t.expectEqual(path_table.max_paths, max_in_flight);

    var outstanding: InFlight = .{};
    try t.expect(outstanding.begin(at(1000)));
    // A second attempt on a path that has one out is refused: it would travel
    // the same 4-tuple to the same peer, so it could only duplicate the first
    // or be lost with it.
    try t.expect(!outstanding.begin(at(1000)));
    try t.expect(outstanding.holds(at(1000)));
    try t.expectEqual(@as(usize, 1), outstanding.count());

    for (0..max_in_flight - 1) |offset| {
        try t.expect(outstanding.begin(at(2000 + @as(u16, @intCast(offset)))));
    }
    try t.expectEqual(max_in_flight, outstanding.count());
    // A set with no room refuses the next path and displaces nothing, which is
    // not a wedge: every path in the table now has an attempt out, so `plan`
    // owes nothing to any of them.
    try t.expect(!outstanding.begin(at(3000)));
    try t.expectEqual(max_in_flight, outstanding.count());
    try t.expect(outstanding.holds(at(1000)));
    try t.expect(outstanding.holds(at(2000)));

    // Discharging takes exactly one slot and moves the last attempt into the
    // gap, which is what makes room again.
    try t.expect(outstanding.end(at(1000)));
    try t.expect(!outstanding.holds(at(1000)));
    try t.expectEqual(@as(usize, 7), outstanding.count());
    try t.expect(outstanding.begin(at(3000)));
    // And a second discharge of the same path is refused rather than counted
    // twice, so a caller cannot discharge an attempt it never began.
    try t.expect(!outstanding.end(at(1000)));
    try t.expectEqual(@as(usize, 8), outstanding.count());
}

test "an attempt out is nothing new owed, and it drains through silence" {
    const entry = entryWith(20 * millis, 1_000);
    var outstanding: InFlight = .{};
    try t.expect(outstanding.begin(entry.addr));

    const stale_at = 1_000 + revalidate_after + 1;
    try t.expectEqualStrings("in_flight", armOf(plan(&entry, stale_at, &outstanding)));
    try t.expect(challengeOf(plan(&entry, stale_at, &outstanding)) == null);

    // Silence discharges it and reports the entry's evidence, and the record is
    // untouched by either: the figure is still the one taken at 1_000.
    const answered_nothing = silence(&outstanding, &entry, stale_at).?;
    try t.expectEqual(Verdict.stale, answered_nothing);
    try t.expectEqual(@as(usize, 0), outstanding.count());
    try t.expectEqual(@as(?Nanos, 20 * millis), entry.rtt);

    // The same discharge past the entry's own window answers `.unverified`,
    // and still writes nothing — that is what costs the path its traffic.
    try t.expect(outstanding.begin(entry.addr));
    const late = 1_000 + unverified_after + 1;
    try t.expectEqual(Verdict.unverified, silence(&outstanding, &entry, late).?);
    try t.expectEqual(@as(usize, 0), outstanding.count());
    try t.expectEqual(@as(Nanos, 1_000), entry.rtt_at);
    try t.expectEqual(PathStatus.open, entry.status);

    // The next turn asks again, and a second discharge of nothing is refused
    // rather than counted as a silence that never happened.
    try t.expect(challengeOf(plan(&entry, late, &outstanding)) != null);
    try t.expect(silence(&outstanding, &entry, late) == null);
}

test "a path closed while its attempt was out still drains its slot" {
    const entry = entryWith(20 * millis, 0);
    var outstanding: InFlight = .{};
    try t.expect(outstanding.begin(entry.addr));

    var closed = entry;
    closed.status = .{ .inactive = 7 };
    // The attempt is the caller's outstanding debt and is asked about before
    // the closed path is, so one more turn discharges it instead of stranding
    // the slot and with it the path's next attempt.
    try t.expectEqualStrings("in_flight", armOf(plan(&closed, revalidate_after + 1, &outstanding)));
    try t.expectEqual(Verdict.stale, silence(&outstanding, &closed, revalidate_after + 1).?);
    try t.expectEqual(@as(usize, 0), outstanding.count());
    // And now there is nothing to send on.
    try t.expectEqualStrings("no_path", armOf(plan(&closed, revalidate_after + 2, &outstanding)));
}

test "a path with no open connection has nothing to send a challenge on" {
    const entry = entryWith(20 * millis, 0);
    // Long past every window, so the evidence demands a measurement and the
    // answer is still that none can be made.
    const late = unverified_after * 10;
    const statuses = [_]PathStatus{
        .{ .inactive = 7 },
        .unknown,
        .unusable,
    };
    var none: InFlight = .{};
    for (statuses) |status| {
        var closed = entry;
        closed.status = status;
        try t.expectEqualStrings("no_path", armOf(plan(&closed, late, &none)));
        // Nothing is filed for it either: there is no answer to attribute.
        try t.expect(landed(&none, &closed, 20 * millis, late) == null);
        try t.expect(silence(&none, &closed, late) == null);
    }
    // An open path is asked instead, so the refusal is about the wire and not
    // about the evidence.
    var open = entry;
    try t.expect(challengeOf(plan(&open, late, &none)) != null);
}

test "a figure is read against the record before the record is written" {
    var table: path_table.Table = .{};
    _ = table.observe(at(1000), .open, 0);
    try t.expect(table.sample(at(1000), 20 * millis, 0));
    const entry = table.get(at(1000)).?;
    const now = 1_000 + unverified_after + 1;
    var outstanding: InFlight = .{};
    try t.expect(outstanding.begin(entry.addr));

    const answer = landed(&outstanding, &entry, 40 * millis, now).?;
    try t.expectEqual(Reading.regressed, answer.reading);
    try t.expect(answer.reselect);
    // The attempt is discharged by its answer.
    try t.expectEqual(@as(usize, 0), outstanding.count());
    // And nothing was written here: the entry the caller holds is a value and
    // still carries the record the figure was read against.
    try t.expectEqual(@as(?Nanos, 20 * millis), entry.rtt);
    try t.expectEqual(@as(Nanos, 0), entry.rtt_at);
    try t.expectEqual(@as(?Nanos, 20 * millis), table.get(at(1000)).?.rtt);

    // Write the figure and the same figure reads as confirmed against itself,
    // which is why the caller reads `Landing` before it samples.
    try t.expect(table.sample(at(1000), 40 * millis, now));
    const written = table.get(at(1000)).?;
    try t.expectEqual(@as(?Nanos, 40 * millis), written.rtt);
    try t.expectEqual(@as(Nanos, now), written.rtt_at);
    try t.expectEqual(Reading.confirmed, path_revalidate.classify(&written, 40 * millis));
    // The regression is recorded regardless — the record changes at once.
    try t.expectEqual(PathStatus.open, written.status);
}

test "only a regression or an unrankable record asks for a selection" {
    const record = entryWith(20 * millis, 0);
    const rankable = 1_000;
    const unrankable = 1_000 + unverified_after + 1;

    // Inside the margin against a record that could still be ranked: noise,
    // absorbed, and no selection asked for. This is `path_revalidate`'s own
    // "inside the margin that is noise".
    const quiet = land(&record, 24 * millis, rankable).?;
    try t.expectEqual(Reading.confirmed, quiet.reading);
    try t.expect(!quiet.reselect);

    // The same figure against the same record, arriving after the record could
    // no longer be ranked on. That is a change of kind — `path_select.faster`
    // and `.displaces` both answer for a path with no figure and can do
    // neither now that it has one — so the selection is asked again.
    const promoted = land(&record, 24 * millis, unrankable).?;
    try t.expectEqual(Reading.confirmed, promoted.reading);
    try t.expect(promoted.reselect);

    // A regression asks for it whatever the record could be ranked on, because
    // the record is known to be wrong and the margin decides there.
    const worse = land(&record, 40 * millis, rankable).?;
    try t.expectEqual(Reading.regressed, worse.reading);
    try t.expect(worse.reselect);

    // A path's first figure has no record to regress from and no ranking to
    // keep, so it asks once and absorbs the figure however large it is.
    const first = land(&entryWith(null, 0), unverified_after * 1000, rankable).?;
    try t.expectEqual(Reading.first, first.reading);
    try t.expect(first.reselect);
}

test "silence costs a path its traffic and writes no status to do it" {
    var table: path_table.Table = .{};
    _ = table.observe(at(1000), .open, 0);
    _ = table.observe(at(1001), .open, 0);
    try t.expect(table.sample(at(1000), 100 * millis, 0));
    const now = 1_000 + unverified_after + 1;
    try t.expect(table.sample(at(1001), 10 * millis, now));

    const incumbent = table.get(at(1000)).?;
    var outstanding: InFlight = .{};
    try t.expect(outstanding.begin(incumbent.addr));
    try t.expectEqual(Verdict.unverified, silence(&outstanding, &incumbent, now).?);

    // The record is untouched: the figure is where it was, and the status is
    // still `.open`, because a failure is a write somebody else made.
    const after = table.get(at(1000)).?;
    try t.expectEqual(@as(?Nanos, 100 * millis), after.rtt);
    try t.expectEqual(PathStatus.open, after.status);
    try t.expect(after.dialable());
    try t.expect(path_select.selectable(&after));
    // The whole of what silence did is arithmetic on the figure's age: it can
    // no longer be ranked on, so the measured challenger displaces it.
    try t.expectEqual(@as(?Nanos, null), after.latency(now));
    try t.expect(table.get(at(1001)).?.latency(now) != null);
    const choice = path_select.switchTo(&table, now, at(1000));
    try t.expectEqual(path_select.Reason.faster, choice.reason);
    try t.expect(sameAddress(choice.path, at(1001)));
}

test "a path somebody observed to fail is a different fact from a silent one" {
    var table: path_table.Table = .{};
    _ = table.observe(at(1000), .open, 0);
    _ = table.observe(at(1001), .unknown, 0);
    const now = unverified_after * 10;
    // The layer wrote `.unusable` because it watched the path fail. That is a
    // recorded failure and it is refused by name, which no amount of silence
    // can become.
    _ = table.observe(at(1001), .unusable, now);
    const gone = table.get(at(1001)).?;
    try t.expect(!gone.dialable());
    try t.expect(!path_select.selectable(&gone));

    var none: InFlight = .{};
    try t.expectEqualStrings("no_path", armOf(plan(&gone, now, &none)));
    // And nothing this module does adds to it or takes from it.
    try t.expect(landed(&none, &gone, 20 * millis, now) == null);
    try t.expect(silence(&none, &gone, now) == null);
    try t.expectEqual(PathStatus.unusable, table.get(at(1001)).?.status);

    // A `.inactive` path is not that: it worked and closed, so it is still
    // dialable and would be challenged again if it were open.
    _ = table.observe(at(1001), .{ .inactive = now }, now);
    try t.expect(table.get(at(1001)).?.dialable());
    try t.expectEqualStrings("no_path", armOf(plan(&table.get(at(1001)).?, now, &none)));
}

test "a figure that answers an attempt returns the path to trust" {
    var table: path_table.Table = .{};
    _ = table.observe(at(1000), .open, 0);
    try t.expect(table.sample(at(1000), 20 * millis, 0));
    const entry = table.get(at(1000)).?;
    const stale_at = 1_000 + revalidate_after + 1;

    var outstanding: InFlight = .{};
    const ask = challengeOf(plan(&entry, stale_at, &outstanding)).?;
    try t.expect(outstanding.begin(entry.addr));

    const answer = landed(&outstanding, &entry, 22 * millis, ask.at).?;
    try t.expectEqual(Reading.confirmed, answer.reading);
    try t.expect(answer.reselect);
    try t.expect(table.sample(entry.addr, 22 * millis, ask.at));

    // The window runs from the new figure, so the path is fresh again and owed
    // nothing for a whole window: revalidation is a cycle and not a countdown
    // to a connection nobody may trust twice.
    const fresh = table.get(at(1000)).?;
    try t.expectEqual(Verdict.fresh, path_revalidate.verdict(&fresh, ask.at));
    try t.expectEqual(@as(?Nanos, 22 * millis), fresh.rtt);
    try t.expectEqualStrings("fresh", armOf(plan(&fresh, ask.at, &outstanding)));
    try t.expectEqualStrings("fresh", armOf(plan(&fresh, ask.deadline, &outstanding)));
    try t.expect(challengeOf(plan(&fresh, ask.deadline + 1, &outstanding)) != null);
}

test "the windows are the ones the module doc claims" {
    var none: InFlight = .{};
    const entry = entryWith(20 * millis, 0);

    // Borrowed, not restated: this file holds no copy of any of them.
    try t.expectEqual(@as(Nanos, 10 * std.time.ns_per_s), probe_grace);
    try t.expectEqual(@as(Nanos, 10 * std.time.ns_per_s), path_revalidate.probe_grace);
    try t.expectEqual(@as(Nanos, 10 * std.time.ns_per_s), unverified_after - revalidate_after);
    try t.expectEqual(@as(Nanos, 20 * std.time.ns_per_s), path_revalidate.unverified_after);
    try t.expectEqual(@as(Nanos, 10 * std.time.ns_per_s), path_revalidate.revalidate_after);

    // An attempt made at the first stale instant is given up one nanosecond
    // after the entry reads `.unverified`, so the attempt never holds the
    // verdict back.
    const ask = challengeOf(plan(&entry, revalidate_after + 1, &none)).?;
    try t.expectEqual(revalidate_after + 1 + probe_grace, ask.deadline);
    try t.expectEqual(unverified_after + 1, ask.deadline);

    // And an attempt is never given up before it is sent, however far the
    // caller's timeline has run.
    const ceiling = std.math.maxInt(Nanos);
    const late = challengeOf(plan(&entry, ceiling, &none)).?;
    try t.expectEqual(ceiling, late.at);
    try t.expectEqual(ceiling, late.deadline);

    // Only one arm exists, and it is the one that travels on the connection.
    try t.expectEqual(@as(usize, 1), @typeInfo(Method).@"enum".fields.len);
    try t.expectEqual(
        Method.path_challenge,
        challengeOf(plan(&entry, revalidate_after + 1, &none)).?.method,
    );
}
