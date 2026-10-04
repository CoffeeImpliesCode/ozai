//! The runner: one turn of a round, in, one turn's instructions out.
//!
//! A runner is what `net_report.rs` and `reportgen.rs` are between them: a plan,
//! an instant, and a set of answers. It holds no socket, no task handle and no
//! future, and it reads no clock — `now` goes to `new` and to `step`.
//!
//! `probe.zig` decides what to run and `probe_quota.zig` decides when to stop;
//! this file is what remembers what has happened in between, and it is the only
//! one of the three that mutates.
//!
//! # What a turn is
//!
//! Upstream spawns a probe and lets its future answer
//! (`net_report.rs:504-540`), so the sends and the wakeup are one choice.
//! `Step` makes them three independent facts, because a turn can send every
//! probe that has come due since the last one and still say when to come back.
//!
//! The order of the questions in `step` is the order upstream asks them in.
//! Having enough answers comes first, because upstream drops the actor the
//! moment it holds (`net_report.rs:369-373`) and a probe that has come due in
//! the same instant is one that never ran. The overall deadline comes second,
//! for the same reason: a round that has spent its budget sends nothing more.
//!
//! # Where a result's family comes from
//!
//! Upstream builds the payload inside the probe's own future, so the family in
//! the tag is the family the probe **ran** with and never the family of the
//! address that came back: a relay answering a v4 probe with an IPv6 address
//! produces a v4 result carrying a v6 address. `Report::update`
//! (`report.rs:81-84`) then records the latency, drops the address, and
//! classifies nothing.
//!
//! That check lives in `report_fold.fold` and this file must not second-guess
//! it. Nothing here canonicalises with `to_canonical` (`net_report.rs:857`) and
//! nothing re-tags from the address. A result that cannot be attributed keeps
//! its latency and declines to classify, and the test that pins it drives one
//! through this file rather than writing one by hand.

const std = @import("std");
const addr = @import("../base/addr.zig");
const base_relay_url = @import("../base/relay_url.zig");
const claim = @import("report_claim.zig");
const probe = @import("probe.zig");
const quota = @import("probe_quota.zig");
const report = @import("report.zig");
const fold_results = @import("report_fold.zig").fold;

/// The plan's names, spelled once: a runner holds a plan and a task, and its
/// every deadline and due instant is one of the plan's constants measured from
/// its start.
const IfState = probe.IfState;
const Input = probe.Input;
const Round = probe.Round;
const Plan = probe.Plan;
const PlanError = probe.PlanError;
const Task = probe.Task;
const TaskIndex = probe.TaskIndex;
const captive_portal_delay = probe.captive_portal_delay;
const captive_portal_timeout = probe.captive_portal_timeout;
const delayFor = probe.delayFor;
const enough_endpoints = probe.enough_endpoints;
const https_attempts = probe.https_attempts;
const https_offset = probe.https_offset;
const initial_retransmit = probe.initial_retransmit;
const max_relays = probe.max_relays;
const max_results = probe.max_results;
const max_tasks = probe.max_tasks;
const overall_timeout = probe.overall_timeout;
const plan = probe.plan;
const probe_timeout = probe.probe_timeout;
const qadResult = probe.qadResult;

/// The stop rule, which is `probe_quota.zig`'s and not this file's: this one
/// asks it twice per turn and never decides it.
const haveEnough = quota.haveEnough;
const measured = quota.measured;

/// The report's names: what an answer is, what a round folds into, and what it
/// is folded against.
const Nanos = report.Nanos;
const Probe = report.Probe;
const ProbeResult = report.ProbeResult;
const QadProbe = report.QadProbe;
const History = claim.History;
const Report = claim.Report;

const RelayUrl = base_relay_url.RelayUrl;
const SocketAddr = addr.SocketAddr;

/// The results one round has collected, in the caller's own storage.
///
/// Borrowed by a runner rather than owned by it: a `report.ProbeResult` carries
/// a `RelayUrl`, so one is some 350 bytes and a runner that returned its
/// results by value would copy a dozen of them on every turn to say nothing
/// changed. The caller owns the buffer, hands it over, and reads it back
/// through `slice`.
pub const Results = struct {
    /// Entries past `len` are never written and never read.
    items: [max_results]ProbeResult = undefined,
    len: u8 = 0,

    /// The results in arrival order, for `report_fold.fold`.
    pub fn slice(self: *const Results) []const ProbeResult {
        return self.items[0..self.len];
    }

    /// Append, unless the buffer is full. A round that has sent everything it
    /// planned cannot reach the bound, and the only way past it is a live QUIC
    /// connection reporting a further address, which `report.max_relays` would
    /// have dropped per family in any case.
    fn push(self: *Results, result: ProbeResult) void {
        if (self.len == max_results) return;
        self.items[self.len] = result;
        self.len += 1;
    }
};
/// Why a round stopped. Upstream's two exits: `drop(actor)` once
/// `have_enough_reports` holds (`net_report.rs:369-373`), and the
/// `OVERALL_REPORT_TIMEOUT` that ends `reportgen`'s `run` (`reportgen.rs:212`).
pub const Outcome = enum {
    /// Enough answers to fold a report.
    enough,
    /// The round ran out of time. A partial set still folds.
    timeout,
};
/// The decision layer. One turn in, one decision out.
///
/// A runner is what `net_report.rs` and `reportgen.rs` are between them: a
/// plan, an instant, and a set of answers. It holds no socket, no task handle
/// and no future, and it reads no clock — `now` goes to `new` and to `step`.
pub const Runner = struct {
    plan: Plan,
    /// When the round started. Every due instant, every deadline and the
    /// captive-portal delay are measured from it, so a runner cannot be asked
    /// two questions about the same instant.
    start: Nanos,
    if_state: IfState,
    /// The caller's results buffer. Borrowed; see `Results`.
    results: *Results,
    /// Which tasks have been sent. A later turn must not send one twice:
    /// upstream spawns a probe once and lets the future answer.
    sent: [max_tasks]bool,
    /// Which families have answered, per relay — the rest of an answered
    /// ladder is dead. See `satisfied`.
    answers: [max_relays]u8,
    /// Whether the captive-portal check has been sent.
    captive_sent: bool,
    /// The check's answer.
    ///
    /// Null is "not decided" and covers three upstream states — never
    /// scheduled, scheduled and unanswered, cancelled — which is why
    /// `Report.captive_portal` is an `Option<bool>` upstream too: a portal
    /// that was never looked for has not been ruled out.
    captive: ?bool,
    /// Set once the round is over. Nothing is decided after it.
    outcome: ?Outcome,

    /// Whether this probe's ladder already has an answer.
    fn satisfied(self: *const Runner, task: Task) bool {
        return self.answers[task.relay] & bit(task.proto) != 0;
    }
};
/// The bit a family occupies in a per-relay mask: its position in
/// `report.Probe`, which is its position in upstream's `Probe` too.
fn bit(proto: Probe) u8 {
    return @as(u8, 1) << @intFromEnum(proto);
}
/// One turn's instructions.
///
/// Not an action list of one: a turn can send every probe that has come due
/// since the last one — upstream spawns the whole QAD fan-out at once
/// (`net_report.rs:504-540`) — so the sends and the wakeup are three
/// independent facts rather than one choice.
pub const Step = struct {
    /// The runner after this turn.
    next: Runner,
    /// The probes to send now, in plan order. At most one per task, and never
    /// two: upstream spawns a probe once and this is the record of it.
    sends: [max_tasks]Task = undefined,
    sends_len: u8 = 0,
    /// When to come back, meaningful only while `outcome` is null. Never null
    /// while a round is unfinished, because the overall deadline is always
    /// ahead of `now` until it is not.
    wake_at: Nanos = 0,
    /// Set on the turn the round is over.
    outcome: ?Outcome = null,
    /// Whether to start the captive-portal check on this turn.
    captive: bool = false,
};
/// A round that has not started.
///
/// `results` is emptied: a round's results are that round's, and the previous
/// one already folded them. The observations a live QUIC connection already
/// holds are seeded into it, which is what `spawn_qad_probes` does with
/// `current_v4()` and `current_v6()` before it decides what to spawn
/// (`net_report.rs:476-488`).
pub fn new(input: Input, results: *Results) Runner {
    const planned = plan(input);
    results.len = 0;
    var runner: Runner = .{
        .plan = planned,
        .start = input.now,
        .if_state = input.if_state,
        .results = results,
        .sent = @splat(false),
        .answers = @splat(0),
        .captive_sent = false,
        .captive = null,
        .outcome = null,
    };
    if (!planned.full) {
        // `QadConns::clear` on a full round closes the connections, so
        // `current_v4` is null by the time the needs are asked.
        if (input.round.carried_v4) |probe| {
            runner = record(runner, 0, .{ .qad_ipv4 = probe });
        }
        if (input.round.carried_v6) |probe| {
            runner = record(runner, 0, .{ .qad_ipv6 = probe });
        }
    }
    return settle(runner);
}
/// One turn: what is due, whether the round is over, and when to come back.
///
/// The order of the questions is the order upstream asks them in. Having enough
/// answers comes first, because upstream drops the actor the moment it holds
/// (`net_report.rs:369-373`) and a probe that has come due in the same instant
/// is one that never ran. The overall deadline comes second, for the same
/// reason: a round that has spent its budget sends nothing more.
///
/// A runner from `new` cannot name more relays than `max_relays` — `plan`
/// truncates there and nowhere else — so this arm is for a runner assembled by
/// hand, and it is the same arm `Plan.taskAt` names.
pub fn step(runner: Runner, now: Nanos) PlanError!Step {
    var out: Step = .{ .next = runner };
    if (runner.outcome) |why| {
        out.outcome = why;
        return out;
    }
    if (haveEnough(
        runner.results.slice(),
        runner.if_state,
        runner.plan.full,
        runner.plan.enough_relays,
    )) {
        out.next.outcome = .enough;
        out.outcome = .enough;
        return out;
    }
    if (now >= runner.start +| overall_timeout) {
        out.next.outcome = .timeout;
        out.outcome = .timeout;
        return out;
    }

    var index: TaskIndex = 0;
    while (try runner.plan.taskAt(index)) |task| : (index += 1) {
        if (runner.sent[index] or runner.satisfied(task)) continue;
        const due = runner.start +| delayFor(task.proto, task.attempt);
        if (now < due) continue;
        out.next.sent[index] = true;
        out.sends[out.sends_len] = task;
        out.sends_len += 1;
    }

    if (runner.plan.captive and !runner.captive_sent) {
        const due = runner.start +| captive_portal_delay;
        if (now >= due) {
            out.next.captive_sent = true;
            out.captive = true;
        }
    }

    out.wake_at = try wakeAt(&out.next, now);
    return out;
}
/// Fold one probe's answer back into the round.
///
/// `task` is the index of the probe the answer is for, taken from the `sends`
/// a turn produced. Upstream's actor receives a `ProbeFinished` from a future
/// it spawned, so the future is the only source of both and an answer with no
/// matching probe is not one this round can use.
///
/// Three things are dropped, and each is a case where upstream has nowhere to
/// put the message: the round is over, the task was never sent, and the
/// results buffer is full. Everything else is stored as given — including an
/// address whose family disagrees with the probe it came from, and including a
/// second answer from a task that already answered, because upstream folds
/// those too: `QadConns::watch_v4` yields every address a live connection
/// observes for as long as it is open (`net_report.rs:205-223`), and
/// `update_relay` keeps the faster of the two.
///
/// The same refusal as `step`, one step earlier: an answer cannot be filed
/// against a plan whose relay list this module cannot index.
pub fn observe(runner: Runner, task: TaskIndex, result: ProbeResult) PlanError!Runner {
    if (runner.outcome != null) return runner;
    const spec = (try runner.plan.taskAt(task)) orelse return runner;
    if (!runner.sent[task]) return runner;
    // A caller that answers one task with another family's result would have
    // its round counted against a family it never probed, which is a caller
    // bug and not a recoverable one.
    std.debug.assert(spec.proto == result.kind());
    return settle(record(runner, spec.relay, result));
}
fn record(runner: Runner, relay: u8, result: ProbeResult) Runner {
    var next = runner;
    next.results.push(result);
    next.answers[relay] |= bit(result.kind());
    return next;
}
/// Re-ask the one question a round asks after every answer.
fn settle(runner: Runner) Runner {
    if (runner.outcome != null) return runner;
    const enough = haveEnough(
        runner.results.slice(),
        runner.if_state,
        runner.plan.full,
        runner.plan.enough_relays,
    );
    if (!enough) return runner;
    var next = runner;
    next.outcome = .enough;
    return next;
}
/// The next instant at which this round would decide something new.
///
/// The overall deadline is always a candidate, so while a round is unfinished
/// there is always something to wait for.
fn wakeAt(runner: *const Runner, now: Nanos) PlanError!Nanos {
    var wake = runner.start +| overall_timeout;
    var in_flight = false;
    var index: TaskIndex = 0;
    while (try runner.plan.taskAt(index)) |task| : (index += 1) {
        if (runner.sent[index]) {
            in_flight = true;
            continue;
        }
        if (runner.satisfied(task)) continue;
        const due = runner.start +| delayFor(task.proto, task.attempt);
        wake = later(wake, due, now);
    }
    // A probe that is in flight keeps the round alive to the budget, which is
    // where upstream's `time::timeout` ends it — a real wake, not a formality:
    // it is the turn on which every outstanding probe is retired at once.
    if (in_flight) wake = later(wake, runner.start +| probe_timeout, now);
    if (runner.plan.captive and runner.captive == null) {
        const due = runner.start +| captive_portal_delay;
        if (!runner.captive_sent) wake = later(wake, due, now);
        wake = later(wake, due +| captive_portal_timeout, now);
    }
    return wake;
}
/// The earlier of two instants, ignoring one this turn has already passed.
fn later(wake: Nanos, candidate: Nanos, now: Nanos) Nanos {
    return if (candidate <= now) wake else @min(wake, candidate);
}
/// The report this round produced. The one place the two halves meet.
///
/// The results go to `report_fold.fold` unchanged and `captive_portal` is written
/// afterwards, because it is not a probe result: upstream delivers it as its
/// own `ProbeFinished::CaptivePortal` and writes it straight onto the report
/// (`net_report.rs:425`), and the fold has no arm for it. Nothing the fold
/// computes reads that field, so writing it after is the same write.
///
/// A partial set folds. `report_fold.fold` over fewer results than were planned is
/// a defined answer and not a shrug: what is missing stays null, which is how
/// a caller tells "not measured" from "measured, and symmetric".
pub fn fold(runner: Runner, history: History, now: Nanos) Report {
    var folded = fold_results(runner.results.slice(), history, now);
    folded.captive_portal = runner.captive;
    return folded;
}

const t = std.testing;
/// A minute in, on the timeline the tests hand to the runner. Five minutes is
/// `full_report_interval`, so a round stamped with it is incremental and one
/// left at zero is a full round for being stale.
const test_start: Nanos = 600 * std.time.ns_per_s;
fn millis(n: u64) Nanos {
    return n * std.time.ns_per_ms;
}
/// A relay URL rendered into `scratch`. The host is `<n>.example.`, so the
/// URLs sort by index and the fold's relay ordering is predictable.
fn namedRelay(scratch: []u8, index: usize) !RelayUrl {
    return RelayUrl.parse(try std.fmt.bufPrint(scratch, "https://{d}.example./", .{index}));
}
/// Three relays, in relay-map order.
fn relaySet(scratch: []u8) ![3]RelayUrl {
    return .{
        try namedRelay(scratch[0..64], 0),
        try namedRelay(scratch[64..128], 1),
        try namedRelay(scratch[128..192], 2),
    };
}
/// `out.len` relay URLs, one 64-byte host each, so a relay list longer than
/// `max_relays` can be built at all.
fn fillRelays(out: []RelayUrl, scratch: []u8) !void {
    for (out, 0..) |*relay, index| {
        relay.* = try namedRelay(scratch[index * 64 ..][0..64], index);
    }
}
/// because `isFull` is what upstream's incremental rules are defined against.
fn freshRound() Round {
    return .{ .next_full = false, .last_full = test_start };
}
const public_v4: SocketAddr = .{ .ip = .{ .v4 = .{ 198, 51, 100, 7 } }, .port = 41234 };
const other_v4: SocketAddr = .{ .ip = .{ .v4 = .{ 198, 51, 100, 9 } }, .port = 51234 };
const public_v6: SocketAddr = .{
    .ip = .{ .v6 = .{
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
        0,    0,    0,    0,    0, 0, 0, 0x07,
    } },
    .port = 41234,
};
test "the ladder is 200, 300 and 400 milliseconds, and QUIC has no ladder" {
    var scratch: [192]u8 = undefined;
    const relays = try relaySet(&scratch);
    var results: Results = .{};
    var runner = new(.{
        .relays = &relays,
        .if_state = .{ .have_v4 = true, .have_v6 = false },
        .protocols = .{ .https = true, .qad_ipv4 = true, .qad_ipv6 = false },
        .now = test_start,
    }, &results);

    // At the start of the round every relay's QUIC probe is due and not one
    // rung of any ladder is: upstream spawns the QAD fan-out in full and holds
    // the HTTPS set back by `HTTPS_OFFSET`.
    const first = try step(runner, test_start);
    try t.expectEqual(@as(u8, 3), first.sends_len);
    try t.expectEqualDeep(
        Task{ .proto = .qad_ipv4, .relay = 0, .attempt = 0 },
        first.sends[0],
    );
    try t.expectEqualDeep(
        Task{ .proto = .qad_ipv4, .relay = 2, .attempt = 0 },
        first.sends[2],
    );
    try t.expectEqual(test_start + https_offset, first.wake_at);
    runner = first.next;

    // Each rung comes due at its own instant, and a turn picks up only what
    // has come due since the last one.
    for ([_]u8{ 0, 1, 2 }) |rung| {
        const turn = try step(runner, test_start + https_offset + initial_retransmit * rung);
        try t.expectEqual(@as(u8, 3), turn.sends_len);
        for (turn.sends[0..3], 0..) |task, relay| {
            try t.expectEqualDeep(
                Task{ .proto = .https, .relay = @intCast(relay), .attempt = rung },
                task,
            );
        }
        runner = turn.next;
    }

    // Nothing is left to send, and the last rung is in flight, so the round
    // waits for the budget rather than for the deadline.
    const spent = try step(runner, test_start + millis(400));
    try t.expectEqual(@as(u8, 0), spent.sends_len);
    try t.expectEqual(test_start + probe_timeout, spent.wake_at);
    try t.expect(spent.outcome == null);
}
test "an incremental round with one live connection on a v4-only host sends nothing" {
    var scratch: [192]u8 = undefined;
    const relays = try relaySet(&scratch);
    const last = report.fold(&.{
        .{ .https = .{ .relay = relays[0], .instant = test_start, .latency = millis(12) } },
    }, .{}, test_start);

    var results: Results = .{};
    const runner = new(.{
        .relays = &relays,
        .if_state = .{ .have_v4 = true, .have_v6 = false },
        .protocols = .{ .https = true, .qad_ipv4 = true, .qad_ipv6 = true },
        .round = .{
            .next_full = false,
            .last_full = test_start,
            .last = &last,
            .carried_v4 = .{
                .relay = relays[0],
                .instant = test_start - millis(5),
                .latency = millis(11),
                .addr = public_v4,
            },
        },
        .now = test_start,
    }, &results);

    // No HTTPS ladder, because the last report measured something, and no QUIC
    // probe, because the v4 connection is already up and the host has no v6.
    try t.expectEqual(@as(u8, 0), try runner.plan.taskCount());
    try t.expect(!runner.plan.full);
    // The carried observation is the round, and one of them is all a v4-only
    // host needs on an incremental round.
    try t.expectEqual(@as(u8, 1), results.len);
    try t.expectEqual(Outcome.enough, runner.outcome.?);
    const turn = try step(runner, test_start);
    try t.expectEqual(@as(u8, 0), turn.sends_len);

    const folded = fold(turn.next, .{}, test_start);
    try t.expect(folded.udp_v4);
    try t.expect(!folded.udp_v6);
    try t.expectEqualDeep(public_v4, folded.global_v4.?);
    try t.expect(folded.mapping_varies_by_dest_ipv4 == null);
}
test "a v6 address from a v4 probe keeps its latency and declines to classify" {
    var scratch: [192]u8 = undefined;
    const relays = try relaySet(&scratch);
    var results: Results = .{};
    var runner = new(.{
        .relays = &relays,
        .if_state = .{ .have_v4 = true, .have_v6 = false },
        .protocols = .{ .https = false, .qad_ipv4 = true, .qad_ipv6 = false },
        .now = test_start,
    }, &results);
    const sent = try step(runner, test_start);
    try t.expectEqual(@as(u8, 3), sent.sends_len);

    // A relay that answers a v4 probe with an IPv6 address. The tag is the
    // probe's, so this is a v4 result carrying a v6 address, and it is the
    // only thing the module knows how to say.
    const crossed = qadResult(.v4, relays[0], test_start, millis(9), public_v6);
    try t.expectEqual(Probe.qad_ipv4, crossed.kind());
    runner = try observe(sent.next, 0, crossed);

    // The measurement is kept: it is in the v4 family's latency list, and the
    // round counts the answer as a v4 answer, which is what upstream does by
    // filing it under the probe's protocol before it checks the address.
    try t.expectEqual(@as(u8, 1), results.len);
    try t.expectEqual(@as(usize, 1), measured(.qad_ipv4, results.slice()));
    try t.expectEqual(@as(usize, 0), measured(.qad_ipv6, results.slice()));
    try t.expectEqual(millis(9), runner.results.slice()[0].latency());

    const folded = fold(runner, .{}, test_start);
    try t.expectEqual(millis(9), folded.relay_latency.get(relays[0]).?);
    // And nothing else is believed: no UDP claim, no address to publish, and
    // no classification, because a NAT characterised from an address of the
    // wrong family is the failure this exists to prevent.
    try t.expect(!folded.udp_v4);
    try t.expect(!folded.hasUdp());
    try t.expect(folded.global_v4 == null);
    try t.expect(folded.mapping_varies_by_dest_ipv4 == null);
    try t.expect(folded.mappingVariesByDest() == null);
}
test "the same address in the right family classifies, and that is the only difference" {
    var scratch: [192]u8 = undefined;
    const relays = try relaySet(&scratch);
    var results: Results = .{};
    const runner = new(.{
        .relays = &relays,
        .if_state = .{ .have_v4 = true, .have_v6 = false },
        .protocols = .{ .https = false, .qad_ipv4 = true, .qad_ipv6 = false },
        .now = test_start,
    }, &results);
    const sent = try step(runner, test_start);

    // Two v4 answers with different addresses from different relays: the
    // mapping varies by destination, and now it can be said.
    const answered = try observe(sent.next, 0, qadResult(
        .v4,
        relays[0],
        test_start,
        millis(9),
        public_v4,
    ));
    const varied = try observe(answered, 1, qadResult(
        .v4,
        relays[1],
        test_start,
        millis(11),
        other_v4,
    ));
    const folded = fold(varied, .{}, test_start);
    try t.expect(folded.udp_v4);
    try t.expectEqual(@as(?bool, true), folded.mapping_varies_by_dest_ipv4);
    try t.expectEqual(@as(?bool, true), folded.mappingVariesByDest());
    try t.expectEqualDeep(public_v4, folded.global_v4.?);
}
test "the first answer to a relay kills the rest of its ladder" {
    var scratch: [192]u8 = undefined;
    const relays = try relaySet(&scratch);
    var results: Results = .{};
    var runner = new(.{
        .relays = &relays,
        .if_state = .{},
        .protocols = .{ .https = true, .qad_ipv4 = false, .qad_ipv6 = false },
        .now = test_start,
    }, &results);

    const first = try step(runner, test_start);
    try t.expectEqual(@as(u8, 0), first.sends_len);
    try t.expectEqual(test_start + https_offset, first.wake_at);
    runner = first.next;

    const due = try step(runner, test_start + https_offset);
    try t.expectEqual(@as(u8, 3), due.sends_len);
    const answered = try observe(due.next, 0, .{
        .https = .{ .relay = relays[0], .instant = test_start, .latency = millis(12) },
    });
    try t.expectEqual(@as(u8, 1), results.len);

    // Relay 0's second rung is not sent, and the other two relays are.
    const later_turn = try step(answered, test_start + https_offset + initial_retransmit);
    try t.expectEqual(@as(u8, 2), later_turn.sends_len);
    try t.expectEqualDeep(
        Task{ .proto = .https, .relay = 1, .attempt = 1 },
        later_turn.sends[0],
    );
    try t.expectEqualDeep(
        Task{ .proto = .https, .relay = 2, .attempt = 1 },
        later_turn.sends[1],
    );
}
test "a round that runs out of time folds what it has" {
    var scratch: [192]u8 = undefined;
    const relays = try relaySet(&scratch);
    var results: Results = .{};
    var runner = new(.{
        .relays = &relays,
        .if_state = .{ .have_v4 = true, .have_v6 = false },
        .protocols = .{ .https = true, .qad_ipv4 = true, .qad_ipv6 = false },
        .now = test_start,
    }, &results);
    const sent = try step(runner, test_start);
    runner = try observe(sent.next, 0, qadResult(
        .v4,
        relays[0],
        test_start,
        millis(9),
        public_v4,
    ));

    // The ladder ran, nothing answered, and the deadline arrives.
    const ended = try step(runner, test_start + overall_timeout);
    try t.expectEqual(Outcome.timeout, ended.outcome.?);
    try t.expectEqual(@as(u8, 0), ended.sends_len);
    // A turn after the end says the same thing and sends nothing.
    const after = try step(ended.next, test_start + overall_timeout + millis(1));
    try t.expectEqual(Outcome.timeout, after.outcome.?);
    try t.expectEqual(@as(u8, 0), after.sends_len);

    const folded = fold(after.next, .{}, test_start + overall_timeout);
    try t.expect(folded.udp_v4);
    try t.expectEqualDeep(public_v4, folded.global_v4.?);
    // One answer compares against nothing, so the round measured a NAT's
    // address and nothing about whether the mapping moves.
    try t.expect(folded.mapping_varies_by_dest_ipv4 == null);
    try t.expect(folded.mappingVariesByDest() == null);
    // And the relay it did time is the one to home on.
    try t.expectEqual(std.math.Order.eq, folded.preferred_relay.?.order(relays[0]));
}
test "the captive-portal check waits, and a round that is already good enough skips it" {
    var scratch: [192]u8 = undefined;
    const relays = try relaySet(&scratch);
    var base_round: Round = freshRound();
    base_round.captive_portal_check = true;
    const base: Input = .{
        .relays = &relays,
        .if_state = .{ .have_v4 = true, .have_v6 = true },
        .protocols = .{ .https = true, .qad_ipv4 = true, .qad_ipv6 = true },
        .round = base_round,
        .now = test_start,
    };
    try t.expect(plan(base).captive);
    // A round that already has a last report does not check: upstream
    // schedules the check only when there is no last report, and re-checking a
    // portal the last round already ruled on is how a report stops converging.
    var with_last = base;
    with_last.round.last = &report.Report{};
    try t.expect(!plan(with_last).captive);

    var results: Results = .{};
    var runner = new(base, &results);
    const start = try step(runner, test_start);
    try t.expect(!start.captive);
    try t.expectEqual(test_start + captive_portal_delay, start.wake_at);
    runner = start.next;

    // Two answers, one of each family, end an incremental-sized round long
    // before the check's 200 ms delay is up.
    runner = try observe(runner, 0, qadResult(
        .v4,
        relays[0],
        test_start,
        millis(9),
        public_v4,
    ));
    runner = try observe(runner, 1, qadResult(
        .v6,
        relays[0],
        test_start,
        millis(9),
        public_v6,
    ));
    const ended = try step(runner, test_start + millis(20));
    try t.expectEqual(Outcome.enough, ended.outcome.?);
    try t.expectEqual(@as(u8, 0), ended.sends_len);
    // The ladder was planned and never sent a rung: the round was over before
    // the first one came due.
    try t.expectEqual(@as(usize, 0), measured(.https, results.slice()));
    try t.expect(!ended.captive);
    try t.expect(!ended.next.captive_sent);
    // Null, not false: a portal nobody looked for has not been ruled out.
    try t.expect(fold(ended.next, .{}, test_start).captive_portal == null);

    // A round that is not satisfied runs the check, and its answer is the only
    // thing `Report.captive_portal` is ever set from.
    var other: Results = .{};
    var idle = new(.{
        .relays = &relays,
        .if_state = .{},
        .protocols = .{ .https = false, .qad_ipv4 = false, .qad_ipv6 = false },
        .round = .{ .captive_portal_check = true },
        .now = test_start,
    }, &other);
    // Nothing can run, so the only thing left is the check.
    const waiting = try step(idle, test_start);
    try t.expect(!waiting.captive);
    const checked = try step(waiting.next, test_start + captive_portal_delay);
    try t.expect(checked.captive);
    try t.expect(checked.outcome == null);
    try t.expectEqual(
        test_start + captive_portal_delay + captive_portal_timeout,
        checked.wake_at,
    );
    idle = checked.next;
    idle.captive = true;
    try t.expectEqual(@as(?bool, true), fold(idle, .{}, test_start).captive_portal);
}
test "an answer for a probe that was never sent is dropped" {
    var scratch: [192]u8 = undefined;
    const relays = try relaySet(&scratch);
    var results: Results = .{};
    const runner = new(.{
        .relays = &relays,
        .if_state = .{ .have_v4 = true, .have_v6 = false },
        .protocols = .{ .https = true, .qad_ipv4 = true, .qad_ipv6 = false },
        .now = test_start,
    }, &results);
    const turn = try step(runner, test_start);

    // Task 3 is the first rung of relay 0's ladder, which is not due yet.
    const ignored = try observe(turn.next, 3, .{
        .https = .{ .relay = relays[0], .instant = test_start, .latency = millis(12) },
    });
    try t.expectEqual(@as(u8, 0), results.len);
    // An index past the plan is not a task at all.
    const past = try observe(ignored, 200, .{
        .https = .{ .relay = relays[0], .instant = test_start, .latency = millis(12) },
    });
    try t.expectEqual(@as(u8, 0), results.len);
    try t.expect(past.outcome == null);
}
test "a round with no relays to probe ends at once and claims nothing" {
    var results: Results = .{};
    const runner = new(.{
        .relays = &.{},
        .if_state = .{ .have_v4 = true, .have_v6 = true },
        .protocols = .{ .https = true, .qad_ipv4 = true, .qad_ipv6 = true },
        .now = test_start,
    }, &results);
    try t.expectEqual(@as(u8, 0), try runner.plan.taskCount());
    try t.expectEqual(@as(usize, 0), runner.plan.enough_relays);
    try t.expectEqual(Outcome.enough, runner.outcome.?);

    const folded = fold(runner, .{}, test_start);
    try t.expect(!folded.hasUdp());
    try t.expect(folded.preferred_relay == null);
    try t.expect(folded.mappingVariesByDest() == null);
}
test "a round this module planned folds into a report" {
    var scratch: [192]u8 = undefined;
    const relays = try relaySet(&scratch);
    var results: Results = .{};
    var runner = new(.{
        .relays = &relays,
        .if_state = .{ .have_v4 = true, .have_v6 = true },
        .protocols = .{ .https = true, .qad_ipv4 = true, .qad_ipv6 = true },
        .now = test_start,
    }, &results);

    // The whole QUIC fan-out goes at once, six probes, and the ladder waits.
    const sent = try step(runner, test_start);
    try t.expectEqual(@as(u8, 6), sent.sends_len);
    runner = sent.next;

    // A v4 answer and a v6 answer from the first relay are not enough on their
    // own: a full round wants two of one family and one of the other.
    runner = try observe(runner, 0, qadResult(
        .v4,
        relays[0],
        test_start,
        millis(12),
        public_v4,
    ));
    runner = try observe(runner, 1, qadResult(
        .v6,
        relays[0],
        test_start,
        millis(11),
        public_v6,
    ));
    const waiting = try step(runner, test_start + millis(5));
    try t.expect(waiting.outcome == null);
    try t.expectEqual(test_start + https_offset, waiting.wake_at);

    // The second relay's v4 answer, and this one disagrees about the address.
    runner = try observe(waiting.next, 5, qadResult(
        .v4,
        relays[1],
        test_start + millis(6),
        millis(9),
        other_v4,
    ));
    const ended = try step(runner, test_start + millis(7));
    try t.expectEqual(Outcome.enough, ended.outcome.?);
    try t.expectEqual(@as(u8, 0), ended.sends_len);
    // The ladder never ran, so nothing was ever measured over HTTPS.
    try t.expectEqual(@as(usize, 0), measured(.https, results.slice()));

    const folded = fold(ended.next, .{}, test_start + millis(7));
    try t.expect(folded.udp_v4);
    try t.expect(folded.udp_v6);
    try t.expect(folded.hasUdp());
    try t.expectEqual(@as(?bool, true), folded.mapping_varies_by_dest_ipv4);
    // One v6 answer compares against nothing.
    try t.expect(folded.mapping_varies_by_dest_ipv6 == null);
    try t.expectEqual(@as(?bool, true), folded.mappingVariesByDest());
    // The fastest v4 observation is the published address, and the fastest
    // measurement overall is the relay to home on.
    try t.expectEqualDeep(other_v4, folded.global_v4.?);
    try t.expectEqualDeep(public_v6, folded.global_v6.?);
    try t.expectEqual(std.math.Order.eq, folded.preferred_relay.?.order(relays[1]));
    try t.expectEqual(millis(9), folded.relay_latency.get(relays[1]).?);
    try t.expect(folded.captive_portal == null);
}
test "the widest relay list a plan admits serves every index it has" {
    // Eight in, five out. `plan` truncates, so the round runs at the width the
    // arrays are sized for and the largest count a `TaskIndex` is ever asked to
    // carry is served rather than refused.
    var many: [max_relays + 3]RelayUrl = undefined;
    var scratch: [(max_relays + 3) * 64]u8 = undefined;
    try fillRelays(&many, &scratch);
    var results: Results = .{};
    const runner = new(.{
        .relays = &many,
        .if_state = .{ .have_v4 = true, .have_v6 = true },
        .protocols = .{ .https = true, .qad_ipv4 = true, .qad_ipv6 = true },
        .now = test_start,
    }, &results);
    try t.expectEqual(@as(usize, max_relays), runner.plan.relays.len);
    try t.expectEqual(@as(u8, max_tasks), try runner.plan.taskCount());

    // The last rung of the last relay, and nothing after it.
    try t.expectEqualDeep(
        Task{ .proto = .https, .relay = max_relays - 1, .attempt = https_attempts - 1 },
        (try runner.plan.taskAt(max_tasks - 1)).?,
    );
    try t.expect((try runner.plan.taskAt(max_tasks)) == null);

    // Every planned relay's QUIC probe goes at once and the ladder waits for
    // its offset, so a turn fills ten of the twenty-five send slots and stops.
    const sent = try step(runner, test_start);
    try t.expectEqual(@as(u8, 2 * max_relays), sent.sends_len);
    try t.expectEqual(test_start + https_offset, sent.wake_at);

    // The last relay's QAD probe is the first of the five tasks it owns, and
    // its answer files in the last mask slot — the relay index one below the
    // count above.
    const last_qad: u8 = (max_relays - 1) * (2 + https_attempts);
    const answered = try observe(sent.next, last_qad, qadResult(
        .v4,
        many[max_relays - 1],
        test_start,
        millis(9),
        public_v4,
    ));
    try t.expectEqual(bit(Probe.qad_ipv4), answered.answers[max_relays - 1]);
    try t.expectEqual(millis(9), answered.results.slice()[0].latency());
    try t.expect(answered.outcome == null);
}
test "a plan wider than the arrays that hold it is refused, not wrapped" {
    // A `Plan` is a public struct with public fields, so a caller can build one
    // by literal and nothing in the type stops the list from outrunning
    // `max_relays`. Wrapped instead of refused, the count would be 30 for a
    // round whose arrays hold 25, and the sixth relay's `Task.relay` would be 5
    // into a `[max_relays]u8`: a walk off the end of `Runner.answers` and of a
    // turn's `sent`, on the first turn, in Debug.
    var many: [max_relays + 1]RelayUrl = undefined;
    var scratch: [(max_relays + 1) * 64]u8 = undefined;
    try fillRelays(&many, &scratch);
    const wide: Plan = .{
        .relays = &many,
        .full = true,
        .enough_relays = enough_endpoints,
        .run = .{ true, true, true },
        .captive = false,
    };
    try t.expectError(error.RelaysTooMany, wide.taskCount());
    try t.expectError(error.RelaysTooMany, wide.taskAt(0));
    try t.expectError(error.RelaysTooMany, wide.taskAt(max_tasks));

    // The other arm of the same proof, and the one the guard cannot reach: a
    // list one relay past what a `TaskIndex` spells never gets as far as the
    // comparison. A caller's length is not one of this file's constants, so
    // the cast is the only thing standing between it and a `u8` of relays.
    const too_wide: [std.math.maxInt(TaskIndex) + 1]RelayUrl = @splat(many[0]);
    const widest: Plan = .{
        .relays = &too_wide,
        .full = true,
        .enough_relays = 0,
        .run = .{ true, true, true },
        .captive = false,
    };
    try t.expectError(error.RelaysTooMany, widest.taskCount());
    try t.expectError(error.RelaysTooMany, widest.taskAt(0));

    var results: Results = .{};
    const runner: Runner = .{
        .plan = wide,
        .start = test_start,
        .if_state = .{ .have_v4 = true, .have_v6 = true },
        .results = &results,
        .sent = @splat(false),
        .answers = @splat(0),
        .captive_sent = false,
        .captive = null,
        .outcome = null,
    };
    try t.expectError(error.RelaysTooMany, step(runner, test_start));
    const answer = qadResult(.v4, many[0], test_start, millis(9), public_v4);
    try t.expectError(error.RelaysTooMany, observe(runner, 0, answer));
    // The refusal does not depend on the index: an answer one past the widest
    // task a legal plan holds is refused the same way, and nothing is filed.
    try t.expectError(error.RelaysTooMany, observe(runner, max_tasks, answer));
    try t.expectEqual(@as(u8, 0), results.len);
}
