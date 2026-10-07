//! Running a planned probe round one turn at a time.
//!
//! This is the state-machine half of the module `probe.zig` is the facade for:
//! `probe_plan.zig` says what a round will run, and this holds the round between
//! turns — what has been sent, what has answered, and what the gate decided.
//! `probe.Runner` is a plain value: it reads no clock (`now` goes to `new` and
//! to `step`), holds no socket, no task and no allocator, and every buffer in
//! it is borrowed from the caller.
//!
//! The module doc `probe.zig` carries is the argument for all three halves and
//! is not repeated here.

const std = @import("std");
const addr = @import("../base/addr.zig");
const report = @import("report.zig");
const plan_mod = @import("probe_plan.zig");

const RelayUrl = addr.RelayUrl;
const Probe = report.Probe;
const Nanos = report.Nanos;
const ProbeResult = report.ProbeResult;

// The plan half's surface, which the turn half reads and does not redefine.
const IfState = plan_mod.IfState;
const Input = plan_mod.Input;
const Plan = plan_mod.Plan;
const PlanError = plan_mod.PlanError;
const Task = plan_mod.Task;
const TaskIndex = plan_mod.TaskIndex;
const buildPlan = plan_mod.plan;
const delayFor = plan_mod.delayFor;
const max_relays = plan_mod.max_relays;
const max_results = plan_mod.max_results;
const max_tasks = plan_mod.max_tasks;
const overall_timeout = plan_mod.overall_timeout;
const probe_timeout = plan_mod.probe_timeout;
const captive_portal_delay = plan_mod.captive_portal_delay;
const captive_portal_timeout = plan_mod.captive_portal_timeout;

/// How many relays have a latency recorded in `probe`. Upstream's
/// `have_enough_reports` counts entries of the three `BTreeMap`s in
/// `RelayLatencies`, so two answers to one relay count once: `update_relay`
/// keeps the faster of them and the map still holds a single entry.
///
/// A walk rather than a bit set, because a result may name a relay the plan
/// does not contain. Upstream seeds a report with whatever a live QUIC
/// connection last saw, and that relay need not be one this round plans:
/// `spawn_qad_probes` truncates to `MAX_RELAYS` and `QadConns::current_v4`
/// does not. The count therefore has to be over relay URLs and not over plan
/// positions.
///
/// A `usize`, not a `u8`: the only ceiling on a results slice is the one its
/// caller brought. `Results.push` caps this module's own results at
/// `max_results`, and a count narrowed below even that would be a bound proved
/// nowhere for a list this module did not fill.
pub fn measured(probe: Probe, results: []const ProbeResult) usize {
    var count: usize = 0;
    for (results, 0..) |result, index| {
        if (result.kind() != probe) continue;
        if (countedBefore(results[0..index], probe, result.relay())) continue;
        count += 1;
    }
    return count;
}

fn countedBefore(earlier: []const ProbeResult, probe: Probe, relay: RelayUrl) bool {
    for (earlier) |result| {
        if (result.kind() != probe) continue;
        if (result.relay().order(relay) == .eq) return true;
    }
    return false;
}

/// A shape of answers that satisfies a round.
pub const Quota = struct { ipv4: u8, ipv6: u8 };

/// The (v4, v6) shapes that end a round, per host capability. Upstream's
/// `have_enough_reports` match on `(have_v4, have_v6)`, read as a list because
/// the full arm admits two of them: two v4 answers with one v6, or two v6 with
/// one v4.
///
/// Two of one family and one of the other is the smallest count that can both
/// prove UDP works and compare two public addresses from different relays — a
/// single answer compares against nothing, which is why `report.Varying`
/// classifies one observation as "not measured" rather than as symmetric.
fn quotas(state: IfState, full: bool) []const Quota {
    if (state.have_v4 and state.have_v6) {
        return if (full)
            &.{ .{ .ipv4 = 2, .ipv6 = 1 }, .{ .ipv4 = 1, .ipv6 = 2 } }
        else
            &.{.{ .ipv4 = 1, .ipv6 = 1 }};
    }
    if (state.have_v4) {
        return if (full) &.{.{ .ipv4 = 2, .ipv6 = 0 }} else &.{.{ .ipv4 = 1, .ipv6 = 0 }};
    }
    if (state.have_v6) {
        return if (full) &.{.{ .ipv4 = 0, .ipv6 = 2 }} else &.{.{ .ipv4 = 0, .ipv6 = 1 }};
    }
    // No address family at all: no QAD probe is ever spawned, so no QAD answer
    // can arrive and the HTTPS check is the only way a round can end.
    return &.{};
}

/// Do these answers end the round. Upstream's `have_enough_reports`,
/// `net_report.rs:661-746`, arm for arm.
///
/// The HTTPS arm is upstream's too and it is the loosest of the three: one
/// answer per planned relay is enough whatever else is missing, because an
/// HTTPS answer still times a relay and still feeds the preferred-relay
/// choice. A round that reaches it is a round that learned no NAT and homed on
/// a relay, which is a real and useful answer.
pub fn haveEnough(
    results: []const ProbeResult,
    if_state: IfState,
    full: bool,
    enough_relays: usize,
) bool {
    // The counts are `usize` because a count is however many answers the
    // caller's list holds, and the quota is a `u8` because a shape is
    // something this module writes.
    const ipv4 = measured(.qad_ipv4, results);
    const ipv6 = measured(.qad_ipv6, results);
    const https = measured(.https, results);
    for (quotas(if_state, full)) |quota| {
        if (ipv4 >= @as(usize, quota.ipv4) and ipv6 >= @as(usize, quota.ipv6)) return true;
    }
    return https >= enough_relays;
}

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

    /// The results in arrival order, for `report.fold`.
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
// The mask itself stays an implementation detail of `Runner.answers`; this is
// widened only so the test in `probe.zig` can read the bit a family occupies.
// ziglint-ignore: Z012
pub fn bit(proto: Probe) u8 {
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
    const planned = buildPlan(input);
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
/// The results go to `report.fold` unchanged and `captive_portal` is written
/// afterwards, because it is not a probe result: upstream delivers it as its
/// own `ProbeFinished::CaptivePortal` and writes it straight onto the report
/// (`net_report.rs:425`), and the fold has no arm for it. Nothing the fold
/// computes reads that field, so writing it after is the same write.
///
/// A partial set folds. `report.fold` over fewer results than were planned is
/// a defined answer and not a shrug: what is missing stays null, which is how
/// a caller tells "not measured" from "measured, and symmetric".
pub fn fold(runner: Runner, history: report.History, now: Nanos) report.Report {
    var folded = report.fold(runner.results.slice(), history, now);
    folded.captive_portal = runner.captive;
    return folded;
}
