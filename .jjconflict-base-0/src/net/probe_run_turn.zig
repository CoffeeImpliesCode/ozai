//! One turn of a probe round: send what the step named, take what came
//! back, give up what did not.
//!
//! The seam vocabulary lives in `probe_run_wire.zig`; this half holds the turn
//! that drives it. Every instant is `Request.now` or something derived from it,
//! the turn never waits, and the bound on the drain is the number of probes
//! open when it began — so a transport that answers for ever costs a turn that
//! returns rather than a round that hangs.
//!
//! The module doc `probe_run.zig` carries is the argument for the whole file
//! and is not repeated here.

const std = @import("std");
const addr = @import("../base/addr.zig");
const probe = @import("probe.zig");
const report = @import("report.zig");
const wire = @import("probe_run_wire.zig");

const Nanos = report.Nanos;
const RelayUrl = addr.RelayUrl;

const Error = wire.Error;
const Observation = wire.Observation;
const Request = wire.Request;
const Transport = wire.Transport;
const InFlight = wire.InFlight;
const Turn = wire.Turn;

/// Run one turn of a round: send what the step named, take what came back,
/// give up what did not.
///
/// `in_flight` must be the same value every turn. Answered and expired probes
/// are closed; pending probes remain open for the next `drive` or `cancel`.
/// A completed round closes all remaining resources. On error, `cancel`
/// has already closed them and the caller must abandon the round.
///
/// A turn is a function of `request.now` and nothing else. It never waits, so
/// the caller drives the round by handing it the next instant in `wake_at`.
pub fn drive(
    runner: probe.Runner,
    transport: Transport,
    in_flight: *InFlight,
    request: Request,
) Error!Turn {
    const now = request.now;
    // A failed turn abandons the whole round, including earlier acquisitions.
    errdefer cancel(transport, in_flight);

    const step = try probe.step(runner, now);

    var opened: usize = 0;
    var slot: u8 = 0;
    while (slot < step.sends_len) : (slot += 1) {
        const task = step.sends[slot];
        const filed = (try sendIndex(&step, task)) orelse return error.Unattributable;
        try transport.vtable.open(transport.ctx, .{
            .task = task,
            .relay = step.next.plan.relays[task.relay],
            .at = now,
            .deadline = probeBudget(step.next),
        });
        in_flight.open[filed.index] = task;
        opened += 1;
    }

    if (step.captive) {
        const relay = request.check_relay orelse return error.NoCheckRelay;
        try transport.vtable.beginCheck(transport.ctx, .{
            .relay = relay,
            .at = now,
            .deadline = checkBudget(step.next),
        });
        in_flight.check = true;
    }

    // Take what came back before anything is given up, because that is the
    // order upstream's own timeout polls in: the inner future is offered the
    // turn first and the deadline is only consulted when it has nothing. A
    // reply that arrived before the budget is a measurement whatever the
    // instant this turn happens to be handed.
    //
    // The bound is the number of probes open when the drain began, and it is
    // the only thing standing between a transport that answers for ever and a
    // turn that never returns: every answer accepted here closes its probe, so
    // the count can only go down. The round's own end stops it too — upstream
    // drops the actor rather than draining the futures inside it.
    const open_before = in_flight.count();
    var answered: usize = 0;
    var current = step.next;
    while (answered < open_before and current.outcome == null) {
        const reply = transport.vtable.poll(transport.ctx, now) orelse break;
        const filed = (try sendIndex(&step, reply.task)) orelse return error.Unattributable;
        const open = in_flight.open[filed.index] orelse return error.Unattributable;
        const result = try resultFor(
            filed.task,
            step.next.plan.relays[filed.task.relay],
            now,
            reply.value,
        );
        // Cleared only once the answer is a result: a shape the task cannot
        // hold refuses the turn, and a probe the refusal took off the open set
        // would never be closed.
        in_flight.open[filed.index] = null;
        current = try probe.observe(current, filed.index, result);
        transport.vtable.close(transport.ctx, open, .answered);
        answered += 1;
    }

    if (in_flight.check) {
        if (transport.vtable.pollCheck(transport.ctx, now)) |answer| {
            transport.vtable.endCheck(transport.ctx, .answered);
            in_flight.check = false;
            // Written straight onto the runner, because it is not a probe
            // result: upstream delivers it as its own `ProbeFinished` and writes
            // it onto the report (`net_report.rs:425`), and `report.fold` has
            // no arm for it.
            current.captive = answer;
        }
    }

    // A round that is over takes its open probes with it, so the budget is
    // only spent on a round that could still use an answer.
    if (current.outcome != null) {
        cancel(transport, in_flight);
        return .{
            .runner = current,
            .wake_at = null,
            .opened = @intCast(opened),
            .answered = @intCast(answered),
            .expired = 0,
        };
    }

    // Give up whatever the budget has run out on. Upstream's `time::timeout`
    // drops the future it wrapped (`reportgen.rs:391-401`), and an answer that
    // arrives after that belongs to a probe that no longer exists: the round
    // stops waiting on it, and a transport that answers anyway is refused.
    const budget = probeBudget(step.next);
    var expired: usize = 0;
    var index: probe.TaskIndex = 0;
    while (index < try step.next.plan.taskCount()) : (index += 1) {
        const open = in_flight.open[index] orelse continue;
        if (now < budget) continue;
        transport.vtable.close(transport.ctx, open, .expired);
        in_flight.open[index] = null;
        expired += 1;
    }
    if (in_flight.check and now >= checkBudget(step.next)) {
        transport.vtable.endCheck(transport.ctx, .expired);
        in_flight.check = false;
    }

    return .{
        .runner = current,
        .wake_at = step.wake_at,
        .opened = @intCast(opened),
        .answered = @intCast(answered),
        .expired = @intCast(expired),
    };
}

/// Close everything a round still has open and give the round up.
///
/// The caller's when it stops early — a shutdown, a cancel handle that fired —
/// and `drive`'s own when the round ends or a turn fails. The reason is
/// `canceled` in both cases because both are the actor being dropped
/// (`probes.rs:36-45`).
pub fn cancel(transport: Transport, in_flight: *InFlight) void {
    for (&in_flight.open) |*slot| {
        const task = slot.* orelse continue;
        transport.vtable.close(transport.ctx, task, .canceled);
        slot.* = null;
    }
    if (in_flight.check) {
        transport.vtable.endCheck(transport.ctx, .canceled);
        in_flight.check = false;
    }
}

/// When a probe this round sent is given up at.
///
/// From the round's start and not from the send, for `reportgen.rs:391-401`'s
/// reason: the timeout is outside the delay, so the 400 ms rung has 2.6 s of
/// probe left and not 3 s. Saturating, like every sum of a start and a budget
/// in this layer.
fn probeBudget(runner: probe.Runner) Nanos {
    return runner.start +| probe.probe_timeout;
}

/// When the captive-portal check is given up at. Its delay and its timeout,
/// both from the round's start (`defaults.rs:30`, `:36`).
fn checkBudget(runner: probe.Runner) Nanos {
    return runner.start +| probe.captive_portal_delay +| probe.captive_portal_timeout;
}

/// Where in the plan `task` was sent, or null when the plan holds no such
/// task.
///
/// `Step.sends` is compacted — `sends_len` entries in plan order, with the
/// indices left behind in `Step.next.sent` — and `probe.observe` files an
/// answer against an index. Recovering it by walking the plan and matching the
/// task is deliberate: a second copy of `step`'s due-and-unsent rule would be a
/// second opinion about when a probe is sent, and the two would disagree the
/// first time that rule changed. Matching needs only two properties of the loop
/// in `step` — that it emits in plan order, and that it never emits one index
/// twice — and a task that is in the plan is a task that was sent.
///
/// The plan's own copy of the task rides back with the index, so the caller
/// attributes against the plan rather than against the answer's own claim
/// about itself, and the walk happens once.
fn sendIndex(step: *const probe.Step, task: probe.Task) Error!?struct {
    index: probe.TaskIndex,
    task: probe.Task,
} {
    var index: probe.TaskIndex = 0;
    while (try step.next.plan.taskAt(index)) |candidate| : (index += 1) {
        if (std.meta.eql(candidate, task)) return .{ .index = index, .task = candidate };
    }
    return null;
}

/// The result an observation is filed under, attributed to the probe that ran.
///
/// The family in the tag is the family of `task` and never the family of the
/// address that came back, for the module doc's attribution reason. The two
/// arms are checked against the task rather than assumed: a transport that
/// answered a QUIC probe with a bare latency, or an HTTPS probe with an
/// address, is describing an exchange this fold has no field for, and
/// `report.ProbeResult`'s union is what makes that unrepresentable — so it is
/// refused here rather than filed as something it is not.
fn resultFor(
    task: probe.Task,
    relay: RelayUrl,
    now: Nanos,
    saw: Observation,
) Error!report.ProbeResult {
    switch (saw) {
        .https => |latency| {
            if (task.proto != .https) return error.AnswerMismatch;
            return .{ .https = .{
                .relay = relay,
                .instant = now,
                .latency = latency,
            } };
        },
        .qad => |qad| {
            // `reported` is handed over as the relay gave it. Upstream
            // canonicalises with `to_canonical` at `net_report.rs:857` and this
            // file deliberately does not: an IPv4-mapped address arriving
            // intact is a case for `report.fold`'s family check rather than a
            // loss of it, and which mapping to trust is the caller's choice.
            return switch (task.proto) {
                .qad_ipv4 => probe.qadResult(
                    .v4,
                    relay,
                    now,
                    qad.latency,
                    qad.reported,
                ),
                .qad_ipv6 => probe.qadResult(
                    .v6,
                    relay,
                    now,
                    qad.latency,
                    qad.reported,
                ),
                .https => error.AnswerMismatch,
            };
        },
    }
}
