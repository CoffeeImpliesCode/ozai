//! Running a probe round: the half of `net/probe.zig` that sends.
//!
//! `probe.zig` plans and folds, `report.zig` folds, and nothing between them
//! ever opened a probe. Every `report.ProbeResult` in this project was written
//! by a test, and the M10 holepunch gate reads probe-derived state no producer
//! made. This file is the producer: it takes a `probe.Step`, opens every send
//! the step names, takes every answer that comes back, files each through
//! `probe.observe`, gives up whatever runs out of budget, and hands back a
//! runner the fold can read.
//!
//! # A probe is a value; this is the thing that makes it traffic
//!
//! `probe.Step` says which probes are due, against which relays, at which rungs,
//! and says so without opening a socket — which is why a whole round can be
//! planned with no network in it. This file is what makes that plan traffic: a
//! transport that can send and receive, injected by the caller. Everything
//! upstream does with a future — spawn it, wait for it, time it out — happens
//! here as a value, and the plan and the send are two halves of one round
//! rather than two opinions about it.
//!
//! # The two probe kinds are different animals and the code says so
//!
//! An HTTPS probe reports a latency and no address, because it never sees one.
//! A QUIC address-discovery probe reports a latency *and* the address the relay
//! saw us come from, and that address is what classifies a NAT.
//! `report.ProbeResult` makes that unrepresentable rather than a null check —
//! its `https` arm has no address field at all and both QAD arms carry a
//! required one — and `Observation` keeps it unrepresentable at this seam too:
//! it has no optional address either. `resultFor` builds one type or the other
//! and there is no third shape, so a latency cannot be filed as a mapping and
//! an address cannot be filed against a probe that never learned one.
//!
//! # Attribution is the probe's, never the address's
//!
//! Upstream builds the payload inside the probe's own future
//! (`net_report.rs:855-859`), so the family in the tag is the family the probe
//! **ran** with and never the family of the address that came back: a relay
//! answering a v4 probe with an IPv6 address produces a v4 result carrying a
//! v6 address. `Report::update` (`report.rs:81-84`) then records the latency,
//! drops the address, and classifies nothing.
//!
//! That check lives in `report.fold` and this file must not second-guess it.
//! Nothing here canonicalises with `to_canonical` (`net_report.rs:857`) and
//! nothing re-tags from the address. A result that cannot be attributed keeps
//! its latency and declines to classify, and the test that pins it drives one
//! through this file rather than writing one by hand.
//!
//! # The budget, and why a round cannot hang on a silent relay
//!
//! Upstream wraps each probe in `PROBES_TIMEOUT` measured from the round's
//! start and not from the send, because the timeout sits outside the delay the
//! probe sleeps first (`reportgen.rs:391-401`) — the 400 ms rung has 2.6 s of
//! probe left and not 3 s. `probe.probe_timeout` carries that number, and
//! `Open.deadline` is the same instant for every probe in the round because it
//! comes from `Runner.start` and never from `Request.now`.
//!
//! A turn takes what came back before it gives up anything, because that is
//! the order `time::timeout` polls in: the future inside it is offered the turn
//! first, and the deadline is consulted only when it has nothing. So a reply
//! that arrived inside the budget is a measurement whatever instant the
//! caller happens to hand this one.
//!
//! What the budget ends is the waiting. A probe still open when it passes is
//! closed and the round stops expecting it, and a transport that answers for a
//! probe that is no longer open is refused rather than believed. That is the
//! whole of the cancellation rule at this layer: the wire is the unreliable
//! part, and a relay that never answers must cost the round one retired probe
//! and not a hang.
//!
//! Every probe this file opens it also closes, exactly once, with the reason —
//! `answered`, `expired` at its budget, or `canceled` because the round ended.
//! Upstream has all three: a future that answered, one the timeout dropped
//! (`reportgen.rs:391-401`), and one dropped with the set (`probes.rs:36-45`).
//! `discovery/dial_source.zig` states the same rule one layer down — every
//! stream a run starts, it closes — and a test here asserts the pairing.
//!
//! # No clock, no task, no socket
//!
//! `Request.now` is the instant. Every due time, every deadline and every
//! observation instant is that one or something derived from it, and a test
//! drives a whole round by handing it the next instant in `Turn.wake_at`. No
//! sleep, no thread, no allocator and no global — including the RNG upstream
//! draws the captive-portal relay from (`reportgen.rs:597`), which is why
//! `Request.check_relay` is the caller's to name. `InFlight` is the caller's
//! storage for the reason `probe.Results` is: a `report.ProbeResult` carries a
//! 258-byte `RelayUrl`, so returning the open set by value would copy it on
//! every turn to say nothing had changed.
//!
//! # The seam, and what is still not on it
//!
//! `Transport` is three methods for probes and three for the captive-portal
//! check. A real one is a QUIC connection to a relay for `run_probe_v4` and
//! `run_probe_v6` (`net_report.rs:826-961`) and an HTTP client for the HTTPS
//! path, which is where `transport/dial.zig` and `transport/socket.zig` come
//! in: this file opens no socket, resolves no relay URL and writes no bytes. It
//! hands the transport a relay URL, an instant and a deadline, and takes back a
//! latency. The four things missing from that are the four
//! `discovery/dial_source.zig` names for its own seam — an `std.Io`, a buffer, a
//! cancellation handle and a copy of the answer.
//!
//! # Divergences from upstream
//!
//! Three, and each is forced.
//!
//! - **A round is driven one turn at a time rather than spawned whole.**
//!   Upstream spawns every probe and drops the actor once the report is
//!   satisfied or has timed out (`net_report.rs:369-373`,
//!   `reportgen.rs:212`). Here the caller holds the clock, so the round
//!   advances when the caller advances it and `Turn.wake_at` is the instant it
//!   would decide something new — the contract `probe.Step` already offers.
//! - **An answer that cannot be attributed is an error rather than a drop.**
//!   Upstream cannot produce one, because the future that answers knows which
//!   protocol it ran. A transport written against this vtable can, and the two
//!   ways it can are why an unattributable answer is refused: filing it would
//!   put a latency in a relay's list that no probe of this round measured.
//! - **The latency is the transport's, not the clock's.** Upstream's
//!   `HttpsProbeReport` and `QadProbeReport` both carry a `Duration` and the
//!   code that builds them already holds a clock. `Open` hands over the send
//!   instant anyway, so a transport can measure without one, and so a test can
//!   substitute a relay that always takes the same time.
//!
//! ## The loop this is written for
//!
//! ```text
//! var in_flight: InFlight = .{};
//! var runner = probe.new(input, &results);
//! while (true) {
//!     const turn = try drive(runner, wire, &in_flight, .{ .now = now });
//!     runner = turn.runner;
//!     const wake = turn.wake_at orelse break; // null only once the round is over
//!     now = wake;
//! }
//! const folded = probe.fold(runner, history, now);
//! ```

const std = @import("std");
const addr = @import("../base/addr.zig");
const probe = @import("probe.zig");
const report = @import("report.zig");

/// Nanoseconds on a monotonic timeline the caller owns. `report.zig` defines
/// `Nanos` for the fold and `probe.zig` reuses it; a third definition of "an
/// instant" in one layer would only invite a conversion nobody wants.
const Nanos = report.Nanos;
const RelayUrl = addr.RelayUrl;
const SocketAddr = addr.SocketAddr;

/// What this file refuses.
///
/// `probe.PlanError` is a plan with more relays than `probe.max_relays`, which
/// `probe.plan` cannot produce and a caller can. `SendError` is a transport
/// that would not start the probe. The three arms below are this file's own.
pub const Error = probe.PlanError || SendError || error{
    /// The transport answered a probe whose task cannot hold the answer: a
    /// latency where `report.QadProbe` requires an address as well, or an
    /// address where `report.HttpsProbe` has no field for one.
    AnswerMismatch,
    /// The answer named a probe this round cannot attribute it to — one the
    /// plan does not hold, one that was never sent, or one that is already
    /// closed. Upstream cannot produce this, because the future that answers
    /// knows which probe it was spawned for.
    Unattributable,
    /// The round scheduled a captive-portal check and the caller named no
    /// relay to run it against. Upstream draws one at random from a global RNG
    /// (`reportgen.rs:597`) and nothing below `ozai.base` may reach one.
    NoCheckRelay,
};

/// Why a probe could not be started.
///
/// Both arms are about this node rather than about the relay. A relay that
/// cannot be reached is a probe that never answers, and the budget turns that
/// into a retirement; a relay that answers is the transport's business and not
/// this file's.
pub const SendError = error{
    /// The round's cancel handle fired before the probe went out. Upstream
    /// drops the whole set on shutdown and no probe of that set runs
    /// (`probes.rs:36-45`), so a probe opened after it would be one nobody is
    /// waiting for.
    Canceled,
    /// The transport has no room for another open probe. A round opens at most
    /// `probe.max_tasks` in one turn, so a transport that runs out was sized
    /// for fewer probes than a round can send.
    Full,
};

/// What a probe came back with, in the transport's own words.
///
/// Two arms and no optional address, for `report.ProbeResult`'s reason: an
/// HTTPS probe reports a latency and nothing else upstream — `HttpsProbeReport`
/// has no address field at all (`reportgen.rs:535`) — so a sender that could
/// hold one would be able to publish an address the relay never sent.
///
/// This is the transport's vocabulary and it does not leave the file. Every
/// result that reaches `probe.Runner` is a `report.ProbeResult`, built by
/// `resultFor`, and there is no second way of saying what a probe measured.
pub const Observation = union(enum) {
    /// A latency, and nothing else.
    https: Nanos,
    /// A latency, and the public address the relay saw us come from.
    qad: struct {
        latency: Nanos,
        /// The address as the relay reported it: unconverted, and carrying no
        /// family of its own. The family in the result is the family of the
        /// task, which is the whole of the module doc's attribution rule.
        reported: SocketAddr,
    },
};

/// One answer, with the probe it answers.
///
/// The transport names the probe rather than a plan index, because the probe
/// is what it opened and the index is this file's bookkeeping. `drive` turns
/// one back into the other and refuses when it cannot.
pub const Reply = struct {
    task: probe.Task,
    value: Observation,
};

/// Why a probe is no longer open.
///
/// The three states upstream has, so a transport can tell a probe that is done
/// from one that is over.
pub const Why = enum {
    /// It answered, and the answer was filed.
    answered,
    /// Its budget ran out. An answer arriving after this belongs to a probe that
    /// no longer exists.
    expired,
    /// The round ended, so the answer could not be filed: upstream drops the
    /// actor once the report is satisfied (`net_report.rs:369-373`) and the
    /// drop takes the set with it (`probes.rs:36-45`).
    canceled,
};

/// One probe the round wants sent.
pub const Open = struct {
    /// What to run, against which relay, at which rung.
    task: probe.Task,
    /// Which relay, resolved. `Task.relay` is an index into the plan's relays
    /// because the URL is 258 bytes; the transport is the one thing that needs
    /// the URL itself.
    relay: RelayUrl,
    /// The instant it went out. A transport measures `latency` from here to the
    /// `now` it polls at, so it needs no clock of its own to be told when the
    /// exchange started.
    at: Nanos,
    /// When it is given up at, measured from the round's start and not from
    /// `at`; see the module doc's budget section.
    deadline: Nanos,
};

/// The captive-portal check, as the round asks for it.
///
/// Its own request rather than a `probe.Task`, because it is not a probe: it
/// reports no latency and no address, and `probe.Runner.captive` is the only
/// field in the tree its answer ever reaches.
pub const Check = struct {
    /// The relay to ask. The caller's to name, for the RNG's reason.
    relay: RelayUrl,
    /// The instant the check went out.
    at: Nanos,
    /// When it is given up at: `CAPTIVE_PORTAL_DELAY` then
    /// `CAPTIVE_PORTAL_TIMEOUT` (`defaults.rs:30`, `:36`), both from the round's
    /// start.
    deadline: Nanos,
};

/// The wire this round runs over.
///
/// Six methods in two trios: a probe is opened, answered and closed, and the
/// check is begun, asked and ended. `poll` and `pollCheck` never wait — they
/// answer with null when nothing is ready — because a round's instants are the
/// caller's and this file has no way to wait for one.
///
/// Every `open` is matched by exactly one `close`, and every `beginCheck` by
/// exactly one `endCheck`, on every path out of `drive`.
pub const Transport = struct {
    vtable: *const VTable,
    ctx: *anyopaque,

    pub const VTable = struct {
        /// Start one probe. Called once per entry in a `Step`'s `sends`.
        open: *const fn (ctx: *anyopaque, at: Open) SendError!void,
        /// Take one answer, or null when none is ready. Never waits.
        poll: *const fn (ctx: *anyopaque, now: Nanos) ?Reply,
        /// One probe is finished with, whether it answered or not.
        close: *const fn (ctx: *anyopaque, task: probe.Task, why: Why) void,
        /// Start the captive-portal check against the relay `drive` names.
        beginCheck: *const fn (ctx: *anyopaque, at: Check) SendError!void,
        /// Whether the check has decided, or null while it has not. Never
        /// waits. `false` is an answer — no portal — and is not the same as
        /// null, which is the three states `probe.Runner.captive` covers.
        pollCheck: *const fn (ctx: *anyopaque, now: Nanos) ?bool,
        /// The check is finished with, whether it decided or not.
        endCheck: *const fn (ctx: *anyopaque, why: Why) void,
    };
};

/// The probes a round has open.
///
/// The caller's storage, like `probe.Results`: a round holds up to
/// `probe.max_tasks` and this file takes no allocator. Passed by pointer
/// because it has to survive across turns, and every turn moves it.
pub const InFlight = struct {
    /// The probe open against each plan task index, or null when none is.
    /// Entries past the plan's task count are never written.
    ///
    /// The whole task rather than a flag, because closing a probe needs to name
    /// it and `cancel` runs on the error path where nothing else is available.
    open: [probe.max_tasks]?probe.Task = @splat(null),
    /// Whether the captive-portal check has begun and not ended.
    check: bool = false,

    /// How many probes are open. This bounds the drain below: every answer
    /// accepted closes one, so the count can only go down.
    pub fn count(self: *const InFlight) usize {
        var total: usize = 0;
        for (self.open) |maybe| total += @intFromBool(maybe != null);
        return total;
    }
};

/// What one turn is run with, as a value.
///
/// Two arguments would be a pair of bare parameters nobody can tell apart at a
/// call site, and `discovery/dial_source.Request` gives the reason for naming
/// them once.
pub const Request = struct {
    /// The relay to run the captive-portal check against when the round asks
    /// for one. Null for a round that does not ask; naming one for a round that
    /// does is required, and a round that asks without one is refused.
    check_relay: ?RelayUrl = null,
    /// The current instant on the caller's timeline. Every due time, every
    /// deadline and every observation instant in a turn is this or something
    /// derived from it.
    now: Nanos,
};

/// What one turn of a round did.
///
/// The counts are what a caller driving rounds over a real wire wants and
/// cannot get from anywhere else: the transport knows what it was asked to
/// open, but only the round knows how much of that was answered and how much
/// the budget spent.
pub const Turn = struct {
    /// The runner after the turn, with every answer folded in and every send
    /// recorded.
    runner: probe.Runner,
    /// When the round next has something to wait for, or null when it is over.
    /// Never null while `runner.outcome` is null and always null when it is
    /// not, for `probe.Step`'s reason: an unfinished round always has something
    /// to wait for, because the overall deadline is always ahead of it.
    wake_at: ?Nanos,
    /// Probes this turn opened, took an answer from, and gave up at their
    /// budget.
    opened: u8,
    answered: u8,
    expired: u8,
};

/// Run one turn of a round: send what the step named, take what came back,
/// give up what did not.
///
/// `in_flight` is the round's own bookkeeping and must be the same value every
/// turn. On success every probe the round had open is closed, including the
/// ones opened on this turn; on an error `cancel` has already done the same,
/// and the round is the caller's to abandon.
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
    // Every probe this turn opens is closed on every path out of here,
    // `discovery/dial_source.zig`'s rule at this layer. The probes earlier
    // turns opened go with them, because upstream drops the whole set when the
    // actor goes away and nothing here decides that a failed turn is a round
    // worth continuing.
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

const t = std.testing;

/// Ten minutes in, on the timeline the tests hand the round. Far past every
/// probe instant, and on the same side of nothing: the runner stamps its
/// deadlines from here and the fold ages its window from there.
const start: Nanos = 600 * std.time.ns_per_s;

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

/// The positions a `Task` can occupy in a `report.Probe`.
///
/// The fake below indexes its table of answers by `@intFromEnum`, so a family
/// added to `report.Probe` has to be counted here as well or that table is
/// walked past its end. The check is where the constant and the index meet,
/// which is the only place a reader can see both.
const family_count = 3;
comptime {
    if (@typeInfo(report.Probe).@"enum".fields.len != family_count) {
        @compileError("report.Probe gained a family; this file's table is sized for three");
    }
}

/// The two families a relay can be asked for an address over.
const v4_slot = @intFromEnum(report.Probe.qad_ipv4);
const v6_slot = @intFromEnum(report.Probe.qad_ipv6);

const public_v4: SocketAddr = .{ .ip = .{ .v4 = .{ 198, 51, 100, 7 } }, .port = 41234 };
const other_v4: SocketAddr = .{ .ip = .{ .v4 = .{ 198, 51, 100, 9 } }, .port = 51234 };
const public_v6: SocketAddr = .{
    .ip = .{ .v6 = .{
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
        0,    0,    0,    0,    0, 0, 0, 0x07,
    } },
    .port = 41234,
};
const other_v6: SocketAddr = .{
    .ip = .{ .v6 = .{
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
        0,    0,    0,    0,    0, 0, 0, 0x09,
    } },
    .port = 51234,
};

/// A relay held open by the fake, so a test can see what went to the wire.
const Live = struct {
    task: probe.Task,
    at: Nanos,
    answered: bool = false,
    closed: bool = false,
};

/// A transport with relays in it, so a test drives a whole round with no
/// socket and no network.
///
/// Each relay answers after the service time it is given, measured from the
/// instant its probe went out, and reports the address it is given. Every open
/// and every close is recorded, so a test can assert what the round did to the
/// wire and not only what it folded.
const Fake = struct {
    vtable: Transport.VTable = .{
        .open = onOpen,
        .poll = onPoll,
        .close = onClose,
        .beginCheck = onBeginCheck,
        .pollCheck = onPollCheck,
        .endCheck = onEndCheck,
    },
    /// The address each relay reports per probe family, or null for a family it
    /// does not answer. Indexed by relay, then by `@intFromEnum(report.Probe)`;
    /// an HTTPS probe reads no entry, because it reports no address.
    reported: [probe.max_relays][family_count]?SocketAddr = @splat(@splat(null)),
    /// How long each relay takes to answer, from the instant its probe went
    /// out.
    think: [probe.max_relays]Nanos = @splat(0),
    /// Relays that never answer at all, whatever they were asked.
    silent: [probe.max_relays]bool = @splat(false),
    /// Answer every probe with a latency and no address, whatever it ran as.
    /// A transport bug rather than a relay: the shapes do not correspond.
    wrong_shape: bool = false,
    /// An answer this fake hands back for a probe it was never asked to
    /// open. The value rides with the task because that is what an answer
    /// is: the impostor's job is to name a probe the round did not send, and
    /// a name this fake owes no address for cannot be dressed up as one it
    /// does. The only way to reach a refusal for an answer that names
    /// something the round did not send.
    impostor: ?Reply = null,
    /// Every probe handed to `open`, in the order it was sent.
    sent: [probe.max_tasks]Live = undefined,
    sent_len: usize = 0,
    /// Why each sent probe was closed, indexed the same way.
    why: [probe.max_tasks]Why = @splat(.canceled),
    /// Every close, paired or not. A round that closes one probe twice, or
    /// closes one it never opened, shows up here as `closes > sent_len`.
    closes: usize = 0,
    /// The captive-portal check, which is not a `probe.Task` and has no ladder.
    portal: ?struct { ready: Nanos } = null,
    /// What the check answers once it is ready. Null is "never decides", which
    /// is a third state and not an answer of `false`.
    portal_answer: ?bool = null,
    /// How long the check takes, from the instant it went out.
    portal_think: Nanos = 0,
    checks: usize = 0,
    portal_why: ?Why = null,

    fn transport(self: *Fake) Transport {
        return .{ .vtable = &self.vtable, .ctx = self };
    }

    /// How many probes this fake was asked to open and then closed as `why`.
    fn closedAs(self: Fake, why: Why) usize {
        var total: usize = 0;
        for (self.why[0..self.sent_len]) |slot| {
            if (slot == why) total += 1;
        }
        return total;
    }

    /// The answer this fake has for `live` at `now`, or null while it has
    /// none: a silent relay, a probe still in flight, or a relay that
    /// reports no address for the family the probe asked about.
    fn answer(self: Fake, live: Live, now: Nanos) ?Observation {
        if (self.silent[live.task.relay]) return null;
        if (now -| live.at < self.think[live.task.relay]) return null;
        // An HTTPS probe reads no address because it reports none; the two
        // address-discovery families read one per relay, and a relay with none
        // is a relay that does not answer that family at all. The refusal is
        // here rather than in the `qad` arm so that `wrong_shape` is handed
        // only a probe this relay does answer — the mismatch these two
        // fields exist for is in the shape, not in the silence.
        const value: Observation = switch (live.task.proto) {
            .https => .{ .https = self.think[live.task.relay] },
            .qad_ipv4, .qad_ipv6 => .{ .qad = .{
                .latency = self.think[live.task.relay],
                .reported = self.reported[live.task.relay][@intFromEnum(live.task.proto)] orelse
                    return null,
            } },
        };
        if (self.wrong_shape) return .{ .https = self.think[live.task.relay] };
        return value;
    }
};

fn onOpen(ctx: *anyopaque, at: Open) SendError!void {
    const self: *Fake = @ptrCast(@alignCast(ctx));
    if (self.sent_len == probe.max_tasks) return error.Full;
    self.sent[self.sent_len] = .{ .task = at.task, .at = at.at };
    self.sent_len += 1;
}

fn onPoll(ctx: *anyopaque, now: Nanos) ?Reply {
    const self: *Fake = @ptrCast(@alignCast(ctx));
    if (self.impostor) |reply| {
        self.impostor = null;
        return reply;
    }
    for (self.sent[0..self.sent_len]) |*live| {
        if (live.answered) continue;
        const value = self.answer(live.*, now) orelse continue;
        live.answered = true;
        return .{ .task = live.task, .value = value };
    }
    return null;
}

fn onClose(ctx: *anyopaque, task: probe.Task, why: Why) void {
    const self: *Fake = @ptrCast(@alignCast(ctx));
    self.closes += 1;
    for (self.sent[0..self.sent_len], self.why[0..self.sent_len]) |*live, *slot| {
        if (!std.meta.eql(live.task, task)) continue;
        live.closed = true;
        slot.* = why;
        return;
    }
}

fn onBeginCheck(ctx: *anyopaque, at: Check) SendError!void {
    const self: *Fake = @ptrCast(@alignCast(ctx));
    if (self.portal != null) return error.Full;
    self.portal = .{ .ready = at.at +| self.portal_think };
    self.checks += 1;
}

fn onPollCheck(ctx: *anyopaque, now: Nanos) ?bool {
    const self: *Fake = @ptrCast(@alignCast(ctx));
    const portal = self.portal orelse return null;
    if (now < portal.ready) return null;
    return self.portal_answer;
}

fn onEndCheck(ctx: *anyopaque, why: Why) void {
    const self: *Fake = @ptrCast(@alignCast(ctx));
    self.portal = null;
    self.portal_why = why;
}

/// Run a round to its end, one `wake_at` at a time, and hand back the runner
/// the fold reads. The loop `drive`'s doc names, written once because five of
/// the tests below are the same round with one relay misbehaving.
fn runRound(
    wire: *Fake,
    runner: probe.Runner,
    in_flight: *InFlight,
    check_relay: ?RelayUrl,
) !probe.Runner {
    var current = runner;
    var now = start;
    while (true) {
        const turn = try drive(current, wire.transport(), in_flight, .{
            .check_relay = check_relay,
            .now = now,
        });
        current = turn.runner;
        const wake = turn.wake_at orelse return current;
        now = wake;
    }
}

/// The service times of the first three relays. A plan in these tests never
/// names a fourth, and a relay past this list is never asked anything.
fn speeds(first: Nanos, second: Nanos, third: Nanos) [probe.max_relays]Nanos {
    var times: [probe.max_relays]Nanos = @splat(0);
    times[0] = first;
    times[1] = second;
    times[2] = third;
    return times;
}

test "a round runs the probes the plan named and folds what it measured" {
    var scratch: [192]u8 = undefined;
    const relays = try relaySet(&scratch);
    var wire: Fake = .{};
    wire.reported[0][v4_slot] = public_v4;
    wire.reported[1][v4_slot] = other_v4;
    wire.reported[0][v6_slot] = public_v6;
    wire.reported[2][v6_slot] = other_v6;
    wire.think = speeds(millis(9), millis(11), millis(4));

    var results: probe.Results = .{};
    var in_flight: InFlight = .{};
    var runner = probe.new(.{
        .relays = &relays,
        .if_state = .{ .have_v4 = true, .have_v6 = true },
        .protocols = .{ .https = true, .qad_ipv4 = true, .qad_ipv6 = true },
        .now = start,
    }, &results);

    // The first turn sends both address-discovery families at all three relays:
    // a QUIC probe carries no delay and has no ladder, so six are due at once.
    const now = start;
    const first = try drive(runner, wire.transport(), &in_flight, .{ .now = now });
    try t.expectEqual(@as(usize, 6), wire.sent_len);
    try t.expectEqual(@as(u8, 6), first.opened);
    // Nothing has come back: every relay's service time is measured from the
    // send, and this is the instant they went out.
    try t.expectEqual(@as(u8, 0), first.answered);
    try t.expect(first.wake_at != null);

    runner = try runRound(&wire, first.runner, &in_flight, null);

    // This is the seam assertion: the results folded below are the ones this
    // module produced from a `Step`, not ones a test wrote by hand.
    try t.expectEqual(probe.Outcome.enough, runner.outcome.?);
    try t.expectEqual(@as(usize, 2), probe.measured(.qad_ipv4, results.slice()));
    try t.expectEqual(@as(usize, 1), probe.measured(.qad_ipv6, results.slice()));
    // The ladder was planned and never sent a rung: the round ended at the
    // first instant anything answered.
    try t.expectEqual(@as(usize, 0), probe.measured(.https, results.slice()));

    // Every probe opened was closed exactly once, and the three that were
    // still in flight when the report was satisfied went with the set.
    try t.expectEqual(wire.sent_len, wire.closes);
    // Six address-discovery probes and the first rung of every ladder, which
    // came due before the round had any answer at all.
    try t.expectEqual(@as(usize, 9), wire.sent_len);
    try t.expectEqual(@as(usize, 3), wire.closedAs(.answered));
    // The other three QUIC probes and the whole of the ladder that was in
    // flight when the report was satisfied went with the set.
    try t.expectEqual(@as(usize, 6), wire.closedAs(.canceled));

    const folded = probe.fold(runner, .{}, now);
    try t.expect(folded.udp_v4);
    try t.expect(folded.udp_v6);
    // Two addresses of the same family, and they differ, so the mapping varies
    // by destination. One address of the other family, and one compares against
    // nothing, so that one is unclassified rather than symmetric.
    try t.expectEqual(@as(?bool, true), folded.mapping_varies_by_dest_ipv4);
    try t.expectEqual(@as(?bool, null), folded.mapping_varies_by_dest_ipv6);
    try t.expectEqual(@as(?bool, true), folded.mappingVariesByDest());
    // The fastest answer of each family is the address published.
    try t.expectEqualDeep(public_v4, folded.global_v4.?);
    try t.expectEqualDeep(public_v6, folded.global_v6.?);
    try t.expectEqual(std.math.Order.eq, folded.preferred_relay.?.order(relays[0]));
}

test "an HTTPS round times its relays and claims no NAT" {
    var scratch: [192]u8 = undefined;
    const relays = try relaySet(&scratch);
    var wire: Fake = .{};
    // No address is reported anywhere, because an HTTPS probe reports none and
    // a host with no address family cannot run a QUIC probe at all.
    wire.think = speeds(millis(12), millis(9), millis(30));

    var results: probe.Results = .{};
    var in_flight: InFlight = .{};
    const runner = probe.new(.{
        .relays = &relays,
        .if_state = .{},
        .protocols = .{ .https = true, .qad_ipv4 = false, .qad_ipv6 = false },
        .now = start,
    }, &results);

    const finished = try runRound(&wire, runner, &in_flight, null);
    try t.expectEqual(probe.Outcome.enough, finished.outcome.?);
    try t.expectEqual(@as(usize, 3), probe.measured(.https, results.slice()));
    try t.expectEqual(wire.sent_len, wire.closes);

    // The asymmetry, end to end: a report folded from HTTPS probes alone times
    // every relay and knows nothing whatever about the NAT.
    const folded = probe.fold(finished, .{}, start + probe.overall_timeout);
    try t.expectEqual(millis(12), folded.relay_latency.get(relays[0]).?);
    try t.expectEqual(millis(9), folded.relay_latency.get(relays[1]).?);
    try t.expectEqual(std.math.Order.eq, folded.preferred_relay.?.order(relays[1]));
    try t.expect(!folded.hasUdp());
    try t.expect(!folded.udp_v4);
    try t.expect(!folded.udp_v6);
    try t.expect(folded.global_v4 == null);
    try t.expect(folded.mapping_varies_by_dest_ipv4 == null);
    try t.expect(folded.mappingVariesByDest() == null);
}

test "a v6 address from a v4 probe keeps its latency and declines to classify" {
    var scratch: [192]u8 = undefined;
    const relays = try relaySet(&scratch);
    var wire: Fake = .{};
    // A relay that answers a v4 probe with an IPv6 address. The sender does
    // not notice and must not: the family in the tag is the family the probe
    // ran with, and `report.fold` is where the two are compared.
    wire.reported[0][v4_slot] = public_v6;
    wire.reported[1][v4_slot] = public_v6;
    wire.silent[2] = true;
    wire.think = speeds(millis(9), millis(11), 0);

    var results: probe.Results = .{};
    var in_flight: InFlight = .{};
    const runner = probe.new(.{
        .relays = &relays,
        .if_state = .{ .have_v4 = true, .have_v6 = false },
        .protocols = .{ .https = false, .qad_ipv4 = true, .qad_ipv6 = false },
        .now = start,
    }, &results);

    const finished = try runRound(&wire, runner, &in_flight, null);
    try t.expectEqual(probe.Outcome.enough, finished.outcome.?);
    // The round counts it as a v4 answer, because upstream files it under the
    // probe's protocol before it checks the address.
    try t.expectEqual(@as(usize, 2), probe.measured(.qad_ipv4, results.slice()));

    const folded = probe.fold(finished, .{}, start + probe.overall_timeout);
    // The measurement is kept: it is in the v4 family's latency list.
    try t.expectEqual(millis(9), folded.relay_latency.get(relays[0]).?);
    try t.expectEqual(millis(11), folded.relay_latency.get(relays[1]).?);
    // And nothing else is believed: no UDP claim, no address to publish and no
    // classification, because a NAT characterised from an address of the wrong
    // family is the failure this exists to prevent.
    try t.expect(!folded.udp_v4);
    try t.expect(!folded.hasUdp());
    try t.expect(folded.global_v4 == null);
    try t.expect(folded.mapping_varies_by_dest_ipv4 == null);
    try t.expect(folded.mappingVariesByDest() == null);
}

test "a silent relay is given up at its budget and the round carries on" {
    var scratch: [192]u8 = undefined;
    const relays = try relaySet(&scratch);
    var wire: Fake = .{};
    // The third relay never answers. A round waiting on it would be a round
    // waiting on the wire, which is the failure mode worth preventing.
    wire.silent[2] = true;
    wire.think = speeds(millis(9), millis(11), 0);

    var results: probe.Results = .{};
    var in_flight: InFlight = .{};
    var runner = probe.new(.{
        .relays = &relays,
        .if_state = .{},
        .protocols = .{ .https = true, .qad_ipv4 = false, .qad_ipv6 = false },
        .now = start,
    }, &results);

    // The ladder runs against the silent relay and the round runs out of
    // budget rather than of relays: two answers cannot satisfy three.
    var now = start;
    var spent: ?Nanos = null;
    var expired: usize = 0;
    while (true) {
        const turn = try drive(runner, wire.transport(), &in_flight, .{ .now = now });
        runner = turn.runner;
        expired += turn.expired;
        if (turn.expired != 0) spent = now;
        const wake = turn.wake_at orelse break;
        now = wake;
    }

    // The budget was spent at the instant upstream spends it — from the round's
    // start and not from the send — and the round ran on to the overall
    // deadline afterwards rather than stopping there.
    try t.expectEqual(@as(?Nanos, start + probe.probe_timeout), spent);
    try t.expectEqual(@as(usize, 3), expired);
    try t.expectEqual(probe.Outcome.timeout, runner.outcome.?);
    try t.expectEqual(wire.sent_len, wire.closes);
    // Both relays that answer get every rung of their ladder answered, because
    // the round asks again on each rung and the fake takes the same time every
    // time. The whole of the silent relay's ladder is the three that expire.
    try t.expectEqual(@as(usize, 4), wire.closedAs(.answered));
    try t.expectEqual(@as(usize, 3), wire.closedAs(.expired));
    try t.expectEqual(@as(usize, 7), wire.sent_len);

    // The partial set still folds, and it is the two relays that answered.
    const folded = probe.fold(runner, .{}, now);
    try t.expectEqual(millis(9), folded.relay_latency.get(relays[0]).?);
    try t.expectEqual(millis(11), folded.relay_latency.get(relays[1]).?);
    try t.expect(folded.relay_latency.get(relays[2]) == null);
    try t.expectEqual(std.math.Order.eq, folded.preferred_relay.?.order(relays[0]));
    try t.expect(!folded.hasUdp());
}

test "an answer for a probe this round did not open is refused" {
    var scratch: [192]u8 = undefined;
    const relays = try relaySet(&scratch);
    var wire: Fake = .{};
    wire.think = speeds(millis(9), millis(11), millis(9));

    var results: probe.Results = .{};
    var in_flight: InFlight = .{};
    const runner = probe.new(.{
        .relays = &relays,
        .if_state = .{ .have_v4 = true, .have_v6 = false },
        .protocols = .{ .https = false, .qad_ipv4 = true, .qad_ipv6 = false },
        .now = start,
    }, &results);

    // A rung this round has not sent: the plan holds it and the round has not
    // reached it, so nothing about the answer can be attributed.
    wire.impostor = .{
        .task = .{ .proto = .https, .relay = 1, .attempt = 2 },
        .value = .{ .https = millis(9) },
    };
    try t.expectError(
        error.Unattributable,
        drive(runner, wire.transport(), &in_flight, .{ .now = start }),
    );

    // And a task the plan does not hold at all: this round has three relays
    // and the fourth was never one of them.
    var other: Fake = .{};
    other.think = speeds(millis(9), millis(11), millis(9));
    other.impostor = .{
        .task = .{ .proto = .qad_ipv4, .relay = 4, .attempt = 0 },
        .value = .{ .qad = .{ .latency = millis(9), .reported = public_v4 } },
    };
    try t.expectError(
        error.Unattributable,
        drive(runner, other.transport(), &in_flight, .{ .now = start }),
    );

    // Both refusals closed the probes the turn had opened, so nothing is left
    // waiting on a wire this fake will never answer.
    try t.expectEqual(wire.sent_len, wire.closes);
    try t.expectEqual(other.sent_len, other.closes);
    try t.expectEqual(@as(usize, 0), in_flight.count());
}

test "an answer whose shape its task cannot hold is refused" {
    var scratch: [192]u8 = undefined;
    const relays = try relaySet(&scratch);
    var wire: Fake = .{};
    wire.reported[0][v4_slot] = public_v4;
    wire.wrong_shape = true;

    var results: probe.Results = .{};
    var in_flight: InFlight = .{};
    const runner = probe.new(.{
        .relays = &relays,
        .if_state = .{ .have_v4 = true, .have_v6 = false },
        .protocols = .{ .https = false, .qad_ipv4 = true, .qad_ipv6 = false },
        .now = start,
    }, &results);

    // A QUIC probe answered with a latency and no address. `report.QadProbe`
    // requires an address, so there is nothing to file and the answer is
    // refused rather than recorded as a measurement with no mapping behind it.
    try t.expectError(
        error.AnswerMismatch,
        drive(runner, wire.transport(), &in_flight, .{ .now = start }),
    );
    try t.expectEqual(wire.sent_len, wire.closes);
    try t.expectEqual(@as(usize, 0), results.len);
}

test "the captive-portal check runs and its answer reaches the report" {
    var scratch: [192]u8 = undefined;
    const relays = try relaySet(&scratch);
    var wire: Fake = .{};
    wire.portal_answer = true;

    var results: probe.Results = .{};
    var in_flight: InFlight = .{};
    const runner = probe.new(.{
        .relays = &relays,
        .if_state = .{},
        .protocols = .{ .https = false, .qad_ipv4 = false, .qad_ipv6 = false },
        .round = .{ .captive_portal_check = true },
        .now = start,
    }, &results);

    // Nothing can be probed on a host with no address family and no HTTPS, so
    // the check is the only thing a round has left to do.
    const first = try drive(runner, wire.transport(), &in_flight, .{
        .check_relay = relays[0],
        .now = start,
    });
    try t.expectEqual(@as(usize, 0), wire.checks);
    try t.expectEqual(start + probe.captive_portal_delay, first.wake_at.?);

    const checked = try drive(first.runner, wire.transport(), &in_flight, .{
        .check_relay = relays[0],
        .now = first.wake_at.?,
    });
    try t.expectEqual(@as(usize, 1), wire.checks);
    try t.expectEqual(Why.answered, wire.portal_why.?);
    // The answer is the only thing `Report.captive_portal` is ever set from,
    // and `isFull` reads it to decide whether repeating the last round's
    // probes is the wrong move.
    try t.expectEqual(@as(?bool, true), probe.fold(
        checked.runner,
        .{},
        first.wake_at.?,
    ).captive_portal);
}

test "a check that never decides is given up and the portal stays unknown" {
    var scratch: [192]u8 = undefined;
    const relays = try relaySet(&scratch);
    var wire: Fake = .{};
    wire.portal_answer = null;
    wire.portal_think = 10 * std.time.ns_per_s;

    var results: probe.Results = .{};
    var in_flight: InFlight = .{};
    const runner = probe.new(.{
        .relays = &relays,
        .if_state = .{},
        .protocols = .{ .https = false, .qad_ipv4 = false, .qad_ipv6 = false },
        .round = .{ .captive_portal_check = true },
        .now = start,
    }, &results);

    const finished = try runRound(&wire, runner, &in_flight, relays[0]);
    try t.expectEqual(@as(usize, 1), wire.checks);
    // Its own timeout, not the round's: the check is `CAPTIVE_PORTAL_DELAY`
    // then `CAPTIVE_PORTAL_TIMEOUT`, both from the round's start.
    try t.expectEqual(Why.expired, wire.portal_why.?);
    // Null and not false: a portal nobody managed to rule on has not been
    // ruled out, and reporting `false` would claim the opposite.
    try t.expect(probe.fold(finished, .{}, start + probe.overall_timeout).captive_portal == null);
}

test "a round that asks for a check with no relay named is refused" {
    var scratch: [192]u8 = undefined;
    const relays = try relaySet(&scratch);
    var wire: Fake = .{};

    var results: probe.Results = .{};
    var in_flight: InFlight = .{};
    const runner = probe.new(.{
        .relays = &relays,
        .if_state = .{},
        .protocols = .{ .https = false, .qad_ipv4 = false, .qad_ipv6 = false },
        .round = .{ .captive_portal_check = true },
        .now = start,
    }, &results);

    const first = try drive(runner, wire.transport(), &in_flight, .{ .now = start });
    try t.expectError(
        error.NoCheckRelay,
        drive(first.runner, wire.transport(), &in_flight, .{
            .now = first.wake_at.?,
        }),
    );
    try t.expectEqual(@as(usize, 0), wire.checks);
}
