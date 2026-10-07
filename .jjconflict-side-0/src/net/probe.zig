//! Net report probes: the decision half.
//!
//! `net/report.zig` is a finished fold — probe results and an instant in, a
//! report out — and nothing in the project has ever produced a probe to feed
//! it. This module is the half that is missing: which probes to run, against
//! which relays, at which instants, what to do with each answer as it arrives,
//! and when to stop.
//!
//! # Upstream
//!
//! Captured 2026-09-30 at n0-computer/iroh commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8 (`main`, the `iroh` 1.3.0 crate as
//! published) — the same pin `report.zig` and `net/holepunch.zig` carry. Every
//! rule below is one of that tree's:
//!
//! - `Probe`, `ProbeSet`, `ProbePlan::initial`, `ProbePlan::with_last_report`
//!   and the three-rung HTTPS ladder from `iroh/src/net_report/probes.rs`:
//!   `DEFAULT_INITIAL_RETRANSMIT` at :15, `HTTPS_OFFSET` at :18,
//!   `for attempt in 0u32..3` at :104-106, the set's cancellation contract at
//!   :36-45, `with_last_report` at :117-128, and `add_if_enabled` at :137-141.
//! - The QAD fan-out and the round's shape from `iroh/src/net_report.rs`:
//!   `FULL_REPORT_INTERVAL` and `ENOUGH_ENDPOINTS` at :132-133,
//!   `QadConns::current_v4` and `current_v6` at :175-203, the `do_full`
//!   decision at :304-325, the enough-relays abort at :554,
//!   `have_enough_reports` at :661-746, `MAX_RELAYS` at :497, the spawn loop
//!   at :504-540, `needs_v4_probe` and `needs_v6_probe` at :478-479, the
//!   `to_canonical` on a reported address at :857, and `run_probe_v4` /
//!   `run_probe_v6` at :826-961.
//! - `ProbeReport`, `QadProbeReport`, `HttpsProbeReport`, `ProbeFinished` and
//!   the captive-portal task from `iroh/src/net_report/reportgen.rs`: the
//!   per-probe budget wrapped around the delay at :391-401, the
//!   `num_probes == 0 && have_udp` cancellation at :256-264, the check's
//!   own construction at :280-349, the preferred-relay-then-draw choice at
//!   :586-600, and the `OVERALL_REPORT_TIMEOUT` that ends the actor at :212.
//! - The timeouts from `iroh/src/net_report/defaults.rs`: `PROBES_TIMEOUT` at
//!   :23, `CAPTIVE_PORTAL_DELAY` at :30, `CAPTIVE_PORTAL_TIMEOUT` at :36, and
//!   `OVERALL_REPORT_TIMEOUT` at :17.
//! - `Options::as_protocols` from `iroh/src/net_report/options.rs:62-76`, and
//!   `Report::update` from `iroh/src/net_report/report.rs:68-130`, which is
//!   where a QAD answer's address family is checked against its probe.
//!
//! # The asymmetry, and where it lives
//!
//! Upstream has two kinds of probe and they are not interchangeable. A QAD
//! probe opens a QUIC connection to a relay and reports the public address the
//! relay saw us come from, so it can classify a NAT. An HTTPS probe is an
//! empty GET to the relay's probe path and reports a latency and nothing else,
//! so it never can. `report.ProbeResult` makes that unrepresentable rather
//! than a null check: it is a union whose `https` arm has no address field at
//! all, and whose two QAD arms both carry a required `addr`. This module
//! builds results of that one type and adds no second way of saying it.
//!
//! What the module does own is the *attribution* of a QAD answer. Upstream
//! builds the payload inside the probe's own future, so the family in the tag
//! is the family the probe **ran** with and never the family of the address
//! that came back: a relay answering a v4 probe with an IPv6 address produces
//! a v4 result carrying a v6 address, `Report::update` warns and returns
//! before setting `udp_v4`, and the latency it already recorded stands. The
//! check lives in `report.fold`; nothing here adds a second one, and the test
//! that pins it is the one that runs an address of the wrong family through
//! this module and folds it.
//!
//! # There is no socket here
//!
//! A probe upstream is a future over a QUIC connection or an HTTP client, and
//! a "probe" here is a value: a protocol, a relay, a position in a retry
//! ladder. `step` says which values are due; the caller opens whatever they
//! name and hands the answers back through `observe`. Nothing below reads a
//! clock — `now` is an argument to `new` and to `step` — spawns a task, holds
//! a socket, or takes an allocator. Every buffer is the caller's: `Results` is
//! borrowed rather than owned because a `report.ProbeResult` carries a
//! `RelayUrl`, and a state machine that returned its results by value would
//! copy the whole set on every turn to say nothing had changed.
//!
//! # Divergences from upstream
//!
//! Four. Three are forced by a rule this project holds and upstream does not;
//! the fourth is a rule upstream has written down and its own numbers make
//! unreachable.
//!
//! - **The relay to run a captive-portal check against is an argument.**
//!   Upstream draws one at random from a global RNG
//!   (`reportgen.rs:597`, `urls[i].clone()`). Nothing below `ozai.base` may
//!   reach a global RNG, so the caller names the relay and this module plans
//!   against it. Everything else about the check is upstream's numbers.
//! - **The check's own cancellation is not implemented, because under the
//!   ported numbers it cannot fire.** Upstream cancels it once every regular
//!   probe has finished and a QUIC answer has proved UDP works
//!   (`reportgen.rs:256-264`). Every regular probe is wrapped in
//!   `PROBES_TIMEOUT` from the start of the round, so the last of them cannot
//!   finish before 3 s; the check is `CAPTIVE_PORTAL_DELAY` then
//!   `CAPTIVE_PORTAL_TIMEOUT` around it, 200 ms then 2 s, and is therefore
//!   always cancelled by its own timeout at 2.2 s first. Upstream's cancel is
//!   a wake that finds the task already gone. The other end of the rule is
//!   implemented and is the one that decides anything: a round that is already
//!   good enough never starts the check.
//! - **A relay's retry ladder is dead once one of its rungs has answered.**
//!   `ProbeSet`'s own doc says so (`probes.rs:40`), and upstream realises it
//!   by dropping the whole actor the moment the report is good enough
//!   (`net_report.rs:369-373`), so nothing upstream observes the difference.
//!   Here it saves the sends.
//! - **The round stops at the overall deadline or at enough answers**, and
//!   there is no third exit. Upstream's actor also stops on a shutdown token;
//!   that is a fact about the runtime, not about a probe, and the caller drops
//!   the runner instead.
//!
//! # What lives where
//!
//! This file is the facade and holds the tests that drive both halves. The two
//! bodies live elsewhere, and the plan half keeps its own tests:
//!
//! - `probe_plan.zig` — what a round will run: the constants, `Protocols`,
//!   `IfState`, `Round`, `Input`, `Task` and `Plan`, and `plan` itself, plus
//!   the tests of that half.
//! - `probe_turn.zig` — the turn machine: `Results`, `Runner`, `Step`, and
//!   `new`, `step`, `observe` and the `fold` that hands the round to the report.
//!
//! Every declaration the facade published before the split is re-exported here,
//! so a caller outside `src/net/` is unchanged.

const std = @import("std");
const addr = @import("../base/addr.zig");
const report = @import("report.zig");

const plan_mod = @import("probe_plan.zig");
const turn_mod = @import("probe_turn.zig");

const RelayUrl = addr.RelayUrl;
const Probe = report.Probe;
const ProbeResult = report.ProbeResult;

// The plan half.
pub const initial_retransmit = plan_mod.initial_retransmit;
pub const https_offset = plan_mod.https_offset;
pub const https_attempts = plan_mod.https_attempts;
pub const probe_timeout = plan_mod.probe_timeout;
pub const overall_timeout = plan_mod.overall_timeout;
pub const max_relays = plan_mod.max_relays;
pub const enough_endpoints = plan_mod.enough_endpoints;
pub const full_report_interval = plan_mod.full_report_interval;
pub const captive_portal_delay = plan_mod.captive_portal_delay;
pub const captive_portal_timeout = plan_mod.captive_portal_timeout;
pub const max_tasks = plan_mod.max_tasks;
pub const max_results = plan_mod.max_results;
pub const QadFamily = plan_mod.QadFamily;
pub const probeFor = plan_mod.probeFor;
pub const qadResult = plan_mod.qadResult;
pub const Protocols = plan_mod.Protocols;
pub const IfState = plan_mod.IfState;
pub const Round = plan_mod.Round;
pub const isFull = plan_mod.isFull;
pub const Input = plan_mod.Input;
pub const TaskIndex = plan_mod.TaskIndex;
pub const Task = plan_mod.Task;
pub const delayFor = plan_mod.delayFor;
pub const PlanError = plan_mod.PlanError;
pub const Plan = plan_mod.Plan;
pub const plan = plan_mod.plan;

// The turn half.
pub const measured = turn_mod.measured;
pub const Quota = turn_mod.Quota;
pub const haveEnough = turn_mod.haveEnough;
pub const Results = turn_mod.Results;
pub const Outcome = turn_mod.Outcome;
pub const Runner = turn_mod.Runner;
pub const Step = turn_mod.Step;
pub const new = turn_mod.new;
pub const step = turn_mod.step;
pub const observe = turn_mod.observe;
pub const fold = turn_mod.fold;

// Widened in `probe_turn.zig` for the test below, which reads the bit a family
// occupies in a per-relay answer mask.
const bit = turn_mod.bit;

const t = std.testing;

// File-scope aliases of the fixtures in `probe_plan.zig`, which owns them and
// the tests that use them; the tests left in this facade keep their own text.
const test_start = plan_mod.test_start;
const millis = plan_mod.millis;
const namedRelay = plan_mod.namedRelay;
const relaySet = plan_mod.relaySet;
const freshRound = plan_mod.freshRound;
const public_v4 = plan_mod.public_v4;
const other_v4 = plan_mod.other_v4;
const public_v6 = plan_mod.public_v6;

/// `out.len` relay URLs, one 64-byte host each, so a relay list longer than
/// `max_relays` can be built at all.
fn fillRelays(out: []RelayUrl, scratch: []u8) !void {
    for (out, 0..) |*relay, index| {
        relay.* = try namedRelay(scratch[index * 64 ..][0..64], index);
    }
}

// The plan half's own tests live in `probe_plan.zig`; the ones below drive `probe_turn.zig`.
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

test "an incremental round ends at one answer per family, a full one at two" {
    var scratch: [192]u8 = undefined;
    const relays = try relaySet(&scratch);
    const dual: IfState = .{ .have_v4 = true, .have_v6 = true };
    const enough: usize = enough_endpoints;

    const v4_a = qadResult(.v4, relays[0], test_start, millis(9), public_v4);
    const v4_b = qadResult(.v4, relays[1], test_start, millis(9), other_v4);
    const v6_a = qadResult(.v6, relays[0], test_start, millis(9), public_v6);
    const v6_b = qadResult(.v6, relays[1], test_start, millis(9), public_v6);

    // Incremental: one of each family, in either order, and one alone is not
    // enough for a host that has both.
    try t.expect(!haveEnough(&.{v4_a}, dual, false, enough));
    try t.expect(!haveEnough(&.{v6_a}, dual, false, enough));
    try t.expect(haveEnough(&.{ v4_a, v6_a }, dual, false, enough));
    try t.expect(haveEnough(&.{ v6_a, v4_a }, dual, false, enough));
    // Full: the same two are not. The two admitted shapes are two of one
    // family *and* one of the other, and two of one with none of the other is
    // not a shape — the other family is what proves the other family works.
    try t.expect(!haveEnough(&.{ v4_a, v6_a }, dual, true, enough));
    try t.expect(!haveEnough(&.{ v4_a, v4_b }, dual, true, enough));
    try t.expect(haveEnough(&.{ v4_a, v4_b, v6_a }, dual, true, enough));
    try t.expect(haveEnough(&.{ v4_a, v6_a, v6_b }, dual, true, enough));
    // A host with one family needs two of it on a full round and one on an
    // incremental one.
    const v4_only: IfState = .{ .have_v4 = true, .have_v6 = false };
    try t.expect(haveEnough(&.{v4_a}, v4_only, false, enough));
    try t.expect(!haveEnough(&.{v4_a}, v4_only, true, enough));
    try t.expect(haveEnough(&.{ v4_a, v4_b }, v4_only, true, enough));
    // A host with neither never gets a QUIC answer, so only HTTPS can end it.
    const no_addr: IfState = .{};
    try t.expect(!haveEnough(&.{ v4_a, v4_b }, no_addr, true, enough));
    try t.expect(haveEnough(&.{
        .{ .https = .{ .relay = relays[0], .instant = test_start, .latency = millis(9) } },
        .{ .https = .{ .relay = relays[1], .instant = test_start, .latency = millis(9) } },
        .{ .https = .{ .relay = relays[2], .instant = test_start, .latency = millis(9) } },
    }, no_addr, true, enough));
    // One answer per relay is the HTTPS arm, and it is enough whatever else is
    // missing.
    try t.expect(haveEnough(&.{
        .{ .https = .{ .relay = relays[0], .instant = test_start, .latency = millis(9) } },
    }, dual, true, 1));
    try t.expect(!haveEnough(&.{
        .{ .https = .{ .relay = relays[0], .instant = test_start, .latency = millis(9) } },
    }, dual, true, 2));
}

test "two answers to one relay count once, as upstream's map does" {
    var scratch: [192]u8 = undefined;
    const relays = try relaySet(&scratch);
    const results = [_]ProbeResult{
        .{ .https = .{ .relay = relays[0], .instant = test_start, .latency = millis(40) } },
        .{ .https = .{ .relay = relays[0], .instant = test_start, .latency = millis(12) } },
        .{ .https = .{ .relay = relays[1], .instant = test_start, .latency = millis(30) } },
        qadResult(.v4, relays[0], test_start, millis(9), public_v4),
    };
    try t.expectEqual(@as(usize, 2), measured(.https, &results));
    try t.expectEqual(@as(usize, 1), measured(.qad_ipv4, &results));
    try t.expectEqual(@as(usize, 0), measured(.qad_ipv6, &results));
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

// `probe_turn.zig` is the only half they drive, which is why they stay here.
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

// `probe_turn.zig` is the only half they drive, which is why they stay here.
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
