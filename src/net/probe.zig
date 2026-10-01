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

const std = @import("std");
const addr = @import("../base/addr.zig");
const report = @import("report.zig");

const RelayUrl = addr.RelayUrl;
const SocketAddr = addr.SocketAddr;

/// The protocol that timed a probe.
///
/// Upstream's `Probe`, imported rather than redeclared. A second enum with the
/// same three names would let a `report.Probe` and a `probe.Probe` be
/// confused at a call site, and the fold files latencies by that enum, so the
/// mistake would be a misfiled measurement rather than a compile error.
const Probe = report.Probe;

/// Nanoseconds on a monotonic timeline the caller owns. `report.zig` defines it
/// for the fold, and two definitions of "an instant" in one layer would only
/// invite a conversion nobody wants.
const Nanos = report.Nanos;

/// One probe's result, in the type the fold consumes. Upstream's
/// `ProbeReport`.
const ProbeResult = report.ProbeResult;

/// One QAD result. Upstream's `QadProbeReport` — `{relay, latency, addr}` — plus
/// the instant `report.zig` adds to every probe.
const QadProbe = report.QadProbe;

/// The interval between rungs of the HTTPS ladder. Upstream's
/// `DEFAULT_INITIAL_RETRANSMIT`, `probes.rs:15`.
pub const initial_retransmit: Nanos = 100 * std.time.ns_per_ms;

/// How long after the round starts the first HTTPS probe is due. Upstream's
/// `HTTPS_OFFSET`, `probes.rs:18`.
///
/// Two hundred milliseconds rather than zero is upstream's choice and it is
/// reproduced exactly: a QAD probe carries no delay, so it has the first word,
/// and a round that is satisfied inside the offset sends no rung at all —
/// `step` asks whether it is finished before it sends anything.
pub const https_offset: Nanos = 200 * std.time.ns_per_ms;

/// How many rungs each relay's HTTPS ladder has. Upstream's
/// `for attempt in 0u32..3`, `probes.rs:104`.
pub const https_attempts: u8 = 3;

/// What one probe has, measured from the start of the round. Upstream's
/// `PROBES_TIMEOUT`, `defaults.rs:23`.
///
/// From the round and not from the send, because upstream wraps the delay in
/// the same `time::timeout` as the probe: `proto.run(delay, ...)` sleeps first
/// and the timeout is outside it (`reportgen.rs:391-401`). The 400 ms rung
/// therefore has 2.6 s of probe left, not 3 s.
pub const probe_timeout: Nanos = 3 * std.time.ns_per_s;

/// What the whole round has. Upstream's `OVERALL_REPORT_TIMEOUT`,
/// `defaults.rs:17`.
pub const overall_timeout: Nanos = 5 * std.time.ns_per_s;

/// How many relays one round probes. Upstream's `MAX_RELAYS`,
/// `net_report.rs:497`.
///
/// The same bound `report.zig` applies per family (`report.max_relays`), so a
/// result past it could not be recorded by the fold anyway, and truncating the
/// HTTPS plan to match costs nothing the fold could have used.
pub const max_relays: usize = 5;

/// How many relays count as enough. Upstream's `ENOUGH_ENDPOINTS`,
/// `net_report.rs:133`.
pub const enough_endpoints: usize = 3;

/// How often a round is a full one whatever the last round found. Upstream's
/// `FULL_REPORT_INTERVAL`, `net_report.rs:132`.
pub const full_report_interval: Nanos = 5 * 60 * std.time.ns_per_s;

/// How long the captive-portal check waits before it starts. Upstream's
/// `CAPTIVE_PORTAL_DELAY`, `defaults.rs:30`.
pub const captive_portal_delay: Nanos = 200 * std.time.ns_per_ms;

/// How long the captive-portal check has once it starts. Upstream's
/// `CAPTIVE_PORTAL_TIMEOUT`, `defaults.rs:36`, which that file requires to sit
/// below `OVERALL_REPORT_TIMEOUT - CAPTIVE_PORTAL_DELAY`.
pub const captive_portal_timeout: Nanos = 2 * std.time.ns_per_s;

/// How many probe families there are.
///
/// The per-family masks below are indexed by `@intFromEnum`, so a family added
/// to `report.Probe` upstream has to be counted here as well or they index
/// past their ends.
const family_count = 3;
comptime {
    if (@typeInfo(Probe).@"enum".fields.len != family_count) {
        @compileError("report.Probe gained a family; this file's masks are sized for three");
    }
}

/// The most tasks one round can hold: both QAD families at every relay, and the
/// whole HTTPS ladder at every one.
pub const max_tasks = max_relays * (2 + https_attempts);

/// The most results one round can hold: the two observations a live QUIC
/// connection may already have, plus one answer per task.
pub const max_results = 2 + max_tasks;

/// The two address-discovery families as a value of their own.
///
/// Upstream has `run_probe_v4` and `run_probe_v6` and no shared type, so a
/// shared function takes a `Probe` and this module has to answer "and if it is
/// HTTPS" for an answer the type should have made impossible. An enum of two
/// has no such answer.
pub const QadFamily = enum { v4, v6 };

/// The probe that measures `family`. Upstream's two functions, one value.
pub fn probeFor(family: QadFamily) Probe {
    return switch (family) {
        .v4 => .qad_ipv4,
        .v6 => .qad_ipv6,
    };
}

/// The result a QAD task produced.
///
/// `family` is the family the probe **ran** with, never the family of the
/// address that came back. Upstream builds the payload inside the probe's own
/// future (`net_report.rs:855-859`, against the arm that carries no address at
/// `reportgen.rs:535`) and checks the family only in `Report::update`
/// (`report.rs:81-84`), so tagging from the address here would make the case
/// unrepresentable and delete the check `report.fold` exists to make.
///
/// The address is not canonicalised here either. Upstream calls
/// `to_canonical` on what the relay reported (`net_report.rs:857`), turning an
/// IPv4-mapped IPv6 address into an IPv4 one. That is the caller's choice, and
/// handing over a mapped address unconverted is a case for the fold's check
/// rather than a loss of it.
pub fn qadResult(
    family: QadFamily,
    relay: RelayUrl,
    instant: Nanos,
    latency: Nanos,
    reported: SocketAddr,
) ProbeResult {
    const probe: QadProbe = .{
        .relay = relay,
        .instant = instant,
        .latency = latency,
        .addr = reported,
    };
    return switch (family) {
        .v4 => .{ .qad_ipv4 = probe },
        .v6 => .{ .qad_ipv6 = probe },
    };
}

/// Which probe families a node can run at all.
///
/// Upstream's `BTreeSet<Probe>`, which `Options::as_protocols` fills in
/// (`options.rs:62-76`): a QAD family is in it when a QUIC client exists and
/// that family is enabled, HTTPS when the user left `https_probes` on. A
/// family outside the set is not probed at all, so a browser build and a QUIC
/// build plan differently without either being a special case.
pub const Protocols = struct {
    https: bool = true,
    qad_ipv4: bool = false,
    qad_ipv6: bool = false,

    pub fn includes(self: Protocols, probe: Probe) bool {
        return switch (probe) {
            .https => self.https,
            .qad_ipv4 => self.qad_ipv4,
            .qad_ipv6 => self.qad_ipv6,
        };
    }
};

/// What the host's interfaces can do. Upstream's `IfStateDetails`.
pub const IfState = struct {
    have_v4: bool = false,
    have_v6: bool = false,
};

/// What a round starts from.
///
/// Upstream's `Reports` — `last`, `prev`, `last_full`, `next_full` — plus the
/// QAD connections' current reports and `get_report`'s `is_major` argument.
/// `prev` is absent because `report.History` already carries it, and the
/// preferred-relay hysteresis reads it rather than the probe layer.
pub const Round = struct {
    /// The last report folded. `Reports::last`, and null on the first round.
    ///
    /// Borrowed, not held: `report.Report` is four kilobytes of inline latency
    /// table, and `isFull` is asked on every round. The caller owns it and
    /// keeps it alive for as long as the round names it, the same rule
    /// `PunchState` follows for its candidate slices.
    last: ?*const report.Report = null,
    /// When the last full round started. `Reports::last_full`.
    last_full: Nanos = 0,
    /// `Reports::next_full`, true until one full round has run.
    next_full: bool = true,
    /// The latest address a still-open IPv4 address-discovery connection has
    /// seen. `QadConns::current_v4`.
    carried_v4: ?QadProbe = null,
    /// `QadConns::current_v6`.
    carried_v6: ?QadProbe = null,
    /// `get_report`'s `is_major`: the caller wants a report on its own terms
    /// rather than on the schedule.
    is_major: bool = false,
    /// Upstream's `NetReportConfig::captive_portal_check`.
    captive_portal_check: bool = false,
};

/// Whether this round probes everything. Upstream's `do_full`,
/// `net_report.rs:304-325`.
///
/// A full round drops the last report and closes the QUIC connections that
/// hold the carried observations (`net_report.rs:456-459`), so nothing survives
/// it and every family is measured from zero. An incremental round keeps both
/// and probes only what is missing.
pub fn isFull(round: Round, now: Nanos) bool {
    if (round.is_major or round.next_full) return true;
    // Saturating: a `last_full` after `now` is a clock that went backwards, and
    // such a round is not old.
    if (now -| round.last_full > full_report_interval) return true;
    // A portal that swallowed the last round's UDP is the one combination that
    // makes repeating those probes the wrong move: the round before said "no
    // UDP" *and* "there is a portal", so the answer will be the same.
    if (round.last) |last| {
        if (!last.hasUdp() and last.captive_portal == @as(?bool, true)) return true;
    }
    return false;
}

/// Everything a plan is a function of.
pub const Input = struct {
    /// The relays, in the order the relay map yields them. Truncated to
    /// `max_relays`; see `plan`.
    relays: []const RelayUrl,
    if_state: IfState = .{},
    protocols: Protocols = .{},
    round: Round = .{},
    /// The current instant on the caller's timeline.
    now: Nanos = 0,
};

/// Index into a plan's task list. `u8`, because `max_tasks` is 25.
pub const TaskIndex = u8;

// Every fixed-size array in this file is indexed by a narrow integer, and each
// bound is proved here, where the constant and the index type meet: a constant
// that outgrew its index turns `sent[index]`, `answers[task.relay]` and
// `items[self.len]` into three ways to walk off an array, and no use site could
// see it coming.
comptime {
    if (max_relays > std.math.maxInt(TaskIndex)) {
        @compileError("a relay index is wider than `Task.relay`");
    }
    if (max_tasks > std.math.maxInt(TaskIndex)) {
        @compileError("a task count is wider than `TaskIndex`");
    }
    if (max_results > std.math.maxInt(u8)) {
        @compileError("a results length is wider than `Results.len`");
    }
}

/// One scheduled probe: what to run, against which relay, and where in its
/// ladder it sits. Upstream's `(delay, relay)` pair inside a `ProbeSet`.
pub const Task = struct {
    proto: Probe,
    /// Index into `Plan.relays`, not a `RelayUrl`: the URL is 258 bytes and a
    /// round holds up to `max_tasks` of them, so a plan of URLs is six
    /// kilobytes of copying to say which relay a probe is for.
    relay: u8,
    /// Zero-based position in the ladder. A QAD probe is rung 0 of a one-rung
    /// ladder — `spawn_qad_probes` spawns it with no delay and no retry
    /// (`net_report.rs:513`) — and an HTTPS probe is one of three.
    attempt: u8,
};

/// The order families are planned in within one relay.
///
/// Upstream's spawn loop puts the v4 probe before the v6 one for each relay
/// (`net_report.rs:506-539`) and the HTTPS plan is a separate structure, so
/// nothing upstream depends on this order. It is data rather than a literal in
/// the walk so that `taskCount` and `taskAt` cannot disagree about it.
const family_order = [family_count]Probe{ .qad_ipv4, .qad_ipv6, .https };

/// How many rungs a family's ladder has. Upstream builds the HTTPS set with
/// `for attempt in 0u32..3` (`probes.rs:104`) and spawns one QAD probe per
/// relay with nothing to retry.
fn ladder(proto: Probe) u8 {
    return switch (proto) {
        .https => https_attempts,
        .qad_ipv4, .qad_ipv6 => 1,
    };
}

/// When in the round `attempt` of `proto` becomes due, relative to its start.
///
/// Upstream's ladder is `HTTPS_OFFSET + DEFAULT_INITIAL_RETRANSMIT * attempt`
/// (`probes.rs:105`), so 200 ms, 300 ms, 400 ms. A QAD probe has no ladder:
/// `spawn_qad_probes` spawns it immediately and wraps the future in
/// `PROBES_TIMEOUT` (`net_report.rs:513-539`).
pub fn delayFor(proto: Probe, attempt: u8) Nanos {
    return switch (proto) {
        .https => https_offset + initial_retransmit * attempt,
        .qad_ipv4, .qad_ipv6 => 0,
    };
}

comptime {
    // The `due >= probe_deadline` case in `step` and `wakeAt` does not exist
    // because it cannot happen, and this is what proves it: the longest delay
    // in the ladder is 400 ms and the budget is 3 s, so a rung is always
    // sendable once it is due. If a future ladder ever outgrew the budget,
    // every rung past the budget would need to be retired unsent and this is
    // the line that says so.
    if (delayFor(.https, https_attempts - 1) >= probe_timeout) {
        @compileError("the HTTPS ladder has outgrown the probe budget");
    }
    // The check's own timeout has to fit inside the round, which is what
    // `defaults.rs:35-36` requires of upstream's numbers.
    if (captive_portal_delay + captive_portal_timeout >= overall_timeout) {
        @compileError("the captive-portal check does not fit inside the round");
    }
}

/// The one answer a plan cannot give.
///
/// A `Plan` is a public struct, so a caller can build one with a literal and
/// nothing in the type stops its relay list from being longer than the arrays
/// below. Every function that turns a relay count into an index refuses one
/// rather than wrapping it, and this is that one answer: a relay past the
/// bound is an index past the end of `Runner.answers` and of a turn's `sends`.
pub const PlanError = error{
    RelaysTooMany,
};

/// One round's plan: which relays, which families, and nothing else.
pub const Plan = struct {
    /// The relays, truncated to `max_relays` by `plan`. Borrowed; see
    /// `Round.last`. Nothing in the type keeps that bound, so every reader of
    /// this field's length proves it for itself; see `relayCount`.
    relays: []const RelayUrl,
    /// `do_full`. See `isFull`.
    full: bool,
    /// `min(relays.len, enough_endpoints)`. Upstream's `enough_relays`, in
    /// upstream's own `usize`: the ceiling is applied by the `min` that
    /// computes this one value and nothing narrows it afterwards, so there is
    /// no bound here to prove. The truncation to `max_relays` does not touch
    /// it: `max_relays` is 5 and `enough_endpoints` is 3, so
    /// `min(min(len, 5), 3)` and `min(len, 3)` are the same number for every
    /// `len`.
    enough_relays: usize,
    /// Which families this round runs, by `@intFromEnum`.
    ///
    /// A family that cannot run is absent rather than present and skipped:
    /// upstream's `add_if_enabled` drops the whole `ProbeSet` when its protocol
    /// is not enabled (`probes.rs:137-141`), and `spawn_qad_probes` never
    /// spawns a family the host lacks.
    run: [family_count]bool,
    /// Whether a captive-portal check is scheduled. Upstream schedules one when
    /// `captive_portal_check` holds and there is no last report
    /// (`reportgen.rs:287`).
    captive: bool,

    /// How many relays this plan holds, in the width every index below is
    /// spelled with.
    ///
    /// The bound is proved here, at the only place a relay length is read, and
    /// proved against `max_relays` rather than against the width of the
    /// integer: a length a `u8` holds is not a length this module indexes by.
    /// The cast arm is the one this file cannot reach — `max_relays` is 5, and
    /// the guard above fails the build if it is ever not — while the comparison
    /// is the arm a caller holding a struct literal can reach.
    fn relayCount(self: Plan) PlanError!TaskIndex {
        const count: TaskIndex = std.math.cast(TaskIndex, self.relays.len) orelse
            return error.RelaysTooMany;
        if (@as(usize, count) > max_relays) return error.RelaysTooMany;
        return count;
    }

    /// How many tasks this plan holds.
    ///
    /// The product is narrowed by a cast that carries its own refusal rather
    /// than by a bound this file asserts: `stride` is at most
    /// `2 + https_attempts` and the relay count is at most `max_relays`, so the
    /// two together are `max_tasks`, which the guard above keeps inside a
    /// `TaskIndex`. A ladder that outgrew it is refused rather than wrapped
    /// into a count that quietly drops work.
    pub fn taskCount(self: Plan) PlanError!TaskIndex {
        const relays = try self.relayCount();
        const tasks = @as(usize, relays) * self.stride();
        return std.math.cast(TaskIndex, tasks) orelse error.RelaysTooMany;
    }

    /// The most tasks one relay contributes: one rung per QAD family and
    /// `https_attempts` of ladder for HTTPS, so at most `2 + https_attempts`.
    /// That is the bound `max_tasks` is built from, and it is what makes the
    /// product in `taskCount` fit.
    fn stride(self: Plan) TaskIndex {
        var count: TaskIndex = 0;
        for (family_order) |proto| {
            if (self.run[@intFromEnum(proto)]) count += ladder(proto);
        }
        return count;
    }

    /// The task at `index`, in plan order: for each relay, its QAD probes and
    /// then its HTTPS ladder.
    pub fn taskAt(self: Plan, index: TaskIndex) PlanError!?Task {
        const relays = try self.relayCount();
        var seen: TaskIndex = 0;
        // Both counters are declared rather than borrowed: a range loop's
        // index is a `usize`, so the relay and rung counts would have to be
        // cast back into a `u8` on the way into a `Task` — and a plan wide
        // enough to need that cast is the one `relayCount` refuses rather
        // than truncates.
        var relay: TaskIndex = 0;
        while (relay < relays) : (relay += 1) {
            for (family_order) |proto| {
                if (!self.run[@intFromEnum(proto)]) continue;
                var attempt: TaskIndex = 0;
                while (attempt < ladder(proto)) : (attempt += 1) {
                    if (seen == index) {
                        return .{
                            .proto = proto,
                            .relay = relay,
                            .attempt = attempt,
                        };
                    }
                    seen += 1;
                }
            }
        }
        return null;
    }
};

/// The probes one round will run, given everything it is a function of.
///
/// Pure and total. The same `Input` always produces the same plan, and an
/// input describing a node that can do nothing produces an empty one rather
/// than an error: the relays are already configured, and upstream's answer to
/// "is this relay suitable" is not to probe it.
///
/// The relay list is truncated here and nowhere else, which is what makes a
/// plan this function returns one the rest of the file can index. A plan a
/// caller assembles by hand is not, and is refused; see `PlanError`.
pub fn plan(input: Input) Plan {
    const full = isFull(input.round, input.now);
    // A full round closes the QUIC connections (`net_report.rs:456-459`), so a
    // carried observation survives only an incremental round.
    const carried_v4 = if (full) null else input.round.carried_v4;
    const carried_v6 = if (full) null else input.round.carried_v6;

    // `net_report.rs:478-479`. The two families are asked different questions
    // and the difference is upstream's: v4 needs a probe exactly when it has
    // no observation, while v6 needs one when its observation and the host's
    // capability *disagree*. A host that has just lost IPv6 therefore stops
    // being asked for a v6 answer it could not get, and one that has just
    // gained it is asked at once.
    const needs_v4 = carried_v4 == null;
    const needs_v6 = input.if_state.have_v6 != (carried_v6 != null);

    var run: [family_count]bool = .{ false, false, false };
    run[@intFromEnum(Probe.qad_ipv4)] = input.protocols.includes(.qad_ipv4) and
        input.if_state.have_v4 and needs_v4;
    run[@intFromEnum(Probe.qad_ipv6)] = input.protocols.includes(.qad_ipv6) and
        input.if_state.have_v6 and needs_v6;
    // `ProbePlan::with_last_report` (`probes.rs:117-128`): a round with a last
    // report that measured something schedules no HTTPS probe at all, and only
    // falls back to the initial plan when there is nothing to inherit.
    // Upstream leaves that path empty beside a `TODO: is this good?`, and it
    // is reproduced as written: the QAD path is what fills an incremental
    // round, and an HTTPS probe measures no address, so there is nothing for
    // one to add.
    run[@intFromEnum(Probe.https)] = input.protocols.includes(.https) and
        (input.round.last == null or isEmpty(&input.round.last.?.relay_latency));

    return .{
        .relays = input.relays[0..@min(input.relays.len, max_relays)],
        .full = full,
        // The min is the whole proof: a length of any size lands on one of
        // three values, and nothing narrows the result on the way out.
        .enough_relays = @min(input.relays.len, enough_endpoints),
        .run = run,
        .captive = input.round.captive_portal_check and input.round.last == null,
    };
}

/// Whether a report has measured anything. Upstream's
/// `RelayLatencies::is_empty` (`report.rs:196`), which `report.zig` has no
/// reason to expose and `probe.zig` needs exactly once.
///
/// By pointer: `RelayLatencies` is three inline arrays of five `RelayUrl`, and
/// a `Report` holds one by value, so a by-value parameter here would copy a
/// kilobyte to answer a yes-or-no question.
fn isEmpty(latencies: *const report.RelayLatencies) bool {
    var iterator = latencies.iter();
    return iterator.next() == null;
}

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

/// A round that is not full: nothing asks for one and the age rule does not
/// force it. Every test of an incremental rule needs one of these first,
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

test "a QAD result is tagged with the probe its family names" {
    var scratch: [64]u8 = undefined;
    const relay = try namedRelay(&scratch, 0);
    // The attribution rule in one line: the tag comes from the family the
    // probe *ran* with, and `report.fold` checks the reported address against
    // that tag. If the two enums ever stopped agreeing, every latency would be
    // filed against a family that never ran and no address would be checked.
    for ([_]QadFamily{ .v4, .v6 }) |family| {
        const tagged = qadResult(family, relay, test_start, millis(9), public_v4);
        try t.expectEqual(probeFor(family), tagged.kind());
    }
}

test "a full round probes every relay over QUIC and ladders every relay over HTTPS" {
    var scratch: [192]u8 = undefined;
    const relays = try relaySet(&scratch);
    const planned = plan(.{
        .relays = &relays,
        .if_state = .{ .have_v4 = true, .have_v6 = true },
        .protocols = .{ .https = true, .qad_ipv4 = true, .qad_ipv6 = true },
        .now = test_start,
    });
    try t.expect(planned.full);
    try t.expectEqual(@as(usize, enough_endpoints), planned.enough_relays);
    try t.expectEqual(@as(u8, 3 * 5), try planned.taskCount());

    const want = [_]Task{
        .{ .proto = .qad_ipv4, .relay = 0, .attempt = 0 },
        .{ .proto = .qad_ipv6, .relay = 0, .attempt = 0 },
        .{ .proto = .https, .relay = 0, .attempt = 0 },
        .{ .proto = .https, .relay = 0, .attempt = 1 },
        .{ .proto = .https, .relay = 0, .attempt = 2 },
        .{ .proto = .qad_ipv4, .relay = 1, .attempt = 0 },
        .{ .proto = .qad_ipv6, .relay = 1, .attempt = 0 },
        .{ .proto = .https, .relay = 1, .attempt = 0 },
        .{ .proto = .https, .relay = 1, .attempt = 1 },
        .{ .proto = .https, .relay = 1, .attempt = 2 },
        .{ .proto = .qad_ipv4, .relay = 2, .attempt = 0 },
        .{ .proto = .qad_ipv6, .relay = 2, .attempt = 0 },
        .{ .proto = .https, .relay = 2, .attempt = 0 },
        .{ .proto = .https, .relay = 2, .attempt = 1 },
        .{ .proto = .https, .relay = 2, .attempt = 2 },
    };
    for (want, 0..) |task, index| {
        try t.expectEqualDeep(task, (try planned.taskAt(@intCast(index))).?);
    }
    try t.expect((try planned.taskAt(@intCast(want.len))) == null);
}

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

test "a v6 probe is planned only when the host's capability and its answer disagree" {
    var scratch: [192]u8 = undefined;
    const relays = try relaySet(&scratch);
    const carried: QadProbe = .{
        .relay = relays[0],
        .instant = test_start - millis(1),
        .latency = millis(10),
        .addr = public_v6,
    };
    const base: Input = .{
        .relays = &relays,
        .if_state = .{ .have_v4 = false, .have_v6 = true },
        .protocols = .{ .https = false, .qad_ipv4 = false, .qad_ipv6 = true },
        .now = test_start,
    };

    // A v6 host with no v6 answer needs one.
    try t.expect(plan(base).run[@intFromEnum(Probe.qad_ipv6)]);
    // A v6 host whose live connection already has one does not: this is the
    // whole point of the connection carrying it.
    var incremental = base;
    incremental.round = freshRound();
    incremental.round.carried_v6 = carried;
    try t.expect(!plan(incremental).run[@intFromEnum(Probe.qad_ipv6)]);
    // A host that has just lost IPv6 with an answer still in hand is the case
    // the two families' rules differ on: v6's rule says "probe", and the
    // capability gate upstream applies to both families (`net_report.rs:523`)
    // says it cannot. Nothing is sent, and the answer stays in the report.
    var lost = base;
    lost.if_state.have_v6 = false;
    lost.round = freshRound();
    lost.round.carried_v6 = carried;
    try t.expect(!plan(lost).run[@intFromEnum(Probe.qad_ipv6)]);
    // v4 has no such clause: it is asked only whether it has an answer.
    var v4: Input = .{
        .relays = &relays,
        .if_state = .{ .have_v4 = true, .have_v6 = false },
        .protocols = .{ .https = false, .qad_ipv4 = true, .qad_ipv6 = false },
        .now = test_start,
    };
    try t.expect(plan(v4).run[@intFromEnum(Probe.qad_ipv4)]);
    v4.round = freshRound();
    v4.round.carried_v4 = .{
        .relay = relays[1],
        .instant = test_start - millis(1),
        .latency = millis(10),
        .addr = public_v4,
    };
    try t.expect(!plan(v4).run[@intFromEnum(Probe.qad_ipv4)]);
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

test "a round is full on the first one, on request, every five minutes, and after a portal" {
    var last: report.Report = .{};
    try t.expect(isFull(.{}, test_start));
    try t.expect(isFull(.{ .next_full = false, .is_major = true }, test_start));
    try t.expect(!isFull(.{
        .next_full = false,
        .last_full = test_start - full_report_interval,
    }, test_start));
    try t.expect(!isFull(.{
        .next_full = false,
        .last_full = test_start - full_report_interval + 1,
    }, test_start));
    // A clock that went backwards is not a stale round.
    try t.expect(!isFull(.{ .next_full = false, .last_full = test_start + 1 }, test_start));

    last.udp_v4 = true;
    try t.expect(!isFull(.{
        .next_full = false,
        .last_full = test_start,
        .last = &last,
    }, test_start));
    // No UDP and a portal: the same probes will be refused the same way, so
    // the round goes back to probing everything.
    last.udp_v4 = false;
    last.captive_portal = true;
    try t.expect(isFull(.{
        .next_full = false,
        .last_full = test_start,
        .last = &last,
    }, test_start));
    // A portal with no UDP is not a reason; a report that has neither is.
    last.captive_portal = false;
    try t.expect(!isFull(.{
        .next_full = false,
        .last_full = test_start,
        .last = &last,
    }, test_start));
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
