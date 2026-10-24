//! Planning a probe round: which probes, against which relays, at which
//! instants.
//!
//! This is the pure half of the module `probe.zig` is the facade for. Every
//! function here is a total function of its arguments: the same `Input` always
//! produces the same `Plan`, an input describing a node that can do nothing
//! produces an empty plan rather than an error, and nothing reads a clock —
//! `now` is an argument to `isFull` and reaches `plan` through `Input`.
//!
//! The module doc `probe.zig` carries is the argument for all three halves and
//! is not repeated here.
//!
//! The tests of this half live here rather than in the facade, beside the code
//! they exercise; the facade keeps the ones that drive `probe_turn.zig`.

const std = @import("std");
const addr = @import("../base/addr.zig");
const report = @import("report.zig");
const t = std.testing;

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
    if (@typeInfo(Probe).@"enum".field_names.len != family_count) {
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

    /// Whether this set plans a probe of that family at all.
    ///
    /// The whole of `Options::as_protocols` in one call, and the only test the
    /// plan applies to a family: a probe outside the set is never scheduled, so
    /// a browser build and a QUIC build differ here and nowhere else. `false`
    /// is not "disabled for this round" — it is "this node does not have the
    /// transport for it", which is why a `false` QAD family also suppresses the
    /// classification that only a QAD answer could produce.
    ///
    /// By value, like `ProbeResult.relay`: these are three bools, and a pointer
    /// would only decide nothing.
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
    /// Index into `Plan.relays`. The plan owns each URL once; repeated probes
    /// name that entry instead of copying its whole value into every task.
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
            if (self.run[@backingInt(proto)]) count += ladder(proto);
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
                if (!self.run[@backingInt(proto)]) continue;
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
    run[@backingInt(Probe.qad_ipv4)] = input.protocols.includes(.qad_ipv4) and
        input.if_state.have_v4 and needs_v4;
    run[@backingInt(Probe.qad_ipv6)] = input.protocols.includes(.qad_ipv6) and
        input.if_state.have_v6 and needs_v6;
    // `ProbePlan::with_last_report` (`probes.rs:117-128`): a round with a last
    // report that measured something schedules no HTTPS probe at all, and only
    // falls back to the initial plan when there is nothing to inherit.
    // Upstream leaves that path empty beside a `TODO: is this good?`, and it
    // is reproduced as written: the QAD path is what fills an incremental
    // round, and an HTTPS probe measures no address, so there is nothing for
    // one to add.
    run[@backingInt(Probe.https)] = input.protocols.includes(.https) and
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

/// A minute in, on the timeline the tests hand to the runner. Five minutes is
/// `full_report_interval`, so a round stamped with it is incremental and one
/// left at zero is a full round for being stale.
pub const test_start: Nanos = 600 * std.time.ns_per_s;

pub fn millis(n: u64) Nanos {
    return n * std.time.ns_per_ms;
}

/// A relay URL rendered into `scratch`. The host is `<n>.example.`, so the
/// URLs sort by index and the fold's relay ordering is predictable.
pub fn namedRelay(scratch: []u8, index: usize) !RelayUrl {
    return RelayUrl.parse(try std.fmt.bufPrint(scratch, "https://{d}.example./", .{index}));
}

/// Three relays, in relay-map order.
pub fn relaySet(scratch: []u8) ![3]RelayUrl {
    return .{
        try namedRelay(scratch[0..64], 0),
        try namedRelay(scratch[64..128], 1),
        try namedRelay(scratch[128..192], 2),
    };
}

/// A round that is not full: nothing asks for one and the age rule does not
/// force it. Every test of an incremental rule needs one of these first,
/// because `isFull` is what upstream's incremental rules are defined against.
pub fn freshRound() Round {
    return .{ .next_full = false, .last_full = test_start };
}

pub const public_v4: SocketAddr = .{ .ip = .{ .v4 = .{ 198, 51, 100, 7 } }, .port = 41234 };
pub const other_v4: SocketAddr = .{ .ip = .{ .v4 = .{ 198, 51, 100, 9 } }, .port = 51234 };
pub const public_v6: SocketAddr = .{
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
    try t.expect(plan(base).run[@backingInt(Probe.qad_ipv6)]);
    // A v6 host whose live connection already has one does not: this is the
    // whole point of the connection carrying it.
    var incremental = base;
    incremental.round = freshRound();
    incremental.round.carried_v6 = carried;
    try t.expect(!plan(incremental).run[@backingInt(Probe.qad_ipv6)]);
    // A host that has just lost IPv6 with an answer still in hand is the case
    // the two families' rules differ on: v6's rule says "probe", and the
    // capability gate upstream applies to both families (`net_report.rs:523`)
    // says it cannot. Nothing is sent, and the answer stays in the report.
    var lost = base;
    lost.if_state.have_v6 = false;
    lost.round = freshRound();
    lost.round.carried_v6 = carried;
    try t.expect(!plan(lost).run[@backingInt(Probe.qad_ipv6)]);
    // v4 has no such clause: it is asked only whether it has an answer.
    var v4: Input = .{
        .relays = &relays,
        .if_state = .{ .have_v4 = true, .have_v6 = false },
        .protocols = .{ .https = false, .qad_ipv4 = true, .qad_ipv6 = false },
        .now = test_start,
    };
    try t.expect(plan(v4).run[@backingInt(Probe.qad_ipv4)]);
    v4.round = freshRound();
    v4.round.carried_v4 = .{
        .relay = relays[1],
        .instant = test_start - millis(1),
        .latency = millis(10),
        .addr = public_v4,
    };
    try t.expect(!plan(v4).run[@backingInt(Probe.qad_ipv4)]);
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
