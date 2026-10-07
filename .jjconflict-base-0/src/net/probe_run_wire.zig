//! The vocabulary of the seam a probe round runs over.
//!
//! `probe_run.zig` is the facade for the module that makes a planned round
//! into traffic; this half holds what the two sides agree on — what a transport
//! is handed, what it hands back, and what it owes. A probe is opened, answered
//! and closed; the captive-portal check is begun, asked and ended. None of it
//! is the turn that drives it, which is `probe_run_turn.zig`.
//!
//! The module doc `probe_run.zig` carries is the argument for the whole file
//! and is not repeated here.

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
    /// A latency in `Nanos` — nanoseconds on the round's own monotonic
    /// timeline — and nothing else. It is the transport's figure, measured
    /// from `Open.at` to the `now` it polls at, which is what lets a
    /// transport measure without a clock of its own; see the module doc's
    /// last divergence.
    https: Nanos,
    /// A latency, and the public address the relay saw us come from.
    qad: struct {
        /// The round trip in `Nanos`, nanoseconds on the round's own monotonic
        /// timeline and the very same figure the `https` arm carries alone.
        ///
        /// The transport's, not the clock's: `Open.at` hands over the send
        /// instant so a transport can measure without one of its own, and a
        /// test substitutes a relay that always takes the same time. Nothing
        /// in this file compares it against anything, and nothing here is
        /// checked against a deadline — `resultFor` files it as
        /// `report.QadProbe.latency` and `report.HttpsProbe.latency`, which is
        /// where its units are defined.
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
    /// Which relay, resolved: `Task.relay` names the plan's relay by index
    /// because the plan holds each URL once, and the transport is the one
    /// thing that needs the URL itself. `Open` owns this copy by value and
    /// borrows nothing, so the plan a caller may rewrite afterwards cannot
    /// change which relay a transport has already been handed.
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
/// A successful `open` is matched by one `close`, and a successful
/// `beginCheck` by one `endCheck`, when answered, expired or cancelled.
/// Unfinished probes survive a successful turn in `InFlight`.
pub const Transport = struct {
    /// Borrowed with `ctx` until all probes and the check are retired.
    vtable: *const VTable,
    /// Backend state; its address must remain stable until cleanup finishes.
    ctx: *anyopaque,

    /// All callbacks run synchronously on the caller's thread. Arguments are
    /// borrowed for the callback; callbacks must not reenter `drive` or `cancel`
    /// for this round. An acquisition error leaves no resource to retire.
    pub const VTable = struct {
        /// Start one probe. On error, no matching `close` will be called.
        open: *const fn (ctx: *anyopaque, at: Open) SendError!void,
        /// Take one answer, or null when none is ready. Never waits.
        poll: *const fn (ctx: *anyopaque, now: Nanos) ?Reply,
        /// Retire one successfully opened probe exactly once.
        close: *const fn (ctx: *anyopaque, task: probe.Task, why: Why) void,
        /// Start the relay check. On error, no matching `endCheck` is owed.
        beginCheck: *const fn (ctx: *anyopaque, at: Check) SendError!void,
        /// Whether the check has decided, or null while it has not. Never
        /// waits. `false` is an answer — no portal — and is not the same as
        /// null, which is the three states `probe.Runner.captive` covers.
        pollCheck: *const fn (ctx: *anyopaque, now: Nanos) ?bool,
        /// Retire the successfully begun check exactly once.
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
