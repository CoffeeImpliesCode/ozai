//! The live `probe_run.Transport`: an HTTPS probe is a real GET, and a QUIC
//! address-discovery probe is the caller's.
//!
//! `probe_run.zig` names six seam methods, opens nothing, and its module doc
//! says so: "It hands the transport a relay URL, an instant and a deadline,
//! and takes back a latency." This file answers all six, and the two probe
//! families it drives are deliberately not symmetric.
//!
//! # The layering decides what "live" can mean here
//!
//! `docs/ARCHITECTURE.md` draws `ozai.net` *below* `ozai.discovery` and
//! `ozai.transport`, and the tree agrees: `src/relay/client.zig` imports
//! `net/report.zig`, and no file under `src/net/` imports either. So a file
//! here may not open a descriptor and may not reach the TLS client in
//! `discovery/tls_client.zig` — the same inversion `discovery/lookup_live.zig`
//! refuses for the same reason.
//!
//! What is therefore live here is everything **above** the descriptor: the
//! request that goes out, the response that comes back, the budget that bounds
//! them, the two measurements, and the rule that a relay which cannot be
//! reached is silence. The connection itself is `Stream`, a parameter, and the
//! caller above `net` is the one that owns a socket, a trust bundle and the
//! node's entropy.
//!
//! **No caller wires one up yet.** That is a gap in the node, not a gap in this
//! file, and `discovery/lookup_live.zig` states the same fact about its own
//! live arm in the same words.
//!
//! # Two arms, and why they differ
//!
//! - **QAD is injected.** A QUIC address-discovery round needs the node's
//!   identity, its bridge and a per-family socket, none of which `net` owns and
//!   none of which a probe round can supply. So the QAD half of the seam is the
//!   caller's, as `Qad`.
//! - **HTTPS is live here.** A GET needs none of that: no identity, no
//!   bridge, no per-family socket — a URL, a path and a deadline, all three of
//!   which the round already hands over. Nothing about it belongs to the node
//!   rather than to the relay, so nothing about it belongs to another layer.
//!
//! # Two latencies with two owners, and why they cannot share one clock
//!
//! The QAD round's latency is **the round's**, measured from `Open.at` to the
//! `now` the answer is polled at, and the injected arm computes it. The HTTPS
//! GET's latency is **its own**, measured with `std.Io.Clock.awake` across the
//! exchange, and this file computes it.
//!
//! They cannot share one clock because the round's clock does not move while
//! this file is inside `open`. `Request.now` is the caller's and the caller is
//! blocked: the GET starts and finishes between two reads of the same instant,
//! so a latency taken from the round's clock is exactly zero for every HTTPS
//! probe — and zero is filed as the best relay in `report.HttpsProbe`. The
//! QAD arm has the opposite shape: its answer arrives on a *later* turn, so
//! `now - at` is a real span, and an `Io` reading inside `poll` would measure
//! the poll rather than the exchange.
//!
//! # The budget bounds a GET because it is spent, not compared
//!
//! `Open.deadline` is `runner.start + probe.probe_timeout`, measured from the
//! round's start, and a TCP retransmit runs for minutes. So every blocking call
//! this file makes is handed `stdBudget(Open)` **minus whatever earlier GETs in
//! the same round already cost**, and the remainder is recomputed from
//! `std.Io.Clock.awake` before each call rather than taken once. A call that
//! would start with nothing left is never made.
//!
//! Two budgets, not one. The first is the probe's own: `deadline - at`, so a
//! probe opened at the 400 ms rung of the ladder has 2.6 s of probe left rather
//! than 3 s, which is `reportgen.rs:391-401`'s own arithmetic. The second is
//! the round's: `probe.probe_timeout` less the time this `Live` has already
//! spent, so a round of fifteen GETs cannot spend fifteen budgets. Both are
//! charged whatever the GET did, refusal included, because a relay that
//! swallowed a retransmit cost exactly as much as one that answered.
//!
//! One `Live` serves one round. The spent budget is never reset, because the
//! seam tells a transport nothing about when a round ends — the last `close`
//! could be the last probe of one round or the first retirement of the next —
//! and guessing there would be a hidden reset.
//!
//! # A relay that cannot be reached is silence
//!
//! `SendError` has two arms and both are about this node: `Canceled` and
//! `Full`. There is no arm for "the relay did not answer", and that is the
//! design, not an omission. A probe round is a survey of several relays, and an
//! unreachable relay is a **fact about the world** — this relay cannot be
//! reached from here — which is what the round exists to learn. Turning it into
//! an error would abandon the whole round over one relay, so the relays that do
//! answer would never be measured either. So every refusal below — an
//! unreachable host, a refused connection, a broken stream, a short write, a
//! peer that half-closes without a status line — opens nothing, answers
//! nothing, and returns `void`. The probe stays open, the budget retires it,
//! `close` is called with `.expired`, and `Turn.expired` counts it. This is
//! `probe_run_wire.SendError`'s own rule ("a relay that cannot be reached is a
//! probe that never answers, and the budget turns that into a retirement") and
//! `discovery/dns_live.zig`'s ("timeout and empty are different outcomes").
//!
//! The one refusal that is **not** silence is a QAD task with no `Qad` armed:
//! that is a caller that planned a probe family it did not wire, which is a
//! bug here rather than a fact about a relay, and it is `error.Full`.
//!
//! # Purity
//!
//!
//! # Divergences from upstream, and what is unpinned
//!
//! Two, both forced by the layer above.
//!
//! - **A round is driven one turn at a time and this file does the I/O inside
//!   `open`.** Upstream spawns a probe and lets the future answer; the seam
//!   here is synchronous, so an HTTPS GET completes inside the call that starts
//!   it and `poll` only reports what it left. That is why the GET's latency is
//!   not on the round's clock.
//! - **The captive-portal verdict is the caller's.** No captured upstream
//!   bytes exist on this machine, so what a relay's answer to the check means —
//!   which status is a portal and which is a clean network — is not reproduced
//!   here. `Check.verdict` is that decision as a parameter, and a verdict of
//!   null leaves the check undecided, which is the state the check's own
//!   timeout retires and `Report.captive_portal` reports as "not looked for".
//!   What would close this is one captured upstream check response. Nothing
//!   here claims interoperability.
//!
//! The same holds for `Options.probe_path` and `Check.path`: the request
//! target on a relay is the relay's own layout and is named here rather than
//! guessed.
//!
//! # Where the tests stand on
//!
//! The doubles the tests below drive live in
//! `probe_live_test_support.zig`: a scripted HTTPS connection, a scripted
//! address-discovery arm, and the round loop that runs them. They are a
//! separate file because they are a different responsibility from the seam
//! they exercise, and because they are half this file's size.
//! `discovery/lookup_test_support.zig` is the same arrangement for the lookup
//! seam. They stand in for the layer above `net` — a socket, a trust bundle,
//! the node's entropy — so nothing here proves that layer exists; the gap is
//! named above and is the same one `discovery/lookup_live.zig` names for its
//! own live arm.

const std = @import("std");
const addr = @import("../base/addr.zig");
const probe = @import("probe.zig");
const probe_run = @import("probe_run.zig");
const report = @import("report.zig");

const Nanos = report.Nanos;
const RelayUrl = addr.RelayUrl;
const SendError = probe_run.SendError;
const Why = probe_run.Why;
const support = @import("probe_live_test_support.zig");

/// How many HTTPS probes one round can have open at once: every relay's whole
/// ladder. A QAD task never reaches this table, because the QAD arm keeps its
/// own open set.
const slot_count = probe.max_relays * probe.https_attempts;

/// The longest request line and header block this file writes: a request target
/// and an RFC 1035 maximum name, plus the two fields and their spacing. No
/// field beyond those two is sent, because every one of them is optional and a
/// field that is not sent cannot be wrong.
const max_request_length: usize = 512;

/// The end of an HTTP header block. RFC 9112 §2.2, and the only framing this
/// file needs: a probe reads a status line and stops, and the body is not read
/// at all.
const header_end = "\r\n\r\n";

/// The request, which is a method, a target, a version, a host and nothing
/// else. `Connection` is not sent and no keep-alive is asked for, because the
/// connection is closed when the status line has been read.
const request_text = "GET {s} HTTP/1.1\r\nHost: {s}\r\nAccept: */*\r\n\r\n";

/// Everything an injected connection can refuse with.
///
/// Three arms, and every one of them becomes silence above. The set is named
/// rather than `anyerror` because a caller supplying a `Stream` has to handle
/// exactly these three, and because a caller reading a log of a silent relay
/// wants to know which of them it was.
pub const Error = error{
    /// No connection: the relay could not be reached, or the connection to it
    /// was refused before a byte went out.
    Unreachable,
    /// The exchange broke under bytes already sent.
    Broken,
    /// A write that did not take everything it was given.
    /// `transport/tcp.zig`'s own rule is that a short count is a success, so a
    /// connection that cannot resume one must refuse it rather than let a
    /// caller read past it.
    ShortWrite,
    /// Nothing of the probe's budget is left, so the call this file was about to
    /// make would be one past it.
    NoBudget,
    /// The request does not fit `max_request_length`.
    RequestTooLong,
    /// No status line: the peer half-closed, or sent no blank line inside the
    /// caller's response buffer.
    NoResponse,
};

/// One connection to one relay, as the four calls an HTTPS probe makes.
///
/// A relay URL rather than a `SocketAddr` because this file does not resolve
/// names: `base/relay.zig`'s `RelayUrl.socketAddr` refuses a name outright and
/// `discovery/dns_live.zig` is the module that has an answer to it. The
/// connection's owner decides what to hand over.
///
/// **Every call runs synchronously and returns before the GET completes**, and
/// `timeout_ms` is the caller's budget, not advice: an implementation must
/// reach the kernel with it, or the module doc's claim about retransmits is
/// not true of this seam at all. `open` and `close` bracket one connection and
/// a failed `open` owes no `close`.
pub const Stream = struct {
    /// Borrowed with `ctx` for as long as this value is used.
    vtable: *const VTable,
    /// The connection factory: whatever the layer above `net` owns.
    ctx: *anyopaque,

    pub const VTable = struct {
        open: *const fn (ctx: *anyopaque, relay: RelayUrl, timeout_ms: i32) Error!void,
        write: *const fn (ctx: *anyopaque, bytes: []const u8) Error!void,
        /// Take up to `into.len` bytes, waiting at most `timeout_ms`, and say
        /// how many there were. **A zero is the peer's half-close and is not
        /// an error**, which is `transport/tcp.zig`'s own spelling of end of
        /// file.
        read: *const fn (ctx: *anyopaque, into: []u8, timeout_ms: i32) Error!usize,
        close: *const fn (ctx: *anyopaque) void,
    };
};

/// The QAD arm, injected.
///
/// The three methods of `probe_run.Transport`'s first trio and no more: the
/// captive-portal check is an HTTPS request, and it is answered above. The
/// arm's obligations are the seam's: an `open` that succeeds is matched by one
/// `close`, `poll` never waits, and a `Reply` names a task of **this** round —
/// an answer for a task the round did not send is refused by `probe_run` as
/// `error.Unattributable`, which abandons the round.
pub const Qad = struct {
    vtable: *const VTable,
    ctx: *anyopaque,

    pub const VTable = struct {
        open: *const fn (ctx: *anyopaque, at: probe_run.Open) SendError!void,
        poll: *const fn (ctx: *anyopaque, now: Nanos) ?probe_run.Reply,
        close: *const fn (ctx: *anyopaque, task: probe.Task, why: Why) void,
    };
};

/// What a relay's answer to the captive-portal check means.
///
/// `null` is "not decided", which is a third state and not an answer of
/// `false`: `Report.captive_portal` is an `?bool` because a portal nobody
/// managed to rule on has not been ruled out.
pub const Verdict = *const fn (status: u16) ?bool;

/// The captive-portal check's own configuration, which is an HTTPS GET like
/// any other and differs only in what its answer is read to mean.
pub const Check = struct {
    /// The request target on the relay. The relay's own layout, so the
    /// caller's; see the module doc's last section.
    path: []const u8,
    /// How to read the status the relay sent.
    verdict: Verdict,
};

/// Everything one `Live` runs over.
pub const Options = struct {
    /// Where an HTTPS GET goes.
    stream: Stream,
    /// The caller's buffer a response's header block is read into. A relay
    /// that sends a longer one is silence; nothing here reads a body.
    response: []u8,
    /// The request target an HTTPS probe asks for.
    probe_path: []const u8,
    /// The captive-portal check's own two fields.
    check: Check,
    /// The QAD arm, or null on a node that runs no address-discovery probe.
    /// A QAD task with none armed is `error.Full`; see the module doc.
    qad: ?Qad = null,
};

/// One open HTTPS probe.
const Slot = struct {
    taken: bool = false,
    task: probe.Task = undefined,
    answer: ?probe_run.Observation = null,
};

// The slot index is built from the relay's own ladder position, so the table
// is checked against the constants it is derived from here rather than at a use
// site that cannot see either of them.
comptime {
    const widest = (probe.max_relays - 1) * probe.https_attempts + (probe.https_attempts - 1);
    if (widest >= slot_count) {
        @compileError("the slot table is smaller than one ladder per relay");
    }
}

/// The slot an HTTPS task occupies: its relay's ladder position.
///
/// **The relay index is not optional.** A table indexed by the rung alone
/// aliases every relay's first rung with every other's, and `close` for the
/// second would free the first's slot and leave the first's probe unretired —
/// two relays' probes sharing one slot with no way to tell which is which.
/// `task.relay` is bounded by `probe.plan`'s truncation to `max_relays`, and
/// `drive` indexes the plan's relays with it before this is reached.
fn slotOf(task: probe.Task) usize {
    return @as(usize, task.relay) * probe.https_attempts + task.attempt;
}

/// One `probe_run.Transport` over real traffic.
///
/// One value serves one round, for the spent-budget reason in the module doc.
/// Keep this value at its original address: the vtable handed out by
/// `transport` points into it.
pub const Live = struct {
    vtable: probe_run.Transport.VTable = .{
        .open = onOpen,
        .poll = onPoll,
        .close = onClose,
        .beginCheck = onBeginCheck,
        .pollCheck = onPollCheck,
        .endCheck = onEndCheck,
    },
    /// The runtime, and the only clock. See the module doc's purity section.
    io: std.Io,
    options: Options,
    /// Set by `stop` and read at every seam entry. Terminal, because a stop
    /// this file can honour is a decision not to start anything, and there is
    /// no wait of its own in flight to end: an exchange finishes inside the
    /// call that started it.
    stopped: std.atomic.Value(bool) = .init(false),
    open_probes: [slot_count]Slot = @splat(Slot{}),
    /// Whether a captive-portal check has begun and not ended.
    checking: bool = false,
    /// What the check decided, or null while it has not.
    check_answer: ?bool = null,
    /// What every GET in this round has cost so far, in nanoseconds, refusals
    /// included. Never reset; see the module doc.
    spent: Nanos = 0,

    pub fn init(io: std.Io, options: Options) Live {
        std.debug.assert(options.response.len > 0);
        return .{ .io = io, .options = options };
    }

    /// The seam `probe_run.drive` and `probe_run.cancel` are handed.
    pub fn transport(self: *Live) probe_run.Transport {
        return .{ .vtable = &self.vtable, .ctx = self };
    }

    /// Stop this transport: refuse every later `open` and `beginCheck`.
    pub fn stop(self: *Live) void {
        self.stopped.store(true, .release);
    }
};

fn onOpen(ctx: *anyopaque, at: probe_run.Open) SendError!void {
    const self: *Live = @ptrCast(@alignCast(ctx));
    if (self.stopped.load(.acquire)) return error.Canceled;
    switch (at.task.proto) {
        .qad_ipv4, .qad_ipv6 => {
            const qad = self.options.qad orelse return error.Full;
            return qad.vtable.open(qad.ctx, at);
        },
        .https => {},
    }
    const slot = claim(self, at.task) orelse return error.Full;
    answerHttps(self, slot, at);
}

fn onPoll(ctx: *anyopaque, now: Nanos) ?probe_run.Reply {
    const self: *Live = @ptrCast(@alignCast(ctx));
    if (self.options.qad) |qad| {
        if (qad.vtable.poll(qad.ctx, now)) |reply| return reply;
    }
    for (&self.open_probes) |*slot| {
        const answer = slot.answer orelse continue;
        slot.answer = null;
        return .{ .task = slot.task, .value = answer };
    }
    return null;
}

fn onClose(ctx: *anyopaque, task: probe.Task, why: Why) void {
    const self: *Live = @ptrCast(@alignCast(ctx));
    switch (task.proto) {
        .qad_ipv4, .qad_ipv6 => {
            if (self.options.qad) |qad| qad.vtable.close(qad.ctx, task, why);
        },
        .https => release(self, task),
    }
}

fn onBeginCheck(ctx: *anyopaque, at: probe_run.Check) SendError!void {
    const self: *Live = @ptrCast(@alignCast(ctx));
    if (self.stopped.load(.acquire)) return error.Canceled;
    if (self.checking) return error.Full;
    self.checking = true;
    answerCheck(self, at);
}

fn onPollCheck(ctx: *anyopaque, _: Nanos) ?bool {
    const self: *Live = @ptrCast(@alignCast(ctx));
    return self.check_answer;
}

fn onEndCheck(ctx: *anyopaque, _: Why) void {
    const self: *Live = @ptrCast(@alignCast(ctx));
    self.checking = false;
    self.check_answer = null;
}

/// Run one GET and file whatever it came to.
///
/// Every refusal is a `return`: the probe stays open with no answer, and the
/// budget retires it. See the module doc's refusal section.
fn answerHttps(self: *Live, slot: *Slot, at: probe_run.Open) void {
    const started = std.Io.Clock.awake.now(self.io);
    defer charge(self, started);
    var status: u16 = 0;
    const left = budgetLeft(self, at.at, at.deadline);
    exchange(self, at.relay, self.options.probe_path, left, &status) catch return;
    slot.answer = .{ .https = elapsedNs(started, std.Io.Clock.awake.now(self.io)) };
}

/// Run the check's own GET and turn its status into an answer.
///
/// A verdict of null leaves `check_answer` null, so `pollCheck` keeps saying
/// "not decided" and the check's own timeout retires it.
fn answerCheck(self: *Live, at: probe_run.Check) void {
    const started = std.Io.Clock.awake.now(self.io);
    defer charge(self, started);
    var status: u16 = 0;
    const left = budgetLeft(self, at.at, at.deadline);
    exchange(self, at.relay, self.options.check.path, left, &status) catch return;
    self.check_answer = self.options.check.verdict(status);
}

/// One GET: connect, ask, read the status line, close.
///
/// `budget_ns` is everything this GET may cost, already reduced by the round,
/// and the status is written out rather than returned because only the check
/// reads it: `Observation.https` carries a latency and has no field for a
/// status, so for a probe the exchange's having produced a status line at all
/// is the whole of what it learns.
fn exchange(
    self: *Live,
    relay: RelayUrl,
    target: []const u8,
    budget_ns: Nanos,
    status: *u16,
) Error!void {
    const stop_at = std.Io.Clock.awake.now(self.io).addDuration(
        std.Io.Duration.fromNanoseconds(budget_ns),
    );
    const cap_ms = capMs(budget_ns);
    const first = waitMs(self, stop_at, cap_ms);
    if (first == 0) return error.NoBudget;
    try self.options.stream.vtable.open(self.options.stream.ctx, relay, first);
    defer self.options.stream.vtable.close(self.options.stream.ctx);

    var request: [max_request_length]u8 = undefined;
    const framed = std.fmt.bufPrint(&request, request_text, .{
        target,
        relay.hostSlice(),
    }) catch return error.RequestTooLong;
    try self.options.stream.vtable.write(self.options.stream.ctx, framed);

    const head = readHead(self, stop_at, cap_ms) orelse return error.NoResponse;
    status.* = statusOf(head) orelse return error.NoResponse;
}

/// The header block, borrowed from the caller's buffer, or null when there was
/// none.
///
/// The search is over what has arrived rather than over the buffer: it runs
/// once per read and the buffer is `Options.response`, so the work is bounded
/// by the caller's own size.
fn readHead(self: *Live, stop_at: std.Io.Timestamp, cap_ms: i32) ?[]const u8 {
    const buffer = self.options.response;
    var at: usize = 0;
    while (at < buffer.len) {
        if (std.mem.find(u8, buffer[0..at], header_end)) |end| return buffer[0..end];
        const left = waitMs(self, stop_at, cap_ms);
        if (left == 0) return null;
        const got = self.options.stream.vtable.read(
            self.options.stream.ctx,
            buffer[at..],
            left,
        ) catch return null;
        if (got == 0) return null;
        at += got;
    }
    return null;
}

/// The status code of a header block, or null when it is not one.
///
/// RFC 9112 §4: `HTTP-version SP status-code SP [ reason-phrase ]`. A version
/// this file does not speak is still a status a caller can time, so the version
/// is skipped rather than matched, and a reason phrase is optional.
fn statusOf(head: []const u8) ?u16 {
    const line_end = std.mem.find(u8, head, "\r\n") orelse head.len;
    const first = std.mem.findScalar(u8, head[0..line_end], ' ') orelse return null;
    const rest = head[0..line_end][first + 1 ..];
    const digits = if (std.mem.findScalar(u8, rest, ' ')) |at| rest[0..at] else rest;
    return std.fmt.parseInt(u16, digits, 10) catch null;
}

/// What one GET may still cost: its own budget from the round's start, and the
/// round's total less everything this `Live` has already spent.
fn budgetLeft(self: *const Live, at: Nanos, deadline: Nanos) Nanos {
    return @min(deadline -| at, probe.probe_timeout -| self.spent);
}

/// Charge what a GET cost the round, whatever it cost.
///
/// A refusal took the same time as an answer, and the next GET's budget is what
/// is left of the round's — so a round of relays that all time out is bounded
/// like a round of relays that all answer.
fn charge(self: *Live, started: std.Io.Timestamp) void {
    self.spent += elapsedNs(started, std.Io.Clock.awake.now(self.io));
}

/// The wait one call may take: what is left of this GET's budget, and never
/// more than what is left of the probe's.
///
/// The recomputation is the point: taking the remainder once would let a
/// response that arrived in pieces cost a whole budget per piece, and a
/// per-call figure that did not shrink would let `n` waits cost `n` budgets.
fn waitMs(self: *const Live, stop_at: std.Io.Timestamp, cap_ms: i32) i32 {
    const left = std.Io.Clock.awake.now(self.io).durationTo(stop_at).toMilliseconds();
    if (left <= 0) return 0;
    return @intCast(@min(left, @as(i64, cap_ms)));
}

fn capMs(budget_ns: Nanos) i32 {
    if (budget_ns == 0) return 0;
    const ms = budget_ns / std.time.ns_per_ms;
    if (ms > std.math.maxInt(i32)) return std.math.maxInt(i32);
    return @intCast(ms);
}

/// A span between two readings of the monotonic clock, never negative.
fn elapsedNs(from: std.Io.Timestamp, to: std.Io.Timestamp) Nanos {
    const ns = from.durationTo(to).nanoseconds;
    if (ns <= 0) return 0;
    return @intCast(@min(ns, @as(i96, std.math.maxInt(Nanos))));
}

fn claim(self: *Live, task: probe.Task) ?*Slot {
    const slot = &self.open_probes[slotOf(task)];
    if (slot.taken) return null;
    slot.* = .{ .taken = true, .task = task };
    return slot;
}

fn release(self: *Live, task: probe.Task) void {
    self.open_probes[slotOf(task)] = .{};
}

const t = std.testing;

// The harness the tests below stand on. Its own module doc says what these
// stand in for and what they cannot prove; `discovery/lookup_test_support.zig`
// is the same arrangement for the lookup seam.
const Script = support.Script;
const Wire = support.Wire;
const start = support.start;
const namedRelay = support.namedRelay;
const relaySet = support.relaySet;
const transport = support.transport;
const runRound = support.runRound;

// One round over both arms. Three relays, one address-discovery probe each and
// a whole HTTPS ladder each: the QAD half goes to the injected arm, the HTTPS
// half is a real exchange that answers, and the round ends on three relays'
// HTTPS latencies — which is `probe.haveEnough`'s own arm. The pairing the seam
// promises is asserted on both sides: one `close` per `open`, and nothing left
// open when the round is over.
test "a round sends QAD to the injected arm and HTTPS to the wire, and closes both" {
    var scratch: [192]u8 = undefined;
    const relays = try relaySet(&scratch);
    var script: Script = .{};
    // A QAD arm that never answers, so the round's work falls to the GETs.
    var wire: Wire = .{ .think = std.math.maxInt(Nanos) };
    var live = transport(&script, wire.arm());

    var results: probe.Results = .{};
    const runner = try runRound(&live, probe.new(.{
        .relays = &relays,
        .if_state = .{ .have_v4 = true, .have_v6 = false },
        .protocols = .{ .https = true, .qad_ipv4 = true, .qad_ipv6 = false },
        .now = start,
    }, &results), null);

    try t.expectEqual(probe.Outcome.enough, runner.outcome.?);
    try t.expectEqual(@as(usize, 3), wire.opened);
    try t.expectEqual(@as(usize, 0), probe.measured(.qad_ipv4, results.slice()));
    try t.expectEqual(@as(usize, 3), probe.measured(.https, results.slice()));
    // Every relay's latency was taken with the file's own clock, so none of
    // them is zero: a reversed span reads as zero, and `report.HttpsProbe`
    // files zero as the best relay there is.
    for (results.slice()) |result| switch (result) {
        .https => |measured| try t.expect(measured.latency > 0),
        else => {},
    };
    // The GET really went out: a request line, a host, and no field this file
    // did not mean to send.
    try t.expectEqual(@as(usize, 3), script.opened);
    try t.expect(std.mem.startsWith(
        u8,
        script.sent(),
        "GET /ping HTTP/1.1\r\nHost: 0.example.\r\n",
    ));
    // Every open is matched by exactly one close on both arms, and the three
    // address-discovery probes were taken with the round rather than retired
    // at a budget they never reached.
    try t.expectEqual(script.opened, script.closed);
    try t.expectEqual(wire.opened, wire.closed);
    try t.expectEqual(@as(usize, 3), wire.closedAs(.canceled));
    try t.expectEqual(@as(usize, 0), wire.closedAs(.expired));
}

// The budget, stated as a number. Nine GETs went out — three relays, three
// rungs each, because no rung answered — and every wait any of them made was
// inside one probe's own budget. A TCP retransmit runs for minutes; what is
// handed to the kernel instead is what is left of that budget, recomputed
// before each call, and that is the whole of the bound.
test "every wait a GET makes is inside the probe's budget, and the round's too" {
    var scratch: [192]u8 = undefined;
    const relays = try relaySet(&scratch);
    // A peer that half-closes at once: no status line, so no answer at all.
    var script: Script = .{ .answer = "" };
    var live = transport(&script, null);

    var results: probe.Results = .{};
    const runner = try runRound(&live, probe.new(.{
        .relays = &relays,
        .if_state = .{},
        .protocols = .{ .https = true },
        .now = start,
    }, &results), null);

    try t.expectEqual(probe.Outcome.timeout, runner.outcome.?);
    try t.expectEqual(@as(usize, 0), probe.measured(.https, results.slice()));
    try t.expectEqual(@as(usize, 9), script.opened);
    try t.expectEqual(script.opened, script.closed);
    try t.expect(script.waits_len > 0);
    const ceiling: i32 = @intCast(probe.probe_timeout / std.time.ns_per_ms);
    for (script.waits[0..script.waits_len]) |wait| {
        try t.expect(wait > 0);
        try t.expect(wait <= ceiling);
    }
    // The second budget: nine GETs together cost no more than what one probe
    // was allowed to cost, so a round cannot spend fifteen budgets.
    try t.expect(live.spent <= probe.probe_timeout);
}

// A relay that cannot be reached is silence. The refusal is proved on every
// rung rather than on the first: `open` refuses, `poll` says nothing, and the
// round carries on to the next rung instead of abandoning every other relay
// with this one. An unreachable relay is a fact about the world and the round
// exists to learn it; making it an error would throw away the relays that do
// answer.
//
// The two counters are separate because `Stream` says a failed `open` owes no
// `close`: nine connections were attempted and none was established, so there
// is nothing to close and `closed` is zero.
test "a relay that cannot be reached is silence, and the budget retires it" {
    var scratch: [192]u8 = undefined;
    const relays = try relaySet(&scratch);
    var script: Script = .{ .fault = error.Unreachable };
    var live = transport(&script, null);
    var results: probe.Results = .{};
    var in_flight: probe_run.InFlight = .{};
    const runner = probe.new(.{
        .relays = &relays,
        .if_state = .{},
        .protocols = .{ .https = true },
        .now = start,
    }, &results);

    // Nothing is due at the round's own start: an HTTPS probe carries the
    // ladder's offset. So the refusal is proved at the first rung.
    const first = try probe_run.drive(runner, live.transport(), &in_flight, .{ .now = start });
    try t.expectEqual(@as(u8, 0), first.opened);
    const finished = try runRound(&live, first.runner, null);
    // Nothing is due at the round's own start: an HTTPS probe carries the
    // ladder's offset, so the first turn opens nothing at all.
    try t.expectEqual(@as(usize, 9), script.attempted);
    try t.expectEqual(@as(usize, 0), script.opened);
    try t.expectEqual(script.opened, script.closed);
    try t.expectEqual(probe.Outcome.timeout, finished.outcome.?);
    try t.expectEqual(@as(usize, 0), probe.measured(.https, results.slice()));
}

// The two clocks, one round. The address-discovery probe went out at the
// round's start and its answer is polled at the ladder's first rung, so its
// latency is exactly the 200 ms between them on the round's own timeline. The
// GET ran inside that same turn, between two reads of one instant — so a
// round-clock figure for it would be zero, and zero is filed as the best relay
// in `report.HttpsProbe`. It is not zero and it is under 200 ms, so it can only
// have come from the `std.Io` clock this file reads for itself.
test "the QAD latency is the round's clock and the GET's is its own" {
    var one: [64]u8 = undefined;
    const relays = [_]RelayUrl{try namedRelay(&one, 0)};
    var script: Script = .{};
    // Five milliseconds of service time, so the answer cannot be polled in the
    // turn that sent the probe: it has to wait for a later instant, and that
    // instant is the round's own clock.
    var wire: Wire = .{ .think = 5 * std.time.ns_per_ms };
    var live = transport(&script, wire.arm());
    var results: probe.Results = .{};
    var in_flight: probe_run.InFlight = .{};

    // Turn one: the address-discovery probe goes out and nothing else is due.
    const first = try probe_run.drive(probe.new(.{
        .relays = &relays,
        .if_state = .{ .have_v4 = true, .have_v6 = false },
        .protocols = .{ .https = true, .qad_ipv4 = true, .qad_ipv6 = false },
        .now = start,
    }, &results), live.transport(), &in_flight, .{ .now = start });
    try t.expectEqual(@as(u8, 1), first.opened);
    try t.expectEqual(@as(u8, 0), first.answered);
    // Turn two, 200 ms later on the round's own timeline: the first rung opens,
    // and both answers are polled at this one instant.
    const second = try probe_run.drive(first.runner, live.transport(), &in_flight, .{
        .now = start + probe.https_offset,
    });
    try t.expectEqual(@as(u8, 1), second.opened);
    try t.expectEqual(@as(u8, 2), second.answered);

    var qad_latency: ?Nanos = null;
    var https_latency: ?Nanos = null;
    for (results.slice()) |result| switch (result) {
        .qad_ipv4 => |measured| qad_latency = measured.latency,
        .https => |measured| https_latency = measured.latency,
        .qad_ipv6 => {},
    };
    try t.expectEqual(probe.https_offset, qad_latency.?);
    try t.expect(https_latency.? > 0);
    try t.expect(https_latency.? < probe.https_offset);
    // Both probes were closed by the drain that took their answers, once each,
    // and cancelling a round with nothing open closes nothing more.
    try t.expectEqual(@as(usize, 1), wire.closed);
    try t.expectEqual(@as(usize, 1), script.closed);
    probe_run.cancel(live.transport(), &in_flight);
    try t.expectEqual(@as(usize, 1), wire.closed);
    try t.expectEqual(@as(usize, 1), script.closed);
}

// The check is a GET like any other and differs only in what its answer is read
// to mean. Three states, and the round reports all three: a clean network is
// `false`, a relay that cannot be reached never decides and stays `null`, and
// somebody else's answer is a portal.
//
// The protocols are spelled out rather than defaulted because
// `Protocols.https` is true by default: `.{}` would plan a whole HTTPS ladder
// beside the check, and this test is about the check's own GET and the one
// relay it was handed.
test "the check is an HTTPS GET, and its three states reach the report" {
    var scratch: [192]u8 = undefined;
    const relays = try relaySet(&scratch);

    var clean: Script = .{};
    var clear = transport(&clean, null);
    var clear_results: probe.Results = .{};
    const answered = try runRound(&clear, probe.new(.{
        .relays = &relays,
        .if_state = .{},
        .protocols = .{ .https = false },
        .round = .{ .captive_portal_check = true },
        .now = start,
    }, &clear_results), relays[0]);
    try t.expectEqual(@as(usize, 1), clean.opened);
    try t.expect(std.mem.startsWith(u8, clean.sent(), "GET /portal-check HTTP/1.1\r\n"));
    // `false`, not null: the check looked and found nothing, which is a
    // different fact from never having looked.
    try t.expectEqual(
        @as(?bool, false),
        probe.fold(answered, .{}, start + probe.overall_timeout).captive_portal,
    );

    var lost: Script = .{ .fault = error.Unreachable };
    var silent = transport(&lost, null);
    var silent_results: probe.Results = .{};
    const undecided = try runRound(&silent, probe.new(.{
        .relays = &relays,
        .if_state = .{},
        .protocols = .{ .https = false },
        .round = .{ .captive_portal_check = true },
        .now = start,
    }, &silent_results), relays[0]);
    // Null and not false: a portal nobody managed to rule on has not been
    // ruled out, and reporting `false` would claim the opposite.
    try t.expectEqual(
        @as(?bool, null),
        probe.fold(undecided, .{}, start + probe.overall_timeout).captive_portal,
    );

    var hijacked: Script = .{ .answer = "HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n" };
    var trapped_wire = transport(&hijacked, null);
    var portal_results: probe.Results = .{};
    const trapped = try runRound(&trapped_wire, probe.new(.{
        .relays = &relays,
        .if_state = .{},
        .protocols = .{ .https = false },
        .round = .{ .captive_portal_check = true },
        .now = start,
    }, &portal_results), relays[0]);
    try t.expectEqual(
        @as(?bool, true),
        probe.fold(trapped, .{}, start + probe.overall_timeout).captive_portal,
    );
}

// The one refusal that is not silence. A caller that planned a probe family it
// did not wire has made a mistake here rather than learned a fact about a
// relay, and `SendError` has no arm for "I have no arm for this" — so it is
// `error.Full`, which abandons the round instead of quietly measuring nothing.
test "a QAD probe with no injected arm is refused rather than left silent" {
    var scratch: [192]u8 = undefined;
    const relays = try relaySet(&scratch);
    var script: Script = .{};
    var live = transport(&script, null);
    var results: probe.Results = .{};
    var in_flight: probe_run.InFlight = .{};
    const runner = probe.new(.{
        .relays = &relays,
        .if_state = .{ .have_v4 = true, .have_v6 = false },
        .protocols = .{ .qad_ipv4 = true },
        .now = start,
    }, &results);

    try t.expectError(
        error.Full,
        probe_run.drive(runner, live.transport(), &in_flight, .{ .now = start }),
    );
    try t.expectEqual(@as(usize, 0), script.opened);
}

// A stop is honoured before the work starts rather than after it. Nothing here
// waits across a call, so a stopped transport has no exchange of its own to
// interrupt; what it can do is refuse the next one, and `SendError.Canceled`
// is the arm that means exactly that.
test "a stopped transport refuses a later open with Canceled" {
    var scratch: [192]u8 = undefined;
    const relays = try relaySet(&scratch);
    var script: Script = .{};
    var live = transport(&script, null);
    live.stop();
    var results: probe.Results = .{};
    var in_flight: probe_run.InFlight = .{};
    const runner = probe.new(.{
        .relays = &relays,
        .if_state = .{},
        .protocols = .{ .https = true },
        .now = start,
    }, &results);

    try t.expectError(
        error.Canceled,
        probe_run.drive(runner, live.transport(), &in_flight, .{
            .now = start + probe.https_offset,
        }),
    );
    try t.expectEqual(@as(usize, 0), script.opened);
}
