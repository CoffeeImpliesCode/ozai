//! The live `probe_run.Transport`: QUIC for the two address-discovery families,
//! HTTPS for the third probe and for the captive-portal check.
//!
//! `probe_run.zig` plans a round and files what comes back, and nothing in this
//! tree has ever sent one: every `report.ProbeResult` was written by a test.
//! `discovery/lookup_live.zig` is what crossing that seam looks like here — the
//! module that names what a round needs from a wire, the module that crosses
//! it, and the tests at the bottom of the file. This is the crossing half of
//! `probe_run.Transport`, and it is all six methods, which is the reason it
//! exists: `lookup_live.zig`'s own module doc refuses to build three of them,
//! because a transport answering half its seam "satisfies the type and answers
//! nothing real".
//!
//! # Two arms, cut where the work is
//!
//! * **QUIC is injected.** A QAD probe is upstream's `run_probe_v4` /
//!   `run_probe_v6` (`net_report.rs:826-961`): a QUIC connection to the relay on
//!   the address-discovery ALPN (`router.qad_alpn`, `/iroh-qad/0`) and a read of
//!   the address the relay saw us come from. Every part of that belongs to the
//!   node rather than to a probe round: the dialer presents this node's
//!   certificate (`transport/dial.zig`), the connection lives in the one
//!   `quic_bridge.Bridge` the node drives, and the socket has to be the family
//!   the probe asked for. A round cannot invent any of it, so `Qad` is three
//!   calls the caller already has.
//! * **HTTPS is live here.** A `GET` of the relay needs no identity, no bridge
//!   and no family, so the only thing standing between the seam and the wire is
//!   a TLS client, and `std.http.Client` is one. `Fetcher` is that client, and
//!   `liveGet` is the call.
//!
//! So the QUIC arm's owner is a node and the HTTPS arm's owner is this file,
//! and the asymmetry is the design rather than a gap: the arm that needed a
//! node is cut where the node is, and the arm that did not is not cut at all.
//!
//! # Two latencies, from two clocks
//!
//! `probe_run.Observation`'s doc calls the latency "the transport's figure,
//! measured from `Open.at` to the `now` it polls at", and that is exactly what
//! the QUIC arm hands over: an exchange that spans turns is timed on the round's
//! own timeline, with no clock here at all. The HTTPS arm cannot be — it runs
//! and finishes inside the `open` that asked for it, and `drive` polls with the
//! same instant it opened with, so `now - at` there is zero. That arm measures
//! with the clock its `std.Io` carries, and reports the figure it measured. Two
//! sources, two owners, and no conversion between them.
//!
//! # The budget is spent, not compared
//!
//! No clock of the round's is available inside an exchange, so `Open.deadline`
//! and `Open.at` are differenced into what is left (`discovery/lookup_live.zig`
//! spends its slices the same way) and that is what bounds the GET. Without a
//! bound this seam would hang the loop that drives it: `std.http.Client.fetch`
//! has no timeout field, and a TCP connection to a relay that stopped answering
//! spends minutes in retransmits.
//!
//! # Divergences from upstream, and each is forced
//!
//! - **A turn blocks.** Upstream spawns a task per probe and drives a round out
//!   of futures (`net_report.rs:504-540`). `probe_run.Transport`'s six methods
//!   are six synchronous callbacks and Zig 0.16's `std.Io.Future` has no
//!   readiness to ask for — only `await` and `cancel` — so an HTTPS exchange
//!   runs inside the `open` that started it. A relay that is silent costs the
//!   round its own budget and nothing more, which is the promise
//!   `probe_run.zig` makes; what it no longer promises is that one turn's probes
//!   overlap each other.
//! - **A relay that could not be reached is silence, not a refusal.** Both of
//!   `probe_run.SendError`'s arms are about this node, and a relay that refused
//!   to answer is a probe that never answers; the budget turns that into one
//!   retired probe. `Qad.Error.Refused` and `HttpsAnswer.silent` both land there.
//! - **The check has three states and two of them are answers.** A relay that
//!   answered with success rules a portal out and a relay that answered with a
//!   redirect rules one in; an exchange that produced no response at all leaves
//!   `probe.Runner.captive` null, which is a portal nobody looked for rather
//!   than a portal that is not there. `checkDecision` is the whole of it.
//!
//! # The four names, and where each one lives
//!
//! `probe_run.zig` lists what the seam was missing: an `std.Io`, a buffer, a
//! cancellation handle and a copy of the answer. They are all here, each owned
//! by the party that can own it: the `std.Io` and the TLS client's allocator in
//! `Fetcher`, because `Transport`'s callbacks take no `Io` and a struct holding
//! one is the caller's (`docs/DECISIONS/0002-async-substrate.md`); the URL text
//! in `httpsGet`, rendered into a buffer this file owns because the only reader
//! is the arm's own call; the cancellation handle in `Live.stop`, one atomic
//! store a shutdown may make from a signal handler, read by `open` and
//! `beginCheck` exactly as `SendError.Canceled` describes — a probe opened after
//! it fired is one nobody is waiting for; and the copy of the answer in
//! `HttpsReply`, because a buffer an `Io` read fills does not outlive the call
//! that filled it.
//!
//! # What is still not here
//!
//! No caller. A node has to own a `Live`, a bridge to dial from, and the loop
//! that hands each turn its instant, and nothing under `src/node/` does that
//! yet — the same gap `TODO.md` records for `lookup_live.zig`'s `Datagram`.
//! Three narrower gaps sit under it: the relay half of the address-discovery
//! exchange is `router.Builder.acceptInternal`, which no node registers, so a
//! QAD probe has nothing to talk to until one does; a relay URL's host is a
//! name, and resolving it is `discovery/dns.zig`'s job by design
//! (`base/relay_url.zig` refuses to resolve one); and the round itself — when to
//! start one, what to do with the report — is a node's decision, not a seam's.
//!
//! # Ownership and lifetimes
//!
//! No global, no thread of its own and no allocator it did not get: `Fetcher`
//! takes the caller's allocator and releases the client in `deinit`, and `Live`
//! holds nothing but the two arms and the round's own bound — `probe.max_tasks`
//! slots and one check, which is the same bound `probe_run.InFlight` keeps on
//! the other side of the seam. A `Live` is a value the caller owns and must keep
//! at one address for as long as any round runs, because `Transport.ctx` is a
//! pointer into it.

const std = @import("std");
const addr = @import("../base/addr.zig");
const base_relay_url = @import("../base/relay_url.zig");
const probe = @import("probe.zig");
const probe_run = @import("probe_run.zig");
const report = @import("report.zig");

const Nanos = report.Nanos;
const RelayUrl = base_relay_url.RelayUrl;
const SocketAddr = addr.SocketAddr;

/// How long the budget waits before it asks the exchange whether it is done.
///
/// 20 ms, and the number is `discovery/lookup_live.zig`'s own `poll_slice_ms`:
/// it is how long a finished exchange can keep the group waiting, so it is
/// small next to a budget and large next to nothing at all.
const poll_slice_ns: i96 = 20 * std.time.ns_per_ms;

/// The bytes a relay URL's text form takes at most: the longest scheme, `://`,
/// the longest host, the longest port, and the trailing slash `format` adds.
const url_text_length = "https".len + "://".len + RelayUrl.max_host_length +
    ":65535".len + "/".len;

/// The two sockets a QAD probe goes out on.
///
/// Upstream's two functions, one value: `report.Probe` keeps the split in the
/// arm a result is filed under, and this keeps it in the exchange that
/// produced it.
pub const Family = enum { v4, v6 };

/// The QUIC address-discovery arm, as the three calls this file makes on it.
///
/// The exchange is keyed by relay and family, and that is enough because a round
/// plans at most one QAD probe per relay per family — `probe.rungsFor` gives
/// both families a single rung — so no two probes one round opens can name the
/// same exchange.
pub const Qad = struct {
    ctx: *anyopaque,
    /// Begin one exchange. On `error.Refused` no exchange is running and no
    /// `stop` is owed.
    start: *const fn (ctx: *anyopaque, relay: RelayUrl, family: Family) Error!void,
    /// The address the relay has reported, or null while it has not. Never waits.
    observed: *const fn (ctx: *anyopaque, relay: RelayUrl, family: Family) ?SocketAddr,
    /// Give the exchange up. Owed for every exchange `start` began and nothing
    /// has retired, which is what `close` and `cancel` ask for.
    stop: *const fn (ctx: *anyopaque, relay: RelayUrl, family: Family) void,

    pub const Error = error{
        /// The relay was not reached, or the arm has no socket on that family.
        /// Silence rather than a refusal, for `probe_run.SendError`'s reason.
        Refused,
        /// The caller's own cancel handle fired before the exchange began.
        Canceled,
        /// The arm has no room for another exchange on that family.
        Full,
    };
};

/// What one HTTPS exchange produced, copied out before the call returned.
pub const HttpsReply = struct {
    /// The status the far end sent — the relay's, or whatever answered in its
    /// place. Unconverted and unexamined: what it means is `checkDecision`'s
    /// question and an HTTPS probe's is not asked at all.
    status: std.http.Status,
    /// How long the exchange took, measured by the arm around its own request.
    elapsed: Nanos,
};

/// One HTTPS exchange's outcome: something answered, or nothing did.
pub const HttpsAnswer = union(enum) {
    /// Nothing came back inside the budget.
    silent,
    replied: HttpsReply,
};

/// The HTTPS arm, as the one call this file makes on it.
///
/// Injected for the reason `lookup_live.zig`'s wire is injected: one GET with a
/// TLS handshake on it cannot be proved with anything else in front of it, and
/// `Fetcher` is the live arm. The URL is borrowed for the call only — the arm
/// writes what it answers, and nothing it holds outlives it.
pub const Https = struct {
    ctx: *anyopaque,
    get: *const fn (ctx: *anyopaque, url: []const u8, budget: Nanos) HttpsAnswer,
};

/// One probe a round has open, and what is known about its exchange.
///
/// The whole task and its relay, because closing a probe has to name it and
/// `probe_run.cancel` runs on the error path where nothing else is available
/// (`InFlight.open`'s reason).
const Slot = struct {
    task: probe.Task,
    relay: RelayUrl,
    /// The instant the round sent it: the QUIC arm's latency is measured from
    /// here to the `now` it polls at, which is why the round's clock and not
    /// one of this file's is what a QAD answer carries.
    at: Nanos,
    /// The latency an HTTPS exchange measured, or null while none has answered.
    answered: ?Nanos = null,
    /// The socket this probe's QUIC exchange is on, or null when it has none: an
    /// HTTPS probe, and a QUIC probe whose exchange `poll` has already retired.
    family: ?Family = null,
};

/// A `probe_run.Transport` that answers over two arms and a table.
pub const Live = struct {
    qad: Qad,
    https: Https,
    /// The probes this round has open. Bounded by `probe.max_tasks` because
    /// that is the most a round can hold, and a table that cannot overflow is
    /// the only thing that makes `error.Full` a fact rather than a guess.
    slots: [probe.max_tasks]?Slot = @splat(null),
    /// Whether a check has begun and not ended.
    check_open: bool = false,
    /// What the check decided, or null while it has not.
    check: ?bool = null,
    /// Latched by `stop` and read by the two methods that start something.
    stopped: std.atomic.Value(bool) = .init(false),

    /// The transport `probe_run.drive` is handed, with `self` as its context.
    ///
    /// `Transport.ctx` is a pointer, so the `Live`'s address has to hold still
    /// for as long as a round runs: one owned by the loop that drives the round
    /// is one that holds still.
    pub fn seam(self: *Live) probe_run.Transport {
        return .{ .vtable = &vtable, .ctx = @ptrCast(self) };
    }

    /// Refuse to start anything more, from here on.
    ///
    /// One atomic store, so a shutdown may call it from where it may call
    /// `src/node/node.zig`'s `Stop.request`. It reaches the two methods that
    /// start an exchange and nothing else: an exchange already in flight is
    /// given up by its own budget or by `close`, which is what
    /// `probe_run.SendError.Canceled` describes — a probe opened *after* the
    /// handle fired is the one nobody is waiting for.
    pub fn stop(self: *Live) void {
        self.stopped.store(true, .release);
    }
};

const vtable: probe_run.Transport.VTable = .{
    .open = open,
    .poll = poll,
    .close = close,
    .beginCheck = beginCheck,
    .pollCheck = pollCheck,
    .endCheck = endCheck,
};

/// Begin one probe.
fn open(ctx: *anyopaque, at: probe_run.Open) probe_run.SendError!void {
    const self: *Live = @ptrCast(@alignCast(ctx));
    if (self.stopped.load(.acquire)) return error.Canceled;
    // Nothing is written before the slot is found, so a refusal here leaves the
    // table as it was and owes no `close`.
    const index = freeSlot(self) orelse return error.Full;
    var slot: Slot = .{ .task = at.task, .relay = at.relay, .at = at.at };
    switch (at.task.proto) {
        .qad_ipv4 => try startQad(self, &slot, at.relay, .v4),
        .qad_ipv6 => try startQad(self, &slot, at.relay, .v6),
        .https => {
            if (httpsGet(self, at.relay, at.deadline -| at.at)) |reply| {
                slot.answered = reply.elapsed;
            }
        },
    }
    self.slots[index] = slot;
}

/// The first table entry no probe occupies, or null when there is none.
///
/// A walk rather than a count, because the table is the bound: `probe.max_tasks`
/// entries is `probe_run.SendError.Full` exactly, with no second number to keep
/// in step with it.
fn freeSlot(self: *Live) ?usize {
    for (self.slots, 0..) |entry, index| {
        if (entry == null) return index;
    }
    return null;
}

/// Start one QUIC exchange and record the socket it is on.
///
/// A `Refused` is not propagated: it is a relay that was not reached, which is
/// a probe that never answers, and the budget is what turns that into one
/// retired probe. `Canceled` and `Full` are about this node rather than about
/// the relay, which is the whole of what `probe_run.SendError` admits.
fn startQad(
    self: *Live,
    slot: *Slot,
    relay: RelayUrl,
    family: Family,
) probe_run.SendError!void {
    self.qad.start(self.qad.ctx, relay, family) catch |err| switch (err) {
        error.Refused => return,
        error.Canceled => return error.Canceled,
        error.Full => return error.Full,
    };
    slot.family = family;
}

/// One `GET` of `relay`, spending at most `budget` nanoseconds on it.
///
/// The URL is rendered here rather than handed in, because the only consumer is
/// the arm's own call and a buffer the caller had to size for it would be a
/// second number to keep in step with `url_text_length`. A URL that did not fit
/// would be a relay this file cannot address, which is silence like any other.
fn httpsGet(self: *Live, relay: RelayUrl, budget: Nanos) ?HttpsReply {
    var text: [url_text_length]u8 = undefined;
    var out = std.Io.Writer.fixed(&text);
    relay.format(&out) catch return null;
    return switch (self.https.get(self.https.ctx, out.buffered(), budget)) {
        .silent => null,
        .replied => |reply| reply,
    };
}

/// Take one answer, or null when none is ready.
///
/// Never waits and never reads a clock: a QUIC exchange is asked what it has,
/// and an HTTPS answer was measured and copied in `open`. An answer is *taken*
/// rather than left for the next call, because `drive` polls until it runs dry
/// and a second answer for a probe it has already closed is
/// `error.Unattributable`.
fn poll(ctx: *anyopaque, now: Nanos) ?probe_run.Reply {
    const self: *Live = @ptrCast(@alignCast(ctx));
    var index: usize = 0;
    while (index < self.slots.len) : (index += 1) {
        const slot = if (self.slots[index]) |*found| found else continue;
        switch (slot.task.proto) {
            .https => {
                const latency = slot.answered orelse continue;
                slot.answered = null;
                return .{ .task = slot.task, .value = .{ .https = latency } };
            },
            .qad_ipv4, .qad_ipv6 => {
                const family = slot.family orelse continue;
                const reported = self.qad.observed(self.qad.ctx, slot.relay, family) orelse
                    continue;
                slot.family = null;
                return .{ .task = slot.task, .value = .{ .qad = .{
                    .latency = now -| slot.at,
                    .reported = reported,
                } } };
            },
        }
    }
    return null;
}

/// Retire one probe, and its exchange with it.
///
/// The three reasons are the round's and not this wire's: an exchange still
/// running is stopped whichever way the round ended, and one that answered was
/// retired by `poll` before this arrives. A task no slot holds is a probe this
/// transport has already retired, which is why there is nothing to refuse.
fn close(ctx: *anyopaque, task: probe.Task, _: probe_run.Why) void {
    const self: *Live = @ptrCast(@alignCast(ctx));
    var index: usize = 0;
    while (index < self.slots.len) : (index += 1) {
        const slot = if (self.slots[index]) |*found| found else continue;
        if (!std.meta.eql(slot.task, task)) continue;
        if (slot.family) |family| self.qad.stop(self.qad.ctx, slot.relay, family);
        self.slots[index] = null;
        return;
    }
}

/// Begin the relay check.
fn beginCheck(ctx: *anyopaque, at: probe_run.Check) probe_run.SendError!void {
    const self: *Live = @ptrCast(@alignCast(ctx));
    if (self.stopped.load(.acquire)) return error.Canceled;
    // One check at a time: `InFlight.check` is a bool and a round asks for the
    // check once, so a second one is a caller driving two rounds at this table.
    if (self.check_open) return error.Full;
    self.check_open = true;
    self.check = checkDecision(httpsGet(self, at.relay, at.deadline -| at.at));
}

/// What the check has decided, or null while it has not.
///
/// `now` is not read: the check's exchange ran inside `beginCheck`, so by the
/// time anything polls it the answer is already the one it will keep giving.
fn pollCheck(ctx: *anyopaque, _: Nanos) ?bool {
    const self: *Live = @ptrCast(@alignCast(ctx));
    if (!self.check_open) return null;
    return self.check;
}

/// Retire the check, decided or not.
fn endCheck(ctx: *anyopaque, _: probe_run.Why) void {
    const self: *Live = @ptrCast(@alignCast(ctx));
    self.check_open = false;
    self.check = null;
}

/// What a status says about a portal, or null when it says nothing.
///
/// A relay answers a `GET /` with success, and a captive portal answers with a
/// redirect to a page of its own, so those two are the answers this reads. The
/// other four classes leave the check undecided and go to
/// `probe.Runner.captive`'s null: a status on its own is not a portal, because
/// this tree's relay answers only a WebSocket upgrade
/// (`relay/http_response.zig`) and reading its 404 as a portal would publish one
/// that is not there — and because an exchange that produced no response at all,
/// including one canceled at its budget, says nothing about anybody's portal.
fn checkDecision(reply: ?HttpsReply) ?bool {
    const answer = reply orelse return null;
    return switch (answer.status.class()) {
        .success => false,
        .redirect => true,
        .informational, .client_error, .server_error => null,
    };
}

/// The live HTTPS arm: one TLS client, built from the caller's allocator.
pub const Fetcher = struct {
    io: std.Io,
    client: std.http.Client,

    /// The client and the `Io` it opens connections with.
    ///
    /// `gpa` is the caller's and must outlive the fetcher, and so must every
    /// buffer it named for the client's own. A client that carried an allocator
    /// of its own would be a client whose allocations nobody could see.
    pub fn init(gpa: std.mem.Allocator, io: std.Io) Fetcher {
        return .{ .io = io, .client = .{ .allocator = gpa, .io = io } };
    }

    /// Release the client. Every exchange has to have finished first: a GET in
    /// flight is still holding one of its connections.
    pub fn deinit(self: *Fetcher) void {
        self.client.deinit();
    }

    /// The arm this fetcher answers `Https` with.
    pub fn seam(self: *Fetcher) Https {
        return .{ .ctx = self, .get = liveGet };
    }
};

/// One exchange in flight, and the flag the budget waits on.
const Exchange = struct {
    /// Whether the `GET` is finished. `liveGet` reads `reply` after the group's
    /// `await`, which is the barrier; this is what the budget reads while it
    /// waits, and a `GET` that fails answers it on its way out.
    done: std.atomic.Value(bool) = .init(false),
    reply: ?HttpsReply = null,
};

/// One `GET` of `url` inside `budget`, as the live arm of `Https`.
///
/// `std.http.Client.fetch` takes no deadline — `FetchOptions` has no timeout
/// field — and the TCP below it spends minutes in retransmits against a relay
/// that stopped answering. So the exchange is two `std.Io.Group` tasks: this
/// waits for both, and `budgetTask` cancels the group when the budget is gone
/// or the `GET` is done.
fn liveGet(ctx: *anyopaque, url: []const u8, budget: Nanos) HttpsAnswer {
    const self: *Fetcher = @ptrCast(@alignCast(ctx));
    var exchange: Exchange = .{};
    var group: std.Io.Group = .init;
    group.async(self.io, budgetTask, .{ self, &group, &exchange, budget });
    group.async(self.io, fetchTask, .{ self, &exchange, url });
    group.await(self.io) catch |err| switch (err) {
        // A canceled group is the budget spending itself, and the GET it
        // canceled may be the whole reason there is an answer to give.
        error.Canceled => {},
    };
    const reply = exchange.reply orelse return .silent;
    return .{ .replied = reply };
}

/// The `GET` itself, timed with the clock this arm's `Io` carries.
fn fetchTask(
    self: *Fetcher,
    exchange: *Exchange,
    url: []const u8,
) std.Io.Cancelable!void {
    defer exchange.done.store(true, .release);
    const started = std.Io.Clock.awake.now(self.io).nanoseconds;
    const result = self.client.fetch(.{
        .location = .{ .url = url },
        // A captive portal answers with a redirect, and following one is how the
        // answer this check is looking for gets hidden behind the page it names.
        .redirect_behavior = .unhandled,
        // One GET, one connection: a round has no reason to pool a relay's
        // connection for a probe it will not send twice, and a pooled one is a
        // connection `deinit` would have to be told about.
        .keep_alive = false,
    }) catch return;
    const finished = std.Io.Clock.awake.now(self.io).nanoseconds;
    exchange.reply = .{
        .status = result.status,
        // A monotonic clock does not go backwards, so this narrows a non-negative
        // count into the width the fold stores.
        .elapsed = @intCast(finished - started),
    };
}

/// Wait out the budget and cancel the exchange, or stop waiting once it is done.
///
/// Slices rather than one sleep, because `std.Io.Group.await` returns when the
/// *last* member finishes: a budget that slept whole would hold a `GET` which
/// answered in five milliseconds for the other 2 995.
fn budgetTask(
    self: *Fetcher,
    group: *std.Io.Group,
    exchange: *Exchange,
    budget: Nanos,
) std.Io.Cancelable!void {
    const slice: std.Io.Clock.Duration = .{
        .raw = .{ .nanoseconds = poll_slice_ns },
        .clock = .awake,
    };
    var left: std.Io.Clock.Duration = .{
        .raw = .{ .nanoseconds = @intCast(budget) },
        .clock = .awake,
    };
    while (!exchange.done.load(.acquire)) {
        if (left.raw.nanoseconds <= 0) break;
        const wait = if (left.raw.nanoseconds > slice.raw.nanoseconds) slice else left;
        wait.sleep(self.io) catch return;
        left.raw.nanoseconds -= wait.raw.nanoseconds;
    }
    group.cancel(self.io);
}

const t = std.testing;

/// Ten minutes in, on the timeline these tests hand the round: past every probe
/// instant, and the same constant `probe_run.zig`'s own tests use so a failure
/// in either file is read against one timeline.
const start: Nanos = 600 * std.time.ns_per_s;

fn millis(n: u64) Nanos {
    return n * std.time.ns_per_ms;
}

/// A scripted arm for both seams, so a test drives a whole round with no socket
/// and no network.
///
/// Every field is a decision the test writes, which is the point of injecting
/// the QUIC arm: `Live`'s own table, its budget arithmetic and its refusals are
/// all reachable without one relay answering anything.
const Scripted = struct {
    /// The address the QUIC arm reports, per family. Null is a relay that has
    /// not answered yet — or never will.
    reported: [2]?SocketAddr = @splat(null),
    /// What the HTTPS arm answers, whatever it was asked.
    https: HttpsAnswer = .silent,
    /// Whether the QUIC arm refuses to start.
    refuses: bool = false,
    /// Every exchange `Qad.stop` was called for.
    stops: usize = 0,

    fn qad(self: *Scripted) Qad {
        return .{ .ctx = self, .start = scriptStart, .observed = scriptObserved, .stop = scriptStop };
    }

    fn httpsArm(self: *Scripted) Https {
        return .{ .ctx = self, .get = scriptGet };
    }
};

fn scriptStart(ctx: *anyopaque, _: RelayUrl, _: Family) Qad.Error!void {
    const self: *Scripted = @ptrCast(@alignCast(ctx));
    if (self.refuses) return error.Refused;
}

fn scriptObserved(ctx: *anyopaque, _: RelayUrl, family: Family) ?SocketAddr {
    const self: *Scripted = @ptrCast(@alignCast(ctx));
    return self.reported[@intFromEnum(family)];
}

fn scriptStop(ctx: *anyopaque, _: RelayUrl, _: Family) void {
    const self: *Scripted = @ptrCast(@alignCast(ctx));
    self.stops += 1;
}

fn scriptGet(ctx: *anyopaque, _: []const u8, _: Nanos) HttpsAnswer {
    const self: *Scripted = @ptrCast(@alignCast(ctx));
    return self.https;
}

/// A `Live` over `arm`, at the caller's address.
fn liveOver(arm: *Scripted) Live {
    return .{ .qad = arm.qad(), .https = arm.httpsArm() };
}

const relay_a: RelayUrl = .{ .scheme = .https, .host = [_]u8{'a'} ** 253, .host_length = 1, .port = 443 };
const relay_b: RelayUrl = .{ .scheme = .https, .host = [_]u8{'b'} ** 253, .host_length = 1, .port = 443 };

const public_v4: SocketAddr = .{ .ip = .{ .v4 = .{ 198, 51, 100, 7 } }, .port = 41234 };
const public_v6: SocketAddr = .{
    .ip = .{ .v6 = .{
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
        0,    0,    0,    0,    0, 0, 0, 0x07,
    } },
    .port = 41234,
};

/// Run a round to its end, one `wake_at` at a time, and hand back the runner
/// the fold reads — `probe_run.zig`'s own loop, run over this file's transport.
fn runRound(
    wire: probe_run.Transport,
    runner: probe.Runner,
    in_flight: *probe_run.InFlight,
) !probe.Runner {
    var current = runner;
    var now = start;
    while (true) {
        const turn = try probe_run.drive(current, wire, in_flight, .{ .now = now });
        current = turn.runner;
        const wake = turn.wake_at orelse return current;
        now = wake;
    }
}

test "a round over the live transport measures what both arms answered" {
    var arm: Scripted = .{};
    arm.reported[@intFromEnum(Family.v4)] = public_v4;
    arm.reported[@intFromEnum(Family.v6)] = public_v6;
    arm.https = .{ .replied = .{ .status = .ok, .elapsed = millis(7) } };

    var wire = liveOver(&arm);
    const relays = [_]RelayUrl{ relay_a, relay_b };
    var results: probe.Results = .{};
    var in_flight: probe_run.InFlight = .{};
    const runner = try runRound(wire.seam(), try probe.new(.{
        .relays = &relays,
        .if_state = .{ .have_v4 = true, .have_v6 = true },
        .protocols = .{ .https = true, .qad_ipv4 = true, .qad_ipv6 = true },
        .now = start,
    }, &results), &in_flight);

    // Both families came back from the QUIC arm and both are what the relay
    // reported: the transport hands the address over as it was given and does
    // not canonicalise it, which is `report.fold`'s check to make.
    try t.expect(runner.results.slice().len > 0);
    try t.expectEqual(@as(usize, 2), probe.measured(.qad_ipv4, results.slice()));
    try t.expectEqual(@as(usize, 2), probe.measured(.qad_ipv6, results.slice()));
    const v4_answer = results.slice()[0];
    try t.expectEqual(millis(0), v4_answer.latency());
    // Every exchange that answered was retired by `poll`, so nothing was left
    // for `close` to stop and the table is empty again.
    try t.expectEqual(@as(usize, 0), arm.stops);
    for (wire.slots) |slot| try t.expect(slot == null);
}

test "a relay that answers nothing is a retired probe and no measurement" {
    var arm: Scripted = .{};
    var wire = liveOver(&arm);
    const relays = [_]RelayUrl{relay_a};
    var results: probe.Results = .{};
    var in_flight: probe_run.InFlight = .{};
    var runner = try runRound(wire.seam(), try probe.new(.{
        .relays = &relays,
        .if_state = .{ .have_v4 = true, .have_v6 = false },
        .protocols = .{ .https = true, .qad_ipv4 = true, .qad_ipv6 = false },
        .now = start,
    }, &results), &in_flight);
    runner = runner;

    try t.expectEqual(@as(usize, 0), results.len);
    // Three QUIC exchanges opened and none of them answered, so each was stopped
    // on the way out rather than left running.
    try t.expectEqual(probe.max_relays * 2, arm.stops);
    for (wire.slots) |slot| try t.expect(slot == null);
}

test "the check rules a portal in, out, and neither" {
    var arm: Scripted = .{};
    var wire = liveOver(&arm);
    const at: probe_run.Check = .{
        .relay = relay_a,
        .at = start,
        .deadline = start +| probe.captive_portal_delay +| probe.captive_portal_timeout,
    };

    // A relay that answered with success rules a portal out.
    arm.https = .{ .replied = .{ .status = .ok, .elapsed = millis(3) } };
    try wire.seam().vtable.beginCheck(@ptrCast(&wire), at);
    try t.expectEqual(@as(?bool, false), wire.seam().vtable.pollCheck(@ptrCast(&wire), start));
    wire.seam().vtable.endCheck(@ptrCast(&wire), .answered);

    // A redirect is the answer a captive portal gives.
    arm.https = .{ .replied = .{ .status = .found, .elapsed = millis(3) } };
    try wire.seam().vtable.beginCheck(@ptrCast(&wire), at);
    try t.expectEqual(@as(?bool, true), wire.seam().vtable.pollCheck(@ptrCast(&wire), start));
    wire.seam().vtable.endCheck(@ptrCast(&wire), .answered);

    // A relay behind a portal that never answered is not a relay that has none,
    // and a 404 is a status rather than a portal.
    for ([_]HttpsAnswer{ .silent, .{ .replied = .{ .status = .not_found, .elapsed = 0 } } }) |answer| {
        arm.https = answer;
        try wire.seam().vtable.beginCheck(@ptrCast(&wire), at);
        try t.expect(wire.seam().vtable.pollCheck(@ptrCast(&wire), start) == null);
        wire.seam().vtable.endCheck(@ptrCast(&wire), .expired);
    }

    // One check at a time, and nothing at all before one begins.
    try t.expect(wire.seam().vtable.pollCheck(@ptrCast(&wire), start) == null);
    try wire.seam().vtable.beginCheck(@ptrCast(&wire), at);
    try t.expectError(error.Full, wire.seam().vtable.beginCheck(@ptrCast(&wire), at));
}

test "a stopped transport refuses to start anything more" {
    var arm: Scripted = .{};
    var wire = liveOver(&arm);
    const open: probe_run.Open = .{
        .task = .{ .proto = .qad_ipv4, .relay = 0, .attempt = 0 },
        .relay = relay_a,
        .at = start,
        .deadline = start +| probe.probe_timeout,
    };
    const ctx: *anyopaque = @ptrCast(&wire);

    try wire.seam().vtable.open(ctx, open);
    wire.stop();
    try t.expectError(error.Canceled, wire.seam().vtable.open(ctx, open));
    try t.expectError(
        error.Canceled,
        wire.seam().vtable.beginCheck(ctx, .{
            .relay = relay_a,
            .at = start,
            .deadline = start +| probe.captive_portal_timeout,
        }),
    );
    // The probe opened before the stop is still owed a close, and closing it is
    // what stops the exchange it began.
    wire.seam().vtable.close(ctx, open.task, .canceled);
    try t.expectEqual(@as(usize, 1), arm.stops);
}

test "the table is the round's bound, and a refused relay is silence" {
    var arm: Scripted = .{};
    var wire = liveOver(&arm);
    const ctx: *anyopaque = @ptrCast(&wire);
    const open: probe_run.Open = .{
        .task = .{ .proto = .https, .relay = 0, .attempt = 0 },
        .relay = relay_a,
        .at = start,
        .deadline = start +| probe.probe_timeout,
    };

    // A relay that could not be reached is a probe that never answers: the slot
    // is taken, no refusal comes back, and nothing is measured.
    arm.refuses = true;
    try t.expectError(error.Refused, arm.qad().start(arm, relay_a, .v4));
    try wire.seam().vtable.open(ctx, open);
    try t.expect(wire.seam().vtable.poll(ctx, start) == null);

    var filled: usize = 0;
    while (filled < probe.max_tasks) : (filled += 1) {
        try wire.seam().vtable.open(ctx, open);
    }
    try t.expectError(error.Full, wire.seam().vtable.open(ctx, open));
    try t.expectEqual(probe.max_tasks, filled);
}