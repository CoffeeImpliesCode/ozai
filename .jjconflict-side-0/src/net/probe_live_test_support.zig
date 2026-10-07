//! The two seams `net/probe_live.zig`'s tests stand on: a scripted HTTPS
//! connection and a scripted address-discovery arm, plus the relay names and
//! the round loop that drive them.
//!
//! Nothing here is a probe. Both doubles stand in for a layer that lives above
//! `net` — a socket, a trust bundle, the node's entropy — and neither can prove
//! that such a layer exists, which is the gap `probe_live.zig`'s own module doc
//! names. What they do carry is everything this file computes for real: the
//! request it frames, the budget arithmetic, the two clocks and the refusal
//! rule.
//!
//! `discovery/lookup_test_support.zig` is the same arrangement for the lookup
//! seam, and the reason this file exists rather than a second copy of the
//! doubles inside `probe_live.zig`: that file's tests are half its size, and
//! the halves are different responsibilities — one is the seam's own
//! implementation, the other is the harness that exercises it.

const std = @import("std");

const addr = @import("../base/addr.zig");
const probe = @import("probe.zig");
const probe_run = @import("probe_run.zig");
const report = @import("report.zig");

const live = @import("probe_live.zig");

const Live = live.Live;
const Qad = live.Qad;
const Stream = live.Stream;
const Error = live.Error;
const Nanos = report.Nanos;
const RelayUrl = addr.RelayUrl;
const SendError = probe_run.SendError;
const Why = probe_run.Why;

/// A minute in, on the timeline the rounds are handed. Far past every probe
/// instant, and on the same side of nothing.
pub const start: Nanos = 600 * std.time.ns_per_s;

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

/// A clean network answers the check with a `204`; anything else is somebody
/// else's answer and is a portal.
pub fn portal(status: u16) ?bool {
    return status != 204;
}

/// The injected connection, scripted: what the exchange wrote, every wait it
/// was handed, and every open and close counted.
pub const Script = struct {
    vtable: Stream.VTable = .{
        .open = scriptOpen,
        .write = scriptWrite,
        .read = scriptRead,
        .close = scriptClose,
    },
    /// What the relay answers with. Empty is a peer that half-closes at once.
    answer: []const u8 = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n",
    /// What `open` refuses with, or null to connect.
    fault: ?Error = null,
    buffer: [1024]u8 = undefined,
    /// The **first** request any connection was given, and its length. Later
    /// ones are counted rather than kept, because a round sends up to fifteen
    /// and `sent` is only ever read to show what went out on the wire; a
    /// buffer sized for all of them would put a length this file does not own
    /// in the way of a request that is about to be answered.
    request: [512]u8 = undefined,
    request_len: usize = 0,
    /// How many requests were written, first and later.
    writes: usize = 0,
    /// How far into `answer` the open connection has read. **Reset by every
    /// successful `open`**, because each one is a new connection and a new
    /// connection is answered from the start of the relay's answer.
    read_at: usize = 0,
    /// Every `timeout_ms` the exchange handed over, and how many there were.
    waits: [32]i32 = @splat(0),
    waits_len: usize = 0,
    /// Every `open` call, refused or not. A refused one is a GET that went out
    /// and reached nothing, which is what the round's budget retires.
    attempted: usize = 0,
    /// Connections established, which is what `close` is owed for: `Stream`
    /// spells it "a failed `open` owes no `close`", so this counts the opens
    /// that succeeded and `closed` must equal it.
    opened: usize = 0,
    closed: usize = 0,

    pub fn stream(self: *Script) Stream {
        return .{ .vtable = &self.vtable, .ctx = self };
    }

    fn note(self: *Script, timeout_ms: i32) void {
        if (self.waits_len == self.waits.len) return;
        self.waits[self.waits_len] = timeout_ms;
        self.waits_len += 1;
    }

    pub fn sent(self: *const Script) []const u8 {
        return self.request[0..self.request_len];
    }
};

fn scriptOpen(ctx: *anyopaque, _: RelayUrl, timeout_ms: i32) Error!void {
    const self: *Script = @ptrCast(@alignCast(ctx));
    self.attempted += 1;
    self.note(timeout_ms);
    if (self.fault) |refusal| return refusal;
    self.opened += 1;
    self.read_at = 0;
}

fn scriptWrite(ctx: *anyopaque, bytes: []const u8) Error!void {
    const self: *Script = @ptrCast(@alignCast(ctx));
    self.writes += 1;
    if (self.request_len != 0) return;
    if (bytes.len > self.request.len) return error.RequestTooLong;
    @memcpy(self.request[0..bytes.len], bytes);
    self.request_len = bytes.len;
}

fn scriptRead(ctx: *anyopaque, into: []u8, timeout_ms: i32) Error!usize {
    const self: *Script = @ptrCast(@alignCast(ctx));
    self.note(timeout_ms);
    if (self.read_at >= self.answer.len) return 0;
    const take = @min(into.len, self.answer.len - self.read_at);
    @memcpy(into[0..take], self.answer[self.read_at..][0..take]);
    self.read_at += take;
    return take;
}

fn scriptClose(ctx: *anyopaque) void {
    const self: *Script = @ptrCast(@alignCast(ctx));
    self.closed += 1;
}

/// The injected QAD arm, scripted: one answer per task after `think`, timed on
/// the round's own clock, with every open and close counted.
pub const Wire = struct {
    vtable: Qad.VTable = .{
        .open = qadOpen,
        .poll = qadPoll,
        .close = qadClose,
    },
    reported: addr.SocketAddr = .{
        .ip = .{ .v4 = .{ 198, 51, 100, 7 } },
        .port = 41234,
    },
    think: Nanos = 0,
    live: [probe.max_tasks]probe_run.Open = undefined,
    live_len: usize = 0,
    answered: [probe.max_tasks]bool = @splat(false),
    why: [probe.max_tasks]Why = @splat(.canceled),
    opened: usize = 0,
    closed: usize = 0,

    pub fn arm(self: *Wire) Qad {
        return .{ .vtable = &self.vtable, .ctx = self };
    }

    pub fn closedAs(self: *const Wire, reason: Why) usize {
        var total: usize = 0;
        for (self.why[0..self.live_len]) |slot| total += @intFromBool(slot == reason);
        return total;
    }
};

fn qadOpen(ctx: *anyopaque, at: probe_run.Open) SendError!void {
    const self: *Wire = @ptrCast(@alignCast(ctx));
    if (self.live_len == probe.max_tasks) return error.Full;
    self.live[self.live_len] = at;
    self.live_len += 1;
    self.opened += 1;
}

fn qadPoll(ctx: *anyopaque, now: Nanos) ?probe_run.Reply {
    const self: *Wire = @ptrCast(@alignCast(ctx));
    for (self.live[0..self.live_len], 0..) |at, index| {
        if (self.answered[index]) continue;
        if (now -| at.at < self.think) continue;
        self.answered[index] = true;
        return .{
            .task = at.task,
            // The round's clock, and the only span the round has: from the
            // instant the probe went out to the instant its answer was polled.
            .value = .{ .qad = .{ .latency = now - at.at, .reported = self.reported } },
        };
    }
    return null;
}

fn qadClose(ctx: *anyopaque, task: probe.Task, why: Why) void {
    const self: *Wire = @ptrCast(@alignCast(ctx));
    self.closed += 1;
    for (self.live[0..self.live_len], 0..) |at, index| {
        if (std.meta.eql(at.task, task)) self.why[index] = why;
    }
}

/// A `Live` over `script`, with `qad` armed or not.
pub fn transport(script: *Script, qad: ?Qad) Live {
    return Live.init(std.testing.io, .{
        .stream = script.stream(),
        .response = &script.buffer,
        .probe_path = "/ping",
        .check = .{ .path = "/portal-check", .verdict = portal },
        .qad = qad,
    });
}

/// A whole round, one `wake_at` at a time: the loop `probe_run.drive`'s own
/// module doc writes out.
pub fn runRound(live_in: *Live, runner: probe.Runner, check_relay: ?RelayUrl) !probe.Runner {
    var in_flight: probe_run.InFlight = .{};
    var current = runner;
    var now = start;
    while (true) {
        const turn = try probe_run.drive(current, live_in.transport(), &in_flight, .{
            .check_relay = check_relay,
            .now = now,
        });
        current = turn.runner;
        now = turn.wake_at orelse return current;
    }
}
