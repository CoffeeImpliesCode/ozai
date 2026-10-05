//! Whether a relay connection is still there: the ping clock, and the decision
//! to retire a peer that stopped answering.
//!
//! `relay/client.zig` owns the round trip itself — `PingTracker` draws the
//! deadline, matches the pong and clamps the next one into its band. What it
//! does not own is the connection around it: when a ping is *owed*, what else
//! counts as hearing from the peer, and what a caller does with a ping that was
//! never answered. Those are three questions about one connection's lifecycle
//! and they belong here, next to the tracker rather than inside it.
//!
//! # Traffic does not answer a ping
//!
//! **A frame that arrives is proof the peer is there, and it is not the answer
//! to a ping.** Upstream's client actor breaks out of its loop on
//! `Timeout::Expired` whatever else arrived (`ping_tracker.rs:96-105`), and the
//! tracker clears `pending` when it expires, so a pong that arrives afterwards
//! measures nothing. This file keeps that rule whole: `heard` moves the *next*
//! ping out — a relay pings an otherwise idle connection, which is what
//! `client.ping_interval` says — and leaves an outstanding ping outstanding.
//! A peer that keeps sending datagrams and cannot answer a ping within three of
//! its own measured round trips is not a peer to keep a relay slot for, and
//! relaxing that here would be a rule no frame in the protocol states.
//!
//! # One outstanding ping, and one answer per question
//!
//! `pingDue` refuses while a ping is outstanding, so at most one is ever in
//! flight and `check`'s `awaiting` arm is the only deadline a caller waits on.
//! `check` answers one of three things: `idle` with the time until a ping is
//! owed, `awaiting` with the time until the outstanding one expires, and
//! `retired` with the eight bytes of the ping that was lost. **`retired` is
//! terminal** — it absorbs every later call and returns the same bytes — so a
//! caller that keeps ticking after a peer went silent is told once, which is
//! the same "reported exactly once" property `server_registry.zig`'s guard has
//! and for the same reason.
//!
//! # Time is an argument
//!
//! Nothing here reads a clock. Every method takes `now` on the caller's
//! timeline, so the whole lifecycle of a connection — four pings answered, then
//! silence — is a scripted sequence of instants a test can run in a
//! microsecond, and a timeout is *compared* rather than waited on.
//!
//! The band is the tracker's and is not restated here: three round trips clamped
//! into `[min_health_check_timeout, max_timeout]`, which is upstream's
//! `ping_timeout` (`ping_tracker.rs:87-91`) and is tested where it is
//! implemented. What this file adds is the retirement decision and the
//! connection-scoped ping schedule.

const std = @import("std");
const client = @import("client.zig");

const std_testing = std.testing;

/// Nanoseconds on the caller's timeline. See `client.Nanos`.
pub const Nanos = client.Nanos;

/// The longest a pong may take by default. Upstream `PING_TIMEOUT`.
pub const default_max_timeout = client.default_max_timeout;

/// The shortest deadline a measured round trip may produce. Upstream
/// `MIN_HEALTH_CHECK_TIMEOUT`.
pub const min_health_check_timeout = client.min_health_check_timeout;

/// How often the relay pings an otherwise idle connection, by default. Upstream
/// `PING_INTERVAL`.
pub const default_ping_interval = client.ping_interval;

/// What one connection is held to.
///
/// **Every field is upstream's number and a caller may change it.** The band the
/// round trip is clamped into is `max_timeout`, and a value under
/// `min_health_check_timeout` is `error.MaxTimeoutBelowFloor` at `init` rather
/// than an assertion failure inside the first clamp — the same arrangement
/// `client.PingTracker.init` states.
pub const Config = struct {
    /// The ceiling on the deadline an outstanding ping gets.
    max_timeout: Nanos = default_max_timeout,
    /// How long a connection may be silent before a ping is owed.
    interval: Nanos = default_ping_interval,
};

/// What `init` refuses.
pub const InitError = client.PingTracker.InitError;

/// What the caller should do about a connection, with the time it has.
///
/// **Two arms are "keep going" and name two different clocks**, which is the
/// point of splitting them: `idle` is measured from the last thing heard and
/// `awaiting` from the ping that is out. A caller that waited the smaller of the
/// two would either ping a connection that owes an answer or wait for a
/// connection that owes a ping.
pub const Verdict = union(enum) {
    /// Nothing is outstanding. This is how long until a ping is owed.
    idle: Nanos,
    /// A ping is outstanding and this is how long its deadline has left.
    awaiting: Nanos,
    /// The outstanding ping was never answered, and these are the eight bytes
    /// that were lost. Terminal: every later call answers this arm with the
    /// same bytes.
    retired: [8]u8,
};

/// One connection's liveness, and the ping clock beside it.
pub const Liveness = struct {
    /// The round trip and the deadline it clamps into. Public because
    /// `client.PingTracker` says so: Zig has no private field, and a caller that
    /// wants to read the last round trip reads `roundTrip`.
    tracker: client.PingTracker,
    /// How long a connection may be silent before a ping is owed.
    interval: Nanos,
    /// When anything last arrived from the peer. The origin for `idle`.
    last_heard: Nanos,
    /// Whether the outstanding ping has already been given up on, and the bytes
    /// it carried. Together they are the terminal latch: a second retirement
    /// cannot be reported because the first one marked it.
    retired: bool,
    lost: [8]u8,

    /// A connection last heard from at `at`, with a caller-chosen band.
    pub fn init(config: Config, at: Nanos) InitError!Liveness {
        return .{
            .tracker = try client.PingTracker.init(config.max_timeout),
            .interval = config.interval,
            .last_heard = at,
            .retired = false,
            .lost = @splat(0),
        };
    }

    /// A connection with upstream's own numbers.
    pub fn withDefaults(at: Nanos) Liveness {
        return .{
            .tracker = client.PingTracker.withDefaults(),
            .interval = default_ping_interval,
            .last_heard = at,
            .retired = false,
            .lost = @splat(0),
        };
    }

    /// Something arrived from the peer: any frame, in either direction.
    ///
    /// **It moves the next ping and not the outstanding one**, for the reason the
    /// module doc gives. A caller that wants a connection held to its ping even
    /// while it talks calls only this and never `answered`.
    pub fn heard(self: *Liveness, now: Nanos) void {
        self.last_heard = now;
    }

    /// A `Pong` arrived carrying `data`.
    ///
    /// The match is the tracker's: only the eight bytes of the most recent ping
    /// count, and a pong for a superseded ping measures nothing. A connection
    /// already retired stays retired — a round trip from a peer this side has
    /// given up on is not a measurement.
    pub fn answered(self: *Liveness, now: Nanos, data: [8]u8) void {
        if (self.retired) return;
        self.tracker.pongReceived(now, data);
    }

    /// The eight bytes to put in a `Ping`, or null when no ping is owed.
    ///
    /// `data` is the caller's because a process-global RNG is what `base`
    /// forbids (`client.PingTracker.newPing` states the same rule). It is
    /// returned as well as taken, because the caller has to write it into the
    /// frame and the tracker's copy is a second value.
    ///
    /// Null is three different things and the caller cannot tell them apart by
    /// design: the peer has been heard from recently, a ping is already out, and
    /// this connection is retired. All three mean the same action, which is none.
    pub fn pingDue(self: *Liveness, now: Nanos, data: [8]u8) ?[8]u8 {
        if (self.retired) return null;
        if (self.tracker.pending != null) return null;
        if (now -| self.last_heard < self.interval) return null;
        return self.tracker.newPing(now, data);
    }

    /// What to do about this connection now.
    ///
    /// **A deadline is compared, never waited on**, so a test reaches the expiry
    /// in one call. **A clock that went backwards answers a whole interval and no
    /// ping**: the elapsed time saturates at zero, zero means "not yet", and a
    /// machine that cannot say when it last heard from a peer does not claim the
    /// peer is alive — it waits the interval and asks again. The same saturation
    /// is what keeps `newPing` from wrapping a deadline that is already at the
    /// end of the timeline.
    pub fn check(self: *Liveness, now: Nanos) Verdict {
        if (self.retired) return .{ .retired = self.lost };
        switch (self.tracker.timeout(now)) {
            .idle => return .{ .idle = self.interval -| (now -| self.last_heard) },
            .pending => |remaining| return .{ .awaiting = remaining },
            .expired => |data| {
                self.retired = true;
                self.lost = data;
                return .{ .retired = data };
            },
        }
    }

    /// The last measured round trip, or null when nothing has been measured.
    ///
    /// A caller logging a retirement usually wants this next to it: the deadline
    /// that expired was three times this, clamped.
    pub fn roundTrip(self: *const Liveness) ?Nanos {
        return self.tracker.last_rtt;
    }
};

// --- tests

const ms = std.time.ns_per_ms;

/// How many answered pings a scripted peer gets before it goes quiet. Bounded
/// because the loop is a loop.
const answered_rounds = 4;

// A peer that keeps answering its pings is never retired, and one that stops
// answering is retired at its deadline — the two answers from one script.
test "a peer that answers is not retired, and one that stops answering is" {
    const interval = 10 * ms;
    const max_timeout = 5 * std.time.ns_per_s;
    var peer = try Liveness.init(
        .{ .max_timeout = max_timeout, .interval = interval },
        0,
    );

    var now: Nanos = 0;
    var round: usize = 0;
    while (round < answered_rounds) : (round += 1) {
        // The peer speaks, goes quiet for one interval, and answers the ping that
        // silence owes it a round trip later. One script, both roles.
        peer.heard(now);
        try std_testing.expectEqual(Verdict{ .idle = interval }, peer.check(now));
        const data = peer.pingDue(now +| interval, @splat(@intCast(round + 1))) orelse
            return error.TestUnexpectedResult;
        // The outstanding ping's deadline is the tracker's own rule, three round
        // trips clamped — five seconds before anything has been measured, and the
        // health-check floor once it has.
        try std_testing.expectEqual(
            Verdict{ .awaiting = peer.tracker.pingTimeout() },
            peer.check(now +| interval),
        );
        peer.answered(now +| interval +| 10 * ms, data);
        now += interval +| 10 * ms;
        // Answered, so not retired, and the round trip is the ten milliseconds
        // this peer took — which is what the next deadline is built from.
        try std_testing.expectEqual(@as(?Nanos, 10 * ms), peer.roundTrip());
        switch (peer.check(now)) {
            .retired => return error.TestUnexpectedResult,
            else => {},
        }
    }

    // This one goes quiet after speaking, so the ping is owed three round trips
    // after it — clamped up to the health-check floor, because 3 × 10 ms is under
    // 500 ms. That floor is why a fast peer is retired sooner than its own speed
    // would suggest, and it is upstream's rule.
    peer.heard(now);
    const pinged_at = now +| interval;
    const lost = peer.pingDue(pinged_at, @splat(0xee)) orelse
        return error.TestUnexpectedResult;
    try std_testing.expectEqual(
        Verdict{ .awaiting = min_health_check_timeout },
        peer.check(pinged_at),
    );

    // It goes quiet. One nanosecond early is still alive; at the deadline it is
    // retired, and the bytes name the ping that was lost.
    const expiry = pinged_at +| min_health_check_timeout;
    try std_testing.expect(peer.check(expiry - 1).awaiting > 0);
    try std_testing.expectEqual(Verdict{ .retired = lost }, peer.check(expiry));

    // Terminal, and reported once: a later tick, a later instant and a late pong
    // all answer the same thing and change nothing.
    const later = expiry + std.time.ns_per_s;
    try std_testing.expectEqual(Verdict{ .retired = lost }, peer.check(later));
    peer.answered(later, lost);
    try std_testing.expect(peer.pingDue(later, @splat(0x01)) == null);
    try std_testing.expectEqual(Verdict{ .retired = lost }, peer.check(later));
}

// A relay pings an idle connection; a connection that is talking owes nothing.
test "a peer that keeps talking is not pinged, and its silence clock restarts" {
    const interval = 10 * ms;
    var peer = try Liveness.init(.{
        .max_timeout = 5 * std.time.ns_per_s,
        .interval = interval,
    }, 0);

    // A frame arrives, and the whole interval is owed again from it: the time
    // until a ping is due is measured from the last thing heard, not from the
    // connection.
    peer.heard(interval - 1);
    try std_testing.expect(peer.pingDue(interval - 1, @splat(0x01)) == null);
    try std_testing.expectEqual(
        Verdict{ .idle = interval },
        peer.check(interval - 1),
    );

    // The interval is measured from that frame and not from the connection, so
    // the ping is owed a whole interval after it and not a nanosecond before.
    const due = interval - 1 +| interval;
    try std_testing.expect(peer.pingDue(due - 1, @splat(0x02)) == null);
    _ = peer.pingDue(due, @splat(0x02)) orelse return error.TestUnexpectedResult;
    // And at most one is ever outstanding: the same instant owes no second ping.
    try std_testing.expect(peer.pingDue(due, @splat(0x03)) == null);

    // Traffic does not answer a ping that is already out: the connection is
    // still held to it, which is the rule the module doc states.
    peer.heard(due);
    try std_testing.expect(peer.check(due).awaiting > 0);
}

// A clock that went backwards waits rather than claiming liveness it cannot
// prove.
test "a timeline that went backwards waits a whole interval and pings nothing" {
    var peer = try Liveness.init(.{
        .max_timeout = 5 * std.time.ns_per_s,
        .interval = 100 * ms,
    }, 10 * ms);

    // Nine milliseconds "before" the last thing heard. The elapsed time
    // saturates at zero, zero means not yet, and so the whole interval is owed
    // and no ping is due: a machine that cannot say when it last heard from a
    // peer does not report the peer healthy.
    try std_testing.expectEqual(Verdict{ .idle = 100 * ms }, peer.check(ms));
    try std_testing.expect(peer.pingDue(ms, @splat(0x01)) == null);

    // And the timeline recovers: from the last thing heard the interval is the
    // ordinary rule again.
    try std_testing.expect(peer.pingDue(10 * ms + 100 * ms, @splat(0x02)) != null);
}

// A ceiling under the floor is refused up front rather than at the first clamp.
test "a ceiling under the health-check floor is refused at init" {
    try std_testing.expectError(
        error.MaxTimeoutBelowFloor,
        Liveness.init(.{ .max_timeout = min_health_check_timeout - 1 }, 0),
    );
    const peer = try Liveness.init(.{ .max_timeout = min_health_check_timeout }, 0);
    try std_testing.expect(peer.tracker.max_timeout == min_health_check_timeout);
}
