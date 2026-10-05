//! One connection attempt: the address it names, the identity it presents, the
//! instant it is over, and what became of it.
//!
//! Pure data. No socket, no allocator, no clock — an instant arrives as an
//! argument and a settled attempt is a value. `holepunch_trigger.zig` builds
//! these and settles them; nothing here decides *which* attempt runs, so
//! nothing here can be wrong about that.
//!
//! # Every field is held by value
//!
//! A `Target` borrows nothing: the address and the node id are both inline, so
//! a copied `Target` reads its own bytes and the two copies cannot drift. That
//! is the same reason `holepunch_gate.Attempt` drops its `local` field, and the
//! module doc there says what a value holding a pointer into itself costs.
//!
//! # Why a target holds no socket
//!
//! **The owner closes it, and `settle` is what tells it whether it owned one.**
//! A superseded attempt's descriptor was opened by whoever opened it, and the
//! only state in which a live descriptor was ever handed out is `pending` — so
//! `Settled.released` is that answer, and it is a fact about the transition
//! rather than a promise the caller has to reconstruct. Putting the descriptor
//! in the value would make a copied `Target` copy a handle, and would give the
//! deadline authority to free something the owner still reads.
//!
//! # No wire, and nothing unpinned
//!
//! Not one byte passes through this file. Upstream's `HolepunchAttempt`
//! (`iroh/src/socket/remote_map/remote_state.rs`) is *one*
//! `initiate_nat_traversal_round` over the whole candidate set, so there is no
//! upstream byte sequence for a per-candidate attempt and none is claimed here.
//! `docs/DECISIONS/0001` records that the call itself is not in this tree yet.
//! What these values cost upstream is one field: the stack's own round has no
//! deadline of its own, so a deadline added per candidate is an ozai
//! construction and is pinned by the tests in this file, not by a vector.

const std = @import("std");
const addr = @import("../base/addr.zig");
const holepunch = @import("holepunch.zig");

const NodeId = addr.NodeId;
const SocketAddr = addr.SocketAddr;

/// Nanoseconds on a monotonic timeline the caller owns.
///
/// `net/report.zig` defines it and `holepunch.zig` re-exports it for the gate,
/// and this file reuses that rather than spelling a third one: two definitions
/// of "an instant" in one layer is a conversion nobody wants.
pub const Nanos = holepunch.Nanos;

/// What became of an attempt.
///
/// `pending` is the absence of an outcome rather than a fifth outcome, and it
/// is the only state in which the attempt owns anything — see the module doc.
pub const Outcome = enum {
    /// In flight. It has a deadline and nothing else.
    pending,
    /// The peer's handshake completed on this address.
    connected,
    /// The stack named this address and would not open a path on it.
    refused,
    /// The deadline passed with no answer.
    timed_out,
    /// Another attempt settled first, or the gate ended punching.
    superseded,
};

comptime {
    // The tree adds a variant when upstream does, so the count is pinned here
    // and a variant added without a settle arm fails the build rather than
    // inheriting a default nobody chose. `holepunch_gate.zig` does this for
    // `NatTraversalError` for the same reason.
    if (@typeInfo(Outcome).@"enum".fields.len != 5) {
        @compileError("an Outcome variant has no settle arm");
    }
}

/// One attempt at one address.
///
/// A value with no lifetime of its own: everything is inline, so a copy is
/// independent of the original. `deadline` is absolute rather than a budget,
/// because a target is copied between the turn that started it and the turn
/// that reads it, and a budget measured from a moment nobody stores would be
/// measured from a different moment each time.
pub const Target = struct {
    /// The address this attempt punches at.
    addr: SocketAddr,
    /// The peer identity the attempt presents and then expects back.
    peer: NodeId,
    /// When it went out, on the caller's own timeline.
    started: Nanos,
    /// When it stops counting. Past this instant the attempt is `.timed_out`
    /// whatever the owner does, because `expired` reads the same field.
    deadline: Nanos,
    /// What became of it. Only `settle` writes this.
    outcome: Outcome = .pending,
    /// When it became that, or null while it is `.pending`.
    settled_at: ?Nanos = null,
};

/// What one attempt became, and whether the caller had something to release.
pub const Settled = struct {
    /// The attempt after the transition. Equal to the input when the
    /// transition was refused, and that equality is how a caller tells.
    target: Target,
    /// The caller held a live descriptor for this attempt and owns the close.
    ///
    /// True exactly when the attempt was `.pending` before the call and the
    /// transition was not refused: `pending` is the only state in which a
    /// descriptor was ever handed out. A refused transition releases nothing,
    /// and a second settle on an already-settled attempt releases nothing
    /// either — the first answer is the only answer that had a socket open.
    released: bool,
};

/// What one answer to an attempt did.
///
/// `now` is the current instant on the caller's timeline, and is used for
/// every outcome except `.timed_out`, which is stamped at `deadline` instead.
/// A poller that runs late must not be able to make a timeout look later than
/// the timeout was; the deadline is when it happened, whatever the clock said
/// when somebody noticed.
pub fn settle(self: Target, now: Nanos, outcome: Outcome) Settled {
    // `pending` is not an answer, and settling into it would leave a live
    // attempt with a settled instant and no outcome to justify it.
    if (outcome == .pending) return .{ .target = self, .released = false };
    // The first answer wins. A late answer to an attempt another answer
    // already closed must not rewrite history: the socket is gone and the
    // answer describes a connection nobody is holding.
    if (self.outcome != .pending) return .{ .target = self, .released = false };
    // A timeout before the deadline is refused rather than clamped. This is the
    // same rule `probe_run_turn.zig` follows in the other direction — take what
    // came back before giving anything up — and it is why the boundary is a
    // refusal and not a clamped instant.
    if (outcome == .timed_out and now < self.deadline) {
        return .{ .target = self, .released = false };
    }
    return .{
        .target = .{
            .addr = self.addr,
            .peer = self.peer,
            .started = self.started,
            .deadline = self.deadline,
            .outcome = outcome,
            .settled_at = if (outcome == .timed_out) self.deadline else now,
        },
        .released = true,
    };
}

/// Whether this attempt is past its deadline and still in flight.
///
/// The same instant `settle` stamps a timeout at, so an owner that asks this
/// at `deadline` and then settles is never refused, and one that settles
/// before it is refused rather than silently timed out early.
pub fn expired(self: Target, now: Nanos) bool {
    return self.outcome == .pending and now >= self.deadline;
}

/// Whether this attempt still owns anything.
pub fn settled(self: Target) bool {
    return self.outcome != .pending;
}

const t = std.testing;

fn ip(port: u16) SocketAddr {
    return .{ .ip = .{ .v4 = .{ 192, 0, 2, 1 } }, .port = port };
}

const peer: NodeId = NodeId.fromBytes([_]u8{9} ** 32) catch
    @compileError("the fixed test peer is not a canonical ed25519 point");

/// An in-flight attempt on `port`, started at `start` with a 1 s deadline.
fn live(start: Nanos, port: u16) Target {
    return .{
        .addr = ip(port),
        .peer = peer,
        .started = start,
        .deadline = start + std.time.ns_per_s,
    };
}

test "an answer inside the budget settles, and a timeout is stamped at the deadline" {
    const start: Nanos = 1_000;
    const answered = settle(live(start, 4000), start + std.time.ns_per_ms, .connected);
    try t.expectEqual(Outcome.connected, answered.target.outcome);
    try t.expectEqual(start + std.time.ns_per_ms, answered.target.settled_at.?);
    try t.expect(answered.released);

    // The same attempt, polled a full second late. The timeout is the deadline,
    // not the instant the poller noticed: `settled_at` is the deadline, so two
    // owners polling at different instants file the same timeout.
    const late = settle(live(start, 4001), start + std.time.ns_per_s * 2, .timed_out);
    try t.expectEqual(Outcome.timed_out, late.target.outcome);
    try t.expectEqual(start + std.time.ns_per_s, late.target.settled_at.?);
    try t.expect(late.released);
}

test "the first answer is the only one that releases anything" {
    const start: Nanos = 1_000;
    const first = settle(live(start, 4000), start, .refused);
    try t.expectEqual(Outcome.refused, first.target.outcome);
    try t.expect(first.released);

    // A second answer on the same attempt, and on the one the first answer
    // produced. Nothing is left to release, so nothing is claimed to be.
    const second = settle(first.target, start + 1, .connected);
    try t.expectEqual(Outcome.refused, second.target.outcome);
    try t.expectEqual(start, second.target.settled_at.?);
    try t.expect(!second.released);
    try t.expect(std.meta.eql(first.target, second.target));
}

test "a timeout before the deadline is refused rather than clamped" {
    const start: Nanos = 1_000;
    const early = settle(live(start, 4000), start, .timed_out);
    try t.expectEqual(Outcome.pending, early.target.outcome);
    try t.expect(early.target.settled_at == null);
    try t.expect(!early.released);

    // One nanosecond later it is not early any more, and the same call settles.
    const on_time = settle(live(start, 4000), start + std.time.ns_per_s, .timed_out);
    try t.expectEqual(Outcome.timed_out, on_time.target.outcome);
    try t.expect(on_time.released);
}

test "pending is not an outcome, and expiry asks for it" {
    const start: Nanos = 1_000;
    const attempt = live(start, 4000);
    const same = settle(attempt, start + std.time.ns_per_ms, .pending);
    try t.expect(std.meta.eql(attempt, same.target));
    try t.expect(!same.released);

    // Expiry is the deadline and nothing else: one nanosecond before, nothing
    // has happened; at it, the attempt is past due and still in flight.
    try t.expect(!attempt.expired(attempt.deadline - 1));
    try t.expect(attempt.expired(attempt.deadline));
    try t.expect(!attempt.settled());
    try t.expect(live(start, 4000).expired(attempt.deadline + std.time.ns_per_s));

    // A settled attempt is never expired again, so a poller cannot time out a
    // connection that already answered.
    try t.expect(!same.target.expired(attempt.deadline + std.time.ns_per_s));
    try t.expect(settle(attempt, start, .connected).target.settled());
    try t.expect(!settle(attempt, start, .connected).target.expired(attempt.deadline + 1));
}

test "a copy of an attempt reads its own bytes" {
    const original = live(1_000, 4000);
    const copy = original;
    try t.expect(std.meta.eql(original, copy));

    // Settling the original leaves the copy in flight, and the copy settles to
    // the same value the original would have: nothing in a `Target` points into
    // another `Target`, so the two cannot read each other's bytes.
    const settled_original = settle(original, 2_000, .connected).target;
    try t.expectEqual(Outcome.pending, copy.outcome);
    try t.expect(std.meta.eql(settle(copy, 2_000, .connected).target, settled_original));
    try t.expect(std.meta.eql(copy, original));
}