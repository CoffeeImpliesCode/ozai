//! The loop: one pass, the wait between passes, the clock, the stop, and the
//! wind-down a `run` owes on the way out.
//!
//! `node.zig`'s module doc states the shape — "`step` is one pass over the
//! kernel, the core, the endpoint's actions and the gossip layer; `run` is
//! `step` in a loop with a clock" — and this is the half of that sentence
//! which is not one pass. The pass itself is `Node.step`, beside the data it
//! walks, because its ordering is the whole of what it is.

const std = @import("std");

const node_mod = @import("node.zig");
const node_config = @import("node_config.zig");
const node_build = @import("node_build.zig");
const node_close = @import("node_close.zig");

const bridge_mod = @import("../transport/quic_bridge.zig");

const Self = node_mod.Node;
const Error = node_config.Error;
const Instant = bridge_mod.Instant;

/// How long `run` blocks on the socket when a pass moved nothing.
///
/// A poll loop has no timer wheel, so this interval *is* the resolution the
/// QUIC timers and the gossip clocks are served at, and it is also how long a
/// stop signal waits to be seen: `Socket.awaitReadable` retries a signal
/// rather than letting it out. A quarter of a second is coarse for a datagram
/// path and right for the two things this loop is actually waiting on — a
/// peer's handshake and membership's shuffles — and it is the honest ceiling
/// of a loop with no scheduler to hold deadlines (`DECISIONS/0002`) and no
/// send path on `Io.Uring`.
pub const poll_interval_ms = 250;

/// The loop's stop signal: a flag a signal handler can set, and a deadline the
/// loop checks against the clock it already reads.
///
/// `request` is async-signal-safe — one atomic store and nothing else — which
/// is why `src/node/main.zig` may call it from a `SIGINT` handler while the
/// loop is inside `poll`.
///
/// It is a parameter of `run` and not a field of `Node` for the same reason
/// `Io` is: the thing being asked to stop should be a value the caller holds,
/// so a caller can hold two of them and stop them independently.
///
/// Only `request` may run concurrently with `run`. Set the deadline before
/// starting the loop; `due` is not atomic. A request is not a join and does not
/// release the node. Wait for `run` to return before releasing either value.
/// Copies hold separate latches and deadlines.
pub const Stop = struct {
    /// Whether anybody has asked. Atomic because `request` may be called from
    /// a signal handler while the loop is inside `poll`, and one store is the
    /// whole of what a handler is allowed to do.
    flag: std.atomic.Value(bool) = .init(false),
    /// The instant this becomes due, in the loop's own clock, or null for
    /// never. It lives here so a caller that wants a bounded run needs neither
    /// a second clock nor a thread; the loop reads one every pass and checks
    /// this against it.
    ///
    /// A deadline is not a stop *signal*, and this module does not pretend it is.
    /// The signal path is `request`; the binary's `--for` sets `due` and is a
    /// convenience over the same loop exit.
    due: ?Instant = null,

    /// A signal nobody has raised and no deadline set.
    pub fn init() Stop {
        return .{};
    }

    /// Ask the loop to wind down.
    pub fn request(self: *Stop) void {
        self.flag.store(true, .release);
    }

    /// Whether anything has asked the loop to wind down, from a signal handler
    /// or from the caller's own code. The flag records no provenance, because
    /// `request` is public and either is a legitimate reason.
    pub fn requested(self: *const Stop) bool {
        return self.flag.load(.acquire);
    }

    /// Stop at `at`. This is the caller saying when, not the loop asking.
    /// Set this before the loop starts, not from a concurrent thread or handler.
    pub fn expireAt(self: *Stop, at: Instant) void {
        self.due = at;
    }

    /// Whether the loop should end, from a signal or from the deadline.
    pub fn expired(self: *const Stop, at: Instant) bool {
        if (self.requested()) return true;
        const due = self.due orelse return false;
        return at >= due;
    }
};

/// Block until the socket has something, or `timeout_ms` passes.
///
/// A datagram this takes is parked in `held` rather than dropped, because
/// the kernel has already handed it over and `take` cannot ask for it
/// again. The timeout is what wakes the loop for gossip timers on an idle
/// socket, and it also bounds how long a stop signal waits to be seen:
/// `Socket.awaitReadable` retries a signal rather than letting it out, so
/// a stop is acted on at the next timeout and not at the next datagram.
///
/// `error.Canceled` is forwarded. The socket checks `io` before its
/// syscalls, but runtime cancellation alone does not wake its raw poll.
/// `Socket.stop` wakes it; a finite timeout bounds the next check.
/// `run` closes the node on cancellation. A caller driving passes itself
/// must do the same.
pub fn wait(self: *Self, io: std.Io, timeout_ms: i32) Error!void {
    if (self.held != null) return;
    const got = self.socket.receive(
        io,
        self.buf,
        &self.control,
        timeout_ms,
    ) catch |err| switch (err) {
        // A poll that timed out is not a failure: the loop's own tick is
        // the only reason to wake with nothing.
        error.WouldBlock => return,
        else => return err,
    };
    self.held = got;
}

/// The loop, with a clock. `stop` ends it, and the node is closed either
/// way.
///
/// **The node is closed on every exit, and the promise covers the exits
/// this loop did not choose.** A pass can fail — a socket write the `Io`
/// refuses, a bridge that would not allocate, a `checkCancel` answered with
/// `error.Canceled` — and the `errdefer` below is what closes the node then.
/// It is registered *before* the first clock read, because `create` has
/// already opened the descriptor and a clock this node cannot use is an exit
/// like any other.
///
/// **The error the loop failed with is what `run` returns.** A close that
/// fails as well is reported at error level beside it and never in place of
/// it: a caller that asked to be cancelled has to hear `error.Canceled` and
/// not the residue of cleaning up after it. `windDown` is that close and
/// `dispose` is the backstop behind it.
///
/// **The instant this loop reads is the instant the close is stamped
/// with.** A peer driven on a clock of its own — a test's virtual one —
/// reads close times from a timeline this loop is not on, and waits out its
/// own retransmit timeout to believe one. Two ends of a connection on two
/// clocks are two nodes' worth of answers, which is `step`'s rule and this
/// loop's.
///
/// The stop is checked once per pass, before the pass rather than after it,
/// so a signal that lands while `wait` is inside `poll` costs at most
/// `poll_interval_ms` — the same bound `Socket.awaitReadable` names.
///
/// One thread, one `run`, and never from a signal handler. See `Node`.
pub fn run(self: *Self, io: std.Io, stop: *const Stop) Error!void {
    // The instant of the pass being run, and null until one has been read.
    // A close needs an instant to stamp a connection close with and a
    // disposal does not, which is what makes this the right type for the
    // register below rather than a plain `Instant`.
    var at: ?Instant = null;
    errdefer windDown(self, io, at);
    var dialled = false;
    while (true) {
        const now = try instantOf(io);
        at = now;
        if (stop.expired(now)) {
            // The break is taken on a pass that read a clock, so this close
            // carries the instant it stamps its connection closes with.
            try node_close.close(self, io, now, self.generator());
            break;
        }
        // The dials happen on the first pass rather than in the caller, so
        // that a stop raised before the loop is entered closes a node that
        // never dialled anything — which is what `start` is idempotent
        // for. A caller that dials before `run` reaches the same state, and
        // this line costs nothing.
        if (!dialled) {
            dialled = true;
            try node_build.start(self, now, self.generator());
        }
        // The pass's own answer is not read here. A poll loop has one tick,
        // and whether the tick moved anything changes what the caller may
        // do next rather than how long this loop waits; `step`'s `bool` is
        // for a caller driving passes itself, which is what the test at the
        // bottom of `node.zig` is.
        _ = try self.step(io, now, self.generator());
        try self.wait(io, poll_interval_ms);
    }
}

/// The close a failed `run` owes: a graceful one where there is an instant
/// to stamp it with, and the disposal behind it in every case.
///
/// **The graceful half runs with cancellation protection switched on**
/// (`std.Io.CancelProtection`), which is the runtime's own answer to
/// "finish this": every `Io` call inside it stops being a cancellation
/// point, so this module does not have to guess which of its calls a backend
/// consults. The previous setting is restored on the way out.
///
/// It is bounded — one step per shutdown phase, one pass over the
/// connection table, one `sendmsg` per egress run, no wait — and it runs
/// after the error that ended the loop has already been decided. Whatever
/// it cannot finish is handed to `dispose`, which is the only part of this
/// that cannot fail.
pub fn windDown(self: *Self, io: std.Io, at: ?Instant) void {
    if (at) |stamp| {
        const protection = io.swapCancelProtection(.blocked);
        defer _ = io.swapCancelProtection(protection);
        node_close.close(self, io, stamp, self.generator()) catch |err| std.log.err(
            "node {f} could not be closed gracefully after its loop ended: {t}",
            .{ self.bridge.nodeId(), err },
        );
    }
    if (self.accept.shutdown.phase != .closed) node_close.dispose(self);
}

/// This node's instant, in the unit the core is driven at.
///
/// `Clock.awake` rather than `.real`: a QUIC timer must not jump because NTP
/// moved the wall clock, and every seam below takes its instant as an argument
/// precisely so that nothing reads one itself.
pub fn instantOf(io: std.Io) Error!Instant {
    const stamp = std.Io.Clock.awake.now(io);
    return std.math.cast(Instant, stamp.nanoseconds) orelse error.InstantOutOfRange;
}
