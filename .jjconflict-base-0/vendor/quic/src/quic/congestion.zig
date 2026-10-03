//! Congestion windows and packet pacing. Two window algorithms — `NewReno`
//! and the `Cubic` a connection actually drives — and one `Pacer`, both
//! reached through `Connection.cc` and `Connection.pacer`.
//!
//! None of these types owns memory, borrows a buffer, reads a clock or draws
//! randomness: every instant is a `now` argument on the call that needs one,
//! and no value here reaches for entropy of its own. The connection is the
//! only thing that decides when to signal a loss; the controllers here react.

const std = @import("std");
const testing = std.testing;

const rtt_mod = @import("rtt.zig");
const RttStats = rtt_mod.RttStats;

/// Default initial congestion window in packets.
/// RFC 9002 §7.2: initial_window = min(10 * mds, max(14720, 2 * mds))
const INITIAL_WINDOW_PACKETS: u64 = 10;

/// RFC 9002 §7.2: floor for initial window (14720 bytes).
const INITIAL_WINDOW_FLOOR: u64 = 14720;

/// Compute the initial congestion window per RFC 9002 §7.2:
///   initial_window = min(10 * max_datagram_size, max(14720, 2 * max_datagram_size))
fn initialWindow(max_datagram_size: u64) u64 {
    return @min(
        INITIAL_WINDOW_PACKETS * max_datagram_size,
        @max(INITIAL_WINDOW_FLOOR, 2 * max_datagram_size),
    );
}

/// Minimum congestion window in bytes (2 * max_datagram_size per RFC 9002).
const MIN_WINDOW_PACKETS: u64 = 2;

/// Ceiling on the congestion window, in packets. Past this the window only
/// measures how long the path has gone without loss, and a burst that size
/// is an amplifier (quic-go uses the same bound).
const MAX_WINDOW_PACKETS: u64 = 10_000;

/// Default max datagram size.
const DEFAULT_MAX_DATAGRAM_SIZE: u64 = 1200;

/// Beta for NewReno multiplicative decrease (per RFC 9002 recommendation).
const NEWRENO_BETA: u64 = 7; // Numerator (divide by 10 for 0.7)
const NEWRENO_BETA_DENOM: u64 = 10;

/// Smallest burst the pacer allows (in packets).
const MAX_BURST_PACKETS: u64 = 10;

/// The pacer's burst also covers this much sending at its rate: quic-go's
/// MinPacingDelay plus TimerGranularity (`pacer.go`). Past the fixed ten
/// packets, a wait shorter than a timer tick buys no smoothness, only another
/// pass for the next ten: a 1 MB HTTP/3 response on loopback left in 12 KB
/// bursts, each drawing its own ACK, ~95 of each per response.
const PACER_BURST_NS: u64 = 2 * std.time.ns_per_ms;

/// Bandwidth multiplier for pacer (1.25x) expressed as fraction.
const PACER_BANDWIDTH_NUM: u64 = 5;
const PACER_BANDWIDTH_DENOM: u64 = 4;

/// Congestion controller using NewReno algorithm (RFC 9002 Appendix B).
///
/// NewReno is simpler than CUBIC and a good starting point. It uses:
/// - Slow start: exponential growth until ssthresh
/// - Congestion avoidance: linear growth (1 MSS per RTT)
/// - On loss: multiplicative decrease (window * beta)
///
/// It is published and exercised, but a connection drives `Cubic`: this
/// controller has no `enterRecoveryForMigration`, so a port-only migration
/// would have no way to mark the pre-migration packets as path losses
/// instead of congestion. Its window is capped at ten thousand packets, so
/// past that the window stops measuring anything but how long the path has
/// been lossless.
pub const NewReno = struct {
    /// Current congestion window in bytes.
    congestion_window: u64,

    /// Slow start threshold.
    ssthresh: u64 = std.math.maxInt(u64),

    /// Maximum datagram size (affects window calculations).
    ///
    /// Non-zero. It is the unit every window figure here is counted in, so
    /// `MAX_WINDOW_PACKETS * 7 * max_datagram_size` must fit a `u64`: that is
    /// the ten-thousand-packet ceiling with room for the multiplicative
    /// decrease `onCongestionEvent` applies to the window it then cuts.
    max_datagram_size: u64 = DEFAULT_MAX_DATAGRAM_SIZE,

    /// Time at which the current recovery period started (RFC 9002 §B.7).
    /// Losses of packets sent before this time don't trigger new recovery.
    congestion_recovery_start_time: ?i64 = null,

    /// Bytes acknowledged in the current round trip (for congestion avoidance).
    ///
    /// Saturating: it is an accumulator, and a figure already past the top
    /// of the range has spent more than the one window it is counting.
    bytes_acked_in_round: u64 = 0,

    /// RFC 9002 §7.8: Application-limited — suppress cwnd growth when the
    /// sender is not fully utilizing the congestion window.
    ///
    /// Written by the connection before it processes an ACK — whether the
    /// path is using the whole window — and never by any method here. It is
    /// a snapshot of that decision, not something the controller maintains:
    /// leave it true and the window never grows again.
    app_limited: bool = false,

    /// Whether we are in slow start: true while the window is below
    /// `ssthresh`, which is every window until the first loss or a
    /// persistent-congestion reset.
    pub fn inSlowStart(self: *const NewReno) bool {
        return self.congestion_window < self.ssthresh;
    }

    /// Check if a packet sent at `sent_time` is from the current recovery period.
    ///
    /// `sent_time` is compared against the instant the current recovery
    /// began, so it must come from the same clock as the `now` passed to
    /// `onCongestionEvent`. False before any recovery has started.
    pub fn inCongestionRecovery(self: *const NewReno, sent_time: i64) bool {
        if (self.congestion_recovery_start_time) |start| {
            return sent_time <= start;
        }
        return false;
    }

    /// Initialize with default values.
    ///
    /// The window starts at RFC 9002 §7.2's initial value for a 1200-byte
    /// datagram: `min(10 * 1200, max(14720, 2400))` = 12000 bytes. Call
    /// `initWithMds` when the real datagram size is known at construction;
    /// `setMaxDatagramSize` afterwards does not re-derive this figure.
    pub fn init() NewReno {
        return .{
            .congestion_window = initialWindow(DEFAULT_MAX_DATAGRAM_SIZE),
        };
    }

    /// Initialize with a specific max datagram size.
    ///
    /// The initial window is computed from `max_datagram_size`, so this and
    /// `init` differ in the window they start from as well as in the size
    /// used for later per-MSS growth.
    ///
    /// The size is stored as given and not checked — the two bounds the
    /// `max_datagram_size` field states are the caller's to honour.
    pub fn initWithMds(max_datagram_size: u64) NewReno {
        return .{
            .congestion_window = initialWindow(max_datagram_size),
            .max_datagram_size = max_datagram_size,
        };
    }

    /// Called when a packet is acknowledged.
    ///
    /// `acked_bytes` is the packet's size and `sent_time` its send instant,
    /// both needed for the recovery test; the controller keeps no clock, so
    /// a caller reporting an acknowledgement must supply the send time the
    /// packet was recorded with. Silent no-op — the window is unchanged —
    /// when the packet predates the current recovery period or when
    /// `app_limited` is set.
    pub fn onPacketAcked(self: *NewReno, acked_bytes: u64, sent_time: i64) void {
        // Don't grow window during recovery
        if (self.inCongestionRecovery(sent_time)) return;

        // RFC 9002 §7.8: Don't increase cwnd when application-limited
        if (self.app_limited) return;

        if (self.inSlowStart()) {
            // Slow start: increase by acked_bytes
            self.congestion_window +|= acked_bytes;
        } else {
            // Congestion avoidance: increase by MSS per RTT
            // Accumulate bytes and increase by MSS when a full window is acked
            self.bytes_acked_in_round +|= acked_bytes;
            if (self.bytes_acked_in_round >= self.congestion_window) {
                self.bytes_acked_in_round -= self.congestion_window;
                self.congestion_window += self.max_datagram_size;
            }
        }
        self.congestion_window = @min(self.congestion_window, MAX_WINDOW_PACKETS * self.max_datagram_size);
    }

    /// Called on congestion event (packet loss detected).
    /// `sent_time` is the sent time of the lost packet.
    /// `now` is the current time (becomes the new recovery start time).
    ///
    /// The loss signal. Cuts the window to seven tenths and starts a
    /// recovery period at `now`; the floor is two MSS, so a window already
    /// below it is not cut further but recovery still begins. A packet from
    /// inside the current recovery period is ignored, so a burst of losses
    /// reported together costs one reduction and not one per packet. Both
    /// instants must come from the same clock.
    pub fn onCongestionEvent(self: *NewReno, sent_time: i64, now: i64) void {
        // Don't trigger new recovery for packets sent during current recovery (RFC 9002 §B.7)
        if (self.inCongestionRecovery(sent_time)) return;

        self.congestion_recovery_start_time = now;

        // Multiplicative decrease
        self.ssthresh = self.congestion_window * NEWRENO_BETA / NEWRENO_BETA_DENOM;
        self.congestion_window = @max(
            self.ssthresh,
            MIN_WINDOW_PACKETS * self.max_datagram_size,
        );
        self.bytes_acked_in_round = 0;
    }

    /// Reset to a two-datagram window and slow start after persistent loss.
    /// Unlike an ordinary congestion event, this is not gated on recovery.
    /// `now` starts recovery and suppresses subsequent losses of older packets.
    pub fn onPersistentCongestion(self: *NewReno, now: i64) void {
        self.congestion_window = MIN_WINDOW_PACKETS * self.max_datagram_size;
        self.ssthresh = std.math.maxInt(u64);
        self.congestion_recovery_start_time = now;
        self.bytes_acked_in_round = 0;
    }

    /// Called when the PTO fires (probe timeout).
    ///
    /// Deliberately empty: a probe timeout is not a loss signal, and
    /// reducing the window for one would let a black-holed path shrink the
    /// window without ever having been acknowledged. The connection still
    /// has to run the PTO; this is the hook that says it changes nothing.
    pub fn onPtoExpired(self: *NewReno) void {
        _ = self;
        // NewReno doesn't adjust window on PTO, only on loss
    }

    /// Get the current send window (bytes that can be in flight).
    ///
    /// A ceiling on bytes in flight, not a grant: the caller is still bound
    /// by its own flow control and by the connection's amplification budget.
    pub fn sendWindow(self: *const NewReno) u64 {
        return self.congestion_window;
    }

    /// Update the max datagram size (e.g., after PMTUD).
    ///
    /// The window itself is left in bytes and is not rescaled, so raising
    /// the datagram size does not hand out more congestion credit; what
    /// changes is the per-MSS increment in congestion avoidance and the
    /// two-MSS floor, which both move with the new size. The ten-thousand
    /// packet ceiling moves with it too.
    ///
    /// `size` is a local field's precondition, not a value this checks: the
    /// two bounds `max_datagram_size` states. Nothing here validates them.
    pub fn setMaxDatagramSize(self: *NewReno, size: u64) void {
        self.max_datagram_size = size;
    }
};

/// CUBIC congestion control (RFC 8312).
///
/// CUBIC uses a cubic function for window growth, providing better
/// bandwidth utilization on high-BDP networks compared to NewReno.
/// Key properties:
/// - Window growth is a cubic function of time since last congestion event
/// - Provides a TCP-friendly region for fairness with Reno flows
/// - Beta = 0.7 (multiplicative decrease factor)
/// - C = 0.4 (cubic scaling constant)
///
/// This is the algorithm a connection drives through `Connection.cc`. Like
/// `NewReno` it owns nothing, reads no clock and draws no randomness: growth
/// is a function of the `now` passed to `onPacketAcked`, so a caller must
/// pass the same clock every time or the curve is sampled against a moving
/// origin. Unlike `NewReno` it has `enterRecoveryForMigration`, which marks
/// pre-migration packets as path losses instead of congestion.
///
/// **Numeric domain.** `max_datagram_size` is non-zero and small enough that
/// `MAX_WINDOW_PACKETS * 17` times it fits a `u64` — `max_datagram_size`
/// says why seventeen. `now` and `sent_time` are instants of one monotonic
/// clock, `now` at or after `epoch_start`. Inside that domain every figure
/// this controller derives is exact or saturating — the curve, `k_ns`,
/// `w_est` and the growth an acknowledgement asks for alike — and none of
/// `now`, `sent_time`, `acked_bytes`, `w_max` or `k_ns` reaches past a type.
/// Outside it — an instant from before the epoch origin, a `w_max` wider
/// than the window — the arithmetic still stays in range, but what the
/// resulting curve means is not promised.
pub const Cubic = struct {
    /// Current congestion window in bytes. Grows toward the larger of the
    /// cubic curve and the TCP-friendly estimate, and is cut on every loss
    /// signal, so the whole algorithm is visible in this one field.
    congestion_window: u64,

    /// Slow start threshold. Infinity until the first loss, and infinity
    /// again after `onPersistentCongestion`, which is what sends the window
    /// back into slow start.
    ssthresh: u64 = std.math.maxInt(u64),

    /// Maximum datagram size (affects window calculations).
    ///
    /// Non-zero, and the epoch divides `w_max` by it to reach MSS. It is the
    /// unit every window figure here is counted in, so
    /// `MAX_WINDOW_PACKETS * 17 * max_datagram_size` must fit a `u64`: that is
    /// the ten-thousand-packet ceiling with room for the widest multiplier
    /// `onCongestionEvent` applies to the window it then cuts. A datagram of
    /// zero bytes is not a datagram, and one wide enough to push the cap
    /// past `u64` is not a QUIC one.
    max_datagram_size: u64 = DEFAULT_MAX_DATAGRAM_SIZE,

    /// Time at which the current recovery period started (RFC 9002 §B.7).
    congestion_recovery_start_time: ?i64 = null,

    /// Bytes acknowledged in the current round trip (for slow start / TCP-friendly).
    ///
    /// Saturating: it is an accumulator, and a figure already past the top
    /// of the range has spent more than the one window it is counting.
    bytes_acked_in_round: u64 = 0,

    /// RFC 9002 §7.8: Application-limited — suppress cwnd growth when the
    /// sender is not fully utilizing the congestion window.
    ///
    /// Written by the connection before it processes an ACK and by no method
    /// here. It is a snapshot of that decision, not something this controller
    /// maintains: leave it true and the window never grows again.
    app_limited: bool = false,

    // ── CUBIC-specific state ──

    /// W_max: congestion window at the time of the last congestion event (in bytes).
    ///
    /// The top of the cubic curve and the point the growth path aims at. Zero
    /// before the first loss and after `onPersistentCongestion`, so the first
    /// epoch after either starts with no curve to climb.
    w_max: u64 = 0,

    /// Epoch start time: when the current CUBIC epoch began (nanoseconds).
    /// Reset on each congestion event.
    ///
    /// Null between a congestion event and the next acknowledged packet: the
    /// epoch starts at that first acknowledgement, not at the loss, so the
    /// curve is measured from when there was something to grow into.
    epoch_start: ?i64 = null,

    /// K: the time period for the cubic function to reach W_max (in nanoseconds).
    /// K = cbrt(W_max * (1 - beta) / C) but we store it pre-computed.
    ///
    /// Computed once per epoch and only when the window is below `w_max`,
    /// where the curve has to descend before it can rise; otherwise it stays
    /// zero and the curve is measured entirely from the epoch start.
    ///
    /// Bounded however wide `w_max` is: the cube root of a `u64` is under
    /// 2.7e6 MSS, and converting it to nanoseconds multiplies that by 1e9,
    /// so this cannot leave `i64`.
    k_ns: i64 = 0,

    /// W_est: estimated TCP-friendly window (for TCP-friendly region).
    ///
    /// The Reno-fair floor the curve is never allowed to fall below, seeded
    /// from the window at the epoch start and grown one datagram per window
    /// acknowledged. The growth saturates at `maxInt(u64)`, which as a floor
    /// is one no window can be under — the answer a window already at the
    /// top of the range had.
    w_est: u64 = 0,

    // ── Constants ──
    // Beta = 0.7 (RFC 8312 §4.5 recommends 0.7 for QUIC)
    const BETA_NUM: u64 = 7;
    const BETA_DENOM: u64 = 10;

    // C = 0.4 (RFC 8312 §5)
    // We scale by 1000 to avoid floating point: C_SCALED = 400
    //
    // Neither C constant is read: the curve carries the same 0.4 as the
    // module-level CURVE_SCALE_NUM / CURVE_SCALE_DENOM. They record the
    // RFC's value, and changing them changes nothing.
    const C_SCALED: u64 = 400;
    const C_DENOM: u64 = 1000;

    /// Whether the window is below `ssthresh`, and so growing by the
    /// acknowledged bytes rather than along the cubic curve.
    pub fn inSlowStart(self: *const Cubic) bool {
        return self.congestion_window < self.ssthresh;
    }

    /// Whether a packet sent at `sent_time` belongs to the current recovery
    /// period. Suppresses both window growth for it and a further cut from
    /// its loss, so `sent_time` must come from the same clock as the `now`
    /// given to `onCongestionEvent`. False before any recovery has started.
    pub fn inCongestionRecovery(self: *const Cubic, sent_time: i64) bool {
        if (self.congestion_recovery_start_time) |start| {
            return sent_time <= start;
        }
        return false;
    }

    /// A controller at RFC 9002 §7.2's initial window for a 1200-byte
    /// datagram, which is 12000 bytes, with no recovery period and no cubic
    /// epoch. Call `initWithMds` when the real datagram size is known at
    /// construction; `setMaxDatagramSize` afterwards does not re-derive the
    /// initial window.
    pub fn init() Cubic {
        return .{
            .congestion_window = initialWindow(DEFAULT_MAX_DATAGRAM_SIZE),
        };
    }

    /// As `init`, with the initial window computed from
    /// `max_datagram_size` and that size kept for later growth and floors.
    ///
    /// The size is stored as given and not checked — the two bounds the
    /// `max_datagram_size` field states are the caller's to honour.
    pub fn initWithMds(max_datagram_size: u64) Cubic {
        return .{
            .congestion_window = initialWindow(max_datagram_size),
            .max_datagram_size = max_datagram_size,
        };
    }

    /// Called when a packet is acknowledged, at `now` (nanoseconds).
    ///
    /// `acked_bytes` is the packet's size and `sent_time` the instant it
    /// went out, on the same clock as `now`. Outside slow start the first
    /// call after a congestion event starts the epoch and computes the cubic
    /// constants, so it also establishes the origin every later call is
    /// measured from. A no-op — window untouched — when the packet predates
    /// the current recovery period or `app_limited` is set.
    pub fn onPacketAcked(self: *Cubic, acked_bytes: u64, sent_time: i64, now: i64) void {
        // Don't grow window during recovery
        if (self.inCongestionRecovery(sent_time)) return;

        // RFC 9002 §7.8: Don't increase cwnd when application-limited
        if (self.app_limited) return;

        if (self.inSlowStart()) {
            // Slow start: increase by acked_bytes (same as NewReno)
            self.congestion_window +|= acked_bytes;
        } else {
            self.cubicUpdate(acked_bytes, now);
        }
        self.congestion_window = @min(self.congestion_window, MAX_WINDOW_PACKETS * self.max_datagram_size);
    }

    /// CUBIC window update during congestion avoidance.
    ///
    /// Reached only from `onPacketAcked`, and only outside slow start, so
    /// the packet's `sent_time` has already been checked against the recovery
    /// period. It never reduces the window: on the descending part of the
    /// curve `w_cubic_bytes` saturates at `w_max` and the Reno-fair `w_est`
    /// holds the floor, so a slow path shrinks through `onCongestionEvent`
    /// rather than through this.
    ///
    /// `now` is expected at or after `epoch_start`, on the same clock — the
    /// epoch opens at the `now` of the first acknowledgement after the loss.
    /// Nothing below needs that to hold to stay in range: every step is
    /// computed at `i128` or wider and saturates rather than wrapping, so
    /// any pair of `i64` instants gives a bounded answer. What that answer
    /// *means* for an instant from before the origin is not promised — a
    /// backwards clock is a caller bug, not a supported mode.
    fn cubicUpdate(self: *Cubic, acked_bytes: u64, now: i64) void {
        // Initialize epoch on first ACK after congestion event
        if (self.epoch_start == null) {
            self.epoch_start = now;
            if (self.congestion_window < self.w_max) {
                // Compute K = cbrt(W_max * (1-beta) / C) in MSS units, then convert to nanoseconds
                // K_mss = cbrt((W_max/MSS) * 0.3 / 0.4) = cbrt((W_max/MSS) * 3/4)
                const w_max_mss = self.w_max / self.max_datagram_size;
                const denominator: u64 = 4; // C = 0.4, scaled by 10 = 4
                // `w_max_mss * 3` is three times a `u64` and leaves the type
                // at a datagram size of one byte. `x / 4 * 3 + (x % 4) * 3 / 4`
                // is the same floor of `3x / 4` — 3 * (4q + r) / 4 is 3q + 3r / 4
                // for r < 4 — and cannot.
                const k_mss_cubed = (w_max_mss / denominator) * 3 +
                    ((w_max_mss % denominator) * 3) / denominator;
                // cbrt using integer approximation. Its answer is at most
                // cbrt(maxInt(u64)) = 2_642_245, so the seconds-to-ns
                // conversion is a multiply that still fits `i64`.
                self.k_ns = @intCast(icbrt(k_mss_cubed) * std.time.ns_per_s);
            } else {
                self.k_ns = 0;
            }
            // Initialize TCP-friendly estimate
            self.w_est = self.congestion_window;
        }

        // W_cubic(t) = C * (t - K)^3 + W_max, with `t` and `K` taken in whole
        // ticks of CURVE_TICK_NS rather than in nanoseconds: what gets cubed
        // is then a tick count, which stays inside `u64` for hours where a
        // nanosecond cube would leave it within seconds. The i128 holds
        // `now - epoch_start - k_ns` for any two i64 instants of one clock,
        // and the tick it yields is what `cubicCurveOffsetBytes` bounds.
        const epoch_start: i64 = self.epoch_start orelse now;
        const tick = @divTrunc(
            @as(i128, now) - @as(i128, epoch_start) - @as(i128, self.k_ns),
            CURVE_TICK_NS,
        );

        // The curve is a distance from `w_max`, not a window: added on the
        // rising side and subtracted on the falling one. Both ends saturate,
        // so the rising curve stops at the top of the range and the falling
        // one at zero rather than wrapping past either.
        const curve_bytes = cubicCurveOffsetBytes(tick, self.max_datagram_size);
        const w_cubic_bytes = if (tick >= 0)
            curve_bytes +| self.w_max
        else
            self.w_max -| curve_bytes;

        // TCP-friendly estimate: W_est grows linearly (1 MSS per RTT) after recovery
        // W_est += 3 * beta / (2 - beta) * (acked_bytes / cwnd) per ACK
        // Simplified: ~= acked_bytes * 3 * 7 / (10 * (2*10 - 7)) * MSS / cwnd
        // ≈ acked_bytes * 21 / 130 * MSS / cwnd
        // Even simpler: grow by MSS per cwnd acked (like NewReno)
        self.bytes_acked_in_round +|= acked_bytes;
        if (self.bytes_acked_in_round >= self.congestion_window) {
            self.bytes_acked_in_round -= self.congestion_window;
            self.w_est +|= self.max_datagram_size;
        }

        // Use the larger of CUBIC and TCP-friendly targets
        const target = @max(w_cubic_bytes, self.w_est);

        // Increase cwnd toward target
        if (target > self.congestion_window) {
            // Increase proportionally to acked_bytes. The `/` here leaves a
            // residue below one byte, and `@max(..., 1)` spends it: an
            // acknowledged packet never contributes nothing. The ratio
            // saturates because the product behind it does not fit, and
            // where that starts depends on both sizes — an epoch of about
            // nine hours past `K` for 1200-byte packets, nearer two for
            // very large ones. The cap in `onPacketAcked` is what a
            // connection keeps either way.
            const increase = saturatingMulDiv(
                target - self.congestion_window,
                acked_bytes,
                self.congestion_window,
            );
            self.congestion_window +|= @max(increase, 1);
        }
    }

    /// Called on congestion event (packet loss detected).
    ///
    /// The loss signal, with `sent_time` the lost packet's send instant and
    /// `now` the current one, both on the connection's clock. Cuts the
    /// window to seven tenths with fast convergence: when the window was
    /// already below `w_max`, `w_max` is pulled down to eight tenths of it
    /// so the next epoch does not climb back to a bandwidth the path has
    /// since lost. Ends the epoch — `epoch_start` goes null and the next
    /// acknowledgement starts a fresh one — and begins recovery at `now`.
    ///
    /// A packet from inside the current recovery period is ignored, so a
    /// burst of losses reported together costs one cut and not one per
    /// packet.
    pub fn onCongestionEvent(self: *Cubic, sent_time: i64, now: i64) void {
        if (self.inCongestionRecovery(sent_time)) return;

        self.congestion_recovery_start_time = now;
        self.epoch_start = null; // Reset CUBIC epoch

        // Fast convergence (RFC 8312 §4.6):
        // If W_max decreased, the available bandwidth is shrinking
        if (self.congestion_window < self.w_max) {
            // Reduce W_max further to probe lower
            self.w_max = self.congestion_window * (BETA_NUM + BETA_DENOM) / (2 * BETA_DENOM);
        } else {
            self.w_max = self.congestion_window;
        }

        // Multiplicative decrease: cwnd = cwnd * beta
        self.ssthresh = self.congestion_window * BETA_NUM / BETA_DENOM;
        self.congestion_window = @max(
            self.ssthresh,
            MIN_WINDOW_PACKETS * self.max_datagram_size,
        );
        self.bytes_acked_in_round = 0;
    }

    /// Persistent congestion: reset to minimum window (RFC 9002 §7.6.2).
    ///
    /// The RFC's response to a span of losses rather than to one, so unlike
    /// `onCongestionEvent` it applies even inside a recovery period. Drops
    /// to two MSS, sends `ssthresh` back to infinity so the window restarts
    /// in slow start, forgets `w_max` entirely — there is no curve to climb
    /// — and begins recovery at `now` so losses of packets sent before it are
    /// suppressed.
    pub fn onPersistentCongestion(self: *Cubic, now: i64) void {
        self.congestion_window = MIN_WINDOW_PACKETS * self.max_datagram_size;
        self.ssthresh = std.math.maxInt(u64);
        self.congestion_recovery_start_time = now;
        self.epoch_start = null;
        self.w_max = 0;
        self.bytes_acked_in_round = 0;
    }

    /// PTO does not reduce window (RFC 9002 §7.5).
    ///
    /// Deliberately empty. A probe timeout is not a loss signal, and cutting
    /// for one would let a path shrink its window without ever having been
    /// acknowledged; the caller still runs the PTO, and this hook says the
    /// window does not move.
    pub fn onPtoExpired(self: *Cubic) void {
        _ = self;
    }

    /// Enter recovery mode for NAT rebinding migration.
    /// Pre-migration packets sent to the old address will appear as losses,
    /// but they are path losses not congestion losses. Setting the recovery
    /// start time to now prevents onCongestionEvent from reducing CWND for
    /// those packets (since inCongestionRecovery(sent_time) will be true).
    ///
    /// Only the recovery mark moves: the window, `w_max` and the epoch are
    /// left as they were, because a rebinding is not a congestion signal.
    /// It does, however, start a recovery period, so a genuine loss of a
    /// packet sent at or before `now` is suppressed until the next one.
    /// Call it once per migration, on the connection's clock.
    pub fn enterRecoveryForMigration(self: *Cubic, now: i64) void {
        self.congestion_recovery_start_time = now;
    }

    /// The window in bytes, which is what a sender may have in flight.
    ///
    /// A ceiling, not a grant: flow control and the connection's
    /// amplification budget can both allow less.
    pub fn sendWindow(self: *const Cubic) u64 {
        return self.congestion_window;
    }

    /// Changes the datagram size used for per-MSS growth, the two-MSS floor
    /// and the ten-thousand packet ceiling. The window itself is not
    /// rescaled, so this never hands out more congestion credit; only the
    /// units it is measured and capped in move.
    ///
    /// `size` is a local field's precondition, not a value this checks: the
    /// two bounds `max_datagram_size` states. Nothing here validates them.
    pub fn setMaxDatagramSize(self: *Cubic, size: u64) void {
        self.max_datagram_size = size;
    }
};

/// The CUBIC curve's `t` axis, in tenths of a second.
///
/// What `Cubic` cubes is a tick count rather than a nanosecond count, and
/// that is the whole reason the curve survives a long epoch: `u64` holds a
/// tick cube for hours and a nanosecond cube for about a second.
const CURVE_TICK_NS: i128 = 100_000_000;

/// RFC 8312 §5's `C = 0.4` over that axis, as the exact integer fraction
/// `CURVE_SCALE_NUM / CURVE_SCALE_DENOM`: `0.4 * (tick / 10)^3 * mss` is
/// `tick^3 * mss * 4 / 10000`, with nothing rounded in the rewriting.
const CURVE_SCALE_NUM: u64 = 4;
const CURVE_SCALE_DENOM: u64 = 10_000;

/// The cubic curve's distance from `w_max`, in bytes: RFC 8312 §5's
/// `C * (t - K)^3` term, in magnitude — `|tick|^3 * max_datagram_size * 4 /
/// 10000`. `tick` may be negative and applying the sign is `Cubic`'s job.
///
/// Exact for every argument whose quotient fits a `u64`, and `maxInt(u64)`
/// above that. Where the line falls depends on the datagram size: at 1200
/// bytes the product `|tick|^3 * 4800` leaves `u64` at about 156_637 ticks,
/// which is four hours and twenty minutes past `K`.
///
/// **Saturation is decided after the division, never before it.** Clamping
/// `|tick|^3 * mss * 4` to `maxInt(u64)` and dividing *that* would report
/// two thirds of what a five-hour epoch asks for — and that value is
/// representable: the exact quotient at that tick is 2_798_893_465_919_520,
/// not the 1_844_674_407_370_955 a pre-division clamp gives, which is 34%
/// low. So the division is taken where it cannot wrap, and only a result
/// that does not fit is clamped.
///
/// `max_datagram_size` is `Cubic.max_datagram_size`, which is non-zero, so
/// `scale` is at least four and the bound below has a divisor.
///
/// `|tick|` must be under `2^65 / CURVE_TICK_NS`, about 3.7e11: that covers
/// a difference of two `i64` instants and a `k_ns` of either sign, without
/// relying on how far apart the two instants are. `Cubic.cubicUpdate` stays
/// well inside it, and this bound's cube is some six thousand times inside
/// `u128`.
fn cubicCurveOffsetBytes(tick: i128, max_datagram_size: u64) u64 {
    const magnitude: u128 = @intCast(if (tick < 0) -tick else tick);
    const cube = magnitude * magnitude * magnitude;
    const scale: u128 = @as(u128, max_datagram_size) * CURVE_SCALE_NUM;
    // The widest product whose quotient still fits. Forming the bound by
    // dividing keeps it exact, and `cube > saturating_at / scale` is exactly
    // `cube * scale > saturating_at`, so the product below is formed only
    // once it is known to fit: 1.8e23 against `u128`'s 3.4e38.
    const saturating_at: u128 = @as(u128, std.math.maxInt(u64)) * CURVE_SCALE_DENOM;
    if (cube > saturating_at / scale) return std.math.maxInt(u64);
    return @intCast(cube * scale / CURVE_SCALE_DENOM);
}

/// `floor(multiplicand * multiplier / divisor)`, clamped to `maxInt(u64)`
/// when the true quotient is wider than a `u64`. `divisor` must be non-zero:
/// `Cubic`'s is the window, which its own growth and the two-MSS floor keep
/// there.
///
/// The product of two `u64`s is exact in `u128` for every pair, so the clamp
/// is the only test — and it is made by dividing rather than multiplying, so
/// that the bound it compares against is exact too.
fn saturatingMulDiv(multiplicand: u64, multiplier: u64, divisor: u64) u64 {
    const product: u128 = @as(u128, multiplicand) * @as(u128, multiplier);
    const saturating_at: u128 = @as(u128, std.math.maxInt(u64)) * @as(u128, divisor);
    if (product > saturating_at) return std.math.maxInt(u64);
    return @intCast(product / divisor);
}

/// Integer cube root approximation (Newton's method).
fn icbrt(x: u64) u64 {
    if (x == 0) return 0;
    if (x <= 7) return 1;

    // Initial guess using bit shifting: `1 << (bit_length / 3 + 1)`.
    //
    // `bit_length` is counted in a `u7` because a full-width `x` has 64 of
    // them and a `u6` stops one short — the counter itself would trap on the
    // last step, before the cube this function returns is ever formed. The
    // exponent it feeds is at most 22 however wide `x` is, so that stays a
    // `u6`.
    var bit_length: u7 = 0;
    var temp = x;
    while (temp > 0) : (bit_length += 1) {
        temp >>= 1;
    }
    var guess: u64 = @as(u64, 1) << @as(u6, @intCast(bit_length / 3 + 1));

    // Newton iterations: guess = (2*guess + x/(guess*guess)) / 3
    var i: u32 = 0;
    while (i < 10) : (i += 1) {
        const g2 = guess * guess;
        if (g2 == 0) break;
        const new_guess = (2 * guess + x / g2) / 3;
        if (new_guess >= guess) break;
        guess = new_guess;
    }

    // Verify and adjust. The cube is compared at `u128`: `guess` starts a
    // step above cbrt(x), so `guess^3` is past `u64` for every argument
    // above about 2^63 and the comparison itself would trap.
    while (@as(u128, guess) * @as(u128, guess) * @as(u128, guess) > x) {
        guess -= 1;
    }

    return guess;
}

/// Pacer for spacing out packet sends to avoid bursts.
///
/// Uses a token bucket algorithm similar to quic-go's pacer.
///
/// Reached through `Connection.pacer`. It owns nothing, borrows nothing,
/// reads no clock and draws no randomness: the caller passes `now` to every
/// method, and the whole state is the token bucket below. A `Pacer` is
/// copyable and each copy paces independently — which is why a migration
/// that resets congestion control also constructs a fresh one.
pub const Pacer = struct {
    /// Available budget in bytes: what may be sent before the next wait.
    /// Saturating, so a send larger than the budget leaves it at zero rather
    /// than wrapping, and the deficit shows up as a delay rather than as
    /// free credit.
    budget: u64,

    /// Max burst size in bytes: ten packets, or `PACER_BURST_NS` of sending
    /// at the pacing rate when that is more. Set with the bandwidth.
    ///
    /// Ten 1200-byte packets, i.e. 12000 bytes from `init`. `setBandwidth`
    /// raises it to at most two milliseconds of sending at the measured
    /// rate, and never lowers it below the ten packets.
    max_burst: u64,

    /// Last time a packet was sent (nanoseconds).
    ///
    /// Zero until the first `onPacketSent`, and zero is treated as "never
    /// sent": `budgetAt` reports a full bucket then, so the first packet
    /// after a fresh `init` is never delayed. A connection whose clock starts
    /// at zero therefore loses the full-bucket credit on its first send.
    last_sent_time: i64 = 0,

    /// When `budget` last had the elapsed time credited to it. Crediting
    /// from `last_sent_time` instead counts the same interval again on every
    /// check between sends.
    ///
    /// The bucket only advances its credit by the whole time the bytes it
    /// just earned took to accumulate, so a fraction of a byte earned is not
    /// thrown away by a check that ran early.
    credited_at: i64 = 0,

    /// Bandwidth in bytes per nanosecond, left-shifted by BANDWIDTH_SHIFT for precision.
    /// This avoids u128 arithmetic on the hot send path.
    ///
    /// Zero means no bandwidth has been measured yet, and the pacer is then
    /// inert: the bucket reports itself full and `delayAt` answers zero. A
    /// connection that never calls `setBandwidth` never paces, rather than
    /// pacing at a rate of zero.
    bandwidth_shifted: u64 = 0,

    /// Max datagram size.
    ///
    /// The smallest packet `delayAt` will wait for: a send is permitted as
    /// soon as the bucket holds one of these. Fixed at the 1200-byte default
    /// unless the caller writes it; `setBandwidth` uses it for the ten-packet
    /// burst floor, so changing it after a bandwidth update leaves `max_burst`
    /// sized for the old one.
    max_datagram_size: u64 = DEFAULT_MAX_DATAGRAM_SIZE,

    /// A full bucket of ten 1200-byte packets and no pacing rate: `budget`
    /// equals `max_burst` at 12000 bytes, and `delayAt` answers zero until
    /// `setBandwidth` supplies a rate. Nothing is allocated and no clock is
    /// read, so a caller can build one before any measurement exists.
    pub fn init() Pacer {
        const max_burst = MAX_BURST_PACKETS * DEFAULT_MAX_DATAGRAM_SIZE;
        return .{
            .budget = max_burst,
            .max_burst = max_burst,
        };
    }

    const BANDWIDTH_SHIFT: u6 = 20; // Fixed-point precision bits

    /// Update the pacer's bandwidth based on the congestion window and RTT.
    ///
    /// Sets the rate to `cwnd / smoothed RTT * 1.25` bytes per nanosecond
    /// and resizes `max_burst` to the larger of ten datagrams and two
    /// milliseconds at that rate. A silent no-op — the previous rate and
    /// burst stand — when there is no smoothed RTT yet or it is zero, so a
    /// connection that calls this before its first measurement keeps the
    /// unpaced state `init` gave it rather than dividing by nothing.
    ///
    /// `rtt_stats` is borrowed for the call and not retained.
    pub fn setBandwidth(self: *Pacer, cwnd: u64, rtt_stats: *const RttStats) void {
        const srtt = rtt_stats.smoothedRttOrDefault();
        if (srtt <= 0) return;

        // bandwidth = cwnd / srtt * 1.25 (bytes per nanosecond)
        // Store left-shifted by BANDWIDTH_SHIFT for fixed-point precision.
        // Use u128 only here (called infrequently on RTT updates, not per-packet).
        self.bandwidth_shifted = @intCast(@divTrunc(
            @as(u128, cwnd) * PACER_BANDWIDTH_NUM * (@as(u128, 1) << BANDWIDTH_SHIFT),
            @as(u128, @intCast(srtt)) * PACER_BANDWIDTH_DENOM,
        ));
        self.max_burst = @max(
            MAX_BURST_PACKETS * self.max_datagram_size,
            (self.bandwidth_shifted *| PACER_BURST_NS) >> BANDWIDTH_SHIFT,
        );
    }

    /// Called when a packet is sent. Deducts from the budget.
    ///
    /// Credits the elapsed time first, then charges `size`. The charge
    /// saturates: a packet larger than the whole bucket leaves `budget` at
    /// zero rather than wrapping, and the whole deficit is repaid at the
    /// measured rate. `now` must be the same clock every other call uses;
    /// a `now` at or before `credited_at` credits nothing.
    pub fn onPacketSent(self: *Pacer, size: u64, now: i64) void {
        self.replenish(now);
        self.budget -|= size;
        self.last_sent_time = now;
        self.credited_at = now;
    }

    /// Returns the time when the next packet can be sent, or 0 if it can be sent now.
    ///
    /// Nanoseconds to wait, on the caller's clock, for one
    /// `max_datagram_size` of budget. Zero means send now, and is also the
    /// answer whenever no bandwidth has been measured. This call advances
    /// the bucket; a caller that only wants to schedule a timer should use
    /// `delayAt`, which computes the same figure without moving the state.
    pub fn timeUntilSend(self: *Pacer, now: i64) i64 {
        self.replenish(now);
        return self.delayAt(now);
    }

    /// `timeUntilSend` without crediting the budget, for timer scheduling:
    /// the two must agree, or a send the pacer refuses gets no wakeup.
    ///
    /// A pure read: the answer is what the bucket would allow at `now` if it
    /// were not advanced, which is also what `timeUntilSend` returns after
    /// it has advanced to the same instant. The two therefore agree only at
    /// the instant they are both called for; calling `delayAt` and then
    /// `timeUntilSend` at a later instant gets a longer wait the second time,
    /// because the first call credited nothing and the second credited the
    /// whole interval.
    pub fn delayAt(self: *const Pacer, now: i64) i64 {
        const budget = self.budgetAt(now);
        if (budget >= self.max_datagram_size or self.bandwidth_shifted == 0) return 0;
        // Time (ns) = deficit / bandwidth_bpns = (deficit << SHIFT) / bandwidth_shifted
        const deficit = self.max_datagram_size - budget;
        return @intCast((deficit << BANDWIDTH_SHIFT) / self.bandwidth_shifted);
    }

    /// What the bucket would hold at `now` if it were not advanced: the
    /// stored `budget` plus the bandwidth earned since `credited_at`, capped
    /// at `max_burst`. A full bucket is reported before anything has been
    /// sent and whenever no bandwidth is known. Read only — `replenish` is
    /// what commits it.
    fn budgetAt(self: *const Pacer, now: i64) u64 {
        if (self.last_sent_time == 0 or self.bandwidth_shifted == 0) return self.max_burst;
        const elapsed = now - self.credited_at;
        if (elapsed <= 0) return self.budget;
        // new_budget = bandwidth_bpns * elapsed = (bandwidth_shifted * elapsed) >> SHIFT
        const new_budget = (self.bandwidth_shifted *| @as(u64, @intCast(elapsed))) >> BANDWIDTH_SHIFT;
        return @min(self.budget +| new_budget, self.max_burst);
    }

    /// Replenish budget based on elapsed time.
    ///
    /// Commits what `budgetAt` computed and moves `credited_at` forward only
    /// by the time the newly earned bytes actually took, so the partial byte
    /// that had accrued is neither lost nor counted twice. Called from
    /// `onPacketSent` and `timeUntilSend`; a caller that only schedules must
    /// use `delayAt` instead, which does not run this.
    fn replenish(self: *Pacer, now: i64) void {
        const budget = self.budgetAt(now);
        if (budget >= self.max_burst or self.bandwidth_shifted == 0) {
            self.budget = budget;
            self.credited_at = @max(self.credited_at, now);
            return;
        }
        // Advance only by the time the whole bytes took, so the fraction
        // of a byte earned so far is not lost to frequent checks.
        const earned = budget - self.budget;
        self.budget = budget;
        self.credited_at += @intCast((earned << BANDWIDTH_SHIFT) / self.bandwidth_shifted);
    }
};

// Tests

test "NewReno: initial state" {
    const cc = NewReno.init();
    try testing.expect(cc.inSlowStart());
    try testing.expectEqual(
        INITIAL_WINDOW_PACKETS * DEFAULT_MAX_DATAGRAM_SIZE,
        cc.congestion_window,
    );
}

test "NewReno: slow start growth" {
    var cc = NewReno.init();
    const initial_window = cc.congestion_window;

    // ACK 1200 bytes (sent at time 100)
    cc.onPacketAcked(1200, 100);
    try testing.expectEqual(initial_window + 1200, cc.congestion_window);
    try testing.expect(cc.inSlowStart());
}

test "NewReno: congestion event reduces window" {
    var cc = NewReno.init();
    const initial_window = cc.congestion_window;

    // Lost packet sent at time 100, detected at time 200
    cc.onCongestionEvent(100, 200);

    // Window should be reduced by beta (0.7)
    const expected = initial_window * NEWRENO_BETA / NEWRENO_BETA_DENOM;
    try testing.expectEqual(expected, cc.congestion_window);
    try testing.expect(!cc.inSlowStart()); // ssthresh = reduced window
}

test "NewReno: recovery period prevents double cutback" {
    var cc = NewReno.init();

    // First loss: packet sent at time 100, detected at time 200
    cc.onCongestionEvent(100, 200);
    const after_first = cc.congestion_window;

    // Second loss of a packet also sent before recovery (time 150 < 200) — should NOT cut
    cc.onCongestionEvent(150, 250);
    try testing.expectEqual(after_first, cc.congestion_window);

    // Loss of packet sent AFTER recovery started (time 300 > 200) — should cut
    cc.onCongestionEvent(300, 400);
    try testing.expect(cc.congestion_window < after_first);
}

test "NewReno: minimum window enforced" {
    var cc = NewReno.init();

    // Force tiny window
    cc.congestion_window = 3000;
    cc.congestion_recovery_start_time = null;
    cc.onCongestionEvent(100, 200);

    try testing.expect(cc.congestion_window >= MIN_WINDOW_PACKETS * DEFAULT_MAX_DATAGRAM_SIZE);
}

test "NewReno: persistent congestion resets to minimum" {
    var cc = NewReno.init();
    const initial_window = cc.congestion_window;
    try testing.expect(initial_window > MIN_WINDOW_PACKETS * DEFAULT_MAX_DATAGRAM_SIZE);

    const now: i64 = 1_000_000_000;
    cc.onPersistentCongestion(now);

    // Window should be at minimum (2 * MSS)
    try testing.expectEqual(MIN_WINDOW_PACKETS * DEFAULT_MAX_DATAGRAM_SIZE, cc.congestion_window);
    // ssthresh should be maxInt to allow slow start recovery (exponential growth)
    try testing.expectEqual(std.math.maxInt(u64), cc.ssthresh);
    // Should be in slow start after persistent congestion
    try testing.expect(cc.inSlowStart());
    // Recovery start time should be set to prevent re-triggering for old packets
    try testing.expectEqual(@as(?i64, now), cc.congestion_recovery_start_time);
    // Packets sent after 'now' should NOT be in recovery (can grow window)
    try testing.expect(!cc.inCongestionRecovery(now + 1));
    // Packets sent at or before 'now' SHOULD be in recovery (suppressed)
    try testing.expect(cc.inCongestionRecovery(now));
}

// ── CUBIC tests ──

test "Cubic: initial state" {
    const cc = Cubic.init();
    try testing.expect(cc.inSlowStart());
    try testing.expectEqual(
        INITIAL_WINDOW_PACKETS * DEFAULT_MAX_DATAGRAM_SIZE,
        cc.congestion_window,
    );
}

test "Cubic: slow start growth" {
    var cc = Cubic.init();
    const initial_window = cc.congestion_window;

    cc.onPacketAcked(1200, 100, 200);
    try testing.expectEqual(initial_window + 1200, cc.congestion_window);
    try testing.expect(cc.inSlowStart());
}

test "Cubic: congestion event reduces window by beta" {
    var cc = Cubic.init();
    const initial_window = cc.congestion_window;

    cc.onCongestionEvent(100, 200);

    // Window should be reduced by beta (0.7)
    const expected = initial_window * Cubic.BETA_NUM / Cubic.BETA_DENOM;
    try testing.expectEqual(expected, cc.congestion_window);
    try testing.expect(!cc.inSlowStart());
    // W_max should be saved
    try testing.expectEqual(initial_window, cc.w_max);
}

test "Cubic: recovery period prevents double cutback" {
    var cc = Cubic.init();

    cc.onCongestionEvent(100, 200);
    const after_first = cc.congestion_window;

    // Packet sent before recovery — should NOT cut
    cc.onCongestionEvent(150, 250);
    try testing.expectEqual(after_first, cc.congestion_window);

    // Packet sent AFTER recovery — should cut
    cc.onCongestionEvent(300, 400);
    try testing.expect(cc.congestion_window < after_first);
}

test "Cubic: minimum window enforced" {
    var cc = Cubic.init();
    cc.congestion_window = 3000;
    cc.congestion_recovery_start_time = null;
    cc.onCongestionEvent(100, 200);

    try testing.expect(cc.congestion_window >= MIN_WINDOW_PACKETS * DEFAULT_MAX_DATAGRAM_SIZE);
}

test "Cubic: persistent congestion resets to minimum" {
    var cc = Cubic.init();
    const now: i64 = 1_000_000_000;
    cc.onPersistentCongestion(now);

    try testing.expectEqual(MIN_WINDOW_PACKETS * DEFAULT_MAX_DATAGRAM_SIZE, cc.congestion_window);
    try testing.expectEqual(std.math.maxInt(u64), cc.ssthresh);
    try testing.expect(cc.inSlowStart());
    try testing.expectEqual(@as(?i64, now), cc.congestion_recovery_start_time);
    try testing.expect(cc.epoch_start == null);
    try testing.expectEqual(@as(u64, 0), cc.w_max);
}

test "Cubic: fast convergence reduces W_max" {
    var cc = Cubic.init();

    // First loss: W_max = initial window
    cc.onCongestionEvent(100, 200);
    const first_w_max = cc.w_max;
    try testing.expectEqual(INITIAL_WINDOW_PACKETS * DEFAULT_MAX_DATAGRAM_SIZE, first_w_max);

    // Second loss with smaller window: fast convergence should reduce W_max
    // Current cwnd < w_max, so fast convergence kicks in
    cc.congestion_recovery_start_time = null; // Allow new congestion event
    const cwnd_before = cc.congestion_window;
    cc.onCongestionEvent(300, 400);
    // W_max should be reduced: cwnd * (beta + 1) / 2
    const expected_w_max = cwnd_before * (Cubic.BETA_NUM + Cubic.BETA_DENOM) / (2 * Cubic.BETA_DENOM);
    try testing.expectEqual(expected_w_max, cc.w_max);
}

test "Cubic: epoch resets on congestion event" {
    var cc = Cubic.init();
    cc.epoch_start = 12345;

    cc.onCongestionEvent(100, 200);
    try testing.expect(cc.epoch_start == null);
}

test "Cubic: setMaxDatagramSize" {
    var cc = Cubic.init();
    cc.setMaxDatagramSize(1400);
    try testing.expectEqual(@as(u64, 1400), cc.max_datagram_size);
}

test "Cubic: PTO does not reduce window" {
    var cc = Cubic.init();
    const window_before = cc.congestion_window;
    cc.onPtoExpired();
    try testing.expectEqual(window_before, cc.congestion_window);
}

// ── icbrt tests ──

test "icbrt: basic cube roots" {
    try testing.expectEqual(@as(u64, 0), icbrt(0));
    try testing.expectEqual(@as(u64, 1), icbrt(1));
    try testing.expectEqual(@as(u64, 1), icbrt(7));
    try testing.expectEqual(@as(u64, 2), icbrt(8));
    try testing.expectEqual(@as(u64, 2), icbrt(26));
    try testing.expectEqual(@as(u64, 3), icbrt(27));
    try testing.expectEqual(@as(u64, 10), icbrt(1000));
    try testing.expectEqual(@as(u64, 10), icbrt(1100));
    try testing.expectEqual(@as(u64, 100), icbrt(1000000));
}

// ── Pacer tests ──

test "Pacer: initial burst allowed" {
    var pacer = Pacer.init();
    try testing.expectEqual(@as(i64, 0), pacer.timeUntilSend(1_000_000_000));
}

test "Pacer: rate limiting after burst" {
    var pacer = Pacer.init();
    var rtt = RttStats{};
    rtt.updateRtt(50_000_000, 0, false); // 50ms RTT

    pacer.setBandwidth(12000, &rtt); // 12KB window

    const now: i64 = 1_000_000_000;

    // Exhaust budget
    var i: u32 = 0;
    while (i < MAX_BURST_PACKETS + 1) : (i += 1) {
        pacer.onPacketSent(1200, now);
    }

    // Should now be rate-limited
    const delay = pacer.timeUntilSend(now);
    try testing.expect(delay > 0);
}

test "Pacer: checking between sends does not earn the same interval twice" {
    var pacer = Pacer.init();
    var rtt = RttStats{};
    rtt.updateRtt(50_000_000, 0, false);
    pacer.setBandwidth(12000, &rtt);

    const t0: i64 = 1_000_000_000;
    while (pacer.budget >= pacer.max_datagram_size) pacer.onPacketSent(1200, t0);
    const wait = pacer.timeUntilSend(t0);
    try testing.expect(wait > 1);

    // Partway through the wait, however often the send path asks, the pacer
    // still refuses, and the timer scheduling sees the same deadline.
    const mid = t0 + @divTrunc(wait, 2) + 1;
    const left = pacer.timeUntilSend(mid);
    try testing.expect(left > 0);
    try testing.expectEqual(left, pacer.timeUntilSend(mid));
    try testing.expectEqual(left, pacer.delayAt(mid));
    try testing.expect(pacer.timeUntilSend(mid + @divTrunc(left, 2)) > 0);
    try testing.expectEqual(@as(i64, 0), pacer.timeUntilSend(t0 + wait + 1));
}

test "Pacer: burst covers two milliseconds at a high rate, ten packets at a low one" {
    var rtt = RttStats{};
    rtt.updateRtt(1_000_000, 0, false); // 1 ms

    // 1.2 MB per ms (×1.25): two milliseconds of it is 3 MB, far past ten packets.
    var fast = Pacer.init();
    fast.setBandwidth(1_200_000, &rtt);
    try testing.expect(fast.max_burst > 2_900_000 and fast.max_burst <= 3_000_000);
    const t0: i64 = 1_000_000_000;
    fast.onPacketSent(1200, t0); // starts the clock
    fast.credited_at = t0 - 10 * std.time.ns_per_ms;
    try testing.expectEqual(fast.max_burst, fast.budgetAt(t0));
    var sent: u64 = 0;
    while (fast.timeUntilSend(t0) == 0) : (sent += 1) fast.onPacketSent(1200, t0);
    try testing.expect(sent > 100 * MAX_BURST_PACKETS);

    // 12 KB per 50 ms: two milliseconds of it is well under ten packets.
    rtt = RttStats{};
    rtt.updateRtt(50_000_000, 0, false);
    var slow = Pacer.init();
    slow.setBandwidth(12000, &rtt);
    try testing.expectEqual(MAX_BURST_PACKETS * DEFAULT_MAX_DATAGRAM_SIZE, slow.max_burst);

    // A larger datagram after PMTUD raises the floor with it.
    slow.max_datagram_size = 1452;
    slow.setBandwidth(12000, &rtt);
    try testing.expectEqual(MAX_BURST_PACKETS * 1452, slow.max_burst);
}

test "congestion window is capped at MAX_WINDOW_PACKETS" {
    var reno = NewReno.init();
    var cubic = Cubic.init();
    const cap = MAX_WINDOW_PACKETS * DEFAULT_MAX_DATAGRAM_SIZE;
    var i: usize = 0;
    while (i < 20_000) : (i += 1) {
        reno.onPacketAcked(DEFAULT_MAX_DATAGRAM_SIZE, 1);
        cubic.onPacketAcked(DEFAULT_MAX_DATAGRAM_SIZE, 1, 2);
    }
    try testing.expectEqual(cap, reno.congestion_window);
    try testing.expectEqual(cap, cubic.congestion_window);
}

// ── CUBIC arithmetic bounds ──

test "Cubic: a five-hour loss-free epoch stays inside the window cap" {
    var cc = Cubic.init();
    const mss = DEFAULT_MAX_DATAGRAM_SIZE;
    const cap = MAX_WINDOW_PACKETS * mss;
    const epoch_start: i64 = std.time.ns_per_s;
    const sent_time: i64 = epoch_start + 1;

    // A loss is ordinary; so is the epoch it opens. The first
    // acknowledgement after it starts the curve and every later one is
    // measured from there.
    cc.onCongestionEvent(0, 0);
    cc.onPacketAcked(mss, sent_time, epoch_start);
    const window_at_epoch_start = cc.congestion_window;
    try testing.expect(!cc.inSlowStart());
    try testing.expect(window_at_epoch_start < cap);

    // One hour and two are ordinary too, and still inside `u64`: the
    // curve's cube times an MSS only leaves the type between the fourth
    // and the fifth hour, so the last hop is the one that has to hold.
    const hours = [_]i64{ 1, 2, 5 };
    for (hours) |hour| {
        const before = cc.congestion_window;
        cc.onPacketAcked(mss, sent_time, epoch_start + hour * std.time.ns_per_hour);
        try testing.expect(cc.congestion_window >= before);
        try testing.expect(cc.congestion_window <= cap);
    }

    // Five hours out the curve asks for more than the cap allows, so the
    // cap — and not a wrapped curve — is the window a connection keeps.
    try testing.expectEqual(cap, cc.congestion_window);
}

test "Cubic: an epoch spanning the whole i64 clock stays bounded and never shrinks" {
    const mss = DEFAULT_MAX_DATAGRAM_SIZE;
    const cap = MAX_WINDOW_PACKETS * mss;
    const sent_time: i64 = 1; // after the recovery mark below, so these grow

    // These two spans are outside the domain — `now` before the epoch
    // origin on one side, a whole i64 of clock on the other — and are here
    // for the arithmetic, not for the physics. A backwards clock is a
    // caller bug and what the curve would mean is not promised; what is
    // promised is that the arithmetic is in range for every pair of `i64`
    // instants on one clock, and that the window a caller keeps stays
    // bounded and never shrinks.
    const spans = [_]struct { epoch_origin: i64, now: i64 }{
        .{
            .epoch_origin = std.math.minInt(i64) + 8 * std.time.ns_per_s,
            .now = std.math.maxInt(i64),
        },
        .{
            .epoch_origin = std.math.maxInt(i64) - 8 * std.time.ns_per_s,
            .now = std.math.minInt(i64),
        },
    };

    for (spans) |span| {
        var cc = Cubic.init();
        cc.onCongestionEvent(0, 0);
        cc.onPacketAcked(mss, sent_time, span.epoch_origin);
        const window_at_epoch_start = cc.congestion_window;
        try testing.expect(!cc.inSlowStart());
        try testing.expect(window_at_epoch_start < cap);

        cc.onPacketAcked(mss, sent_time, span.now);
        try testing.expect(cc.congestion_window >= window_at_epoch_start);
        try testing.expect(cc.congestion_window <= cap);
    }
}

test "Cubic: K is computed for a W_max at the top of the u64 range" {
    // Below `w_max` is what makes the epoch compute K at all, and outside
    // slow start is what makes the acknowledgement reach the curve.
    //
    // The datagram size is the divisor that turns `w_max` into MSS first,
    // so it decides whether `floor(3 * W_max_mss / 4)` is a figure this can
    // hold: at 1200 bytes it comfortably is, and at a datagram of one byte
    // the multiply that forms it is three times `maxInt(u64)` wide.
    const datagram_sizes = [_]struct { max_datagram_size: u64, k_ns: i64 }{
        .{ .max_datagram_size = DEFAULT_MAX_DATAGRAM_SIZE, .k_ns = 225_908_000_000_000 },
        .{ .max_datagram_size = 1, .k_ns = 2_400_639_000_000_000 },
    };

    for (datagram_sizes) |datagram| {
        var cc = Cubic.initWithMds(datagram.max_datagram_size);
        cc.congestion_window = std.math.maxInt(u64) - 1;
        cc.w_max = std.math.maxInt(u64);
        cc.ssthresh = 0;
        cc.onPacketAcked(1, 1, 0);

        // `floor(3 * W_max_mss / 4)` is a 1.15e16 MSS here, whose cube root
        // is about 2.26e5 — nanoseconds for K, and an answer `i64` holds.
        try testing.expectEqual(datagram.k_ns, cc.k_ns);
    }
}

test "Cubic curve: exact while the quotient fits, saturated above it" {
    const mss = DEFAULT_MAX_DATAGRAM_SIZE;

    // Five hours past K. The intermediate product `|tick|^3 * 4800` is what
    // leaves `u64` there; the quotient is not, and has to be the exact one —
    // 2_798_893_465_919_520, and not the 1_844_674_407_370_955 a clamp
    // applied before the division would hand back.
    //
    // The tick is (5h − K) in tenths of a second, with K at one second: the
    // epoch this comes from opens at one second and this is five hours
    // after it.
    const five_hour_tick: i128 = 179_990;
    try testing.expectEqual(
        @as(u64, 2_798_893_465_919_520),
        cubicCurveOffsetBytes(five_hour_tick, mss),
    );
    // The sign is the caller's, so the magnitude is the same either way.
    try testing.expectEqual(
        @as(u64, 2_798_893_465_919_520),
        cubicCurveOffsetBytes(-five_hour_tick, mss),
    );

    // The bound `cubicCurveOffsetBytes` documents: `2^65 / CURVE_TICK_NS`,
    // wide enough for two `i64` instants and a `k_ns` of either sign. It
    // saturates, and it does so from the sign the caller chose.
    const widest: i128 = @divTrunc(@as(i128, 1) << 65, CURVE_TICK_NS);
    try testing.expectEqual(std.math.maxInt(u64), cubicCurveOffsetBytes(widest, mss));
    try testing.expectEqual(std.math.maxInt(u64), cubicCurveOffsetBytes(-widest, mss));
}

test "saturatingMulDiv: exact below the bound, clamped above it" {
    // The first acknowledgement of a CUBIC epoch divides its way to this.
    try testing.expectEqual(@as(u64, 445), saturatingMulDiv(3120, 1200, 8400));

    // A divisor at the top of the range makes the bound `maxInt^2`, which
    // still fits u128; the quotient is zero, not a trap.
    try testing.expectEqual(@as(u64, 0), saturatingMulDiv(1, 1, std.math.maxInt(u64)));

    // Widest product there is, and a narrow divisor for it.
    try testing.expectEqual(
        std.math.maxInt(u64),
        saturatingMulDiv(std.math.maxInt(u64), std.math.maxInt(u64), 1),
    );
    try testing.expectEqual(
        std.math.maxInt(u64),
        saturatingMulDiv(std.math.maxInt(u64), 2, 1),
    );
}

// ── ACK input bounds ──

test "congestion: an acknowledgement wider than the window reaches the cap" {
    const cap = MAX_WINDOW_PACKETS * DEFAULT_MAX_DATAGRAM_SIZE;

    // `acked_bytes` is a packet's size, so a connection only ever hands over
    // what its send path fits in a datagram. `onPacketAcked` is a public
    // method and nothing in it says the sum fits: the growth add is a plain
    // `u64` addition, and an acknowledged size anywhere near the top of the
    // range walks past it. The ceiling is applied after the add, so the cap
    // is the window a caller should end up holding, and it is the value
    // these assert — not merely that nothing traps.
    var cubic = Cubic.init();
    cubic.onPacketAcked(std.math.maxInt(u64), 1, 2);
    try testing.expectEqual(cap, cubic.congestion_window);

    var reno = NewReno.init();
    reno.onPacketAcked(std.math.maxInt(u64), 1);
    try testing.expectEqual(cap, reno.congestion_window);

    // The same input reaches the round accumulator in congestion avoidance,
    // where the window is no longer growing by the acknowledged bytes: the
    // loss cuts 12_000 to seven tenths, and each round acknowledged whole
    // then adds one datagram back. The first round leaves the accumulator a
    // full window short of the top of the range, so it is the second that
    // has to stay in range.
    var reno_avoidance = NewReno.initWithMds(DEFAULT_MAX_DATAGRAM_SIZE);
    reno_avoidance.onCongestionEvent(0, 1);
    reno_avoidance.onPacketAcked(std.math.maxInt(u64), 2);
    reno_avoidance.onPacketAcked(std.math.maxInt(u64), 2);
    try testing.expectEqual(
        INITIAL_WINDOW_PACKETS * DEFAULT_MAX_DATAGRAM_SIZE * NEWRENO_BETA / NEWRENO_BETA_DENOM +
            2 * DEFAULT_MAX_DATAGRAM_SIZE,
        reno_avoidance.congestion_window,
    );
}
