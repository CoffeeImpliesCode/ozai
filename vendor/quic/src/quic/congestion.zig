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
    max_datagram_size: u64 = DEFAULT_MAX_DATAGRAM_SIZE,

    /// Time at which the current recovery period started (RFC 9002 §B.7).
    /// Losses of packets sent before this time don't trigger new recovery.
    congestion_recovery_start_time: ?i64 = null,

    /// Bytes acknowledged in the current round trip (for congestion avoidance).
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
            self.congestion_window += acked_bytes;
        } else {
            // Congestion avoidance: increase by MSS per RTT
            // Accumulate bytes and increase by MSS when a full window is acked
            self.bytes_acked_in_round += acked_bytes;
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

    // Persistent congestion detected (RFC 9002 §7.6.2).
    // Reset to minimum window with slow start (exponential) recovery,
    // similar to TCP RTO behavior (RFC 5681): cwnd = minimum, ssthresh = infinity
    // so that slow start can quickly probe available capacity.
    // Sets congestion_recovery_start_time = now so that subsequent loss events
    // for old packets (sent before this point) are suppressed via inCongestionRecovery.
    //
    // Not gated on recovery like `onCongestionEvent`: this is the RFC's
    // response to a span of losses, and it always applies. `ssthresh` goes to
    // infinity, so the next window is slow start from two MSS, and recovery
    // restarts at `now` so losses of packets sent before it are suppressed.
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
    max_datagram_size: u64 = DEFAULT_MAX_DATAGRAM_SIZE,

    /// Time at which the current recovery period started (RFC 9002 §B.7).
    congestion_recovery_start_time: ?i64 = null,

    /// Bytes acknowledged in the current round trip (for slow start / TCP-friendly).
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
    k_ns: i64 = 0,

    /// W_est: estimated TCP-friendly window (for TCP-friendly region).
    ///
    /// The Reno-fair floor the curve is never allowed to fall below, seeded
    /// from the window at the epoch start and grown one datagram per window
    /// acknowledged.
    w_est: u64 = 0,

    // ── Constants ──
    // Beta = 0.7 (RFC 8312 §4.5 recommends 0.7 for QUIC)
    const BETA_NUM: u64 = 7;
    const BETA_DENOM: u64 = 10;

    // C = 0.4 (RFC 8312 §5)
    // We scale by 1000 to avoid floating point: C_SCALED = 400
    //
    // Neither C constant is read: `cubicUpdate` carries the same 0.4 as the
    // literal scale factor 4 / 10000. They record the RFC's value, and
    // changing them changes nothing.
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
            self.congestion_window += acked_bytes;
        } else {
            self.cubicUpdate(acked_bytes, now);
        }
        self.congestion_window = @min(self.congestion_window, MAX_WINDOW_PACKETS * self.max_datagram_size);
    }

    /// CUBIC window update during congestion avoidance.
    ///
    /// Reached only from `onPacketAcked`, and only outside slow start, so
    /// `now` has already been checked against the recovery period. It never
    /// reduces the window: on the descending part of the curve
    /// `w_cubic_bytes` saturates at `w_max` and the Reno-fair `w_est` holds
    /// the floor, so a slow path shrinks through `onCongestionEvent` rather
    /// than through this.
    fn cubicUpdate(self: *Cubic, acked_bytes: u64, now: i64) void {
        // Initialize epoch on first ACK after congestion event
        if (self.epoch_start == null) {
            self.epoch_start = now;
            if (self.congestion_window < self.w_max) {
                // Compute K = cbrt(W_max * (1-beta) / C) in MSS units, then convert to nanoseconds
                // K_mss = cbrt((W_max/MSS) * 0.3 / 0.4) = cbrt((W_max/MSS) * 3/4)
                const w_max_mss = self.w_max / self.max_datagram_size;
                const numerator = w_max_mss * 3; // (1 - beta) = 0.3, scaled by 10 = 3
                const denominator: u64 = 4; // C = 0.4, scaled by 10 = 4
                const k_mss_cubed = numerator / denominator;
                // cbrt using integer approximation
                self.k_ns = @intCast(icbrt(k_mss_cubed) * 1_000_000_000); // seconds → ns
            } else {
                self.k_ns = 0;
            }
            // Initialize TCP-friendly estimate
            self.w_est = self.congestion_window;
        }

        const t_ns = now - (self.epoch_start orelse now); // time since epoch start in ns

        // W_cubic(t) = C * (t - K)^3 + W_max
        // All in bytes. t and K are in nanoseconds, so we need to convert to seconds.
        // t_sec = t_ns / 1e9, K_sec = K_ns / 1e9
        // W_cubic = C * ((t_ns - K_ns) / 1e9)^3 + W_max
        //         = C * (t_ns - K_ns)^3 / 1e27 + W_max
        // To avoid overflow, compute in MSS units:
        // W_cubic_mss = C * ((t_sec - K_sec))^3 + W_max_mss

        const t_minus_k_ns = t_ns - self.k_ns;
        const t_minus_k_sec_10 = @divTrunc(t_minus_k_ns, 100_000_000); // in 0.1 second units

        // (t-K)^3 in units of 0.001 seconds^3
        const t_cubed = t_minus_k_sec_10 * t_minus_k_sec_10 * t_minus_k_sec_10;

        // W_cubic = C * (t-K)^3 + W_max
        // With our scaling: C=0.4, t in 0.1s units, so (t/10)^3 = t^3/1000
        // W_cubic_bytes = 0.4 * t_cubed / 1000 * MSS + W_max
        // = t_cubed * MSS * 4 / 10000 + W_max
        const w_cubic_bytes: u64 = if (t_cubed >= 0)
            @as(u64, @intCast(t_cubed)) * self.max_datagram_size * 4 / 10000 + self.w_max
        else
            self.w_max -| @as(u64, @intCast(-t_cubed)) * self.max_datagram_size * 4 / 10000;

        // TCP-friendly estimate: W_est grows linearly (1 MSS per RTT) after recovery
        // W_est += 3 * beta / (2 - beta) * (acked_bytes / cwnd) per ACK
        // Simplified: ~= acked_bytes * 3 * 7 / (10 * (2*10 - 7)) * MSS / cwnd
        // ≈ acked_bytes * 21 / 130 * MSS / cwnd
        // Even simpler: grow by MSS per cwnd acked (like NewReno)
        self.bytes_acked_in_round += acked_bytes;
        if (self.bytes_acked_in_round >= self.congestion_window) {
            self.bytes_acked_in_round -= self.congestion_window;
            self.w_est += self.max_datagram_size;
        }

        // Use the larger of CUBIC and TCP-friendly targets
        const target = @max(w_cubic_bytes, self.w_est);

        // Increase cwnd toward target
        if (target > self.congestion_window) {
            // Increase proportionally to acked_bytes
            const increase = (target - self.congestion_window) * acked_bytes / self.congestion_window;
            self.congestion_window += @max(increase, 1);
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
    pub fn setMaxDatagramSize(self: *Cubic, size: u64) void {
        self.max_datagram_size = size;
    }
};

/// Integer cube root approximation (Newton's method).
fn icbrt(x: u64) u64 {
    if (x == 0) return 0;
    if (x <= 7) return 1;

    // Initial guess using bit shifting
    var guess: u64 = 1;
    var shift: u6 = 0;
    var temp = x;
    while (temp > 0) : (shift += 1) {
        temp >>= 1;
    }
    guess = @as(u64, 1) << (shift / 3 + 1);

    // Newton iterations: guess = (2*guess + x/(guess*guess)) / 3
    var i: u32 = 0;
    while (i < 10) : (i += 1) {
        const g2 = guess * guess;
        if (g2 == 0) break;
        const new_guess = (2 * guess + x / g2) / 3;
        if (new_guess >= guess) break;
        guess = new_guess;
    }

    // Verify and adjust
    while (guess * guess * guess > x) {
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
