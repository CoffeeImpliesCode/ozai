//! The RFC 9000 §13.4.2.1 ECN validation state machine: one value per path,
//! moved by four calls, holding no clock and no timer. It is reached through
//! `Connection.ecn_validator`, and its answer to `shouldMark` is what the
//! packet packer turns into the ECT(0) bit on outgoing 1-RTT packets.

const std = @import("std");
const testing = std.testing;

/// ECN validation state machine (RFC 9000 §13.4.2.1).
///
/// Tracks whether the network path supports ECN by monitoring
/// peer-reported ECN counts in ACK_ECN frames against what we sent.
///
/// It owns nothing and borrows nothing: it holds no allocator, no buffer and
/// no clock, and every instant and every peer count reaches it as an
/// argument. Copying the value copies the state, so a caller that hands a
/// copy to a path and keeps the original has two independent machines rather
/// than two views of one. All four methods are safe to call from one thread
/// only, the thread that owns this value.
pub const EcnValidator = struct {
    /// Which of the five RFC 9000 §13.4.2.1 states the path is in. Starts at
    /// `.disabled`, and only `start` moves it to `.testing`; nothing but
    /// `start` returns a validator to `.disabled` — a peer whose validation
    /// failed must not retry it on the same path without `reset`.
    state: State = .disabled,

    /// ECT(0)-marked packets this validator has been told about, counted
    /// since the last `start` or `reset`. Nothing reads it: `onPacketSent`
    /// adds and no method compares against it, so it is a running total a
    /// caller may read for its own accounting and nothing more.
    sent_ect0_count: u64 = 0,

    /// ECT(0)-marked packets the peer has acknowledged, accumulated by
    /// `validate` across calls. Also unread by every method here — a run
    /// that fails validation stops accumulating at the value it had reached,
    /// so it is not a total for the path and must not be read as one.
    acked_ect0_count: u64 = 0,

    /// ECT(0)-marked packets counted since `start`, against the ten-packet
    /// threshold in `onPacketSent`. Reset by `start` and `reset`; it is what
    /// `.testing` counts.
    testing_count: u8 = 0,

    const TESTING_THRESHOLD: u8 = 10;

    /// The five states of RFC 9000 §13.4.2.1, exhaustive and with no other
    /// value: a validator is in exactly one of them, and only `start` and
    /// `reset` leave `.disabled`.
    pub const State = enum {
        /// The default, and the state of a freshly declared validator.
        /// Nothing is validated and nothing is marked ECT(0). `validate`
        /// reports false without changing it, and `onPacketSent` only counts.
        disabled,
        /// `start` has run and fewer than ten ECT(0) packets have gone out.
        /// Outgoing packets are marked, and no ACK_ECN can move the path to
        /// `.capable` yet.
        testing,
        /// Enough packets have gone out to judge. Still marked, and the first
        /// `validate` call that reports any ECT(0) or CE increase makes it
        /// `.capable`.
        unknown,
        /// The path validated. Terminal for this path: nothing leaves
        /// `.capable` except `reset`.
        capable,
        /// A peer report failed validation. Terminal for this path, and
        /// permanent until `reset`: `validate` keeps reporting false and
        /// `shouldMark` keeps answering false, so a caller must not retry
        /// validation without moving to a new path first.
        failed,
    };

    /// Enters `.testing` from `.disabled`, zeroing both counters. A call in
    /// any other state is a no-op, so a path that has already failed cannot
    /// be restarted into validation without a `reset` first.
    pub fn start(self: *EcnValidator) void {
        if (self.state == .disabled) {
            self.state = .testing;
            self.testing_count = 0;
            self.sent_ect0_count = 0;
            self.acked_ect0_count = 0;
        }
    }

    /// Records one outgoing ack-eliciting packet marked ECT(0), and moves
    /// `.testing` to `.unknown` once ten of them have gone out in this epoch.
    /// Called for every ECT(0) packet, or the threshold is never reached and
    /// the path is never judged. A packet sent while the state is
    /// `.disabled` or `.failed` still increments `sent_ect0_count`; the
    /// threshold check runs only from `.testing`.
    pub fn onPacketSent(self: *EcnValidator) void {
        self.sent_ect0_count += 1;
        if (self.state == .testing) {
            self.testing_count += 1;
            if (self.testing_count >= TESTING_THRESHOLD) {
                self.state = .unknown;
            }
        }
    }

    /// Whether outgoing packets carry ECT(0). True in `.testing`, `.unknown`
    /// and `.capable`; false in `.disabled` and `.failed`. A pure read of
    /// `state` — it does not advance validation, so a path that sends no
    /// ECT(0) packets never leaves `.testing`.
    pub fn shouldMark(self: *const EcnValidator) bool {
        return switch (self.state) {
            .testing, .unknown, .capable => true,
            .disabled, .failed => false,
        };
    }

    /// Validate peer's ECN counts from an ACK_ECN frame.
    /// Returns true if valid; transitions to .failed on invalid.
    ///
    /// peer_ect0/ect1/ce: newly reported counts from ACK_ECN
    /// prev_ect0/ect1/prev_ce: previously stored counts for this PN space
    /// newly_acked_ect0: number of ECT(0)-marked packets acknowledged in this ACK
    ///
    /// False means one of three things, and only the caller can tell them:
    /// the validator was already `.disabled` or `.failed` and nothing
    /// changed; or the peer reported an ECT(1) increase, or an ECT(0)+CE
    /// increase below `newly_acked_ect0`, and the state is now `.failed`.
    /// A rejected report leaves `acked_ect0_count` at its previous value —
    /// the count is credited only on the accepted path — and `.failed` is
    /// not re-examined by any later call.
    ///
    /// The three `prev_*` arguments are the peer's last reported counts and
    /// the validator stores none of them, so the caller must keep them per
    /// packet number space and pass them back; the deltas are computed with
    /// saturating subtraction, so a peer that lowers a count reads as no
    /// change rather than as a wrap.
    pub fn validate(
        self: *EcnValidator,
        peer_ect0: u64,
        peer_ect1: u64,
        peer_ce: u64,
        prev_ect0: u64,
        prev_ect1: u64,
        prev_ce: u64,
        newly_acked_ect0: u64,
    ) bool {
        if (self.state == .disabled or self.state == .failed) return false;

        const ect0_delta = peer_ect0 -| prev_ect0;
        const ce_delta = peer_ce -| prev_ce;
        const ect1_delta = peer_ect1 -| prev_ect1;

        // ECT(1) must not increase — we never send ECT(1)
        if (ect1_delta > 0) {
            std.log.debug("ECN validation failed: ECT(1) increased by {d}", .{ect1_delta});
            self.state = .failed;
            return false;
        }

        // The sum of ECT(0) and CE increases must account for newly-acked ECT(0) packets
        if (newly_acked_ect0 > 0 and ect0_delta + ce_delta < newly_acked_ect0) {
            std.log.debug("ECN validation failed: ect0_delta({d})+ce_delta({d}) < newly_acked({d})", .{
                ect0_delta, ce_delta, newly_acked_ect0,
            });
            self.state = .failed;
            return false;
        }

        // Valid — transition unknown→capable
        if (self.state == .unknown and ect0_delta + ce_delta > 0) {
            self.state = .capable;
            std.log.info("ECN validation: path is ECN-capable", .{});
        }

        self.acked_ect0_count += newly_acked_ect0;
        return true;
    }

    /// Returns the validator to `.disabled` with both counters at zero,
    /// discards `.failed` along with the rest. Called when the path moves to
    /// a different IP: the old verdict described a path that is gone, and
    /// carrying it onto the new one would mark it `failed` without evidence.
    pub fn reset(self: *EcnValidator) void {
        self.* = .{};
    }
};

// Tests

test "start transitions disabled→testing" {
    var v = EcnValidator{};
    try testing.expectEqual(EcnValidator.State.disabled, v.state);
    v.start();
    try testing.expectEqual(EcnValidator.State.testing, v.state);
}

test "after 10 packets, testing→unknown" {
    var v = EcnValidator{};
    v.start();
    var i: u8 = 0;
    while (i < 9) : (i += 1) {
        v.onPacketSent();
        try testing.expectEqual(EcnValidator.State.testing, v.state);
    }
    v.onPacketSent(); // 10th
    try testing.expectEqual(EcnValidator.State.unknown, v.state);
}

test "valid ACK_ECN: unknown→capable" {
    var v = EcnValidator{};
    v.start();
    // Send 10 packets to reach unknown
    var i: u8 = 0;
    while (i < 10) : (i += 1) v.onPacketSent();
    try testing.expectEqual(EcnValidator.State.unknown, v.state);

    // Peer reports 10 ECT(0), 0 ECT(1), 0 CE (prev all 0)
    const valid = v.validate(10, 0, 0, 0, 0, 0, 10);
    try testing.expect(valid);
    try testing.expectEqual(EcnValidator.State.capable, v.state);
}

test "invalid ACK_ECN (ect1 increase): →failed" {
    var v = EcnValidator{};
    v.start();
    var i: u8 = 0;
    while (i < 10) : (i += 1) v.onPacketSent();

    // Peer reports ECT(1) increase — invalid since we never send ECT(1)
    const valid = v.validate(5, 3, 0, 0, 0, 0, 5);
    try testing.expect(!valid);
    try testing.expectEqual(EcnValidator.State.failed, v.state);
}

test "shouldMark returns false when failed/disabled" {
    var v = EcnValidator{};
    try testing.expect(!v.shouldMark()); // disabled

    v.start();
    try testing.expect(v.shouldMark()); // testing

    v.state = .failed;
    try testing.expect(!v.shouldMark()); // failed
}

test "reset returns to disabled" {
    var v = EcnValidator{};
    v.start();
    var i: u8 = 0;
    while (i < 10) : (i += 1) v.onPacketSent();
    _ = v.validate(10, 0, 0, 0, 0, 0, 10);
    try testing.expectEqual(EcnValidator.State.capable, v.state);

    v.reset();
    try testing.expectEqual(EcnValidator.State.disabled, v.state);
    try testing.expectEqual(@as(u64, 0), v.sent_ect0_count);
}

test "validate: ect0+ce delta too small → failed" {
    var v = EcnValidator{};
    v.start();
    var i: u8 = 0;
    while (i < 10) : (i += 1) v.onPacketSent();

    // Sent 10 ECT(0) packets but peer only reports 3
    const valid = v.validate(3, 0, 0, 0, 0, 0, 10);
    try testing.expect(!valid);
    try testing.expectEqual(EcnValidator.State.failed, v.state);
}
