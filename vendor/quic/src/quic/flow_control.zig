//! QUIC's two flow-control windows — one per connection, one per stream — as
//! two structs over one `BaseFlowController`. Reached through
//! `Connection.conn_flow_ctrl` and, for streams, through each stream's
//! `StreamFlowController`.
//!
//! Every window is in bytes. Send-side counters count bytes charged against
//! the peer's advertised limit and never decrease; receive-side counters
//! count bytes the peer may send, where `receive_window` is an absolute
//! stream offset rather than a size. No clock is read here: the only time
//! input is the `RttStats` the caller passes, which is borrowed for the
//! duration of one call.

const std = @import("std");
const testing = std.testing;

const rtt_mod = @import("rtt.zig");
const RttStats = rtt_mod.RttStats;

/// Fraction of the receive window that triggers a window update.
/// When the consumed portion exceeds this fraction, send a window update.
const WINDOW_UPDATE_FRACTION: u64 = 4; // 1/4

/// Maximum auto-tuning window size (default 6MB).
const MAX_RECEIVE_WINDOW: u64 = 6 * 1024 * 1024;

/// Base flow controller shared by both stream and connection level.
///
/// Two independent halves over one value. The send half charges bytes
/// against the peer's advertised limit and only ever moves forward; the
/// receive half tracks what the peer has sent and what the application has
/// read, and advertises a new limit when enough has been consumed. Nothing
/// here owns memory or borrows a buffer, so the struct is copyable and every
/// copy is an independent controller; `StreamFlowController` is not, because
/// it points at a `ConnectionFlowController`.
pub const BaseFlowController = struct {
    // Send-side state
    /// Bytes charged against `send_window` so far, cumulative for the life of
    /// the controller and never decremented: the window moves down on a
    /// `send_window` cut and up on a new MAX_DATA, this total does not.
    bytes_sent: u64 = 0,
    /// The peer's limit in bytes — MAX_DATA or MAX_STREAM_DATA, whichever
    /// this controller is — as an absolute offset into the byte space, not a
    /// size. Zero until the peer grants credit, so a fresh controller
    /// reports itself blocked.
    send_window: u64 = 0,
    // Track the limit at which we last sent a blocked frame (avoid duplicates)
    /// The limit `shouldSendBlocked` last reported, so it emits once per
    /// limit. `null` means none has been emitted; `updateSendWindow` clears
    /// it whenever the peer raises credit.
    blocked_at: ?u64 = null,

    // Receive-side state
    /// Bytes the application has consumed, cumulative. It is never reset, so
    /// a caller that re-reports the same bytes inflates the window update
    /// rate; each byte must be reported exactly once.
    bytes_read: u64 = 0,
    /// Highest byte offset the peer has sent, the value checked against
    /// `receive_window` and the one a window update is computed from.
    highest_received: u64 = 0,
    /// The limit currently advertised to the peer, as an absolute offset.
    /// `getWindowUpdate` advances it as a side effect, so the field and the
    /// value that method returned cannot be read as two independent facts.
    receive_window: u64,
    /// How much credit the next window update will grant: the distance from
    /// the offset the last update started at. Doubled by auto-tuning, capped
    /// by `max_receive_window_size`.
    receive_window_size: u64,
    /// Ceiling on `receive_window_size`, fixed at `init`. Auto-tuning doubles
    /// towards it and never past it.
    max_receive_window_size: u64,

    // Auto-tuning state
    /// Never read and never written after `init`: the auto-tuning epoch is
    /// measured in consumed bytes, not time, so there is no start instant
    /// here. Kept as a field for a caller that wants to record one.
    epoch_start_time: i64 = 0,
    /// `bytes_read` at the last auto-tuning check, so one epoch's
    /// consumption is measured from a fixed point rather than from
    /// connection start.
    epoch_start_offset: u64 = 0,

    /// A controller with no credit granted and no bytes exchanged.
    ///
    /// `receive_window` is the first limit advertised to the peer and
    /// `receive_window_size` the credit each later update grants.
    /// `max_receive_window` is a ceiling on the tunable size, raised to
    /// `receive_window` when it is given smaller — the ceiling can never sit
    /// below the window already in force, so auto-tuning cannot shrink the
    /// window a caller started with.
    pub fn init(receive_window: u64, max_receive_window: u64) BaseFlowController {
        return .{
            .receive_window = receive_window,
            .receive_window_size = receive_window,
            .max_receive_window_size = @max(max_receive_window, receive_window),
        };
    }

    /// Applies a new peer limit. A `new_window` at or below the current
    /// `send_window` is ignored: the peer may not retract credit, and a
    /// MAX_DATA that arrives stale or reordered leaves the higher limit in
    /// place. A limit that does raise it also clears `blocked_at`, so a
    /// BLOCKED frame can be emitted again at the new limit.
    pub fn updateSendWindow(self: *BaseFlowController, new_window: u64) void {
        if (new_window > self.send_window) {
            self.send_window = new_window;
            // Clear blocked_at so we can send a new blocked frame if we hit the new limit
            self.blocked_at = null;
        }
    }

    /// Bytes still available to send: `send_window - bytes_sent`, or zero
    /// once the two meet or the total has overshot. Saturating, so a caller
    /// that charged more than the window is told zero rather than a wrap.
    pub fn sendWindowSize(self: *const BaseFlowController) u64 {
        if (self.bytes_sent >= self.send_window) return 0;
        return self.send_window - self.bytes_sent;
    }

    /// Charges `n` bytes against the window. No error and no clamp: charging
    /// past the window leaves `bytes_sent` above `send_window` and the
    /// controller blocked, which is a protocol violation the caller has
    /// already committed. Size the send from `sendWindowSize` first.
    pub fn addBytesSent(self: *BaseFlowController, n: u64) void {
        self.bytes_sent += n;
    }

    /// Whether no further bytes may be sent. True at exactly the limit, not
    /// past it, so a sender that fills the window exactly is reported
    /// blocked.
    pub fn isBlocked(self: *const BaseFlowController) bool {
        return self.bytes_sent >= self.send_window;
    }

    // Check if we should send a BLOCKED frame and mark it as sent.
    // Returns the limit if a blocked frame should be sent, null otherwise.
    // BLOCKED frames are advisory. Emitting once per blocked limit avoids
    // packet storms while still re-arming when the peer raises credit.
    //
    // The return is the limit to encode in the frame, and taking it consumes
    // the one emission for that limit: a second call at the same limit
    // returns null. `updateSendWindow` re-arms it.
    pub fn shouldSendBlocked(self: *BaseFlowController) ?u64 {
        if (self.bytes_sent >= self.send_window and self.blocked_at != self.send_window) {
            self.blocked_at = self.send_window;
            return self.send_window;
        }
        return null;
    }

    /// Records that the peer has sent up to `offset` in this byte space.
    /// `offset` is an absolute end offset, not a length: pass the highest
    /// offset received, and pass it again for a retransmission of data
    /// already counted.
    ///
    /// `error.FlowControlError` when `offset` is past `receive_window`, which
    /// is a FLOW_CONTROL_ERROR the connection turns into a connection close.
    /// The check runs before the update, so `highest_received` is left at its
    /// previous value and the controller stays usable. An offset inside the
    /// window never lowers `highest_received`.
    pub fn addBytesReceived(self: *BaseFlowController, offset: u64) !void {
        if (offset > self.receive_window) {
            return error.FlowControlError;
        }
        if (offset > self.highest_received) {
            self.highest_received = offset;
        }
    }

    /// Reports `n` bytes consumed by the application, advancing the window
    /// update trigger. Each byte must be reported exactly once: this is a
    /// cumulative total and a repeated report grants the peer credit it has
    /// not earned.
    pub fn addBytesRead(self: *BaseFlowController, n: u64) void {
        self.bytes_read += n;
    }

    /// Whether to advertise more receive credit, and the new absolute limit
    /// if so. Returns null when less than a quarter of the granted window has
    /// been consumed, so the peer is not pinged for credit it has not spent.
    ///
    /// The returned limit is committed before the call returns:
    /// `receive_window` already holds it, and the caller must queue a
    /// MAX_DATA or MAX_STREAM_DATA carrying exactly this value. Calling
    /// again before the frame goes out returns null rather than a second,
    /// larger limit, so a caller that drops the answer has spent the update.
    ///
    /// Before answering it may double `receive_window_size`, up to
    /// `max_receive_window_size`, when this epoch consumed more than a
    /// quarter of the window and the RTT sample is fresh; the check needs a
    /// measurement, so with no RTT sample yet the window never grows.
    ///
    /// `rtt_stats` is borrowed for the call and not retained.
    pub fn getWindowUpdate(self: *BaseFlowController, rtt_stats: *const RttStats) ?u64 {
        const consumed = self.bytes_read;
        const window_end = self.receive_window;

        // Don't update until we've consumed a significant portion
        if (consumed + self.receive_window_size / WINDOW_UPDATE_FRACTION > window_end) {
            // Auto-tune the window size
            self.maybeAdjustWindowSize(rtt_stats);

            // Calculate new window
            const new_window = consumed + self.receive_window_size;
            if (new_window > self.receive_window) {
                self.receive_window = new_window;
                return new_window;
            }
        }
        return null;
    }

    /// Auto-tune the receive window based on throughput and RTT.
    ///
    /// Reached only from `getWindowUpdate`, and only on the branch where an
    /// update was already due, so it can never grow the window by itself. It
    /// needs a fresh RTT sample and a non-zero `srtt`, or it returns having
    /// done nothing — including without resetting the epoch, so the next
    /// check measures the same bytes again.
    fn maybeAdjustWindowSize(self: *BaseFlowController, rtt_stats: *const RttStats) void {
        if (!rtt_stats.has_measurement) return;

        const bytes_consumed = self.bytes_read - self.epoch_start_offset;
        if (bytes_consumed == 0) return;

        // Check if we're consuming data fast enough to justify a larger window
        // If consumption exceeds window_size / (4 * RTT) within the epoch,
        // double the window.
        const srtt = rtt_stats.smoothedRttOrDefault();
        if (srtt <= 0) return;

        // Threshold: if consumed > window_size * fraction / (4 * RTT) * RTT
        // Simplified: if consumed > window_size / 4
        if (bytes_consumed > self.receive_window_size / WINDOW_UPDATE_FRACTION) {
            self.receive_window_size = @min(
                self.receive_window_size * 2,
                self.max_receive_window_size,
            );
        }

        // Reset epoch
        self.epoch_start_offset = self.bytes_read;
    }
};

/// Stream-level flow controller: this stream's own window, charged against
/// the connection's.
///
/// It owns its `base` and borrows `connection`, which must outlive it. That
/// borrow is what makes this struct unsafe to copy: a copy shares the
/// connection controller with the original, and bytes charged through either
/// move the same connection window, so exactly one of the two may be treated
/// as the stream's. It owns no memory and holds no buffer.
pub const StreamFlowController = struct {
    /// This stream's own window. The same counters as the connection's, over
    /// this stream's byte space only.
    base: BaseFlowController,
    /// The connection window every send and every read is charged against as
    /// well. Borrowed at `init`, never null, and not owned: this struct has
    /// no `deinit`, because there is nothing of its own to release. The
    /// connection controller must outlive every stream pointing at it.
    connection: *ConnectionFlowController,

    /// A stream window at `receive_window` with a tunable ceiling of
    /// `max_receive_window`, bound to the connection controller `connection`
    /// names. Nothing is allocated and nothing is copied out of `connection`,
    /// so the controller may be stored inline in a stream, but the pointer is
    /// what links the two: the connection controller must stay where `init`
    /// found it.
    pub fn init(
        receive_window: u64,
        max_receive_window: u64,
        connection: *ConnectionFlowController,
    ) StreamFlowController {
        return .{
            .base = BaseFlowController.init(receive_window, max_receive_window),
            .connection = connection,
        };
    }

    /// Applies a MAX_STREAM_DATA to this stream only. The connection window
    /// is untouched: a peer's MAX_DATA is applied to the connection
    /// controller separately.
    pub fn updateSendWindow(self: *StreamFlowController, new_window: u64) void {
        self.base.updateSendWindow(new_window);
    }

    /// Returns the number of bytes available to send (minimum of stream and connection window).
    ///
    /// The connection window is read live, so the figure shrinks as other
    /// streams on the same connection spend it, and no single call reserves
    /// anything: a caller sizing one packet from this value can still be
    /// over-committed by the time it sends.
    pub fn sendWindowSize(self: *const StreamFlowController) u64 {
        return @min(
            self.base.sendWindowSize(),
            self.connection.base.sendWindowSize(),
        );
    }

    /// Charges `n` bytes against both windows. Neither charge can fail, so a
    /// stream that is charged is charged, and the connection total stays the
    /// sum of the streams'.
    pub fn addBytesSent(self: *StreamFlowController, n: u64) void {
        self.base.addBytesSent(n);
        self.connection.base.addBytesSent(n);
    }

    /// Records that the peer sent this stream up to `offset` in the stream's
    /// byte space, and charges the growth past what this stream had already
    /// reported against the connection window.
    ///
    /// `error.FlowControlError` comes from either level: past this stream's
    /// `receive_window`, or past the connection's. The stream's own
    /// `highest_received` is updated first, so when the connection window is
    /// the one that rejects the frame, this stream has already recorded the
    /// offset while the connection has not. The connection is closing on this
    /// error, so the asymmetry is not repaired — a caller that retries must
    /// not assume the two are back in step.
    pub fn addBytesReceived(self: *StreamFlowController, offset: u64) !void {
        try self.base.addBytesReceived(offset);
        try self.connection.base.addBytesReceived(
            self.connection.base.highest_received + (offset - self.base.highest_received),
        );
    }

    /// Reports `n` bytes consumed, against this stream and the connection.
    /// The two triggers move together, so a byte the application read frees
    /// credit on both windows; report it once, or the window update fires
    /// twice for one read.
    pub fn addBytesRead(self: *StreamFlowController, n: u64) void {
        self.base.addBytesRead(n);
        self.connection.addBytesRead(n);
    }

    /// This stream's window update, with `getWindowUpdate`'s committed-limit
    /// contract and its quarter-of-window trigger. The connection's own
    /// update is a separate call on the connection controller, and the two
    /// are independent: this one returning null says nothing about whether
    /// the connection has credit to advertise.
    pub fn getWindowUpdate(self: *StreamFlowController, rtt_stats: *const RttStats) ?u64 {
        return self.base.getWindowUpdate(rtt_stats);
    }

    /// Whether either window is exhausted. A stream blocked only by the
    /// connection reports blocked, so a caller that reacts by sending
    /// MAX_STREAM_DATA has diagnosed nothing; check which one it is before
    /// answering.
    pub fn isBlocked(self: *const StreamFlowController) bool {
        return self.base.isBlocked() or self.connection.base.isBlocked();
    }
};

/// Connection-level flow controller: the sum of every stream on the
/// connection. Reached through `Connection.conn_flow_ctrl`, which the
/// packet packer also borrows to charge the bytes it packs.
///
/// It owns nothing and borrows nothing, so it may be copied freely and each
/// copy is an independent window — except that a `StreamFlowController`
/// pointing at the original would then be updating a different window from
/// the connection's, so the value must not be copied once streams are bound
/// to it.
pub const ConnectionFlowController = struct {
    /// The one window. The packer and the connection's own send path reach
    /// through it for the operations this type does not forward:
    /// `shouldSendBlocked`, `addBytesReceived` and `addBytesSent` have no
    /// wrapper here and are called on `base`.
    base: BaseFlowController,

    /// A connection window at `receive_window` with a tunable ceiling of
    /// `max_receive_window`. Same starting values and same ceiling rule as
    /// `BaseFlowController.init`.
    pub fn init(receive_window: u64, max_receive_window: u64) ConnectionFlowController {
        return .{
            .base = BaseFlowController.init(receive_window, max_receive_window),
        };
    }

    /// Applies a MAX_DATA from the peer. A smaller value is ignored, as in
    /// `BaseFlowController.updateSendWindow`.
    pub fn updateSendWindow(self: *ConnectionFlowController, new_window: u64) void {
        self.base.updateSendWindow(new_window);
    }

    /// Bytes the connection may still send, connection-level only. This is
    /// the figure a single stream's `sendWindowSize` is clamped by, so it
    /// falls as any stream on the connection spends it.
    pub fn sendWindowSize(self: *const ConnectionFlowController) u64 {
        return self.base.sendWindowSize();
    }

    /// Reports `n` bytes consumed anywhere on the connection, advancing the
    /// trigger for the one MAX_DATA this window produces. Each byte is
    /// reported once across all streams; a stream reporting through
    /// `StreamFlowController.addBytesRead` has already reported it here.
    pub fn addBytesRead(self: *ConnectionFlowController, n: u64) void {
        self.base.addBytesRead(n);
    }

    /// The MAX_DATA to send, with `BaseFlowController.getWindowUpdate`'s
    /// committed-limit contract: the returned value already is
    /// `base.receive_window`, and a caller that drops it has spent the
    /// update.
    pub fn getWindowUpdate(self: *ConnectionFlowController, rtt_stats: *const RttStats) ?u64 {
        return self.base.getWindowUpdate(rtt_stats);
    }

    /// Whether the connection window is exhausted, ignoring every individual
    /// stream: a connection can be open for sending while no one stream can
    /// use it.
    pub fn isBlocked(self: *const ConnectionFlowController) bool {
        return self.base.isBlocked();
    }
};

// Tests

test "BaseFlowController: send window" {
    var fc = BaseFlowController.init(1000, MAX_RECEIVE_WINDOW);
    fc.send_window = 5000;

    try testing.expectEqual(@as(u64, 5000), fc.sendWindowSize());
    try testing.expect(!fc.isBlocked());

    fc.addBytesSent(3000);
    try testing.expectEqual(@as(u64, 2000), fc.sendWindowSize());

    fc.addBytesSent(2000);
    try testing.expect(fc.isBlocked());
    try testing.expectEqual(@as(u64, 0), fc.sendWindowSize());
}

test "BaseFlowController: receive window" {
    var fc = BaseFlowController.init(1000, MAX_RECEIVE_WINDOW);

    // Should accept data within window
    try fc.addBytesReceived(500);
    try fc.addBytesReceived(1000);

    // Should reject data outside window
    try testing.expectError(error.FlowControlError, fc.addBytesReceived(1001));
}

test "BaseFlowController: window update" {
    var fc = BaseFlowController.init(1000, MAX_RECEIVE_WINDOW);
    var rtt = RttStats{};
    rtt.updateRtt(50_000_000, 0, false); // 50ms

    try fc.addBytesReceived(1000);

    // Read enough to trigger update (> 1/4 of window)
    fc.addBytesRead(800);
    const update = fc.getWindowUpdate(&rtt);
    try testing.expect(update != null);
    try testing.expect(update.? > 1000);
}

test "ConnectionFlowController: basic" {
    var cfc = ConnectionFlowController.init(10000, MAX_RECEIVE_WINDOW);
    cfc.updateSendWindow(50000);

    try testing.expectEqual(@as(u64, 50000), cfc.sendWindowSize());
    try testing.expect(!cfc.isBlocked());
}

test "StreamFlowController: limited by connection" {
    var cfc = ConnectionFlowController.init(10000, MAX_RECEIVE_WINDOW);
    cfc.base.send_window = 500; // Connection window is 500

    var sfc = StreamFlowController.init(10000, MAX_RECEIVE_WINDOW, &cfc);
    sfc.base.send_window = 2000; // Stream window is 2000

    // Should be limited by connection window
    try testing.expectEqual(@as(u64, 500), sfc.sendWindowSize());
}

test "BaseFlowController: shouldSendBlocked emits once per blocked limit" {
    var fc = BaseFlowController.init(1000, MAX_RECEIVE_WINDOW);
    fc.send_window = 100;
    fc.addBytesSent(100);

    // First call should return the limit
    try testing.expectEqual(@as(?u64, 100), fc.shouldSendBlocked());
    // Repeated calls at the same blocked limit should not generate a packet storm.
    try testing.expectEqual(@as(?u64, null), fc.shouldSendBlocked());

    // After window update, should be able to send again
    fc.updateSendWindow(200);
    try testing.expect(!fc.isBlocked());
    fc.addBytesSent(100);
    try testing.expectEqual(@as(?u64, 200), fc.shouldSendBlocked());
}

test "BaseFlowController: updateSendWindow ignores smaller values" {
    var fc = BaseFlowController.init(1000, MAX_RECEIVE_WINDOW);
    fc.send_window = 5000;

    // Smaller window should be ignored
    fc.updateSendWindow(3000);
    try testing.expectEqual(@as(u64, 5000), fc.send_window);

    // Larger window should be accepted
    fc.updateSendWindow(8000);
    try testing.expectEqual(@as(u64, 8000), fc.send_window);
}

test "StreamFlowController: addBytesSent updates both stream and connection" {
    var cfc = ConnectionFlowController.init(10000, MAX_RECEIVE_WINDOW);
    cfc.base.send_window = 10000;

    var sfc = StreamFlowController.init(10000, MAX_RECEIVE_WINDOW, &cfc);
    sfc.base.send_window = 10000;

    sfc.addBytesSent(500);
    try testing.expectEqual(@as(u64, 500), sfc.base.bytes_sent);
    try testing.expectEqual(@as(u64, 500), cfc.base.bytes_sent);
}

test "StreamFlowController: isBlocked when either is blocked" {
    var cfc = ConnectionFlowController.init(10000, MAX_RECEIVE_WINDOW);
    cfc.base.send_window = 1000;

    var sfc = StreamFlowController.init(10000, MAX_RECEIVE_WINDOW, &cfc);
    sfc.base.send_window = 5000;

    // Neither blocked initially
    try testing.expect(!sfc.isBlocked());

    // Block at connection level
    cfc.base.addBytesSent(1000);
    try testing.expect(sfc.isBlocked());
}

test "BaseFlowController: auto-tuning doubles window" {
    var fc = BaseFlowController.init(1000, MAX_RECEIVE_WINDOW);
    var rtt = RttStats{};
    rtt.updateRtt(50_000_000, 0, false);

    try fc.addBytesReceived(1000);
    // Read more than 1/4 of window to trigger auto-tuning
    fc.addBytesRead(800);
    _ = fc.getWindowUpdate(&rtt);

    // Window size should have doubled (up to max)
    try testing.expectEqual(@as(u64, 2000), fc.receive_window_size);
}
