//! Path MTU discovery for the sans-I/O core: the binary search, the probe
//! schedule, and the raise timer, as a state machine over caller-supplied
//! nanosecond instants.
//!
//! Nothing here reads a clock or touches a socket. Every entry point takes the
//! current instant as an `i64` nanosecond value the caller read, and the
//! discoverer never interprets it — it only differences it, so a caller must
//! keep passing instants from one monotonic clock. A `MtuDiscoverer` borrows
//! nothing and allocates nothing; it is a value the `Connection` owns and
//! resets on migration.

const std = @import("std");
const testing = std.testing;

/// QUIC minimum datagram size — always works (RFC 9000 Section 14).
pub const BASE_PLPMTU: u16 = 1200;

/// Maximum PLPMTU to probe for (IPv6 over Ethernet: 1500 - 40 - 8 = 1452).
pub const MAX_PLPMTU: u16 = 1452;

/// Binary search termination threshold (bytes).
const MTU_SEARCH_STEP: u16 = 20;

/// Maximum consecutive failed probes before giving up on a size.
const MAX_PROBES: u8 = 3;

/// Multiplier for probe interval (5 × smoothed RTT).
const PROBE_DELAY_MULTIPLIER: i64 = 5;

/// Minimum probe interval (200ms in nanoseconds) to avoid probing too fast.
const MIN_PROBE_INTERVAL: i64 = 200_000_000;

/// Timer for re-probing after search completes (600 seconds = 10 minutes).
const RAISE_TIMER_NS: i64 = 600_000_000_000;

/// Which arm of the search a `MtuDiscoverer` is in. `.disabled` is the zero
/// value and what a freshly default-constructed discoverer holds; it is also
/// the only state `MtuDiscoverer.state` is allowed to hold before `start`.
pub const MtuState = enum {
    /// Search not started yet (waiting for handshake).
    disabled,
    /// Actively probing for larger MTU via binary search.
    searching,
    /// Search converged; current PLPMTU is the best we found.
    search_complete,
};

/// Datagram Packetization Layer PMTU Discovery (DPLPMTUD) for QUIC.
///
/// After handshake completion, performs a binary search between BASE_PLPMTU
/// and MAX_PLPMTU to discover the largest packet size the path supports.
/// Probes are PING+PADDING packets; ACK confirms success, loss narrows range.
pub const MtuDiscoverer = struct {
    /// Which arm of the search this discoverer is in. Nothing else reads it to
    /// decide whether to probe; `shouldProbe` and `checkRaiseTimer` are the
    /// only entries that consult it.
    state: MtuState = .disabled,

    /// Bytes. The largest probe size the path has acknowledged. `Connection`
    /// copies it into the packer, the congestion controller and the pacer, so
    /// this is the datagram size the outbound path is held to; it never falls
    /// below `BASE_PLPMTU`.
    current_mtu: u16 = BASE_PLPMTU,

    /// Bytes. Lower bound of the binary search: the last size confirmed good.
    /// `nextProbeSize` never proposes below it, and `onProbeAcked` raises it to
    /// the size just acknowledged.
    search_min: u16 = BASE_PLPMTU,

    /// Bytes. Inclusive upper bound of the search range, at most `MAX_PLPMTU`.
    /// `onProbeLost` lowers it to `probe_size` once that size has failed
    /// `MAX_PROBES` times, and `checkRaiseTimer` restores it on re-probe.
    search_max: u16 = MAX_PLPMTU,

    /// Packet number of the last MTU probe sent (null if none outstanding).
    probe_pn: ?u64 = null,

    /// Bytes. The size `onProbeSent` recorded, which `onProbeAcked` promotes to
    /// `current_mtu` and which `onProbeLost` turns into the new `search_max`.
    /// 0 means no probe has been sent.
    probe_size: u16 = 0,

    /// Number of consecutive failed probes at current probe_size.
    probe_count: u8 = 0,

    /// The caller's monotonic instant, in nanoseconds, at which the last probe
    /// went out. 0 is the sentinel for "never probed", so `shouldProbe` answers
    /// true regardless of interval until the first `onProbeSent`. Every instant
    /// must come from one clock: the only use here is a difference.
    last_probe_time: i64 = 0,

    /// The caller's monotonic instant, in nanoseconds, at which the search
    /// converged. Written by `onProbeAcked` and `onProbeLost` on the transition
    /// into `.search_complete`, and read by `checkRaiseTimer` as the start of
    /// the raise interval.
    search_complete_time: i64 = 0,

    /// Start MTU discovery (called after handshake completes).
    ///
    /// Moves `.disabled` to `.searching` and resets the search range and
    /// `probe_count`. It is a no-op in any other state, so a caller that has
    /// already started gets its in-flight search rather than a restarted one;
    /// `reset` is the entry that restarts from `.search_complete`.
    pub fn start(self: *MtuDiscoverer) void {
        if (self.state != .disabled) return;
        self.state = .searching;
        self.search_min = BASE_PLPMTU;
        self.search_max = MAX_PLPMTU;
        self.probe_count = 0;
    }

    /// Check if it's time to send a probe.
    ///
    /// `now` is the caller's monotonic instant in nanoseconds and
    /// `smoothed_rtt` is the current estimate in nanoseconds, both on the same
    /// clock as `last_probe_time`. True only in `.searching` with no probe
    /// outstanding, and then only once `max(5 * smoothed_rtt, 200ms)` has
    /// elapsed since `onProbeSent`. Reads only; it does not reserve the probe,
    /// so a caller that sends nothing leaves the answer unchanged.
    pub fn shouldProbe(self: *const MtuDiscoverer, now: i64, smoothed_rtt: i64) bool {
        if (self.state != .searching) return false;
        // Don't probe if we have one outstanding
        if (self.probe_pn != null) return false;

        if (self.last_probe_time == 0) return true;

        const interval = @max(smoothed_rtt * PROBE_DELAY_MULTIPLIER, MIN_PROBE_INTERVAL);
        return (now - self.last_probe_time) >= interval;
    }

    /// Get the next probe size (binary search midpoint), in bytes.
    ///
    /// The midpoint of `[search_min, search_max]`, so never below `search_min`
    /// and never above `search_max`. Reads only; the size is not consumed until
    /// `onProbeSent` records it, and asking twice returns the same answer.
    pub fn nextProbeSize(self: *const MtuDiscoverer) u16 {
        return self.search_min + (self.search_max - self.search_min) / 2;
    }

    /// Record that a probe was sent.
    ///
    /// `pn` is the packet number the probe left under and `size` the value
    /// `nextProbeSize` returned, in bytes; `now` is the caller's monotonic
    /// instant in nanoseconds. This is what makes the probe outstanding, so
    /// `shouldProbe` answers false until `onProbeAcked` or `onProbeLost` takes
    /// the same `pn`. Any earlier outstanding probe is overwritten, not
    /// reported.
    pub fn onProbeSent(self: *MtuDiscoverer, pn: u64, size: u16, now: i64) void {
        self.probe_pn = pn;
        self.probe_size = size;
        self.last_probe_time = now;
    }

    /// Called when the probe packet was ACK'd — the probed size works.
    ///
    /// `pn` must be the outstanding probe's packet number and the state must be
    /// `.searching`; anything else returns false and changes nothing, so
    /// `Connection` can hand this every ACK without filtering first. On true,
    /// `probe_size` becomes `current_mtu` and `search_min`, `probe_count`
    /// resets, and the search moves to `.search_complete` once the remaining
    /// range is 20 bytes or narrower, or `current_mtu` reached `MAX_PLPMTU`.
    pub fn onProbeAcked(self: *MtuDiscoverer, pn: u64, now: i64) bool {
        if (self.probe_pn == null or self.probe_pn.? != pn) return false;
        if (self.state != .searching) return false;

        // Confirmed: this size works
        self.current_mtu = self.probe_size;
        self.search_min = self.probe_size;
        self.probe_pn = null;
        self.probe_count = 0;

        // Check if search is done
        if (self.search_max - self.search_min <= MTU_SEARCH_STEP or
            self.current_mtu >= MAX_PLPMTU)
        {
            self.state = .search_complete;
            self.search_complete_time = now;
        }

        return true;
    }

    /// Called when the probe packet was declared lost — the probed size may not work.
    ///
    /// Same acceptance rule as `onProbeAcked`: false and unchanged unless `pn`
    /// is the outstanding probe and the state is `.searching`. On true the
    /// probe is no longer outstanding; `search_max` only drops to `probe_size`
    /// once three consecutive losses have accumulated at that size, and the
    /// search converges when the remaining range is 20 bytes or narrower. A
    /// loss below that count reports true and narrows nothing, which is how
    /// the caller tells a probe loss from an ordinary one.
    pub fn onProbeLost(self: *MtuDiscoverer, pn: u64, now: i64) bool {
        if (self.probe_pn == null or self.probe_pn.? != pn) return false;
        if (self.state != .searching) return false;

        self.probe_pn = null;
        self.probe_count += 1;

        if (self.probe_count >= MAX_PROBES) {
            // This size doesn't work — narrow the upper bound
            self.search_max = self.probe_size;
            self.probe_count = 0;

            // Check if search is done
            if (self.search_max - self.search_min <= MTU_SEARCH_STEP) {
                self.state = .search_complete;
                self.search_complete_time = now;
            }
        }

        return true;
    }

    /// Check if the raise timer has expired (re-probe after search_complete).
    ///
    /// In `.search_complete` and at least the raise interval past
    /// `search_complete_time`, this returns the discoverer to `.searching`
    /// with `search_max` back at `MAX_PLPMTU`. It does not lower `current_mtu`
    /// or widen `search_min`: the next `onProbeAcked` does that. In every other
    /// state, or before the interval has elapsed, nothing changes.
    pub fn checkRaiseTimer(self: *MtuDiscoverer, now: i64) void {
        if (self.state != .search_complete) return;
        if (now - self.search_complete_time >= RAISE_TIMER_NS) {
            // Re-enter searching to see if path MTU has increased
            self.state = .searching;
            self.search_max = MAX_PLPMTU;
            self.probe_count = 0;
        }
    }

    /// Reset to base (e.g., on connection migration with IP change).
    ///
    /// `current_mtu` and `search_min` return to `BASE_PLPMTU`, `search_max` to
    /// `MAX_PLPMTU`, any outstanding probe is forgotten, and the state lands in
    /// `.searching` — not `.disabled` — because the new path is already usable.
    /// Unlike `start` this runs from any state, including `.searching`.
    pub fn reset(self: *MtuDiscoverer) void {
        self.current_mtu = BASE_PLPMTU;
        self.search_min = BASE_PLPMTU;
        self.search_max = MAX_PLPMTU;
        self.probe_pn = null;
        self.probe_count = 0;
        self.state = .searching;
    }
};

// Tests

test "MtuDiscoverer: initial state" {
    const d = MtuDiscoverer{};
    try testing.expectEqual(MtuState.disabled, d.state);
    try testing.expectEqual(BASE_PLPMTU, d.current_mtu);
}

test "MtuDiscoverer: start begins searching" {
    var d = MtuDiscoverer{};
    d.start();
    try testing.expectEqual(MtuState.searching, d.state);
}

test "MtuDiscoverer: binary search midpoint" {
    var d = MtuDiscoverer{};
    d.start();
    // Midpoint of 1200..1452 = 1200 + (1452-1200)/2 = 1200 + 126 = 1326
    try testing.expectEqual(@as(u16, 1326), d.nextProbeSize());
}

test "MtuDiscoverer: probe ACK raises min and MTU" {
    var d = MtuDiscoverer{};
    d.start();

    const probe_size = d.nextProbeSize();
    d.onProbeSent(42, probe_size, 1000);
    try testing.expect(d.shouldProbe(2000, 100) == false); // outstanding probe

    const changed = d.onProbeAcked(42, 2000);
    try testing.expect(changed);
    try testing.expectEqual(probe_size, d.current_mtu);
    try testing.expectEqual(probe_size, d.search_min);
    try testing.expect(d.probe_pn == null);
}

test "MtuDiscoverer: probe loss narrows after MAX_PROBES" {
    var d = MtuDiscoverer{};
    d.start();

    const probe_size = d.nextProbeSize();
    var now: i64 = 1000;

    // Fail MAX_PROBES times
    var i: u8 = 0;
    while (i < MAX_PROBES) : (i += 1) {
        d.onProbeSent(i, probe_size, now);
        _ = d.onProbeLost(i, now);
        now += 1000;
    }

    // search_max should now be narrowed
    try testing.expectEqual(probe_size, d.search_max);
    try testing.expectEqual(BASE_PLPMTU, d.search_min);
}

test "MtuDiscoverer: converges to search_complete" {
    var d = MtuDiscoverer{};
    d.start();

    var pn: u64 = 0;
    var now: i64 = 1000;
    var iterations: usize = 0;

    while (d.state == .searching and iterations < 20) : (iterations += 1) {
        const size = d.nextProbeSize();
        d.onProbeSent(pn, size, now);
        // Simulate ACK for sizes <= 1400, loss for > 1400
        if (size <= 1400) {
            _ = d.onProbeAcked(pn, now + 100);
        } else {
            _ = d.onProbeLost(pn, now + 100);
            // Need MAX_PROBES failures to narrow
            var retry: u8 = 1;
            while (retry < MAX_PROBES and d.state == .searching) : (retry += 1) {
                pn += 1;
                d.onProbeSent(pn, size, now);
                _ = d.onProbeLost(pn, now + 100);
            }
        }
        pn += 1;
        now += 1000;
    }

    try testing.expectEqual(MtuState.search_complete, d.state);
    try testing.expect(d.current_mtu >= BASE_PLPMTU);
    try testing.expect(d.current_mtu <= 1400);
}

test "MtuDiscoverer: raise timer re-enters searching" {
    var d = MtuDiscoverer{};
    d.start();

    // Force to search_complete
    d.state = .search_complete;
    d.search_complete_time = 1000;
    d.current_mtu = 1400;

    // Not expired yet
    d.checkRaiseTimer(1000 + RAISE_TIMER_NS - 1);
    try testing.expectEqual(MtuState.search_complete, d.state);

    // Expired
    d.checkRaiseTimer(1000 + RAISE_TIMER_NS);
    try testing.expectEqual(MtuState.searching, d.state);
}

test "MtuDiscoverer: reset returns to base" {
    var d = MtuDiscoverer{};
    d.start();
    d.current_mtu = 1400;
    d.search_min = 1400;

    d.reset();
    try testing.expectEqual(BASE_PLPMTU, d.current_mtu);
    try testing.expectEqual(BASE_PLPMTU, d.search_min);
    try testing.expectEqual(MtuState.searching, d.state);
}

test "MtuDiscoverer: wrong PN ignored" {
    var d = MtuDiscoverer{};
    d.start();
    d.onProbeSent(10, 1326, 1000);

    try testing.expect(!d.onProbeAcked(99, 2000)); // wrong PN
    try testing.expect(d.probe_pn != null); // still outstanding
}

test "MtuDiscoverer: shouldProbe timing" {
    var d = MtuDiscoverer{};
    d.start();

    // First probe: always allowed
    try testing.expect(d.shouldProbe(1000, 50_000_000));

    d.onProbeSent(0, 1326, 1000);
    _ = d.onProbeAcked(0, 2000);

    // Too soon (5 × 50ms = 250ms, MIN_PROBE_INTERVAL = 200ms)
    try testing.expect(!d.shouldProbe(2000 + 100_000_000, 50_000_000));

    // After 250ms
    try testing.expect(d.shouldProbe(2000 + 250_000_001, 50_000_000));
}
