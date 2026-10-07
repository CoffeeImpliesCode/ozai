//! Fixed storage for Noq off-path NAT challenges, retry scheduling and round cancellation.
const wire = @import("native_nat.zig");
pub const capacity = 32;
pub const max_probe_attempts = 9;
pub const Error = error{ NoPendingProbe, ChallengeCollision, ChallengeLimit };
pub const Candidate = struct {
    address: wire.SocketAddr,
    sequence: u64 = 0,
    remaining: u8 = 9,
    pending: bool = false,
};
const Challenge = struct { address: wire.SocketAddr, token: u64 };
pub const Probes = struct {
    ipv6: bool,
    remote: [capacity]?Candidate = @splat(null),
    challenges: [capacity * max_probe_attempts]?Challenge = @splat(null),
    round: u64 = 0,
    attempt: u8 = 0,
    last_retry_ns: u64 = 0,

    pub fn cancel(self: *Probes, now_ns: u64) void {
        self.challenges = @splat(null);
        self.attempt = 0;
        self.last_retry_ns = now_ns;
    }
    pub fn supported(self: *const Probes, address: wire.SocketAddr) bool {
        return self.ipv6 or address.ip == .v4;
    }
    pub fn nextProbe(self: *const Probes) ?wire.SocketAddr {
        for (self.remote) |slot| if (slot) |candidate| {
            if (candidate.pending) return candidate.address;
        };
        return null;
    }
    pub fn markProbeSent(self: *Probes, input: wire.SocketAddr, token: u64) Error!void {
        const address = wire.canonical(input);
        var pending = false;
        for (self.remote) |slot| if (slot) |candidate| {
            pending = pending or (candidate.pending and candidate.address.order(address) == .eq);
        };
        if (!pending) return error.NoPendingProbe;
        try self.recordChallenge(address, token);
        for (&self.remote) |*slot| if (slot.*) |*candidate| {
            if (candidate.address.order(address) == .eq) candidate.pending = false;
        };
    }
    /// Called only after sending a fresh challenge, including reciprocal DEDN challenges.
    pub fn recordChallenge(self: *Probes, input: wire.SocketAddr, token: u64) Error!void {
        const address = wire.canonical(input);
        for (self.challenges) |slot| if (slot) |challenge| {
            if (challenge.token == token) return error.ChallengeCollision;
        };
        for (&self.challenges) |*slot| if (slot.* == null) {
            slot.* = .{ .address = address, .token = token };
            return;
        };
        return error.ChallengeLimit;
    }
    pub fn response(self: *Probes, input: wire.SocketAddr, token: u64) bool {
        const address = wire.canonical(input);
        for (self.challenges) |slot| if (slot) |challenge| {
            if (challenge.token != token or challenge.address.order(address) != .eq) continue;
            self.forget(address);
            for (&self.remote) |*slot_candidate| if (slot_candidate.*) |*candidate| {
                if (candidate.address.order(address) == .eq) {
                    candidate.remaining = 0;
                    candidate.pending = false;
                }
            };
            return true;
        };
        return false;
    }
    pub fn forget(self: *Probes, address: wire.SocketAddr) void {
        for (&self.challenges) |*slot| if (slot.*) |challenge| {
            if (challenge.address.order(address) == .eq) slot.* = null;
        };
    }
    pub fn deadline(self: *const Probes, initial_rtt_ns: u64) ?u64 {
        var active = false;
        for (self.remote) |slot| if (slot) |candidate| {
            active = active or candidate.remaining > 0;
        };
        if (!active or self.round == 0) return null;
        const exponent: u6 = @intCast(if (self.attempt == 0) 0 else @min(self.attempt - 1, 7));
        return @min((initial_rtt_ns / 10) *| (@as(u64, 1) << exponent), 2_000_000_000);
    }
    pub fn retry(self: *Probes, now_ns: u64, initial_rtt_ns: u64) void {
        const delay = self.deadline(initial_rtt_ns) orelse return;
        if (now_ns < self.last_retry_ns or now_ns - self.last_retry_ns < delay) return;
        self.last_retry_ns = now_ns;
        self.attempt +|= 1;
        for (&self.remote) |*slot| if (slot.*) |*candidate| {
            if (candidate.remaining > 0) {
                candidate.remaining -= 1;
                candidate.pending = true;
            }
        };
    }
};
