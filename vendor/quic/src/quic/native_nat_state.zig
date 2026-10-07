pub const Address = @import("../address.zig").Address;
const policy = @import("native_nat_policy.zig");
const canonicalAddress = policy.canonicalAddress;
const snapshot = policy.snapshot;
const transition = @import("native_nat_transition.zig");
pub const Event = transition.Event;
pub const Result = transition.Result;

/// Bounded, allocator-free Noq 1.3.0 candidate and round bookkeeping.
/// Limits follow State::new: local TP limits remotes, peer TP limits locals.
pub const Candidate = transition.Candidate;
pub const Error = error{
    WrongConnectionSide, TooManyAddresses, NotEnoughAddresses, InvalidAddress, InvalidSequence,
    ProbeNotPending, TooManyChallenges,
};
const sequence_max: u64 = (1 << 62) - 1;
const capacity = policy.candidate_limit;
const Probe = struct { remaining: u8 = 0, pending: bool = false, succeeded: bool = false };
const Challenge = transition.Challenge;
pub const RoundState = enum { idle, probing, completed, failed };

pub const State = struct {
    is_server: bool,
    local_limit: u8,
    peer_limit: u8,
    supported_ipv6: bool = true,
    direct_validated: bool = false,
    locals: [capacity]Candidate = undefined,
    remotes: [capacity]Candidate = undefined,
    probes: [capacity]Probe = undefined,
    local_count: u8 = 0,
    remote_count: u8 = 0,
    next_sequence: u64 = 0,
    round: u64 = 0,
    attempt: u8 = 0,
    retry_at_ns: ?i64 = null,
    challenges: [capacity * 9]Challenge = undefined,
    challenge_count: u16 = 0,

    pub fn init(is_server: bool, local_limit: u8, peer_limit: u8) State {
        return .{
            .is_server = is_server,
            .local_limit = @min(local_limit, capacity),
            .peer_limit = @min(peer_limit, capacity),
        };
    }

    fn add(self: *State, address: Address) Error!?u64 {
        const canonical = try canonicalAddress(address);
        for (self.localCandidates()) |entry| {
            if (Address.eql(entry.address, canonical)) return null;
        }
        if (self.local_count == self.peer_limit) return error.TooManyAddresses;
        const sequence = self.next_sequence;
        if (self.is_server) {
            if (sequence > sequence_max) return error.InvalidSequence;
            self.next_sequence = sequence + 1;
        }
        self.locals[self.local_count] = .{ .sequence = sequence, .address = canonical };
        self.local_count += 1;
        return if (self.is_server) sequence else null;
    }

    fn remove(self: *State, address: Address) Error!?u64 {
        const canonical = try canonicalAddress(address);
        for (self.localCandidates(), 0..) |entry, index| {
            if (!Address.eql(entry.address, canonical)) continue;
            self.local_count -= 1;
            self.locals[index] = self.locals[self.local_count];
            if (!self.is_server and self.local_count == 0) self.cancel();
            return if (self.is_server) entry.sequence else null;
        }
        return null;
    }

    fn receiveAdd(self: *State, sequence: u64, address: Address) Error!void {
        if (self.is_server) return error.WrongConnectionSide;
        if (sequence > sequence_max) return error.InvalidSequence;
        const canonical = try canonicalAddress(address);
        for (self.remoteCandidates()) |entry| {
            if (entry.sequence != sequence) continue;
            // Noq connection reception enforces ClientState::check_remote_address.
            if (!Address.eql(entry.address, canonical)) return error.InvalidAddress;
            return;
        }
        if (self.remote_count == self.local_limit) return error.TooManyAddresses;
        self.remotes[self.remote_count] = .{ .sequence = sequence, .address = canonical };
        // An ADD joins the next retry batch, not the initial pending batch.
        self.probes[self.remote_count] = .{
            .remaining = if (policy.supportedAddress(canonical, self.supported_ipv6)) 9 else 0,
        };
        for (self.remoteCandidates(), 0..) |entry, index| {
            if (!Address.eql(entry.address, canonical)) continue;
            // A duplicate advertisement must not create a fresh retry budget.
            self.probes[self.remote_count] = self.probes[index];
            self.probes[self.remote_count].pending = false;
            break;
        }
        self.remote_count += 1;
    }

    fn receiveRemove(self: *State, sequence: u64) Error!void {
        if (self.is_server) return error.WrongConnectionSide;
        if (sequence > sequence_max) return error.InvalidSequence;
        for (self.remoteCandidates(), 0..) |entry, index| {
            if (entry.sequence != sequence) continue;
            self.remote_count -= 1;
            self.remotes[index] = self.remotes[self.remote_count];
            var destination_survives = false;
            for (self.remoteCandidates()) |remaining| {
                destination_survives = destination_survives or
                    Address.eql(remaining.address, entry.address);
            }
            // REMOVE cancels one advertisement, not another sequence's issued probe.
            if (!destination_survives) self.clearChallenges(entry.address);
            self.probes[index] = self.probes[self.remote_count];
            return;
        }
    }

    fn initiate(self: *State, now: i64) Error!void {
        if (self.is_server) return error.WrongConnectionSide;
        if (self.local_count == 0) return error.NotEnoughAddresses;
        self.round = @min(sequence_max, self.round + 1);
        self.attempt = 0;
        self.challenge_count = 0;
        self.direct_validated = false;
        var active = false;
        for (self.probes[0..self.remote_count], self.remoteCandidates()) |*probe, entry| {
            const supported = policy.supportedAddress(entry.address, self.supported_ipv6);
            probe.* = if (supported) .{ .remaining = 8, .pending = true } else .{};
            active = active or supported;
        }
        self.retry_at_ns = if (active) now +| policy.retryDelay(0) else null;
    }

    fn receiveReach(self: *State, round: u64, address: Address, now: i64) Error!void {
        if (!self.is_server) return error.WrongConnectionSide;
        if (round > sequence_max) return error.InvalidSequence;
        if (round < self.round) return;
        const canonical = try canonicalAddress(address);
        if (!policy.supportedAddress(canonical, self.supported_ipv6)) return;
        if (round == self.round) {
            for (self.remoteCandidates()) |entry| {
                if (Address.eql(entry.address, canonical)) return;
            }
        }
        const count = if (round > self.round) 0 else self.remote_count;
        if (count == self.local_limit) return error.TooManyAddresses;
        if (round > self.round) {
            self.round = round;
            self.remote_count = 0;
            self.attempt = 0;
            self.challenge_count = 0;
            self.direct_validated = false;
            self.retry_at_ns = now +| policy.retryDelay(0);
        }
        self.remotes[self.remote_count] = .{ .sequence = round, .address = canonical };
        const supported = policy.supportedAddress(canonical, self.supported_ipv6);
        self.probes[self.remote_count] = if (supported)
            .{ .remaining = 8, .pending = true }
        else
            .{};
        self.remote_count += 1;
        if (supported and self.retry_at_ns == null) {
            self.retry_at_ns = now +| policy.retryDelay(self.attempt);
        }
    }

    /// Offers one ready probe. recordProbe commits only after a successful send.
    /// Noq retries batches at initial_rtt/10, doubling and capped at two seconds.
    fn nextProbe(self: *State, now: i64) ?Address {
        for (self.probes[0..self.remote_count], 0..) |probe, index| {
            if (probe.pending and self.canRecordChallenge(self.remotes[index].address)) {
                return self.remotes[index].address;
            }
        }
        if (self.retry_at_ns) |retry_at| {
            if (now >= retry_at) {
                self.attempt +|= 1;
                var retry = false;
                for (self.probes[0..self.remote_count]) |*probe| {
                    if (probe.remaining == 0) continue;
                    probe.remaining -= 1;
                    probe.pending = true;
                    retry = true;
                }
                self.retry_at_ns = if (retry) now +| policy.retryDelay(self.attempt) else null;
                if (!retry) {
                    self.challenge_count = 0;
                    for (self.probes[0..self.remote_count]) |*probe| probe.* = .{};
                }
            }
        }
        for (self.probes[0..self.remote_count], 0..) |probe, index| {
            if (probe.pending and self.canRecordChallenge(self.remotes[index].address)) {
                return self.remotes[index].address;
            }
        }
        return null;
    }

    fn recordProbe(self: *State, address: Address, token: [8]u8) Error!void {
        const canonical = try canonicalAddress(address);
        if (!self.pendingDestination(canonical)) return error.ProbeNotPending;
        try self.recordChallenge(canonical, token);
        // Advertisements are sequence-keyed; a pending send is destination-keyed.
        for (self.remoteCandidates(), 0..) |entry, index| {
            if (Address.eql(entry.address, canonical)) self.probes[index].pending = false;
        }
    }

    fn pendingDestination(self: *const State, address: Address) bool {
        for (self.remoteCandidates(), 0..) |entry, index| {
            if (Address.eql(entry.address, address) and self.probes[index].pending) return true;
        }
        return false;
    }

    fn cancel(self: *State) void {
        for (self.probes[0..self.remote_count]) |*probe| probe.* = .{};
        self.retry_at_ns = null;
        self.challenge_count = 0;
        self.direct_validated = false;
    }

    fn configure(self: *State, supported_ipv6: bool) void {
        if (self.supported_ipv6 == supported_ipv6) return;
        self.supported_ipv6 = supported_ipv6;
        for (self.remoteCandidates(), 0..) |entry, index| {
            if (policy.supportedAddress(entry.address, supported_ipv6)) continue;
            self.probes[index] = .{};
            self.clearChallenges(entry.address);
        }
    }

    /// Preflights a fresh challenge before the caller sends anything off-path.
    pub fn canRecordChallenge(self: *const State, address: Address) bool {
        return policy.supportedAddress(address, self.supported_ipv6) and
            policy.canRecordChallenge(self.challenges[0..self.challenge_count], address);
    }

    fn recordChallenge(self: *State, address: Address, token: [8]u8) Error!void {
        const canonical = try canonicalAddress(address);
        if (!policy.supportedAddress(canonical, self.supported_ipv6)) return error.InvalidAddress;
        var address_count: u8 = 0;
        for (self.challenges[0..self.challenge_count]) |sent| {
            if (!Address.eql(sent.address, canonical)) continue;
            if (std.mem.eql(u8, &sent.token, &token)) return;
            address_count += 1;
        }
        if (address_count == 9 or self.challenge_count == self.challenges.len) {
            return error.TooManyChallenges;
        }
        self.challenges[self.challenge_count] = .{ .address = canonical, .token = token };
        self.challenge_count += 1;
    }

    fn response(self: *State, address: Address, token: [8]u8) bool {
        const canonical = canonicalAddress(address) catch return false;
        for (self.challenges[0..self.challenge_count]) |sent| {
            if (!Address.eql(sent.address, canonical)) continue;
            if (!std.mem.eql(u8, &sent.token, &token)) continue;
            self.clearChallenges(canonical);
            for (self.remoteCandidates(), 0..) |entry, index| {
                if (Address.eql(entry.address, canonical)) {
                    self.probes[index] = .{ .succeeded = true };
                }
            }
            return true;
        }
        return false;
    }

    fn clearChallenges(self: *State, address: Address) void {
        var index: u16 = 0;
        while (index < self.challenge_count) {
            if (!Address.eql(self.challenges[index].address, address)) {
                index += 1;
                continue;
            }
            self.challenge_count -= 1;
            self.challenges[index] = self.challenges[self.challenge_count];
        }
    }

    pub fn deadline(self: *const State) ?i64 {
        for (self.probes[0..self.remote_count]) |probe| {
            if (probe.remaining != 0 or probe.pending) return self.retry_at_ns;
        }
        return if (self.challenge_count != 0) self.retry_at_ns else null;
    }

    pub fn roundState(self: *const State) RoundState {
        if (self.round == 0 and !(self.is_server and self.remote_count != 0)) return .idle;
        if (self.direct_validated) return .completed;
        var responsive = false;
        for (self.probes[0..self.remote_count]) |probe| {
            if (probe.pending or probe.remaining != 0) return .probing;
            responsive = responsive or probe.succeeded;
        }
        // An off-path response is only permission to open the real direct path.
        return if (responsive or self.challenge_count != 0) .probing else .failed;
    }


    pub fn currentRound(self: *const State) u64 {
        return self.round;
    }

    pub fn localCandidates(self: *const State) []const Candidate {
        return self.locals[0..self.local_count];
    }

    pub fn remoteCandidates(self: *const State) []const Candidate {
        return self.remotes[0..self.remote_count];
    }

    pub fn snapshotLocal(self: *const State, out: []Address) []const Address {
        return snapshot(self.localCandidates(), out);
    }

    pub fn snapshotRemote(self: *const State, out: []Address) []const Address {
        return snapshot(self.remoteCandidates(), out);
    }
};





/// Explicit state-in/state-out transition. Input and output may alias to avoid a large copy.
/// Nonaliased input is unchanged. On errors output retains the input's logical state.
pub fn process(state: *const State, event: Event, out: *State) Error!Result {
    if (state != out) out.* = state.*;
    switch (event) {
        .configure => |config| out.configure(config.supported_ipv6),
        .cancel => out.cancel(),
        .directValidated => {
            out.cancel();
            out.direct_validated = true;
        },
        .preflightProbe => |address| {
            const canonical = canonicalAddress(address) catch return .{ .ready = false };
            return .{ .ready = out.pendingDestination(canonical) and
                policy.supportedAddress(canonical, out.supported_ipv6) and
                out.canRecordChallenge(canonical) };
        },
        .add => |address| return .{ .sequence = try out.add(address) },
        .remove => |address| return .{ .sequence = try out.remove(address) },
        .receiveAdd => |add| try out.receiveAdd(add.sequence, add.address),
        .receiveRemove => |sequence| try out.receiveRemove(sequence),
        .initiate => |now| try out.initiate(now),
        .receiveReach => |reach| try out.receiveReach(reach.round, reach.address, reach.now),
        .nextProbe => |now| return .{ .probe = out.nextProbe(now) },
        .recordProbe => |sent| try out.recordProbe(sent.address, sent.token),
        .recordChallenge => |sent| try out.recordChallenge(sent.address, sent.token),
        .response => |received| return .{ .matched = out.response(received.address, received.token) },
    }
    return .none;
}

const std = @import("std");
const first = Address.initIpv4(.{ 192, 0, 2, 1 }, 1000);
const second = Address.initIpv4(.{ 192, 0, 2, 2 }, 1001);
const third = Address.initIpv4(.{ 192, 0, 2, 3 }, 1002);

test "roles and negotiated address caps follow Noq transport parameter direction" {
    var server = State.init(true, 2, 1);
    var client = State.init(false, 1, 2);
    try std.testing.expectEqual(@as(?u64, 0), try sequenceResult(&server, .{ .add = first }));
    try std.testing.expectEqual(@as(?u64, null), try sequenceResult(&server, .{ .add = first }));
    try std.testing.expectError(error.TooManyAddresses, sequenceResult(&server, .{ .add = second }));
    try std.testing.expectEqual(@as(?u64, null), try sequenceResult(&client, .{ .add = first }));
    try std.testing.expectEqual(@as(?u64, null), try sequenceResult(&client, .{ .add = second }));
    try std.testing.expectError(error.TooManyAddresses, sequenceResult(&client, .{ .add = third }));
    try std.testing.expectError(error.WrongConnectionSide, voidResult(&server, .{ .receiveAdd = .{ .sequence = 0, .address = first } }));
    try std.testing.expectError(error.WrongConnectionSide, voidResult(&server, .{ .receiveRemove = 0 }));
    try std.testing.expectError(error.WrongConnectionSide, voidResult(&server, .{ .initiate = 0 }));
    try std.testing.expectError(error.WrongConnectionSide, voidResult(&client, .{ .receiveReach = .{ .round = 1, .address = first, .now = 0 } }));
    try voidResult(&client, .{ .receiveAdd = .{ .sequence = 0, .address = first } });
    try voidResult(&client, .{ .receiveAdd = .{ .sequence = 0, .address = first } });
    try std.testing.expectError(error.InvalidAddress, voidResult(&client, .{ .receiveAdd = .{ .sequence = 0, .address = second } }));
    try std.testing.expectError(error.TooManyAddresses, voidResult(&client, .{ .receiveAdd = .{ .sequence = 1, .address = second } }));
    try std.testing.expectError(error.InvalidAddress, sequenceResult(&server, .{ .add = .unset }));
    try std.testing.expectError(error.InvalidSequence, voidResult(&client, .{ .receiveRemove = 1 << 62 }));
}

test "removal cancels probes and server sequences are never reused" {
    var server = State.init(true, 2, 2);
    try std.testing.expectEqual(@as(?u64, 0), try sequenceResult(&server, .{ .add = first }));
    try std.testing.expectEqual(@as(?u64, 0), try sequenceResult(&server, .{ .remove = first }));
    try std.testing.expectEqual(@as(?u64, null), try sequenceResult(&server, .{ .remove = first }));
    try std.testing.expectEqual(@as(?u64, 1), try sequenceResult(&server, .{ .add = first }));
    var client = State.init(false, 2, 2);
    try std.testing.expectError(error.NotEnoughAddresses, voidResult(&client, .{ .initiate = 0 }));
    try std.testing.expectEqual(@as(?u64, null), try sequenceResult(&client, .{ .add = first }));
    try voidResult(&client, .{ .receiveAdd = .{ .sequence = 1, .address = second } });
    try voidResult(&client, .{ .initiate = 0 });
    try voidResult(&client, .{ .recordProbe = .{ .address = second, .token = [_]u8{1} ** 8 } });
    try voidResult(&client, .{ .receiveRemove = 1 });
    try voidResult(&client, .{ .receiveRemove = 1 });
    try std.testing.expect(!matchedResult(&client, second, [_]u8{1} ** 8));
    try std.testing.expectEqual(@as(?Address, null), probeResult(&client, 0));
    try std.testing.expectEqual(@as(usize, 0), client.remoteCandidates().len);
    try voidResult(&client, .{ .initiate = 1 });
    try std.testing.expectEqual(@as(u64, 2), client.currentRound());
}

test "server ignores stale rounds and duplicates and replaces old round candidates" {
    var server = State.init(true, 1, 2);
    try voidResult(&server, .{ .receiveReach = .{ .round = 1, .address = first, .now = 0 } });
    try voidResult(&server, .{ .receiveReach = .{ .round = 1, .address = first, .now = 10 } });
    try std.testing.expectError(error.TooManyAddresses, voidResult(&server, .{ .receiveReach = .{ .round = 1, .address = second, .now = 10 } }));
    try std.testing.expect(Address.eql(first, probeResult(&server, 0).?));
    try voidResult(&server, .{ .recordProbe = .{ .address = first, .token = [_]u8{1} ** 8 } });
    try std.testing.expectEqual(@as(?Address, null), probeResult(&server, 1));
    try voidResult(&server, .{ .receiveReach = .{ .round = 2, .address = second, .now = 20 } });
    try std.testing.expect(!matchedResult(&server, first, [_]u8{1} ** 8));
    try voidResult(&server, .{ .receiveReach = .{ .round = 1, .address = first, .now = 20 } });
    try std.testing.expect(Address.eql(second, probeResult(&server, 20).?));
    try std.testing.expectEqual(@as(u64, 2), server.currentRound());
    try std.testing.expectEqual(@as(usize, 1), server.remoteCandidates().len);
    var zero = State.init(true, 0, 2);
    try std.testing.expectError(error.TooManyAddresses, voidResult(&zero, .{ .receiveReach = .{ .round = 1, .address = first, .now = 0 } }));
}

test "nine Noq default probe attempts expire and a new round resets the schedule" {
    var client = State.init(false, 2, 2);
    try std.testing.expectEqual(@as(?u64, null), try sequenceResult(&client, .{ .add = first }));
    try voidResult(&client, .{ .receiveAdd = .{ .sequence = 0, .address = second } });
    try voidResult(&client, .{ .initiate = 0 });
    const times = [_]i64{
        0, 33_300_000, 66_600_000, 133_200_000, 266_400_000,
        532_800_000, 1_065_600_000, 2_131_200_000, 4_131_200_000,
    };
    for (times, 0..) |now, index| {
        if (index != 0) try std.testing.expectEqual(@as(?Address, null), probeResult(&client, now - 1));
        try std.testing.expect(Address.eql(second, probeResult(&client, now).?));
        try voidResult(&client, .{ .recordProbe = .{ .address = second, .token = [_]u8{@intCast(index)} ** 8 } });
        try std.testing.expectEqual(@as(?Address, null), probeResult(&client, now));
    }
    try std.testing.expectEqual(@as(?Address, null), probeResult(&client, 20_000_000_000));
    try std.testing.expectEqual(RoundState.failed, client.roundState());
    try voidResult(&client, .{ .initiate = 30_000_000_000 });
    try std.testing.expectEqual(@as(u64, 2), client.currentRound());
    try std.testing.expect(Address.eql(second, probeResult(&client, 30_000_000_000).?));
    var out: [1]Address = undefined;
    try std.testing.expect(Address.eql(first, client.snapshotLocal(&out)[0]));
    try std.testing.expect(Address.eql(second, client.snapshotRemote(&out)[0]));
}

test "offers survive failed sends and responses bind source token and current round" {
    var client = State.init(false, 2, 2);
    try std.testing.expectEqual(@as(?u64, null), try sequenceResult(&client, .{ .add = first }));
    try voidResult(&client, .{ .receiveAdd = .{ .sequence = 0, .address = second } });
    try voidResult(&client, .{ .initiate = 0 });
    const token = [_]u8{7} ** 8;
    try std.testing.expectEqual(RoundState.probing, client.roundState());
    try std.testing.expect(Address.eql(second, probeResult(&client, 0).?));
    try std.testing.expect(Address.eql(second, probeResult(&client, 10).?));
    try std.testing.expect(!matchedResult(&client, second, token));
    try voidResult(&client, .{ .recordProbe = .{ .address = second, .token = token } });
    try std.testing.expect(!matchedResult(&client, first, token));
    try std.testing.expect(!matchedResult(&client, second, [_]u8{8} ** 8));
    try std.testing.expect(matchedResult(&client, second, token));
    try std.testing.expect(!matchedResult(&client, second, token));
    try std.testing.expectEqual(RoundState.probing, client.roundState());
    try voidResult(&client, .{ .initiate = 100 });
    try std.testing.expect(!matchedResult(&client, second, token));
    // A reciprocal challenge validates an unadvertised DEDN source, never receipt alone.
    try voidResult(&client, .{ .recordChallenge = .{ .address = third, .token = token } });
    try std.testing.expect(!matchedResult(&client, first, token));
    try std.testing.expect(matchedResult(&client, third, token));
    try std.testing.expect(!matchedResult(&client, third, token));
    try voidResult(&client, .{ .recordChallenge = .{ .address = third, .token = token } });
    try voidResult(&client, .{ .initiate = 200 });
    try std.testing.expect(!matchedResult(&client, third, token));
}

test "mapped addresses canonicalize and bounded challenge storage rejects a tenth token" {
    var state = State.init(true, 255, 255);
    const mapped = Address.initIpv6(.{
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 192, 0, 2, 1,
    }, 1000, 0);
    try std.testing.expectEqual(@as(?u64, 0), try sequenceResult(&state, .{ .add = mapped }));
    try std.testing.expectEqual(@as(?u64, null), try sequenceResult(&state, .{ .add = first }));
    var empty: [0]Address = .{};
    try std.testing.expectEqual(@as(usize, 0), state.snapshotLocal(&empty).len);
    for (0..9) |index| {
        try voidResult(&state, .{ .recordChallenge = .{ .address = first, .token = [_]u8{@intCast(index)} ** 8 } });
    }
    try voidResult(&state, .{ .recordChallenge = .{ .address = mapped, .token = [_]u8{0} ** 8 } });
    try std.testing.expectError(
        error.TooManyChallenges, voidResult(&state, .{ .recordChallenge = .{ .address = first, .token = [_]u8{9} ** 8 } }),
    );
    try std.testing.expect(matchedResult(&state, mapped, [_]u8{0} ** 8));
    try std.testing.expect(!matchedResult(&state, first, [_]u8{1} ** 8));
}

test "server fails exhausted sequence space instead of reusing its final sequence" {
    var state = State.init(true, 2, 2);
    state.next_sequence = sequence_max;
    try std.testing.expectEqual(@as(?u64, sequence_max), try sequenceResult(&state, .{ .add = first }));
    try std.testing.expectEqual(@as(?u64, null), try sequenceResult(&state, .{ .add = first }));
    try std.testing.expectError(error.InvalidSequence, sequenceResult(&state, .{ .add = second }));
    try std.testing.expectEqual(@as(?u64, sequence_max), try sequenceResult(&state, .{ .remove = first }));
    try std.testing.expectError(error.InvalidSequence, sequenceResult(&state, .{ .add = first }));
}

test "pure transition output aliases or preserves input and clamps peer address limit" {
    const original = State.init(true, 32, 255);
    var output: State = undefined;
    const added = try process(&original, .{ .add = first }, &output);
    try std.testing.expectEqual(@as(?u64, 0), added.sequence);
    try std.testing.expectEqual(@as(usize, 0), original.localCandidates().len);
    try std.testing.expectEqual(@as(usize, 1), output.localCandidates().len);
    try std.testing.expectEqual(@as(u8, 32), output.peer_limit);
    const removed = try process(&output, .{ .remove = first }, &output);
    try std.testing.expectEqual(@as(?u64, 0), removed.sequence);
    try std.testing.expectEqual(@as(usize, 0), output.localCandidates().len);
    try std.testing.expectError(error.InvalidAddress, process(&output, .{ .add = .unset }, &output));
    try std.testing.expectEqual(@as(usize, 0), output.localCandidates().len);
    try std.testing.expect(output.canRecordChallenge(first));
    for (0..9) |index| {
        const result = try process(&output, .{ .recordChallenge = .{
            .address = first, .token = [_]u8{@intCast(index)} ** 8,
        } }, &output);
        try std.testing.expectEqual(@as(Result, .none), result);
    }
    try std.testing.expect(!output.canRecordChallenge(first));
    try std.testing.expect(output.canRecordChallenge(second));
}

fn sequenceResult(state: *State, event: Event) Error!?u64 {
    return (try process(state, event, state)).sequence;
}

fn voidResult(state: *State, event: Event) Error!void {
    switch (try process(state, event, state)) {
        .none => {},
        else => unreachable,
    }
}

fn probeResult(state: *State, now: i64) ?Address {
    return (process(state, .{ .nextProbe = now }, state) catch unreachable).probe;
}

fn matchedResult(state: *State, address: Address, token: [8]u8) bool {
    const event: Event = .{ .response = .{ .address = address, .token = token } };
    return (process(state, event, state) catch unreachable).matched;
}

test "peer limit 255 is legal but candidate work remains bounded to 32 addresses" {
    var state = State.init(true, 32, 255);
    for (0..32) |index| {
        const address = Address.initIpv4(.{ 192, 0, 2, @intCast(index) }, 1000);
        try std.testing.expectEqual(
            @as(?u64, @intCast(index)), try sequenceResult(&state, .{ .add = address }),
        );
    }
    try std.testing.expectError(
        error.TooManyAddresses, sequenceResult(&state, .{ .add = third }),
    );
    try std.testing.expectEqual(@as(usize, 32), state.localCandidates().len);
}

test "duplicate sequence destinations commit once even with first pending cleared" {
    var state = State.init(false, 32, 32);
    try std.testing.expectEqual(@as(?u64, null), try sequenceResult(&state, .{ .add = first }));
    try voidResult(&state, .{ .receiveAdd = .{ .sequence = 1, .address = second } });
    try voidResult(&state, .{ .receiveAdd = .{ .sequence = 2, .address = second } });
    try voidResult(&state, .{ .initiate = 0 });
    state.probes[0].pending = false;
    try std.testing.expect(Address.eql(second, probeResult(&state, 0).?));
    try std.testing.expect((try process(&state, .{ .preflightProbe = second }, &state)).ready);
    try voidResult(&state, .{ .recordProbe = .{ .address = second, .token = [_]u8{4} ** 8 } });
    try std.testing.expectEqual(@as(u16, 1), state.challenge_count);
    try std.testing.expectEqual(@as(?Address, null), probeResult(&state, 0));
    try std.testing.expectEqual(@as(usize, 2), state.remoteCandidates().len);
    try voidResult(&state, .{ .receiveRemove = 1 });
    try std.testing.expect(matchedResult(&state, second, [_]u8{4} ** 8));
    try std.testing.expect(state.probes[0].succeeded);
    try voidResult(&state, .{ .receiveAdd = .{ .sequence = 3, .address = second } });
    try voidResult(&state, .{ .initiate = 1 });
    try voidResult(&state, .{ .recordProbe = .{ .address = second, .token = [_]u8{5} ** 8 } });
    try std.testing.expectEqual(@as(?Address, null), probeResult(&state, 1));
}

test "IPv4 sending family excludes IPv6 pending retries and tokens" {
    const six = Address.initIpv6(.{ 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, 1000, 0);
    var state = State.init(false, 32, 32);
    try voidResult(&state, .{ .configure = .{ .supported_ipv6 = false } });
    try std.testing.expectEqual(@as(?u64, null), try sequenceResult(&state, .{ .add = first }));
    try voidResult(&state, .{ .receiveAdd = .{ .sequence = 1, .address = six } });
    try voidResult(&state, .{ .receiveAdd = .{ .sequence = 2, .address = second } });
    try voidResult(&state, .{ .initiate = 0 });
    try std.testing.expect(Address.eql(second, probeResult(&state, 0).?));
    try std.testing.expect(!state.probes[0].pending);
    try std.testing.expectEqual(@as(u8, 0), state.probes[0].remaining);
    try std.testing.expect(!(try process(&state, .{ .preflightProbe = six }, &state)).ready);
    try std.testing.expect(!state.canRecordChallenge(six));
    try std.testing.expectError(error.InvalidAddress, voidResult(&state, .{
        .recordChallenge = .{ .address = six, .token = [_]u8{1} ** 8 },
    }));
    try voidResult(&state, .{ .recordProbe = .{ .address = second, .token = [_]u8{1} ** 8 } });
    try std.testing.expect(Address.eql(second, probeResult(&state, 33_300_000).?));
    try voidResult(&state, .cancel);
    try std.testing.expectEqual(@as(?i64, null), state.deadline());
    try std.testing.expectEqual(@as(?Address, null), probeResult(&state, 100_000_000));
    try std.testing.expect(!matchedResult(&state, second, [_]u8{1} ** 8));
    try voidResult(&state, .{ .configure = .{ .supported_ipv6 = true } });
    try voidResult(&state, .{ .initiate = 0 });
    try std.testing.expect(Address.eql(six, probeResult(&state, 0).?));
}

test "probe preflight capacity prevents send and full path validation alone completes round" {
    var state = State.init(false, 32, 32);
    try std.testing.expectEqual(@as(?u64, null), try sequenceResult(&state, .{ .add = first }));
    try voidResult(&state, .{ .receiveAdd = .{ .sequence = 1, .address = second } });
    try voidResult(&state, .{ .initiate = 0 });
    for (0..9) |index| {
        try voidResult(&state, .{ .recordChallenge = .{ .address = second, .token = [_]u8{@intCast(index)} ** 8 } });
    }
    try std.testing.expect(!(try process(&state, .{ .preflightProbe = second }, &state)).ready);
    try std.testing.expectError(error.TooManyChallenges, voidResult(&state, .{ .recordProbe = .{ .address = second, .token = [_]u8{10} ** 8 } }));
    try std.testing.expect(state.probes[0].pending);
    try std.testing.expect(matchedResult(&state, second, [_]u8{0} ** 8));
    try std.testing.expectEqual(RoundState.probing, state.roundState());
    try voidResult(&state, .directValidated);
    try std.testing.expectEqual(RoundState.completed, state.roundState());
    try voidResult(&state, .cancel);
    try std.testing.expectEqual(RoundState.failed, state.roundState());
}

test "exhausted attempts expire all tokens after final response grace" {
    var state = State.init(false, 32, 32);
    try std.testing.expectEqual(@as(?u64, null), try sequenceResult(&state, .{ .add = first }));
    try voidResult(&state, .{ .receiveAdd = .{ .sequence = 1, .address = second } });
    try voidResult(&state, .{ .initiate = 0 });
    var now: i64 = 0;
    for (0..9) |index| {
        try std.testing.expect(Address.eql(second, probeResult(&state, now).?));
        try voidResult(&state, .{ .recordProbe = .{
            .address = second, .token = [_]u8{@intCast(index)} ** 8,
        } });
        now = state.deadline().?;
    }
    try std.testing.expectEqual(@as(u16, 9), state.challenge_count);
    try std.testing.expectEqual(@as(?Address, null), probeResult(&state, now));
    try std.testing.expectEqual(@as(u16, 0), state.challenge_count);
    try std.testing.expect(!matchedResult(&state, second, [_]u8{8} ** 8));
    try std.testing.expectEqual(@as(?i64, null), state.deadline());
    try std.testing.expectEqual(RoundState.failed, state.roundState());
}

test "last local candidate removal cancels outstanding client probes" {
    var state = State.init(false, 32, 32);
    try std.testing.expectEqual(@as(?u64, null), try sequenceResult(&state, .{ .add = first }));
    try voidResult(&state, .{ .receiveAdd = .{ .sequence = 1, .address = second } });
    try voidResult(&state, .{ .initiate = 0 });
    try voidResult(&state, .{ .recordProbe = .{ .address = second, .token = [_]u8{3} ** 8 } });
    try std.testing.expectEqual(@as(?u64, null), try sequenceResult(&state, .{ .remove = first }));
    try std.testing.expectEqual(@as(?i64, null), state.deadline());
    try std.testing.expect(!matchedResult(&state, second, [_]u8{3} ** 8));
}
