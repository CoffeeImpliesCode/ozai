//! Bounded Noq NAT roles and probe lifetimes (c1f41156 n0_nat_traversal.rs).
//! Owner sends returned frames reliably and uses authenticated 1-RTT PATH_CHALLENGE.
//! A successful NAT probe validates an address, not a 1200-byte path or peer identity.
const std = @import("std");
const wire = @import("native_nat.zig");
const probe = @import("native_nat_probe.zig");
pub const capacity = probe.capacity;
pub const max_probe_attempts = probe.max_probe_attempts;
pub const Side = enum { client, server };
pub const Action = enum { open_path, address_validated };
pub const Event = union(enum) { added: wire.SocketAddr, removed: wire.SocketAddr };
pub const Error = error{
    ExtensionNotNegotiated, WrongConnectionSide, TooManyAddresses, NotEnoughAddresses,
    Closed, AddressConflict, SequenceExhausted, NoPendingProbe, ChallengeCollision, ChallengeLimit,
};
const Candidate = probe.Candidate;

pub const State = struct {
    closed: bool = false,
    side: Side,
    local_limit: u8,
    remote_limit: u8,
    local: [capacity]?Candidate = @splat(null),
    probes: probe.Probes,
    next_sequence: u64 = 0,

    /// local_limit is the peer's TP, remote_limit is our advertised TP.
    pub fn init(side: Side, remote_limit: u8, local_limit: u8, ipv6: bool) Error!State {
        if (remote_limit > capacity) return error.TooManyAddresses;
        return .{ .side = side, .local_limit = @min(local_limit, capacity),
            .remote_limit = remote_limit, .probes = .{ .ipv6 = ipv6 } };
    }

    fn negotiated(self: *const State) Error!void {
        if (self.closed) return error.Closed;
        if (self.local_limit == 0 or self.remote_limit == 0) {
            return error.ExtensionNotNegotiated;
        }
    }
    fn close(self: *State) void {
        self.closed = true;
        self.local = @splat(null);
        self.probes.remote = @splat(null);
        self.probes.cancel(0);
    }

    fn addLocal(self: *State, input: wire.SocketAddr) Error!?wire.Frame {
        try self.negotiated();
        const address = wire.canonical(input);
        if (findAddress(&self.local, address) != null) return null;
        if (count(&self.local) >= self.local_limit) return error.TooManyAddresses;
        if (self.next_sequence == wire.max_sequence) return error.SequenceExhausted;
        const sequence = self.next_sequence;
        self.next_sequence += 1;
        self.local[empty(&self.local).?] = .{ .address = address, .sequence = sequence };
        return if (self.side == .server)
            .{ .add = .{ .sequence = sequence, .address = address } } else null;
    }

    fn removeLocal(self: *State, input: wire.SocketAddr) Error!?wire.Frame {
        try self.negotiated();
        const index = findAddress(&self.local, wire.canonical(input)) orelse return null;
        const sequence = self.local[index].?.sequence;
        self.local[index] = null;
        return if (self.side == .server) .{ .remove = sequence } else null;
    }

    /// REACH_OUT frames are exposed by reachFrame; the owner cancels queued old-round frames.
    fn initiate(self: *State, now_ns: u64) Error!void {
        try self.negotiated();
        if (self.side != .client) return error.WrongConnectionSide;
        if (count(&self.local) == 0) return error.NotEnoughAddresses;
        if (self.probes.round == wire.max_sequence) return error.SequenceExhausted;
        self.probes.round += 1;
        self.probes.cancel(now_ns);
        for (&self.probes.remote) |*slot| if (slot.*) |*candidate| {
            const supported = self.probes.supported(candidate.address);
            candidate.remaining = if (supported) 8 else 0;
            candidate.pending = supported;
        };
    }

    fn reachFrame(self: *const State, index: usize) ?wire.Frame {
        if (self.side != .client or self.probes.round == 0 or index >= capacity) return null;
        const candidate = self.local[index] orelse return null;
        return .{ .reach = .{ .round = self.probes.round, .address = candidate.address } };
    }

    fn receive(self: *State, frame: wire.Frame, now_ns: u64) Error!?Event {
        try self.negotiated();
        switch (frame) {
            .add => |value| {
                if (self.side != .client) return error.WrongConnectionSide;
                const address = wire.canonical(value.address);
                for (self.probes.remote) |slot| if (slot) |candidate| {
                    if (candidate.sequence == value.sequence) {
                        if (candidate.address.order(address) != .eq) return error.AddressConflict;
                        return null;
                    }
                };
                if (count(&self.probes.remote) >= self.remote_limit) return error.TooManyAddresses;
                self.probes.remote[empty(&self.probes.remote).?] = .{
                    .address = address, .sequence = value.sequence,
                    .remaining = if (self.probes.supported(address)) 9 else 0,
                };
                return .{ .added = address };
            },
            .remove => |sequence| {
                if (self.side != .client) return error.WrongConnectionSide;
                for (&self.probes.remote) |*slot| if (slot.*) |candidate| {
                    if (candidate.sequence == sequence) {
                        slot.* = null;
                        self.probes.forget(candidate.address);
                        return .{ .removed = candidate.address };
                    }
                };
            },
            .reach => |value| {
                if (self.side != .server) return error.WrongConnectionSide;
                const address = wire.canonical(value.address);
                if (value.round < self.probes.round or !self.probes.supported(address)) return null;
                if (value.round > self.probes.round) {
                    self.probes.round = value.round;
                    self.probes.remote = @splat(null);
                    self.probes.cancel(now_ns);
                }
                if (findAddress(&self.probes.remote, address) != null) return null;
                if (count(&self.probes.remote) >= self.remote_limit) return error.TooManyAddresses;
                self.probes.remote[empty(&self.probes.remote).?] = .{
                    .address = address, .remaining = 8, .pending = true,
                };
            },
        }
        return null;
    }

    fn nextProbe(self: *const State) ?wire.SocketAddr { return self.probes.nextProbe(); }
    fn markProbeSent(self: *State, address: wire.SocketAddr, token: u64) Error!void {
        try self.negotiated();
        try self.probes.markProbeSent(address, token);
    }
    fn recordChallenge(self: *State, address: wire.SocketAddr, token: u64) Error!void {
        try self.negotiated();
        try self.probes.recordChallenge(address, token);
    }
    fn response(self: *State, address: wire.SocketAddr, token: u64) ?Action {
        if (!self.probes.response(address, token)) return null;
        return if (self.side == .client) .open_path else .address_validated;
    }
    fn deadline(self: *const State, initial_rtt_ns: u64) ?u64 {
        return self.probes.deadline(initial_rtt_ns);
    }
    fn retry(self: *State, now_ns: u64, initial_rtt_ns: u64) void {
        self.probes.retry(now_ns, initial_rtt_ns);
    }
};

pub const Input = struct {
    initial_rtt_ns: u64,
    event: union(enum) {
        add_local: wire.SocketAddr,
        remove_local: wire.SocketAddr,
        initiate: u64,
        received: struct { frame: wire.Frame, now_ns: u64 },
        retry: u64,
        probe_sent: struct { address: wire.SocketAddr, token: u64 },
        reciprocal_sent: struct { address: wire.SocketAddr, token: u64 },
        response: struct { address: wire.SocketAddr, token: u64 },
        inspect,
        close,
    },
};
pub const Actions = struct {
    frames: [capacity]wire.Frame = undefined,
    frame_count: usize = 0,
    event: ?Event = null,
    validation: ?struct { address: wire.SocketAddr, kind: Action } = null,
    next_probe: ?wire.SocketAddr = null,
    retry_at_ns: ?u64 = null,
    cancel_queued_reach: bool = false,
};

/// Input is immutable; caller adopts out only on success. Distinct storage is required.
/// Fixed output storage avoids returning/copying a large State through the call ABI.
pub fn process(state: *const State, input: Input, noalias out: *State) Error!Actions {
    std.debug.assert(@intFromPtr(state) != @intFromPtr(out));
    out.* = state.*;
    var actions: Actions = .{};
    switch (input.event) {
        .add_local => |address| if (try out.addLocal(address)) |frame| {
            actions.frames[0] = frame;
            actions.frame_count = 1;
        },
        .remove_local => |address| if (try out.removeLocal(address)) |frame| {
            actions.frames[0] = frame;
            actions.frame_count = 1;
        },
        .initiate => |now_ns| {
            try out.initiate(now_ns);
            actions.cancel_queued_reach = true;
            for (0..capacity) |index| if (out.reachFrame(index)) |frame| {
                actions.frames[actions.frame_count] = frame;
                actions.frame_count += 1;
            };
        },
        .received => |value| actions.event = try out.receive(value.frame, value.now_ns),
        .retry => |now_ns| out.retry(now_ns, input.initial_rtt_ns),
        .probe_sent => |value| try out.markProbeSent(value.address, value.token),
        .reciprocal_sent => |value| try out.recordChallenge(value.address, value.token),
        .response => |value| if (out.response(value.address, value.token)) |kind| {
            actions.validation = .{ .address = wire.canonical(value.address), .kind = kind };
        },
        .inspect => {},
        .close => {
            out.close();
            actions.cancel_queued_reach = true;
        },
    }
    actions.next_probe = out.nextProbe();
    if (out.deadline(input.initial_rtt_ns)) |delay| {
        actions.retry_at_ns = out.probes.last_retry_ns +| delay;
    }
    return actions;
}

fn findAddress(set: *const [capacity]?Candidate, address: wire.SocketAddr) ?usize {
    for (set, 0..) |slot, index| if (slot) |candidate| {
        if (candidate.address.order(address) == .eq) return index;
    };
    return null;
}
fn count(set: *const [capacity]?Candidate) usize {
    var length: usize = 0;
    for (set) |slot| if (slot != null) { length += 1; };
    return length;
}
fn empty(set: *const [capacity]?Candidate) ?usize {
    for (set, 0..) |slot, index| if (slot == null) return index;
    return null;
}

const t = std.testing;
const example: wire.SocketAddr = .{ .ip = .{ .v4 = .{192, 0, 2, 1} }, .port = 1234 };

test "negotiation role and remote limits fail closed" {
    var disabled = try State.init(.client, 0, 1, false);
    try t.expectError(error.ExtensionNotNegotiated, disabled.addLocal(example));
    var server = try State.init(.server, 1, 1, false);
    try t.expectError(error.WrongConnectionSide, server.initiate(0));
    try t.expectError(error.WrongConnectionSide, server.receive(.{ .add = .{ .sequence = 0, .address = example } }, 0));
    const reach: wire.Frame = .{ .reach = .{ .round = 1, .address = example } };
    _ = try server.receive(reach, 0);
    _ = try server.receive(reach, 0);
    var other = example;
    other.port += 1;
    try t.expectError(error.TooManyAddresses, server.receive(.{ .reach = .{ .round = 1, .address = other } }, 0));
}

test "nine probes bounded by default four second schedule" {
    var server = try State.init(.server, 1, 1, false);
    _ = try server.receive(.{ .reach = .{ .round = 1, .address = example } }, 0);
    var now: u64 = 0;
    var probes_sent_count: u64 = 0;
    while (probes_sent_count < 9) : (probes_sent_count += 1) {
        try t.expect(server.nextProbe() != null);
        try server.markProbeSent(example, probes_sent_count + 1);
        try t.expect(server.nextProbe() == null);
        if (server.deadline(333_000_000)) |delay| {
            now += delay;
            server.retry(now, 333_000_000);
        }
    }
    try t.expect(server.nextProbe() == null);
    try t.expect(now < 4_200_000_000);
    try t.expect(server.deadline(333_000_000) == null);
}

test "new server round cancels tokens and stale reach cannot revive it" {
    var server = try State.init(.server, 1, 1, false);
    _ = try server.receive(.{ .reach = .{ .round = 1, .address = example } }, 0);
    try server.markProbeSent(example, 123);
    _ = try server.receive(.{ .reach = .{ .round = 2, .address = example } }, 10);
    try t.expect(server.response(example, 123) == null);
    try server.markProbeSent(example, 456);
    _ = try server.receive(.{ .reach = .{ .round = 1, .address = example } }, 20);
    var wrong = example;
    wrong.port += 1;
    try t.expect(server.response(wrong, 456) == null);
    try t.expectEqual(Action.address_validated, server.response(example, 456).?);
    try t.expect(server.response(example, 456) == null);
}

test "server address sequence survives remove and client conflicts fail closed" {
    var server = try State.init(.server, 2, 2, false);
    const first = (try server.addLocal(example)).?;
    const removed = (try server.removeLocal(example)).?;
    try t.expectEqual(first.add.sequence, removed.remove);
    const second = (try server.addLocal(example)).?;
    try t.expectEqual(first.add.sequence + 1, second.add.sequence);
    var client = try State.init(.client, 2, 2, false);
    _ = try client.receive(first, 0);
    var changed = first;
    changed.add.address.port += 1;
    try t.expectError(error.AddressConflict, client.receive(changed, 0));
    try t.expectError(error.NotEnoughAddresses, client.initiate(0));
    _ = try client.addLocal(example);
    try client.initiate(0);
    try client.markProbeSent(example, 77);
    _ = try client.receive(removed, 0);
    try t.expect(client.response(example, 77) == null);
}

test "retry clock does not send early and prior retry tokens remain valid" {
    var client = try State.init(.client, 1, 1, false);
    _ = try client.addLocal(example);
    _ = try client.receive(.{ .add = .{ .sequence = 1, .address = example } }, 0);
    try client.initiate(100);
    const frame = client.reachFrame(0).?;
    try t.expectEqual(@as(u64, 1), frame.reach.round);
    try client.markProbeSent(example, 10);
    client.retry(99, 333_000_000);
    client.retry(33_300_099, 333_000_000);
    try t.expect(client.nextProbe() == null);
    client.retry(33_300_100, 333_000_000);
    try client.markProbeSent(example, 11);
    try t.expectEqual(Action.open_path, client.response(example, 10).?);
    try t.expect(client.response(example, 11) == null);
    try client.initiate(40_000_000);
    try client.markProbeSent(example, 12);
    try client.initiate(40_000_001);
    try t.expect(client.response(example, 12) == null);
}

test "candidate family canonicalization and duplicate at local capacity" {
    var server = try State.init(.server, 1, 1, false);
    _ = try server.addLocal(example);
    var mapped = example;
    mapped.ip = .{ .v6 = .{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 192, 0, 2, 1} };
    try t.expect((try server.addLocal(mapped)) == null);
    const unsupported: wire.SocketAddr = .{ .ip = .{ .v6 = @splat(1) }, .port = 1234 };
    _ = try server.receive(.{ .reach = .{ .round = 100, .address = unsupported } }, 0);
    try t.expectEqual(@as(u64, 0), server.probes.round);
    _ = try server.receive(.{ .reach = .{ .round = 1, .address = mapped } }, 0);
    try t.expectEqualDeep(example, server.nextProbe().?);
    try t.expectError(error.TooManyAddresses, server.addLocal(unsupported));
}

test "challenge collisions limits and absent probe cannot overwrite tokens" {
    var server = try State.init(.server, 1, 1, true);
    try t.expectError(error.NoPendingProbe, server.markProbeSent(example, 0));
    for (0..capacity * max_probe_attempts) |token| try server.recordChallenge(example, token);
    try t.expectError(error.ChallengeCollision, server.recordChallenge(example, 0));
    try t.expectError(error.ChallengeLimit, server.recordChallenge(example, 1000));
    try t.expectEqual(Action.address_validated, server.response(example, 0).?);
    try server.recordChallenge(example, 1000);
    try t.expect(server.response(example, 1) == null);
}

test "sequence exhaustion leaves candidate and round unchanged" {
    var client = try State.init(.client, 1, 1, false);
    client.next_sequence = wire.max_sequence;
    try t.expectError(error.SequenceExhausted, client.addLocal(example));
    try t.expectEqual(@as(usize, 0), count(&client.local));
    client.next_sequence = 0;
    _ = try client.addLocal(example);
    client.probes.round = wire.max_sequence;
    try t.expectError(error.SequenceExhausted, client.initiate(0));
    try t.expectEqual(wire.max_sequence, client.probes.round);
    try t.expectError(error.TooManyAddresses, State.init(.client, 33, 1, false));
}

test "connection close invalidates probes tokens and further local commands" {
    var server = try State.init(.server, 1, 1, false);
    _ = try server.receive(.{ .reach = .{ .round = 1, .address = example } }, 0);
    try server.markProbeSent(example, 99);
    server.close();
    try t.expect(server.nextProbe() == null);
    try t.expect(server.response(example, 99) == null);
    try t.expectError(error.Closed, server.addLocal(example));
    try t.expectError(error.Closed, server.receive(.{ .remove = 0 }, 0));
}

test "multiple server sequence ids sharing one address commit one probe" {
    var client = try State.init(.client, 2, 1, false);
    _ = try client.addLocal(example);
    _ = try client.receive(.{ .add = .{ .sequence = 1, .address = example } }, 0);
    _ = try client.receive(.{ .add = .{ .sequence = 2, .address = example } }, 0);
    try client.initiate(0);
    try client.markProbeSent(example, 1);
    try t.expect(client.nextProbe() == null);
    try t.expectEqual(Action.open_path, client.response(example, 1).?);
}

test "public pure processor leaves input immutable and returns real wire and probe actions" {
    const original = try State.init(.client, 1, 1, false);
    var with_local: State = undefined;
    const added = try process(&original, .{
        .initial_rtt_ns = 333_000_000, .event = .{ .add_local = example },
    }, &with_local);
    try t.expectEqual(@as(usize, 0), count(&original.local));
    try t.expectEqual(@as(usize, 1), count(&with_local.local));
    try t.expectEqual(@as(usize, 0), added.frame_count);
    var with_remote: State = undefined;
    const received = try process(&with_local, .{
        .initial_rtt_ns = 333_000_000,
        .event = .{ .received = .{
            .frame = .{ .add = .{ .sequence = 0, .address = example } }, .now_ns = 0,
        } },
    }, &with_remote);
    try t.expectEqualDeep(example, received.event.?.added);
    var probing: State = undefined;
    const actions = try process(&with_remote, .{
        .initial_rtt_ns = 333_000_000, .event = .{ .initiate = 100 },
    }, &probing);
    try t.expect(actions.cancel_queued_reach);
    try t.expectEqual(@as(usize, 1), actions.frame_count);
    try t.expectEqual(@as(u64, 1), actions.frames[0].reach.round);
    try t.expectEqualDeep(example, actions.next_probe.?);
    try t.expectEqual(@as(u64, 33_300_100), actions.retry_at_ns.?);
    try t.expectEqual(@as(u64, 0), with_remote.probes.round);
}
