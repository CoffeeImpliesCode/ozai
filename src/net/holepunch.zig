//! Holepunching: the gate around one call into the QUIC stack.
//!
//! Holepunching is not a protocol. It is `initiate_nat_traversal_round` on a
//! QUIC connection, and relay and direct are two paths on that one connection.
//! What ozai owns is everything around that call: when to make it, what to do
//! with the answer, and which paths to forget.
//!
//!
//! Every function here takes plain slices and returns plain values, which is
//! what makes them fuzzable: `decide`, `settle`, `classify` and `prune`
//! allocate nothing and reach nothing a test cannot hand them, so a
//! `std.testing.fuzz` target can drive them from bytes against fixed oracles —
//! every prune keeps every `open` path, keeps the
//! `max_inactive_non_relay_paths` most recently closed `inactive` paths, and
//! drops no relay. No target is registered yet; those are its oracles.
//!
//! Upstream, captured 2026-09-30 at n0-computer/iroh commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8:
//!
//! - `HOLEPUNCH_ATTEMPTS_INTERVAL`, `trigger_holepunching`, `do_holepunching`
//!   and `HolepunchAttempt` from `iroh/src/socket/remote_map/remote_state.rs`.
//! - `MAX_QNT_ADDRESSES` from `iroh/src/socket.rs:145`.
//! - `MAX_NON_RELAY_PATHS`, `MAX_INACTIVE_NON_RELAY_PATHS`, `PathStatus`,
//!   `PathState` and `prune_non_relay_paths` from
//!   `iroh/src/socket/remote_map/remote_state/path_state.rs`.
//!
//! The error arms are `noq_proto::n0_nat_traversal::Error`, fetched from
//! n0-computer/noq at commit 89ed00c31297c2127d1697a7b63983d60fd02ecb,
//! `noq-proto/src/n0_nat_traversal.rs:114`.
//!
//! # What lives where
//!
//! This file is the facade and holds the module's test suite. Two modules hold
//! the bodies:
//!
//! - `holepunch_gate.zig` — the punch gate: connection selection, `decide`,
//!   `settle`, `classify`, and the state and instructions they act on.
//! - `holepunch_path.zig` — the per-peer path table, its statuses, and the
//!   prune that enforces the ceiling.
//!
//! Every declaration the facade published before the split is re-exported here,
//! so a caller outside `src/net/` is unchanged.

const std = @import("std");
const addr = @import("../base/addr.zig");

const gate = @import("holepunch_gate.zig");
const path_mod = @import("holepunch_path.zig");

const SocketAddr = addr.SocketAddr;

// The punch gate.
pub const Nanos = gate.Nanos;
pub const punch_interval = gate.punch_interval;
pub const retry_interval = gate.retry_interval;
pub const max_qnt_addresses = gate.max_qnt_addresses;
pub const mayAdvertise = gate.mayAdvertise;
pub const ConnId = gate.ConnId;
pub const Side = gate.Side;
pub const Connection = gate.Connection;
pub const selectPunchConnection = gate.selectPunchConnection;
pub const hasNewAddress = gate.hasNewAddress;
pub const Attempt = gate.Attempt;
pub const PunchState = gate.PunchState;
pub const Action = gate.Action;
pub const Step = gate.Step;
pub const Candidates = gate.Candidates;
pub const decide = gate.decide;
pub const Outcome = gate.Outcome;
pub const settle = gate.settle;
pub const NatTraversalError = gate.NatTraversalError;
pub const Verdict = gate.Verdict;
pub const classify = gate.classify;

// The path table.
pub const max_non_relay_paths = path_mod.max_non_relay_paths;
pub const max_inactive_non_relay_paths = path_mod.max_inactive_non_relay_paths;
pub const PathStatus = path_mod.PathStatus;
pub const Path = path_mod.Path;
pub const Pruned = path_mod.Pruned;
pub const prune = path_mod.prune;

// Widened in `holepunch_path.zig` for the counting helper below, which asks
// `prune`'s question about a path rather than restating it.
const isRelay = path_mod.isRelay;

const t = std.testing;

/// A direct address on port `port`, all from one documentation range so a test
/// that prints one is never mistaken for a routable host.
fn ip(port: u16) SocketAddr {
    return .{ .ip = .{ .v4 = .{ 192, 0, 2, 1 } }, .port = port };
}

/// Fill `paths` with direct paths on consecutive ports, starting at `first`.
fn fillIp(paths: []Path, first: u16, status: PathStatus) void {
    for (paths, 0..) |*path, index| {
        path.* = .{
            .addr = .{ .ip = ip(first + @as(u16, @intCast(index))) },
            .status = status,
        };
    }
}

/// Whether `paths` still carries a direct path on `port`.
fn carries(paths: []const Path, port: u16) bool {
    for (paths) |path| {
        switch (path.addr) {
            .ip => |socket| if (socket.port == port) return true,
            else => {},
        }
    }
    return false;
}

/// How many of `paths` are relay paths.
fn countRelays(paths: []const Path) usize {
    var count: usize = 0;
    for (paths) |path| {
        if (isRelay(path.addr)) count += 1;
    }
    return count;
}

/// Whether two address lists name the same addresses in the same order.
/// `SocketAddr` is a struct, so `expectEqualSlices` cannot compare one.
fn expectSameAddrs(expected: []const SocketAddr, actual: []const SocketAddr) !void {
    if (expected.len != actual.len) return error.DifferentAddresses;
    for (expected, actual) |left, right| {
        if (left.order(right) != .eq) return error.DifferentAddresses;
    }
}

/// The one instruction a step produced.
fn onlyAction(step: Step) !Action {
    return step.action orelse error.NoAction;
}

/// What a refused round classified to, as the two things a caller can ask.
fn expectVerdict(err: NatTraversalError, want: Verdict) !void {
    switch (want) {
        .retry => |after| switch (classify(err)) {
            .retry => |delay| try t.expectEqual(after, delay),
            .fatal => return error.NotRetried,
        },
        .fatal => switch (classify(err)) {
            .fatal => {},
            .retry => return error.NotFatal,
        },
    }
}

test "the punch connection is the lowest client connection" {
    const conns: []const Connection = &.{
        .{ .id = 7, .side = .server },
        .{ .id = 9, .side = .client },
        .{ .id = 4, .side = .server },
        .{ .id = 2, .side = .client },
    };
    try t.expectEqual(@as(?ConnId, 2), selectPunchConnection(conns));
    // Only server-side connections, which is what an inbound-only endpoint
    // holds, and what upstream declines to punch on.
    const inbound: []const Connection = &.{
        .{ .id = 7, .side = .server },
        .{ .id = 4, .side = .server },
    };
    try t.expectEqual(@as(?ConnId, null), selectPunchConnection(inbound));
    try t.expectEqual(@as(?ConnId, null), selectPunchConnection(&.{}));
}

test "a peer with no client connection is not punched" {
    const state: PunchState = .{};
    const step = decide(state, 0, .{
        .local = &.{ip(1)},
        .remote = &.{ip(2)},
        .previous_local = &.{},
    });
    try t.expect(step.action == null);
}

test "the first round runs whatever else is true" {
    // No attempt on record, so there is no interval and no comparison set.
    const state: PunchState = .{ .punch = 3 };
    const step = decide(state, 0, .{ .local = &.{}, .remote = &.{}, .previous_local = &.{} });
    try t.expect(std.meta.eql(Action{ .initiateNatTraversalRound = 3 }, try onlyAction(step)));
}

test "a new address before the interval is still a punch" {
    const local = [_]SocketAddr{ip(1000)};
    const remote = [_]SocketAddr{ip(2000)};
    const state: PunchState = .{
        .punch = 3,
        .last = .{ .when = 1_000, .remote = &.{} },
    };
    // A millisecond after the last round, with a remote candidate that was not
    // there then. The interval has not elapsed and the round happens anyway.
    const step = decide(state, 1_000 + std.time.ns_per_ms, .{
        .local = &local,
        .remote = &remote,
        .previous_local = &local,
    });
    try t.expect(std.meta.eql(Action{ .initiateNatTraversalRound = 3 }, try onlyAction(step)));
}

test "a new local address before the interval is still a punch" {
    const remote = [_]SocketAddr{ip(2000)};
    const state: PunchState = .{
        .punch = 3,
        .last = .{ .when = 1_000, .remote = &remote },
    };
    const step = decide(state, 1_000 + std.time.ns_per_ms, .{
        .local = &.{ip(1000)},
        .remote = &remote,
        .previous_local = &.{},
    });
    try t.expect(std.meta.eql(Action{ .initiateNatTraversalRound = 3 }, try onlyAction(step)));
}

test "an expired interval with nothing new is still a punch" {
    const local = [_]SocketAddr{ip(1000)};
    const remote = [_]SocketAddr{ip(2000)};
    const state: PunchState = .{
        .punch = 3,
        .last = .{ .when = 1_000, .remote = &remote },
    };
    const step = decide(state, 1_000 + punch_interval, .{
        .local = &local,
        .remote = &remote,
        .previous_local = &local,
    });
    try t.expect(std.meta.eql(Action{ .initiateNatTraversalRound = 3 }, try onlyAction(step)));
}

test "neither a new address nor an expired interval is not a punch" {
    const local = [_]SocketAddr{ip(1000)};
    const remote = [_]SocketAddr{ip(2000)};
    const state: PunchState = .{
        .punch = 3,
        .last = .{ .when = 1_000, .remote = &remote },
    };
    const step = decide(state, 1_000 + punch_interval - 1, .{
        .local = &local,
        .remote = &remote,
        .previous_local = &local,
    });
    const wanted: Action = .{ .wakeAt = 1_000 + punch_interval };
    try t.expect(std.meta.eql(wanted, try onlyAction(step)));
}

test "an address disappearing is not news" {
    const before = [_]SocketAddr{ ip(1000), ip(1001), ip(1002) };
    const after = [_]SocketAddr{ip(1002)};
    try t.expect(!hasNewAddress(&after, &before));
    try t.expect(!hasNewAddress(&before, &before));
    try t.expect(hasNewAddress(&.{ ip(1002), ip(1003) }, &before));
}

test "every retryable error asks again in 100 ms" {
    const state: PunchState = .{ .punch = 3 };
    for ([_]NatTraversalError{ .multipath, .not_enough_addresses }) |err| {
        const step = settle(state, 50_000, .{ .refused = err });
        try t.expect(std.meta.eql(
            Action{ .wakeAt = 50_000 + retry_interval },
            try onlyAction(step),
        ));

        try t.expect(step.next.stopped == null);
    }
}

test "every fatal error stops punching" {
    const state: PunchState = .{ .punch = 3 };
    const fatal = [_]NatTraversalError{
        .closed,
        .too_many_addresses,
        .wrong_connection_side,
        .extension_not_negotiated,
    };
    for (fatal) |err| {
        const step = settle(state, 50_000, .{ .refused = err });
        try t.expect(std.meta.eql(Action.stopPunching, try onlyAction(step)));
        try t.expectEqual(err, step.next.stopped.?);
        // A stopped state does not punch again, whatever the wakeup says.
        const again = decide(step.next, 50_000 + punch_interval, .{
            .local = &.{},
            .remote = &.{ip(1)},
            .previous_local = &.{},
        });
        try t.expect(again.action == null);
    }
}

test "every error variant is classified, and none is left over" {
    // The `comptime` guard above is the half the compiler checks: a variant
    // without a classification fails the build. This is the half it cannot —
    // that each of the six the guard names lands where upstream puts it.
    const retryable = [_]NatTraversalError{ .multipath, .not_enough_addresses };
    const fatal = [_]NatTraversalError{
        .closed,
        .too_many_addresses,
        .wrong_connection_side,
        .extension_not_negotiated,
    };
    try t.expectEqual(
        @typeInfo(NatTraversalError).@"enum".field_names.len,
        retryable.len + fatal.len,
    );
    for (retryable) |err| try expectVerdict(err, .{ .retry = retry_interval });
    for (fatal) |err| try expectVerdict(err, .fatal);
}

test "an accepted round records when it ran and what the stack found" {
    const discovered = [_]SocketAddr{ ip(2000), ip(2001) };
    const state: PunchState = .{ .punch = 3, .selected = .{ .ip = ip(1000) } };
    const step = settle(state, 7_000, .{ .accepted = &discovered });
    // Upstream schedules nothing on `Ok`: the next trigger is an address
    // change, the scheduled wakeup it may already hold, or the periodic
    // connection check.
    try t.expect(step.action == null);
    const last = step.next.last orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(Nanos, 7_000), last.when);
    try expectSameAddrs(&discovered, last.remote);
    // The set the round *started* with is not recorded here: it is the caller's,
    // and the caller hands it back as `Candidates.previous_local`. A state that
    // kept a slice of it would be borrowing the storage its own owner holds,
    // and a copy of the state would read the original's bytes.
    try t.expectEqual(@as(?ConnId, 3), step.next.punch);
}

test "a refused round does not move the interval" {
    // The state has no record of the failed round, so the same candidates read
    // as new on the next wakeup and the round happens again rather than sitting
    // out five seconds. This is what makes the 100 ms retry reachable at all.
    const local = [_]SocketAddr{ip(1000)};
    const state: PunchState = .{ .punch = 3 };
    const step = settle(state, 1_000, .{ .refused = .not_enough_addresses });
    try t.expect(step.next.last == null);
    const again = decide(step.next, 1_000 + retry_interval, .{
        .local = &local,
        .remote = &local,
        .previous_local = &.{},
    });
    try t.expect(std.meta.eql(Action{ .initiateNatTraversalRound = 3 }, try onlyAction(again)));
}

test "a selected relay path does not suppress a punch" {
    const relay_url = try addr.RelayUrl.parse("https://use1-1.relay.iroh.network./");
    const local = [_]SocketAddr{ip(1000)};
    const remote = [_]SocketAddr{ip(2000)};
    const last: Attempt = .{ .when = 1_000, .remote = &.{} };
    // A millisecond after the last round: inside the interval, with a remote
    // candidate that was not there then.
    const now = 1_000 + std.time.ns_per_ms;
    const wanted: Action = .{ .initiateNatTraversalRound = 3 };

    const candidates: Candidates = .{
        .local = &local,
        .remote = &remote,
        .previous_local = &local,
    };
    const on_relay = decide(
        .{ .punch = 3, .last = last, .selected = .{ .relay = relay_url } },
        now,
        candidates,
    );
    const on_direct = decide(
        .{ .punch = 3, .last = last, .selected = .{ .ip = ip(1000) } },
        now,
        candidates,
    );
    try t.expect(std.meta.eql(wanted, try onlyAction(on_relay)));
    try t.expect(std.meta.eql(try onlyAction(on_direct), try onlyAction(on_relay)));

    // And on the interval, with nothing new either way: the two states differ
    // only in what the connection is currently sending on, and both wait for
    // the same instant. Selecting a relay is not a reason to stop trying to
    // leave it.
    const held: Attempt = .{ .when = 1_000, .remote = &remote };
    const waited: Action = .{ .wakeAt = 1_000 + punch_interval };
    const held_candidates: Candidates = .{
        .local = &local,
        .remote = &remote,
        .previous_local = &local,
    };
    const relay_wait = decide(
        .{ .punch = 3, .last = held, .selected = .{ .relay = relay_url } },
        now,
        held_candidates,
    );
    const direct_wait = decide(
        .{ .punch = 3, .last = held, .selected = .{ .ip = ip(1000) } },
        now,
        held_candidates,
    );
    try t.expect(std.meta.eql(waited, try onlyAction(relay_wait)));
    try t.expect(std.meta.eql(try onlyAction(direct_wait), try onlyAction(relay_wait)));
}

test "the advertised-address ceiling is a hard one" {
    try t.expect(mayAdvertise(max_qnt_addresses));
    try t.expect(!mayAdvertise(max_qnt_addresses + 1));
    // Past the ceiling the stack answers `too_many_addresses`, which is fatal,
    // so an over-full lookup result ends the punch loop instead of slowing it.
    try expectVerdict(.too_many_addresses, .fatal);
}

test "nothing is pruned below the ceiling" {
    var paths: [max_non_relay_paths - 1]Path = undefined;
    fillIp(&paths, 1_000, .unknown);
    for (0..5) |index| paths[index].status = .{ .inactive = @intCast(index) };
    for (0..5) |index| paths[10 + index].status = .unusable;

    const result = prune(&paths);
    try t.expectEqual(@as(usize, paths.len), result.kept);
    try t.expectEqual(@as(usize, 0), result.unusable_dropped);
    try t.expectEqual(@as(usize, 0), result.inactive_dropped);
}

test "unusable paths are pruned before inactive ones" {
    var paths: [35]Path = undefined;
    fillIp(&paths, 1_000, .open);
    for (0..15) |index| paths[15 + index].status = .{ .inactive = @intCast(index) };
    for (0..5) |index| paths[30 + index].status = .unusable;

    const result = prune(&paths);
    try t.expectEqual(@as(usize, 5), result.unusable_dropped);
    // The ten most recently closed of the fifteen: ports 1_020..1_029.
    try t.expectEqual(@as(usize, 5), result.inactive_dropped);
    try t.expectEqual(@as(usize, 25), result.kept);
    const alive = paths[0..result.kept];
    for (0..15) |index| try t.expect(carries(alive, 1_000 + @as(u16, @intCast(index))));
    for (0..5) |index| {
        try t.expect(!carries(alive, 1_030 + @as(u16, @intCast(index))));
    }
    for (5..15) |index| {
        try t.expect(carries(alive, 1_015 + @as(u16, @intCast(index))));
    }
    for (0..5) |index| {
        try t.expect(!carries(alive, 1_015 + @as(u16, @intCast(index))));
    }
}

test "at most ten previously-successful paths survive" {
    var paths: [50]Path = undefined;
    fillIp(&paths, 2_000, .unknown);
    for (0..20) |index| paths[index].status = .{ .inactive = @intCast(index) };

    const result = prune(&paths);
    try t.expectEqual(@as(usize, 10), result.inactive_dropped);
    // The twenty most recently closed are ports 2_010..2_019.
    const alive = paths[0..result.kept];
    for (0..10) |index| {
        try t.expect(!carries(alive, 2_000 + @as(u16, @intCast(index))));
    }
    for (10..20) |index| {
        try t.expect(carries(alive, 2_000 + @as(u16, @intCast(index))));
    }
    // The thirty untried paths are not candidates for eviction at all.
    for (20..50) |index| {
        try t.expect(carries(alive, 2_000 + @as(u16, @intCast(index))));
    }
}

test "a burst of untested results does not evict the paths that work" {
    // The ten working paths sit at the cap and were closed first; the burst
    // arrives afterwards, forty addresses long, and every one of them is
    // untried. An eviction ordered by freshness rather than by what is known
    // drops all ten working paths and keeps thirty never-tried ones.
    var paths: [55]Path = undefined;
    for (0..10) |index| {
        paths[index] = .{
            .addr = .{ .ip = ip(3_000 + @as(u16, @intCast(index))) },
            .status = .{ .inactive = @intCast(index) },
        };
    }
    fillIp(paths[10..15], 3_100, .unusable);
    fillIp(paths[15..], 4_000, .unknown);

    const result = prune(&paths);
    try t.expectEqual(@as(usize, 5), result.unusable_dropped);
    try t.expectEqual(@as(usize, 0), result.inactive_dropped);
    try t.expectEqual(@as(usize, 50), result.kept);

    const alive = paths[0..result.kept];
    for (0..10) |index| {
        try t.expect(carries(alive, 3_000 + @as(u16, @intCast(index))));
    }
    for (0..5) |index| {
        try t.expect(!carries(alive, 3_100 + @as(u16, @intCast(index))));
    }
    for (0..40) |index| {
        try t.expect(carries(alive, 4_000 + @as(u16, @intCast(index))));
    }
}

test "a table that is entirely unusable keeps the ceiling worth keeping" {
    var paths: [40]Path = undefined;
    fillIp(&paths, 5_000, .unusable);

    const result = prune(&paths);
    try t.expectEqual(@as(usize, 10), result.unusable_dropped);
    try t.expectEqual(@as(usize, max_non_relay_paths), result.kept);
    // Upstream's guard does not fire once a relay path is present, and drops
    // every path instead of any; this keeps the paths the caller listed first.
    const alive = paths[0..result.kept];
    try t.expect(carries(alive, 5_000));
    try t.expect(!carries(alive, 5_030));
}

test "relay paths are neither counted nor pruned" {
    const relay_url = try addr.RelayUrl.parse("https://use1-1.relay.iroh.network./");

    // Thirty-five direct paths against four relay ones, so the non-relay count
    // is over the ceiling on its own and the prune has something to do.
    var over: [39]Path = undefined;
    fillIp(&over, 6_000, .open);
    for (0..5) |index| over[30 + index].status = .unusable;
    for (0..4) |index| {
        over[35 + index] = .{ .addr = .{ .relay = relay_url }, .status = .unusable };
    }
    const pruned = prune(&over);
    try t.expectEqual(@as(usize, 5), pruned.unusable_dropped);
    try t.expectEqual(@as(usize, 34), pruned.kept);
    try t.expectEqual(@as(usize, 4), countRelays(over[0..pruned.kept]));

    // The same relays beside twenty-five direct paths: under the ceiling, and
    // nothing is dropped however many of the paths are unusable.
    var under: [29]Path = undefined;
    fillIp(&under, 7_000, .unusable);
    for (0..4) |index| {
        under[25 + index] = .{ .addr = .{ .relay = relay_url }, .status = .unusable };
    }
    const held = prune(&under);
    try t.expectEqual(@as(usize, 29), held.kept);
    try t.expectEqual(@as(usize, 0), held.unusable_dropped);
}
