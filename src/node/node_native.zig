const std = @import("std");
const addr = @import("../base/addr.zig");
const ula = @import("../base/ula.zig");
const bridge_conn = @import("../transport/bridge_conn.zig");
const multipath = @import("../transport/multipath.zig");
const path_action = @import("../net/path_action.zig");
const holepunch = @import("../net/holepunch.zig");
const run = @import("../net/holepunch_run.zig");
const tracking = @import("node_holepunch.zig");
const Node = @import("node.zig").Node;
const Instant = @import("../transport/quic_bridge.zig").Instant;
const Random = std.Random;

pub const NativeError = bridge_conn.TraversalError || multipath.ActionError;

/// Drives only configured candidates on existing authenticated connections.
/// Native NAT responses already open and challenge path one; opening a second
/// path here would race that actuator and bypass its reciprocal NAT proof.
pub fn pass(self: *Node, at: Instant, random: Random) NativeError!bool {
    std.debug.assert(at >= 0);
    const config = self.config.traversal;
    if (config.local_candidates.len == 0) return false;
    tracking.prepare(&self.holepunch, self.bridge);
    self.holepunch.sweepNative(self.bridge);
    var moved = false;
    var index: usize = 0;
    while (self.bridge.connectionAt(index)) |conn| : (index += 1) {
        const fact = tracking.authenticated(conn) orelse continue;
        if (conn.entry.conn.nat_state == null) continue;
        if (!conn.entry.conn.multipathNegotiated()) continue;
        const join = self.holepunch.get(fact.peer) orelse continue;
        const native = self.holepunch.nativeFor(conn.id());
        while (native.advertised < config.local_candidates.len) {
            const candidate = config.local_candidates[native.advertised];
            if (ula.classify(candidate) != .ip) return error.InvalidAddress;
            conn.addTraversalAddress(candidate) catch |err| {
                recordRefusal(join, at, err);
                return err;
            };
            native.advertised += 1;
            moved = true;
        }
        join.local.clear();
        for (config.local_candidates) |candidate| join.local.append(candidate);
        var remote_buffer: [32]addr.SocketAddr = undefined;
        const remote = conn.traversalCandidates(&remote_buffer);
        try validateCandidates(remote);
        recordCandidates(join, remote);
        if (config.initiate and fact.side == .client and
            remote.len != 0 and !native.initiated)
        {
            conn.initiateTraversal(at, random) catch |err| {
                recordRefusal(join, at, err);
                return err;
            };
            native.initiated = true;
            native.started_at = at;
            join.punch.punch = std.math.cast(usize, conn.id());
            // The void initiation API reports no returned candidates. The
            // independently copied remote snapshot lives in Join.remote.
            const next = join.settle(@intCast(at), .{ .accepted = &.{} });
            _ = next;
            moved = true;
        }
        const round = conn.traversalState();
        if (native.round != round) moved = true;
        native.round = round;
        const slots = multipath.actionSlots(conn);
        const action = selectCandidate(remote, &slots);
        if (action != .none) {
            const opened = try multipath.applyAction(conn, action, at, random);
            std.debug.assert(opened == null);
            moved = true;
        }
        recordPaths(join, conn);
    }
    return moved;
}

fn recordRefusal(join: *run.Join, at: Instant, err: bridge_conn.TraversalError) void {
    const refused: holepunch.NatTraversalError = switch (err) {
        error.TooManyAddresses => .too_many_addresses,
        error.WrongConnectionSide => .wrong_connection_side,
        error.NatTraversalNotNegotiated => .extension_not_negotiated,
        error.NotEnoughAddresses => .not_enough_addresses,
        error.InvalidAddress, error.InvalidSequence, error.ProbeNotPending,
        error.TooManyChallenges => return,
    };
    const next = join.settle(@intCast(at), .{ .refused = refused });
    _ = next;
}

fn validateCandidates(candidates: []const addr.SocketAddr) bridge_conn.TraversalError!void {
    for (candidates) |candidate| {
        if (ula.classify(candidate) != .ip) return error.InvalidAddress;
    }
}

fn recordCandidates(join: *run.Join, candidates: []const addr.SocketAddr) void {
    join.remote.clear();
    for (candidates) |candidate| {
        if (ula.classify(candidate) != .ip) continue;
        join.remote.append(candidate);
        const absorbed = join.absorb(&.{candidate});
        _ = absorbed;
    }
}

fn selectCandidate(candidates: []const addr.SocketAddr, slots: *const path_action.Slots)
    path_action.Action
{
    var planned: path_action.Action = .none;
    for (slots) |snapshot| {
        const path = snapshot orelse continue;
        if (ula.classify(path.key.local) != .ip) continue;
        if (ula.classify(path.key.peer) != .ip) continue;
        for (candidates) |candidate| {
            if (candidate.order(path.key.peer) != .eq) continue;
            if (path.selected and path.validated) return .none;
            const action = path_action.planSelect(path.key, slots);
            if (planned == .none) planned = action;
        }
    }
    return planned;
}

fn recordPaths(join: *run.Join, conn: bridge_conn.Conn) void {
    join.punch.selected = null;
    for (0..path_action.supported_paths) |index| {
        const snapshot = conn.pathSnapshot(@intCast(index)) orelse continue;
        const peer = snapshot.peer orelse continue;
        if (ula.classify(peer) != .ip) continue;
        if (snapshot.selected and snapshot.validated and snapshot.status == .available) {
            join.punch.selected = .{ .ip = peer };
        }
        if (snapshot.state == .failed) {
            const filed = join.observe(.{ .addr = .{ .ip = peer }, .status = .unusable });
            _ = filed;
        }
    }
}

const direct: addr.SocketAddr = .{ .ip = .{ .v4 = .{ 192, 0, 2, 2 } }, .port = 4001 };

test "native candidate snapshots are not proof and virtual candidates are excluded" {
    var join: run.Join = .{};
    recordCandidates(&join, &.{ direct, ula.default_fake_addr });
    try std.testing.expectEqual(@as(usize, 1), join.remote.len);
    try std.testing.expectEqual(@as(usize, 1), join.path_count);
    try std.testing.expect(join.paths[0].status == .unknown);
    const filed = join.observe(.{ .addr = .{ .ip = direct }, .status = .open });
    try std.testing.expect(filed.stored);
    recordCandidates(&join, &.{direct});
    try std.testing.expect(join.paths[0].status == .open);
}

test "native selection requires validated candidate on same physical connection path" {
    const local: addr.SocketAddr = .{ .ip = .{ .v4 = .{ 192, 0, 2, 1 } }, .port = 4000 };
    var slots: path_action.Slots = .{ null, .{
        .key = .{ .local = local, .peer = direct }, .validated = false,
    } };
    try std.testing.expect(selectCandidate(&.{direct}, &slots) == .none);
    slots[1].?.validated = true;
    try std.testing.expect(selectCandidate(&.{direct}, &slots) == .select);
    try std.testing.expect(selectCandidate(&.{}, &slots) == .none);
    slots[1].?.key.peer = ula.default_fake_addr;
    try std.testing.expect(selectCandidate(&.{ula.default_fake_addr}, &slots) == .none);
}

test "already selected direct candidate prevents native path oscillation" {
    const local: addr.SocketAddr = .{ .ip = .{ .v4 = .{ 192, 0, 2, 1 } }, .port = 4000 };
    const slots: path_action.Slots = .{ .{
        .key = .{ .local = local, .peer = direct }, .validated = true,
    }, .{
        .key = .{ .local = local, .peer = direct },
        .validated = true, .selected = true,
    } };
    try std.testing.expect(selectCandidate(&.{direct}, &slots) == .none);
}

test "actual traversal refusal is retained without manufacturing a path failure" {
    var join: run.Join = .{};
    recordRefusal(&join, 10, error.TooManyAddresses);
    try std.testing.expectEqual(@as(?@import("../net/holepunch.zig").NatTraversalError,
        .too_many_addresses), join.punch.stopped);
    try std.testing.expectEqual(@as(usize, 0), join.path_count);
}

test "native remote snapshot cannot authorize a synthetic probe destination" {
    try std.testing.expectError(error.InvalidAddress,
        validateCandidates(&.{ direct, ula.default_fake_addr }));
    try validateCandidates(&.{direct});
}
