const std = @import("std");
const addr = @import("../base/addr.zig");
const ula = @import("../base/ula.zig");
const bridge_conn = @import("../transport/bridge_conn.zig");
const native_path = @import("../transport/native_path.zig");
const path_action = @import("../net/path_action.zig");
const holepunch = @import("../net/holepunch.zig");
const run = @import("../net/holepunch_run.zig");
const tracking = @import("node_holepunch.zig");
const Node = @import("node.zig").Node;
const Instant = @import("../transport/quic_bridge.zig").Instant;
const Random = std.Random;

pub const NativeError = bridge_conn.TraversalError || native_path.ActionError;

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
        if (fact.side == .client) {
            // Preparation owns client admission; server responders still advertise.
            const selected = join.punch.punch orelse continue;
            if (selected != conn.id()) continue;
        }
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
            // The void initiation API reports no returned candidates. The
            // independently copied remote snapshot lives in Join.remote.
            const next = join.settle(@intCast(at), .{ .accepted = &.{} });
            _ = next;
            moved = true;
        }
        const round = conn.traversalState();
        if (native.round != round) moved = true;
        native.round = round;
        const slots = native_path.actionSlots(conn);
        const action = selectCandidate(remote, &slots);
        if (action != .none) {
            const opened = try native_path.applyAction(conn, action, at, random);
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
        error.InvalidAddress, error.InvalidSequence => return,
        error.ProbeNotPending, error.TooManyChallenges => return,
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

fn selectCandidate(
    candidates: []const addr.SocketAddr,
    slots: *const path_action.Slots,
) path_action.Action {
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
        .key = .{ .local = local, .peer = direct },
        .validated = false,
    } };
    try std.testing.expect(selectCandidate(&.{direct}, &slots) == .none);
    const slot = if (slots[1]) |*value| value else return error.TestUnexpectedResult;
    slot.validated = true;
    try std.testing.expect(selectCandidate(&.{direct}, &slots) == .select);
    try std.testing.expect(selectCandidate(&.{}, &slots) == .none);
    slot.key.peer = ula.default_fake_addr;
    try std.testing.expect(selectCandidate(&.{ula.default_fake_addr}, &slots) == .none);
}

test "already selected direct candidate prevents native path oscillation" {
    const local: addr.SocketAddr = .{ .ip = .{ .v4 = .{ 192, 0, 2, 1 } }, .port = 4000 };
    const slots: path_action.Slots = .{ .{
        .key = .{ .local = local, .peer = direct },
        .validated = true,
    }, .{
        .key = .{ .local = local, .peer = direct },
        .validated = true,
        .selected = true,
    } };
    try std.testing.expect(selectCandidate(&.{direct}, &slots) == .none);
}

test "actual traversal refusal is retained without manufacturing a path failure" {
    var join: run.Join = .{};
    recordRefusal(&join, 10, error.TooManyAddresses);
    try std.testing.expectEqual(
        @as(?holepunch.NatTraversalError, .too_many_addresses),
        join.punch.stopped,
    );
    try std.testing.expectEqual(@as(usize, 0), join.path_count);
}

test "native remote snapshot cannot authorize a synthetic probe destination" {
    try std.testing.expectError(
        error.InvalidAddress,
        validateCandidates(&.{ direct, ula.default_fake_addr }),
    );
    try validateCandidates(&.{direct});
}

test "native driver initiates only minimum authenticated client ID in either table order" {
    // Real handshakes establish two eligible connections to the same peer.
    // Reverse their table order without assuming allocation order is ID order.
    const t = std.testing;
    const fixture = @import("../transport/dial_pair.zig");
    const bridge = @import("../transport/quic_bridge.zig");
    const quic = @import("quic");
    for ([_]bool{ false, true }) |reverse| {
        var pair: fixture.Pair = undefined;
        try pair.init(fixture.client_seed, fixture.server_seed, null, 891, true);
        defer pair.deinit();
        const server_bridge = try bridge.Bridge.create(t.allocator, t.io, .{
            .secret = pair.server_secret,
            .expect_peer = pair.dialer_secret.nodeId(),
            .alpn = fixture.alpn,
            .address_discovery_role = .send_only,
            .max_remote_nat_traversal_addresses = 32,
            .initial_max_path_id = 1,
        }, pair.engine.random());
        pair.server_bridge.destroy();
        pair.server_bridge = server_bridge;
        pair.dialer.config.address_discovery_role = .receive_only;
        pair.dialer.config.max_remote_nat_traversal_addresses = 7;
        pair.dialer.config.initial_max_path_id = 1;
        const clients = blk: {
            var connections: [2]bridge.Conn = undefined;
            for (&connections) |*connection| {
                const dial = try pair.dialer.dial(
                    try fixture.relayTarget(),
                    pair.server_secret.nodeId(),
                    fixture.client_addr,
                    &pair.map,
                    fixture.start,
                    pair.engine.random(),
                );
                var log: fixture.StateLog = .{};
                try fixture.exchange(
                    pair.dialer,
                    dial.conn,
                    pair.server_bridge,
                    &pair.map,
                    &log,
                    fixture.start,
                    pair.engine.random(),
                );
                try t.expect(dial.conn.established());
                try t.expect(tracking.authenticated(dial.conn).?.side == .client);
                try t.expect(dial.conn.entry.conn.multipathNegotiated());
                try t.expect(dial.conn.entry.conn.nat_state != null);
                const add: quic.frame.Frame = .{ .add_address = .{
                    .sequence = 1,
                    .address = quic.address.Address.initIpv4(.{ 192, 0, 2, 11 }, 4040),
                } };
                try dial.conn.entry.conn.processFrame(
                    &add,
                    .application,
                    fixture.start,
                    pair.engine.random(),
                );
                connection.* = dial.conn;
            }
            break :blk connections;
        };
        const selected = if (clients[0].id() < clients[1].id()) clients[0] else clients[1];
        const other = if (clients[0].id() < clients[1].id()) clients[1] else clients[0];
        try t.expect(selected.id() != other.id());
        const entries = pair.dialer_bridge.manager.entries.items;
        try t.expectEqual(@as(usize, 2), entries.len);
        entries[0] = if (reverse) other.entry else selected.entry;
        entries[1] = if (reverse) selected.entry else other.entry;
        const driver = try t.allocator.create(Node);
        defer t.allocator.destroy(driver);
        driver.config = .{
            .secret = pair.dialer_secret,
            .traversal = .{ .local_candidates = &.{direct}, .initiate = true },
        };
        driver.bridge = pair.dialer_bridge;
        driver.holepunch = try tracking.State.init(t.allocator, 2);
        defer driver.holepunch.deinit(t.allocator);
        try t.expect(try pass(driver, fixture.start, pair.engine.random()));
        const join = driver.holepunch.get(pair.server_secret.nodeId()) orelse
            return error.TestUnexpectedResult;
        try t.expectEqual(std.math.cast(usize, selected.id()), join.punch.punch);
        try t.expect(driver.holepunch.nativeFor(selected.id()).initiated);
        try t.expect(!driver.holepunch.nativeFor(other.id()).initiated);
        try t.expectEqual(@as(usize, 0), driver.holepunch.nativeFor(other.id()).advertised);
        const other_nat = other.entry.conn.nat_state orelse return error.TestUnexpectedResult;
        try t.expectEqual(@as(u8, 0), other_nat.local_count);
        try t.expectEqual(@as(u64, 0), other_nat.round);
        try t.expect(other.traversalState() == .idle);
        try t.expectEqual(@as(usize, 1), join.remote.len);
        const responder = try t.allocator.create(Node);
        defer t.allocator.destroy(responder);
        responder.config = .{
            .secret = pair.server_secret,
            .traversal = .{ .local_candidates = &.{direct}, .initiate = true },
        };
        responder.bridge = pair.server_bridge;
        responder.holepunch = try tracking.State.init(t.allocator, 2);
        defer responder.holepunch.deinit(t.allocator);
        try t.expect(try pass(responder, fixture.start, pair.engine.random()));
        const response_join = responder.holepunch.get(pair.dialer_secret.nodeId()) orelse
            return error.TestUnexpectedResult;
        try t.expect(response_join.punch.punch == null);
        for (pair.server_bridge.manager.entries.items) |entry| {
            const accepted: bridge.Conn = .{ .entry = entry };
            const accepted_nat = entry.conn.nat_state orelse return error.TestUnexpectedResult;
            try t.expectEqual(@as(u8, 1), accepted_nat.local_count);
            try t.expect(!responder.holepunch.nativeFor(accepted.id()).initiated);
        }
    }
}
