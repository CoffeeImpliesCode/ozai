const std = @import("std");
const addr = @import("../base/addr.zig");
const holepunch = @import("../net/holepunch.zig");
const run = @import("../net/holepunch_run.zig");
const bridge_mod = @import("../transport/quic_bridge.zig");
const ula = @import("../base/ula.zig");

pub const Native = struct {
    id: u64,
    advertised: usize = 0,
    initiated: bool = false,
    started_at: ?bridge_mod.Instant = null,
    round: @import("../transport/bridge_conn.zig").RoundState = .idle,
};

const Fact = struct {
    id: u64,
    peer: addr.NodeId,
    side: holepunch.Side,
    packets: u64,
};

const Slot = struct {
    peer: addr.NodeId = undefined,
    join: run.Join = .{},
    live: bool = false,
    before: Fact = undefined,
    native: Native = undefined,
};

/// Receipt facts and native per-connection latches occupy separate counted prefixes.
/// Slots are bounded by the manager's live-connection limit and allocated once.
pub const State = struct {
    slots: []Slot,
    peer_count: usize = 0,
    before_count: usize = 0,
    native_count: usize = 0,
    traffic_refused: usize = 0,

    pub fn init(gpa: std.mem.Allocator, max_connections: usize) error{OutOfMemory}!State {
        const slots = try gpa.alloc(Slot, max_connections);
        for (slots) |*slot| slot.* = .{};
        return .{ .slots = slots };
    }

    pub fn deinit(self: *State, gpa: std.mem.Allocator) void {
        gpa.free(self.slots);
        self.* = undefined;
    }

    pub fn get(self: *State, peer: addr.NodeId) ?*run.Join {
        for (self.slots[0..self.peer_count]) |*slot| {
            if (std.mem.eql(u8, &slot.peer.toBytes(), &peer.toBytes())) return &slot.join;
        }
        return null;
    }

    pub fn nativeFor(self: *State, id: u64) *Native {
        for (self.slots[0..self.native_count]) |*slot| {
            if (slot.native.id == id) return &slot.native;
        }
        std.debug.assert(self.native_count < self.slots.len);
        const native = &self.slots[self.native_count].native;
        native.* = .{ .id = id };
        self.native_count += 1;
        return native;
    }

    pub fn sweepNative(self: *State, bridge: *bridge_mod.Bridge) void {
        var index: usize = 0;
        while (index < self.native_count) {
            var found = false;
            var connection_index: usize = 0;
            while (bridge.connectionAt(connection_index)) |conn| : (connection_index += 1) {
                if (conn.id() == self.slots[index].native.id and !conn.closed()) {
                    found = true;
                    break;
                }
            }
            if (found) {
                index += 1;
            } else {
                self.native_count -= 1;
                self.slots[index].native = self.slots[self.native_count].native;
            }
        }
    }

    fn begin(self: *State) void {
        self.before_count = 0;
        for (self.slots[0..self.peer_count]) |*slot| {
            slot.live = false;
            slot.join.punch.punch = null;
        }
    }

    fn connection(self: *State, fact: Fact) void {
        std.debug.assert(self.before_count < self.slots.len);
        self.slots[self.before_count].before = fact;
        self.before_count += 1;
        var index: usize = 0;
        while (index < self.peer_count) : (index += 1) {
            if (std.mem.eql(u8, &self.slots[index].peer.toBytes(), &fact.peer.toBytes())) break;
        }
        if (index == self.peer_count) {
            std.debug.assert(self.peer_count < self.slots.len);
            self.slots[index].peer = fact.peer;
            self.slots[index].join = .{};
            self.peer_count += 1;
        }
        const slot = &self.slots[index];
        slot.live = true;
        if (fact.side == .client) {
            const id = std.math.cast(usize, fact.id) orelse return;
            if (slot.join.punch.punch == null or id < slot.join.punch.punch.?) {
                slot.join.punch.punch = id;
            }
        }
    }

    fn end(self: *State) void {
        var index: usize = 0;
        while (index < self.peer_count) {
            if (self.slots[index].live) {
                index += 1;
            } else {
                self.peer_count -= 1;
                // Snapshot storage has a separate counted prefix. Do not move it.
                self.slots[index].peer = self.slots[self.peer_count].peer;
                self.slots[index].join = self.slots[self.peer_count].join;
                self.slots[index].live = self.slots[self.peer_count].live;
            }
        }
    }

    fn accepted(self: *State, fact: Fact, source: addr.SocketAddr) void {
        if (ula.classify(source) != .ip) return;
        for (self.slots[0..self.before_count]) |*slot| {
            const before = slot.before;
            if (before.id != fact.id or fact.packets <= before.packets) continue;
            if (!std.mem.eql(u8, &before.peer.toBytes(), &fact.peer.toBytes())) continue;
            const join = self.get(fact.peer) orelse return;
            const filed = join.observe(.{ .addr = .{ .ip = source }, .status = .open });
            if (!filed.stored) self.traffic_refused += 1;
            return;
        }
    }
};

pub fn authenticated(conn: bridge_mod.Conn) ?Fact {
    if (!conn.established() or conn.closed()) return null;
    const handshake = conn.entry.conn.tls13_hs orelse return null;
    const bytes = handshake.peerNodeId() orelse return null;
    const peer = addr.NodeId.fromBytes(bytes) catch return null;
    return .{
        .id = conn.id(),
        .peer = peer,
        .side = if (conn.entry.conn.is_server) .server else .client,
        .packets = conn.entry.conn.total_packets_received,
    };
}

/// Call immediately before each individual datagram enters Bridge.recv.
pub fn prepare(self: *State, bridge: *bridge_mod.Bridge) void {
    // Discard reaped peers before adding new ones so capacity follows live connections.
    for (self.slots[0..self.peer_count]) |*slot| {
        slot.live = false;
        var index: usize = 0;
        while (bridge.connectionAt(index)) |conn| : (index += 1) {
            const fact = authenticated(conn) orelse continue;
            if (std.mem.eql(u8, &slot.peer.toBytes(), &fact.peer.toBytes())) {
                slot.live = true;
                break;
            }
        }
    }
    self.end();
    self.begin();
    var index: usize = 0;
    while (bridge.connectionAt(index)) |conn| : (index += 1) {
        self.connection(authenticated(conn) orelse continue);
    }
    self.end();
}

/// Counter increments follow AEAD acceptance. UDP receipt and path-validation flags
/// alone are not traffic proof. Requiring authentication before and after the call
/// also excludes packets replayed from pre-handshake buffering.
pub fn received(
    self: *State,
    bridge: *bridge_mod.Bridge,
    source: addr.SocketAddr,
    datagram: []const u8,
) void {
    if (!applicationDatagram(datagram)) return;
    var index: usize = 0;
    while (bridge.connectionAt(index)) |conn| : (index += 1) {
        self.accepted(authenticated(conn) orelse continue, source);
    }
}

fn applicationDatagram(datagram: []const u8) bool {
    // Initial protection is public, so only 1-RTT can prove peer path traffic.
    return datagram.len > 0 and datagram[0] & 0xc0 == 0x40;
}

test "accepted traffic opens only the source path of the same authenticated connection" {
    const t = std.testing;
    var state = try State.init(t.allocator, 2);
    defer state.deinit(t.allocator);
    const peer = try addr.NodeId.fromBytes([_]u8{7} ** 32);
    const source = addr.SocketAddr{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 9000 };
    state.begin();
    state.connection(.{ .id = 41, .peer = peer, .side = .client, .packets = 9 });
    state.end();
    state.accepted(.{ .id = 41, .peer = peer, .side = .client, .packets = 9 }, source);
    try t.expectEqual(@as(usize, 0), state.get(peer).?.path_count);
    state.accepted(.{ .id = 42, .peer = peer, .side = .client, .packets = 10 }, source);
    try t.expectEqual(@as(usize, 0), state.get(peer).?.path_count);
    const other = try addr.NodeId.fromBytes([_]u8{9} ** 32);
    state.accepted(.{ .id = 41, .peer = other, .side = .client, .packets = 10 }, source);
    try t.expectEqual(@as(usize, 0), state.get(peer).?.path_count);
    state.accepted(.{ .id = 41, .peer = peer, .side = .client, .packets = 10 }, source);
    const join = state.get(peer).?;
    try t.expectEqual(@as(usize, 1), join.path_count);
    try t.expectEqual(std.math.Order.eq, join.paths[0].addr.ip.order(source));
    try t.expectEqual(std.meta.Tag(holepunch.PathStatus).open, std.meta.activeTag(join.paths[0].status));
}

test "live client identity selection excludes servers and forgets reaped connections" {
    const t = std.testing;
    var state = try State.init(t.allocator, 3);
    defer state.deinit(t.allocator);
    const peer = try addr.NodeId.fromBytes([_]u8{7} ** 32);
    state.begin();
    state.connection(.{ .id = 3, .peer = peer, .side = .server, .packets = 1 });
    state.connection(.{ .id = 50, .peer = peer, .side = .client, .packets = 1 });
    state.connection(.{ .id = 40, .peer = peer, .side = .client, .packets = 1 });
    state.end();
    try t.expectEqual(@as(?usize, 40), state.get(peer).?.punch.punch);
    state.begin();
    state.connection(.{ .id = 3, .peer = peer, .side = .server, .packets = 1 });
    state.end();
    try t.expectEqual(@as(?usize, null), state.get(peer).?.punch.punch);
    state.begin();
    state.end();
    try t.expect(state.get(peer) == null);
}

test "publicly decryptable Initial and other long headers are not authenticated traffic" {
    const t = std.testing;
    try t.expect(!applicationDatagram(&.{}));
    try t.expect(!applicationDatagram(&.{0xc0}));
    try t.expect(!applicationDatagram(&.{0xe0}));
    try t.expect(!applicationDatagram(&.{0x00}));
    try t.expect(applicationDatagram(&.{0x40}));
    try t.expect(applicationDatagram(&.{0x5f}));
}

test "native connection latches do not move fact or peer prefixes" {
    const t = std.testing;
    var state = try State.init(t.allocator, 2);
    defer state.deinit(t.allocator);
    const peer = try addr.NodeId.fromBytes([_]u8{7} ** 32);
    state.begin();
    state.connection(.{ .id = 41, .peer = peer, .side = .client, .packets = 9 });
    state.end();
    const native = state.nativeFor(41);
    native.advertised = 2;
    native.initiated = true;
    try t.expectEqual(@as(usize, 2), state.nativeFor(41).advertised);
    try t.expect(state.nativeFor(41).initiated);
    try t.expect(!state.nativeFor(42).initiated);
    try t.expectEqual(@as(u64, 41), state.slots[0].before.id);
    try t.expectEqual(@as(?usize, 41), state.get(peer).?.punch.punch);
}

test "synthetic relay receipt is never direct path proof" {
    const t = std.testing;
    var state = try State.init(t.allocator, 1);
    defer state.deinit(t.allocator);
    const peer = try addr.NodeId.fromBytes([_]u8{7} ** 32);
    state.begin();
    state.connection(.{ .id = 41, .peer = peer, .side = .client, .packets = 9 });
    state.end();
    const fact: Fact = .{ .id = 41, .peer = peer, .side = .client, .packets = 10 };
    state.accepted(fact, @import("../base/ula.zig").default_fake_addr);
    try t.expectEqual(@as(usize, 0), state.get(peer).?.path_count);
}
