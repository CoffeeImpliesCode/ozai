//! The run: the event queue, the links, and the arena copies that let a
//! queued message outlive the state that emitted it.
//!
//! `enqueue` keeps the queue ordered by `(time, insertion order)`, `tick`
//! takes the next entry and hands it to a node, and `command`, `runTrips` and
//! `runDuration` are the three ways a caller advances the clock. The link table
//! and the one latency drawn per link are here too, because a link only comes
//! into being while a tick is moving a message along it.
const plumtree = @import("../plumtree.zig");
const topic = @import("topic.zig");
const harness = @import("sim_harness.zig");
const parking = @import("sim_park.zig");
const swarm = @import("sim_swarm.zig");

const Nanos = plumtree.Nanos;
const Actions = plumtree.Actions;
const Command = topic.Command;
const InEvent = topic.InEvent;
const AppEvent = topic.AppEvent;
const OutEvent = topic.OutEvent;
const max_conns = harness.max_conns;
const max_kills = harness.max_kills;
const disconnect_grace = harness.disconnect_grace;
const HarnessError = harness.HarnessError;
const nodeIdFor = harness.nodeIdFor;
const Network = swarm.Network;
const Conn = swarm.Conn;

// ziglint-ignore: Z015
/// Hand a command to a node, then run whatever the current instant
/// has queued. Upstream `Network::command`.
pub fn command(self: *Network, index: u8, request: Command) HarnessError!void {
    const leaving = request == .quit;
    const parked = try park(self, .{ .command = request });
    try enqueue(self, self.time, index, parked);
    try tick(self);
    if (!leaving) return;
    if (self.peerSlot(index)) |peer| peer.joined = false;
}

// ziglint-ignore: Z015
pub fn runTrips(self: *Network, count: u64) HarnessError!void {
    try runDuration(self, self.config.latency.maxLatency() * count);
}

// ziglint-ignore: Z015
pub fn runDuration(self: *Network, duration: Nanos) HarnessError!void {
    const end = self.time + duration;
    while (self.queue.items.len > 0 and self.queue.items[0].time <= end) {
        try tick(self);
    }
    self.time = end;
}

/// When the next queued event is due, or `null` when nothing is
/// pending. A gossip round uses this to stop on its timeout.
pub fn nextTime(self: *const Network) ?Nanos {
    if (self.queue.items.len == 0) return null;
    return self.queue.items[0].time;
}

/// Insert keeping the queue ordered by `(time, insertion order)`.
///
/// **The tie-break is part of the contract.** Among events due at the
/// same instant the earliest *inserted* is handled first, so a node
/// sees a message before the disconnect that follows it, and a
/// `Neighbor` before whatever provoked it. Inserting after every entry
/// whose time is less than or equal to the new one gives that for
/// free, and it is exactly what upstream's
/// `BinaryHeap<(TimedEvent, i32)>` does: a reversed `Ord` on the time
/// and a negated sequence number as the second key, which together pop
/// equal times first-in-first-out. A queue sorted by peer id, or with
/// any other tie-break, silently changes the run, and because the
/// protocol is symmetric the change is invisible in the final views
/// and visible only in the event counts.
fn enqueue(
    self: *Network,
    time: Nanos,
    index: u8,
    event: InEvent,
) HarnessError!void {
    var at = self.queue.items.len;
    for (self.queue.items, 0..) |entry, position| {
        if (entry.time > time) {
            at = position;
            break;
        }
    }
    try self.queue.insert(self.gpa, at, .{
        .time = time,
        .peer = index,
        .event = event,
    });
}

pub fn tick(self: *Network) HarnessError!void {
    if (self.queue.items.len == 0) return;
    const entry = self.queue.orderedRemove(0);
    self.time = entry.time;
    const peer = self.peerSlot(entry.peer) orelse return;
    if (!peer.joined) return;
    if (entry.event == .recv_message) {
        if (self.peerIndexOf(entry.event.recv_message.from)) |other| {
            addConn(self, other, entry.peer);
        }
    }
    var out: Actions(OutEvent) = .init(self.gpa);
    defer out.deinit();
    try peer.state.handle(entry.event, self.time, &out);

    var kills: [max_kills]Conn = undefined;
    var kill_count: usize = 0;
    for (out.slice()) |event| switch (event) {
        .send_message => |send| {
            const to = self.peerIndexOf(send.to) orelse continue;
            const latency = latencyBetween(self, entry.peer, to);
            const parked = try park(self, .{
                .recv_message = .{ .from = peer.id, .message = send.message },
            });
            try enqueue(self, self.time + latency, to, parked);
        },
        .schedule_timer => |schedule| {
            const parked = try park(self, .{ .timer_expired = schedule.timer });
            try enqueue(self, self.time + schedule.after, entry.peer, parked);
        },
        .disconnect_peer => |other| {
            const to = self.peerIndexOf(other) orelse continue;
            if (kill_count == max_kills) return error.TooManyDisconnects;
            kills[kill_count] = .{ .a = @min(entry.peer, to), .b = @max(entry.peer, to) };
            kill_count += 1;
        },
        .emit_event => |reported| try self.events.append(self.gpa, .{
            .peer = entry.peer,
            .event = try parkEvent(self, reported),
        }),
        .peer_data => {},
    };
    for (kills[0..kill_count]) |conn| try killConnection(self, conn.a, conn.b);
}

/// Break a link; the other end hears about it one microsecond after the
/// usual latency, so anything already in flight lands first.
fn killConnection(self: *Network, a: u8, b: u8) HarnessError!void {
    if (!removeConn(self, a, b)) return;
    const latency = latencyBetween(self, a, b) + disconnect_grace;
    try enqueue(self, self.time + latency, b, .{
        .peer_disconnected = try nodeIdFor(a),
    });
}

fn addConn(self: *Network, a: u8, b: u8) void {
    if (a == b) return;
    if (findConn(self, a, b) != null) return;
    if (self.conn_count == max_conns) return;
    self.links[self.conn_count] = .{ .a = @min(a, b), .b = @max(a, b) };
    self.conn_count += 1;
}

fn removeConn(self: *Network, a: u8, b: u8) bool {
    for (self.links[0..self.conn_count], 0..) |conn, index| {
        if (conn.a != @min(a, b) or conn.b != @max(a, b)) continue;
        @memmove(
            self.links[index .. self.conn_count - 1],
            self.links[index + 1 .. self.conn_count],
        );
        self.conn_count -= 1;
        return true;
    }
    return false;
}

fn findConn(self: *const Network, a: u8, b: u8) ?Conn {
    for (self.links[0..self.conn_count]) |conn| {
        if (conn.a == @min(a, b) and conn.b == @max(a, b)) return conn;
    }
    return null;
}

/// Every open link. Upstream `Network::conns`.
pub fn conns(self: *const Network) []const Conn {
    return self.links[0..self.conn_count];
}

/// One latency per link, drawn the first time the link is used and
/// kept. A link whose speed changed every message would be a different
/// network on every tick, and the run would stop being reproducible.
fn latencyBetween(self: *Network, a: u8, b: u8) Nanos {
    const conn: Conn = .{ .a = @min(a, b), .b = @max(a, b) };
    for (self.latencies[0..self.latency_count]) |entry| {
        if (entry.conn.a == conn.a and entry.conn.b == conn.b) return entry.latency;
    }
    const drawn = self.config.latency.draw(&self.rng);
    if (self.latency_count == max_conns) return drawn;
    self.latencies[self.latency_count] = .{ .conn = conn, .latency = drawn };
    self.latency_count += 1;
    return drawn;
}

/// Deep-copy an event's payloads into the arena, so a queued message
/// does not point into the state that emitted it.
fn park(self: *Network, event: InEvent) HarnessError!InEvent {
    const a = self.arena.allocator();
    return switch (event) {
        .recv_message => |recv| .{ .recv_message = .{
            .from = recv.from,
            .message = try parking.parkMessage(a, recv.message),
        } },
        .command => |requested| switch (requested) {
            .broadcast => |b| .{ .command = .{ .broadcast = .{
                .content = try a.dupe(u8, b.content),
                .scope = b.scope,
            } } },
            else => .{ .command = requested },
        },
        else => event,
    };
}

fn parkEvent(self: *Network, event: AppEvent) HarnessError!AppEvent {
    return switch (event) {
        .received => |received| .{ .received = .{
            .content = try self.arena.allocator().dupe(u8, received.content),
            .delivered_from = received.delivered_from,
            .scope = received.scope,
        } },
        else => event,
    };
}
